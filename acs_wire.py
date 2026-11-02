"""
ACS wire layer — a minimal, language-independent client and validator for the OWASP
Agent Control Standard (ACS) v0.1.0 Guardian contract.

Standard library only. This speaks the ACS wire so the conformance tests can point at
*any* Guardian over HTTP — the reference TypeScript/AGT Guardian, a vendor's, or the
mock Guardians shipped here — exactly the "point the suite at its own Guardian URL" that
issue #311 asks for. It measures the wire, not the implementation language.

Grounded against the published v0.1.0 schemas:
  specification/v0.1.0/request-envelope.json
  specification/v0.1.0/response-envelope.json
  docs/spec/.../conformance.md  (ACS-Core)

What is deliberately NOT done here yet, and is marked pending rather than faked:
  * §10 signature construction/verification (HMAC-SHA256 over the JCS canonicalization
    with an HKDF-derived per-session key). The envelope carries the field; the exact
    canonicalization is confirmed against §10 before the signing tests are switched on.
  * §10.3 replay/timestamp acceptance window (value not in the published excerpt).
These are real ACS-Core requirements; they are stubbed in the contract layer with the
reason stated, not silently passed.
"""
from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone

ACS_VERSION = "0.1.0"
DEFAULT_GUARDIAN_URL = "http://localhost:8787/acs"

# From response-envelope.json: AcsResult.decision enum.
DECISIONS = {"allow", "deny", "modify", "ask", "defer"}
# ACS-Core §6: ALLOW/DENY/ASK/DEFER are MUST-support; MODIFY is SHOULD-support.
CORE_REQUIRED_DECISIONS = {"allow", "deny", "ask", "defer"}
# Conditional fields required by the response schema's allOf, per decision.
DECISION_REQUIRES = {
    "deny": ["reasoning"],
    "modify": ["reasoning", "modifications"],
    "ask": ["reasoning", "ask_details"],
    "defer": ["reasoning", "defer_details"],
}

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def now_iso() -> str:
    """ISO 8601 / RFC 3339 UTC timestamp, e.g. 2026-11-02T04:05:06.123456+00:00."""
    return datetime.now(timezone.utc).isoformat()


def new_uuid() -> str:
    return str(uuid.uuid4())


def build_request(method: str, payload: dict, *, session_id: str, agent_id: str = "acs-conformance",
                  request_id: str | None = None, timestamp: str | None = None,
                  nonce: str | None = None, extra_metadata: dict | None = None) -> dict:
    """Construct an ACS request envelope (JSON-RPC 2.0) to the v0.1.0 request schema.

    `method` is a namespaced method (e.g. "steps/toolCallRequest", "handshake/hello",
    "system/ping"). `payload` is the hook-specific params.payload object. A signature is
    intentionally omitted here (see module note on §10) and added by the signing layer
    once the canonicalization is confirmed.
    """
    metadata = {"agent_id": agent_id, "session_id": session_id}
    if extra_metadata:
        metadata.update(extra_metadata)
    params = {
        "acs_version": ACS_VERSION,
        "request_id": request_id or new_uuid(),
        "timestamp": timestamp or now_iso(),
        "metadata": metadata,
        "payload": payload,
    }
    if nonce is not None:
        params["nonce"] = nonce
    return {"jsonrpc": "2.0", "id": new_uuid(), "method": method, "params": params}


def tool_call_request(tool_name: str, arguments: dict, *, session_id: str, **kw) -> dict:
    """A steps/toolCallRequest envelope. `arguments` is {param: value}; the ACS payload
    shape wraps each argument as {"value": <v>}."""
    payload = {
        "tool": {"name": tool_name},
        "arguments": {k: {"value": v} for k, v in arguments.items()},
    }
    return build_request("steps/toolCallRequest", payload, session_id=session_id, **kw)


class WireError(Exception):
    """Transport- or protocol-level failure talking to the Guardian."""


class GuardianClient:
    """A thin JSON-RPC-over-HTTP client for an ACS Guardian endpoint."""

    def __init__(self, url: str = DEFAULT_GUARDIAN_URL, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout

    def call(self, envelope: dict) -> dict:
        """POST one request envelope, return the parsed response envelope.

        Raises WireError on transport failure or non-JSON body. An ACS error *response*
        (a JSON-RPC object with `error`) is returned, not raised — refusing a bad request
        is conformant behaviour the tests need to inspect.
        """
        body = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)                 # an ACS error response may ride an HTTP 4xx
            except json.JSONDecodeError:
                raise WireError(f"HTTP {e.code} with non-JSON body: {raw[:200]}")
        except Exception as e:
            raise WireError(f"transport error to {self.url}: {e}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise WireError(f"non-JSON response body: {raw[:200]}")


def validate_response(resp: dict, request_envelope: dict) -> list[str]:
    """Check a response envelope against the v0.1.0 response schema and the ACS-Core
    conditional rules. Returns a list of violation strings; empty means conformant at the
    structural level checked here (this does not assert signature validity — see §10).
    """
    v: list[str] = []
    if resp.get("jsonrpc") != "2.0":
        v.append('jsonrpc must be "2.0"')
    if "id" not in resp:
        v.append("response missing id")
    elif resp.get("id") != request_envelope.get("id"):
        v.append(f"id {resp.get('id')!r} does not correlate to request id "
                 f"{request_envelope.get('id')!r}")

    has_result, has_error = "result" in resp, "error" in resp
    if has_result == has_error:
        v.append("exactly one of result/error must be present")
        return v

    if has_error:
        err = resp["error"]
        if not isinstance(err.get("code"), int):
            v.append("error.code must be an integer")
        if not isinstance(err.get("message"), str):
            v.append("error.message must be a string")
        return v

    r = resp["result"]
    # result may be an AcsResult or a ServerHello; a hook call must yield an AcsResult.
    # A ServerHello is keyed by negotiated_version (a handshake.json $def required field),
    # not by the optional profiles_accepted.
    if "decision" not in r and "negotiated_version" in r:
        return v  # ServerHello handshake result; validated by the handshake check
    if r.get("type") != "final":
        v.append('result.type must be "final" in v0.1')
    if not _SEMVER.match(str(r.get("acs_version", ""))):
        v.append("result.acs_version must match semver")
    rid = r.get("request_id", "")
    try:
        uuid.UUID(str(rid))
    except ValueError:
        v.append("result.request_id must be a uuid")
    req_rid = request_envelope.get("params", {}).get("request_id")
    if req_rid and rid != req_rid:
        v.append(f"result.request_id {rid!r} != request params.request_id {req_rid!r}")

    decision = r.get("decision")
    if decision not in DECISIONS:
        v.append(f"result.decision {decision!r} not in {sorted(DECISIONS)}")
    else:
        for field in DECISION_REQUIRES.get(decision, []):
            if field not in r:
                v.append(f"decision={decision} requires {field!r} (response-envelope allOf)")

    if "chain_hash" in r and not _HEX64.match(str(r["chain_hash"])):
        v.append("chain_hash must be 64 lowercase hex chars")
    return v


def decision_of(resp: dict) -> str | None:
    """Extract the decision, or None if this is not an AcsResult verdict."""
    r = resp.get("result")
    return r.get("decision") if isinstance(r, dict) else None


if __name__ == "__main__":
    # Smoke check: build a toolCallRequest and show the envelope shape (no network).
    env = tool_call_request("file_read", {"path": "/etc/hosts"}, session_id=new_uuid())
    print(json.dumps(env, indent=2))
