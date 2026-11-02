"""
Reconciling mock Guardian — the delegated-authority / reconciliation model the OWASP
GenAI Security Project's §5.1 thread converged on, made executable so the T1–T7 matrix
can be MEASURED over the ACS wire instead of argued in prose.

For a shared cumulative grant it implements:
  - atomic, ordered admission (reserve against the grant balance)
  - stable operation_id binding: a resend of a known operation is idempotent, never a
    second consumption
  - holding the reservation on a lost acknowledgement (never auto-release)
  - reconciliation against committed truth: committed | non_effect | unresolved
  - limit change mid-flight: re-admit the not-yet-dispatched against the new limit; never
    cancel an in-flight operation — flag an overrun instead
  - revocation: release the not-yet-dispatched, resolve the in-flight, flag a
    post-revocation commit
  - authority-basis drift (T4): a definition digest recorded at admission and checked at
    dispatch — enforced -> hold for reauthorization; recorded-only -> commit but flag the
    attempt mismatched

The model is credited to the OWASP delegated-authority discussion: the operation/attempt
split and holding the reservation on a lost ack (Boris Abuzov); the lost-ack and
stop-or-reauthorize boundary (t-iida); ordered admission (Sol_ni_shko); the authority-basis
drift scenario and digests (Paolo Costanzo). It encodes ONE reading of the still-open
commitment-boundary question (valid-at-admission, overrun-flagged); the alternative
(all-times invariant / effective-limit) is noted in SCENARIO_T1_T7.md, not silently chosen.

Two variants, selected by name:
  reconciling - the design above.
  naive       - releases on a lost ack, does not re-admit on a limit cut, re-admits a
                resent operation_id (double-counts its own books), and does not flag. Foil.

Test-harness control methods (control/*, NOT ACS wire methods — clearly namespaced) let
the runner drive the scenarios and read ground state:
  control/setLimit {grant_id, new_limit}
  control/revoke   {grant_id}
  control/setBasis {grant_id, definition_digest?, enforce?}
  control/state    {grant_id} -> {limit, revoked, consumed, outstanding, reservations, flags}

Run one:  python3 reconciling.py --policy reconciling --port 8810
"""
from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ACS_VERSION = "0.1.0"
DEFAULT_LIMIT = 100

# reservation states
RESERVED, IN_FLIGHT, COMMITTED, NON_EFFECT, RELEASED, HELD = (
    "reserved", "in_flight", "committed", "non_effect", "released", "held")

BEHAVIOUR = {
    # correct design the thread converged on
    "reconciling": dict(idempotent_resend=True, hold_on_lost_ack=True,
                        readmit_on_limit_cut=True, flag_overrun=True, deny_on_revoke=True),
    # foil: each switch flipped to the classic failure
    "naive":       dict(idempotent_resend=False, hold_on_lost_ack=False,
                        readmit_on_limit_cut=False, flag_overrun=False, deny_on_revoke=False),
}


class Grant:
    def __init__(self, limit: int):
        self.limit = limit
        self.revoked = False
        self.enforce_basis = False
        self.cur_def_digest = "def-v1"
        self.reservations: dict[str, dict] = {}   # op_id -> {amount,state,def_digest,release_reason,flag}
        self.order: list[str] = []
        self.flags: list[dict] = []

    def committed_total(self) -> int:
        return sum(r["amount"] for r in self.reservations.values() if r["state"] == COMMITTED)

    def outstanding_total(self, exclude: str | None = None) -> int:
        return sum(r["amount"] for op, r in self.reservations.items()
                   if op != exclude and r["state"] in (RESERVED, IN_FLIGHT, HELD))

    def add_flag(self, ftype: str, detail: str):
        self.flags.append({"type": ftype, "detail": detail})


class Policy:
    def __init__(self, name: str, limit: int = DEFAULT_LIMIT):
        self.name = name
        self.limit = limit
        self.b = BEHAVIOUR[name]
        self.lock = threading.Lock()
        self.grants: dict[tuple, Grant] = {}   # (session, grant_id) -> Grant

    def _grant(self, session, grant_id) -> Grant:
        return self.grants.setdefault((session, grant_id), Grant(self.limit))

    # ---- admission (steps/toolCallRequest, tool budget.consume) -------------------------
    def decide_consume(self, session, grant_id, operation_id, amount):
        with self.lock:
            g = self._grant(session, grant_id)
            if g.revoked:
                return "deny", "grant revoked", ["grant_revoked"]
            existing = g.reservations.get(operation_id)
            if existing:
                if self.b["idempotent_resend"]:
                    if existing["state"] in (RESERVED, IN_FLIGHT, COMMITTED, HELD):
                        return "allow", "idempotent: existing reservation", ["idempotent_existing"]
                    if existing["state"] in (RELEASED, NON_EFFECT):
                        return "deny", f"re-confirm after release: {existing.get('release_reason','released')}", \
                               [existing.get("release_reason", "released")]
                # naive: fall through and admit AGAIN (double-counts its own books)
            avail = g.limit - g.committed_total() - g.outstanding_total()
            if amount <= avail:
                g.reservations[operation_id] = {"amount": amount, "state": RESERVED,
                                                "def_digest": g.cur_def_digest, "release_reason": None}
                g.order.append(operation_id)
                return "allow", "reserved against the grant", []
            return "deny", "reservation would exceed the grant", ["cumulative_limit_exceeded"]

    # ---- reconciliation (steps/toolCallResult) ------------------------------------------
    def on_result(self, session, grant_id, operation_id, status):
        with self.lock:
            g = self._grant(session, grant_id)
            r = g.reservations.get(operation_id)
            if not r:
                return
            if status == "dispatched":
                if r["state"] == RESERVED:
                    if r["def_digest"] != g.cur_def_digest:
                        # authority-basis drift at first dispatch
                        if g.enforce_basis:
                            r["state"] = HELD           # hold for reauthorization, no attempt
                            r["release_reason"] = "basis_reauth_required"
                            return
                        g.add_flag("basis_mismatch", f"{operation_id}: definition digest drifted")
                        r["flag"] = "basis_mismatch"
                    r["state"] = IN_FLIGHT
            elif status == "committed":
                r["state"] = COMMITTED
                if g.revoked:
                    g.add_flag("post_revocation_commit", f"{operation_id} committed after revoke")
                if self.b["flag_overrun"] and g.committed_total() > g.limit:
                    g.add_flag("overrun", f"committed {g.committed_total()} over limit {g.limit}")
            elif status == "non_effect":
                r["state"] = NON_EFFECT
                r["release_reason"] = "non_effect"
            elif status == "unresolved":
                if self.b["hold_on_lost_ack"]:
                    r["state"] = HELD                   # hold the reservation; do NOT release
                else:
                    r["state"] = RELEASED               # naive bug: frees budget already spent
                    r["release_reason"] = "auto_released_on_lost_ack"

    # ---- control plane (test harness) ---------------------------------------------------
    def set_limit(self, session, grant_id, new_limit):
        with self.lock:
            g = self._grant(session, grant_id)
            g.limit = new_limit
            released = []
            if self.b["readmit_on_limit_cut"]:
                # re-admit the not-yet-dispatched in admission order against the new limit
                for op in g.order:
                    r = g.reservations.get(op)
                    if not r or r["state"] != RESERVED:
                        continue
                    avail = new_limit - g.committed_total() - g.outstanding_total(exclude=op)
                    if r["amount"] > avail:
                        r["state"] = RELEASED
                        r["release_reason"] = "cumulative_limit_exceeded"
                        released.append(op)
            if self.b["flag_overrun"] and g.committed_total() > new_limit:
                g.add_flag("overrun", f"committed {g.committed_total()} over new limit {new_limit}")
            return {"released": released, "limit": new_limit}

    def revoke(self, session, grant_id):
        with self.lock:
            g = self._grant(session, grant_id)
            g.revoked = True
            released = []
            if self.b["deny_on_revoke"]:
                for op, r in g.reservations.items():
                    if r["state"] == RESERVED:          # not-yet-dispatched
                        r["state"] = RELEASED
                        r["release_reason"] = "grant_revoked"
                        released.append(op)
            return {"released": released, "revoked": True}

    def set_basis(self, session, grant_id, definition_digest=None, enforce=None):
        with self.lock:
            g = self._grant(session, grant_id)
            if definition_digest is not None:
                g.cur_def_digest = definition_digest
            if enforce is not None:
                g.enforce_basis = bool(enforce)
            return {"definition_digest": g.cur_def_digest, "enforce_basis": g.enforce_basis}

    def state(self, session, grant_id):
        with self.lock:
            g = self._grant(session, grant_id)
            return {"limit": g.limit, "revoked": g.revoked,
                    "consumed": g.committed_total(), "outstanding": g.outstanding_total(),
                    "reservations": {op: {"amount": r["amount"], "state": r["state"]}
                                     for op, r in g.reservations.items()},
                    "flags": list(g.flags)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _acs(self, req_id, acs_rid, decision, reasoning, codes):
        result = {"type": "final", "acs_version": ACS_VERSION, "request_id": acs_rid,
                  "decision": decision}
        if reasoning:
            result["reasoning"] = reasoning
        if codes:
            result["reason_codes"] = codes
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _ok(self, req_id, data):
        return {"jsonrpc": "2.0", "id": req_id, "result": data}

    def _err(self, req_id, code, msg):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            env = json.loads(self.rfile.read(n).decode())
        except Exception as e:
            return self._send(self._err(None, -32700, f"parse error: {e}"), 400)

        req_id = env.get("id")
        method = env.get("method", "")
        params = env.get("params", {}) or {}
        acs_rid = params.get("request_id")
        meta = params.get("metadata", {}) or {}
        session = meta.get("session_id", "default")
        payload = params.get("payload", {}) or {}
        pol: Policy = self.server.policy  # type: ignore[attr-defined]

        if method == "handshake/hello":
            return self._send(self._ok(req_id, {
                "negotiated_version": ACS_VERSION,
                "methods_evaluated": ["steps/toolCallRequest", "steps/toolCallResult"],
                "selected_transport": "http", "timeout_config": {"default_ms": 5000},
                "on_decision_failure": "deny", "signature_algorithms_supported": [],
                "skew_window_ms": 30000}))
        if method == "system/ping":
            return self._send(self._ok(req_id, {"status": "ok"}))

        if method == "steps/toolCallRequest":
            tool = (payload.get("tool") or {}).get("name")
            args = {k: v.get("value") for k, v in (payload.get("arguments") or {}).items()}
            if tool == "budget.consume":
                d, why, codes = pol.decide_consume(session, args.get("grant_id"),
                                                   args.get("operation_id"), args.get("amount"))
                return self._send(self._acs(req_id, acs_rid, d, why, codes))
            return self._send(self._acs(req_id, acs_rid, "deny", "unknown tool", ["unknown_tool"]))

        if method == "steps/toolCallResult":
            pol.on_result(session, payload.get("grant_id"), payload.get("operation_id"),
                          payload.get("status"))
            return self._send(self._acs(req_id, acs_rid, "allow", "result recorded", []))

        # test-harness control plane
        if method == "control/setLimit":
            return self._send(self._ok(req_id, pol.set_limit(session, payload.get("grant_id"),
                                                             payload.get("new_limit"))))
        if method == "control/revoke":
            return self._send(self._ok(req_id, pol.revoke(session, payload.get("grant_id"))))
        if method == "control/setBasis":
            return self._send(self._ok(req_id, pol.set_basis(session, payload.get("grant_id"),
                                                            payload.get("definition_digest"),
                                                            payload.get("enforce"))))
        if method == "control/state":
            return self._send(self._ok(req_id, pol.state(session, payload.get("grant_id"))))

        return self._send(self._err(req_id, -32601, f"method not found: {method}"), 404)


def make_server(policy_name: str, port: int, limit: int = DEFAULT_LIMIT) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.policy = Policy(policy_name, limit)  # type: ignore[attr-defined]
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", choices=list(BEHAVIOUR), required=True)
    ap.add_argument("--port", type=int, default=8810)
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = ap.parse_args()
    srv = make_server(args.policy, args.port, args.limit)
    print(f"ACS reconciling mock '{args.policy}' at http://127.0.0.1:{args.port}/acs (limit {args.limit})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
