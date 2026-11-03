"""
Reconciling mock Guardian — the delegated-authority / reconciliation model the OWASP
GenAI Security Project's §5.1 thread converged on, made executable so the T1–T9 matrix
can be MEASURED over the ACS wire instead of argued in prose.

For a shared cumulative grant it implements:
  - atomic, ordered admission (reserve against the grant balance)
  - stable operation_id binding: a resend of a known operation is idempotent, never a
    second consumption
  - holding the reservation on a lost acknowledgement (never auto-release)
  - reconciliation against committed truth: committed | non_effect | unresolved
  - partial fulfilment (T8): a result carries an observed effect (observed < reserved); the
    books track the observed amount and the unfilled remainder stays reserved until the key
    closes (settle), when it commits or is released — never freed before it lands
  - limit change mid-flight: re-admit the not-yet-dispatched against the new limit; never
    cancel an in-flight operation — flag an overrun instead
  - revocation: release the not-yet-dispatched, resolve the in-flight, flag a
    post-revocation commit
  - authority-basis drift (T4): a definition digest recorded at admission and checked at
    dispatch — enforced -> hold for reauthorization; recorded-only -> commit but flag the
    attempt mismatched
  - behaviour drift under a STABLE digest (T9): the server changes behaviour while the
    declared definition digest is unchanged. A digest check cannot see this by construction;
    the suite records it as an explicit expected-miss — the ceiling of attestation-by-digest,
    not a gap pretended covered

The model is credited to the OWASP delegated-authority discussion: the operation/attempt
split and holding the reservation on a lost ack (Boris Abuzov, github.com/boris-ai-sec); the lost-ack and
stop-or-reauthorize boundary (t-iida); ordered admission (Sol_ni_shko); the authority-basis
drift scenario and digests (Paolo Costanzo). It encodes ONE reading of the still-open
commitment-boundary question (valid-at-admission, overrun-flagged); the alternative
(all-times invariant / effective-limit) is noted in SCENARIO_T1_T9.md, not silently chosen.

Three variants, selected by name:
  reconciling      - the design above.
  naive            - releases on a lost ack, does not re-admit on a limit cut, re-admits a
                     resent operation_id (double-counts its own books), does not flag. Foil.
  resource-reliant - reconciling, except it outsources idempotency to the resource: on a
                     resend it re-authorizes execution instead of signalling "already done",
                     so it holds only when the ERP ledger itself dedupes.

The commitment boundary is a declared per-grant parameter (control/setBoundary; default
"dispatch"): the execution stage at and beyond which a limit cut can no longer cancel an
operation. A reservation advances through stages (reserved -> queued -> dispatched ->
resource_accepted -> committed) as the runner reports toolCallResult statuses.

Test-harness control methods (control/*, NOT ACS wire methods, clearly namespaced) let the
runner drive the scenarios and read ground state:
  control/setLimit    {grant_id, new_limit}
  control/revoke      {grant_id}
  control/setBoundary {grant_id, boundary}   (queue_admission|dispatch|resource_acceptance|transaction_commit)
  control/setBasis    {grant_id, definition_digest?, enforce?, behaviour?}
  control/state       {grant_id} -> {limit, revoked, commitment_boundary, definition_digest,
                                     behaviour_tag, consumed, outstanding, reservations, flags}

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
RESERVED, COMMITTED, NON_EFFECT, RELEASED, HELD, PARTIAL = (
    "reserved", "committed", "non_effect", "released", "held", "partial")

# execution-pipeline stage a live reservation has reached, in order. The commitment
# boundary is the stage at and beyond which a limit cut can no longer cancel the operation.
STAGE_ORDER = ["reserved", "queued", "dispatched", "resource_accepted", "committed"]
BOUNDARY_STAGE = {"queue_admission": "queued", "dispatch": "dispatched",
                  "resource_acceptance": "resource_accepted", "transaction_commit": "committed"}

BEHAVIOUR = {
    # the correct design the thread converged on
    "reconciling":      dict(idempotent_resend=True, emit_idempotent_signal=True,
                             hold_on_lost_ack=True, readmit_on_limit_cut=True,
                             flag_overrun=True, deny_on_revoke=True, hold_partial_residual=True),
    # foil: each switch flipped to the classic failure
    "naive":            dict(idempotent_resend=False, emit_idempotent_signal=False,
                             hold_on_lost_ack=False, readmit_on_limit_cut=False,
                             flag_overrun=False, deny_on_revoke=False, hold_partial_residual=False),
    # reconciling in every respect EXCEPT it outsources idempotency to the resource: on a
    # resend it re-authorizes execution instead of signalling "already done", so it holds
    # only when the ERP ledger itself dedupes. Isolates Guardian- vs resource-provided guarantees.
    "resource-reliant": dict(idempotent_resend=True, emit_idempotent_signal=False,
                             hold_on_lost_ack=True, readmit_on_limit_cut=True,
                             flag_overrun=True, deny_on_revoke=True, hold_partial_residual=True),
}


class Grant:
    def __init__(self, limit: int):
        self.limit = limit
        self.revoked = False
        self.enforce_basis = False
        self.cur_def_digest = "def-v1"
        self.commitment_boundary = "dispatch"     # declared per grant; default matches base T1-T7
        self.behaviour_tag = "b1"                  # ground-truth server behaviour; a digest does NOT attest it
        self.reservations: dict[str, dict] = {}   # op_id -> {amount,state,stage,def_digest,release_reason,committed_amount,residual,flag}
        self.order: list[str] = []
        self.flags: list[dict] = []

    @staticmethod
    def _committed_of(r) -> int:
        # a partial/settled commit counts its OBSERVED effect, not the requested amount
        ca = r.get("committed_amount")
        return ca if ca is not None else r["amount"]

    def committed_total(self) -> int:
        return sum(self._committed_of(r) for r in self.reservations.values()
                   if r["state"] in (COMMITTED, PARTIAL))

    def outstanding_total(self, exclude: str | None = None) -> int:
        tot = 0
        for op, r in self.reservations.items():
            if op == exclude:
                continue
            if r["state"] in (RESERVED, HELD):
                tot += r["amount"]
            elif r["state"] == PARTIAL:
                tot += r.get("residual", 0)   # unfilled remainder stays reserved until the key closes
        return tot

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
                    if existing["state"] in (RESERVED, COMMITTED, HELD):
                        # a known operation is never a second consumption. Whether the agent
                        # may re-execute is signalled by emit_idempotent_signal; a Guardian
                        # that outsources dedup to the resource withholds that signal.
                        codes = ["idempotent_existing"] if self.b["emit_idempotent_signal"] else []
                        return "allow", "existing operation", codes
                    if existing["state"] in (RELEASED, NON_EFFECT):
                        return "deny", f"re-confirm after release: {existing.get('release_reason','released')}", \
                               [existing.get("release_reason", "released")]
                # naive: fall through and admit AGAIN (double-counts its own books)
            avail = g.limit - g.committed_total() - g.outstanding_total()
            if amount <= avail:
                g.reservations[operation_id] = {"amount": amount, "state": RESERVED, "stage": "reserved",
                                                "def_digest": g.cur_def_digest, "release_reason": None,
                                                "committed_amount": None, "residual": 0}
                g.order.append(operation_id)
                return "allow", "reserved against the grant", []
            return "deny", "reservation would exceed the grant", ["cumulative_limit_exceeded"]

    # ---- reconciliation (steps/toolCallResult) ------------------------------------------
    def on_result(self, session, grant_id, operation_id, status, observed=None):
        with self.lock:
            g = self._grant(session, grant_id)
            r = g.reservations.get(operation_id)
            if not r:
                return
            if status in ("queued", "dispatched", "resource_accepted"):
                if r["state"] != RESERVED:
                    return
                if status == "dispatched" and r["def_digest"] != g.cur_def_digest:
                    # authority-basis drift checked at first dispatch
                    if g.enforce_basis:
                        r["state"] = HELD               # hold for reauthorization, no attempt
                        r["release_reason"] = "basis_reauth_required"
                        return
                    g.add_flag("basis_mismatch", f"{operation_id}: definition digest drifted")
                    r["flag"] = "basis_mismatch"
                r["stage"] = status                     # advance along the execution pipeline
            elif status == "committed":
                r["state"] = COMMITTED
                r["stage"] = "committed"
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
            elif status == "partial":
                # the resource fulfilled only `observed` of the reserved amount
                if r["state"] not in (RESERVED, HELD):
                    return
                r["committed_amount"] = observed
                r["residual"] = r["amount"] - (observed or 0)
                r["stage"] = "committed"
                if self.b["hold_partial_residual"]:
                    r["state"] = PARTIAL                # residual stays reserved until the key closes
                else:
                    r["state"] = COMMITTED              # naive: commit the observed, free the remainder
                    r["residual"] = 0
                if self.b["flag_overrun"] and g.committed_total() > g.limit:
                    g.add_flag("overrun", f"committed {g.committed_total()} over limit {g.limit}")
            elif status == "settle":
                # the ERP closed the key; `observed` is the final effect for this operation
                r["committed_amount"] = observed
                r["residual"] = 0
                r["state"] = COMMITTED
                r["stage"] = "committed"
                if g.revoked:
                    g.add_flag("post_revocation_commit", f"{operation_id} committed after revoke")
                if self.b["flag_overrun"] and g.committed_total() > g.limit:
                    g.add_flag("overrun", f"committed {g.committed_total()} over limit {g.limit}")

    # ---- control plane (test harness) ---------------------------------------------------
    def set_limit(self, session, grant_id, new_limit):
        with self.lock:
            g = self._grant(session, grant_id)
            g.limit = new_limit
            released = []
            if self.b["readmit_on_limit_cut"]:
                b_idx = STAGE_ORDER.index(BOUNDARY_STAGE[g.commitment_boundary])
                # re-admit, in admission order, only reservations not yet past the commitment
                # boundary. Anything at or beyond it is already-committed execution: not
                # cancelled, and any resulting overrun is flagged instead.
                for op in g.order:
                    r = g.reservations.get(op)
                    if not r or r["state"] != RESERVED:
                        continue
                    if STAGE_ORDER.index(r["stage"]) >= b_idx:
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

    def set_boundary(self, session, grant_id, boundary):
        with self.lock:
            g = self._grant(session, grant_id)
            if boundary in BOUNDARY_STAGE:
                g.commitment_boundary = boundary
            return {"commitment_boundary": g.commitment_boundary}

    def set_basis(self, session, grant_id, definition_digest=None, enforce=None, behaviour=None):
        with self.lock:
            g = self._grant(session, grant_id)
            if definition_digest is not None:
                g.cur_def_digest = definition_digest
            if enforce is not None:
                g.enforce_basis = bool(enforce)
            if behaviour is not None:
                g.behaviour_tag = behaviour      # ground-truth drift; NOT consulted by any decision
            return {"definition_digest": g.cur_def_digest, "enforce_basis": g.enforce_basis,
                    "behaviour_tag": g.behaviour_tag}

    def state(self, session, grant_id):
        with self.lock:
            g = self._grant(session, grant_id)
            return {"limit": g.limit, "revoked": g.revoked,
                    "commitment_boundary": g.commitment_boundary,
                    "definition_digest": g.cur_def_digest, "behaviour_tag": g.behaviour_tag,
                    "consumed": g.committed_total(), "outstanding": g.outstanding_total(),
                    "reservations": {op: {"amount": r["amount"], "state": r["state"],
                                          "stage": r.get("stage", "reserved"),
                                          "committed_amount": r.get("committed_amount"),
                                          "residual": r.get("residual", 0)}
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
                          payload.get("status"), payload.get("observed"))
            return self._send(self._acs(req_id, acs_rid, "allow", "result recorded", []))

        # test-harness control plane
        if method == "control/setLimit":
            return self._send(self._ok(req_id, pol.set_limit(session, payload.get("grant_id"),
                                                             payload.get("new_limit"))))
        if method == "control/revoke":
            return self._send(self._ok(req_id, pol.revoke(session, payload.get("grant_id"))))
        if method == "control/setBoundary":
            return self._send(self._ok(req_id, pol.set_boundary(session, payload.get("grant_id"),
                                                               payload.get("boundary"))))
        if method == "control/setBasis":
            return self._send(self._ok(req_id, pol.set_basis(session, payload.get("grant_id"),
                                                            payload.get("definition_digest"),
                                                            payload.get("enforce"),
                                                            payload.get("behaviour"))))
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
