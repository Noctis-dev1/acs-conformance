"""
T1–T7 reconciliation matrix — the OWASP §5.1 delegated-authority test cases made
executable and measured over the ACS wire.

The §5.1 discussion produced a set of reconciliation test cases (Paolo Costanzo's T1–T7,
building on Boris Abuzov's 3×40 case and the operation/attempt split, t-iida's lost-ack
boundary, and Sol_ni_shko's ordered admission). They exist as prose. This runs them.

Ground truth is an independent ERP ledger the runner keeps, NOT the Guardian's own books.
Unlike the base Layer B ledger, this ERP is idempotent on operation_id — Paolo's setup
passes operation_id as the ERP idempotency key — so a double dispatch commits once and the
test of a Guardian's accounting is whether its books stay consistent with that ledger.

Each case is measured on the ONE property it isolates (stated per row), not a single
pass/fail notion — because the cases isolate different things: a ledger invariant, an
overrun that must be flagged rather than silent, an idempotent resend, a safe release, a
revocation. One reading of the still-open commitment-boundary question is encoded
(valid-at-admission, overrun-flagged); the alternative is noted in SCENARIO_T1_T7.md.

  python3 matrix.py            # run both Guardians through the matrix, write results
  python3 verify.py            # re-derive every verdict from the transcript
"""
from __future__ import annotations

import json
import os
import threading
import time

import acs_wire as w
import mock_guardians.reconciling as rg

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
os.makedirs(RES, exist_ok=True)

TX: list[dict] = []


class Client:
    """A well-behaved agent over the ACS wire, plus the independent ERP ledger."""

    def __init__(self, url: str, policy: str, session: str):
        self.c = w.GuardianClient(url)
        self.policy = policy
        self.session = session
        self.erp: dict[tuple, int] = {}            # (case, op) -> amount, idempotent by op

    def _rec(self, **kw):
        TX.append({"policy": self.policy, **kw})

    def consume(self, case, op, amt):
        env = w.tool_call_request("budget.consume",
                                  {"grant_id": case, "operation_id": op, "amount": amt},
                                  session_id=self.session)
        resp = self.c.call(env)
        d = w.decision_of(resp)
        codes = (resp.get("result") or {}).get("reason_codes") or []
        self._rec(case=case, ev="consume", op=op, amount=amt, decision=d, codes=codes)
        return d

    def result(self, case, op, status):
        env = w.build_request("steps/toolCallResult",
                              {"grant_id": case, "operation_id": op, "status": status},
                              session_id=self.session)
        self.c.call(env)
        self._rec(case=case, ev="result", op=op, status=status)

    def control(self, method, case, **kw):
        env = w.build_request(method, {"grant_id": case, **kw}, session_id=self.session)
        resp = self.c.call(env)
        data = resp.get("result") or {}
        self._rec(case=case, ev="control", method=method, args=kw, response=data)
        return data

    def state(self, case):
        return self.control("control/state", case)

    def erp_commit(self, case, op, amt):
        self.erp[(case, op)] = amt                 # idempotent: op_id is the key
        self._rec(case=case, ev="erp_commit", op=op, amount=amt)

    def erp_total(self, case):
        return sum(a for (g, o), a in self.erp.items() if g == case)

    # a careful agent dispatches an op only if the Guardian still holds a valid reservation
    def maybe_dispatch(self, case, op, amt):
        st = self.state(case)
        if (st.get("reservations", {}).get(op, {}) or {}).get("state") == rg.RESERVED:
            self.result(case, op, "dispatched")
            self.erp_commit(case, op, amt)
            self.result(case, op, "committed")
            return True
        return False


def _flags(st):
    return [f["type"] for f in st.get("flags", [])]


# ---------------------------------------------------------------- the eight measured cases
def T1(cli):
    c = "T1"   # limit 100->60, op-B still reserved (not dispatched)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.consume(c, "op-C", 40)                     # third 40 denied: ordered admission
    cli.control("control/setLimit", c, new_limit=60)
    cli.maybe_dispatch(c, "op-B", 40)              # only if the Guardian still holds it
    erp = cli.erp_total(c)
    return dict(case=c, measures="undispatched reservation re-admitted on a limit cut (ledger stays within the new limit)",
                erp=erp, limit=60, verdict="PASS" if erp <= 60 else "FAIL",
                detail=f"committed {erp} vs limit 60")


def T2(cli):
    c = "T2"   # op-B dispatched before the cut, ack lost, ERP HAS the record
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", "dispatched"); cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "unresolved")
    cli.control("control/setLimit", c, new_limit=60)
    cli.result(c, "op-B", "committed")             # reconcile: ERP confirms the record
    st = cli.state(c); erp = cli.erp_total(c); flagged = "overrun" in _flags(st)
    return dict(case=c, measures="a pre-cut in-flight commit over the new limit is FLAGGED as an overrun, not silently accepted",
                erp=erp, flagged=flagged, verdict="PASS" if (erp == 80 and flagged) else "FAIL",
                detail=f"committed {erp}, overrun flagged={flagged}")


def T3(cli):
    c = "T3"   # op-B dispatched, ack lost, ERP has NO record
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", "dispatched"); cli.result(c, "op-B", "unresolved")   # no erp_commit: nothing landed
    cli.control("control/setLimit", c, new_limit=60)
    cli.result(c, "op-B", "non_effect")            # reconcile: ERP confirms no record
    retry = cli.consume(c, "op-B2", 40)            # a retry as a NEW operation id
    erp = cli.erp_total(c)
    return dict(case=c, measures="lost ack with no committed effect: reservation released, a fresh retry denied against the reduced limit",
                erp=erp, retry=retry, verdict="PASS" if (erp == 40 and retry == "deny") else "FAIL",
                detail=f"committed {erp}, retry={retry}")


def T4a(cli):
    c = "T4a"  # definition digest drift under an unchanged name, ENFORCED
    cli.control("control/setBasis", c, enforce=True)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)                      # reserved under def-v1
    cli.control("control/setBasis", c, definition_digest="def-v2")   # server redefines the tool
    cli.result(c, "op-B", "dispatched")             # drift at dispatch, enforced -> held
    st = cli.state(c); bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
    cli.result(c, "op-B", "non_effect")             # reauth times out -> released
    erp = cli.erp_total(c)
    return dict(case=c, measures="definition digest drift, enforced: operation held for reauthorization, never committed",
                erp=erp, op_b_state=bstate, verdict="PASS" if (bstate == rg.HELD and erp == 40) else "FAIL",
                detail=f"op-B {bstate} at dispatch, committed {erp}")


def T4b(cli):
    c = "T4b"  # same drift, RECORDED but not enforced
    cli.control("control/setBasis", c, enforce=False)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/setBasis", c, definition_digest="def-v2")
    cli.result(c, "op-B", "dispatched")             # drift at dispatch, not enforced -> in flight + flag
    cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    st = cli.state(c); erp = cli.erp_total(c); mism = "basis_mismatch" in _flags(st)
    return dict(case=c, measures="definition digest drift, recorded-not-enforced: operation commits but the attempt is flagged mismatched",
                erp=erp, flagged=mism, verdict="PASS" if (erp == 80 and mism) else "FAIL",
                detail=f"committed {erp}, basis_mismatch flagged={mism}")


def T5(cli):
    c = "T5"   # transport resend of a known operation_id, nothing changed
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40); cli.result(c, "op-B", "dispatched"); cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    resend = cli.consume(c, "op-B", 40)            # same op_id again
    st = cli.state(c); erp = cli.erp_total(c)
    ok = resend == "allow" and st.get("consumed") == erp == 80
    return dict(case=c, measures="a transport resend of a known operation_id is idempotent (allowed, no second consumption; books match the ledger)",
                erp=erp, resend=resend, consumed=st.get("consumed"),
                verdict="PASS" if ok else "FAIL",
                detail=f"resend={resend}, guardian consumed {st.get('consumed')} vs ledger {erp}")


def T6(cli):
    c = "T6"   # limit 100->30: op-A alone (40) is already over
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/setLimit", c, new_limit=30)
    st = cli.state(c); erp = cli.erp_total(c); flagged = "overrun" in _flags(st)
    return dict(case=c, measures="a limit cut below already-committed consumption flags an overrun on the grant",
                erp=erp, flagged=flagged, verdict="PASS" if flagged else "FAIL",
                detail=f"committed {erp} vs limit 30, overrun flagged={flagged}")


def T7(cli):
    c = "T7"   # revocation with op-B not yet dispatched
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/revoke", c)
    cli.maybe_dispatch(c, "op-B", 40)              # only if still reserved
    reconfirm = cli.consume(c, "op-B", 40)         # re-confirm -> should be denied
    st = cli.state(c); erp = cli.erp_total(c); post = "post_revocation_commit" in _flags(st)
    ok = erp == 40 and reconfirm == "deny" and not post
    return dict(case=c, measures="revocation releases the not-yet-dispatched; nothing new commits; a prior commit is not retro-flagged",
                erp=erp, reconfirm=reconfirm, verdict="PASS" if ok else "FAIL",
                detail=f"committed {erp}, re-confirm={reconfirm}, post-revoke-commit flag={post}")


CASES_ALL = [T1, T2, T3, T4a, T4b, T5, T6, T7]
CASES_NAIVE = [T1, T2, T3, T5, T6, T7]             # T4 is an enforcement posture, not a foil for naive


def run_policy(policy: str, port: int, cases):
    srv = rg.make_server(policy, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    cli = Client(f"http://127.0.0.1:{port}/acs", policy, w.new_uuid())
    rows = [fn(cli) for fn in cases]
    srv.shutdown()
    return rows


def main():
    scorecards = {
        "reconciling": run_policy("reconciling", 8810, CASES_ALL),
        "naive": run_policy("naive", 8811, CASES_NAIVE),
    }
    with open(os.path.join(RES, "matrix_transcript.jsonl"), "w") as f:
        for t in TX:
            f.write(json.dumps(t) + "\n")
    with open(os.path.join(RES, "matrix_scorecard.json"), "w") as f:
        json.dump({"scorecards": scorecards}, f, indent=2)

    print("T1–T7 reconciliation matrix (OWASP §5.1 delegated-authority), measured over the ACS wire\n")
    order = ["T1", "T2", "T3", "T4a", "T4b", "T5", "T6", "T7"]
    def row(policy):
        by = {r["case"]: r["verdict"] for r in scorecards[policy]}
        cells = "".join(f"{by.get(cs, 'n/a'):<7}" for cs in order)
        print(f"  {policy:<13}{cells}")
    print(f"  {'':<13}" + "".join(f"{cs:<7}" for cs in order))
    row("reconciling")
    row("naive")
    print("\nWhat each case isolates:")
    for r in scorecards["reconciling"]:
        print(f"  {r['case']:<5} {r['measures']}")
    print(f"\nFrozen evidence in {RES}/  —  verify with: python3 verify.py")


if __name__ == "__main__":
    main()
