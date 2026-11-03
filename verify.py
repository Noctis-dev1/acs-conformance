#!/usr/bin/env python3
"""
Independent verifier for the ACS Guardian conformance results. Standard library only.

It recomputes every invariant verdict from results/transcript.jsonl — the recorded wire
effects — rather than trusting the scorecard the runner wrote. For each (policy, scenario)
it sums the amounts of the effects the runner actually executed (honoured `allow`s) and
re-derives HOLD vs OVERSHOOT/LEAK/DOUBLE-SPEND, then checks that against scorecard.json.
It also re-hashes the sources against results/manifest.json.

If a verdict in the scorecard is not reproduced from the transcript, it does not count.

Usage:  python3 verify.py   (exit 0 = VERIFIED)
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
LIMIT = 100


def classify(scenario, committed, exec_count, reason):
    if exec_count == 0:
        return f"N/A ({reason})"       # held only vacuously: nothing was allowed
    if scenario == "race":
        return "HOLD" if committed <= LIMIT else "OVERSHOOT"
    if scenario == "continue":
        return "HOLD" if committed <= LIMIT else "LEAK"
    if scenario == "retry":
        return "HOLD" if committed <= 40 else "DOUBLE-SPEND"
    return "?"


def verify_matrix():
    """Re-derive every T1–T9 verdict from matrix_transcript.jsonl, independently of
    matrix_scorecard.json. Returns True/False, or None if no matrix run is present."""
    tpath = os.path.join(RES, "matrix_transcript.jsonl")
    spath = os.path.join(RES, "matrix_scorecard.json")
    if not (os.path.exists(tpath) and os.path.exists(spath)):
        return None
    tx = [json.loads(l) for l in open(tpath) if l.strip()]
    doc = json.load(open(spath))
    scorecard = doc["scorecards"]

    events = {}
    for t in tx:
        events.setdefault((t["policy"], t["case"]), []).append(t)

    def erp_total(evs):
        amts = {}
        for e in evs:
            if e["ev"] == "erp_commit":
                amts[e["op"]] = e["amount"]          # idempotent: op_id is the ledger key
        return sum(amts.values())

    def final_state(evs):
        st = {}
        for e in evs:
            if e["ev"] == "control" and e.get("method") == "control/state":
                st = e.get("response") or {}
        return st

    def decisions(evs, op):
        return [e["decision"] for e in evs if e["ev"] == "consume" and e["op"] == op]

    def classify(case, evs):
        erp = erp_total(evs); st = final_state(evs)
        flags = [f["type"] for f in st.get("flags", [])]
        if case == "T1":
            return "PASS" if erp <= 60 else "FAIL"
        if case == "T2":
            return "PASS" if (erp == 80 and "overrun" in flags) else "FAIL"
        if case == "T3":
            r = decisions(evs, "op-B2")
            return "PASS" if (erp == 40 and r and r[-1] == "deny") else "FAIL"
        if case == "T4a":
            bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
            return "PASS" if (bstate == "held" and erp == 40) else "FAIL"
        if case == "T4b":
            return "PASS" if (erp == 80 and "basis_mismatch" in flags) else "FAIL"
        if case == "T5":
            d = decisions(evs, "op-B")
            return "PASS" if (len(d) >= 2 and d[-1] == "allow" and st.get("consumed") == erp == 80) else "FAIL"
        if case == "T6":
            return "PASS" if "overrun" in flags else "FAIL"
        if case == "T7":
            d = decisions(evs, "op-B")
            return "PASS" if (erp == 40 and d and d[-1] == "deny"
                              and "post_revocation_commit" not in flags) else "FAIL"
        if case == "T8":
            opc = decisions(evs, "op-C")
            return "PASS" if (erp == 80 and st.get("consumed") == 80
                              and opc and opc[-1] == "deny"
                              and "reconciliation_required" in flags
                              and "overrun" not in flags) else "FAIL"
        if case == "T9":
            bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
            return "EXPECTED-MISS" if (st.get("definition_digest") == "def-v1"
                                       and st.get("behaviour_tag") == "b2" and erp == 80
                                       and "basis_mismatch" not in flags and bstate == "committed") else "FAIL"
        return "?"

    print("\nVERIFY  T1–T9 reconciliation matrix")
    print("  (every verdict re-derived from matrix_transcript.jsonl, not the scorecard)")
    ok = True
    for policy, rows in scorecard.items():
        cells = []
        for r in rows:
            case = r["case"]
            recomputed = classify(case, events.get((policy, case), []))
            good = recomputed == r["verdict"]
            ok = ok and good
            cells.append(f"{case}={recomputed}" + ("" if good else f"!=sc({r['verdict']})"))
        print(f"  {policy:<13}{'  '.join(cells)}")

    def erp_sum(evs):                       # non-idempotent ledger: every commit counts
        return sum(e["amount"] for e in evs if e["ev"] == "erp_commit")

    # independent copy of the stage/boundary order — do not trust the Guardian's module
    S_ORDER = ["reserved", "queued", "dispatched", "resource_accepted", "committed"]
    S_BOUNDARY = {"queue_admission": "queued", "dispatch": "dispatched",
                  "resource_acceptance": "resource_accepted", "transaction_commit": "committed"}

    sweep_ok = True
    for r in doc.get("sweep", []):
        stage, b = r["stage"], r["boundary"]
        erp = erp_total(events.get(("reconciling", f"SWEEP-{stage}-{b}"), []))
        immune = S_ORDER.index(stage) >= S_ORDER.index(S_BOUNDARY[b])
        recomputed = "PASS" if erp == (80 if immune else 40) else "FAIL"
        good = recomputed == r["verdict"] and erp == r["erp"]
        ok = ok and good
        sweep_ok = sweep_ok and good
        if not good:
            print(f"  sweep {stage}/{b}: {recomputed} ({erp}) !=sc({r['verdict']}/{r['erp']})")
    sweep_rows = doc.get("sweep", [])
    if sweep_rows:
        print(f"  sweep ({len(sweep_rows)} stage×boundary cells): {'all reproduce' if sweep_ok else 'MISMATCH above'}")

    for r in doc.get("ledger", []):
        evs = events.get((r["policy"], f"LEDGER-{r['policy']}-{r['ledger']}"), [])
        erp = erp_total(evs) if r["ledger"] == "idempotent" else erp_sum(evs)
        recomputed = "HOLD" if erp <= 100 else "DOUBLE-SPEND"
        good = recomputed == r["verdict"] and erp == r["erp"]
        ok = ok and good
        print(f"  ledger {r['policy']}/{r['ledger']}: {recomputed} ({erp})"
              + ("" if good else f" !=sc({r['verdict']}/{r['erp']})"))

    return ok


def main():
    for n in ("transcript.jsonl", "scorecard.json", "manifest.json"):
        if not os.path.exists(os.path.join(RES, n)):
            print(f"missing {n} — run: python3 run_conformance.py --selftest")
            return 1

    tx = [json.loads(l) for l in open(os.path.join(RES, "transcript.jsonl")) if l.strip()]
    scorecard = json.load(open(os.path.join(RES, "scorecard.json")))

    # recompute committed totals, executed counts, reasons, per-op counts from the transcript
    recomputed = {}            # (policy, scenario) -> committed
    exec_count = {}            # (policy, scenario) -> executed ops
    reasons = {}               # (policy, scenario) -> [reason, ...]
    op_count = {}              # (policy, scenario, op) -> times executed
    for t in tx:
        key = (t["policy"], t["scenario"])
        reasons.setdefault(key, []).append(t.get("reason", "none"))
        if not t["executed"]:
            continue
        recomputed[key] = recomputed.get(key, 0) + t["amount"]
        exec_count[key] = exec_count.get(key, 0) + 1
        ok = (t["policy"], t["scenario"], t["operation_id"])
        op_count[ok] = op_count.get(ok, 0) + 1

    def dom_reason(key):
        rs = reasons.get(key, [])
        return max(set(rs), key=rs.count) if rs else "none"

    print("VERIFY  ACS Guardian conformance")
    print("  (every verdict re-derived from the recorded wire transcript, not the scorecard)\n")
    print(f"  {'policy':<14}{'race':<18}{'continue':<18}{'retry':<20}")

    ok_all = True
    for row in scorecard["scorecards"]:
        policy = row["policy"]
        cells = []
        for scen in ("race", "continue", "retry"):
            key = (policy, scen)
            committed = recomputed.get(key, 0)
            verdict = classify(scen, committed, exec_count.get(key, 0), dom_reason(key))
            published = row["verdict"][scen]
            good = verdict == published and committed == row["committed"][scen]
            ok_all = ok_all and good
            tag = "" if good else f"!=sc({published}/{row['committed'][scen]})"
            cells.append(f"{verdict} ({committed}){tag}")
        # double-spend cross-check: any operation executed more than once?
        dupes = [op for (p, s, op), n in op_count.items() if p == policy and n > 1]
        print(f"  {policy:<14}{cells[0]:<18}{cells[1]:<18}{cells[2]:<20}"
              + (f"  dup-ops={dupes}" if dupes else ""))

    print("\nsource-hash check vs manifest:")
    man = json.load(open(os.path.join(RES, "manifest.json")))
    for src, want in man.get("src_sha256", {}).items():
        p = os.path.join(HERE, src)
        got = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None
        good = got == want
        ok_all = ok_all and good
        print(f"  {src:<32} {'OK' if good else 'MISMATCH'}")

    matrix_ok = verify_matrix()          # None if no T1–T7 run is present in results/
    if matrix_ok is not None:
        ok_all = ok_all and matrix_ok

    print("\nVERIFIED" if ok_all else "\nNOT VERIFIED — transcript does not reproduce the scorecard")
    return 0 if ok_all else 2


if __name__ == "__main__":
    sys.exit(main())
