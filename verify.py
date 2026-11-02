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

    print("\nVERIFIED" if ok_all else "\nNOT VERIFIED — transcript does not reproduce the scorecard")
    return 0 if ok_all else 2


if __name__ == "__main__":
    sys.exit(main())
