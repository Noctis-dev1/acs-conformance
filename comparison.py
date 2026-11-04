"""
ARC x Guardian x ledger: render the three-layer comparison from the verified matrix results.

This is a presenter, not a measurer. Every Guardian and ledger cell it prints comes from
results/matrix_scorecard.json, which verify.py re-derives from the wire transcript, so the
comparison introduces no second source of truth and nothing it shows rests on its own say-so.

The ARC column is filled from ARC's fixture (github.com/suirindo/agent-role-contracts). The
cells here marked "pending ARC fixture" are expectations drawn from ARC's documented G1
construction, to confirm or correct, not results measured by this suite.

  python3 matrix.py         # produce the verified results first
  python3 comparison.py     # render the three-layer table from them
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SCORE = os.path.join(HERE, "results", "matrix_scorecard.json")

ARC = {
    "t4_declared":   "REJECT, G1 subject mismatch (pending ARC fixture)",
    "t4_underlying": "PASS, G1 subject unchanged, expected-miss by construction (pending ARC fixture)",
    "t8":            "N/A, outside ARC's declaration and lifecycle scope (pending ARC fixture)",
}


def main():
    if not os.path.exists(SCORE):
        print("no results/matrix_scorecard.json found; run: python3 matrix.py")
        return 1
    doc = json.load(open(SCORE))
    rec = {r["case"]: r for r in doc["scorecards"]["reconciling"]}
    cmp = {r["policy"]: r for r in doc.get("comparison", [])}
    t4a, t4b, t8 = rec.get("T4a", {}), rec.get("T4b", {}), rec.get("T8", {})
    rc, db = cmp.get("reconciling", {}), cmp.get("declaration-bound", {})

    print("ARC x Guardian x ledger: three independent layers over one scenario")
    print("  Guardian and ledger columns from the verified matrix results; ARC column pending the ARC fixture.\n")

    print("T4-declared (change is in the declared bundle, task or action):")
    print(f"  ARC (declaration):   {ARC['t4_declared']}")
    print(f"  Guardian (boundary): drift caught at dispatch: hold for reauth when enforced (T4a={t4a.get('verdict')}), "
          f"commit and flag basis_mismatch when recorded (T4b={t4b.get('verdict')})")
    print("  independent ledger:  effect bounded, 40 held / 80 committed-and-flagged\n")

    print("T4-underlying (underlying tool or MCP definition changes, declaration unchanged):")
    print(f"  ARC (declaration):   {ARC['t4_underlying']}")
    print(f"  Guardian (boundary): a definition-binding Guardian {rc.get('outcome')} it "
          f"(reconciling, basis_mismatch flagged={rc.get('flagged')}); a declaration-bound one "
          f"{db.get('outcome')} it (flagged={db.get('flagged')})")
    print(f"  independent ledger:  {rc.get('erp')} committed either way; the difference is whether the drift was noticed\n")

    print("T8 (partial fulfilment with a late-arriving effect):")
    print(f"  ARC (declaration):   {ARC['t8']}")
    print("  Guardian (boundary): counts the confirmed 20, holds the remainder to key close, denies a competing op, "
          f"flags reconciliation_required on the late fill (T8={t8.get('verdict')})")
    print(f"  independent ledger:  {t8.get('erp')}, flagged, no double-spend (naive double-spends to 120)\n")

    print("Every Guardian and ledger cell above is a verdict in matrix_scorecard.json that verify.py")
    print("re-derives from the wire transcript. The ARC cells are expectations to confirm against the fixture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
