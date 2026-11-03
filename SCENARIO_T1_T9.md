# The T1–T9 reconciliation matrix, made executable

*The OWASP GenAI Security Project's delegated-authority discussion produced a set of reconciliation test cases — the 3×40 cumulative-grant race and its lost-ack, revocation, limit-change, basis-drift, partial-fulfilment, and behaviour-drift variants. They exist as prose. This runs them, and measures each from an independent ledger.*

**Suite:** `matrix.py` · **Guardian:** `mock_guardians/reconciling.py` · **Verifier:** `verify.py` · **Target contract:** ACS v0.1.0 Guardian wire (JSON-RPC 2.0 over HTTP).

## The model, and whose it is

The reconciling Guardian encodes the design the thread converged on:

- the **operation / attempt split** and **holding the reservation on a lost acknowledgement** ([Boris Abuzov](https://github.com/boris-ai-sec)),
- the **lost-ack boundary** and **stop-or-reauthorize** on a changed basis (t-iida),
- **ordered admission** of concurrent requests (Sol_ni_shko),
- the **authority-basis drift** scenario — a tool redefined under an unchanged name — and content-addressed **digests** (Paolo Costanzo).

That model is theirs. The encoding here is mine, and it may differ from what any of them intended — the point of making it executable is that a difference now shows up as a failing assertion instead of a disagreement in prose. Corrections to the encoding are welcome.

## How it is measured

Ground truth is an independent **ERP ledger** the runner keeps, never the Guardian's own books. Two deliberate choices:

- The ERP is **idempotent on `operation_id`** — Paolo's setup passes `operation_id` as the ERP idempotency key — so a double dispatch commits once. The test of a Guardian is then whether its *authority accounting* stays consistent with that reconciled truth. (This differs from the base Layer B ledger, which has no idempotency backstop; there the Guardian must prevent the double-spend itself. The two ledgers model two different questions.)
- A **well-behaved agent** drives the wire: it honours each verdict, and after a policy change it consults the Guardian's reservation state before dispatching, dispatching only what the Guardian still holds.
- Limit changes, revocation, and basis drift are injected through out-of-band `control/*` methods rather than ACS wire hooks. They model the authorization-state changes a Guardian receives from policy, not from agent traffic; the admission and reconciliation decisions themselves run over the ACS wire (`steps/toolCallRequest`, `steps/toolCallResult`).

Each case is scored on the **one property it isolates**, not a single notion of pass/fail, because the cases isolate different things.

## The ten cases

Measured by `matrix.py`, re-derived from the transcript by `verify.py`. `reconciling` is the model above; `naive` is a foil that releases on a lost ack, does not re-admit on a limit cut, treats a resend as new work, frees a partial-fulfilment remainder, and does not flag.

| Case | What it isolates | reconciling | naive |
|---|---|---|---|
| T1 | undispatched reservation re-admitted on a limit cut (ledger stays ≤ the new limit) | PASS | FAIL (overshoots to 80) |
| T2 | a pre-cut in-flight commit over the new limit is **flagged** as an overrun, not silent | PASS | FAIL (silent) |
| T3 | lost ack, no committed effect: reservation released, fresh retry denied against the cut | PASS | PASS |
| T4a | definition digest drift, **enforced**: operation held for reauthorization, never commits | PASS | n/a |
| T4b | definition digest drift, **recorded-not-enforced**: commits, but the attempt is flagged | PASS | n/a |
| T5 | a transport resend of a known `operation_id` is idempotent (allowed once; books = ledger) | PASS | FAIL (rejects it as new work) |
| T6 | a limit cut below already-committed consumption flags an overrun on the grant | PASS | FAIL (silent) |
| T7 | revocation releases the not-yet-dispatched; nothing new commits; a prior commit isn't retro-flagged | PASS | FAIL (dispatches past revocation) |
| T8 | partial fulfilment (ERP confirms 20 of 40): consumption counts the confirmed effect, the remainder stays reserved until the key closes, then a fill after close is counted and the grant is flagged **reconciliation_required**; a competing op is denied while the remainder is held | PASS | FAIL (frees the remainder; a competing op is admitted and the late fill double-spends to 120, unflagged) |
| T9 | unchanged definition digest, changed server behaviour: a digest attests the declaration, not the behaviour — an **expected-miss** by construction | E-MISS | n/a |

T3 passing for both is the point of T3: a correct **release** on a confirmed non-effect is as required as holding on an unresolved one. T4 is an enforcement posture rather than a foil, so it runs against the reconciling Guardian under both settings. T9 is not scored pass/fail: it is an **expected-miss**, the executable statement that attestation-by-digest is necessary but not sufficient — the digest proves the declaration is stable and says nothing about the behaviour behind it, so no honest digest-based check could catch this, and the suite records the ceiling rather than pretending to cover it. Flagging it would be a false positive, which is the fail condition.

## Two further axes, now executable

**Commitment-boundary sweep.** The boundary is a declared per-grant parameter (`control/setBoundary`), not a fixed assumption. The sweep advances op-B to each pre-cut stage, cuts the limit 100 → 60, and runs that against each boundary. Running stage × boundary, rather than fixing op-B at dispatched, separates boundaries a dispatched-only setup conflates: a queued-but-not-dispatched op is immune at queue_admission yet re-admitted at dispatch. This refinement is due to Paolo Costanzo, who noted the original dispatched-only sweep could not tell the two apart. Committed total per cell; immune (80) when op-B's stage is at or beyond the boundary, else re-admitted (40):

| op-B stage \ boundary | queue_admission | dispatch | resource_acceptance | transaction_commit |
|---|---|---|---|---|
| queued | 80 | 40 | 40 | 40 |
| dispatched | 80 | 80 | 40 | 40 |
| resource_accepted | 80 | 80 | 80 | 40 |

The earlier the boundary relative to the operation's stage, the more of the operation sits past it, so the grant absorbs a larger overrun: Paolo's observation, measured. Which boundary §5.1 should mandate per action class is still an open normative question (below); the suite makes the consequence of each choice concrete.

**Non-idempotent ledger variant.** The matrix ledger is idempotent on `operation_id` by default, but that is a switch. Running a transport resend of op-B against both ledgers, with a `resource-reliant` Guardian alongside `reconciling`, separates a guarantee the Guardian provides from one the resource provides:

| Guardian | idempotent ledger | non-idempotent ledger |
|---|---|---|
| `reconciling` (stable operation_id) | HOLD (80) | HOLD (80) |
| `resource-reliant` (trusts the ERP key) | HOLD (80) | DOUBLE-SPEND (120) |

`reconciling` holds under both because it binds consumption to the operation itself. `resource-reliant` holds only while the resource dedupes; flip the resource and the guarantee is gone, and the Guardian's own books do not even register the second commit. That is the line between a Guardian-provided and a resource-provided guarantee, made testable.

## What is open, and not silently chosen

The thread has not settled these, and neither does this suite. It encodes one reading and says so:

1. **Which boundary is normative.** The boundary is now a declared parameter and the sweep runs the cases at each (above). What stays open is the normative choice Boris and t-iida are weighing: whether §5.1 should mandate a specific boundary per action class, and which one. The suite measures the consequence of each; it does not pick one.
2. **Is a committed overrun (T2) a violation or valid-plus-reconcile?** Paolo's open question #1. This encodes reading **(a)**: valid at admission, the overrun flagged on the grant — not reading (b), where the effective limit simply cannot drop below consumed-plus-in-flight. The gap measured is identical (20 in T2); only its label differs.
3. **Partial fulfilment** (the ERP confirms 20 of 40) — Paolo's open question #2 — is **encoded as T8**, following the rule Paolo specified: consumption counts the confirmed effect (60), the remaining 20 stays reserved until the ERP confirms no more fills or the key's deadline passes, only then released; and a fill arriving after that is handled like a commit after a non_effect verdict, counted with the grant flagged `reconciliation_required`. The competing-op denial while the remainder is held shows the reservation is real, not cosmetic. What stays open is whether a late fill should be allowed to exceed the grant at all, or only logged for reconciliation as encoded here.
4. **Per-attempt records.** The operation/attempt split is encoded as a stable `operation_id` with idempotent resend, which covers the transport-resend case (T5). A distinct `attempt_id` carrying its own matched/mismatched authorization record, as in Paolo's scenario, is not yet modeled separately; a basis mismatch is flagged on the operation. Per-attempt records are the other extension I'd add.

## Reproduce

```
python3 matrix.py
python3 verify.py
```

`verify.py` re-derives every verdict above from `results/matrix_transcript.jsonl` and re-hashes the sources against `results/manifest.json`. If a verdict does not reproduce from the transcript, it does not count.

## Mapping

Delegated-authority / cumulative-limit, and the retry/revocation/basis-drift variants → OWASP Agentic **ASI03** (Identity & Privilege Abuse). The authority-basis-drift cases (T4) also touch **ASI02** (Tool Misuse) where a redefined tool changes behaviour under an unchanged name.
