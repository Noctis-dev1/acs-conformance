# The T1–T7 reconciliation matrix, made executable

*The OWASP GenAI Security Project's delegated-authority discussion produced a set of reconciliation test cases — the 3×40 cumulative-grant race and its lost-ack, revocation, limit-change, and basis-drift variants. They exist as prose. This runs them, and measures each from an independent ledger.*

**Suite:** `matrix.py` · **Guardian:** `mock_guardians/reconciling.py` · **Verifier:** `verify.py` · **Target contract:** ACS v0.1.0 Guardian wire (JSON-RPC 2.0 over HTTP).

## The model, and whose it is

The reconciling Guardian encodes the design the thread converged on:

- the **operation / attempt split** and **holding the reservation on a lost acknowledgement** (Boris Abuzov),
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

## The eight cases

Measured by `matrix.py`, re-derived from the transcript by `verify.py`. `reconciling` is the model above; `naive` is a foil that releases on a lost ack, does not re-admit on a limit cut, treats a resend as new work, and does not flag.

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

T3 passing for both is the point of T3: a correct **release** on a confirmed non-effect is as required as holding on an unresolved one. T4 is an enforcement posture rather than a foil, so it runs against the reconciling Guardian under both settings.

## What is open, and not silently chosen

The thread has not settled these, and neither does this suite. It encodes one reading and says so:

1. **Commitment boundary.** Boris's point that "first dispatch" should not be universal, but one of several possible boundaries (queue admission, dispatch, resource acceptance, transaction commit), is right. This suite fixes the boundary at **dispatch**, isolated at a single point so the cases can be re-run at the others without a rewrite. That sweep is a planned extension, not yet implemented.
2. **Is a committed overrun (T2) a violation or valid-plus-reconcile?** Paolo's open question #1. This encodes reading **(a)**: valid at admission, the overrun flagged on the grant — not reading (b), where the effective limit simply cannot drop below consumed-plus-in-flight. The gap measured is identical (20 in T2); only its label differs.
3. **Partial fulfilment** (the ERP fills 20 of 40) — Paolo's open question #2 — is **not yet encoded**. The intended shape, from the thread, is a confirmed effect carrying an observed amount (requested 40 / observed 20) with the remainder reserved until the ERP closes the key. It is the next case to add.
4. **Per-attempt records.** The operation/attempt split is encoded as a stable `operation_id` with idempotent resend, which covers the transport-resend case (T5). A distinct `attempt_id` carrying its own matched/mismatched authorization record, as in Paolo's scenario, is not yet modeled separately; a basis mismatch is flagged on the operation. Per-attempt records are the other extension I'd add.

## Reproduce

```
python3 matrix.py
python3 verify.py
```

`verify.py` re-derives every verdict above from `results/matrix_transcript.jsonl` and re-hashes the sources against `results/manifest.json`. If a verdict does not reproduce from the transcript, it does not count.

## Mapping

Delegated-authority / cumulative-limit, and the retry/revocation/basis-drift variants → OWASP Agentic **ASI03** (Identity & Privilege Abuse). The authority-basis-drift cases (T4) also touch **ASI02** (Tool Misuse) where a redefined tool changes behaviour under an unchanged name.
