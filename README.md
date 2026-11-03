# acs-conformance

An independent, language-independent conformance suite for OWASP **Agent Control Standard (ACS)** v0.1.0 Guardians. It points at any Guardian over its HTTP endpoint and asks two questions:

1. **Protocol conformance (Layer A)** — does the Guardian speak ACS correctly? Handshake/ServerHello, schema-valid decision envelopes, refusal of undeclared methods, `system/ping`, and (pending the §10 canonicalization) signature and replay rejection.
2. **Invariant conformance (Layer B)** — does a *protocol-perfect* Guardian actually preserve a security invariant? ACS-Core states it "does not assert that policies are strict." This layer drives the delegated-authority, cumulative-limit scenarios (OWASP Agentic ASI03) — a shared grant consumed under concurrency, lost acknowledgements, and retries — and measures, from an independent world ledger, whether the committed total ever exceeds the grant.

Built in response to [issue #311](https://github.com/GenAI-Security-Project/agent-control-standard/issues/311) (a language-independent Guardian contract test suite) and issue #19 (no independent conformance steward in v0.1.0).

## Quickstart

```
python3 run_conformance.py --selftest          # Layer A + B against the three bundled mock Guardians
python3 matrix.py                              # the T1–T9 reconciliation matrix (OWASP §5.1 cases)
python3 verify.py                              # re-derive every verdict from the wire transcripts
python3 run_conformance.py --guardian-url http://localhost:8787/acs   # point Layer A/B at a real Guardian
```

Standard library only. No dependencies.

## What it finds (bundled mock Guardians)

All three mocks are protocol-conformant. Only one holds the invariant.

| Guardian | race 3×40 | lost-ack continue | lost-ack retry |
|---|---|---|---|
| stateless | OVERSHOOT (120) | LEAK (110) | DOUBLE-SPEND (80) |
| reserve-only | HOLD (80) | LEAK (110) | DOUBLE-SPEND (80) |
| holding | HOLD (80) | HOLD (40) | HOLD (40) |

The point of Layer B in one line: a destination that passes the test everyone writes (concurrency) can still fail the two almost nobody writes — a reservation auto-released on a lost acknowledgement (leak) and a retry that is not bound to a stable operation identity (double-spend). Only `holding` — atomic reservation + stable-operation-id binding + holding the pending reservation on a lost ack — keeps the limit under all three. Full write-up in [SCENARIO.md](SCENARIO.md).

## The T1–T9 reconciliation matrix

The OWASP delegated-authority discussion took the 3×40 case well past the race, into a full reconciliation model: an operation/attempt split, holding a reservation on a lost acknowledgement, ordered admission, limit changes mid-flight, revocation, authority-basis drift (a tool redefined under an unchanged name), partial fulfilment, and behaviour drift under an unchanged digest. Those cases (T1–T9) live in that thread as prose. `matrix.py` makes them executable and measures each one from an independent, `operation_id`-idempotent ERP ledger.

| | T1 | T2 | T3 | T4a | T4b | T5 | T6 | T7 | T8 | T9 |
|---|---|---|---|---|---|---|---|---|---|---|
| `reconciling` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | E-MISS |
| `naive` | FAIL | FAIL | PASS | n/a | n/a | FAIL | FAIL | FAIL | FAIL | n/a |

T8 is partial fulfilment (the ERP confirms 20 of a 40-unit request; consumption counts the confirmed effect, the remainder stays reserved until the key closes, and a fill after close is counted and the grant flagged `reconciliation_required`). T9 is an **expected-miss**: a digest attests the declaration, not the behaviour behind it, so a changed-behaviour/unchanged-digest case is outside what any digest check can catch — the suite records the ceiling rather than pretending to cover it. `matrix.py` also runs a commitment-boundary sweep (each pre-cut stage against each declared boundary, 12 cells) and a non-idempotent ledger variant (separating a guarantee the Guardian provides from one the resource provides). The model is credited to the thread's participants; the encoding, and the questions it does not pretend to settle (which boundary is normative, whether a committed overrun is a violation), are written up in [SCENARIO_T1_T9.md](SCENARIO_T1_T9.md).

## Running it against the real reference Guardian

The suite is the instrument; the AGT reference Guardian is a target. See [REFERENCE_GUARDIAN.md](REFERENCE_GUARDIAN.md) for standing the reference Guardian up in an isolated container and pointing the suite at it.

## Integrity

`verify.py` recomputes every invariant verdict from `results/transcript.jsonl` — the recorded wire effects, not the runner's own flags — summing the amounts the suite actually executed on each honoured `allow`, re-deriving HOLD / OVERSHOOT / LEAK / DOUBLE-SPEND, and flagging any operation that committed more than once. It re-hashes the sources against `results/manifest.json` and exits non-zero if anything fails to reproduce.

## Scope, stated plainly

The world ledger is modelled as a faithful append-only record with **no idempotency backstop**, so preventing a double-spend is forced onto the control plane — this isolates the Guardian, which is the point of a conformance test (a production ERP with an idempotency key would also stop a double-spend). Layer A's §10 HMAC signing over the JCS/RFC-8785 canonicalization and §10.3 replay window are reported as PENDING, not asserted, until confirmed against the specification. The suite measures the wire; it does not inspect a Guardian's internals.

## Credits

The reconciliation model (Layer B and the T1–T9 matrix) comes from the OWASP GenAI Security Project's delegated-authority discussion:

- [Boris Abuzov](https://github.com/boris-ai-sec) ([borisabuzov.com](https://borisabuzov.com)) — the 3×40 cumulative-grant case, the operation/attempt split, and holding the reservation on a lost acknowledgement.
- t-iida — the lost-ack boundary and stop-or-reauthorize.
- Sol_ni_shko — ordered admission.
- Paolo Costanzo — authority-basis drift and the T1–T7 scenario.

The encoding here is mine and may differ from their intent; corrections welcome.

## License

Apache-2.0 (see [LICENSE](LICENSE)), matching the upstream ACS project. Copyright © 2026 Malachi Zion Kopman.
