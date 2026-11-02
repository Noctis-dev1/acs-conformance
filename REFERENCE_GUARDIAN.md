# Running the suite against the reference AGT Guardian

The suite is the instrument; the reference Guardian (Microsoft AGT behind the ACS wire contract, TypeScript on Bun) is a target. Nothing here needs Bun on your host — stand the Guardian up in a disposable container and point the suite (plain Python) at it.

> Note on scope: the AGT reference Guardian is a governance toolkit, not a cumulative-grant budget enforcer. Pointing Layer B's scenarios at it tests whether it enforces that invariant at all — a result either way, and the honest thing to report. Layer A (protocol) applies to it directly.

## Isolated run (Docker)

```bash
# 1. clone into a throwaway dir (never your project tree)
mkdir -p /tmp/acs-ref && git clone --branch integration \
  https://github.com/GenAI-Security-Project/agent-control-standard /tmp/acs-ref/src

# 2. run the Guardian inside the official Bun image, isolated, port-mapped
docker run --rm -it -p 8787:8787 -v /tmp/acs-ref/src:/app -w /app \
  oven/bun:1 sh -c "cd reference-implementations/agt && bun install && bun run guardian"

# 3. from the host, point the suite at it
python3 run_conformance.py --guardian-url http://localhost:8787/acs
python3 verify.py
```

`bun install` pulls an npm dependency tree and may run postinstall scripts, which is why this runs in a container and not on your main machine — consistent with keeping the trading Mac clean and isolating unvetted builds (the RF bench VM is the other place this belongs). Tear it down with `rm -rf /tmp/acs-ref` and the container is `--rm`.

## If the Guardian's endpoint or command differs

The repo's `reference-implementations/agt/` README is authoritative for the exact `bun run` target and port. Check `bun run` scripts there; the ACS wire path is `/acs` and the default port in the docs is 8787. If it listens elsewhere, pass that URL to `--guardian-url`.

## What to capture for the record

- Layer A: which protocol checks the reference Guardian passes.
- Layer B: its invariant scorecard. If it returns `allow` on the third concurrent `consume(40)`, the suite records the overshoot from the world ledger — the cumulative-grant gap, measured against the reference implementation itself. If it has no cumulative-grant policy at all, the suite reports `N/A` (nothing executed), never a misleading `HOLD`.
