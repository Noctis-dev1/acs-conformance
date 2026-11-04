"""
ACS Guardian conformance runner.

Two layers, pointed at any Guardian over its HTTP endpoint (--guardian-url), or at a
launched mock (--policy):

  Layer A — PROTOCOL conformance: does the Guardian speak ACS correctly? Handshake
    returns a schema-valid ServerHello (the v0.1.0 handshake.json $def requires
    negotiated_version, methods_evaluated, selected_transport, timeout_config); a
    toolCallRequest returns an AcsResult that validates against response-envelope.json;
    deny carries reasoning; an undeclared method is refused; system/ping answers (§13
    SHOULD). (§10 signing and §10.3 replay are reported as PENDING rather than asserted,
    with the ServerHello's advertised signature_algorithms_supported and skew_window_ms
    noted — see acs_wire.py.)

  Layer B — INVARIANT conformance: a protocol-perfect Guardian can still fail a security
    property. We drive adversarial steps/toolCallRequest sequences for a shared 100-unit
    grant and measure, from an independent world ledger (not the Guardian's own books),
    whether the committed total ever exceeded the grant. Three scenarios, straight from
    the delegated-authority cumulative-limit case (OWASP Agentic ASI03):
       race       - three concurrent consume(40) against a limit of 100
       continue   - one consume(40), its ack lost, then a later consume(70)
       retry      - one consume(40), its ack lost, then the same operation retried

The runner honours verdicts literally: on `allow` it executes (appends to the world
ledger); on `deny`/`ask`/`defer` it does not. The world ledger is a faithful append-only
record (no idempotency backstop), so preventing a double-spend is forced onto the
Guardian — this isolates the control plane, which is the point of a conformance test.

Writes results/transcript.jsonl and results/scorecard.json. Verify with verify.py.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time

import acs_wire as w

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
os.makedirs(RES, exist_ok=True)

LIMIT = 100
GRANT = "COMP-17"

# A single transcript collects every executed effect across scenarios, for the verifier.
_tx_lock = threading.Lock()
TRANSCRIPT: list[dict] = []


def record(policy, scenario, operation_id, amount, decision, executed, reason):
    with _tx_lock:
        TRANSCRIPT.append({"policy": policy, "scenario": scenario,
                           "operation_id": operation_id, "amount": amount,
                           "decision": decision, "executed": bool(executed),
                           "reason": reason})


def consume(client: w.GuardianClient, session, operation_id, amount, policy, scenario):
    """Send one budget.consume, honour the verdict against the world ledger."""
    env = w.tool_call_request("budget.consume",
                              {"grant_id": GRANT, "operation_id": operation_id, "amount": amount},
                              session_id=session)
    resp = client.call(env)
    decision = w.decision_of(resp)
    executed = decision in ("allow", "modify")
    result = resp.get("result") or {}
    if decision is None and "error" in resp:
        reason = f"jsonrpc_error:{resp['error'].get('code')}"
    else:
        rc = result.get("reason_codes") or []
        reason = ",".join(rc) if rc else (decision or "none")
    record(policy, scenario, operation_id, amount, decision, executed, reason)
    return decision, executed, env


def send_result(client: w.GuardianClient, session, operation_id, status):
    env = w.build_request("steps/toolCallResult",
                          {"grant_id": GRANT, "operation_id": operation_id, "status": status},
                          session_id=session)
    client.call(env)


# ---------------------------------------------------------------- Layer A: protocol -----
SERVERHELLO_REQUIRED = ("negotiated_version", "methods_evaluated", "selected_transport", "timeout_config")


def protocol_checks(client: w.GuardianClient, policy: str) -> list[dict]:
    out = []
    session = w.new_uuid()

    # A schema-valid ClientHello (handshake.json's $def requires these four). The reference
    # Guardian does not read it, but a conformance client should still send a valid one.
    client_hello = {"acs_versions_supported": [w.ACS_VERSION],
                    "methods_implemented": ["steps/toolCallRequest", "steps/toolCallResult"],
                    "transports_supported": ["http"],
                    "provenance_producer": "noctis-acs-conformance"}
    hello = client.call(w.build_request("handshake/hello", client_hello, session_id=session))
    sh = hello["result"] if isinstance(hello.get("result"), dict) else {}
    missing = [f for f in SERVERHELLO_REQUIRED if f not in sh]
    out.append({"check": "handshake returns a schema-valid ServerHello (v0.1.0 $def required fields)",
                "ok": not missing,
                "detail": f"missing required field(s): {missing}" if missing else ""})
    # Capabilities the ServerHello advertises; the §10 / §10.3 checks read these.
    sig_algs = sh.get("signature_algorithms_supported") or []
    skew = sh.get("skew_window_ms")

    ping = client.call(w.build_request("system/ping", {}, session_id=session))
    if "error" not in ping:
        out.append({"check": "system/ping answers (liveness probe)", "ok": True, "detail": ""})
    else:
        # Normativity is unsettled: handshake.json says clients SHOULD include system/ping,
        # while hooks/system-ping.json says a Guardian MUST return allow for it. We report the
        # absence as an open observation (PENDING), not a pass/fail, pending clarification.
        out.append({"check": "system/ping answers (liveness probe)", "ok": None,
                    "detail": f"no system/ping (error {ping.get('error', {}).get('code')}); normativity unsettled "
                              "(handshake.json: clients SHOULD include it; hooks/system-ping.json: a Guardian MUST "
                              "return allow) — reported as an open observation, not a failure"})

    env = w.tool_call_request("budget.consume",
                              {"grant_id": GRANT, "operation_id": w.new_uuid(), "amount": 10},
                              session_id=session)
    resp = client.call(env)
    violations = w.validate_response(resp, env)
    out.append({"check": "toolCallRequest returns schema-valid AcsResult",
                "ok": not violations, "detail": violations})

    bogus = client.call(w.build_request("steps/doesNotExist", {}, session_id=session))
    out.append({"check": "undeclared method is refused (JSON-RPC error)",
                "ok": "error" in bogus})

    out.append({"check": "§10 signature verification", "ok": None,
                "detail": (f"PENDING: ServerHello advertises signature_algorithms_supported={sig_algs}; the next build "
                           "step sends a JCS/RFC-8785-canonicalized signed envelope and asserts a bad signature is rejected"
                           if sig_algs else
                           "PENDING: ServerHello advertises no signature_algorithms_supported — this Guardian does not "
                           "require §10 signatures; a signed-envelope test still needs JCS/RFC-8785 pinned")})
    out.append({"check": "§10.3 replay/timestamp rejection", "ok": None,
                "detail": (f"PENDING: ServerHello advertises skew_window_ms={skew}; a timestamp outside that window and a "
                           "replayed nonce should both be rejected — test to be built against the advertised window"
                           if skew is not None else
                           "PENDING: ServerHello advertises no skew_window_ms — the acceptance window is unspecified")})
    return out


# ---------------------------------------------------------------- Layer B: invariant ----
def scenario_race(client, policy):
    session = w.new_uuid()
    barrier = threading.Barrier(3)

    def worker(i):
        barrier.wait()                       # three concurrent arrivals
        consume(client, session, f"op-{i}", 40, policy, "race")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # confirm whatever was allowed
    for e in [t for t in TRANSCRIPT if t["policy"] == policy and t["scenario"] == "race" and t["executed"]]:
        send_result(client, session, e["operation_id"], "committed")


def scenario_continue(client, policy):
    session = w.new_uuid()
    consume(client, session, "L1", 40, policy, "continue")      # commits
    send_result(client, session, "L1", "unresolved")            # ack lost
    consume(client, session, "L2", 70, policy, "continue")      # a later, unrelated op


def scenario_retry(client, policy):
    session = w.new_uuid()
    consume(client, session, "L1", 40, policy, "retry")         # commits
    send_result(client, session, "L1", "unresolved")            # ack lost
    consume(client, session, "L1", 40, policy, "retry")         # retry the SAME operation


def committed_for(policy, scenario) -> int:
    return sum(t["amount"] for t in TRANSCRIPT
               if t["policy"] == policy and t["scenario"] == scenario and t["executed"])


def executed_count(policy, scenario) -> int:
    return sum(1 for t in TRANSCRIPT
               if t["policy"] == policy and t["scenario"] == scenario and t["executed"])


def dominant_reason(policy, scenario) -> str:
    reasons = [t["reason"] for t in TRANSCRIPT
               if t["policy"] == policy and t["scenario"] == scenario]
    return max(set(reasons), key=reasons.count) if reasons else "none"


def scenario_verdict(policy, scenario, committed) -> str:
    # A scenario is only meaningful if the Guardian actually allowed the legitimate
    # baseline. If it executed nothing (denied/errored everything), the invariant held
    # only vacuously — report N/A with the reason, never a misleading HOLD.
    if executed_count(policy, scenario) == 0:
        return f"N/A ({dominant_reason(policy, scenario)})"
    if scenario == "race":
        return "HOLD" if committed <= LIMIT else "OVERSHOOT"
    if scenario == "continue":
        return "HOLD" if committed <= LIMIT else "LEAK"
    return "HOLD" if committed <= 40 else "DOUBLE-SPEND"


def run_against(client: w.GuardianClient, policy: str) -> dict:
    protocol = protocol_checks(client, policy)
    scenario_race(client, policy)
    scenario_continue(client, policy)
    scenario_retry(client, policy)
    sc = {s: committed_for(policy, s) for s in ("race", "continue", "retry")}
    verdict = {s: scenario_verdict(policy, s, sc[s]) for s in ("race", "continue", "retry")}
    return {"policy": policy, "limit": LIMIT, "protocol": protocol,
            "committed": sc, "verdict": verdict}


def selftest() -> list[dict]:
    """Launch each mock policy in-process and run the full suite against it."""
    import mock_guardians.guardian as g
    scorecards = []
    port = 8830
    for policy in ("stateless", "reserve-only", "holding"):
        srv = g.make_server(policy, port, LIMIT)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        time.sleep(0.2)
        client = w.GuardianClient(f"http://127.0.0.1:{port}/acs")
        scorecards.append(run_against(client, policy))
        srv.shutdown()
        port += 1
    return scorecards


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guardian-url", help="run against an external Guardian at this URL")
    ap.add_argument("--policy", choices=["stateless", "reserve-only", "holding"],
                    help="launch a mock Guardian of this policy and run against it")
    ap.add_argument("--selftest", action="store_true", help="run all mock policies")
    args = ap.parse_args()

    if args.selftest or (not args.guardian_url and not args.policy):
        scorecards = selftest()
        label = "selftest (all mock policies)"
    elif args.guardian_url:
        scorecards = [run_against(w.GuardianClient(args.guardian_url), "external")]
        label = args.guardian_url
    else:
        import mock_guardians.guardian as g
        srv = g.make_server(args.policy, 8829, LIMIT)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        scorecards = [run_against(w.GuardianClient("http://127.0.0.1:8829/acs"), args.policy)]
        srv.shutdown()
        label = f"mock:{args.policy}"

    with open(os.path.join(RES, "transcript.jsonl"), "w") as f:
        for t in TRANSCRIPT:
            f.write(json.dumps(t) + "\n")
    with open(os.path.join(RES, "scorecard.json"), "w") as f:
        json.dump({"target": label, "limit": LIMIT, "scorecards": scorecards}, f, indent=2)

    # manifest for the verifier
    import hashlib
    man = {"limit": LIMIT, "src_sha256": {}}
    for src in ("acs_wire.py", "run_conformance.py", os.path.join("mock_guardians", "guardian.py"),
                os.path.join("mock_guardians", "reconciling.py"), "matrix.py", "comparison.py", "verify.py"):
        p = os.path.join(HERE, src)
        if os.path.exists(p):
            man["src_sha256"][src] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with open(os.path.join(RES, "manifest.json"), "w") as f:
        json.dump(man, f, indent=2)

    print(f"ACS Guardian conformance — target: {label}\n")
    print("Layer A — protocol conformance"
          + ("  (representative; all mock policies are protocol-conformant by design)"
             if len(scorecards) > 1 else ""))
    for c in scorecards[0]["protocol"]:
        mark = {True: "PASS", False: "FAIL", None: "PENDING"}[c["ok"]]
        extra = f"  ({c['detail']})" if c.get("detail") and mark != "PASS" else ""
        print(f"  [{mark:<7}] {c['check']}{extra}")
    def short(v):  # keep the table aligned; N/A reasons go to a footnote
        return "N/A" if v.startswith("N/A") else v

    print("\nLayer B — invariant conformance (does the Guardian hold the limit of 100?)")
    print(f"  {'policy':<14}{'race 3x40':<18}{'lost-ack continue':<20}{'lost-ack retry':<20}")
    notes = []
    for row in scorecards:
        v, c = row["verdict"], row["committed"]
        race = f"{short(v['race'])} ({c['race']})"
        cont = f"{short(v['continue'])} ({c['continue']})"
        retry = f"{short(v['retry'])} ({c['retry']})"
        print(f"  {row['policy']:<14}{race:<18}{cont:<20}{retry:<20}")
        for scen in ("race", "continue", "retry"):
            if v[scen].startswith("N/A"):
                notes.append(f"  {row['policy']}/{scen}: {v[scen]} — nothing was allowed, so the invariant held only vacuously")
    for n in dict.fromkeys(notes):
        print(n)
    print(f"\nFrozen evidence in {RES}/  —  verify with: python3 verify.py")


if __name__ == "__main__":
    main()
