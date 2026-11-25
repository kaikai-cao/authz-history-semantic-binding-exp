"""Deterministic attack replay driver for D3-13-01-R1.

R1 corrections:
  * Explicit applicability matrix (38 arms: A7 / B9 / C11 / D11). N/A arms are
    written to the JSON, never silently omitted or remapped.
  * One historical seed request per architecture, minted and stored BEFORE the
    attack arms; T5 replays it verbatim. Seed requests are logged in
    meta.seed_requests and are NOT counted in any attack N.
  * Ground truth per attempt records actual_query_where,
    actual_query_result_digest, returned_output_digest, executed,
    unauthorized_execution, unauthorized_result_disclosure, executor_role, note.
  * Evidence bytes: C = DS evidence, D = DS evidence + Observer evidence.
  * Only e2e wall-clock latency is reported (no fabricated gen/verify split,
    no unverified process-startup timing claim).

Totals at N=100: 34 attack arms x 100 = 3400 attack attempts;
4 T12 control arms x 100 = 400 benign controls; 3800 formal trials.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from typing import Any

from .architectures import (
    ArchAAdapterReceipt,
    ArchBIndependentProxy,
    ArchCSignedDataService,
    ArchDOracleAssistedObserver,
    Verdict,
)
from .consistency import evidence_is_false
from .metrics import ArmMetrics, Attempt
from .model import (
    SEED_NONCE,
    SEED_REQUEST_ID,
    SEED_RUN_ID,
    SignedGrant,
    build_truth,
    issue_grant,
    make_call,
    DEMO_CONTEXT,
    result_within_grant,
)
from .primitives import Ed25519Signer, canonical_json, digest_object

SEED = 20261125
REPEATS = int(os.environ.get("D3_13_REPEATS", "100"))
ARCHITECTURES = ["A", "B", "C", "D"]
ATTACKS = [f"T{i}" for i in range(1, 13)]

# R1 Phase 1 fixed applicability matrix. N/A = the architecture has no such
# role or evidence field; it is recorded in JSON, never remapped.
APPLICABLE: dict[str, set[str]] = {
    "A": {"T1", "T2", "T4", "T5", "T10", "T11", "T12"},
    "B": {"T1", "T2", "T3", "T4", "T5", "T6", "T10", "T11", "T12"},
    "C": {"T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"},
    "D": {"T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"},
}

# Why an arm is N/A (never remapped to a different attack).
NA_REASON: dict[str, dict[str, str]] = {
    "A": {
        "T3": "A has no independent Proxy signing identity; Adapter self-signs (covered by T1).",
        "T6": "Adapter Receipt has no independent source_id/snapshot_id/query evidence fields.",
        "T7": "A has no separate Data Service identity to forge.",
        "T8": "A has no independent Data Service; the executor already signs its own receipt.",
        "T9": "A has no Proxy/Data Service pair to collude.",
    },
    "B": {
        "T7": "B has no separate Data Service identity; proxy self-signature is covered by T3.",
        "T8": "B has no independent Data Service; the proxy signs its own evidence.",
        "T9": "B has no Proxy/Data Service pair to collude.",
    },
    "C": {"T1": "C no longer uses the MVP Adapter Receipt as trusted evidence; proxy self-forgery is T3/T7."},
    "D": {"T1": "D no longer uses the MVP Adapter Receipt as trusted evidence; proxy self-forgery is T3/T7."},
}


def _grant_for(issuer: Ed25519Signer, attack: str, nonce: str) -> SignedGrant:
    """Fresh grant per attempt. T11 = expired grant only (no snapshot-expiry test)."""
    now = int(time.time())
    if attack == "T11":
        return issue_grant(
            issuer, make_call(), DEMO_CONTEXT, now=now, ttl_seconds=60,
            nonce=nonce,
            override_payload={"issued_at": now - 120, "expires_at": now - 60},
        )
    return issue_grant(issuer, make_call(), DEMO_CONTEXT, now=now, ttl_seconds=120, nonce=nonce)


def _false_evidence_flag(evidence_payload: dict[str, Any] | None,
                         truth: dict[str, Any] | None,
                         accepted: bool) -> bool:
    """Accepted-and-false decided by evidence-vs-ground-truth field compare,
    never by attack name. T8/T9 (valid signature, false statement) are caught;
    T12 (honest) is not."""
    if not accepted:
        return False
    return evidence_is_false(evidence_payload, truth)


def _build_arch(key: str, issuer: Ed25519Signer, truth_shared: Any):
    if key == "A":
        return ArchAAdapterReceipt(issuer, truth_shared)
    if key == "B":
        return ArchBIndependentProxy(issuer, truth_shared)
    if key == "C":
        return ArchCSignedDataService(issuer, truth_shared)
    if key == "D":
        return ArchDOracleAssistedObserver(issuer, truth_shared)
    raise ValueError(key)


def _evidence_bytes(result: dict[str, Any], arch_key: str) -> int:
    """C: DS evidence only. D: DS evidence + Observer evidence."""
    resp = result.get("response", {})
    ev = resp.get("evidence") if isinstance(resp, dict) else None
    total = len(canonical_json(ev)) if isinstance(ev, dict) else 0
    if arch_key == "D":
        obs = result.get("observation")
        if isinstance(obs, dict) and obs.get("ok"):
            o = obs.get("observation")
            if isinstance(o, dict):
                total += len(canonical_json(o))
    return total


def _observation_summary(result: dict[str, Any]) -> dict[str, Any] | None:
    obs = result.get("observation")
    if isinstance(obs, dict) and obs.get("ok"):
        return obs.get("observation", {}).get("payload")
    return None


def _synth_no_execution_truth(run_id: str, arch_key: str, note: str) -> dict[str, Any]:
    role = {"A": "adapter", "B": "proxy",
            "C": "data_service", "D": "data_service"}[arch_key]
    return build_truth(run_id, role, False, None, None, None, note)


def run_one_pass(repeats: int) -> dict[str, Any]:
    results: dict[str, Any] = {
        "meta": {
            "stage": "D3-13-01-R1",
            "seed": SEED,
            "repeats_per_arm": repeats,
            "python": sys.version.split()[0],
            "baseline_repo": "kaikai-cao/agent-exec-binding-mvp",
            "baseline_branch": "experiment/independent-execution-proxy",
            "baseline_head": "e327a9444ed8cea17baefbac01587b7fa77e8d39",
            "r0_commit": "22cc839eb41a15ff38580ac918361ccaf5a158e2",
            "observer_model": (
                "D = Oracle-assisted Observer; truth_shared is a trusted TEST "
                "ORACLE side channel (ideal-condition upper bound), NOT production "
                "independent observation. H4 remains OPEN."
            ),
            "note": "single-host mock/process simulation; no production TEE; no Halo2",
            "seed_requests": [],
            "applicability": {k: sorted(v) for k, v in APPLICABLE.items()},
            "na_reason": NA_REASON,
        },
        "arms": [],
        "raw_samples": [],
    }

    mgr = mp.Manager()
    issuer = Ed25519Signer.generate()  # one issuer for the entire pass

    for arch_key in ARCHITECTURES:
        truth_shared = mgr.dict()
        arch = _build_arch(arch_key, issuer, truth_shared)
        try:
            # Seed request: mint and store ONE honest historical response.
            # Not counted in any attack arm's N.
            seed_desc = arch.make_seed()
            seed_desc["arch"] = arch_key
            results["meta"]["seed_requests"].append(seed_desc)

            for attack in ATTACKS:
                if attack not in APPLICABLE[arch_key]:
                    results["arms"].append({
                        "arch": arch_key, "attack": attack,
                        "status": "NOT_APPLICABLE",
                        "reason": NA_REASON.get(arch_key, {}).get(attack, "role/field absent"),
                    })
                    continue
                arm = ArmMetrics(
                    arch=arch_key, attack=attack,
                    extra_processes={"A": 0, "B": 1, "C": 2, "D": 3}[arch_key],
                    ipc_roundtrips={"A": 0, "B": 1, "C": 3, "D": 4}[arch_key],
                )
                for i in range(repeats):
                    run_id = f"{arch_key}-{attack}-{i:04d}"
                    nonce = f"{SEED}-{run_id}-nonce"
                    request_id = f"{SEED}-{run_id}-req"
                    grant = _grant_for(issuer, attack, nonce)
                    t0 = time.perf_counter()
                    result = arch.execute(attack, run_id, grant, request_id, nonce)
                    e2e_ms = (time.perf_counter() - t0) * 1000.0
                    verdict: Verdict = result["verdict"]

                    # Ground truth: prefer the executor's record; fall back to
                    # truth_shared; synthesize 'no execution' when neither exists
                    # (replay / pre-execution reject / proxy forgery).
                    truth = result.get("truth")
                    if truth is None and run_id in truth_shared:
                        truth = dict(truth_shared[run_id])
                    if truth is None:
                        truth = _synth_no_execution_truth(run_id, arch_key,
                                                          "no real execution (reject/replay/forge)")

                    # R1: returned_output_digest & disclosure are derived from
                    # what was actually handed to the Gateway, not from what the
                    # executor thought it returned (this catches T4 substitution).
                    resp = result.get("response", {})
                    final_output = resp.get("output") if isinstance(resp, dict) else None
                    returned_digest = (
                        digest_object(final_output) if final_output is not None else None
                    )
                    disclosure = bool(final_output) and not result_within_grant(final_output)
                    truth["returned_output_digest"] = returned_digest
                    truth["unauthorized_result_disclosure"] = disclosure

                    ground_executed = bool(truth.get("executed"))
                    ground_unauth = bool(truth.get("unauthorized_execution"))
                    obs_payload = _observation_summary(result)
                    ev_payload = (
                        resp.get("evidence", {}).get("payload") if isinstance(resp, dict) else None
                    )
                    false_acc = _false_evidence_flag(ev_payload, truth, verdict.accepted)

                    a = Attempt(
                        arch=arch_key, attack=attack, run_id=run_id,
                        accepted=verdict.accepted, detected=verdict.detected,
                        reason=verdict.reason,
                        ground_executed=ground_executed,
                        ground_unauthorized=ground_unauth,
                        false_evidence_accepted=false_acc,
                        unauthorized_result_disclosure=disclosure,
                        is_control=(attack == "T12"),
                    )
                    arm.add(a, evidence_bytes=_evidence_bytes(result, arch_key),
                            e2e_ms=e2e_ms)
                    results["raw_samples"].append({
                        "run_id": run_id, "arch": arch_key, "attack": attack,
                        "accepted": a.accepted, "detected": a.detected,
                        "reason": a.reason, "class": a.cls,
                        "ground_truth": {
                            "executor_role": truth.get("executor_role"),
                            "executed": truth.get("executed"),
                            "actual_query_where": truth.get("actual_query_where"),
                            "actual_query_result_digest": truth.get("actual_query_result_digest"),
                            "returned_output_digest": truth.get("returned_output_digest"),
                            "unauthorized_execution": truth.get("unauthorized_execution"),
                            "unauthorized_result_disclosure": truth.get("unauthorized_result_disclosure"),
                            "note": truth.get("note"),
                        },
                        "ground_executed": a.ground_executed,
                        "ground_unauthorized": a.ground_unauthorized,
                        "false_evidence_accepted": a.false_evidence_accepted,
                        "unauthorized_result_disclosure": a.unauthorized_result_disclosure,
                        "is_control": a.is_control,
                        "observation": obs_payload,
                    })
                results["arms"].append(arm.as_dict())
        finally:
            arch.close()

    # Totals and counts.
    na_count = sum(1 for a in results["arms"] if a.get("status") == "NOT_APPLICABLE")
    applicable_arms = [a for a in results["arms"] if a.get("status") != "NOT_APPLICABLE"]
    attack_arms = [a for a in applicable_arms if a["attack"] != "T12"]
    control_arms = [a for a in applicable_arms if a["attack"] == "T12"]
    results["meta"]["counts"] = {
        "applicable_arms": len(applicable_arms),
        "na_arms": na_count,
        "attack_arms": len(attack_arms),
        "control_arms": len(control_arms),
        "attack_attempts": sum(a["N"] for a in attack_arms),
        "benign_controls": sum(a["N"] for a in control_arms),
        "formal_trials_total": sum(a["N"] for a in applicable_arms),
        "raw_samples": len(results["raw_samples"]),
        "seed_requests_excluded": len(results["meta"]["seed_requests"]),
    }
    results["meta"]["frr_legit_T12"] = _legit_frr(results["raw_samples"])
    return results


def _legit_frr(raw: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arch in ARCHITECTURES:
        rows = [r for r in raw if r["arch"] == arch and r["attack"] == "T12"
                and r.get("is_control")]
        if not rows:
            continue
        rejected = sum(1 for r in rows if not r["accepted"])
        out[arch] = {
            "legit_runs": len(rows),
            "legit_rejected": rejected,
            "FRR": rejected / len(rows),
            "normal_accept_rate": (len(rows) - rejected) / len(rows),
        }
    return out


def main() -> None:
    repeats = REPEATS
    results = run_one_pass(repeats)
    out_dir = Path(__file__).resolve().parent.parent / "results"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "attack_results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    counts = results["meta"]["counts"]
    print(f"SEED={SEED} REPEATS={repeats} -> {out_dir / 'attack_results.json'}")
    print(f"counts={json.dumps(counts, ensure_ascii=False)}")
    for arm in results["arms"]:
        if arm.get("status") == "NOT_APPLICABLE":
            continue
        print(
            f"{arm['arch']} {arm['attack']:>3} N={arm['N']:>3} "
            f"A={arm['class_A_prevented']:>3} B={arm['class_B_detected']:>3} "
            f"C={arm['class_C_undetected']:>3} D={arm['class_D_indeterminate']:>3} "
            f"ASR={arm['ASR']} PR={arm['PR']} DR={arm['DR']} UER={arm['UER']} "
            f"disc={arm['result_disclosure_rate']}"
        )
    print("FRR:", json.dumps(results["meta"]["frr_legit_T12"], ensure_ascii=False))


if __name__ == "__main__":
    main()
