"""Deterministic attack replay driver for D3-13-01.

For each architecture (A/B/C/D) we replay attacks T1..T12, N=100 fresh
grant/nonce instances each, fixed seed. Raw per-attempt records and aggregate
metrics are written to results/attack_results.json.

Scope guard: this is a controlled, single-host, mock/process-level simulation.
No production TEE, no real remote data service, no Halo2. Results are NOT
extrapolated to production systems.
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
    ArchDIndependentObserver,
    Verdict,
)
from .consistency import evidence_is_false
from .metrics import ArmMetrics, Attempt
from .model import SignedGrant, issue_grant, make_call, DEMO_CONTEXT
from .primitives import Ed25519Signer, canonical_json

SEED = 20261125
REPEATS = int(os.environ.get("D3_13_REPEATS", "100"))
ARCHITECTURES = ["A", "B", "C", "D"]
ATTACKS = [f"T{i}" for i in range(1, 13)]

# Which attacks are applicable per architecture. N/A entries are recorded as
# such (never silently omitted) so the coverage table is auditable.
APPLICABLE: dict[str, set[str]] = {
    "A": {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"},
    "B": {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"},
    "C": {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"},
    "D": {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"},
}

# Ground-truth flag for whether a given attack, when it succeeds, corresponds
# to an unauthorized execution actually happening at the data layer.
# T8/T9: DS signs a false result; for T8 no real unauthorized query runs
# (ground flag from process), for T9 a colluding DS does run a Finance query.
FALSE_EVIDENCE_ATTACKS = {"T1", "T2", "T3", "T4", "T6", "T7", "T8", "T10"}


def _grant_for(issuer: Ed25519Signer, attack: str, nonce: str, i: int) -> SignedGrant:
    """Build a fresh grant. T11 uses an EXPIRED grant (controlled fixture)."""
    now = int(time.time())
    if attack == "T11":
        # Expired grant: expires_at in the past. Signed with the real issuer key
        # (fixture), so the only failing condition is the validity window.
        return issue_grant(
            issuer, make_call(), DEMO_CONTEXT, now=now, ttl_seconds=60,
            nonce=nonce,
            override_payload={"issued_at": now - 120, "expires_at": now - 60},
        )
    return issue_grant(issuer, make_call(), DEMO_CONTEXT, now=now, ttl_seconds=120, nonce=nonce)


def _false_evidence_flag(attack: str, truth: dict[str, Any] | None, accepted: bool,
                         observed: dict[str, Any] | None,
                         evidence_payload: dict[str, Any] | None) -> bool:
    """Accepted-and-false is decided by evidence-vs-ground-truth hash mismatch,
    not by attack name. T8/T9 (DS signs a false result with a valid key) are
    captured here; T12 (honest) is not."""
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
        return ArchDIndependentObserver(issuer, truth_shared)
    raise ValueError(key)


def _evidence_bytes(result: dict[str, Any]) -> int:
    resp = result.get("response", {})
    ev = resp.get("evidence") if isinstance(resp, dict) else None
    if isinstance(ev, dict):
        return len(canonical_json(ev))
    return 0


def _observation_summary(result: dict[str, Any]) -> dict[str, Any] | None:
    obs = result.get("observation")
    if isinstance(obs, dict) and obs.get("ok"):
        return obs.get("observation", {}).get("payload")
    return None


def run_one_pass(repeats: int) -> dict[str, Any]:
    results: dict[str, Any] = {
        "meta": {
            "stage": "D3-13-01",
            "seed": SEED,
            "repeats_per_arm": repeats,
            "python": sys.version.split()[0],
            "baseline_repo": "kaikai-cao/agent-exec-binding-mvp",
            "baseline_branch": "experiment/independent-execution-proxy",
            "baseline_head": "e327a9444ed8cea17baefbac01587b7fa77e8d39",
            "note": "single-host mock/process simulation; no production TEE; no Halo2",
        },
        "arms": [],
        "raw_samples": [],
    }

    mgr = mp.Manager()
    issuer = Ed25519Signer.generate()  # one issuer for the whole pass

    for arch_key in ARCHITECTURES:
        truth_shared = mgr.dict()
        arch = _build_arch(arch_key, issuer, truth_shared)
        try:
            for attack in ATTACKS:
                if attack not in APPLICABLE[arch_key]:
                    results["arms"].append({
                        "arch": arch_key, "attack": attack,
                        "status": "NOT_APPLICABLE",
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
                    grant = _grant_for(issuer, attack, nonce, i)
                    t0 = time.perf_counter()
                    result = arch.execute(attack, run_id, grant, request_id, nonce)
                    e2e_ms = (time.perf_counter() - t0) * 1000.0
                    verdict: Verdict = result["verdict"]

                    truth = result.get("truth")
                    if truth is None and run_id in truth_shared:
                        truth = dict(truth_shared[run_id])
                    ground_executed = bool(truth and truth.get("executed"))
                    ground_unauth = bool(truth and truth.get("unauthorized_execution"))
                    obs_payload = _observation_summary(result)
                    resp = result.get("response", {})
                    ev_payload = resp.get("evidence", {}).get("payload") if isinstance(resp, dict) else None
                    false_acc = _false_evidence_flag(attack, truth, verdict.accepted, obs_payload, ev_payload)

                    a = Attempt(
                        arch=arch_key, attack=attack, run_id=run_id,
                        accepted=verdict.accepted, detected=verdict.detected,
                        reason=verdict.reason,
                        ground_executed=ground_executed,
                        ground_unauthorized=ground_unauth,
                        false_evidence_accepted=false_acc,
                        is_control=(attack == "T12"),
                    )
                    arm.add(a, evidence_bytes=_evidence_bytes(result), e2e_ms=e2e_ms)
                    results["raw_samples"].append({
                        "run_id": run_id, "arch": arch_key, "attack": attack,
                        "accepted": a.accepted, "detected": a.detected,
                        "reason": a.reason, "class": a.cls,
                        "ground_executed": a.ground_executed,
                        "ground_unauthorized": a.ground_unauthorized,
                        "false_evidence_accepted": a.false_evidence_accepted,
                        "observation": obs_payload,
                    })
                results["arms"].append(arm.as_dict())
        finally:
            arch.close()
    return results


def _legit_frr(raw: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arch in ARCHITECTURES:
        rows = [r for r in raw if r["arch"] == arch and r["attack"] == "T12"]
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
    results["meta"]["frr_legit_T12"] = _legit_frr(results["raw_samples"])
    out_dir = Path(__file__).resolve().parent.parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "attack_results.json"
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    # Console summary (raw counts).
    print(f"SEED={SEED} REPEATS={repeats} -> {out_path}")
    for arm in results["arms"]:
        if arm.get("status") == "NOT_APPLICABLE":
            continue
        print(
            f"{arm['arch']} {arm['attack']:>3} N={arm['N']:>3} "
            f"A={arm['class_A_prevented']:>3} B={arm['class_B_detected']:>3} "
            f"C={arm['class_C_undetected']:>3} D={arm['class_D_indeterminate']:>3} "
            f"ASR={arm['ASR']} PR={arm['PR']} DR={arm['DR']} UER={arm['UER']} "
            f"reason_sample={arm.get('ground_unauthorized_executions')}"
        )
    print("FRR:", json.dumps(results["meta"]["frr_legit_T12"], ensure_ascii=False))


if __name__ == "__main__":
    main()
