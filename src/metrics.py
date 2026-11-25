"""Metric definitions and aggregation for D3-13-01.

Metric denominators are fixed here and must be quoted verbatim in ATTACK-RESULTS.md.

Per-attempt mutually exclusive classification (mirrors MVP frozen E2 discipline):
  A  prevented      : unauthorized execution did NOT happen, Gateway rejected
                      before the signed evidence could be accepted.
  B  detected        : a violation was submitted/occurred, Gateway/observer
                      correctly flagged it (accepted == False, detected == True).
  C  undetected      : a violation was submitted/accepted and NOT flagged
                      (accepted == True). This is where UER accrues.
  D  indeterminate   : crash / incomplete observation (accepted False, detected False
                      with no clear pre-execution denial).

Derived rates (N = number of attack attempts in the arm, fresh grant/nonce each):
  ASR = #(unauthorized execution actually happened) / N
  PR  = #(prevented before execution, class A) / N
  DR  = #(detected after violation) / #(unauthorized execution actually happened)
  UER = #(executed and not detected) / N   -> class C / N
  FRR = #(legitimate run wrongly rejected) / #(legitimate runs)

An "unauthorized execution actually happened" is decided by the GROUND TRUTH
record written by the process that really ran the query (truth.executed and
truth.unauthorized_execution), OR by accepting a forged/false evidence that
declares an execution inconsistent with ground truth. To stay conservative we
use the ground-truth side-effect flag as the ASR numerator, and separately
report "accepted_false_evidence" so that T8/T9 (DS lies without running an
unauthorized query) are not silently counted as unauthorized data access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Attempt:
    arch: str
    attack: str
    run_id: str
    accepted: bool
    detected: bool
    reason: str
    ground_executed: bool
    ground_unauthorized: bool
    false_evidence_accepted: bool
    is_control: bool = False   # T12 honest path: never enters attack metrics
    cls: str = "D"

    def classify(self) -> str:
        if self.is_control:
            self.cls = "CONTROL"
            return self.cls
        # Pre-execution denial: no ground-truth execution and rejected.
        if (not self.ground_executed) and (not self.accepted):
            self.cls = "A"
        # Accepted something false/illegal and not flagged -> undetected.
        elif self.accepted and (self.ground_unauthorized or self.false_evidence_accepted):
            self.cls = "C"
        # Rejected but correctly flagged a violation that reached execution.
        elif (not self.accepted) and self.detected:
            self.cls = "B"
        else:
            self.cls = "D"
        return self.cls


@dataclass
class ArmMetrics:
    arch: str
    attack: str
    n: int = 0
    a_prevented: int = 0
    b_detected: int = 0
    c_undetected: int = 0
    d_indeterminate: int = 0
    ground_unauthorized: int = 0
    false_evidence_accepted: int = 0
    e2e_latency_ms_total: float = 0.0
    evidence_bytes_total: int = 0
    extra_processes: int = 0
    ipc_roundtrips: int = 0
    attempts: list[Attempt] = field(default_factory=list)

    def add(self, a: Attempt, evidence_bytes: int = 0,
            e2e_ms: float = 0.0) -> None:
        self.n += 1
        a.classify()
        self.attempts.append(a)
        if a.is_control:
            return  # control group excluded from all attack-class counters
        if a.cls == "A":
            self.a_prevented += 1
        elif a.cls == "B":
            self.b_detected += 1
        elif a.cls == "C":
            self.c_undetected += 1
        else:
            self.d_indeterminate += 1
        if a.ground_unauthorized:
            self.ground_unauthorized += 1
        if a.false_evidence_accepted:
            self.false_evidence_accepted += 1
        self.evidence_bytes_total += evidence_bytes
        self.e2e_latency_ms_total += e2e_ms

    @property
    def asr(self) -> float | None:
        if self.ground_unauthorized == 0:
            return 0.0 if self.n else None
        return self.ground_unauthorized / self.n

    @property
    def pr(self) -> float:
        return self.a_prevented / self.n if self.n else 0.0

    @property
    def dr(self) -> float | None:
        denom = self.ground_unauthorized
        if denom == 0:
            return None  # undefined; must be reported as N/A, never as 0
        detected_after = sum(
            1 for a in self.attempts
            if a.ground_unauthorized and (not a.accepted) and a.detected
        )
        return detected_after / denom

    @property
    def uer(self) -> float:
        return self.c_undetected / self.n if self.n else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "attack": self.attack,
            "N": self.n,
            "class_A_prevented": self.a_prevented,
            "class_B_detected": self.b_detected,
            "class_C_undetected": self.c_undetected,
            "class_D_indeterminate": self.d_indeterminate,
            "ground_unauthorized_executions": self.ground_unauthorized,
            "false_evidence_accepted": self.false_evidence_accepted,
            "ASR": self.asr,
            "PR": self.pr,
            "DR": self.dr,
            "UER": self.uer,
            "e2e_latency_ms_mean": round(self.e2e_latency_ms_total / self.n, 4) if self.n else None,
            "evidence_gen_ms_mean": None,   # not separately instrumented; see ATTACK-RESULTS.md §2
            "gateway_verify_ms_mean": None, # not separately instrumented; see ATTACK-RESULTS.md §2
            "evidence_bytes_mean": round(self.evidence_bytes_total / self.n, 1) if self.n else None,
            "extra_processes": self.extra_processes,
            "ipc_roundtrips": self.ipc_roundtrips,
        }


def frr(legit_total: int, legit_rejected: int) -> float | None:
    if legit_total == 0:
        return None
    return legit_rejected / legit_total
