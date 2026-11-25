"""Metric definitions and aggregation for D3-13-01-R1.1.

Denominators (quote verbatim in ATTACK-RESULTS.md):
  ASR = real unauthorized query executions / attack attempts
  PR  = class A (pre-execution prevention) / attack attempts
  DR  = detected AFTER a real unauthorized execution / real unauthorized executions
        (N/A when the denominator is 0 -- never 0, never 1)
  UER = accepted false/illegal evidence without detection (class C) / attack attempts
  FRR = legit T12 runs wrongly rejected / legit T12 runs

R1.1 classification change (the core correction of this round):
  "No query executed" does NOT automatically mean "prevention". A forged/replayed
  response that REACHES the Gateway verifier and is rejected is class B
  (post-submission detection), not class A. The discriminator is the explicit
  field `gateway_verification_attempted`, set by the REAL execution path and
  NEVER inferred from `accepted`/`executed`.

Per-attempt mutually exclusive classification (strict order):
  0. T12 -> CONTROL.
  1. no execution AND response did NOT enter Gateway verification AND rejected
     -> A (pre-execution prevention).
  2. response DID enter Gateway verification AND rejected AND detected -> B
     (post-submission detection).
  3. accepted AND (real unauthorized exec OR false/illegal evidence) -> C
     (undetected acceptance).
  4. anything else -> D (indeterminate; kept and explained, never relabelled).

Output metrics (R1.1, two INDEPENDENT quantities):
  out_of_scope_output_presented : out-of-scope output submitted to the Gateway
                                  verifier (acceptance NOT required).
  out_of_scope_output_accepted  : out-of-scope output accepted by the FINAL
                                  verifier (under D: after the Observer; not the
                                  intermediate DS Gateway verdict).
  Neither proves a human end user actually read/consumed the data.
  `result_disclosure_rate` is a deprecated alias of the presented rate.
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
    gateway_verification_attempted: bool = True  # set by the real execution path
    out_of_scope_output_presented: bool = False
    out_of_scope_output_accepted: bool = False
    unauthorized_result_disclosure: bool = False  # legacy == presented
    is_control: bool = False   # T12 honest path: excluded from all attack metrics
    cls: str = "D"

    def classify(self) -> str:
        if self.is_control:
            self.cls = "CONTROL"
            return self.cls
        # 1. Pre-execution prevention: no query ran AND the attack never reached
        #    the Gateway evidence-verification flow AND it was rejected.
        if (not self.ground_executed) and (not self.gateway_verification_attempted) \
                and (not self.accepted):
            self.cls = "A"
        # 2. Post-submission detection: response DID enter the Gateway verifier,
        #    was rejected, and the anomaly was flagged.
        elif self.gateway_verification_attempted and (not self.accepted) and self.detected:
            self.cls = "B"
        # 3. Undetected acceptance of a real violation.
        elif self.accepted and (self.ground_unauthorized or self.false_evidence_accepted):
            self.cls = "C"
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
    output_presented: int = 0
    output_accepted: int = 0
    result_disclosures: int = 0  # legacy == output_presented
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
        # Latency and evidence size are observations orthogonal to attack class;
        # accumulate them for control arms too (incl. Observer evidence under D).
        self.evidence_bytes_total += evidence_bytes
        self.e2e_latency_ms_total += e2e_ms
        if a.is_control:
            return  # control excluded from all attack-class counters
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
        if a.out_of_scope_output_presented:
            self.output_presented += 1
        if a.out_of_scope_output_accepted:
            self.output_accepted += 1
        if a.unauthorized_result_disclosure:
            self.result_disclosures += 1

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
            return None  # undefined -> N/A, never 0 or 1
        detected_after = sum(
            1 for a in self.attempts
            if a.ground_unauthorized and (not a.accepted) and a.detected
        )
        return detected_after / denom

    @property
    def uer(self) -> float:
        return self.c_undetected / self.n if self.n else 0.0

    @property
    def presented_rate(self) -> float:
        return self.output_presented / self.n if self.n else 0.0

    @property
    def accepted_rate(self) -> float:
        return self.output_accepted / self.n if self.n else 0.0

    @property
    def disclosure_rate(self) -> float:
        # Deprecated alias: kept identical to the presented rate.
        return self.presented_rate

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
            "gateway_verification_attempted_count": sum(
                1 for a in self.attempts if a.gateway_verification_attempted
            ),
            "out_of_scope_output_presented": self.output_presented,
            "out_of_scope_output_accepted": self.output_accepted,
            "out_of_scope_output_presented_rate": self.presented_rate,
            "out_of_scope_output_accepted_rate": self.accepted_rate,
            "result_disclosure_rate": self.disclosure_rate,  # deprecated alias
            "unauthorized_result_disclosures": self.result_disclosures,
            "ASR": self.asr,
            "PR": self.pr,
            "DR": self.dr,
            "UER": self.uer,
            "e2e_latency_ms_mean": round(self.e2e_latency_ms_total / self.n, 4) if self.n else None,
            "evidence_gen_ms_mean": None,     # not separately instrumented; see ATTACK-RESULTS.md §2
            "gateway_verify_ms_mean": None,   # not separately instrumented; see ATTACK-RESULTS.md §2
            "evidence_bytes_mean": round(self.evidence_bytes_total / self.n, 1) if self.n else None,
            "extra_processes": self.extra_processes,
            "ipc_roundtrips": self.ipc_roundtrips,
        }


def frr(legit_total: int, legit_rejected: int) -> float | None:
    if legit_total == 0:
        return None
    return legit_rejected / legit_total
