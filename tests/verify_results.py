"""Re-derive every headline claim in the R1.1 docs from results/attack_results.json.

Run: python -m tests.verify_results
Exits 0 with 'ALL R1.1 CLAIMS VERIFIED' only if all 16 assertion groups hold.
This is the 'document tables auto-verifiable from JSON' deliverable required by
R1.1 Phase 7.3. No number is hand-copied; all rates are re-derived from raw_samples.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "results" / "attack_results.json").read_text(encoding="utf-8"))

ARMS = [a for a in DATA["arms"] if a.get("status") != "NOT_APPLICABLE"]
NA = [a for a in DATA["arms"] if a.get("status") == "NOT_APPLICABLE"]
RAW = DATA["raw_samples"]
SEEDS = {s["arch"]: s for s in DATA["meta"]["seed_requests"]}
PKS = DATA["meta"]["public_keys"]


def arm(a: str, t: str) -> dict:
    return next(x for x in ARMS if x["arch"] == a and x["attack"] == t)


def rows(a: str, t: str) -> list[dict]:
    return [r for r in RAW if r["arch"] == a and r["attack"] == t]


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    # (1) formal sample count + applicability
    c = DATA["meta"]["counts"]
    check((c["applicable_arms"], c["na_arms"], c["attack_arms"], c["control_arms"])
          == (38, 10, 34, 4), "arm counts")
    check((c["attack_attempts"], c["benign_controls"], c["formal_trials_total"],
           c["raw_samples"], c["seed_requests_excluded"])
          == (3400, 400, 3800, 3800, 4), "trial counts")
    check(len(ARMS) == 38 and len(NA) == 10 and len(RAW) == 3800, "list sizes")
    check(all(a["N"] == 100 for a in ARMS), "all arms N=100")
    check(len(SEEDS) == 4 and all(s["nonce"] == "20261125-seed-nonce" for s in SEEDS.values()),
          "4 seed requests with seed nonce")

    # (2) N/A set exact, never remapped
    check({(a["arch"], a["attack"]) for a in NA} ==
          {("A", "T3"), ("A", "T6"), ("A", "T7"), ("A", "T8"), ("A", "T9"),
           ("B", "T7"), ("B", "T8"), ("B", "T9"), ("C", "T1"), ("D", "T1")},
          "N/A set")

    # (3) A/B T1 vs T2 distinct stages: entry vs actual query
    for a in ("A", "B"):
        t1, t2 = rows(a, "T1")[0]["query_states"], rows(a, "T2")[0]["query_states"]
        check(t1["granted_query_where"] == t2["granted_query_where"], f"{a} grant same")
        check(t1["executor_input_query_where"] != t2["executor_input_query_where"],
              f"{a} entry differs")
        check(t1["tamper_stage"] != t2["tamper_stage"], f"{a} stage differs")
        check(t1["executor_input_query_where"]["department"] == "Sales", f"{a} T1 entry Sales")
        check(t2["executor_input_query_where"]["department"] == "Finance", f"{a} T2 entry Finance")

    # (4) T10: signature verifies under proxy key, NOT ds key; rejection attributed
    from src.primitives import verify_b64, unb64
    for a in ("C", "D"):
        r = rows(a, "T10")[0]
        ev = r["evidence"]
        check(r["reason"] == "ds_signature_invalid", f"{a} T10 reason")
        check(r["gateway_verification_attempted"] is True, f"{a} T10 submitted to Gateway")
        check(r["ground_truth"]["executed"] is False, f"{a} T10 no execution")
        check(verify_b64(unb64(PKS[a]["proxy"]), ev["signature"], ev["payload"]),
              f"{a} T10 proxy-key verifies")
        check(not verify_b64(unb64(PKS[a]["ds"]), ev["signature"], ev["payload"]),
              f"{a} T10 ds-key fails")
        check(arm(a, "T10")["class_B_detected"] == 100, f"{a} T10 class B")

    # (5) T5: verbatim replay digest equality in ALL FOUR architectures
    for a in "ABCD":
        for r in rows(a, "T5"):
            check(r["replayed_evidence_digest"] == SEEDS[a]["evidence_digest"],
                  f"{a} T5 digest equals seed")
            check(r["evidence"]["payload"]["nonce"] != r["nonce"], f"{a} T5 old nonce")
            check(r["evidence"]["payload"]["request_id"] != r["request_id"],
                  f"{a} T5 old request_id")
            check(r["class"] == "B" and r["gateway_verification_attempted"] is True,
                  f"{a} T5 class B not A")
        t5 = arm(a, "T5")
        check(t5["PR"] == 0.0 and t5["class_B_detected"] == 100 and t5["UER"] == 0.0,
              f"{a} T5 PR no longer 1")

    # (6) C/D T3/T7/T10 = B (post-submission detection), T2/T11 = A (prevention)
    for a in ("C", "D"):
        for t in ("T3", "T7", "T10"):
            check(arm(a, t)["class_B_detected"] == 100 and arm(a, t)["PR"] == 0.0,
                  f"{a} {t} class B")
        for t in ("T2", "T11"):
            check(arm(a, t)["class_A_prevented"] == 100 and arm(a, t)["PR"] == 1.0,
                  f"{a} {t} class A")
    check(arm("C", "T2")["gateway_verification_attempted_count"] == 0,
          "C T2 never reached Gateway")

    # (7) A/B T10 = C (forged success accepted)
    for a in ("A", "B"):
        check(arm(a, "T10")["class_C_undetected"] == 100 and arm(a, "T10")["UER"] == 1.0,
              f"{a} T10 class C")

    # (8) trust boundary C T8/T9 unchanged; D detected under Oracle
    c8, c9 = arm("C", "T8"), arm("C", "T9")
    check((c8["UER"], c8["ASR"], c8["DR"]) == (1.0, 0.0, None), "C T8")
    check((c9["UER"], c9["ASR"], c9["DR"]) == (1.0, 1.0, 0.0), "C T9")
    d8, d9 = arm("D", "T8"), arm("D", "T9")
    check(d8["class_B_detected"] == 100 and d8["UER"] == 0.0 and d8["DR"] is None,
          "D T8 detected, DR=N/A")
    check(d9["class_B_detected"] == 100 and d9["UER"] == 0.0 and d9["DR"] == 1.0,
          "D T9 detected DR=1")

    # (9) B≈A self-sign failure persists
    check(arm("A", "T1")["UER"] == 1.0 and arm("A", "T1")["ASR"] == 1.0, "A T1")
    check(arm("B", "T1")["UER"] == 1.0 and arm("B", "T3")["UER"] == 1.0, "B self-sign")

    # (10) two independent output metrics, presented vs accepted
    for a in "ABCD":
        t4 = arm(a, "T4")
        check(t4["out_of_scope_output_presented_rate"] == 1.0, f"{a} T4 presented")
        check(abs(t4["out_of_scope_output_presented_rate"]
                  - t4["result_disclosure_rate"]) < 1e-9, f"{a} deprecated alias equals presented")
    check(arm("A", "T4")["out_of_scope_output_accepted_rate"] == 1.0, "A T4 accepted")
    check(arm("B", "T4")["out_of_scope_output_accepted_rate"] == 1.0, "B T4 accepted")
    check(arm("C", "T4")["out_of_scope_output_accepted_rate"] == 0.0, "C T4 rejected")
    check(arm("D", "T4")["out_of_scope_output_accepted_rate"] == 0.0, "D T4 rejected")
    check(arm("C", "T8")["out_of_scope_output_accepted_rate"] == 1.0, "C T8 accepted")
    check(arm("D", "T8")["out_of_scope_output_accepted_rate"] == 0.0, "D T8 rejected")
    for a in ("C", "D"):
        check(arm(a, "T10")["out_of_scope_output_presented_rate"] == 1.0
              and arm(a, "T10")["out_of_scope_output_accepted_rate"] == 0.0,
              f"{a} T10 presented not accepted")

    # (11) every arm's classes/rates re-derivable from raw_samples
    for a in ARMS:
        rr = rows(a["arch"], a["attack"])
        n = len(rr)
        A = sum(r["class"] == "A" for r in rr)
        B = sum(r["class"] == "B" for r in rr)
        C = sum(r["class"] == "C" for r in rr)
        D = sum(r["class"] == "D" for r in rr)
        unauth = sum(r["ground_unauthorized"] for r in rr)
        det = sum(r["ground_unauthorized"] and not r["accepted"] and r["detected"] for r in rr)
        pres = sum(r["out_of_scope_output_presented"] for r in rr)
        acc = sum(r["out_of_scope_output_accepted"] for r in rr)
        check((A, B, C, D) == (a["class_A_prevented"], a["class_B_detected"],
                               a["class_C_undetected"], a["class_D_indeterminate"]),
              f"class recalc {a['arch']} {a['attack']}")
        check(abs(a["ASR"] - unauth / n) < 1e-9, f"ASR {a['arch']} {a['attack']}")
        check(abs(a["PR"] - A / n) < 1e-9, f"PR {a['arch']} {a['attack']}")
        check(abs(a["UER"] - C / n) < 1e-9, f"UER {a['arch']} {a['attack']}")
        exp_dr = det / unauth if unauth else None
        check((a["DR"] == exp_dr) or (a["DR"] is None and exp_dr is None),
              f"DR {a['arch']} {a['attack']}")
        check(abs(a["out_of_scope_output_presented_rate"] - pres / n) < 1e-9,
              f"presented recalc {a['arch']} {a['attack']}")
        check(abs(a["out_of_scope_output_accepted_rate"] - acc / n) < 1e-9,
              f"accepted recalc {a['arch']} {a['attack']}")

    # (12) FRR + control isolation: T12 only in FRR/normal accept, not attack classes
    for a in "ABCD":
        check(DATA["meta"]["frr_legit_T12"][a]["FRR"] == 0.0, f"{a} FRR=0")
        t12 = arm(a, "T12")
        check(t12["class_A_prevented"] == 0 and t12["class_B_detected"] == 0
              and t12["class_C_undetected"] == 0, f"{a} T12 no attack class")
        check(all(r["class"] == "CONTROL" for r in rows(a, "T12")), f"{a} T12 CONTROL")

    # (13) DR=0-denominator => N/A everywhere (never 0/1)
    for a in ARMS:
        if a["ground_unauthorized_executions"] == 0:
            check(a["DR"] is None, f"DR N/A for {a['arch']} {a['attack']}")

    # (14) no indeterminate class, evidence size includes Observer
    check(all(r["class"] != "D" for r in RAW), "no indeterminate class")
    check(arm("D", "T12")["evidence_bytes_mean"] > arm("C", "T12")["evidence_bytes_mean"],
          "D T12 evidence includes Observer")

    # (15) T4 ASR=0 (authorized query executed) while output presented=1
    for a in "ABCD":
        check(arm(a, "T4")["ASR"] == 0.0, f"{a} T4 ASR=0")

    # (16) D remains Oracle-assisted, H4 open, no ZKP claim (meta statement)
    check("Oracle" in DATA["meta"]["observer_model"] and "OPEN" in DATA["meta"]["observer_model"],
          "observer model honesty")

    print("ALL R1.1 CLAIMS VERIFIED (16 groups / 38 arms / 3800 samples / 10 N/A / 4 seed / 0 indeterminate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
