"""Re-derive every headline claim in the R1 docs from results/attack_results.json.

Run: python -m tests.verify_results   (or python tests/verify_results.py)
Exits 0 with 'ALL DOC CLAIMS VERIFIED' only if every assertion holds. This is
the 'document tables auto-verifiable from JSON' deliverable required by R1.
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


def arm(a: str, t: str) -> dict:
    return next(x for x in ARMS if x["arch"] == a and x["attack"] == t)


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    c = DATA["meta"]["counts"]
    # Phase 1 scale + applicability
    check((c["applicable_arms"], c["na_arms"], c["attack_arms"], c["control_arms"])
          == (38, 10, 34, 4), "arm counts")
    check((c["attack_attempts"], c["benign_controls"], c["formal_trials_total"],
           c["raw_samples"], c["seed_requests_excluded"])
          == (3400, 400, 3800, 3800, 4), "trial counts")
    check(len(ARMS) == 38 and len(NA) == 10 and len(RAW) == 3800, "list sizes")
    check({(a["arch"], a["attack"]) for a in NA} ==
          {("A", "T3"), ("A", "T6"), ("A", "T7"), ("A", "T8"), ("A", "T9"),
           ("B", "T7"), ("B", "T8"), ("B", "T9"), ("C", "T1"), ("D", "T1")},
          "N/A set")
    check(all(a["N"] == 100 for a in ARMS), "all arms N=100")
    check(all(r["class"] != "D" for r in RAW), "no indeterminate class")

    # Seed requests (T5 real replay)
    check(len(DATA["meta"]["seed_requests"]) == 4, "4 seed requests")
    check(all(s["nonce"] == "20261125-seed-nonce" for s in DATA["meta"]["seed_requests"]),
          "seed nonce")
    for a in "ABCD":
        t5 = arm(a, "T5")
        check(t5["PR"] == 1.0 and t5["UER"] == 0.0, f"{a} T5 replay rejected")

    # A/B self-signed evidence fails (T1; B T3/T10)
    check(arm("A", "T1")["UER"] == 1.0 and arm("A", "T1")["ASR"] == 1.0, "A T1")
    check(arm("B", "T1")["UER"] == 1.0, "B T1")
    check(arm("B", "T3")["UER"] == 1.0 and arm("B", "T10")["UER"] == 1.0, "B T3/T10")
    # T4 execution vs disclosure separated
    check(arm("A", "T4")["ASR"] == 0.0 and arm("A", "T4")["result_disclosure_rate"] == 1.0,
          "A T4 ASR=0 disclosure=1")

    # C resists all proxy-side tampering
    for t in ("T2", "T3", "T5", "T7", "T10", "T11"):
        check(arm("C", t)["PR"] == 1.0, f"C {t} PR=1")
    check(arm("C", "T4")["class_B_detected"] == 100 and arm("C", "T4")["UER"] == 0.0,
          "C T4 detected")
    check(arm("C", "T6")["class_B_detected"] == 100, "C T6 detected")

    # Trust boundary: T8/T9 valid signature but false statement
    c8, c9 = arm("C", "T8"), arm("C", "T9")
    check((c8["UER"], c8["ASR"], c8["DR"]) == (1.0, 0.0, None), "C T8")
    check((c9["UER"], c9["ASR"], c9["DR"]) == (1.0, 1.0, 0.0), "C T9")
    # D Oracle-assisted: detected, H4 still open
    d8, d9 = arm("D", "T8"), arm("D", "T9")
    check(d8["class_B_detected"] == 100 and d8["UER"] == 0.0 and d8["DR"] is None,
          "D T8 detected, DR=N/A")
    check(d9["class_B_detected"] == 100 and d9["UER"] == 0.0 and d9["DR"] == 1.0,
          "D T9 detected DR=1")

    # FRR all zero; cost ordering
    for a in "ABCD":
        check(DATA["meta"]["frr_legit_T12"][a]["FRR"] == 0.0, f"{a} FRR=0")
    d12, c12 = arm("D", "T12"), arm("C", "T12")
    check(d12["evidence_bytes_mean"] > c12["evidence_bytes_mean"],
          "D T12 evidence includes Observer")

    # Every arm's rates re-derivable from raw_samples
    for a in ARMS:
        rows = [r for r in RAW if r["arch"] == a["arch"] and r["attack"] == a["attack"]]
        n = len(rows)
        A = sum(r["class"] == "A" for r in rows)
        B = sum(r["class"] == "B" for r in rows)
        C = sum(r["class"] == "C" for r in rows)
        D = sum(r["class"] == "D" for r in rows)
        unauth = sum(r["ground_unauthorized"] for r in rows)
        det = sum(r["ground_unauthorized"] and not r["accepted"] and r["detected"] for r in rows)
        disc = sum(r["unauthorized_result_disclosure"] for r in rows)
        check((A, B, C, D) == (a["class_A_prevented"], a["class_B_detected"],
                               a["class_C_undetected"], a["class_D_indeterminate"]),
              f"class recalc {a['arch']} {a['attack']}")
        check(abs(a["ASR"] - unauth / n) < 1e-9, "ASR recalc")
        check(abs(a["UER"] - C / n) < 1e-9, "UER recalc")
        check(abs(a["PR"] - A / n) < 1e-9, "PR recalc")
        exp_dr = det / unauth if unauth else None
        check((a["DR"] == exp_dr) or (a["DR"] is None and exp_dr is None), "DR recalc")
        check(abs(a["result_disclosure_rate"] - disc / n) < 1e-9, "disclosure recalc")

    print("ALL DOC CLAIMS VERIFIED (38 arms / 3800 samples / 10 N/A / 4 seed / 0 indeterminate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
