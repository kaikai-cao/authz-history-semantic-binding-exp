"""Automated checks for the D3-07-B-P1-R1 protocol audit."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scenarios import run_all  # noqa: E402

MODELS = ("A", "B", "C")
PIDS = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10")
R1_B_IDS = tuple(f"R1-B{i}" for i in range(1, 9))
REQUIRED_EVENT_FIELDS = {
    "global_event_seq",
    "sim_time",
    "phase",
    "actor",
    "action",
    "detail",
    "message",
    "signature_time",
    "durable_change",
    "qc_formed",
    "fc_formed",
    "gateway_decision",
    "witness_state",
}
# P1-P10 x 3 + CK1-CK7 + U1 + AL1 + FRESH-B + R1-B1..B8
EXPECTED_COUNT = 30 + 7 + 1 + 1 + 1 + len(R1_B_IDS)


def counterexample(result: dict, limit: int = 6) -> str:
    """Render a compact tail of the event log for a failing assertion."""
    tail = result["events"][-limit:]
    return "\n".join(
        f"#{e['global_event_seq']} [{e['phase']}] {e['actor']} {e['action']}: {e['detail'][:120]}"
        for e in tail
    )


def recompute_liveness_basic(result: dict) -> dict:
    """Re-derive L1/L3/L4 from serialized events only (independent of the simulator)."""
    events = result["events"]
    actions = [e["action"] for e in events]
    phases = [e.get("phase", "") for e in events]
    accepted = [e for e in events if e["action"] in ("qc_accepted", "fc_accepted")]
    byzantine = {e["actor"] for e in events if e["action"] == "byzantine_marked"}
    recovery = any(
        a in ("timeout_round_advance", "trusted_recovery", "unsafe_timeout_unlock")
        or "heal" in p
        or "recovery" in p
        for a, p in zip(actions, phases)
    )

    if not accepted and not recovery:
        l1 = "not_applicable"
    else:
        l1 = "achieved" if accepted else "not_achieved"

    if not byzantine:
        l3 = "not_applicable"
    else:
        quorum = result["gateway_qc"] + result["gateway_fc"]
        honest_ok = any(
            len([s for s in rec["signers"] if s not in byzantine]) >= 3 for rec in quorum
        )
        l3 = "achieved" if honest_ok else "not_achieved"

    if not accepted:
        l4 = "not_applicable"
    else:
        deps = (
            "trusted_recovery" in actions
            or "timeout_round_advance" in actions
            or result["model"] == "C"
        )
        l4 = "not_achieved" if deps else "achieved"
    return {"L1": l1, "L3": l3, "L4": l4}


class ProtocolAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.results = run_all()

    def test_expected_scenario_count(self) -> None:
        self.assertEqual(len(self.results), EXPECTED_COUNT)
        for model in MODELS:
            for pid in PIDS:
                self.assertIn(f"{pid}-{model}", self.results)
        for rid in R1_B_IDS:
            self.assertIn(f"{rid}-B", self.results)
        self.assertIn("FRESH-B-B", self.results)

    def test_determinism(self) -> None:
        first = json.dumps(run_all(), sort_keys=True, ensure_ascii=False)
        second = json.dumps(run_all(), sort_keys=True, ensure_ascii=False)
        self.assertEqual(first, second)

    def test_p1_p10_have_no_safety_violations(self) -> None:
        for model in MODELS:
            for pid in PIDS:
                result = self.results[f"{pid}-{model}"]
                self.assertTrue(
                    all(result["safety"].values()),
                    f"{pid}-{model}: {result['violations']}\n{counterexample(result)}",
                )

    def test_unsafe_timeout_counterexample_fails(self) -> None:
        result = self.results["U1-UNSAFE"]
        self.assertFalse(result["safety"]["S2"], counterexample(result))
        self.assertTrue(any(v["invariant"] == "S2" for v in result["violations"]))

    def test_total_state_loss_counterexample_fails_s5(self) -> None:
        result = self.results["AL1-A"]
        self.assertFalse(result["safety"]["S5"], counterexample(result))
        self.assertTrue(any(v["invariant"] == "S5" for v in result["violations"]))

    def test_lease_boundaries(self) -> None:
        checks = [
            ("CK1-C", 0, "QC_REJECT"),
            ("CK2-C", 0, "QC_REJECT"),
            ("CK3-C", 0, "QC_ACCEPT"),
            ("CK3-C", 1, "QC_REJECT"),
            ("CK5-C", 0, "QC_ACCEPT"),
            ("CK6-C", 0, "QC_ACCEPT"),
            ("CK6-C", 1, "QC_REJECT"),
            ("CK7-C", 1, "QC_ACCEPT"),
        ]
        for key, idx, prefix in checks:
            decisions = self.results[key]["gateway_decisions"]
            self.assertGreater(len(decisions), idx, f"{key}: {decisions}")
            self.assertTrue(decisions[idx].startswith(prefix), f"{key}: {decisions}")

    def test_event_records_are_complete(self) -> None:
        for key, result in self.results.items():
            self.assertTrue(result["events"], f"{key} has no events")
            for event in result["events"]:
                self.assertTrue(REQUIRED_EVENT_FIELDS.issubset(event), f"{key}: missing event fields")

    def test_safety_and_liveness_reported_separately(self) -> None:
        for key, result in self.results.items():
            self.assertEqual(set(result["safety"]), {"S1", "S2", "S3", "S4", "S5"}, key)
            self.assertEqual(set(result["liveness"]), {"L1", "L2", "L3", "L4"}, key)
            for code, entry in result["liveness"].items():
                self.assertIn(entry["status"], ("achieved", "not_achieved", "not_applicable"), f"{key}/{code}")
                self.assertTrue(entry["basis"], f"{key}/{code}: missing evidence basis")
                if entry["status"] == "not_applicable":
                    self.assertIsNone(entry["passed"], f"{key}/{code}")
                else:
                    self.assertIsInstance(entry["passed"], bool, f"{key}/{code}")

    def test_liveness_matches_recomputed_state(self) -> None:
        """Liveness must agree with evidence re-derived from the serialized log."""
        for key, result in self.results.items():
            derived = recompute_liveness_basic(result)
            for code, status in derived.items():
                actual = result["liveness"][code]["status"]
                self.assertEqual(actual, status, f"{key}/{code}: reported={actual} derived={status}\n{counterexample(result)}")
            if result["liveness"]["L2"]["status"] == "achieved":
                self.assertTrue(
                    any(e["action"] in ("qc_accepted", "fc_accepted") for e in result["events"]),
                    f"{key}: L2 achieved without an accepted QC/FC\n{counterexample(result)}",
                )

    def test_r0_author_annotations_preserved(self) -> None:
        """R0 hand-written booleans are preserved for before/after comparison, not used as R1 results."""
        for key, result in self.results.items():
            if key.endswith(tuple(f"-{m}" for m in MODELS)) or key in ("U1-UNSAFE", "AL1-A"):
                self.assertTrue(result["author_liveness_r0"], f"{key}: missing R0 annotation")

    # ---------------- Model B lock-transfer regressions ----------------

    def _probe(self, key: str, label: str) -> str:
        notes = self.results[key]["notes"]
        matches = [n for n in notes if n.startswith(label + ":") and "expected_allowed=" in n]
        self.assertTrue(matches, f"{key}: no {label} probe record\n{counterexample(self.results[key])}")
        return matches[0]

    def test_lock_round_comparison(self) -> None:
        expectations = {
            "R1-B1-B": ("R1-B1", False),
            "R1-B2-B": ("R1-B2", False),
            "R1-B3-B": ("R1-B3", True),
            "R1-B4-B": ("R1-B4", False),
            "R1-B6-B": ("R1-B6-honest", False),
            "R1-B7-B": ("R1-B7", False),
        }
        for key, (label, expected) in expectations.items():
            note = self._probe(key, label)
            self.assertIn(f"expected_allowed={expected}", note, note)
            self.assertIn(f"can_sign={expected}", note, note)
            self.assertIn(f"signature_created={expected}", note, note)
            self.assertNotIn("ANOMALY", note, note)
            self.assertTrue(all(self.results[key]["safety"].values()), counterexample(self.results[key]))

    def test_polc_signer_threshold(self) -> None:
        result = self.results["R1-B5-B"]
        note = next((n for n in result["notes"] if n.startswith("R1-B5: expected_allowed=")), "")
        self.assertIn("expected_allowed=False", note, note)
        self.assertIn("can_sign=False", note, note)
        self.assertIn("signature_created=False", note, note)
        self.assertIn("observed=['W1', 'W2']", note, note)
        self.assertIn("has_polc=False", note, note)

    def test_old_round_polc_not_reused(self) -> None:
        result = self.results["R1-B8-B"]
        note = next(
            (n for n in result["notes"] if n.startswith("R1-B8: expected_allowed=")), ""
        )
        self.assertIn("expected_allowed=False", note, note)
        self.assertIn("can_sign=False", note, note)
        self.assertIn("signature_created=False", note, note)

    # ---------------- P2 / P3 / P8 evidence ----------------

    def test_p2_b_real_polc_and_qc(self) -> None:
        result = self.results["P2-B"]
        notes = result["notes"]
        for expected in (
            "W2 observed prevote signers ['W1', 'W2', 'W3'] for cp_a round 0; PoLC=True",
            "W3 observed prevote signers ['W1', 'W2', 'W3'] for cp_a round 0; PoLC=True",
            "W1 observed prevote signers ['W1']; PoLC=False",
            "gateway received precommit signers ['W2', 'W3', 'W4']",
            "W1 conflicting prevote after learning commit produced signature=False",
        ):
            self.assertTrue(any(expected in n for n in notes), f"P2-B missing evidence: {expected}\n{counterexample(result)}")
        self.assertEqual(len(result["gateway_qc"]), 1, counterexample(result))
        self.assertEqual(sorted(result["gateway_qc"][0]["signers"]), ["W2", "W3", "W4"])

    def test_p3_b_conflicting_polc_unreachable(self) -> None:
        result = self.results["P3-B"]
        self.assertEqual(len(result["gateway_qc"]), 1, counterexample(result))
        self.assertTrue(result["gateway_qc"][0]["digest"].startswith("oldd"), counterexample(result))
        self.assertTrue(any("cp_new@1 PoLC=False" in n for n in result["notes"]), counterexample(result))
        self.assertTrue(any("not reachable" in n for n in result["notes"]), counterexample(result))
        for event in result["events"]:
            is_honest_conflict = (
                event["action"] == "signature_created"
                and event.get("actor") in ("W1", "W2", "W3")
                and "prevote digest=neww3333" in event["detail"]
            )
            self.assertFalse(
                is_honest_conflict,
                f"honest witness signed conflicting prevote:\n{counterexample(result)}",
            )

    def test_p8_b_lock_blocks_recovery(self) -> None:
        result = self.results["P8-B"]
        self.assertFalse(any(q["digest"].startswith("cccc") for q in result["gateway_qc"]), counterexample(result))
        self.assertTrue(any("R1 finding" in n for n in result["notes"]), counterexample(result))

    def test_parse_generated_results(self) -> None:
        path = ROOT / "results" / "p1_p10.json"
        self.assertTrue(path.exists())
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(payload), EXPECTED_COUNT)
        self.assertEqual(json.loads((ROOT / "results" / "summary.json").read_text(encoding="utf-8"))["revision"], "R1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
