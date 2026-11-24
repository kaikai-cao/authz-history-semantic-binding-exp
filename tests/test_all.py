"""Automated checks for the D3-07-B-P1 protocol audit."""

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


class ProtocolAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.results = run_all()

    def test_expected_scenario_count(self) -> None:
        self.assertEqual(len(self.results), 39)
        for model in MODELS:
            for pid in PIDS:
                self.assertIn(f"{pid}-{model}", self.results)

    def test_determinism(self) -> None:
        first = json.dumps(run_all(), sort_keys=True, ensure_ascii=False)
        second = json.dumps(run_all(), sort_keys=True, ensure_ascii=False)
        self.assertEqual(first, second)

    def test_p1_p10_have_no_safety_violations(self) -> None:
        for model in MODELS:
            for pid in PIDS:
                result = self.results[f"{pid}-{model}"]
                self.assertTrue(all(result["safety"].values()), f"{pid}-{model}: {result['violations']}")

    def test_unsafe_timeout_counterexample_fails(self) -> None:
        result = self.results["U1-UNSAFE"]
        self.assertFalse(result["safety"]["S2"])
        self.assertTrue(any(v["invariant"] == "S2" for v in result["violations"]))

    def test_total_state_loss_counterexample_fails_s5(self) -> None:
        result = self.results["AL1-A"]
        self.assertFalse(result["safety"]["S5"])
        self.assertTrue(any(v["invariant"] == "S5" for v in result["violations"]))

    def test_lease_boundaries(self) -> None:
        self.assertTrue(self.results["CK1-C"]["gateway_decisions"][0].startswith("QC_REJECT"))
        self.assertTrue(self.results["CK2-C"]["gateway_decisions"][0].startswith("QC_REJECT"))
        self.assertTrue(self.results["CK3-C"]["gateway_decisions"][0].startswith("QC_ACCEPT"))
        self.assertTrue(self.results["CK3-C"]["gateway_decisions"][1].startswith("QC_REJECT"))
        self.assertTrue(self.results["CK5-C"]["gateway_decisions"][0].startswith("QC_ACCEPT"))
        self.assertTrue(self.results["CK6-C"]["gateway_decisions"][0].startswith("QC_ACCEPT"))
        self.assertTrue(self.results["CK6-C"]["gateway_decisions"][1].startswith("QC_REJECT"))
        self.assertTrue(self.results["CK7-C"]["gateway_decisions"][1].startswith("QC_ACCEPT"))

    def test_event_records_are_complete(self) -> None:
        for key, result in self.results.items():
            self.assertTrue(result["events"], f"{key} has no events")
            for event in result["events"]:
                self.assertTrue(REQUIRED_EVENT_FIELDS.issubset(event), f"{key}: missing event fields")

    def test_safety_and_liveness_reported_separately(self) -> None:
        for key, result in self.results.items():
            self.assertEqual(set(result["safety"]), {"S1", "S2", "S3", "S4", "S5"}, key)
            self.assertEqual(set(result["liveness"]), {"L1", "L2", "L3", "L4"}, key)

    def test_parse_generated_results(self) -> None:
        path = ROOT / "results" / "p1_p10.json"
        self.assertTrue(path.exists())
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(payload), 39)


if __name__ == "__main__":
    unittest.main(verbosity=2)
