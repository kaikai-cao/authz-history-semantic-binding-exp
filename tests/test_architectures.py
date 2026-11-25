"""Unit tests pinning R1 attack semantics and trust boundaries.

Deterministic structural tests (few iterations). The N=100 statistical replay
lives in src/runner.py. Run: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import copy
import multiprocessing as mp
import time
import unittest

from src.architectures import (
    ArchAAdapterReceipt,
    ArchBIndependentProxy,
    ArchCSignedDataService,
    ArchDOracleAssistedObserver,
)
from src.consistency import evidence_is_false
from src.model import (
    DEMO_CONTEXT,
    SEED_NONCE,
    SEED_REQUEST_ID,
    issue_grant,
    make_call,
    result_within_grant,
)
from src.primitives import Ed25519Signer, canonical_json, digest_object, verify_b64


def _grant(issuer: Ed25519Signer, nonce: str, expired: bool = False):
    now = int(time.time())
    if expired:
        return issue_grant(issuer, make_call(), DEMO_CONTEXT, now=now, ttl_seconds=60,
                           nonce=nonce,
                           override_payload={"issued_at": now - 120, "expires_at": now - 60})
    return issue_grant(issuer, make_call(), DEMO_CONTEXT, now=now, ttl_seconds=120, nonce=nonce)


class ArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = Ed25519Signer.generate()

    def _fresh_shared(self):
        # STRONG refs to manager + dict proxy for the whole test; otherwise the
        # proxy is GC'd and child processes see a stale id.
        self._mgr = mp.Manager()
        self._shared = self._mgr.dict()
        return self._shared

    def _run(self, arch, attack, i=0, expired=False):
        rid = f"test-{arch.name}-{attack}-{i}"
        nonce = f"n-{rid}"
        g = _grant(self.issuer, nonce, expired=expired)
        return arch.execute(attack, rid, g, rid + "-req", nonce)

    # ---------------- A: adapter is executor + evidence producer ----------------
    def test_a_t1_self_consistent_receipt_accepted(self):
        a = ArchAAdapterReceipt(self.issuer)
        r = self._run(a, "T1")
        self.assertTrue(r["verdict"].accepted)
        self.assertTrue(r["truth"]["unauthorized_execution"])  # real Finance query
        ev = r["response"]["evidence"]["payload"]
        self.assertTrue(evidence_is_false(ev, r["truth"]))
        a.close()

    def test_a_t4_execution_and_disclosure_separated(self):
        # T4 executes AUTHORIZED Sales but returns a different real result.
        a = ArchAAdapterReceipt(self.issuer)
        r = self._run(a, "T4")
        self.assertTrue(r["verdict"].accepted)
        self.assertFalse(r["truth"]["unauthorized_execution"])       # Sales executed
        self.assertTrue(r["truth"]["unauthorized_result_disclosure"])  # Finance returned
        a.close()

    def test_a_t11_expired_grant_denied_before_execution(self):
        a = ArchAAdapterReceipt(self.issuer)
        r = self._run(a, "T11", expired=True)
        self.assertFalse(r["verdict"].accepted)
        self.assertFalse(r["truth"]["executed"])
        a.close()

    # ---------------- B: independent process but proxy self-signs (TOFU) ----------------
    def test_b_t3_self_sign_accepted(self):
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        b.make_seed()
        r = self._run(b, "T3")
        self.assertTrue(r["verdict"].accepted)   # TOFU trusts proxy's own key
        self.assertTrue(r["verdict"].reason == "accepted")
        b.close()

    def test_b_t6_source_tamper_reported_false(self):
        # B gateway does NOT bind source_id, so it accepts; but the statement is
        # false w.r.t. ground truth (source rewritten to attacker-source).
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        b.make_seed()
        r = self._run(b, "T6")
        self.assertTrue(r["verdict"].accepted)
        self.assertFalse(r["truth"]["unauthorized_execution"])  # authorized query ran
        ev = r["response"]["evidence"]["payload"]
        self.assertEqual(ev["source_id"], "attacker-source")
        self.assertTrue(evidence_is_false(ev, r["truth"]))
        b.close()

    def test_b_t10_forged_success_executed_false(self):
        # T10: no execution, but forged EXECUTED evidence accepted, and it is
        # classified as false evidence (not a normal path).
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        b.make_seed()
        r = self._run(b, "T10")
        self.assertTrue(r["verdict"].accepted)
        self.assertFalse(r["truth"]["executed"])
        ev = r["response"]["evidence"]["payload"]
        self.assertTrue(evidence_is_false(ev, r["truth"]))
        b.close()

    def test_b_t5_replay_is_verbatim_and_nonce_differs(self):
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        seed_desc = b.make_seed()
        rid = "test-B-T5-replay"; nonce = f"cur-{rid}-nonce"; req = f"cur-{rid}-req"
        g = _grant(self.issuer, nonce)
        r = b.execute("T5", rid, g, req, nonce)
        ev = r["response"]["evidence"]
        # Replayed evidence carries the SEED nonce, not the current request nonce.
        self.assertEqual(ev["payload"]["nonce"], SEED_NONCE)
        self.assertNotEqual(ev["payload"]["nonce"], nonce)
        self.assertEqual(ev["payload"]["request_id"], SEED_REQUEST_ID)
        self.assertNotEqual(ev["payload"]["request_id"], req)
        self.assertEqual(seed_desc["nonce"], SEED_NONCE)
        # Gateway rejects on current-request binding.
        self.assertFalse(r["verdict"].accepted)
        self.assertIn("replay", r["verdict"].reason)
        b.close()

    # ---------------- C: DS owns key+dataset; proxy pure relay ----------------
    def test_c_t2_query_tamper_prevented_before_execution(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T2")
        self.assertFalse(r["verdict"].accepted)
        if r["truth"] is not None:
            self.assertFalse(r["truth"]["executed"])  # DS never ran Finance
        c.close()

    def test_c_t3_t7_proxy_forged_ds_signature_rejected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        for atk in ("T3", "T7"):
            r = self._run(c, atk, i=1)
            self.assertFalse(r["verdict"].accepted)
            self.assertEqual(r["verdict"].reason, "ds_signature_invalid")
        c.close()

    def test_c_t4_substituted_result_detected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T4")
        self.assertFalse(r["verdict"].accepted)
        self.assertEqual(r["verdict"].reason, "result_digest_mismatch")
        c.close()

    def test_c_t6_post_sign_field_tamper_rejected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T6")
        self.assertFalse(r["verdict"].accepted)
        self.assertEqual(r["verdict"].reason, "ds_signature_invalid")
        c.close()

    def test_c_t5_replay_rejected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T5")
        self.assertFalse(r["verdict"].accepted)
        c.close()

    def test_c_t8_valid_signature_false_result_accepted(self):
        # Core T8: DS uses its OWN valid key to sign a false result. Signature
        # verifies; only the statement is false. MUST be 'accepted', never a
        # signature failure.
        shared = self._fresh_shared()
        c = ArchCSignedDataService(self.issuer, shared)
        c.make_seed()
        r = self._run(c, "T8")
        self.assertTrue(r["verdict"].accepted)
        self.assertEqual(r["verdict"].reason, "accepted")
        truth = dict(shared[f"test-{c.name}-T8-0"])
        ev = r["response"]["evidence"]["payload"]
        self.assertTrue(evidence_is_false(ev, truth))
        self.assertFalse(truth["unauthorized_execution"])  # Sales ran, no ASR
        self.assertTrue(truth["unauthorized_result_disclosure"])  # Finance disclosed
        c.close()

    def test_c_t9_colluding_ds_accepted(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T9")
        self.assertTrue(r["verdict"].accepted)
        # Real Finance query executed -> ASR contributor.
        self.assertTrue(r["truth"]["unauthorized_execution"])
        c.close()

    def test_c_t10_no_execution_forged_ds_evidence_rejected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T10")
        self.assertFalse(r["verdict"].accepted)
        self.assertFalse(r["truth"]["executed"])
        c.close()

    def test_c_t11_expired_grant_rejected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        c.make_seed()
        r = self._run(c, "T11", expired=True)
        self.assertFalse(r["verdict"].accepted)
        c.close()

    def test_ds_key_never_reaches_proxy(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        self.assertEqual(len(c.ds_pk), 32)
        self.assertFalse(hasattr(c, "ds_signer"))
        self.assertFalse(hasattr(c, "ds_private_key"))
        c.close()

    # ---------------- D: Oracle-assisted Observer (upper bound) ----------------
    def test_d_t8_t9_detected_under_trusted_oracle(self):
        d = ArchDOracleAssistedObserver(self.issuer, self._fresh_shared())
        d.make_seed()
        for atk in ("T8", "T9"):
            r = self._run(d, atk, i=2)
            self.assertFalse(r["verdict"].accepted)
            self.assertEqual(r["verdict"].reason, "observer_inconsistency")
            self.assertTrue(r["verdict"].detected)
            obs = r["observation"]["observation"]["payload"]
            self.assertTrue(obs["observed"])  # from test Oracle side channel
        d.close()

    def test_d_t12_honest_accepted_with_observation(self):
        d = ArchDOracleAssistedObserver(self.issuer, self._fresh_shared())
        d.make_seed()
        r = self._run(d, "T12")
        self.assertTrue(r["verdict"].accepted)
        self.assertEqual(r["verdict"].reason, "accepted_with_observation")
        d.close()


class R11SemanticsTests(unittest.TestCase):
    """R1.1 finite corrections: attack stages, T10 signature object, T5 replay, classes."""

    @classmethod
    def setUpClass(cls):
        cls.issuer = Ed25519Signer.generate()

    def _fresh_shared(self):
        self._mgr = mp.Manager()
        self._shared = self._mgr.dict()
        return self._shared

    def _run(self, arch, attack, expired=False):
        rid = f"r11-{arch.name}-{attack}"
        nonce = f"n-{rid}"
        g = _grant(self.issuer, nonce, expired=expired)
        return arch.execute(attack, rid, g, rid + "-req", nonce)

    # ---- Phase 1: T1 vs T2 real injection paths ----
    def test_a_t1_t2_query_states_distinct(self):
        a = ArchAAdapterReceipt(self.issuer)
        t1, t2 = self._run(a, "T1")["truth"], self._run(a, "T2")["truth"]
        self.assertEqual(t1["granted_query_where"]["department"], "Sales")
        self.assertEqual(t1["executor_input_query_where"]["department"], "Sales")
        self.assertEqual(t1["actual_query_where"]["department"], "Finance")
        self.assertEqual(t1["tamper_stage"], "post_authorization_executor_override")
        self.assertEqual(t2["granted_query_where"]["department"], "Sales")
        self.assertEqual(t2["executor_input_query_where"]["department"], "Finance")
        self.assertEqual(t2["actual_query_where"]["department"], "Finance")
        self.assertEqual(t2["tamper_stage"], "pre_executor_ingress_tamper")
        a.close()

    def test_b_t1_t2_query_states_distinct(self):
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared()); b.make_seed()
        t1, t2 = self._run(b, "T1")["truth"], self._run(b, "T2")["truth"]
        self.assertEqual(t1["executor_input_query_where"]["department"], "Sales")
        self.assertEqual(t2["executor_input_query_where"]["department"], "Finance")
        self.assertNotEqual(t1["tamper_stage"], t2["tamper_stage"])
        b.close()

    # ---- Phase 2: T10 signs the real forged payload ----
    def test_c_t10_signature_verifiable_under_proxy_key_not_ds_key(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared()); c.make_seed()
        r = self._run(c, "T10")
        ev = r["response"]["evidence"]
        self.assertFalse(r["verdict"].accepted)
        self.assertEqual(r["verdict"].reason, "ds_signature_invalid")
        self.assertEqual(r["verdict"].gateway_verification_attempted, True)
        self.assertFalse(r["truth"]["executed"])
        # Proxy's own key DID sign the exact submitted payload; DS key did not.
        self.assertTrue(verify_b64(c.proxy.public_key(), ev["signature"], ev["payload"]))
        self.assertFalse(verify_b64(c.ds_pk, ev["signature"], ev["payload"]))
        c.close()

    # ---- Phase 3: classification uses gateway_verification_attempted ----
    def test_classification_prevention_vs_detection(self):
        from src.metrics import Attempt
        def mk(gva, accepted, detected, executed=False):
            return Attempt("A", "T5", "r", accepted, detected, "x", executed,
                           False, False, gateway_verification_attempted=gva)
        # Replay reached the verifier and was rejected -> B, never A.
        self.assertEqual(mk(True, False, True).classify(), "B")
        # DS pre-execution rejection never reached the verifier -> A.
        self.assertEqual(mk(False, False, True).classify(), "A")
        # Control -> CONTROL.
        ctl = mk(False, True, False); ctl.is_control = True
        self.assertEqual(ctl.classify(), "CONTROL")

    # ---- Phase 5: T5 verbatim replay in ALL FOUR architectures ----
    def _t5_digest_check(self, arch):
        seed = arch.make_seed()
        rid = f"r11-{arch.name}-T5"
        nonce = f"n-{rid}"
        g = _grant(self.issuer, nonce)
        r = arch.execute("T5", rid, g, rid + "-req", nonce)
        ev = r["response"]["evidence"]
        self.assertEqual(seed["evidence_digest"], digest_object(ev))
        p = ev["payload"]
        self.assertEqual(p["nonce"], SEED_NONCE)   # replayed evidence carries old nonce
        self.assertNotEqual(p["nonce"], nonce)     # historical nonce != CURRENT request nonce
        self.assertNotEqual(p["request_id"], rid + "-req")
        self.assertTrue(r["verdict"].gateway_verification_attempted)
        self.assertFalse(r["verdict"].accepted)
        self.assertTrue(r["verdict"].detected)
        return r

    def test_t5_digest_equal_all_architectures(self):
        a = ArchAAdapterReceipt(self.issuer)
        r = self._t5_digest_check(a)
        self.assertIn("replay", r["verdict"].reason)
        a.close()
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        self._t5_digest_check(b); b.close()
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        self._t5_digest_check(c); c.close()
        d = ArchDOracleAssistedObserver(self.issuer, self._fresh_shared())
        # D replays the DS evidence verbatim; observer evidence is separate.
        self._t5_digest_check(d); d.close()

    # ---- Phase 4: presented vs accepted output metrics ----
    def test_t4_output_presented_not_accepted_under_c(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared()); c.make_seed()
        r = self._run(c, "T4")
        self.assertFalse(r["verdict"].accepted)
        final_output = r["response"]["output"]
        self.assertFalse(result_within_grant(final_output))  # out-of-scope presented
        c.close()


if __name__ == "__main__":
    unittest.main()
