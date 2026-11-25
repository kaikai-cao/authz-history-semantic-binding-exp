"""Unit tests pinning the trust-boundary behavior of A/B/C/D.

These are deterministic structural tests (few iterations). The 100-run statistical
replay lives in src/runner.py. Run with: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import multiprocessing as mp
import time
import unittest

from src.architectures import (
    ArchAAdapterReceipt,
    ArchBIndependentProxy,
    ArchCSignedDataService,
    ArchDIndependentObserver,
)
from src.consistency import evidence_is_false
from src.model import issue_grant, make_call, DEMO_CONTEXT
from src.primitives import Ed25519Signer


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
        # Keep STRONG references to both manager and dict proxy for the whole
        # test; otherwise the proxy is GC'd and child processes see a stale id.
        self._mgr = mp.Manager()
        self._shared = self._mgr.dict()
        return self._shared

    def _run(self, arch, attack, i=0, expired=False):
        rid = f"test-{arch.name}-{attack}-{i}"
        nonce = f"n-{rid}"
        g = _grant(self.issuer, nonce, expired=expired)
        return arch.execute(attack, rid, g, rid + "-req", nonce)

    # --- A: adapter is both executor and evidence producer ---
    def test_a_self_consistent_receipt_accepted(self):
        a = ArchAAdapterReceipt(self.issuer)
        r = self._run(a, "T1")
        self.assertTrue(r["verdict"].accepted)
        self.assertTrue(r["truth"]["unauthorized_execution"])
        ev = r["response"]["evidence"]["payload"]
        self.assertTrue(evidence_is_false(ev, r["truth"]))
        a.close()

    def test_a_expired_grant_denied(self):
        a = ArchAAdapterReceipt(self.issuer)
        r = self._run(a, "T11", expired=True)
        self.assertFalse(r["verdict"].accepted)
        self.assertFalse(r["truth"]["executed"])
        a.close()

    # --- B: independent process but proxy self-signs; still fails ---
    def test_b_malicious_proxy_self_sign_accepted(self):
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        r = self._run(b, "T3")
        self.assertTrue(r["verdict"].accepted)
        b.close()

    def test_b_key_is_generated_by_proxy_itself(self):
        # The gateway pins the key the proxy reports at startup (MVP-equivalent
        # TOFU). This is exactly why B is not an independent evidence source.
        b = ArchBIndependentProxy(self.issuer, self._fresh_shared())
        self.assertIsInstance(b.pinned_pk, bytes)
        self.assertEqual(len(b.pinned_pk), 32)
        b.close()

    # --- C: DS owns key+dataset; proxy is pure relay ---
    def test_c_proxy_query_tamper_prevented(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        r = self._run(c, "T2")
        self.assertFalse(r["verdict"].accepted)
        self.assertIn("mismatch", r["verdict"].reason + str(r["response"]))
        c.close()

    def test_c_proxy_forged_ds_signature_rejected(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        for atk in ("T3", "T7"):
            r = self._run(c, atk, i=1)
            self.assertFalse(r["verdict"].accepted)
            self.assertEqual(r["verdict"].reason, "ds_signature_invalid")
        c.close()

    def test_c_malicious_ds_valid_signature_false_result_accepted(self):
        # Core T8: DS uses its OWN valid key to sign a false result. The
        # signature verifies; only the statement is false. This MUST be
        # reported as accepted under C, never as "signature verification failed".
        shared = self._fresh_shared()
        c = ArchCSignedDataService(self.issuer, shared)
        r = self._run(c, "T8")
        self.assertTrue(r["verdict"].accepted)
        # Valid DS signature: reason is 'accepted', NOT a signature failure.
        self.assertEqual(r["verdict"].reason, "accepted")
        # The submitted evidence is false w.r.t. the DS's ground-truth record.
        truth = dict(shared[f"test-{c.name}-T8-0"])
        ev = r["response"]["evidence"]["payload"]
        self.assertTrue(evidence_is_false(ev, truth))
        # T8 DS ran the authorized Sales query (no real unauthorized access).
        self.assertFalse(truth["unauthorized_execution"])
        c.close()

    def test_c_colluding_ds_accepted(self):
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        r = self._run(c, "T9")
        self.assertTrue(r["verdict"].accepted)
        c.close()

    # --- D: observer provides evidence beyond proxy/DS self-report ---
    def test_d_observer_detects_t8_and_t9(self):
        d = ArchDIndependentObserver(self.issuer, self._fresh_shared())
        for atk in ("T8", "T9"):
            r = self._run(d, atk, i=2)
            self.assertFalse(r["verdict"].accepted)
            self.assertEqual(r["verdict"].reason, "observer_inconsistency")
            self.assertTrue(r["verdict"].detected)
        d.close()

    def test_d_honest_path_accepted_with_observation(self):
        d = ArchDIndependentObserver(self.issuer, self._fresh_shared())
        r = self._run(d, "T12")
        self.assertTrue(r["verdict"].accepted)
        self.assertEqual(r["verdict"].reason, "accepted_with_observation")
        d.close()

    def test_ds_key_never_reaches_proxy(self):
        # Structural assertion: no ds private key object is held by the parent
        # or passed to the proxy. The signer is created inside the DS process.
        c = ArchCSignedDataService(self.issuer, self._fresh_shared())
        self.assertEqual(len(c.ds_pk), 32)
        self.assertFalse(hasattr(c, "ds_signer"))  # signer lives only in DS process
        self.assertFalse(hasattr(c, "ds_private_key"))
        c.close()


if __name__ == "__main__":
    unittest.main()
