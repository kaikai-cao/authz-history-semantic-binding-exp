"""Four execution-evidence architectures under test (D3-13-01-R1.1).

R1.1 changes on top of R1 (all finite, no new attacks, no new research):

  * T1 vs T2 are now DIFFERENT real injection paths, recorded in ground truth:
      T1 = post_authorization_executor_override: executor receives Sales, the
           grant binding passes on Sales, then the executor overrides the actual
           query to Finance before running it.
      T2 = pre_executor_ingress_tamper: the request is already Finance when it
           reaches the executor; the executor does NOT re-bind the real input.
    Three query states + tamper_stage are written for every attempt.
  * T10 signature-object bug fixed: the proxy now signs the SAME `forged`
    payload it submits (previously it signed {"forged": True}), so Gateway
    rejection is provably due to DS public-key verification, not a stray bug.
  * gateway_verification_attempted is set by the ACTUAL execution path (never
    inferred from `executed`). A response that reaches the Gateway verifier and
    is rejected is class B (post-submission detection), NOT class A (prevention).

Trust-boundary facts enforced in code (see ARCHITECTURE-COMPARISON.md):
  A Adapter Receipt       : adapter holds signing key, owns dataset, executes
                            and self-signs the receipt (faithful E2.2 baseline).
  B Independent Proxy     : separate PROCESS, but proxy self-generates key, owns
                            dataset, executes and self-signs; Gateway pins the
                            key the proxy reports at startup (TOFU).
  C Signed Data Service   : separate DS PROCESS generates/owns its Ed25519 key
                            and dataset. Forward proxy is a pure relay with NO
                            ds private key and NO dataset. nonce/request_id come
                            from the trusted driver. Gateway pins ds_pk read
                            directly from DS and binds fields to the grant.
  D Oracle-assisted Obs.  : C plus an observer PROCESS reading the DS execution
                            record from truth_shared, an explicitly-trusted
                            TEST ORACLE side channel (ideal upper bound only).

No Halo2 / no new proof system anywhere in this module.
"""
from __future__ import annotations

import copy
import multiprocessing as mp
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .model import (
    AUTHORIZED_WHERE,
    DEMO_CONTEXT,
    DEMO_POLICY,
    DS_EVIDENCE_VERSION,
    DS_SIGNED_FIELDS,
    FINANCE_WHERE,
    OBSERVER_EVIDENCE_VERSION,
    PROXY_EVIDENCE_VERSION,
    RECORDS,
    SEED_NONCE,
    SEED_REQUEST_ID,
    SEED_RUN_ID,
    SNAPSHOT_ID,
    SOURCE_ID,
    TOOL_ID,
    TOOL_SCHEMA_HASH,
    AuthorizationError,
    SignedGrant,
    build_truth,
    execute_query,
    make_call,
)
from .primitives import Ed25519Signer, digest_object, unb64, verify_b64

# A real result that already exists in the DS dataset (the Finance rows). T4
# returns THIS instead of the actual Sales result without re-executing Finance.
SUBSTITUTED_REAL_OUTPUT: list[dict[str, Any]] = [
    {"year": 2026, "department": "Finance", "amount": 3400}
]

# R1.1 tamper-stage labels (single source of truth, used by truth + tests).
STAGE_NONE = "none"
STAGE_T1 = "post_authorization_executor_override"
STAGE_T2 = "pre_executor_ingress_tamper"
STAGE_COLLUSION = "collusion_ds_finance"
STAGE_REPLAY = "historical_replay"
STAGE_PRE_FAILURE = "pre_execution_failure"


def _truth(run_id: str, role: str, executed: bool,
           where: dict[str, Any] | None,
           actual_result: list[dict[str, Any]] | None,
           returned_output: list[dict[str, Any]] | None,
           note: str = "",
           *,
           executor_input: dict[str, Any] | None = None,
           tamper_stage: str = STAGE_NONE) -> dict[str, Any]:
    """Adapter for the enriched ground-truth builder (R1.1 query provenance)."""
    return build_truth(
        run_id, role, executed, where, actual_result, returned_output, note,
        executor_input_query_where=executor_input,
        tamper_stage=tamper_stage,
    )


def _verify_grant_binding(
    issuer_pk: bytes,
    grant: SignedGrant,
    call_dict: dict[str, Any],
    context_dict: dict[str, str],
    now: int | None = None,
) -> dict[str, Any]:
    if not verify_b64(issuer_pk, grant.signature, grant.payload):
        raise AuthorizationError("invalid issuer signature")
    p = grant.payload
    now = int(time.time()) if now is None else now
    if not isinstance(p.get("issued_at"), int) or not isinstance(p.get("expires_at"), int):
        raise AuthorizationError("invalid grant validity interval")
    if now < p["issued_at"] or now >= p["expires_at"]:
        raise AuthorizationError("grant expired")
    if p.get("request_hash") != digest_object(call_dict):
        raise AuthorizationError("request hash mismatch")
    if p.get("context_hash") != digest_object(context_dict):
        raise AuthorizationError("context hash mismatch")
    if p.get("policy_hash") != DEMO_POLICY.policy_hash:
        raise AuthorizationError("policy hash mismatch")
    if p.get("tool_id") != call_dict.get("tool_id") or call_dict.get("tool_id") != TOOL_ID:
        raise AuthorizationError("tool id mismatch")
    if p.get("tool_schema_hash") != TOOL_SCHEMA_HASH:
        raise AuthorizationError("tool schema hash mismatch")
    if p.get("agent_id") != call_dict.get("agent_id"):
        raise AuthorizationError("agent id mismatch")
    return p


@dataclass
class Verdict:
    accepted: bool
    reason: str
    detected: bool  # Gateway/observer correctly flagged an anomaly
    # R1.1: set by the REAL execution path. True iff the attack response entered
    # the Gateway evidence-verification flow. Pre-execution denials set False.
    # Never inferred from `accepted` or `executed`.
    gateway_verification_attempted: bool = True


def make_service_loop(
    handler: Callable[[dict[str, Any]], dict[str, Any]],
    public_key_getter: Callable[[], str],
) -> Callable[[Any, Any], None]:
    def loop(req_q: Any, resp_q: Any) -> None:
        while True:
            msg = req_q.get()
            if msg.get("cmd") == "shutdown":
                resp_q.put({"ok": True})
                return
            if msg.get("cmd") == "get_public_key":
                resp_q.put({"public_key_b64": public_key_getter()})
                continue
            try:
                resp_q.put(handler(msg))
            except AuthorizationError as exc:
                resp_q.put({"ok": False, "error": str(exc)})
            except Exception as exc:  # keep process alive; report faithfully
                resp_q.put({"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    return loop


class _ProcService:
    def __init__(self, name: str, target: Callable[..., None], args: tuple = (),
                 req_q: Any = None, resp_q: Any = None) -> None:
        ctx = mp.get_context("spawn")
        self.req_q = req_q if req_q is not None else ctx.Queue()
        self.resp_q = resp_q if resp_q is not None else ctx.Queue()
        self.proc = ctx.Process(
            target=target, args=(self.req_q, self.resp_q, *args),
            name=name, daemon=True,
        )
        self.proc.start()

    def call(self, msg: dict[str, Any], timeout: float = 20.0) -> dict[str, Any]:
        self.req_q.put(msg)
        return self.resp_q.get(timeout=timeout)

    def public_key(self) -> bytes:
        return unb64(self.call({"cmd": "get_public_key"})["public_key_b64"])

    def close(self) -> None:
        try:
            self.call({"cmd": "shutdown"}, timeout=5)
        except Exception:
            pass
        self.proc.join(timeout=3)
        if self.proc.is_alive():
            self.proc.terminate()
            self.proc.join(timeout=3)


# ---------------------------------------------------------------------------
# A Adapter Receipt (in-process; faithful E2.2 baseline)
# applies: T1 T2 T4 T5 T10 T11 T12
# ---------------------------------------------------------------------------


class ArchAAdapterReceipt:
    name = "A_adapter_receipt"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any = None) -> None:
        self.issuer_pk = issuer_signer.public_key_raw()
        self.adapter_signer = Ed25519Signer.generate()
        self.pinned_pk = self.adapter_signer.public_key_raw()
        self.records = copy.deepcopy(RECORDS)
        self.seed_response: dict[str, Any] | None = None

    def make_seed(self) -> dict[str, Any]:
        """Independent seed request: honest Sales query, honest self-signed receipt."""
        auth_call = make_call()
        output, _ = execute_query(auth_call, self.records)
        payload = self._payload(auth_call, output, SEED_NONCE, SEED_REQUEST_ID)
        response = {"output": output,
                    "evidence": {"payload": payload,
                                 "signature": self.adapter_signer.sign_b64(payload)},
                    "seed": True}
        self.seed_response = response
        return {"run_id": SEED_RUN_ID, "request_id": SEED_REQUEST_ID,
                "nonce": SEED_NONCE, "output_digest": digest_object(output),
                "evidence_digest": digest_object(response["evidence"]),
                "purpose": "historical honest response replayed verbatim by T5; not counted in attack N"}

    def _payload(self, claim_call: Any, output: list[dict[str, Any]],
                 nonce: str, request_id: str) -> dict[str, Any]:
        return {
            "status": "EXECUTED",
            "tool_id": TOOL_ID,
            "tool_schema_hash": TOOL_SCHEMA_HASH,
            "request_hash": digest_object(claim_call.as_dict()),
            "policy_hash": DEMO_POLICY.policy_hash,
            "context_hash": digest_object(DEMO_CONTEXT.as_dict()),
            "nonce": nonce,
            "output_hash": digest_object(output),
            "request_id": request_id,
        }

    def _gateway(self, evidence: dict[str, Any] | None, output: list[dict[str, Any]],
                 nonce: str, request_id: str) -> Verdict:
        # This function IS the Gateway evidence-verification flow.
        if evidence is None:
            return Verdict(False, "missing_evidence", True)
        p = evidence["payload"]
        if not verify_b64(self.pinned_pk, evidence["signature"], p):
            return Verdict(False, "signature_invalid", True)
        if p.get("request_hash") != digest_object(make_call().as_dict()):
            return Verdict(False, "request_hash_mismatch", True)
        if p.get("nonce") != nonce:
            return Verdict(False, "replayed_nonce_mismatch", True)
        if p.get("request_id") != request_id:
            return Verdict(False, "replayed_request_mismatch", True)
        if p.get("output_hash") != digest_object(output):
            return Verdict(False, "output_hash_mismatch", True)
        return Verdict(True, "accepted", False)

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str = "", nonce: str = "") -> dict[str, Any]:
        auth_call = make_call()
        try:
            _verify_grant_binding(self.issuer_pk, grant, auth_call.as_dict(),
                                  DEMO_CONTEXT.as_dict())
        except AuthorizationError as exc:
            # T11: denied before any query and before the Gateway verifier.
            return {"response": {"error": str(exc)},
                    "truth": _truth(run_id, "adapter", False, None, None, None, str(exc),
                                    executor_input=AUTHORIZED_WHERE,
                                    tamper_stage=STAGE_NONE),
                    "verdict": Verdict(False, str(exc), True,
                                       gateway_verification_attempted=False),
                    "observation": None}

        # T5: verbatim historical response (seed nonce/request_id/signature).
        if attack == "T5":
            assert self.seed_response is not None
            resp = copy.deepcopy(self.seed_response)
            t = _truth(run_id, "adapter", False, None, None, resp["output"],
                       "T5: verbatim historical response replay, no new execution",
                       executor_input=AUTHORIZED_WHERE, tamper_stage=STAGE_REPLAY)
            v = self._gateway(resp["evidence"], resp["output"], nonce, request_id)
            return {"response": resp, "truth": t, "verdict": v, "observation": None}

        # T10: tool fails BEFORE execution; adapter forges success with its key.
        if attack == "T10":
            fake = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
            p = self._payload(auth_call, fake, nonce, request_id)
            evidence = {"payload": p, "signature": self.adapter_signer.sign_b64(p)}
            t = _truth(run_id, "adapter", False, None, None, fake,
                       "T10: pre-execution failure, adapter forged EXECUTED receipt",
                       executor_input=AUTHORIZED_WHERE, tamper_stage=STAGE_PRE_FAILURE)
            v = self._gateway(evidence, fake, nonce, request_id)
            return {"response": {"output": fake, "evidence": evidence},
                    "truth": t, "verdict": v, "observation": None}

        # R1.1: T1 vs T2 different real injection paths.
        #   T1: executor INPUT is the granted Sales; binding passes; then the
        #       malicious executor overrides the actual query to Finance.
        #   T2: executor INPUT is already Finance (tampered before ingress);
        #       the malicious executor does NOT re-bind the real input.
        # Both ultimately run the real Finance query and sign a Sales receipt.
        if attack == "T1":
            exec_call = make_call(FINANCE_WHERE)
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_T1
            note = "T1: Sales input passed binding, executor overrode to Finance"
        elif attack == "T2":
            exec_call = make_call(FINANCE_WHERE)
            exec_input = FINANCE_WHERE
            stage = STAGE_T2
            note = "T2: Finance arrived at ingress, executor ran it without re-binding"
        elif attack == "T4":
            exec_call = auth_call  # authorized Sales really executed
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_NONE
            note = "T4: authorized Sales executed, different real Finance result returned"
        else:  # T12 honest
            exec_call = auth_call
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_NONE
            note = "honest authorized query"

        actual_output, probe = execute_query(exec_call, self.records)
        returned = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT) if attack == "T4" else actual_output
        p = self._payload(auth_call, returned, nonce, request_id)
        evidence = {"payload": p, "signature": self.adapter_signer.sign_b64(p)}
        t = _truth(run_id, "adapter", True, probe["where"], probe["result"], returned, note,
                   executor_input=exec_input, tamper_stage=stage)
        v = self._gateway(evidence, returned, nonce, request_id)
        return {"response": {"output": returned, "evidence": evidence},
                "truth": t, "verdict": v, "observation": None}

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# B Independent Proxy (separate process; proxy self-generates key + dataset)
# applies: T1 T2 T3 T4 T5 T6 T10 T11 T12
# ---------------------------------------------------------------------------


def _proxy_process(req_q: Any, resp_q: Any, issuer_pk: bytes, truth_shared: Any) -> None:
    signer = Ed25519Signer.generate()
    records = copy.deepcopy(RECORDS)
    historical_response: dict[str, Any] | None = None
    lock = threading.Lock()

    def payload(claim_call: Any, output: list[dict[str, Any]], nonce: str,
                request_id: str, source_id: str = SOURCE_ID) -> dict[str, Any]:
        return {
            "evidence_version": PROXY_EVIDENCE_VERSION,
            "status": "EXECUTED",
            "grant_hash": "",  # filled by caller via payload_setdefault
            "request_hash": digest_object(claim_call.as_dict()),
            "context_hash": digest_object(DEMO_CONTEXT.as_dict()),
            "tool_id": TOOL_ID,
            "tool_schema_hash": TOOL_SCHEMA_HASH,
            "nonce": nonce,
            "query_hash": digest_object(claim_call.args),
            "output_hash": digest_object(output),
            "row_count": len(output),
            "source_id": source_id,
            "snapshot_id": SNAPSHOT_ID,
            "request_id": request_id,
        }

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        nonlocal historical_response
        attack, run_id = msg["attack"], msg["run_id"]
        grant = SignedGrant(msg["grant"]["payload"], msg["grant"]["signature"])
        auth_call = make_call()
        # T11 (expired grant) denied before any query and before Gateway.
        _verify_grant_binding(issuer_pk, grant, auth_call.as_dict(), DEMO_CONTEXT.as_dict())
        nonce = grant.payload["nonce"]
        request_id = msg.get("request_id", "")
        with lock:
            pass  # no nonce pre-consume: replay is decided by current-request binding

        # __SEED__: honest historical response, cached for T5.
        if attack == "__SEED__":
            output, _ = execute_query(auth_call, records)
            p = payload(auth_call, output, SEED_NONCE, SEED_REQUEST_ID)
            p["grant_hash"] = digest_object(grant.as_dict())
            resp = {"ok": True, "output": output,
                    "evidence": {"payload": p, "signature": signer.sign_b64(p)},
                    "seed": True}
            historical_response = copy.deepcopy(resp)
            return resp

        if attack == "T5":
            assert historical_response is not None
            return {"ok": True, **copy.deepcopy(historical_response)}

        # T10: pre-execution failure; proxy forges success with its own key.
        if attack == "T10":
            fake = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
            p = payload(auth_call, fake, nonce, request_id)
            p["grant_hash"] = grant.grant_hash
            evidence = {"payload": p, "signature": signer.sign_b64(p)}
            t = _truth(run_id, "proxy", False, None, None, fake,
                       "T10: pre-execution failure, proxy forged EXECUTED evidence",
                       executor_input=AUTHORIZED_WHERE, tamper_stage=STAGE_PRE_FAILURE)
            truth_shared[run_id] = t
            return {"ok": True, "output": fake, "evidence": evidence, "truth": t}

        # T3: self-sign false evidence with proxy's own (TOFU-trusted) key.
        if attack == "T3":
            fake = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
            p = payload(auth_call, fake, nonce, request_id)
            p["grant_hash"] = grant.grant_hash
            evidence = {"payload": p, "signature": signer.sign_b64(p)}
            t = _truth(run_id, "proxy", False, None, None, fake,
                       "T3: proxy self-signed fabricated evidence (trust-source issue)",
                       executor_input=AUTHORIZED_WHERE, tamper_stage=STAGE_NONE)
            truth_shared[run_id] = t
            return {"ok": True, "output": fake, "evidence": evidence, "truth": t}

        # T6 (B): field-tamper, NOT query tamper -- execute the AUTHORIZED query
        # and only rewrite the source_id/snapshot fields it signs with its key.
        # R1.1 T1/T2 distinction (same as A): both run Finance, but the recorded
        # executor INPUT and tamper_stage differ.
        if attack == "T1":
            exec_call = make_call(FINANCE_WHERE)
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_T1
            note = "T1: Sales input passed binding, proxy overrode to Finance"
        elif attack == "T2":
            exec_call = make_call(FINANCE_WHERE)
            exec_input = FINANCE_WHERE
            stage = STAGE_T2
            note = "T2: Finance arrived at ingress, proxy ran it without re-binding"
        elif attack == "T4":
            exec_call = auth_call
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_NONE
            note = "T4: authorized Sales executed, different real Finance result returned"
        elif attack == "T6":
            exec_call = auth_call
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_NONE
            note = "T6: proxy tampered source_id then self-signed with its own key"
        else:  # T12
            exec_call = auth_call
            exec_input = AUTHORIZED_WHERE
            stage = STAGE_NONE
            note = "honest authorized query"

        actual_output, probe = execute_query(exec_call, records)
        returned = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT) if attack == "T4" else actual_output
        src = "attacker-source" if attack == "T6" else SOURCE_ID
        p = payload(auth_call, returned, nonce, request_id, source_id=src)
        p["grant_hash"] = grant.grant_hash
        evidence = {"payload": p, "signature": signer.sign_b64(p)}
        t = _truth(run_id, "proxy", True, probe["where"], probe["result"], returned, note,
                   executor_input=exec_input, tamper_stage=stage)
        truth_shared[run_id] = t
        return {"ok": True, "output": returned, "evidence": evidence, "truth": t}

    make_service_loop(handler, signer.public_key_b64)(req_q, resp_q)


class ArchBIndependentProxy:
    name = "B_independent_proxy"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any) -> None:
        self.issuer_pk = issuer_signer.public_key_raw()
        self._issuer = issuer_signer
        self.proc = _ProcService("B-proxy", _proxy_process, (self.issuer_pk, truth_shared))
        self.pinned_pk = self.proc.public_key()  # MVP-equivalent TOFU
        self.seed_descriptor: dict[str, Any] | None = None

    def make_seed(self) -> dict[str, Any]:
        grant = issue_seed_grant(self._issuer, SEED_NONCE)
        resp = self.proc.call({"attack": "__SEED__", "run_id": SEED_RUN_ID,
                               "grant": grant.as_dict(), "request_id": SEED_REQUEST_ID})
        ev = resp["evidence"]
        self.seed_descriptor = {
            "run_id": SEED_RUN_ID, "request_id": SEED_REQUEST_ID,
            "nonce": SEED_NONCE, "output_digest": digest_object(resp["output"]),
            "evidence_digest": digest_object(ev),
            "purpose": "historical honest response replayed verbatim by T5; not counted in attack N",
        }
        return self.seed_descriptor

    def _gateway(self, evidence: dict[str, Any] | None, output: list[dict[str, Any]],
                 nonce: str, request_id: str) -> Verdict:
        # This function IS the Gateway evidence-verification flow.
        if evidence is None:
            return Verdict(False, "missing_evidence", True)
        p = evidence["payload"]
        if not verify_b64(self.pinned_pk, evidence["signature"], p):
            return Verdict(False, "signature_invalid", True)
        # B Gateway (MVP-equivalent): signature + request/output/nonce only.
        if p.get("request_hash") != digest_object(make_call().as_dict()):
            return Verdict(False, "request_hash_mismatch", True)
        if p.get("output_hash") != digest_object(output):
            return Verdict(False, "output_hash_mismatch", True)
        if p.get("nonce") != nonce:
            return Verdict(False, "replayed_nonce_mismatch", True)
        if p.get("request_id") != request_id:
            return Verdict(False, "replayed_request_mismatch", True)
        # NOTE: B does NOT bind source_id/snapshot_id -> T6 tamper is accepted.
        return Verdict(True, "accepted", False)

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str = "", nonce: str = "") -> dict[str, Any]:
        resp = self.proc.call({"attack": attack, "run_id": run_id,
                               "grant": grant.as_dict(), "request_id": request_id})
        if not resp.get("ok"):
            # Denied inside proxy before reaching the Gateway verification flow.
            return {"response": resp, "truth": resp.get("truth"),
                    "verdict": Verdict(False, resp.get("error", "proxy_denied"), True,
                                       gateway_verification_attempted=False),
                    "observation": None}
        output, evidence = resp["output"], resp["evidence"]
        v = self._gateway(evidence, output, nonce, request_id)
        return {"response": resp, "truth": resp.get("truth"),
                "verdict": v, "observation": None}

    def close(self) -> None:
        self.proc.close()


# ---------------------------------------------------------------------------
# C Signed Data Service (DS owns key+dataset; proxy pure relay)
# applies: T2 T3 T4 T5 T6 T7 T8 T9 T10 T11 T12
# ---------------------------------------------------------------------------


def _ds_process(req_q: Any, resp_q: Any, issuer_pk: bytes, truth_shared: Any) -> None:
    ds_signer = Ed25519Signer.generate()  # DS generates its own key.
    records = copy.deepcopy(RECORDS)      # DS owns the real dataset.

    def sign_payload(qd: str, claimed: list[dict[str, Any]], request_id: str,
                     grant_id: str, nonce: str) -> dict[str, Any]:
        p = {
            "protocol_version": DS_EVIDENCE_VERSION,
            "source_id": SOURCE_ID,
            "request_id": request_id,
            "grant_id": grant_id,
            "nonce": nonce,
            "canonical_query_digest": qd,
            "snapshot_id": SNAPSHOT_ID,
            "result_digest": digest_object(claimed),
            "status": "EXECUTED",
            "issued_at": int(time.time()),
        }
        assert tuple(sorted(p)) == tuple(sorted(DS_SIGNED_FIELDS))
        return p

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        attack, run_id = msg["attack"], msg["run_id"]
        grant = SignedGrant(msg["grant"]["payload"], msg["grant"]["signature"])
        auth_call = make_call()
        request_id, nonce = msg["request_id"], msg["nonce"]

        # __SEED__: honest DS execution for the historical seed response.
        if attack == "__SEED__":
            _verify_grant_binding(issuer_pk, grant, auth_call.as_dict(), DEMO_CONTEXT.as_dict())
            output, probe = execute_query(auth_call, records)
            p = sign_payload(digest_object(auth_call.args), output,
                             SEED_REQUEST_ID, grant.grant_id, SEED_NONCE)
            return {"ok": True, "status": "EXECUTED", "output": output,
                    "evidence": {"payload": p, "signature": ds_signer.sign_b64(p)}, "seed": True}

        # T10: tool fails BEFORE execution; DS writes executed=False and no evidence.
        if attack == "T10":
            t = _truth(run_id, "data_service", False, None, None, [],
                       "T10: pre-execution tool failure, DS did not execute",
                       executor_input=AUTHORIZED_WHERE, tamper_stage=STAGE_PRE_FAILURE)
            truth_shared[run_id] = t
            return {"ok": True, "status": "FAILED", "output": [], "evidence": None, "truth": t}

        # T9_DS_SIDE: colluding DS really executes Finance, but signs the
        # authorized query digest (disguise). Signature is fully valid.
        if attack == "T9_DS_SIDE":
            exec_call = make_call(FINANCE_WHERE)
            output, probe = execute_query(exec_call, records)
            claimed = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
            p = sign_payload(msg["query_digest_hint"], claimed, request_id,
                             grant.grant_id, nonce)
            note = "T9: colluding DS ran Finance, signed authorized-query digest"
            exec_input = FINANCE_WHERE
            stage = STAGE_COLLUSION
        else:
            # DS re-verifies the grant against the query it is asked to run.
            # T2: proxy rewrote the query to Finance -> DS rejects pre-execution.
            asked = make_call(FINANCE_WHERE) if msg.get("force_finance") else auth_call
            try:
                _verify_grant_binding(issuer_pk, grant, asked.as_dict(), DEMO_CONTEXT.as_dict())
            except AuthorizationError as exc:
                if msg.get("force_finance"):
                    # R1.1: record the tampered ingress and PROVE no query ran.
                    t = _truth(
                        run_id, "data_service", False, None, None, None,
                        "T2: DS received tampered Finance query; grant binds Sales; rejected before execution",
                        executor_input=FINANCE_WHERE, tamper_stage=STAGE_T2,
                    )
                    truth_shared[run_id] = t
                    return {"ok": False, "error": str(exc), "status": "REJECTED_PRE_QUERY",
                            "truth": t}
                raise
            if nonce != grant.payload["nonce"]:
                raise AuthorizationError("nonce not bound to grant")
            exec_call = asked
            output, probe = execute_query(exec_call, records)
            claimed = output
            p = sign_payload(digest_object(exec_call.args), claimed, request_id,
                             grant.grant_id, nonce)
            note = "DS executed bound query and signed canonical response"
            exec_input = asked.args["where"]
            stage = STAGE_NONE
            if attack == "T8":
                # Malicious DS: runs authorized Sales, signs a FALSE Finance result.
                # Valid signature; only the statement is false.
                claimed = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
                p = sign_payload(digest_object(auth_call.args), claimed, request_id,
                                 grant.grant_id, nonce)
                note = "T8: DS signed false result with its own valid key"

        evidence = {"payload": p, "signature": ds_signer.sign_b64(p)}
        t = _truth(run_id, "data_service", True, probe["where"], probe["result"],
                   claimed, note, executor_input=exec_input, tamper_stage=stage)
        truth_shared[run_id] = t
        return {"ok": True, "status": "EXECUTED", "output": claimed,
                "evidence": evidence, "truth": t}

    make_service_loop(handler, ds_signer.public_key_b64)(req_q, resp_q)


def _forward_proxy_process(
    req_q: Any, resp_q: Any,
    ds_req_q: Any, ds_resp_q: Any,
) -> None:
    """Pure relay: NO ds private key, NO dataset. It keeps its own key only to
    demonstrate that proxy self-signatures fail C verification (T3/T7/T10)."""
    proxy_signer = Ed25519Signer.generate()
    historical_response: dict[str, Any] | None = None

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        nonlocal historical_response
        attack = msg["attack"]
        forwarded = dict(msg)

        # __SEED__: ask DS for an honest response, cache it verbatim for T5.
        if attack == "__SEED__":
            forwarded["attack"] = "__SEED__"
            ds_req_q.put(forwarded)
            result = ds_resp_q.get(timeout=20)
            historical_response = copy.deepcopy(result)
            return result

        # T5: verbatim historical DS response (original nonce/signature).
        if attack == "T5":
            assert historical_response is not None
            return {"ok": True, **copy.deepcopy(historical_response)}

        # T3/T7: proxy forges a DS-looking evidence with its OWN key.
        # T7 is the explicit "claiming DS identity/signature" framing.
        if attack in ("T3", "T7"):
            forged = {
                "protocol_version": DS_EVIDENCE_VERSION,
                "source_id": SOURCE_ID,
                "request_id": msg["request_id"],
                "grant_id": msg["grant_id_hint"],
                "nonce": msg["nonce"],
                "canonical_query_digest": msg["query_digest_hint"],
                "snapshot_id": SNAPSHOT_ID,
                "result_digest": digest_object(SUBSTITUTED_REAL_OUTPUT),
                "status": "EXECUTED",
                "issued_at": int(time.time()),
            }
            return {"ok": True, "status": "EXECUTED",
                    "output": copy.deepcopy(SUBSTITUTED_REAL_OUTPUT),
                    "evidence": {"payload": forged,
                                 "signature": proxy_signer.sign_b64(forged)},
                    "forged_by_proxy": True}

        if attack == "T9":
            forwarded["ds_attack"] = "T9_DS_SIDE"
        if attack == "T2":
            # Proxy rewrites the query to Finance; DS independently binds the
            # grant's request_hash and rejects before execution.
            forwarded["force_finance"] = True
        if forwarded.get("ds_attack"):
            forwarded["attack"] = forwarded["ds_attack"]

        ds_req_q.put(forwarded)
        result = ds_resp_q.get(timeout=20)

        # T6: proxy tampers source_id/snapshot_id AFTER DS signed -> DS sig invalid.
        if attack == "T6" and result.get("evidence"):
            result["evidence"]["payload"]["source_id"] = "attacker-source"
            result["evidence"]["payload"]["snapshot_id"] = "attacker-snapshot"
        # T4: DS signed the honest Sales result; proxy substitutes a different
        # REAL result afterwards -> result_digest mismatch at Gateway.
        if attack == "T4" and result.get("output"):
            result["output"] = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
        # T10: DS returned FAILED with no evidence; proxy forges DS evidence
        # with its OWN key -> Gateway rejects on DS public-key verification.
        # R1.1 BUGFIX: sign the SAME `forged` payload that is submitted, so the
        # rejection is attributable to key-source verification (not a stray
        # signature over {"forged": True}).
        if attack == "T10" and result.get("status") == "FAILED":
            forged = {
                "protocol_version": DS_EVIDENCE_VERSION, "source_id": SOURCE_ID,
                "request_id": msg["request_id"], "grant_id": msg["grant_id_hint"],
                "nonce": msg["nonce"], "canonical_query_digest": msg["query_digest_hint"],
                "snapshot_id": SNAPSHOT_ID,
                "result_digest": digest_object(SUBSTITUTED_REAL_OUTPUT),
                "status": "EXECUTED", "issued_at": int(time.time()),
            }
            result["status"] = "EXECUTED"
            result["output"] = copy.deepcopy(SUBSTITUTED_REAL_OUTPUT)
            result["evidence"] = {"payload": forged,
                                  "signature": proxy_signer.sign_b64(forged)}
        return result

    make_service_loop(handler, proxy_signer.public_key_b64)(req_q, resp_q)


class ArchCSignedDataService:
    name = "C_signed_data_service"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any) -> None:
        self.issuer_pk = issuer_signer.public_key_raw()
        self._issuer = issuer_signer
        ctx = mp.get_context("spawn")
        self.ds_req_q = ctx.Queue()
        self.ds_resp_q = ctx.Queue()
        # DS started directly from trusted side; pk read directly from DS, never
        # relayed by the proxy. DS and proxy share the SAME queue pair.
        self.ds = _ProcService(
            "C-data-service", _ds_process, (self.issuer_pk, truth_shared),
            req_q=self.ds_req_q, resp_q=self.ds_resp_q,
        )
        self.ds_pk = self.ds.public_key()
        self.proxy = _ProcService(
            "C-forward-proxy", _forward_proxy_process,
            (self.ds_req_q, self.ds_resp_q),
        )
        self.seed_descriptor: dict[str, Any] | None = None

    def make_seed(self) -> dict[str, Any]:
        grant = issue_seed_grant(self._issuer, SEED_NONCE)
        resp = self.proxy.call({"attack": "__SEED__", "run_id": SEED_RUN_ID,
                                "grant": grant.as_dict(), "request_id": SEED_REQUEST_ID,
                                "nonce": SEED_NONCE, "grant_id_hint": grant.grant_id,
                                "query_digest_hint": digest_object(make_call().args)})
        ev = resp["evidence"]
        self.seed_descriptor = {
            "run_id": SEED_RUN_ID, "request_id": SEED_REQUEST_ID,
            "nonce": SEED_NONCE, "output_digest": digest_object(resp["output"]),
            "evidence_digest": digest_object(ev),
            "purpose": "historical honest DS response replayed verbatim by T5; not counted in attack N",
        }
        return self.seed_descriptor

    def _verify(self, evidence: dict[str, Any] | None, output: list,
                expected: dict[str, Any]) -> Verdict:
        # This function IS the Gateway DS-evidence verification flow.
        if evidence is None:
            return Verdict(False, "missing_ds_evidence", True)
        payload = evidence.get("payload", {})
        if not verify_b64(self.ds_pk, evidence.get("signature", ""), payload):
            return Verdict(False, "ds_signature_invalid", True)
        checks = {
            "protocol_version": DS_EVIDENCE_VERSION,
            "source_id": SOURCE_ID,
            "request_id": expected["request_id"],
            "grant_id": expected["grant_id"],
            "nonce": expected["nonce"],
            "canonical_query_digest": expected["query_digest"],
            "snapshot_id": SNAPSHOT_ID,
            "result_digest": digest_object(output),
            "status": "EXECUTED",
        }
        for key, want in checks.items():
            if payload.get(key) != want:
                return Verdict(False, f"{key}_mismatch", True)
        issued = payload.get("issued_at")
        now = int(time.time())
        if not isinstance(issued, int) or issued > now or now - issued > 300:
            return Verdict(False, "stale_issued_at", True)
        return Verdict(True, "accepted", False)

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str, nonce: str) -> dict[str, Any]:
        call = make_call()
        query_digest = digest_object(call.args)
        resp = self.proxy.call({
            "attack": attack, "run_id": run_id, "grant": grant.as_dict(),
            "request_id": request_id, "nonce": nonce,
            "grant_id_hint": grant.grant_id, "query_digest_hint": query_digest,
        })
        if not resp.get("ok"):
            # DS/proxy denied BEFORE the Gateway evidence-verification flow.
            return {"response": resp, "truth": resp.get("truth"),
                    "verdict": Verdict(False, resp.get("error", "denied"), True,
                                       gateway_verification_attempted=False),
                    "observation": None}
        v = self._verify(resp.get("evidence"), resp.get("output", []),
                         {"request_id": request_id, "grant_id": grant.grant_id,
                          "nonce": nonce, "query_digest": query_digest})
        return {"response": resp, "truth": resp.get("truth"),
                "verdict": v, "observation": None}

    def close(self) -> None:
        self.proxy.close()
        self.ds.close()


def issue_seed_grant(issuer_signer: Ed25519Signer, nonce: str) -> SignedGrant:
    """Mint an honest, non-expiring grant for the seed request in the parent."""
    from .model import issue_grant
    now = int(time.time())
    return issue_grant(issuer_signer, make_call(), DEMO_CONTEXT, now=now,
                       ttl_seconds=3600, nonce=nonce)


# ---------------------------------------------------------------------------
# D Oracle-assisted Observer (C + observer over trusted TEST-ORACLE channel)
# applies: T2 T3 T4 T5 T6 T7 T8 T9 T10 T11 T12
# ---------------------------------------------------------------------------


def _observer_process(req_q: Any, resp_q: Any, truth_shared: Any) -> None:
    obs_signer = Ed25519Signer.generate()

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        # truth_shared is the experiment TEST ORACLE: a trusted side channel
        # carrying the DS execution record. It is NOT a production observation
        # interface; if the DS controls/forges it, detection is lost.
        record = truth_shared.get(msg["run_id"])
        if record is None:
            payload = {
                "evidence_version": OBSERVER_EVIDENCE_VERSION,
                "run_id": msg["run_id"], "request_id": msg["request_id"],
                "observed": False, "observed_where": None,
                "observed_result_digest": None, "observed_source_id": None,
            }
        else:
            payload = {
                "evidence_version": OBSERVER_EVIDENCE_VERSION,
                "run_id": msg["run_id"], "request_id": msg["request_id"],
                "observed": True,
                "executor_role": record["executor_role"],
                "executed": record["executed"],
                "observed_where": record["actual_query_where"],
                "observed_result_digest": record["actual_query_result_digest"],
                "observed_source_id": record["actual_source_id"],
                "note": record["note"],
            }
        return {"ok": True,
                "observation": {"payload": payload,
                                "signature": obs_signer.sign_b64(payload)}}

    make_service_loop(handler, obs_signer.public_key_b64)(req_q, resp_q)


class ArchDOracleAssistedObserver:
    name = "D_oracle_assisted_observer"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any) -> None:
        self.c = ArchCSignedDataService(issuer_signer, truth_shared)
        self.truth_shared = truth_shared
        self.observer = _ProcService("D-observer", _observer_process, (truth_shared,))
        self.observer_pk = self.observer.public_key()

    def make_seed(self) -> dict[str, Any]:
        return self.c.make_seed()

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str, nonce: str) -> dict[str, Any]:
        result = self.c.execute(attack, run_id, grant, request_id, nonce)
        obs_resp = self.observer.call({"run_id": run_id, "request_id": request_id})
        result["observation"] = obs_resp
        verdict: Verdict = result["verdict"]
        if verdict.accepted and obs_resp.get("ok"):
            obs = obs_resp["observation"]
            if verify_b64(self.observer_pk, obs["signature"], obs["payload"]):
                p = obs["payload"]
                claimed = result["response"].get("evidence", {})
                cp = claimed.get("payload", {}) if isinstance(claimed, dict) else {}
                consistent = (
                    p.get("observed") is True
                    and p.get("observed_where") == AUTHORIZED_WHERE
                    and p.get("observed_result_digest") == cp.get("result_digest")
                    and p.get("observed_source_id") == cp.get("source_id")
                )
                if not consistent:
                    # Observer detection occurs AFTER the DS Gateway verification;
                    # preserve gateway_verification_attempted from the C verdict.
                    result["verdict"] = Verdict(
                        False, "observer_inconsistency", True,
                        gateway_verification_attempted=verdict.gateway_verification_attempted,
                    )
                else:
                    result["verdict"] = Verdict(
                        True, "accepted_with_observation", False,
                        gateway_verification_attempted=verdict.gateway_verification_attempted,
                    )
        return result

    def close(self) -> None:
        self.observer.close()
        self.c.close()


# Backward-compatible alias; canonical name is ArchDOracleAssistedObserver.
ArchDIndependentObserver = ArchDOracleAssistedObserver
