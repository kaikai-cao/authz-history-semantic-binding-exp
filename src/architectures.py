"""Four execution-evidence architectures under test (D3-13-01).

Trust-boundary facts enforced in code (see ARCHITECTURE-COMPARISON.md):

  A Adapter Receipt      : adapter holds the signing key, owns the dataset,
                           executes the query and self-signs the receipt.
  B Independent Proxy    : separate PROCESS, but the proxy self-generates its
                           key, owns the dataset, executes and self-signs.
                           Gateway pins the key the proxy reports at startup.
  C Signed Data Service  : separate DS PROCESS generates/owns its Ed25519 key
                           and dataset. The forward proxy is a pure relay with
                           NO ds private key and NO dataset. nonce/request_id
                           come from the trusted driver. Gateway pins ds_pk
                           read directly from DS, never relayed by the proxy.
                           Gateway additionally binds the signed fields to the
                           authorized request (query/grant/nonce/snapshot).
  D Independent Observer : C plus an observer PROCESS that reads the DS real
                           execution record from a side channel the proxy
                           never receives, and signs independent evidence.

Gateway semantics under test:
  - C verifies: ds signature + field-to-authorization bindings + freshness.
    It CANNOT verify that the DS actually executed the signed query (no
    independent observation). Hence T8/T9 remain accepted under C.
  - D adds observer cross-check, so T8/T9 become detectable.

No Halo2 and no new proof system anywhere in this module.
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
    SNAPSHOT_ID,
    SOURCE_ID,
    TOOL_ID,
    TOOL_SCHEMA_HASH,
    AuthorizationError,
    SignedGrant,
    execute_query,
    make_call,
)
from .primitives import Ed25519Signer, digest_object, unb64, verify_b64

FAKE_FINANCE_OUTPUT: list[dict[str, Any]] = [
    {"year": 2026, "department": "Finance", "amount": 3400}
]


def _truth(
    run_id: str,
    role: str,
    executed: bool,
    where: dict[str, Any] | None,
    result: list[dict[str, Any]] | None,
    source_id: str | None,
    note: str = "",
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "executor_role": role,
        "executed": executed,
        "actual_where": copy.deepcopy(where) if where is not None else None,
        "actual_result": copy.deepcopy(result) if result is not None else None,
        "actual_source_id": source_id,
        "result_digest": digest_object(result) if result is not None else None,
        "unauthorized_execution": bool(executed and where != AUTHORIZED_WHERE),
        "note": note,
    }


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
            except Exception as exc:
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
# ---------------------------------------------------------------------------


class ArchAAdapterReceipt:
    name = "A_adapter_receipt"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any = None) -> None:
        self.issuer_pk = issuer_signer.public_key_raw()
        self.adapter_signer = Ed25519Signer.generate()
        self.pinned_pk = self.adapter_signer.public_key_raw()
        self.records = copy.deepcopy(RECORDS)
        self.used_nonces: set[str] = set()

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str = "", nonce: str = "") -> dict[str, Any]:
        auth_call = make_call()
        try:
            _verify_grant_binding(self.issuer_pk, grant, auth_call.as_dict(), DEMO_CONTEXT.as_dict())
        except AuthorizationError as exc:
            t = _truth(run_id, "adapter", False, None, None, None, str(exc))
            return {"response": {"error": str(exc)}, "truth": t,
                    "verdict": Verdict(False, str(exc), True), "observation": None}

        n = grant.payload["nonce"]
        if attack == "T5":
            self.used_nonces.add(n)  # simulate a prior consumption
        if n in self.used_nonces:
            t = _truth(run_id, "adapter", False, None, None, None, "nonce replay")
            return {"response": {"error": "nonce_replay"}, "truth": t,
                    "verdict": Verdict(False, "nonce_replay", True), "observation": None}
        self.used_nonces.add(n)

        # A = Adapter is both executor and evidence producer (the E2.2 trust
        # boundary). Every malicious-adapter attack runs a real unauthorized
        # Finance query, then the adapter self-signs a receipt that CLAIMS the
        # authorized request. Only T12 is honest; T5/T11 are denied upstream.
        honest = attack == "T12"
        actual = auth_call if honest else make_call(FINANCE_WHERE)
        output, probe = execute_query(actual, self.records)

        payload = {
            "status": "EXECUTED",
            "tool_id": TOOL_ID,
            "tool_schema_hash": TOOL_SCHEMA_HASH,
            # Adapter always claims the authorized request regardless of what
            # it actually queried -> self-consistent false receipt (E2.2).
            "request_hash": digest_object(auth_call.as_dict()),
            "policy_hash": DEMO_POLICY.policy_hash,
            "context_hash": digest_object(DEMO_CONTEXT.as_dict()),
            "nonce": n,
            "output_hash": digest_object(output),
        }
        evidence = {"payload": payload, "signature": self.adapter_signer.sign_b64(payload)}
        t = _truth(run_id, "adapter", True, probe["where"], probe["result"], SOURCE_ID,
                   "honest" if honest else "malicious adapter ran Finance, signed authorized claim")

        sig_ok = verify_b64(self.pinned_pk, evidence["signature"], payload)
        bind_ok = payload["request_hash"] == digest_object(auth_call.as_dict())
        accepted = bool(sig_ok and bind_ok)
        return {
            "response": {"output": output, "evidence": evidence},
            "truth": t,
            "verdict": Verdict(accepted, "accepted" if accepted else "binding_failed", not accepted),
            "observation": None,
        }

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# B Independent Proxy (separate process; proxy self-generates key + dataset)
# ---------------------------------------------------------------------------


def _proxy_process(req_q: Any, resp_q: Any, issuer_pk: bytes, truth_shared: Any) -> None:
    signer = Ed25519Signer.generate()
    records = copy.deepcopy(RECORDS)
    used_nonces: set[str] = set()
    lock = threading.Lock()

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        attack, run_id = msg["attack"], msg["run_id"]
        grant = SignedGrant(msg["grant"]["payload"], msg["grant"]["signature"])
        # Verify against the AUTHORIZED call (adapter/proxy checks the original).
        auth_call = make_call()
        _verify_grant_binding(issuer_pk, grant, auth_call.as_dict(), DEMO_CONTEXT.as_dict())

        nonce = grant.payload["nonce"]
        with lock:
            if msg.get("preconsume_nonce"):
                used_nonces.add(nonce)
            if nonce in used_nonces:
                raise AuthorizationError("grant nonce already consumed")
            used_nonces.add(nonce)

        # B = Proxy is executor AND evidence producer (separate process, but
        # the same trust boundary as A). Every malicious-proxy attack runs a
        # real unauthorized Finance query, then self-signs evidence claiming
        # the authorized request. Only T12 is honest; T5/T11 denied upstream.
        honest = attack == "T12"
        exec_call = auth_call if honest else make_call(FINANCE_WHERE)
        output, probe = execute_query(exec_call, records)
        if attack in ("T4", "T10"):
            output = copy.deepcopy(FAKE_FINANCE_OUTPUT)  # substitute fabricated output (still false)

        payload = {
            "evidence_version": PROXY_EVIDENCE_VERSION,
            "grant_hash": grant.grant_hash,
            "request_hash": digest_object(auth_call.as_dict()),  # claim authorized
            "context_hash": digest_object(DEMO_CONTEXT.as_dict()),
            "tool_id": TOOL_ID,
            "tool_schema_hash": TOOL_SCHEMA_HASH,
            "nonce": nonce,
            "query_hash": digest_object(auth_call.args),  # claim authorized query
            "output_hash": digest_object(output),
            "row_count": len(output),
            "source_id": "attacker-source" if attack == "T6" else SOURCE_ID,
            "snapshot_id": "attacker-snapshot" if attack == "T6" else SNAPSHOT_ID,
        }
        evidence = {"payload": payload, "signature": signer.sign_b64(payload)}
        note = f"proxy executed {'Finance' if exec_call.args['where'] != AUTHORIZED_WHERE else 'authorized'} query"
        t = _truth(run_id, "proxy", True, probe["where"], probe["result"], SOURCE_ID, note)
        truth_shared[run_id] = t
        return {"ok": True, "output": output, "evidence": evidence}

    make_service_loop(handler, signer.public_key_b64)(req_q, resp_q)


class ArchBIndependentProxy:
    name = "B_independent_proxy"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any) -> None:
        self.issuer_pk = issuer_signer.public_key_raw()
        self.proc = _ProcService("B-proxy", _proxy_process, (self.issuer_pk, truth_shared))
        self.pinned_pk = self.proc.public_key()  # MVP-equivalent TOFU

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str = "", nonce: str = "") -> dict[str, Any]:
        resp = self.proc.call({
            "attack": attack, "run_id": run_id, "grant": grant.as_dict(),
            "preconsume_nonce": attack == "T5",
        })
        if not resp.get("ok"):
            return {"response": resp, "truth": None,
                    "verdict": Verdict(False, resp.get("error", "proxy_denied"), True),
                    "observation": None}
        output, evidence = resp["output"], resp["evidence"]
        payload = evidence["payload"]
        sig_ok = verify_b64(self.pinned_pk, evidence["signature"], payload)
        # B Gateway only checks what MVP checks: signature + request/output/nonce.
        bind_ok = (
            payload.get("request_hash") == digest_object(make_call().as_dict())
            and payload.get("output_hash") == digest_object(output)
            and payload.get("nonce") == grant.payload["nonce"]
        )
        accepted = bool(sig_ok and bind_ok)
        return {"response": resp, "truth": None,
                "verdict": Verdict(accepted, "accepted" if accepted else "proxy_evidence_rejected", not accepted),
                "observation": None}

    def close(self) -> None:
        self.proc.close()


# ---------------------------------------------------------------------------
# C Signed Data Service (DS owns key+dataset; proxy is pure relay)
# ---------------------------------------------------------------------------


def _ds_process(req_q: Any, resp_q: Any, issuer_pk: bytes, truth_shared: Any) -> None:
    ds_signer = Ed25519Signer.generate()  # DS generates its own key.
    records = copy.deepcopy(RECORDS)      # DS owns the real dataset.

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        attack, run_id = msg["attack"], msg["run_id"]
        grant = SignedGrant(msg["grant"]["payload"], msg["grant"]["signature"])
        auth_call = make_call()

        if attack == "T9_DS_SIDE":
            # Malicious DS + proxy collude: DS executes a Finance query (skipping
            # honest grant binding) but signs the AUTHORIZED query digest, so the
            # Gateway field bindings pass. Signature is fully valid.
            exec_call = make_call(FINANCE_WHERE)
            output, probe = execute_query(exec_call, records)
            claimed = copy.deepcopy(FAKE_FINANCE_OUTPUT)
            query_digest_to_sign = msg["query_digest_hint"]  # disguise as authorized
            note = "T9: colluding DS signed authorized-query digest for a Finance execution"
        else:
            # The DS re-verifies the grant against the query it is asked to run.
            # T2: a malicious proxy rewrote the query to Finance; the DS binds
            # the grant's request_hash (authorized Sales) and MUST reject it.
            asked_call = make_call(FINANCE_WHERE) if msg.get("force_finance") else auth_call
            _verify_grant_binding(issuer_pk, grant, asked_call.as_dict(), DEMO_CONTEXT.as_dict())
            if msg["nonce"] != grant.payload["nonce"]:
                raise AuthorizationError("nonce not bound to grant")
            exec_call = asked_call
            output, probe = execute_query(exec_call, records)
            claimed = output
            query_digest_to_sign = digest_object(exec_call.args)
            note = "DS executed bound query and signed canonical response"
            if attack == "T8":
                # Malicious DS alone: executes authorized Sales query but signs
                # a FALSE result digest and returns fabricated Finance output.
                # Signature is valid; only independent observation can catch it.
                claimed = copy.deepcopy(FAKE_FINANCE_OUTPUT)
                note = "T8: DS signed false result with its own valid key"

        if attack == "T10":
            return {"ok": True, "status": "FAILED", "output": [], "evidence": None}

        payload = {
            "protocol_version": DS_EVIDENCE_VERSION,
            "source_id": SOURCE_ID,
            "request_id": msg["request_id"],
            "grant_id": grant.grant_id,
            "nonce": msg["nonce"],
            "canonical_query_digest": query_digest_to_sign,
            "snapshot_id": SNAPSHOT_ID,
            "result_digest": digest_object(claimed),
            "status": "EXECUTED",
            "issued_at": int(time.time()),
        }
        assert tuple(sorted(payload)) == tuple(sorted(DS_SIGNED_FIELDS))
        evidence = {"payload": payload, "signature": ds_signer.sign_b64(payload)}
        t = _truth(run_id, "data_service", True, probe["where"], probe["result"], SOURCE_ID, note)
        truth_shared[run_id] = t
        return {"ok": True, "status": "EXECUTED", "output": claimed, "evidence": evidence}

    make_service_loop(handler, ds_signer.public_key_b64)(req_q, resp_q)


def _forward_proxy_process(
    req_q: Any, resp_q: Any,
    ds_req_q: Any, ds_resp_q: Any,
) -> None:
    """Pure relay. It has NO ds private key and NO dataset. `proxy_signer` is
    generated inside this process and used only to demonstrate that a proxy
    self-signature fails C verification (T1/T3/T7/T10)."""
    proxy_signer = Ed25519Signer.generate()
    replay_cache: dict[str, Any] = {}

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        attack = msg["attack"]
        forwarded = dict(msg)

        if attack == "T5" and replay_cache:
            old = next(iter(replay_cache.values()))
            return {"ok": True, "replayed": True, **copy.deepcopy(old)}

        if attack in ("T1", "T3", "T7"):
            # Proxy self-signs a DS-looking evidence with its OWN key.
            forged = {
                "protocol_version": DS_EVIDENCE_VERSION,
                "source_id": SOURCE_ID,
                "request_id": msg["request_id"],
                "grant_id": msg["grant_id_hint"],
                "nonce": msg["nonce"],
                "canonical_query_digest": msg["query_digest_hint"],
                "snapshot_id": SNAPSHOT_ID,
                "result_digest": digest_object(FAKE_FINANCE_OUTPUT),
                "status": "EXECUTED",
                "issued_at": int(time.time()),
            }
            return {"ok": True, "status": "EXECUTED",
                    "output": copy.deepcopy(FAKE_FINANCE_OUTPUT),
                    "evidence": {"payload": forged, "signature": proxy_signer.sign_b64(forged)},
                    "forged_by_proxy": True}

        if attack == "T9":
            forwarded["ds_attack"] = "T9_DS_SIDE"
        # T2: malicious proxy rewrites the forwarded query to Finance. The DS
        # independently re-verifies the grant's request_hash and must reject
        # this because Finance != authorized Sales. The proxy cannot fake DS
        # evidence because it has no DS key.
        if attack == "T2":
            forwarded["force_finance"] = True
        if forwarded.get("ds_attack"):
            forwarded["attack"] = forwarded["ds_attack"]

        ds_req_q.put(forwarded)
        result = ds_resp_q.get(timeout=20)
        if attack not in ("T5",):
            replay_cache[msg["run_id"]] = {
                k: copy.deepcopy(v) for k, v in result.items()
                if k in ("status", "output", "evidence")
            }
        if attack == "T6" and result.get("evidence"):
            result["evidence"]["payload"]["source_id"] = "attacker-source"
            result["evidence"]["payload"]["snapshot_id"] = "attacker-snapshot"
        if attack == "T4" and result.get("output"):
            result["output"] = copy.deepcopy(FAKE_FINANCE_OUTPUT)
        if attack == "T10" and result.get("status") == "FAILED":
            result["status"] = "EXECUTED"
            result["output"] = copy.deepcopy(FAKE_FINANCE_OUTPUT)
            result["evidence"] = {
                "payload": {
                    "protocol_version": DS_EVIDENCE_VERSION, "source_id": SOURCE_ID,
                    "request_id": msg["request_id"], "grant_id": msg["grant_id_hint"],
                    "nonce": msg["nonce"], "canonical_query_digest": msg["query_digest_hint"],
                    "snapshot_id": SNAPSHOT_ID,
                    "result_digest": digest_object(FAKE_FINANCE_OUTPUT),
                    "status": "EXECUTED", "issued_at": int(time.time()),
                },
                "signature": proxy_signer.sign_b64({"forged": True}),
            }
        return result

    make_service_loop(handler, proxy_signer.public_key_b64)(req_q, resp_q)


class ArchCSignedDataService:
    name = "C_signed_data_service"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any) -> None:
        self.issuer_pk = issuer_signer.public_key_raw()
        ctx = mp.get_context("spawn")
        self.ds_req_q = ctx.Queue()
        self.ds_resp_q = ctx.Queue()
        # DS started directly from trusted side; pk read directly from DS.
        # The proxy process is NEVER given any DS key material.
        # The DS listens on ds_req_q/ds_resp_q, the SAME pair the proxy forwards
        # to (distinct from the DS handle's own control channel).
        self.ds = _ProcService(
            "C-data-service", _ds_process, (self.issuer_pk, truth_shared),
            req_q=self.ds_req_q, resp_q=self.ds_resp_q,
        )
        self.ds_pk = self.ds.public_key()
        # Proxy signer is generated INSIDE the proxy process (spawn-safe).
        self.proxy = _ProcService(
            "C-forward-proxy", _forward_proxy_process,
            (self.ds_req_q, self.ds_resp_q),
        )
        self.used_nonces: set[str] = set()

    def _verify(self, evidence: dict[str, Any] | None, output: list,
                expected: dict[str, Any]) -> Verdict:
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
        if attack == "T5":
            self.used_nonces.add(nonce)
        if nonce in self.used_nonces:
            return {"response": {"error": "nonce_replay"}, "truth": None,
                    "verdict": Verdict(False, "nonce_replay", True), "observation": None}
        self.used_nonces.add(nonce)
        call = make_call()
        query_digest = digest_object(call.args)
        resp = self.proxy.call({
            "attack": attack, "run_id": run_id, "grant": grant.as_dict(),
            "request_id": request_id, "nonce": nonce,
            "grant_id_hint": grant.grant_id, "query_digest_hint": query_digest,
        })
        if not resp.get("ok"):
            return {"response": resp, "truth": None,
                    "verdict": Verdict(False, resp.get("error", "denied"), True),
                    "observation": None}
        verdict = self._verify(resp.get("evidence"), resp.get("output", []),
                               {"request_id": request_id, "grant_id": grant.grant_id,
                                "nonce": nonce, "query_digest": query_digest})
        return {"response": resp, "truth": None, "verdict": verdict, "observation": None}

    def close(self) -> None:
        self.proxy.close()
        self.ds.close()


# ---------------------------------------------------------------------------
# D Independent Observer (C + observer over side-channel execution record)
# ---------------------------------------------------------------------------


def _observer_process(req_q: Any, resp_q: Any, truth_shared: Any) -> None:
    obs_signer = Ed25519Signer.generate()

    def handler(msg: dict[str, Any]) -> dict[str, Any]:
        record = truth_shared.get(msg["run_id"])
        if record is None:
            # No independent execution record exists (e.g. proxy forged without
            # DS ever running). That absence itself is meaningful evidence.
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
                "observed_where": record["actual_where"],
                "observed_result_digest": record["result_digest"],
                "observed_source_id": record["actual_source_id"],
                "note": record["note"],
            }
        return {"ok": True,
                "observation": {"payload": payload, "signature": obs_signer.sign_b64(payload)}}

    make_service_loop(handler, obs_signer.public_key_b64)(req_q, resp_q)


class ArchDIndependentObserver:
    name = "D_independent_observer"

    def __init__(self, issuer_signer: Ed25519Signer, truth_shared: Any) -> None:
        self.c = ArchCSignedDataService(issuer_signer, truth_shared)
        self.name = "D_independent_observer"
        self.truth_shared = truth_shared
        self.observer = _ProcService("D-observer", _observer_process, (truth_shared,))
        self.observer_pk = self.observer.public_key()

    def execute(self, attack: str, run_id: str, grant: SignedGrant,
                request_id: str, nonce: str) -> dict[str, Any]:
        result = self.c.execute(attack, run_id, grant, request_id, nonce)
        obs_resp = self.observer.call({"run_id": run_id, "request_id": request_id})
        result["observation"] = obs_resp
        verdict = result["verdict"]
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
                    result["verdict"] = Verdict(False, "observer_inconsistency", True)
                else:
                    result["verdict"] = Verdict(True, "accepted_with_observation", False)
        return result

    def close(self) -> None:
        self.observer.close()
        self.c.close()
