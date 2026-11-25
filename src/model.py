"""Shared data model, fixed dataset, and ground-truth execution probe.

Ground truth is produced by the process that ACTUALLY runs the query, and is
reported to the experiment driver over a side channel that Proxy never sees.
This is a fixture-level probe (cf. MVP E2 B4): it does NOT claim the Gateway
has an independent production observation capability.
"""
from __future__ import annotations

import copy
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .primitives import digest_object

TOOL_ID = "finance.query.v1"
TOOL_SCHEMA: dict[str, Any] = {
    "tool_id": TOOL_ID,
    "input": {
        "fields": "non-empty list[str]",
        "where": "dict[str, scalar]",
        "limit": "integer >= 1",
    },
    "output": "list[object]",
}
TOOL_SCHEMA_HASH = digest_object(TOOL_SCHEMA)

POLICY_ID = "finance-read-sales-2026"
SOURCE_ID = "ds-finance-records-v1"
SNAPSHOT_ID = "snapshot-2026-11-v1"
SNAPSHOT_ISSUED_AT = 1_793_000_000  # fixed, reproducible snapshot epoch

DS_EVIDENCE_VERSION = "d3-13-ds-evidence-v1"
PROXY_EVIDENCE_VERSION = "d3-13-proxy-evidence-v1"
OBSERVER_EVIDENCE_VERSION = "d3-13-observer-evidence-v1"

# DS evidence signed-field set (user-specified 10 fields, no ambiguous JSON).
DS_SIGNED_FIELDS = (
    "protocol_version",
    "source_id",
    "request_id",
    "grant_id",
    "nonce",
    "canonical_query_digest",
    "snapshot_id",
    "result_digest",
    "status",
    "issued_at",
)

# Fixed dataset owned by the Data Service (not by Adapter or Proxy).
RECORDS: list[dict[str, Any]] = [
    {"year": 2026, "department": "Sales", "amount": 1200, "id_number": "SENSITIVE-001"},
    {"year": 2026, "department": "Finance", "amount": 3400, "id_number": "SENSITIVE-002"},
    {"year": 2025, "department": "Sales", "amount": 900, "id_number": "SENSITIVE-003"},
]

AUTHORIZED_WHERE: dict[str, Any] = {"year": 2026, "department": "Sales"}
AUTHORIZED_FIELDS: list[str] = ["year", "department", "amount"]
AUTHORIZED_LIMIT = 5
FINANCE_WHERE: dict[str, Any] = {"year": 2026, "department": "Finance"}


class AuthorizationError(Exception):
    """Raised when a request fails an authorization/verification check."""


@dataclass(frozen=True)
class ToolCall:
    agent_id: str
    tool_id: str
    resource: str
    operation: str
    args: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "resource": self.resource,
            "operation": self.operation,
            "args": self.args,
        }


@dataclass(frozen=True)
class ExecutionContext:
    session_id: str
    task_id: str
    tenant_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    agent_id: str
    tool_id: str
    resource: str
    allowed_operations: tuple[str, ...]
    allowed_fields: tuple[str, ...]
    required_filters: dict[str, Any]
    allowed_filter_values: dict[str, tuple[Any, ...]]
    max_rows: int
    tenant_id: str
    expires_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "resource": self.resource,
            "allowed_operations": list(self.allowed_operations),
            "allowed_fields": list(self.allowed_fields),
            "required_filters": self.required_filters,
            "allowed_filter_values": {k: list(v) for k, v in self.allowed_filter_values.items()},
            "max_rows": self.max_rows,
            "tenant_id": self.tenant_id,
            "expires_at": self.expires_at,
        }

    @property
    def policy_hash(self) -> str:
        return digest_object(self.as_dict())

    def check(self, call: ToolCall, context: ExecutionContext) -> None:
        if call.agent_id != self.agent_id:
            raise AuthorizationError("agent principal is not authorized")
        if call.tool_id != self.tool_id:
            raise AuthorizationError("tool is not authorized by this policy")
        if call.resource != self.resource:
            raise AuthorizationError("resource is outside policy scope")
        if call.operation not in self.allowed_operations:
            raise AuthorizationError("operation is not allowed")
        if context.tenant_id != self.tenant_id:
            raise AuthorizationError("tenant context does not match policy")
        args = call.args
        if set(args) != {"fields", "where", "limit"}:
            raise AuthorizationError("tool arguments do not match the closed schema")
        fields, where, limit = args["fields"], args["where"], args["limit"]
        if not isinstance(fields, list) or not fields:
            raise AuthorizationError("fields must be a non-empty list")
        if not set(fields).issubset(set(self.allowed_fields)):
            raise AuthorizationError("requested field is outside policy scope")
        if not isinstance(where, dict):
            raise AuthorizationError("where must be an object")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise AuthorizationError("limit must be a positive integer")
        if limit > self.max_rows:
            raise AuthorizationError("requested row limit exceeds policy")
        for key, required_value in self.required_filters.items():
            if where.get(key) != required_value:
                raise AuthorizationError(f"required filter missing or changed: {key}")
        for key, value in where.items():
            if key in self.required_filters:
                continue
            allowed = self.allowed_filter_values.get(key)
            if allowed is None or value not in allowed:
                raise AuthorizationError(f"filter is not allowed: {key}")


DEMO_POLICY = Policy(
    policy_id=POLICY_ID,
    version=1,
    agent_id="agent:finance-assistant",
    tool_id=TOOL_ID,
    resource="finance_records",
    allowed_operations=("read",),
    allowed_fields=("year", "department", "amount"),
    required_filters={"year": 2026},
    allowed_filter_values={"department": ("Sales", "Finance")},
    max_rows=10,
    tenant_id="tenant:example",
    expires_at=2_000_000_000,
)

DEMO_CONTEXT = ExecutionContext("session-001", "task-001", "tenant:example")


def make_call(where: dict[str, Any] | None = None) -> ToolCall:
    return ToolCall(
        agent_id="agent:finance-assistant",
        tool_id=TOOL_ID,
        resource="finance_records",
        operation="read",
        args={
            "fields": list(AUTHORIZED_FIELDS),
            "where": copy.deepcopy(AUTHORIZED_WHERE if where is None else where),
            "limit": AUTHORIZED_LIMIT,
        },
    )


@dataclass(frozen=True)
class SignedGrant:
    payload: dict[str, Any]
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    @property
    def grant_hash(self) -> str:
        return digest_object(self.as_dict())

    @property
    def grant_id(self) -> str:
        return self.grant_hash


def issue_grant(
    signer: Any,
    call: ToolCall,
    context: ExecutionContext,
    policy: Policy = DEMO_POLICY,
    now: int | None = None,
    ttl_seconds: int = 60,
    nonce: str | None = None,
    override_payload: dict[str, Any] | None = None,
) -> SignedGrant:
    """Mint a request-bound grant.

    `nonce` lets the trusted requester (Gateway/driver) supply freshness for C/D,
    instead of letting the execution proxy choose it. `override_payload` is used
    only by controlled fixtures (expired-grant attack), never by an attacker.
    """
    now = int(time.time()) if now is None else int(now)
    policy.check(call, context)
    if now >= policy.expires_at:
        raise AuthorizationError("policy has expired")
    expires_at = min(now + ttl_seconds, policy.expires_at)
    payload = {
        "issuer_id": "issuer-1",
        "agent_id": call.agent_id,
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "policy_hash": policy.policy_hash,
        "request_hash": digest_object(call.as_dict()),
        "context_hash": digest_object(context.as_dict()),
        "tool_id": call.tool_id,
        "tool_schema_hash": TOOL_SCHEMA_HASH,
        "nonce": nonce if nonce is not None else secrets.token_hex(24),
        "issued_at": now,
        "expires_at": expires_at,
    }
    if override_payload:
        payload.update(override_payload)
    return SignedGrant(payload, signer.sign_b64(payload))


@dataclass
class ExecutionTruth:
    """Ground truth written by the process that actually ran the query."""

    run_id: str
    executor_role: str
    executed: bool
    actual_where: dict[str, Any] | None
    actual_result: list[dict[str, Any]] | None
    actual_source_id: str | None
    result_digest: str | None
    note: str = ""

    @property
    def unauthorized_execution(self) -> bool:
        """True when a real query ran with parameters outside the grant."""
        return bool(self.executed and self.actual_where != AUTHORIZED_WHERE)


def execute_query(
    call: ToolCall,
    records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the real query against the given records (no receipt involved)."""
    data = RECORDS if records is None else records
    where = call.args["where"]
    fields = call.args["fields"]
    matched = [
        row for row in data
        if all(row.get(key) == value for key, value in where.items())
    ]
    selected = matched[: call.args["limit"]]
    output = [{key: row[key] for key in fields if key in row} for row in selected]
    probe = {
        "where": copy.deepcopy(where),
        "scanned_rows": len(data),
        "matched_rows": len(matched),
        "result": copy.deepcopy(output),
        "result_digest": digest_object(output),
        "comparison_events": sum(1 for row in data for _ in where.items()),
    }
    return output, probe


# --- R1: fixed seed-request constants and the enriched ground-truth record ---
# A historical response is produced ONCE per architecture from an independent
# seed request, stored, then replayed verbatim by T5. The seed request is NOT
# counted in any attack arm's N; it is logged in meta.seed_requests.
SEED_RUN_ID = "d3-13-historical-seed"
SEED_REQUEST_ID = "20261125-seed-req"
SEED_NONCE = "20261125-seed-nonce"


def result_within_grant(output: list[dict[str, Any]] | None) -> bool:
    """True iff every returned row is inside the granted Sales filter scope.

    In this fixture the only out-of-scope data is Finance rows, so "returned a
    row whose department/year does not match AUTHORIZED_WHERE" is the concrete
    instantiation of unauthorized_result_disclosure. An empty result discloses
    nothing.
    """
    if not output:
        return True
    return all(
        isinstance(row, dict)
        and all(row.get(key) == value for key, value in AUTHORIZED_WHERE.items())
        for row in output
    )


def build_truth(
    run_id: str,
    role: str,
    executed: bool,
    actual_where: dict[str, Any] | None,
    actual_result: list[dict[str, Any]] | None,
    returned_output: list[dict[str, Any]] | None,
    note: str = "",
    *,
    granted_query_where: dict[str, Any] | None = None,
    executor_input_query_where: dict[str, Any] | None = None,
    tamper_stage: str = "none",
) -> dict[str, Any]:
    """R1.1 ground truth: separate real execution from returned output, AND
    distinguish the three query states so T1 and T2 are different real attacks.

      granted_query_where         : what the grant authorized (Sales/2026).
      executor_input_query_where  : what the executor actually received.
      actual_query_where          : what the DS truly ran (None if not executed).
      tamper_stage                : where the parameter diverged from the grant.
        - none                              : no divergence (honest / result-only)
        - post_authorization_executor_override (T1): executor got Sales, grant
          check passed, executor then overrode to Finance before running it.
        - pre_executor_ingress_tamper (T2)  : request already Finance when it
          reached the executor; executor did NOT re-bind the actual input.
        - collusion_ds_finance              (T9): colluding DS ran Finance.
        - historical_replay / pre_execution_failure : no new query.

    Written by the role that actually controls the query path, and reported to
    the driver over the experiment side channel. For architecture D this side
    channel is an explicitly-trusted TEST ORACLE, not a production observation
    interface (see THREAT-MODEL.md / ARCHITECTURE-COMPARISON.md).
    """
    unauthorized_exec = bool(executed and actual_where != AUTHORIZED_WHERE)
    unauthorized_disclosure = bool(returned_output) and not result_within_grant(returned_output)
    actual_res_digest = digest_object(actual_result) if actual_result is not None else None
    return {
        "run_id": run_id,
        "executor_role": role,
        "executed": bool(executed),
        "actual_query_where": copy.deepcopy(actual_where) if actual_where is not None else None,
        "actual_query_result_digest": actual_res_digest,
        "returned_output_digest": (
            digest_object(returned_output) if returned_output is not None else None
        ),
        "actual_source_id": SOURCE_ID if executed else None,
        "unauthorized_execution": unauthorized_exec,
        "unauthorized_result_disclosure": unauthorized_disclosure,
        # R1.1 query-state provenance
        "granted_query_where": copy.deepcopy(
            granted_query_where if granted_query_where is not None else AUTHORIZED_WHERE
        ),
        "executor_input_query_where": (
            copy.deepcopy(executor_input_query_where)
            if executor_input_query_where is not None else None
        ),
        "tamper_stage": tamper_stage,
        # legacy aliases kept so older tooling keeps working
        "result_digest": actual_res_digest,
        "actual_where": copy.deepcopy(actual_where) if actual_where is not None else None,
        "note": note,
    }
