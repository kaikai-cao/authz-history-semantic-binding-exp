"""Evidence-vs-ground-truth consistency (R1).

A signed receipt/evidence is "false" when what it DECLARES does not match what
the process that really ran the query recorded as ground truth. This check is
independent of attack names; it is computed from evidence payload vs the
enriched ground-truth record. R1 changes:

  - ground truth carries BOTH actual_query_result_digest (what the executed
    query really returned) and returned_output_digest (what was handed to the
    Gateway). T4 result substitution is now detectable: the query was honest
    but the returned output is a different real result.
  - source_id is checked against the truth's actual_source_id, so B's T6
    field tamper ("attacker-source") is a false statement even when B's weak
    Gateway would accept it.
  - "executed=False but status=EXECUTED" is still false evidence (T3/T10).
"""
from __future__ import annotations

from typing import Any

from .model import make_call
from .primitives import digest_object


def _actual_query_digests(truth: dict[str, Any]) -> tuple[str | None, str | None]:
    where = truth.get("actual_query_where")
    if where is None:
        where = truth.get("actual_where")
    if where is None:
        return None, None
    call = make_call(where)
    return digest_object(call.args), digest_object(call.as_dict())


def claimed_query_matches_actual(evidence_payload: dict[str, Any] | None,
                                 truth: dict[str, Any] | None) -> bool:
    if not evidence_payload or not truth:
        return False
    actual_args_d, actual_req_d = _actual_query_digests(truth)
    if actual_args_d is None:
        return False
    if "canonical_query_digest" in evidence_payload:
        return evidence_payload["canonical_query_digest"] == actual_args_d
    if "query_hash" in evidence_payload:
        return evidence_payload["query_hash"] == actual_args_d
    if "request_hash" in evidence_payload:
        return evidence_payload["request_hash"] == actual_req_d
    return False


def claimed_result_matches_execution(evidence_payload: dict[str, Any] | None,
                                     truth: dict[str, Any] | None) -> bool:
    """Compare the declared result to what the EXECUTED query really returned.

    We deliberately use actual_query_result_digest (not returned_output_digest):
    a substituted output (T4/T8) is exactly the case where evidence declares a
    result that was not produced by the query it claims to have run.
    """
    if not evidence_payload or not truth:
        return False
    actual = truth.get("actual_query_result_digest")
    if actual is None:
        actual = truth.get("result_digest")
    if actual is None:
        return False
    for key in ("result_digest", "output_hash"):
        if key in evidence_payload:
            return evidence_payload[key] == actual
    return False


def claimed_source_matches_actual(evidence_payload: dict[str, Any] | None,
                                  truth: dict[str, Any] | None) -> bool:
    if not evidence_payload or not truth:
        return False
    if "source_id" not in evidence_payload:
        return True  # field not in this architecture's evidence schema
    return evidence_payload.get("source_id") == truth.get("actual_source_id")


def evidence_is_false(evidence_payload: dict[str, Any] | None,
                      truth: dict[str, Any] | None) -> bool:
    """True iff the evidence statement is inconsistent with ground truth."""
    if not evidence_payload or not truth:
        return False
    if not truth.get("executed"):
        # Evidence claiming an execution that never happened (T3/T10/T5-replay).
        return evidence_payload.get("status") == "EXECUTED"
    return not (
        claimed_query_matches_actual(evidence_payload, truth)
        and claimed_result_matches_execution(evidence_payload, truth)
        and claimed_source_matches_actual(evidence_payload, truth)
    )
