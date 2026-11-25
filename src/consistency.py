"""Cross-architecture evidence-vs-ground-truth consistency check.

A signed receipt/evidence is "false" when what it declares does not match what
the process that really ran the query recorded as ground truth. This check is
independent of attack names; it is computed from the evidence payload and the
execution record so T8/T9 (valid signature, false statement) are captured and
T12 (honest) is not.
"""
from __future__ import annotations

from typing import Any

from .model import AUTHORIZED_WHERE, make_call
from .primitives import digest_object


def claimed_query_matches_actual(evidence_payload: dict[str, Any] | None,
                                 truth: dict[str, Any] | None) -> bool:
    if not evidence_payload or not truth:
        return False
    actual_where = truth.get("actual_where")
    if actual_where is None:
        return False
    actual_call = make_call(actual_where)
    actual_query_digest = digest_object(actual_call.args)
    actual_request_hash = digest_object(actual_call.as_dict())

    # Architecture C/D: canonical_query_digest over args.
    if "canonical_query_digest" in evidence_payload:
        return evidence_payload["canonical_query_digest"] == actual_query_digest
    # Architecture A/B: request_hash and/or query_hash over the call.
    if "request_hash" in evidence_payload and evidence_payload["request_hash"] != actual_request_hash:
        return False
    if "query_hash" in evidence_payload and evidence_payload["query_hash"] != actual_query_digest:
        return False
    return "request_hash" in evidence_payload


def claimed_result_matches_actual(evidence_payload: dict[str, Any] | None,
                                  truth: dict[str, Any] | None) -> bool:
    if not evidence_payload or not truth:
        return False
    actual_digest = truth.get("result_digest")
    if actual_digest is None:
        return False
    for key in ("result_digest", "output_hash"):
        if key in evidence_payload:
            return evidence_payload[key] == actual_digest
    return False


def evidence_is_false(evidence_payload: dict[str, Any] | None,
                      truth: dict[str, Any] | None) -> bool:
    """True iff the evidence statement is inconsistent with ground truth."""
    if not evidence_payload or not truth:
        return False
    if not truth.get("executed"):
        # Evidence that claims an execution which never happened.
        return evidence_payload.get("status") == "EXECUTED"
    return not (claimed_query_matches_actual(evidence_payload, truth)
                and claimed_result_matches_actual(evidence_payload, truth))
