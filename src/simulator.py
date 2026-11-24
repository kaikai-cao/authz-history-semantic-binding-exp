"""Deterministic protocol simulator for D3-07-B-P1.

No cryptography is performed here.  Votes are structured objects whose
binding fields model what a signed message would commit to.  The simulator is
used only to compare recovery rules under prescribed schedules.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEED = 20261124
WITNESS_COUNT = 4
QC_THRESHOLD = 3
FC_THRESHOLD = 3
BYZANTINE_LIMIT = 1
LEASE_DURATION = 100
CLOCK_EPSILON = 5

WITNESS_IDS = ("W1", "W2", "W3", "W4")
VALID_MODELS = ("A", "B", "C", "UNSAFE")


def keystr(key: Tuple[Any, ...]) -> str:
    return "|".join(str(x) for x in key)


@dataclass(frozen=True)
class Checkpoint:
    chain_id: str
    witness_set_id: str
    epoch: int
    checkpoint_digest: str
    parent_digest: str
    transition_version: str = "d3-transition-v1"

    def lock_key(self) -> Tuple[str, str, int]:
        return (self.chain_id, self.witness_set_id, self.epoch)

    def full_key(self) -> Tuple[Any, ...]:
        return self.lock_key() + (
            self.checkpoint_digest,
            self.parent_digest,
            self.transition_version,
        )

    def conflicts(self, other: "Checkpoint") -> bool:
        return self.lock_key() == other.lock_key() and self.checkpoint_digest != other.checkpoint_digest


@dataclass(frozen=True)
class Vote:
    kind: str
    witness: str
    round: int
    cp: Checkpoint
    issued_at: int
    expires_at: Optional[int] = None
    nonce: Optional[str] = None

    def binding(self) -> Tuple[Any, ...]:
        return (self.kind, self.round) + self.cp.full_key() + (self.nonce,)


@dataclass
class Witness:
    wid: str
    honest: bool = True
    durable: Dict[str, Any] = field(default_factory=dict)
    volatile: Dict[str, Any] = field(default_factory=dict)
    clock_offset: int = 0

    def now(self, global_time: int) -> int:
        return global_time + self.clock_offset

    def signed_votes(self) -> List[Vote]:
        return list(self.durable.get("signed_votes", []))

    def add_vote(self, vote: Vote) -> None:
        self.durable.setdefault("signed_votes", []).append(vote)

    def floor(self) -> Tuple[int, str]:
        votes = self.signed_votes()
        if not votes:
            return (-1, "")
        highest = max(v.round for v in votes)
        digests = sorted({v.cp.checkpoint_digest for v in votes if v.round == highest})
        return (highest, digests[0] if digests else "")


@dataclass
class Gateway:
    model: str
    observed: List[Vote] = field(default_factory=list)
    qc: List[Dict[str, Any]] = field(default_factory=list)
    fc: List[Dict[str, Any]] = field(default_factory=list)
    committed: Dict[str, str] = field(default_factory=dict)
    decisions: List[str] = field(default_factory=list)


class Simulator:
    """One deterministic scenario instance."""

    def __init__(self, model: str, scenario_id: str, description: str) -> None:
        if model not in VALID_MODELS:
            raise ValueError(f"unknown model: {model}")
        self.model = model
        self.scenario_id = scenario_id
        self.description = description
        self.seed = SEED
        self.time = 0
        self.seq = 0
        self.events: List[Dict[str, Any]] = []
        self.messages: List[Dict[str, Any]] = []
        self.violations: List[Dict[str, str]] = []
        self.adversarial_observations: List[str] = []
        self.liveness: Dict[str, Dict[str, Any]] = {}
        self.author_liveness_r0: Dict[str, bool] = {}
        self.notes: List[str] = []
        self.initial_state: Dict[str, Any] = {}
        self.witnesses: Dict[str, Witness] = {
            wid: Witness(
                wid=wid,
                durable={
                    "signed_votes": [],
                    "pending": {},
                    "locked": {},
                    "committed": {},
                    "current_round": 0,
                },
                volatile={"observed": [], "polc": [], "current_round": 0},
            )
            for wid in WITNESS_IDS
        }
        self.gateway = Gateway(model=model)

    # ---------- event log ----------

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for wid, w in self.witnesses.items():
            floor_round, floor_digest = w.floor()
            out[wid] = {
                "honest": w.honest,
                "pending": {
                    keystr(k): {"digest": v["digest"], "round": v["round"], "expires_at": v.get("expires_at")}
                    for k, v in w.durable.get("pending", {}).items()
                },
                "locked": {keystr(k): v for k, v in w.durable.get("locked", {}).items()},
                "committed": {keystr(k): v for k, v in w.durable.get("committed", {}).items()},
                "current_round": w.volatile.get("current_round", 0),
                "signed_votes": len(w.signed_votes()),
                "floor_round": floor_round,
                "floor_digest": floor_digest,
                "clock_offset": w.clock_offset,
            }
        return out

    def log(
        self,
        action: str,
        *,
        phase: str = "",
        actor: str = "",
        detail: str = "",
        message: str = "",
        signature_time: Optional[int] = None,
        durable_change: str = "",
        qc_formed: str = "",
        fc_formed: str = "",
        gateway_decision: str = "",
    ) -> None:
        self.seq += 1
        self.events.append(
            {
                "global_event_seq": self.seq,
                "sim_time": self.time,
                "phase": phase,
                "actor": actor,
                "action": action,
                "detail": detail,
                "message": message,
                "signature_time": signature_time,
                "durable_change": durable_change,
                "qc_formed": qc_formed,
                "fc_formed": fc_formed,
                "gateway_decision": gateway_decision,
                "witness_state": self.snapshot(),
            }
        )

    def advance(self, dt: int, phase: str = "") -> None:
        self.time += dt
        self.log("clock_advance", phase=phase, detail=f"advanced {dt} time units to t={self.time}")
        self.deliver_due(phase=phase)

    def set_clock_offset(self, wid: str, offset: int, phase: str = "") -> None:
        self.witnesses[wid].clock_offset = offset
        self.log("clock_offset_set", phase=phase, actor=wid, detail=f"clock_offset={offset}")

    def set_gateway_time(self, t: int, phase: str = "") -> None:
        self.time = t
        self.log("gateway_time_set", phase=phase, actor="G", detail=f"gateway time set to {t}")
        self.deliver_due(phase=phase)

    def mark_byzantine(self, wid: str, phase: str = "") -> None:
        self.witnesses[wid].honest = False
        self.log("byzantine_marked", phase=phase, actor=wid, detail="witness treated as Byzantine for this scenario")

    def note(self, text: str) -> None:
        self.notes.append(text)

    def violation(self, invariant: str, detail: str) -> None:
        self.violations.append({"invariant": invariant, "detail": detail})

    def adversarial(self, detail: str) -> None:
        self.adversarial_observations.append(detail)

    def set_liveness(self, code: str, passed: bool, note: str) -> None:
        """R0 compatibility: keep the author's hand-written annotation only.

        R1 does not use this as the reported Liveness result; it is preserved
        as ``author_liveness_r0`` for the before/after comparison.
        """
        self.author_liveness_r0[code] = bool(passed)
        self.liveness[code] = {"passed": bool(passed), "note": note}

    # ---------- R1: liveness derived from recorded evidence ----------

    def _liveness_entry(self, passed: Optional[bool], note: str, basis: str) -> Dict[str, Any]:
        if passed is None:
            status = "not_applicable"
        elif passed:
            status = "achieved"
        else:
            status = "not_achieved"
        return {"status": status, "passed": passed, "note": note, "basis": basis}

    def derive_liveness(self) -> Dict[str, Dict[str, Any]]:
        """Compute L1-L4 from events and final state, never from author input.

        Precondition absent -> ``not_applicable`` (passed=None), never an
        automatic pass.  ``basis`` records the exact evidence used so the
        test suite can re-derive and cross-check the reported field.
        """
        actions = [e["action"] for e in self.events]
        phases = [e.get("phase", "") for e in self.events]
        accepted_events = [e for e in self.events if e["action"] in ("qc_accepted", "fc_accepted")]
        byzantine = {wid for wid, w in self.witnesses.items() if not w.honest}
        recovery_attempted = any(
            a in ("timeout_round_advance", "trusted_recovery", "unsafe_timeout_unlock")
            or "heal" in p
            or "recovery" in p
            for a, p in zip(actions, phases)
        )
        trusted_recovery_used = "trusted_recovery" in actions
        round_change_used = "timeout_round_advance" in actions
        clock_dependency = self.model == "C"

        signers_by_key: Dict[Tuple[str, int], set] = {}
        for w in self.witnesses.values():
            for v in w.signed_votes():
                if v.kind not in ("candidate", "prevote"):
                    continue
                signers_by_key.setdefault((v.cp.checkpoint_digest, v.round), set()).add(v.witness)
        accepted_digests = {q["digest"] for q in self.gateway.qc} | {f["digest"] for f in self.gateway.fc}
        incomplete = [
            (d, r, sorted(ss))
            for (d, r), ss in signers_by_key.items()
            if 0 < len(ss) < QC_THRESHOLD and d not in accepted_digests
        ]

        gateway_committed = set(self.gateway.committed.values())
        blocked: List[str] = []
        for wid, w in self.witnesses.items():
            if not w.honest:
                continue
            for rec in w.durable.get("locked", {}).values():
                if rec["digest"] not in gateway_committed:
                    blocked.append(f"{wid}:locked@{rec['round']}:{rec['digest'][:8]}")
            for rec in w.durable.get("pending", {}).values():
                if rec["digest"] not in gateway_committed:
                    blocked.append(f"{wid}:pending@{rec['round']}:{rec['digest'][:8]}")

        quorum_records = self.gateway.qc + self.gateway.fc
        honest_quorum = any(
            len([s for s in rec["signers"] if s not in byzantine]) >= QC_THRESHOLD
            for rec in quorum_records
        )

        out: Dict[str, Dict[str, Any]] = {}
        if not accepted_events and not recovery_attempted:
            out["L1"] = self._liveness_entry(
                None,
                "no advance or recovery attempt appears in this schedule",
                "events: qc_accepted/fc_accepted, timeout_round_advance, trusted_recovery, heal/recovery phase",
            )
        else:
            out["L1"] = self._liveness_entry(
                bool(accepted_events),
                (
                    f"{len(accepted_events)} accepted QC/FC record(s) observed"
                    if accepted_events
                    else "recovery attempted but no QC/FC was accepted"
                ),
                "events: qc_accepted / fc_accepted",
            )

        if not incomplete:
            out["L2"] = self._liveness_entry(
                None,
                "no candidate signed by 1..2 distinct witnesses exists in this schedule",
                "signed candidate/prevote signer sets versus accepted QC/FC digests",
            )
        else:
            out["L2"] = self._liveness_entry(
                bool(accepted_events) and not blocked,
                (
                    "progress observed despite an incomplete candidate"
                    if accepted_events and not blocked
                    else "no accepted progress" + (f"; unresolved lock(s): {blocked}" if blocked else "")
                ),
                "events: qc_accepted/fc_accepted; final durable locked/pending state",
            )

        if not byzantine:
            out["L3"] = self._liveness_entry(
                None,
                "no witness marked Byzantine/offline in this schedule",
                "events: byzantine_marked; accepted QC/FC signer sets",
            )
        else:
            out["L3"] = self._liveness_entry(
                honest_quorum,
                (
                    "accepted QC/FC contains at least three non-Byzantine signers"
                    if honest_quorum
                    else "no accepted QC/FC formed by three honest signers"
                ),
                "events: byzantine_marked; gateway QC/FC signer sets",
            )

        if not accepted_events:
            out["L4"] = self._liveness_entry(
                None,
                "no accepted QC/FC, so recovery dependencies cannot be observed",
                "events: trusted_recovery, timeout_round_advance; model clock parameter",
            )
        else:
            deps: List[str] = []
            if trusted_recovery_used:
                deps.append("trusted_recovery")
            if round_change_used:
                deps.append("extra_consensus_round")
            if clock_dependency:
                deps.append("trusted_clock")
            out["L4"] = self._liveness_entry(
                not deps,
                "no administrator/round/clock dependency observed" if not deps else "depends on " + ",".join(deps),
                "events: trusted_recovery, timeout_round_advance; model parameter",
            )
        return out

    # ---------- messaging ----------

    def send(self, vote: Vote, recipients: List[str], delay: int = 0, phase: str = "", drop: bool = False) -> Optional[int]:
        if vote is None:
            return None
        mid = len(self.messages) + 1
        self.messages.append(
            {
                "id": mid,
                "vote": vote,
                "recipients": list(recipients),
                "due": self.time + delay,
                "delivered": False,
                "dropped": drop,
            }
        )
        self.log(
            "message_send",
            phase=phase,
            actor=vote.witness,
            detail=f"{vote.kind} {vote.cp.checkpoint_digest[:8]} round={vote.round}",
            message=f"msg#{mid} -> {','.join(recipients)} due=t{self.time + delay} drop={drop}",
            signature_time=vote.issued_at,
        )
        return mid

    def deliver_due(self, phase: str = "") -> None:
        for msg in self.messages:
            if msg["delivered"] or msg["dropped"] or msg["due"] > self.time:
                continue
            msg["delivered"] = True
            for recipient in msg["recipients"]:
                if recipient == "G":
                    self.gateway.observed.append(msg["vote"])
                elif recipient in self.witnesses:
                    self.witnesses[recipient].volatile.setdefault("observed", []).append(msg["vote"])
                    if self.model == "B":
                        self.update_polc(self.witnesses[recipient])
                self.log(
                    "message_receive",
                    phase=phase or "delivery",
                    actor=recipient,
                    detail=f"received {msg['vote'].kind} {msg['vote'].cp.checkpoint_digest[:8]} round={msg['vote'].round}",
                    message=f"msg#{msg['id']}",
                    signature_time=msg["vote"].issued_at,
                )
            if self.model == "B":
                self.update_polc_gateway()

    def deliver_message(self, mid: int, phase: str = "") -> None:
        msg = self.messages[mid - 1]
        if msg["delivered"] or msg["dropped"]:
            return
        msg["due"] = self.time
        self.deliver_due(phase=phase)

    # ---------- model rules ----------

    def votes_for_polc(self, w: Witness) -> List[Vote]:
        """Votes available to a witness when evaluating a PoLC.

        A witness always knows its own votes, so its durable vote log is
        merged with delivered messages.  ``binding()`` deduplicates a vote
        that was both signed locally and delivered back by the network.
        """
        seen = set()
        out: List[Vote] = []
        for v in list(w.volatile.get("observed", [])) + w.signed_votes():
            # binding() intentionally omits the signer; include witness here so
            # three independent prevotes are not collapsed into one vote.
            b = (v.witness,) + v.binding()
            if b in seen:
                continue
            seen.add(b)
            out.append(v)
        return out

    def update_polc(self, w: Witness) -> None:
        counts: Dict[Tuple[Any, ...], set] = {}
        for v in self.votes_for_polc(w):
            if v.kind != "prevote":
                continue
            k = (v.cp.lock_key(), v.round, v.cp.checkpoint_digest)
            counts.setdefault(k, set()).add(v.witness)
        for k, signers in sorted(counts.items(), key=lambda kv: (kv[0][1], kv[0][2])):
            if len(signers) >= QC_THRESHOLD and list(k) not in w.volatile["polc"]:
                w.volatile["polc"].append(list(k))
                self.log(
                    "polc_observed",
                    phase="B",
                    actor=w.wid,
                    detail=f"PoLC round={k[1]} digest={k[2][:8]} signers={sorted(signers)}",
                )

    def update_polc_gateway(self) -> None:
        counts: Dict[Tuple[Any, ...], set] = {}
        for v in self.gateway.observed:
            if v.kind != "prevote":
                continue
            k = (v.cp.lock_key(), v.round, v.cp.checkpoint_digest)
            counts.setdefault(k, set()).add(v.witness)
        for k, signers in counts.items():
            if len(signers) >= QC_THRESHOLD:
                observed = self.gateway.__dict__.setdefault("polc", [])
                if list(k) not in [list(x) for x in observed]:
                    observed.append(list(k))

    def has_polc(self, w: Witness, cp: Checkpoint, round: int) -> bool:
        """Exact-round PoLC: no old-round evidence may be reused (S4)."""
        target = [cp.lock_key(), round, cp.checkpoint_digest]
        return any(list(x) == target for x in w.volatile.get("polc", []))

    def find_unlock_polc(
        self, w: Witness, cp: Checkpoint, locked: Dict[str, Any], current_round: int
    ) -> Optional[int]:
        """PoLC that may legally transfer a lock.

        Tendermint's condition is strictly
        ``locked_round < polc_round < current_round`` and the PoLC must bind a
        *different* digest on the same chain / witness set / epoch.  Same-round
        or lower-round PoLC, and merely entering a higher round, never unlock.
        """
        locked_round = locked["round"]
        locked_digest = locked["digest"]
        valid_rounds: List[int] = []
        for entry in w.volatile.get("polc", []):
            e = list(entry)
            if len(e) != 3 or tuple(e[0]) != cp.lock_key():
                continue
            polc_round, digest = e[1], e[2]
            if digest == locked_digest:
                continue
            if locked_round < polc_round < current_round:
                valid_rounds.append(polc_round)
        return min(valid_rounds) if valid_rounds else None

    def lock_state(self, w: Witness) -> Optional[Dict[str, Any]]:
        """Current durable lock for a witness (single binding namespace)."""
        locked = w.durable.get("locked", {})
        if not locked:
            return None
        key = sorted(locked)[0]
        return locked[key]

    def lease_expired_for(self, w: Witness, rec: Dict[str, Any]) -> bool:
        expires = rec.get("expires_at")
        return expires is not None and w.now(self.time) > expires + CLOCK_EPSILON

    def conflicting_pending(self, w: Witness, cp: Checkpoint) -> Optional[Tuple[Any, ...]]:
        for k, rec in w.durable.get("pending", {}).items():
            if rec["digest"] != cp.checkpoint_digest and k == keystr(cp.lock_key()):
                if self.model == "C" and self.lease_expired_for(w, rec):
                    continue
                return k
        return None

    def conflicting_commit(self, w: Witness, cp: Checkpoint) -> bool:
        rec = w.durable.get("committed", {}).get(keystr(cp.lock_key()))
        return rec is not None and rec != cp.checkpoint_digest

    def same_round_conflict_signed(self, w: Witness, cp: Checkpoint, kind: str, round: int) -> bool:
        for v in w.signed_votes():
            if v.kind == kind and v.round == round and v.cp.conflicts(cp):
                return True
        return False

    def can_sign(self, w: Witness, cp: Checkpoint, kind: str, round: int) -> Tuple[bool, str]:
        if not w.honest:
            return True, "byzantine witness bypasses local safety checks"

        if self.same_round_conflict_signed(w, cp, kind, round):
            return False, "S1: conflicting vote already signed for same kind/round"
        if self.conflicting_commit(w, cp):
            return False, "S2/S5: conflicting checkpoint already committed locally"

        if self.model == "A":
            if self.conflicting_pending(w, cp) is not None:
                return False, "pending lock conflict; no automatic release"
            return True, "permanent-lock rule allows signature"

        if self.model == "UNSAFE":
            return True, "unsafe timeout policy allows signature after local unlock"

        if self.model == "C":
            if self.conflicting_pending(w, cp) is not None:
                return False, "lease still active; pending lock conflict"
            return True, "lease rule allows signature"

        # Model B: Tendermint-style lock / PoLC state machine (R1 corrected).
        #
        # Explicit state, never conflated:
        #   current_round = w.volatile["current_round"] (advanced by timeout only)
        #   locked_round  = locked["round"]   (durable, set by precommit)
        #   locked_digest = locked["digest"]
        #   polc_round    = the round at which a 3-of-4 prevote set was observed
        #   polc_digest   = digest that the PoLC binds
        locked = w.durable.get("locked", {}).get(keystr(cp.lock_key()))
        current_round = max(w.volatile.get("current_round", 0), round)

        if kind == "prevote":
            if locked and locked["digest"] != cp.checkpoint_digest:
                unlock_round = self.find_unlock_polc(w, cp, locked, current_round)
                if unlock_round is None:
                    return False, (
                        f"locked at round {locked['round']} for different digest; "
                        f"conflicting prevote needs locked_round < polc_round < current_round "
                        f"({locked['round']} < polc_round < {current_round}); none observed"
                    )
                return True, (
                    f"lock transfer allowed by PoLC round {unlock_round}: "
                    f"{locked['round']} < {unlock_round} < {current_round}, digest={cp.checkpoint_digest[:8]}"
                )
            return True, "prevote rule allows signature (no conflicting lock)"

        if kind == "precommit":
            # Precommit requires a PoLC in the *same round* for the same cp;
            # an old-round PoLC must not be reinterpreted (S4).
            if not self.has_polc(w, cp, round):
                return False, "precommit requires PoLC observed for same checkpoint and exact round"
            # A witness that is locked on a conflicting digest must also satisfy
            # the strict lock-transfer condition before it may precommit.
            if locked and locked["digest"] != cp.checkpoint_digest:
                unlock_round = self.find_unlock_polc(w, cp, locked, round)
                if unlock_round is None:
                    return False, (
                        "precommit for conflicting digest blocked: "
                        f"no qualifying PoLC with {locked['round']} < polc_round < {round}"
                    )
            has_prevote = any(
                v.kind == "prevote" and v.round == round and v.cp.full_key() == cp.full_key()
                for v in w.signed_votes()
            )
            if not has_prevote:
                return False, "precommit requires own prevote in the same round"
            return True, "current-round PoLC + own prevote allow precommit and lock update"

        return False, f"unsupported vote kind for Model B: {kind}"

    # ---------- signing ----------

    def sign_vote(
        self,
        wid: str,
        cp: Checkpoint,
        kind: str,
        round: int = 0,
        *,
        nonce: Optional[str] = None,
        lease: Optional[int] = None,
        force_byzantine_conflict: bool = False,
        phase: str = "",
    ) -> Optional[Vote]:
        w = self.witnesses[wid]
        allowed, reason = self.can_sign(w, cp, kind, round)
        if not allowed and not force_byzantine_conflict:
            self.log("sign_rejected", phase=phase, actor=wid, detail=f"{kind} {cp.checkpoint_digest[:8]} round={round}: {reason}")
            return None
        if force_byzantine_conflict and w.honest:
            raise AssertionError("force_byzantine_conflict requires a Byzantine witness")

        issued = w.now(self.time)
        expires = issued + (lease if lease is not None else LEASE_DURATION) if self.model == "C" else None
        vote = Vote(kind=kind, witness=wid, round=round, cp=cp, issued_at=issued, expires_at=expires, nonce=nonce)

        durable_change = "signed vote appended to durable vote log"
        # R1: for Model B the durable lock is written *before* the vote is
        # recorded, so lock state and vote log cannot disagree, and both are
        # committed before the signature is returned to the caller.  This is
        # simulator state discipline only, not a claim of crash-safe storage.
        if self.model == "B" and kind == "precommit":
            w.durable.setdefault("locked", {})[keystr(cp.lock_key())] = {
                "round": round,
                "digest": cp.checkpoint_digest,
            }
            w.volatile["current_round"] = max(w.volatile.get("current_round", 0), round)
            durable_change = "lockedQC written before vote-log append for precommit"
        w.add_vote(vote)

        if kind in ("candidate", "prevote") and self.model in ("A", "C", "UNSAFE"):
            w.durable.setdefault("pending", {})[keystr(cp.lock_key())] = {
                "digest": cp.checkpoint_digest,
                "round": round,
                "expires_at": expires,
            }
            durable_change = "pending lock written before/at signature"

        if force_byzantine_conflict:
            self.adversarial(f"Byzantine {wid} signed conflicting {kind} digest={cp.checkpoint_digest[:8]} round={round}")

        self.log(
            "signature_created",
            phase=phase,
            actor=wid,
            detail=f"{kind} digest={cp.checkpoint_digest[:8]} round={round} epoch={cp.epoch} nonce={nonce} reason={reason}",
            signature_time=issued,
            durable_change=durable_change,
        )
        return vote

    def sign_fc(
        self,
        wid: str,
        cp: Checkpoint,
        nonce: str,
        round: int = 0,
        *,
        phase: str = "",
    ) -> Optional[Vote]:
        w = self.witnesses[wid]
        if self.conflicting_pending(w, cp) is not None or self.conflicting_commit(w, cp):
            self.log("fc_sign_rejected", phase=phase, actor=wid, detail="FC request conflicts with locked/committed checkpoint")
            return None
        if self.model == "B":
            for entry in w.volatile.get("polc", []):
                k = list(entry)
                if k[0] == cp.lock_key() and k[1] > 0 and k[2] != cp.checkpoint_digest:
                    self.log("fc_sign_rejected", phase=phase, actor=wid, detail="higher-round PoLC for conflicting checkpoint; FC for stale digest rejected")
                    return None
        issued = w.now(self.time)
        expires = issued + LEASE_DURATION if self.model == "C" else None
        vote = Vote(kind="fc", witness=wid, round=round, cp=cp, issued_at=issued, expires_at=expires, nonce=nonce)
        w.add_vote(vote)
        self.log("fc_signature_created", phase=phase, actor=wid, detail=f"FC digest={cp.checkpoint_digest[:8]} nonce={nonce}", signature_time=issued, durable_change="FC signature appended to durable vote log")
        return vote

    # ---------- recovery actions ----------

    def timeout_advance(self, wid: str, new_round: int, *, phase: str = "") -> None:
        w = self.witnesses[wid]
        if self.model == "B":
            old_round = w.volatile.get("current_round", 0)
            w.volatile["current_round"] = max(old_round, new_round)
            self.log("timeout_round_advance", phase=phase, actor=wid, detail=f"round {old_round} -> {w.volatile['current_round']}; lock unchanged")
            self.note("Model B: timeout advances the round state machine only; it is not an unlock proof.")
        elif self.model == "UNSAFE":
            w.durable.setdefault("pending", {}).clear()
            self.log("unsafe_timeout_unlock", phase=phase, actor=wid, detail="pending lock cleared solely by local timeout")
        else:
            self.log("timeout_no_unlock", phase=phase, actor=wid, detail=f"model {self.model}: local timeout does not release pending lock")

    def learn_commit(self, wid: str, cp: Checkpoint, *, phase: str = "") -> None:
        w = self.witnesses[wid]
        w.durable.setdefault("committed", {})[keystr(cp.lock_key())] = cp.checkpoint_digest
        self.log("commit_evidence_learned", phase=phase, actor=wid, detail=f"checkpoint digest={cp.checkpoint_digest[:8]} recorded as committed", durable_change="committed checkpoint recorded locally")

    def trusted_recovery(self, wid: str, *, phase: str = "") -> None:
        w = self.witnesses[wid]
        if self.model == "A":
            w.durable.setdefault("pending", {}).clear()
        self.log("trusted_recovery", phase=phase, actor=wid, detail="explicit trusted recovery invoked; no automatic timeout semantics")

    def restart(self, wid: str, mode: str = "full", *, phase: str = "") -> None:
        w = self.witnesses[wid]
        floor_before = w.floor()
        volatile_observed = list(w.volatile.get("observed", []))
        if mode == "full":
            w.volatile = {"observed": volatile_observed, "polc": list(w.volatile.get("polc", [])), "current_round": w.volatile.get("current_round", 0)}
            detail = "full durable state restored"
        elif mode == "lost_pending":
            w.durable.setdefault("pending", {})
            for v in w.signed_votes():
                if v.kind in ("candidate", "prevote"):
                    w.durable["pending"].setdefault(
                        keystr(v.cp.lock_key()),
                        {"digest": v.cp.checkpoint_digest, "round": v.round, "expires_at": v.expires_at},
                    )
            if self.model == "B":
                for v in w.signed_votes():
                    if v.kind == "precommit":
                        w.durable["locked"].setdefault(keystr(v.cp.lock_key()), {"round": v.round, "digest": v.cp.checkpoint_digest})
            w.volatile = {"observed": volatile_observed, "polc": list(w.volatile.get("polc", [])), "current_round": w.volatile.get("current_round", 0)}
            detail = "volatile pending lost; reconstructed from durable signed-vote log"
        elif mode == "lost_all":
            w.durable = {"signed_votes": [], "pending": {}, "locked": {}, "committed": {}, "current_round": 0}
            w.volatile = {"observed": [], "polc": [], "current_round": 0}
            detail = "all local state lost; no protocol can infer forgotten state locally"
        else:
            raise ValueError(f"unknown restart mode: {mode}")

        floor_after = w.floor()
        if w.honest and floor_after < floor_before:
            self.violation("S5", f"{wid} restart({mode}) rolled signing floor from {floor_before} to {floor_after}")
        self.log("witness_restart", phase=phase, actor=wid, detail=f"mode={mode}; {detail}; floor {floor_before} -> {floor_after}")

    # ---------- gateway verification ----------

    def lease_valid(self, vote: Vote, now_g: int) -> bool:
        if self.model != "C" or vote.expires_at is None:
            return True
        return now_g + CLOCK_EPSILON >= vote.issued_at and now_g - CLOCK_EPSILON <= vote.expires_at

    def _accepted_kind(self) -> str:
        return {"A": "candidate", "B": "precommit", "C": "candidate", "UNSAFE": "candidate"}[self.model]

    def submit_qc(self, cp: Checkpoint, round: int, *, votes: Optional[List[Vote]] = None, phase: str = "") -> bool:
        pool = list(votes) if votes is not None else list(self.gateway.observed)
        expected = self._accepted_kind()
        candidates = [v for v in pool if v.kind == expected and v.round == round and v.cp.full_key() == cp.full_key()]
        wrong_round = [v for v in pool if v.kind == expected and v.cp.full_key() == cp.full_key() and v.round != round]
        if wrong_round:
            self.log("old_round_vote_ignored", phase=phase, actor="G", detail=f"{len(wrong_round)} vote(s) from other round excluded from QC")

        for v in candidates:
            if v.cp.full_key() != cp.full_key():
                self.violation("S3", "QC vote binding mismatch")
        if any(v.round != round for v in candidates):
            self.violation("S4", "old-round signature reinterpreted as current-round QC vote")

        valid = [v for v in candidates if self.lease_valid(v, self.time)]
        distinct = {v.witness for v in valid}
        reason = ""
        if len(candidates) != len(valid):
            reason = "expired lease vote(s) excluded"
        if len(distinct) < QC_THRESHOLD:
            reason = (reason + "; " if reason else "") + f"insufficient valid signatures {len(distinct)}/{QC_THRESHOLD}"
            self.gateway.decisions.append(f"QC_REJECT digest={cp.checkpoint_digest[:8]} round={round}: {reason}")
            self.log("qc_rejected", phase=phase, actor="G", detail=reason, gateway_decision=self.gateway.decisions[-1])
            return False

        lk = keystr(cp.lock_key())
        committed = self.gateway.committed.get(lk)
        if committed is not None and committed != cp.checkpoint_digest:
            self.violation("S2", f"conflicting committed checkpoint {committed[:8]} vs {cp.checkpoint_digest[:8]}")
            reason = "conflicting checkpoint already committed"
            self.gateway.decisions.append(f"QC_REJECT digest={cp.checkpoint_digest[:8]} round={round}: {reason}")
            self.log("qc_rejected", phase=phase, actor="G", detail=reason, gateway_decision=self.gateway.decisions[-1])
            return False

        self.gateway.committed[lk] = cp.checkpoint_digest
        record = {"digest": cp.checkpoint_digest, "round": round, "signers": sorted(distinct), "epoch": cp.epoch, "chain_id": cp.chain_id, "witness_set_id": cp.witness_set_id}
        self.gateway.qc.append(record)
        decision = f"QC_ACCEPT digest={cp.checkpoint_digest[:8]} round={round} signers={sorted(distinct)}"
        self.gateway.decisions.append(decision)
        self.log("qc_accepted", phase=phase, actor="G", detail=json.dumps(record, sort_keys=True), qc_formed=decision, gateway_decision=decision)
        return True

    def submit_fc(self, cp: Checkpoint, nonce: str, *, votes: Optional[List[Vote]] = None, phase: str = "") -> bool:
        pool = list(votes) if votes is not None else list(self.gateway.observed)
        candidates = [v for v in pool if v.kind == "fc" and v.nonce == nonce and v.cp.full_key() == cp.full_key()]
        for v in candidates:
            if v.cp.full_key() != cp.full_key() or v.nonce != nonce:
                self.violation("S3", "FC vote binding mismatch")
        valid = [v for v in candidates if self.lease_valid(v, self.time)]
        distinct = {v.witness for v in valid}
        reason = ""
        if len(candidates) != len(valid):
            reason = "expired lease vote(s) excluded"
        if len(distinct) < FC_THRESHOLD:
            reason = (reason + "; " if reason else "") + f"insufficient FC signatures {len(distinct)}/{FC_THRESHOLD}"
            self.gateway.decisions.append(f"FC_REJECT digest={cp.checkpoint_digest[:8]} nonce={nonce}: {reason}")
            self.log("fc_rejected", phase=phase, actor="G", detail=reason, gateway_decision=self.gateway.decisions[-1])
            return False

        lk = keystr(cp.lock_key())
        committed = self.gateway.committed.get(lk)
        if committed is not None and committed != cp.checkpoint_digest:
            self.violation("S2", "FC accepted for checkpoint conflicting with committed checkpoint")
            reason = "conflicting committed checkpoint"
            self.gateway.decisions.append(f"FC_REJECT digest={cp.checkpoint_digest[:8]} nonce={nonce}: {reason}")
            self.log("fc_rejected", phase=phase, actor="G", detail=reason, gateway_decision=self.gateway.decisions[-1])
            return False

        record = {"digest": cp.checkpoint_digest, "nonce": nonce, "signers": sorted(distinct), "epoch": cp.epoch, "chain_id": cp.chain_id, "witness_set_id": cp.witness_set_id}
        self.gateway.fc.append(record)
        decision = f"FC_ACCEPT digest={cp.checkpoint_digest[:8]} nonce={nonce} signers={sorted(distinct)}"
        self.gateway.decisions.append(decision)
        self.log("fc_accepted", phase=phase, actor="G", detail=json.dumps(record, sort_keys=True), fc_formed=decision, gateway_decision=decision)
        return True

    # ---------- finalization ----------

    def finalize(self) -> Dict[str, Any]:
        safety: Dict[str, bool] = {}
        for i in range(1, 6):
            code = f"S{i}"
            safety[code] = not any(v["invariant"] == code for v in self.violations)
        liveness = self.derive_liveness()
        return {
            "scenario_id": self.scenario_id,
            "model": self.model,
            "description": self.description,
            "seed": self.seed,
            "initial_state": self.initial_state,
            "events": self.events,
            "final_witness_state": self.snapshot(),
            "gateway_decisions": self.gateway.decisions,
            "gateway_qc": self.gateway.qc,
            "gateway_fc": self.gateway.fc,
            "safety": safety,
            "liveness": liveness,
            "liveness_notes": {k: v["note"] for k, v in liveness.items()},
            "author_liveness_r0": dict(self.author_liveness_r0),
            "violations": self.violations,
            "adversarial_observations": self.adversarial_observations,
            "notes": self.notes,
        }


def make_cp(digest: str, *, epoch: int = 1, parent: str = "genesis", set_id: str = "set-v1", chain: str = "chain-main") -> Checkpoint:
    return Checkpoint(
        chain_id=chain,
        witness_set_id=set_id,
        epoch=epoch,
        checkpoint_digest=digest,
        parent_digest=parent,
    )


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
