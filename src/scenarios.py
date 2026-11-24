"""Deterministic P1-P10 schedules plus one unsafe-timeout counterexample."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from simulator import (
    CLOCK_EPSILON,
    FC_THRESHOLD,
    LEASE_DURATION,
    QC_THRESHOLD,
    Simulator,
    Vote,
    keystr,
    make_cp,
    write_json,
)
from pathlib import Path

HONEST = ("W1", "W2", "W3")
ALL = ("W1", "W2", "W3", "W4")
BASE = {
    "N": 4,
    "QC_threshold": QC_THRESHOLD,
    "FC_threshold": FC_THRESHOLD,
    "byzantine_limit": 1,
    "seed": 20261124,
    "lease_duration": LEASE_DURATION,
    "clock_epsilon": CLOCK_EPSILON,
}


def _new(model: str, sid: str, desc: str) -> Simulator:
    s = Simulator(model, sid, desc)
    s.initial_state = dict(BASE)
    s.initial_state["model"] = model
    return s


def _liv(s: Simulator, l1: bool, l2: bool, l3: bool, l4: bool, notes: Dict[str, str]) -> None:
    for code, val in (("L1", l1), ("L2", l2), ("L3", l3), ("L4", l4)):
        s.set_liveness(code, val, notes.get(code, ""))


def _kind(s: Simulator) -> str:
    return "prevote" if s.model == "B" else "candidate"


def _sign(
    s: Simulator,
    wid: str,
    cp: Any,
    *,
    round: int = 0,
    kind: Optional[str] = None,
    recipients: Tuple[str, ...] = ("G",),
    delay: int = 0,
    force_byzantine_conflict: bool = False,
    lease: Optional[int] = None,
    phase: str = "",
) -> Optional[int]:
    vote = s.sign_vote(
        wid,
        cp,
        kind or _kind(s),
        round,
        lease=lease,
        force_byzantine_conflict=force_byzantine_conflict,
        phase=phase,
    )
    if vote is None:
        return None
    return s.send(vote, list(recipients), delay=delay, phase=phase)


def _sign_fc(
    s: Simulator,
    wid: str,
    cp: Any,
    nonce: str,
    *,
    recipients: Tuple[str, ...] = ("G",),
    phase: str = "",
) -> Optional[int]:
    vote = s.sign_fc(wid, cp, nonce, phase=phase)
    if vote is None:
        return None
    return s.send(vote, list(recipients), phase=phase)


def _deliver(s: Simulator, mids: List[Optional[int]], phase: str = "") -> None:
    for mid in mids:
        if mid is not None:
            s.deliver_message(mid, phase=phase)


def _precommit_and_qc(
    s: Simulator,
    cp: Any,
    round: int,
    signers: Tuple[str, ...],
    *,
    phase: str = "",
    vote_recipients: Tuple[str, ...] = ALL,
) -> bool:
    prevote_mids = [
        _sign(s, wid, cp, round=round, kind="prevote", recipients=vote_recipients, phase=phase)
        for wid in signers
    ]
    _deliver(s, prevote_mids, phase=phase)
    precommit_mids = [
        _sign(s, wid, cp, round=round, kind="precommit", recipients=("G",), phase=phase)
        for wid in signers
    ]
    _deliver(s, precommit_mids, phase=phase)
    return s.submit_qc(cp, round, phase=phase)


# ---------------- P1 ----------------

def p1(s: Simulator) -> None:
    cp_a = make_cp("aaaa1111")
    cp_b = make_cp("bbbb1111")
    _sign(s, "W1", cp_a, phase="P1")
    _sign(s, "W2", cp_a, phase="P1")

    if s.model == "B":
        mids = [
            _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=ALL, phase="P1"),
            _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=ALL, phase="P1"),
        ]
        _deliver(s, mids, phase="P1")
        for wid in HONEST:
            s.timeout_advance(wid, 1, phase="P1-recovery")
        mids = [
            _sign(s, "W1", cp_b, round=1, kind="prevote", recipients=ALL, phase="P1-recovery"),
            _sign(s, "W2", cp_b, round=1, kind="prevote", recipients=ALL, phase="P1-recovery"),
            _sign(s, "W3", cp_b, round=1, kind="prevote", recipients=ALL, phase="P1-recovery"),
        ]
        _deliver(s, mids, phase="P1-recovery")
        accepted = _precommit_and_qc(s, cp_b, 1, ("W1", "W2", "W3"), phase="P1-recovery")
        _liv(s, accepted, accepted, True, False, {
            "L1": "network heal + higher round with honest quorum advances",
            "L2": "no PoLC means no lock was created by the two signatures",
            "L3": "three honest witnesses can still form quorum",
            "L4": "no administrator, but an explicit round change is required",
        })
        return

    s.timeout_advance("W1", 1, phase="P1-timeout")
    _sign(s, "W1", cp_b, round=1, phase="P1-timeout")
    _sign(s, "W2", cp_b, round=1, phase="P1-timeout")
    s.submit_qc(cp_b, 1, phase="P1-timeout")

    if s.model == "C":
        s.advance(LEASE_DURATION + CLOCK_EPSILON + 1, phase="P1-lease-expiry")
        mids = [
            _sign(s, "W1", cp_b, round=1, phase="P1-lease-expiry"),
            _sign(s, "W2", cp_b, round=1, phase="P1-lease-expiry"),
            _sign(s, "W3", cp_b, round=1, phase="P1-lease-expiry"),
        ]
        _deliver(s, mids, phase="P1-lease-expiry")
        accepted = s.submit_qc(cp_b, 1, phase="P1-lease-expiry")
        _liv(s, accepted, accepted, True, False, {
            "L1": "recovers only after trusted-clock lease expiry",
            "L2": "lease expiry releases the incomplete candidate",
            "L3": "three honest witnesses can form quorum after expiry",
            "L4": "no administrator, but a trusted clock is required",
        })
        return

    _liv(s, False, False, False, True, {
        "L1": "two locked witnesses cannot sign a conflicting candidate after network heal",
        "L2": "permanent lock leaves the incomplete candidate blocking",
        "L3": "with two locked and one offline, fewer than three witnesses remain usable",
        "L4": "requires an explicit trusted recovery procedure",
    })


# ---------------- P2 ----------------

def p2(s: Simulator) -> None:
    cp_a = make_cp("aaaa2222")
    cp_b = make_cp("bbbb2222")
    if s.model == "B":
        # R1 fix: deliver W1's round-0 prevote to W2/W3, and let W2/W3 exchange
        # their own prevotes.  W1 deliberately receives neither, so it keeps a
        # stale local view without pretending a PoLC is absent globally.
        m1 = _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=("W2", "W3"), phase="P2")
        m2 = _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=("W3",), phase="P2")
        m3 = _sign(s, "W3", cp_a, round=0, kind="prevote", recipients=("W2",), phase="P2")
        _deliver(s, [m1, m2, m3], phase="P2")
        for wid in ("W2", "W3"):
            w = s.witnesses[wid]
            seen = sorted({v.witness for v in s.votes_for_polc(w) if v.kind == "prevote" and v.round == 0})
            s.note(f"P2-B: {wid} observed prevote signers {seen} for cp_a round 0; PoLC={s.has_polc(w, cp_a, 0)}")
        s.note(
            "P2-B: W1 observed prevote signers "
            + str(sorted({v.witness for v in s.votes_for_polc(s.witnesses["W1"]) if v.kind == "prevote"}))
            + f"; PoLC={s.has_polc(s.witnesses['W1'], cp_a, 0)}"
        )
        s.mark_byzantine("W4", phase="P2")
        pre_mids = [
            _sign(s, "W2", cp_a, round=0, kind="precommit", recipients=("G",), phase="P2"),
            _sign(s, "W3", cp_a, round=0, kind="precommit", recipients=("G",), phase="P2"),
            _sign(s, "W4", cp_a, round=0, kind="precommit", recipients=("G",), phase="P2"),
        ]
        _deliver(s, pre_mids, phase="P2")
        pre_votes = [v for v in s.gateway.observed if v.kind == "precommit" and v.round == 0]
        s.note(f"P2-B: gateway received precommit signers {sorted({v.witness for v in pre_votes})}")
        committed = s.submit_qc(cp_a, 0, phase="P2")
        s.learn_commit("W1", cp_a, phase="P2-heal")
        s.timeout_advance("W1", 1, phase="P2-heal")
        stale_vote = _sign(s, "W1", cp_b, round=1, kind="prevote", recipients=("G",), phase="P2-heal")
        s.note(f"P2-B: W1 conflicting prevote after learning commit produced signature={stale_vote is not None}")
        # Delayed old-round prevote must not become a round-1 QC vote.
        s.submit_qc(
            cp_b,
            1,
            votes=[s.witnesses["W1"].signed_votes()[0], s.witnesses["W4"].signed_votes()[0]]
            if s.witnesses["W4"].signed_votes()
            else [],
            phase="P2-heal",
        )
        _liv(s, committed, committed, True, False, {
            "L1": "QC formed and committed at the gateway despite W1 not observing it",
            "L2": "candidate did form QC; W1's local view is stale but not authoritative",
            "L3": "remaining honest witnesses sustained quorum",
            "L4": "no administrator; old-round votes are excluded by round binding",
        })
        return

    mids = [
        _sign(s, "W1", cp_a, phase="P2"),
        _sign(s, "W2", cp_a, phase="P2"),
        _sign(s, "W3", cp_a, phase="P2"),
    ]
    _deliver(s, mids[1:], phase="P2")
    committed = s.submit_qc(cp_a, 0, phase="P2")
    for wid in HONEST:
        s.learn_commit(wid, cp_a, phase="P2-heal")
    s.timeout_advance("W1", 1, phase="P2-heal")
    _sign(s, "W1", cp_b, round=1, phase="P2-heal")
    s.submit_qc(cp_b, 1, phase="P2-heal")
    if s.model == "C":
        s.advance(LEASE_DURATION + CLOCK_EPSILON + 1, phase="P2-lease-expiry")
        _sign(s, "W1", cp_b, round=1, phase="P2-lease-expiry")
    _liv(s, committed, committed, True, s.model == "A", {
        "L1": "QC formed; W1 cannot sign a conflicting state after learning commit",
        "L2": "candidate did form QC, so no unresolved incomplete candidate remains globally",
        "L3": "three honest witnesses formed QC",
        "L4": "A needs trusted recovery for a stale local view; C relies on trusted clock",
    })


# ---------------- P3 ----------------

def p3(s: Simulator) -> None:
    cp_old = make_cp("oldd3333")
    cp_new = make_cp("neww3333")
    if s.model == "B":
        mids = [
            _sign(s, "W1", cp_old, round=0, kind="prevote", recipients=ALL, phase="P3"),
            _sign(s, "W2", cp_old, round=0, kind="prevote", recipients=ALL, phase="P3"),
            _sign(s, "W3", cp_old, round=0, kind="prevote", recipients=ALL, phase="P3"),
        ]
        _deliver(s, mids, phase="P3")
        pre = [
            _sign(s, "W1", cp_old, round=0, kind="precommit", recipients=("G",), phase="P3"),
            _sign(s, "W2", cp_old, round=0, kind="precommit", recipients=("G",), phase="P3"),
            _sign(s, "W3", cp_old, round=0, kind="precommit", recipients=("G",), phase="P3"),
        ]
        _deliver(s, pre, phase="P3")
        committed_old = s.submit_qc(cp_old, 0, phase="P3")
        s.mark_byzantine("W4", phase="P3-observed")
        # R1 reachability study: all three honest witnesses are now locked on
        # cp_old at round 0.  A conflicting cp_new PoLC at round 1 requires
        # three distinct prevotes; with f=1 at least two locked honest
        # witnesses would have to unlock first, and unlocking itself needs a
        # strictly higher-round conflicting PoLC.  Under the corrected rule
        # this is circular, so no honest witness may prevote cp_new.
        for wid in ("W2", "W3"):
            s.timeout_advance(wid, 1, phase="P3-observed")
            _sign(s, wid, cp_new, round=1, kind="prevote", recipients=("W1",), phase="P3-observed")
            w = s.witnesses[wid]
            s.note(f"P3-B: {wid} lock={w.durable.get('locked')} cp_new@1 PoLC={s.has_polc(w, cp_new, 1)}")
        byz = s.sign_vote("W4", cp_new, "prevote", 1, force_byzantine_conflict=True, phase="P3-observed")
        if byz:
            _deliver(s, [s.send(byz, ["W1"], phase="P3-observed")], phase="P3-observed")
        s.timeout_advance("W1", 2, phase="P3-observed")
        s.note(
            "P3-B reachability: cp_old committed at round 0; only the Byzantine witness "
            f"prevoted cp_new at round 1; W1 PoLC(cp_new,1)={s.has_polc(s.witnesses['W1'], cp_new, 1)}; "
            "a conflicting higher-round PoLC is not reachable under the corrected lock rules"
        )
        fc = _sign_fc(s, "W1", cp_old, "nonce-1", recipients=("G",), phase="P3-fc")
        _deliver(s, [fc], phase="P3-fc")
        s.submit_fc(cp_old, "nonce-1", phase="P3-fc")
        _liv(s, committed_old, committed_old, True, False, {
            "L1": "gateway can still obtain an authenticated QC for cp_old",
            "L2": "no incomplete conflicting candidate can be formed by honest witnesses",
            "L3": "three honest witnesses formed the committed QC",
            "L4": "no administrator; round advance alone cannot transfer a lock",
        })
        return

    mids = [
        _sign(s, "W1", cp_old, phase="P3"),
        _sign(s, "W2", cp_old, phase="P3"),
        _sign(s, "W3", cp_old, phase="P3"),
    ]
    _deliver(s, mids, phase="P3")
    s.submit_qc(cp_old, 0, phase="P3")
    # Witnesses observe cp_new messages but keep their old pending lock.
    fc_mids = [
        _sign_fc(s, wid, cp_old, "nonce-1", recipients=("G",), phase="P3-fc")
        for wid in HONEST
    ]
    _deliver(s, fc_mids, phase="P3-fc")
    accepted = s.submit_fc(cp_old, "nonce-1", phase="P3-fc")
    s.note("Gateway accepted FC for old checkpoint while witnesses had observed a newer candidate; this is a freshness limitation, not an S1-S5 violation.")
    _liv(s, accepted, True, True, s.model == "A", {
        "L1": "service advances, but on the stale digest",
        "L2": "no incomplete candidate is blocking",
        "L3": "three honest witnesses can form FC",
        "L4": "A requires trusted recovery; C relies on trusted clock; neither binds FC to observed newer state",
    })


# ---------------- P4 ----------------

def p4(s: Simulator) -> None:
    cp_a = make_cp("aaaa4444")
    cp_b = make_cp("bbbb4444")
    cp_c = make_cp("cccc4444")
    if s.model == "B":
        mids = [
            _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=("G",), phase="P4"),
            _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=("G",), phase="P4"),
            _sign(s, "W3", cp_b, round=0, kind="prevote", recipients=("G",), phase="P4"),
        ]
        s.mark_byzantine("W4", phase="P4")
        b = s.sign_vote("W4", cp_b, "prevote", 0, force_byzantine_conflict=True, phase="P4")
        if b:
            mids.append(s.send(b, ["G"], phase="P4"))
        _deliver(s, mids, phase="P4")
        s.submit_qc(cp_a, 0, phase="P4")
        s.submit_qc(cp_b, 0, phase="P4")
        for wid in HONEST:
            s.timeout_advance(wid, 1, phase="P4-recovery")
        accepted = _precommit_and_qc(s, cp_c, 1, ("W1", "W2", "W3"), phase="P4-recovery")
        _liv(s, accepted, accepted, True, False, {
            "L1": "higher round with an honest quorum resolves the split",
            "L2": "no quorum for either sibling, so neither can lock honestly",
            "L3": "three honest witnesses remain",
            "L4": "no administrator, but a new round is needed",
        })
        return

    mids = [
        _sign(s, "W1", cp_a, phase="P4"),
        _sign(s, "W2", cp_a, phase="P4"),
        _sign(s, "W3", cp_b, phase="P4"),
        _sign(s, "W4", cp_b, phase="P4"),
    ]
    _deliver(s, mids, phase="P4")
    s.submit_qc(cp_a, 0, phase="P4")
    s.submit_qc(cp_b, 0, phase="P4")
    if s.model == "C":
        s.advance(LEASE_DURATION + CLOCK_EPSILON + 1, phase="P4-lease-expiry")
        mids = [
            _sign(s, "W1", cp_c, round=1, phase="P4-lease-expiry"),
            _sign(s, "W2", cp_c, round=1, phase="P4-lease-expiry"),
            _sign(s, "W3", cp_c, round=1, phase="P4-lease-expiry"),
        ]
        _deliver(s, mids, phase="P4-lease-expiry")
        accepted = s.submit_qc(cp_c, 1, phase="P4-lease-expiry")
    else:
        accepted = False
    _liv(s, accepted, accepted, False, s.model == "A", {
        "L1": "C recovers after lease expiry; A remains blocked",
        "L2": "two conflicting incomplete candidates block progress",
        "L3": "with two witnesses per sibling and one offline, no quorum remains",
        "L4": "A needs trusted recovery; C needs trusted clock",
    })


# ---------------- P5 ----------------

def p5(s: Simulator) -> None:
    cp_a = make_cp("aaaa5555")
    if s.model == "B":
        accepted = _precommit_and_qc(s, cp_a, 0, HONEST, phase="P5")
    else:
        mids = [_sign(s, wid, cp_a, phase="P5") for wid in HONEST]
        _deliver(s, mids, phase="P5")
        accepted = s.submit_qc(cp_a, 0, phase="P5")
    for wid in HONEST:
        s.learn_commit(wid, cp_a, phase="P5")
    for wid in ALL:
        s.restart(wid, "full", phase="P5-restart")
    cp_b = make_cp("bbbb5555")
    if s.model == "B":
        s.timeout_advance("W1", 1, phase="P5-recovery")
        _sign(s, "W1", cp_b, round=1, kind="prevote", recipients=("G",), phase="P5-recovery")
    else:
        _sign(s, "W1", cp_b, round=1, phase="P5-recovery")
    s.submit_qc(cp_b, 1, phase="P5-recovery")
    _liv(s, accepted, accepted, True, s.model == "A", {
        "L1": "full restart preserves accepted state and blocks conflicting signature",
        "L2": "candidate did form QC",
        "L3": "three honest witnesses available before restart",
        "L4": "A needs trusted recovery to change committed digest",
    })


# ---------------- P6 ----------------

def p6(s: Simulator) -> None:
    cp_a = make_cp("aaaa6666")
    cp_b = make_cp("bbbb6666")
    if s.model == "B":
        mids = [
            _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=ALL, phase="P6"),
            _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=ALL, phase="P6"),
            _sign(s, "W3", cp_a, round=0, kind="prevote", recipients=ALL, phase="P6"),
        ]
        _deliver(s, mids, phase="P6")
        pre = [
            _sign(s, "W1", cp_a, round=0, kind="precommit", recipients=("G",), phase="P6"),
            _sign(s, "W2", cp_a, round=0, kind="precommit", recipients=("G",), phase="P6"),
            _sign(s, "W3", cp_a, round=0, kind="precommit", recipients=("G",), phase="P6"),
        ]
        _deliver(s, pre, phase="P6")
        s.submit_qc(cp_a, 0, phase="P6")
    else:
        mids = [_sign(s, wid, cp_a, phase="P6") for wid in HONEST]
        _deliver(s, mids, phase="P6")
        s.submit_qc(cp_a, 0, phase="P6")

    for wid in ("W1", "W2"):
        s.restart(wid, "lost_pending", phase="P6-restart")
    if s.model == "B":
        s.timeout_advance("W1", 1, phase="P6-recovery")
        _sign(s, "W1", cp_b, round=1, kind="prevote", recipients=("G",), phase="P6-recovery")
    else:
        _sign(s, "W1", cp_b, round=1, phase="P6-recovery")
    s.submit_qc(cp_b, 1, phase="P6-recovery")
    _liv(s, True, True, True, s.model == "A", {
        "L1": "durable signed-vote log reconstructs the lock after volatile loss",
        "L2": "candidate did form QC",
        "L3": "three honest witnesses available",
        "L4": "A needs trusted recovery; B/C rely on durable signed-vote log",
    })


# ---------------- P7 ----------------

def p7(s: Simulator) -> None:
    cp_a = make_cp("aaaa7777")
    cp_b = make_cp("bbbb7777")
    s.mark_byzantine("W4", phase="P7")
    if s.model == "B":
        mids = [
            _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=ALL, phase="P7"),
            _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=ALL, phase="P7"),
        ]
        b1 = s.sign_vote("W4", cp_a, "prevote", 0, force_byzantine_conflict=True, phase="P7")
        b2 = s.sign_vote("W4", cp_b, "prevote", 0, force_byzantine_conflict=True, phase="P7")
        if b1:
            mids.append(s.send(b1, list(ALL), phase="P7"))
        if b2:
            mids.append(s.send(b2, ["G"], phase="P7"))
        _deliver(s, mids, phase="P7")
        pre = [
            _sign(s, "W1", cp_a, round=0, kind="precommit", recipients=("G",), phase="P7"),
            _sign(s, "W2", cp_a, round=0, kind="precommit", recipients=("G",), phase="P7"),
            _sign(s, "W4", cp_a, round=0, kind="precommit", recipients=("G",), phase="P7"),
        ]
        _deliver(s, pre, phase="P7")
        accepted = s.submit_qc(cp_a, 0, phase="P7")
        s.submit_qc(cp_b, 0, phase="P7")
    else:
        mids = [
            _sign(s, "W1", cp_a, phase="P7"),
            _sign(s, "W2", cp_a, phase="P7"),
        ]
        b1 = s.sign_vote("W4", cp_a, "candidate", 0, force_byzantine_conflict=True, phase="P7")
        b2 = s.sign_vote("W4", cp_b, "candidate", 0, force_byzantine_conflict=True, phase="P7")
        if b1:
            mids.append(s.send(b1, ["G"], phase="P7"))
        if b2:
            mids.append(s.send(b2, ["G"], phase="P7"))
        _deliver(s, mids, phase="P7")
        accepted = s.submit_qc(cp_a, 0, phase="P7")
        s.submit_qc(cp_b, 0, phase="P7")
    _liv(s, accepted, accepted, True, False, {
        "L1": "one Byzantine witness cannot prevent a valid QC",
        "L2": "conflicting sibling has only the Byzantine signature",
        "L3": "three honest witnesses remain",
        "L4": "no administrator or clock needed for this case",
    })


# ---------------- P8 ----------------

def p8(s: Simulator) -> None:
    cp_a = make_cp("aaaa8888")
    cp_b = make_cp("bbbb8888")
    cp_c = make_cp("cccc8888")
    s.mark_byzantine("W4", phase="P8")
    if s.model == "B":
        a = [
            _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=("W1", "W2"), phase="P8-partition"),
            _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=("W1", "W2"), phase="P8-partition"),
        ]
        ba = s.sign_vote("W4", cp_a, "prevote", 0, force_byzantine_conflict=True, phase="P8-partition")
        if ba:
            a.append(s.send(ba, ["W1", "W2"], phase="P8-partition"))
        _deliver(s, a, phase="P8-partition")
        b = [
            _sign(s, "W3", cp_b, round=0, kind="prevote", recipients=("W3",), phase="P8-partition"),
        ]
        bb = s.sign_vote("W4", cp_b, "prevote", 0, force_byzantine_conflict=True, phase="P8-partition")
        if bb:
            b.append(s.send(bb, ["W3"], phase="P8-partition"))
        _deliver(s, b, phase="P8-partition")
        pre = [
            _sign(s, "W1", cp_a, round=0, kind="precommit", recipients=("G",), phase="P8-partition"),
            _sign(s, "W2", cp_a, round=0, kind="precommit", recipients=("G",), phase="P8-partition"),
        ]
        _deliver(s, pre, phase="P8-partition")
        first = s.submit_qc(cp_a, 0, phase="P8-partition")
        second = s.submit_qc(cp_b, 0, phase="P8-partition")
        for wid in HONEST:
            s.timeout_advance(wid, 1, phase="P8-heal")
        accepted = _precommit_and_qc(s, cp_c, 1, HONEST, phase="P8-heal")
        _liv(s, accepted, accepted, True, False, {
            "L1": "after partition heals, higher-round honest quorum advances",
            "L2": "neither partition could commit with only two valid votes",
            "L3": "three honest witnesses can form quorum after heal",
            "L4": "no administrator; round change required",
        })
        s.note(f"partition QCs: cp_a={first}, cp_b={second}")
        s.note(
            "R1 finding: W1/W2 lawfully precommitted cp_a at round 0 after observing a "
            "PoLC that included the Byzantine witness, but the gateway received only two "
            "precommits, so no commit was recorded. Their durable locks remain cp_a@0. "
            "After heal, timeout alone cannot unlock; a conflicting cp_c@1 prevote needs "
            f"0 < polc_round < current_round and no qualifying PoLC exists (accepted={accepted}). "
            "The R0 claim that a higher round trivially recovers this partition is overturned; "
            "recovery would require an explicit lock-transfer quorum that the two locked "
            "honest witnesses cannot create by themselves."
        )
        _liv(s, accepted, accepted, True, False, {
            "L1": "R1: partition heal does not unlock a durable lock without quorum evidence",
            "L2": "R1: the incomplete cp_a precommit still blocks cp_c",
            "L3": "three honest witnesses exist but two are locked",
            "L4": "R1: an explicit lock-transfer quorum is required",
        })
        return

    mids = [
        _sign(s, "W1", cp_a, phase="P8-partition"),
        _sign(s, "W2", cp_a, phase="P8-partition"),
        _sign(s, "W3", cp_b, phase="P8-partition"),
    ]
    _deliver(s, mids, phase="P8-partition")
    s.submit_qc(cp_a, 0, phase="P8-partition")
    s.submit_qc(cp_b, 0, phase="P8-partition")
    if s.model == "C":
        s.advance(LEASE_DURATION + CLOCK_EPSILON + 1, phase="P8-lease-expiry")
        mids = [
            _sign(s, "W1", cp_c, round=1, phase="P8-lease-expiry"),
            _sign(s, "W2", cp_c, round=1, phase="P8-lease-expiry"),
            _sign(s, "W3", cp_c, round=1, phase="P8-lease-expiry"),
        ]
        _deliver(s, mids, phase="P8-lease-expiry")
        accepted = s.submit_qc(cp_c, 1, phase="P8-lease-expiry")
    else:
        accepted = False
    _liv(s, accepted, accepted, False, s.model == "A", {
        "L1": "C recovers after lease expiry; A stays blocked by divergent pending locks",
        "L2": "no quorum in either partition",
        "L3": "one offline leaves too few unlocked witnesses",
        "L4": "A needs trusted recovery; C needs trusted clock",
    })


# ---------------- P9 ----------------

def p9(s: Simulator) -> None:
    cp_new = make_cp("newd9999")
    cp_old = make_cp("oldd9999")
    if s.model == "B":
        accepted = _precommit_and_qc(s, cp_new, 0, HONEST, phase="P9")
    else:
        mids = [_sign(s, wid, cp_new, phase="P9") for wid in HONEST]
        _deliver(s, mids, phase="P9")
        accepted = s.submit_qc(cp_new, 0, phase="P9")
    for wid in HONEST:
        s.learn_commit(wid, cp_new, phase="P9")
    s.mark_byzantine("W4", phase="P9")
    fc = _sign_fc(s, "W4", cp_old, "nonce-new", recipients=("G",), phase="P9-fc")
    _deliver(s, [fc], phase="P9-fc")
    stale_fc = s.submit_fc(cp_old, "nonce-new", phase="P9-fc")
    _liv(s, accepted and not stale_fc, True, True, False, {
        "L1": "fresh FC for the committed checkpoint can still be obtained",
        "L2": "stale checkpoint with new nonce cannot gather three honest FC signatures",
        "L3": "three honest witnesses available",
        "L4": "no administrator or clock needed for this case",
    })


# ---------------- P10 ----------------

def p10(s: Simulator) -> None:
    cp_old = make_cp("oldd1010", set_id="set-v1")
    cp_new = make_cp("neww1010", set_id="set-v2")
    if s.model == "B":
        accepted = _precommit_and_qc(s, cp_old, 0, HONEST, phase="P10")
    else:
        mids = [_sign(s, wid, cp_old, phase="P10") for wid in HONEST]
        _deliver(s, mids, phase="P10")
        accepted = s.submit_qc(cp_old, 0, phase="P10")

    mixed = [s.witnesses[wid].signed_votes()[0] for wid in HONEST]
    s.submit_qc(cp_new, 0, votes=mixed, phase="P10-mixed")

    if s.model == "B":
        for wid in HONEST:
            s.timeout_advance(wid, 1, phase="P10-rotated")
        rotated = _precommit_and_qc(s, cp_new, 1, HONEST, phase="P10-rotated")
    else:
        mids = [_sign(s, wid, cp_new, round=1, phase="P10-rotated") for wid in HONEST]
        _deliver(s, mids, phase="P10-rotated")
        rotated = s.submit_qc(cp_new, 1, phase="P10-rotated")
    s.note("set-v1 and set-v2 are separate binding namespaces; the simulator does not define an authenticated rotation rule between them.")
    _liv(s, accepted and rotated, True, True, True, {
        "L1": "new witness-set namespace can continue under this simulator",
        "L2": "old pending lock is not automatically reused across set IDs",
        "L3": "three honest witnesses remain",
        "L4": "a real rotation protocol requires an external trust decision",
    })


# ---------------- unsafe counterexample ----------------

def unsafe_u1(s: Simulator) -> None:
    cp_a = make_cp("aaaa9999")
    cp_b = make_cp("bbbb9999")
    mids = [_sign(s, wid, cp_a, phase="U1") for wid in HONEST]
    _deliver(s, mids, phase="U1")
    s.submit_qc(cp_a, 0, phase="U1")
    s.mark_byzantine("W4", phase="U1")
    for wid in ("W1", "W2"):
        s.timeout_advance(wid, 1, phase="U1-unsafe-recovery")
        _sign(s, wid, cp_b, round=1, phase="U1-unsafe-recovery")
    byz = s.sign_vote("W4", cp_b, "candidate", 1, force_byzantine_conflict=True, phase="U1-unsafe-recovery")
    if byz:
        mids = [s.send(byz, ["G"], phase="U1-unsafe-recovery")]
        for wid in ("W1", "W2"):
            v = s.witnesses[wid].signed_votes()[-1]
            mids.append(s.send(v, ["G"], phase="U1-unsafe-recovery"))
        _deliver(s, mids, phase="U1-unsafe-recovery")
    s.submit_qc(cp_b, 1, phase="U1-unsafe-recovery")
    _liv(s, False, False, True, False, {
        "L1": "unsafe timeout unlock admits a conflicting QC",
        "L2": "incomplete candidate no longer blocks, but at the cost of safety",
        "L3": "quorum still numerically available",
        "L4": "no administrator, but this is not a valid recovery rule",
    })


# ---------------- extra boundary checks ----------------

def ck1(s: Simulator) -> None:
    cp = make_cp("lease1111")
    mids = [
        _sign(s, wid, cp, round=0, recipients=("G",), lease=50, phase="CK1")
        for wid in HONEST
    ]
    _deliver(s, mids, phase="CK1")
    s.advance(60, phase="CK1-expiry")
    accepted = s.submit_qc(cp, 0, phase="CK1-expiry")
    _liv(s, accepted, accepted, True, False, {
        "L1": "expired signatures cannot authenticate the state",
        "L2": "lease expiry bounds availability by design",
        "L3": "quorum existed numerically but was invalid at verification",
        "L4": "requires trusted clock",
    })


def ck2(s: Simulator) -> None:
    cp = make_cp("lease2222")
    mids = [
        _sign(s, wid, cp, round=0, recipients=("G",), lease=50, phase="CK2")
        for wid in HONEST
    ]
    _deliver(s, mids, phase="CK2")
    s.note("Three valid signatures existed at t=0; the gateway did not receive/accept them until t=70.")
    s.advance(70, phase="CK2-late-submit")
    accepted = s.submit_qc(cp, 0, phase="CK2-late-submit")
    _liv(s, accepted, accepted, True, False, {
        "L1": "late submission of an otherwise valid QC is rejected",
        "L2": "gateway-time validity, not local formation time, controls acceptance",
        "L3": "quorum existed numerically",
        "L4": "requires trusted clock",
    })


def ck3(s: Simulator) -> None:
    cp_a = make_cp("lease3333", epoch=1)
    cp_b = make_cp("lease3334", epoch=2)
    mids = [
        _sign(s, wid, cp_a, round=0, recipients=("G",), lease=50, phase="CK3")
        for wid in HONEST
    ]
    mids += [
        _sign(s, wid, cp_b, round=0, recipients=("G",), lease=50, phase="CK3")
        for wid in HONEST
    ]
    _deliver(s, mids, phase="CK3")
    s.set_gateway_time(55, phase="CK3-boundary")
    boundary = s.submit_qc(cp_a, 0, phase="CK3-boundary")
    s.set_gateway_time(56, phase="CK3-beyond")
    beyond = s.submit_qc(cp_b, 0, phase="CK3-beyond")
    _liv(s, boundary and not beyond, True, True, False, {
        "L1": "expiry + epsilon is the accepted boundary in this model",
        "L2": "beyond the boundary signatures cannot be used",
        "L3": "quorum available in both cases",
        "L4": "requires trusted clock and epsilon",
    })


def ck4(s: Simulator) -> None:
    cp = make_cp("lease4444")
    mids = [
        _sign(s, wid, cp, round=0, recipients=("G",), lease=50, phase="CK4")
        for wid in HONEST
    ]
    _deliver(s, mids, phase="CK4")
    s.submit_qc(cp, 0, phase="CK4")
    s.set_clock_offset("W1", -200, phase="CK4-rollback")
    s.note("Clock rollback makes W1 believe old leases are still live; a clock-unavailable witness cannot decide safe release at all.")
    s.note("This case is recorded as an external-clock assumption, not as a simulated safety proof.")
    _liv(s, False, False, True, True, {
        "L1": "rollback or unavailable clock prevents a trustworthy release decision",
        "L2": "availability depends on clock recovery",
        "L3": "quorum still numerically available",
        "L4": "trusted clock source is mandatory for Model C",
    })


def ck5(s: Simulator) -> None:
    cp_a = make_cp("lease5555")
    cp_b = make_cp("lease5556")
    old = [
        _sign(s, wid, cp_a, round=0, recipients=("G",), lease=50, phase="CK5")
        for wid in HONEST
    ]
    _deliver(s, old, phase="CK5")
    s.advance(60, phase="CK5-expiry")
    new = [
        _sign(s, wid, cp_b, round=1, recipients=("G",), lease=50, phase="CK5-new")
        for wid in HONEST
    ]
    _deliver(s, new, phase="CK5-new")
    accepted = s.submit_qc(cp_b, 1, votes=[v for v in s.gateway.observed], phase="CK5-new")
    s.note("Old-round lease signatures are excluded by round and checkpoint-digest binding; mixing cannot form a QC.")
    _liv(s, accepted, accepted, True, False, {
        "L1": "new-round signatures form a valid QC after old leases expire",
        "L2": "old leases do not block new rounds after expiry",
        "L3": "three honest witnesses available",
        "L4": "requires trusted clock",
    })


def ck6(s: Simulator) -> None:
    cp = make_cp("lease6666")
    mids = [
        _sign(s, wid, cp, round=0, recipients=("G",), lease=50, phase="CK6")
        for wid in HONEST
    ]
    _deliver(s, mids, phase="CK6")
    first = s.submit_qc(cp, 0, phase="CK6-before-expiry")
    s.advance(70, phase="CK6-after-expiry")
    second = s.submit_qc(cp, 0, votes=[v for v in s.gateway.observed], phase="CK6-after-expiry")
    _liv(s, first and not second, True, True, False, {
        "L1": "old QC cannot be replayed to the gateway after lease expiry",
        "L2": "freshness is time-bounded by design",
        "L3": "quorum originally available",
        "L4": "requires trusted clock",
    })


def ck7(s: Simulator) -> None:
    cp = make_cp("lease7777")
    mids = [
        _sign(s, wid, cp, round=0, recipients=("G",), lease=50, phase="CK7")
        for wid in HONEST
    ]
    _deliver(s, mids, phase="CK7")
    s.advance(70, phase="CK7-expired")
    expired = s.submit_qc(cp, 0, phase="CK7-expired")
    s.set_gateway_time(0, phase="CK7-gateway-rollback")
    replay = s.submit_qc(cp, 0, votes=[v for v in s.gateway.observed], phase="CK7-gateway-rollback")
    s.note("Gateway clock rollback makes expired signatures acceptable again; this violates the trusted-clock assumption, not S1-S5.")
    _liv(s, True, True, True, True, {
        "L1": "gateway rollback defeats lease expiry",
        "L2": "availability remains, but freshness guarantee is lost",
        "L3": "quorum unchanged",
        "L4": "strictly requires a monotonic trusted clock",
    })


def al1(s: Simulator) -> None:
    cp_a = make_cp("lostaaaa")
    cp_b = make_cp("lostbbbb")
    mids = [_sign(s, wid, cp_a, phase="AL1") for wid in HONEST]
    _deliver(s, mids, phase="AL1")
    s.submit_qc(cp_a, 0, phase="AL1")
    s.restart("W1", "lost_all", phase="AL1-total-loss")
    s.mark_byzantine("W4", phase="AL1")
    _sign(s, "W1", cp_b, phase="AL1-after-loss")
    byz = s.sign_vote("W4", cp_b, "candidate", 0, force_byzantine_conflict=True, phase="AL1-after-loss")
    if byz:
        _deliver(s, [s.send(byz, ["G"], phase="AL1-after-loss")], phase="AL1-after-loss")
    _sign(s, "W1", cp_b, phase="AL1-after-loss")
    s.submit_qc(cp_b, 0, phase="AL1-after-loss")
    s.note("If both pending lock and durable signed-vote log are lost, no local protocol can reconstruct the forgotten state.")
    _liv(s, False, False, True, True, {
        "L1": "total local state loss breaks Model A's safety floor",
        "L2": "availability returns only by giving up the safety floor",
        "L3": "numerical quorum remains",
        "L4": "requires external recoverytrust",
    })


# ---------------- R1-B1..B8: Model B lock-transfer regression ----------------


def _set_lock(s: Simulator, wid: str, cp: Any, round: int) -> None:
    """Install a durable lock directly as scenario initial state.

    C1: this helper must NOT advance current_round. Scenarios that need the
    witness to be in a higher round call timeout_advance explicitly, so the
    round transition is visible in the event log.
    """
    w = s.witnesses[wid]
    w.durable.setdefault("locked", {})[keystr(cp.lock_key())] = {
        "round": round,
        "digest": cp.checkpoint_digest,
    }


def _set_polc(s: Simulator, wid: str, cp: Any, round: int) -> None:
    """Install an observed 3-of-4 prevote PoLC as scenario evidence."""
    w = s.witnesses[wid]
    entry = [cp.lock_key(), round, cp.checkpoint_digest]
    if entry not in [list(x) for x in w.volatile.setdefault("polc", [])]:
        w.volatile["polc"].append(entry)
    # The PoLC is backed by three distinct prevote records in the vote log.
    for name in ("W1", "W2", "W3"):
        if not any(
            v.kind == "prevote" and v.witness == name and v.round == round
            and v.cp.full_key() == cp.full_key()
            for v in w.signed_votes()
        ):
            w.add_vote(Vote(kind="prevote", witness=name, round=round, cp=cp, issued_at=0))


def _r1_probe(
    s: Simulator,
    wid: str,
    cp: Any,
    kind: str,
    round: int,
    expected: bool,
    label: str,
) -> None:
    """Exercise the real can_sign/sign_vote path and record the reason."""
    w = s.witnesses[wid]
    allowed, reason = s.can_sign(w, cp, kind, round)
    vote = s.sign_vote(wid, cp, kind, round, phase=label)
    qc = s.submit_qc(cp, round, votes=[vote] if vote else [], phase=label)
    s.note(
        f"{label}: expected_allowed={expected} can_sign={allowed} "
        f"signature_created={vote is not None} qc_accepted={qc} reason={reason}; "
        f"lock={w.durable.get('locked')} current_round={w.volatile.get('current_round')} "
        f"polc={w.volatile.get('polc')}"
    )
    if allowed != expected:
        s.note(f"{label}: ANOMALY expected={expected} actual={allowed}")


def r1_b1(s: Simulator) -> None:
    """Locked round 2, round 3 conflicting prevote, no PoLC -> reject."""
    locked_cp = make_cp("b1lockkk")
    other = make_cp("b1conflict")
    _set_lock(s, "W1", locked_cp, 2)
    s.timeout_advance("W1", 3, phase="R1-B1-advance")
    _r1_probe(s, "W1", other, "prevote", 3, False, "R1-B1")
    _liv(s, False, False, False, True, {"L1": "targeted lock-rule probe, no recovery schedule"})


def r1_b2(s: Simulator) -> None:
    """Locked round 2, PoLC at round 2 (same round) -> no unlock."""
    locked_cp = make_cp("b2lockkk")
    other = make_cp("b2conflict")
    _set_lock(s, "W1", locked_cp, 2)
    _set_polc(s, "W1", other, 2)
    s.timeout_advance("W1", 3, phase="R1-B2-advance")
    _r1_probe(s, "W1", other, "prevote", 3, False, "R1-B2")
    _liv(s, False, False, False, True, {"L1": "same-round PoLC must not unlock"})


def r1_b3(s: Simulator) -> None:
    """Locked round 2, PoLC round 3, current round 4 -> lawful transfer."""
    locked_cp = make_cp("b3lockkk")
    other = make_cp("b3conflict")
    _set_lock(s, "W1", locked_cp, 2)
    _set_polc(s, "W1", other, 3)
    s.timeout_advance("W1", 4, phase="R1-B3-advance")
    _r1_probe(s, "W1", other, "prevote", 4, True, "R1-B3")
    _liv(s, True, True, True, True, {"L1": "2 < 3 < 4 permits lock transfer"})


def r1_b4(s: Simulator) -> None:
    """Locked round 2, PoLC round 4, current round 4 -> no strict inequality."""
    locked_cp = make_cp("b4lockkk")
    other = make_cp("b4conflict")
    _set_lock(s, "W1", locked_cp, 2)
    _set_polc(s, "W1", other, 4)
    s.timeout_advance("W1", 4, phase="R1-B4-advance")
    _r1_probe(s, "W1", other, "prevote", 4, False, "R1-B4")
    _liv(s, False, False, False, True, {"L1": "polc_round == current_round must not unlock"})


def r1_b5(s: Simulator) -> None:
    """Only two distinct prevotes -> no PoLC, so no precommit."""
    cp = make_cp("b5onlytwo")
    mids = [
        _sign(s, "W1", cp, round=0, kind="prevote", recipients=("W3",), phase="R1-B5"),
        _sign(s, "W2", cp, round=0, kind="prevote", recipients=("W3",), phase="R1-B5"),
    ]
    _deliver(s, mids, phase="R1-B5")
    w3 = s.witnesses["W3"]
    seen = sorted({v.witness for v in s.votes_for_polc(w3) if v.kind == "prevote"})
    allowed, reason = s.can_sign(w3, cp, "precommit", 0)
    vote = s.sign_vote("W3", cp, "precommit", 0, phase="R1-B5")
    s.note(
        f"R1-B5: expected_allowed=False can_sign={allowed} signature_created={vote is not None} "
        f"reason={reason}; W3 observed={seen} has_polc={s.has_polc(w3, cp, 0)}"
    )
    if allowed:
        s.note("R1-B5: ANOMALY expected=False actual=True")
    _liv(s, False, True, True, False, {"L1": "two prevotes are below the 3-of-4 PoLC threshold"})


def r1_b6(s: Simulator) -> None:
    """Byzantine double-signs; honest lock rule is unchanged."""
    cp_a = make_cp("b6aaa")
    cp_b = make_cp("b6bbb")
    _set_lock(s, "W1", cp_a, 2)
    s.timeout_advance("W1", 3, phase="R1-B6-advance")
    s.mark_byzantine("W4", phase="R1-B6")
    b1 = s.sign_vote("W4", cp_a, "prevote", 3, force_byzantine_conflict=True, phase="R1-B6")
    b2 = s.sign_vote("W4", cp_b, "prevote", 3, force_byzantine_conflict=True, phase="R1-B6")
    _deliver(s, [s.send(v, ["W1"], phase="R1-B6") for v in (b1, b2) if v], phase="R1-B6")
    s.note(f"R1-B6: Byzantine W4 emitted two conflicting prevotes: {b1 is not None and b2 is not None}")
    _r1_probe(s, "W1", cp_b, "prevote", 3, False, "R1-B6-honest")
    _liv(s, False, False, False, True, {"L1": "Byzantine equivocation must not relax an honest lock"})


def r1_b7(s: Simulator) -> None:
    """Restart restores locked_round/locked_digest; lock is not forgotten."""
    locked_cp = make_cp("b7lockkk")
    other = make_cp("b7conflict")
    _set_lock(s, "W1", locked_cp, 2)
    s.timeout_advance("W1", 3, phase="R1-B7-advance")
    s.restart("W1", "full", phase="R1-B7")
    _r1_probe(s, "W1", other, "prevote", 3, False, "R1-B7")
    _liv(s, False, False, False, True, {"L1": "durable lock survives a full restart"})


def r1_b8(s: Simulator) -> None:
    """An old-round PoLC cannot be reused as a new-round PoLC."""
    cp = make_cp("b8reuse")
    _set_polc(s, "W1", cp, 1)
    s.timeout_advance("W1", 2, phase="R1-B8-advance")
    allowed, reason = s.can_sign(s.witnesses["W1"], cp, "precommit", 2)
    vote = s.sign_vote("W1", cp, "precommit", 2, phase="R1-B8")
    s.note(
        f"R1-B8: expected_allowed=False can_sign={allowed} signature_created={vote is not None} "
        f"reason={reason}; polc={s.witnesses['W1'].volatile.get('polc')}"
    )
    if allowed:
        s.note("R1-B8: ANOMALY expected=False actual=True")
    _liv(s, False, True, True, False, {"L1": "exact-round PoLC binding prevents old-round reuse (S4)"})


def fresh_b(s: Simulator) -> None:
    """Freshness is not implied by a valid QC: three observation layers."""
    cp_old = make_cp("freshhold")
    cp_new = make_cp("freshnewr")
    committed = _precommit_and_qc(s, cp_old, 0, HONEST, phase="FRESH-commit")
    # Honest witnesses are locked on cp_old; a conflicting cp_new prevote
    # cannot be produced without a qualifying PoLC (verified in P3-B/R1-B1).
    for wid in HONEST:
        s.timeout_advance(wid, 1, phase="FRESH-observe")
        _sign(s, wid, cp_new, round=1, kind="prevote", recipients=("G",), phase="FRESH-observe")
    s.note(
        "FRESH-B layers: (1) gateway committed QC="
        + str(sorted(s.gateway.committed.values()))
        + "; (2) witness durable locks="
        + str({w: s.witnesses[w].durable.get("locked") for w in HONEST})
        + "; (3) witness volatile observed digests="
        + str(sorted({v.cp.checkpoint_digest for w in HONEST for v in s.witnesses[w].volatile.get("observed", [])}))
    )
    s.note(
        "FRESH-B: a valid QC certifies commit of cp_old only; it does not prove "
        "that cp_old is the newest state. In this model a conflicting honest "
        "commit is unreachable after cp_old QC, but a partition may hide a "
        "newer candidate from the gateway. This remains an external latestness assumption."
    )
    _liv(s, committed, committed, True, False, {
        "L1": "gateway holds a valid but possibly stale commit",
        "L2": "no incomplete conflicting candidate formed by honest witnesses",
        "L3": "three honest witnesses formed the QC",
        "L4": "no administrator or clock; latestness is still external",
    })


# ---------------- R1-C1: explicit Model B round advancement ----------------


def _state_fingerprint(w: Any) -> Tuple[Any, ...]:
    """Read-only fingerprint used to prove can_sign has no side effects."""
    return (
        w.volatile.get("current_round", 0),
        repr(w.durable.get("locked", {})),
        repr(w.durable.get("pending", {})),
        tuple(
            (v.kind, v.witness, v.round, v.cp.checkpoint_digest, v.nonce)
            for v in w.signed_votes()
        ),
    )


def r1_c1_b1(s: Simulator) -> None:
    """C1 A-E: current_round advances only via explicit events, never by signing."""
    lock_a = make_cp("c1lockaa")
    conflict = make_cp("c1conflict")

    # --- Test A: round 4 request while current_round is 2 -> reject; no advance.
    _set_lock(s, "W1", lock_a, 2)
    s.timeout_advance("W1", 2, phase="R1-C1-A-advance")
    _set_polc(s, "W1", conflict, 3)
    w1 = s.witnesses["W1"]
    round_a_before = w1.volatile.get("current_round")
    allowed_a, reason_a = s.can_sign(w1, conflict, "prevote", 4)
    vote_a = s.sign_vote("W1", conflict, "prevote", 4, phase="R1-C1-A")
    round_a_after = w1.volatile.get("current_round")
    s.note(
        f"R1-C1-A: expected_allowed=False can_sign={allowed_a} signature_created={vote_a is not None} "
        f"current_round_before={round_a_before} current_round_after={round_a_after} reason={reason_a}"
    )

    # --- Test B: explicit advance to 4, then lawful transfer (2 < 3 < 4).
    _set_lock(s, "W2", lock_a, 2)
    s.timeout_advance("W2", 2, phase="R1-C1-B-advance2")
    _set_polc(s, "W2", conflict, 3)
    s.timeout_advance("W2", 4, phase="R1-C1-B-advance4")
    w2 = s.witnesses["W2"]
    round_b_after_advance = w2.volatile.get("current_round")
    allowed_b, reason_b = s.can_sign(w2, conflict, "prevote", 4)
    vote_b = s.sign_vote("W2", conflict, "prevote", 4, phase="R1-C1-B")
    round_b_after_sign = w2.volatile.get("current_round")
    s.note(
        f"R1-C1-B: expected_allowed=True can_sign={allowed_b} signature_created={vote_b is not None} "
        f"current_round_after_advance={round_b_after_advance} current_round_after_sign={round_b_after_sign} "
        f"reason={reason_b}"
    )

    # --- Test C: current_round 4, request old round 3 -> reject.
    s.timeout_advance("W3", 4, phase="R1-C1-C-advance")
    w3 = s.witnesses["W3"]
    before_c = _state_fingerprint(w3)
    allowed_c, reason_c = s.can_sign(w3, conflict, "prevote", 3)
    vote_c = s.sign_vote("W3", conflict, "prevote", 3, phase="R1-C1-C")
    after_c = _state_fingerprint(w3)
    s.note(
        f"R1-C1-C: expected_allowed=False can_sign={allowed_c} signature_created={vote_c is not None} "
        f"state_unchanged={before_c == after_c} reason={reason_c}"
    )

    # --- Test D: can_sign is a pure check on a higher-round request.
    before_d = _state_fingerprint(w3)
    for _ in range(2):
        d_allowed, d_reason = s.can_sign(w3, conflict, "prevote", 6)
    after_d = _state_fingerprint(w3)
    s.note(
        f"R1-C1-D: can_sign={d_allowed} state_unchanged={before_d == after_d} "
        f"current_round={w3.volatile.get('current_round')} reason={d_reason}"
    )

    # --- Test E: timeout advances the round but never unlocks a durable lock.
    _set_lock(s, "W4", lock_a, 2)
    s.timeout_advance("W4", 4, phase="R1-C1-E-advance")
    w4 = s.witnesses["W4"]
    lock_before_e = repr(w4.durable.get("locked", {}))
    allowed_e, reason_e = s.can_sign(w4, conflict, "prevote", 4)
    vote_e = s.sign_vote("W4", conflict, "prevote", 4, phase="R1-C1-E")
    lock_after_e = repr(w4.durable.get("locked", {}))
    s.note(
        f"R1-C1-E: expected_allowed=False can_sign={allowed_e} signature_created={vote_e is not None} "
        f"lock_unchanged={lock_before_e == lock_after_e} current_round={w4.volatile.get('current_round')} "
        f"reason={reason_e}"
    )

    _liv(s, False, False, False, True, {
        "L1": "targeted state-machine probe; no recovery schedule claimed",
        "L4": "explicit advancement is an event-machine rule, not an external trusted clock",
    })


SCENARIOS: Dict[Tuple[str, str], Callable[[Simulator], None]] = {}
for _model in ("A", "B", "C"):
    SCENARIOS[(_model, "P1")] = p1
    SCENARIOS[(_model, "P2")] = p2
    SCENARIOS[(_model, "P3")] = p3
    SCENARIOS[(_model, "P4")] = p4
    SCENARIOS[(_model, "P5")] = p5
    SCENARIOS[(_model, "P6")] = p6
    SCENARIOS[(_model, "P7")] = p7
    SCENARIOS[(_model, "P8")] = p8
    SCENARIOS[(_model, "P9")] = p9
    SCENARIOS[(_model, "P10")] = p10
SCENARIOS[("UNSAFE", "U1")] = unsafe_u1
SCENARIOS[("C", "CK1")] = ck1
SCENARIOS[("C", "CK2")] = ck2
SCENARIOS[("C", "CK3")] = ck3
SCENARIOS[("C", "CK4")] = ck4
SCENARIOS[("C", "CK5")] = ck5
SCENARIOS[("C", "CK6")] = ck6
SCENARIOS[("C", "CK7")] = ck7
SCENARIOS[("A", "AL1")] = al1
SCENARIOS[("B", "FRESH-B")] = fresh_b
for _sid, _fn in (
    ("R1-B1", r1_b1),
    ("R1-B2", r1_b2),
    ("R1-B3", r1_b3),
    ("R1-B4", r1_b4),
    ("R1-B5", r1_b5),
    ("R1-B6", r1_b6),
    ("R1-B7", r1_b7),
    ("R1-B8", r1_b8),
):
    SCENARIOS[("B", _sid)] = _fn
SCENARIOS[("B", "R1-C1-B1")] = r1_c1_b1

DESCRIPTIONS = {
    "P1": "two witnesses lock a candidate, but only two signatures exist",
    "P2": "three witnesses sign a candidate while its QC is delayed to one witness",
    "P3": "gateway observes the old state while witnesses observe a newer state",
    "P4": "two conflicting sibling checkpoints",
    "P5": "witness restart with complete durable state",
    "P6": "witness restart after pending-lock record loss",
    "P7": "one Byzantine witness issues conflicting signatures",
    "P8": "network partition yields different round observations",
    "P9": "old checkpoint receives a fresh-nonce FC request",
    "P10": "witness-set rotation with inconsistent old/new locks",
    "U1": "unsafe counterexample: local timeout used as unlock proof",
    "CK1": "signature issued before lease expiry, QC submitted after expiry",
    "CK2": "quorum present before expiry but submitted to gateway after expiry",
    "CK3": "clock skew at and beyond epsilon",
    "CK4": "clock rollback or unavailable clock",
    "CK5": "old-lease and new-round signatures mixed",
    "CK6": "old QC replay after lease expiry",
    "CK7": "gateway clock rollback re-enables expired QC",
    "AL1": "permanent lock with total durable-state loss",
    "FRESH-B": "valid QC does not prove global latestness; three observation layers",
    "R1-B1": "locked round 2, round 3 conflicting prevote without PoLC rejected",
    "R1-B2": "same-round PoLC cannot unlock round-2 lock",
    "R1-B3": "locked 2, PoLC 3, current 4 permits lock transfer",
    "R1-B4": "polc_round == current_round cannot unlock",
    "R1-B5": "two prevotes do not form a PoLC",
    "R1-B6": "Byzantine double-sign does not relax an honest lock",
    "R1-B7": "full restart restores locked round and digest",
    "R1-B8": "old-round PoLC cannot be reused for a new-round precommit",
    "R1-C1-B1": "explicit round advancement required; signature requests never advance rounds",
}


def run_all() -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for (model, sid), fn in SCENARIOS.items():
        s = _new(model, sid, DESCRIPTIONS[sid])
        fn(s)
        results[f"{sid}-{model}"] = s.finalize()
    return results


def main() -> None:
    results = run_all()
    out = Path(__file__).resolve().parent.parent / "results"
    write_json(out / "p1_p10.json", results)
    summary = {
        "revision": "R1-C1",
        "base_commit": "41e1742a85f7de8955a1409e4750fb1e6d85207c",
        "seed": 20261124,
        "scenario_count": len(results),
        "models": ["A", "B", "C"],
        "unsafe_counterexample": "U1-UNSAFE",
        "model_b_lock_transfer": "locked_round < polc_round < current_round; same/lower round PoLC never unlocks",
        "model_b_round_advance": "current_round only via explicit timeout_advance; can_sign is read-only; vote round must equal current_round",
        "liveness_source": "derived from recorded events and final state; not_applicable when precondition is absent",
        "note": "Safety and liveness are reported separately. Simulator results are not a BFT soundness proof.",
    }
    write_json(out / "summary.json", summary)
    print(f"wrote {len(results)} scenario results to {out}")


if __name__ == "__main__":
    main()
