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
        s.timeout_advance("W1", 1, phase="P1-recovery")
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
        mids = [
            _sign(s, "W1", cp_a, round=0, kind="prevote", recipients=ALL, phase="P2"),
            _sign(s, "W2", cp_a, round=0, kind="prevote", recipients=ALL, phase="P2"),
            _sign(s, "W3", cp_a, round=0, kind="prevote", recipients=ALL, phase="P2"),
        ]
        _deliver(s, [mids[1], mids[2]], phase="P2")
        s.mark_byzantine("W4", phase="P2")
        pre_mids = [
            _sign(s, "W2", cp_a, round=0, kind="precommit", recipients=("G",), phase="P2"),
            _sign(s, "W3", cp_a, round=0, kind="precommit", recipients=("G",), phase="P2"),
            _sign(s, "W4", cp_a, round=0, kind="precommit", recipients=("G",), phase="P2"),
        ]
        _deliver(s, pre_mids, phase="P2")
        committed = s.submit_qc(cp_a, 0, phase="P2")
        s.learn_commit("W1", cp_a, phase="P2-heal")
        s.timeout_advance("W1", 1, phase="P2-heal")
        _sign(s, "W1", cp_b, round=1, kind="prevote", recipients=("G",), phase="P2-heal")
        # Delayed old-round prevote must not become a round-1 QC vote.
        s.submit_qc(cp_b, 1, votes=[s.witnesses["W1"].signed_votes()[0], s.witnesses["W4"].signed_votes()[0]] if s.witnesses["W4"].signed_votes() else [], phase="P2-heal")
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
        s.submit_qc(cp_old, 0, phase="P3")
        # W2/W3 (unlocked in this branch) and Byzantine W4 publish a higher-round PoLC for cp_new.
        obs = [
            _sign(s, "W2", cp_new, round=1, kind="prevote", recipients=("W1",), phase="P3-observed"),
            _sign(s, "W3", cp_new, round=1, kind="prevote", recipients=("W1",), phase="P3-observed"),
        ]
        s.mark_byzantine("W4", phase="P3-observed")
        byz = s.sign_vote("W4", cp_new, "prevote", 1, force_byzantine_conflict=True, phase="P3-observed")
        if byz:
            obs.append(s.send(byz, ["W1"], phase="P3-observed"))
        _deliver(s, obs, phase="P3-observed")
        fc = _sign_fc(s, "W1", cp_old, "nonce-1", recipients=("G",), phase="P3-fc")
        _deliver(s, [fc], phase="P3-fc")
        s.submit_fc(cp_old, "nonce-1", phase="P3-fc")
        _liv(s, True, True, True, False, {
            "L1": "gateway can still obtain fresh authentication for a non-stale digest",
            "L2": "stale FC is blocked by higher-round PoLC evidence",
            "L3": "three honest witnesses were available",
            "L4": "no administrator; requires PoLC observation at the witness",
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
        s.timeout_advance("W1", 1, phase="P4-recovery")
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
        s.timeout_advance("W1", 1, phase="P8-heal")
        accepted = _precommit_and_qc(s, cp_c, 1, HONEST, phase="P8-heal")
        _liv(s, accepted, accepted, True, False, {
            "L1": "after partition heals, higher-round honest quorum advances",
            "L2": "neither partition could commit with only two valid votes",
            "L3": "three honest witnesses can form quorum after heal",
            "L4": "no administrator; round change required",
        })
        s.note(f"partition QCs: cp_a={first}, cp_b={second}")
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
        "seed": 20261124,
        "scenario_count": len(results),
        "models": ["A", "B", "C"],
        "unsafe_counterexample": "U1-UNSAFE",
        "note": "Safety and liveness are reported separately. Simulator results are not a BFT soundness proof.",
    }
    write_json(out / "summary.json", summary)
    print(f"wrote {len(results)} scenario results to {out}")


if __name__ == "__main__":
    main()
