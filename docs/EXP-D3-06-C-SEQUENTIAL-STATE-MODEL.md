# EXP-D3-06-C — Sequential Two-Event State Model

## 1. Scope

This document defines the host-side state model for `EXP-D3-06-C`. It covers exactly two active events in one proof:

- GG: Grant → Grant;
- GR: Grant → Revoke;
- RR: Revoke → Revoke.

RG, three-or-more events, recursion and DENY are outside this stage.

The host model is a witness-construction aid. Its correctness is necessary for honest witness generation but is **not** trusted by the circuit: the circuit independently re-derives all roots and constrains Event 1 to consume Event 0's output.

## 2. State

```text
S0 = (GR0, RR0, IR0, epoch0, policy)
S1 = (GR1, RR1, IR1, epoch1, policy)
S2 = (GR2, RR2, IR2, epoch2, policy)
```

The batch uses one epoch increment:

```text
epoch1 = epoch2 = epoch0 + 1 = nextEpoch
```

Both events are bound to `nextEpoch`; the epoch is not incremented once per event.

S0 is supplied as explicit GR/RR/IR preimages compatible with the D3-06-A validator:

- GR/RR leaves use frozen B/C leaf encodings and witness slots;
- IR leaves use `H(D3-INDEX-v1, full_id, state)` at slot `low_4(full_id)`;
- `VALIDATE(S0)` remains a host/external trust assumption.

## 3. Host execution order

`build_scenario_c` performs a genuine sequential execution:

1. Build `GR0`, `RR0`, `IR0` roots from explicit preimages.
2. Construct Event 0 old/new openings from `S0`.
3. Apply Event 0 to obtain the leaf arrays for `S1`.
4. Construct Event 1 old/new openings from `S1`, never from `S0`.
5. Apply Event 1 to obtain `S2`.
6. Record event commitments in order: slot 0 = C0, slot 1 = C1, slot 2 = canonical padding.

The event list is ordered. The builder does not sort, commute or swap events. RG is not emulated by reordering GR.

## 4. Grant event

For a Grant of child `b` by parent `a`:

Current state `Si`:

- GR: parent slot opening must contain `leaf(a)`; child slot must be empty.
- IR: read opening at `low_4(a.id)` must be `ACTIVE`; write opening at `low_4(b.id)` must be canonical `ABSENT`.
- RR: unchanged.

After the event:

- `GR_{i+1}` writes `leaf(b)` into the same GR child slot;
- `IR_{i+1}` writes `H(D3-INDEX-v1, b.id, ACTIVE)` into the same IR slot;
- `RR_{i+1} = RR_i`.

Additional semantics inherited from D3-06-B / E-R1:

- `b.parent_key = a.id`;
- `b.issuer = a.subject`;
- `b.epoch = nextEpoch`;
- child scope is a subset of parent scope;
- resource prefix equals parent prefix.

## 5. Revoke event

For a Revoke of target `t` by `revoker`:

Current state `Si`:

- GR: target slot opening must contain `leaf(t)`;
- IR: opening at `low_4(t.id)` must be `ACTIVE`;
- RR: target slot must be empty.

After the event:

- `GR_{i+1} = GR_i`;
- `RR_{i+1}` writes `revoke_leaf(t.id, revoker, nextEpoch)` into the same RR slot;
- `IR_{i+1}` writes `H(D3-INDEX-v1, t.id, REVOKED)` into the same IR slot.

Mandatory binding:

```text
target.id = revoke.grant_id = IR write id
```

## 6. Sequential combinations

### GG — Grant → Grant

```text
S0: A ACTIVE
e0: A grants B at GR slot 2
S1: B ACTIVE in both GR1 and IR1
e1: B grants C at GR slot 3
S2: B, C ACTIVE
```

This is the key induction-chain case: Event 1's parent opening is taken from `S1`, not from `S0`. If `B` did not exist in `S1`, the circuit cannot satisfy the Event 1 GR/IR parent bindings.

### GR — Grant → Revoke

```text
S0: A ACTIVE
e0: A grants B
S1: B ACTIVE
e1: revoke B
S2: B REVOKED in IR2, RR2 contains B
```

Event 1's GR target and IR target openings are taken from `S1`. The newly created grant can be revoked in the same batch only through the state produced by Event 0.

### RR — Revoke → Revoke

```text
S0: A, B ACTIVE
e0: revoke A
S1: A REVOKED
e1: revoke B
S2: A, B REVOKED
```

Event 1 uses `RR1` and `IR1`. Revoking A twice or writing into an already occupied RR slot is rejected.

## 7. What the host model does not prove

The builder does not establish:

- external anchoring or signature validity of S0;
- that the host preimages are the unique real-world authorization state;
- freshness at execution time;
- that Event 1 follows Event 0 in the circuit — this is enforced by root-cell chaining in `d3_06_c_circuit.rs`;
- DENY, Cascade, recursive history or full replay;
- large-capacity IR beyond depth 4 / 16 slots.

The circuit result must be stated as: given a trusted, cross-structure-consistent S0, a successful two-event proof binds both events to one ordered state chain.
