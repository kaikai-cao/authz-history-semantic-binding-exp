# EXP-D3-06-C — Two-Event IR-Bound Circuit Specification

## 1. Circuit identity

| Item | Value |
| --- | --- |
| Module | `src/transition/d3_06_c_circuit.rs` |
| Circuit | `TransitionCircuitC` |
| Config | `TransitionConfigC` |
| Witness | `TransitionWitnessC` |
| K | `K_C = 16` (engineering decision; measured in Phase 6) |
| Events | exactly 2 active slots |
| Public values | frozen 8 values |

The circuit is an independent additive module. B and all earlier frozen implementations are unchanged; `mod.rs` only registers the three new C modules.

## 2. Root chaining

The most important constraint is not a new hash; it is a cell-level dependency:

```text
Event 0 output GR cell ──> Event 1 input GR cell
Event 0 output RR cell ──> Event 1 input RR cell
Event 0 output IR cell ──> Event 1 input IR cell
```

Implementation detail:

- `gr_in[0]`, `rr_in[0]`, `ir_in[0]` are assigned from S0;
- after each event, `state_transition` produces a new root cell;
- that exact `AssignedCell` is pushed into the input vector for the next event.

Therefore Event 1 has no independent root witness. A prover cannot substitute a fresh intermediate root or replay S0 roots without failing the root-binding gates of Event 1.

This is the circuit-level answer to the stage question: Event 1 can only continue from the state produced by Event 0.

## 3. Per-event constraints

For each `i ∈ {0, 1}`:

### 3.1 Control

```text
isGrant_i + isRevoke_i = 1
isGrant_i, isRevoke_i ∈ {0,1}
event_count = 2
```

Both slots are active. There is no `active_i` flag that can disable an event.

### 3.2 Grant branch

- GR parent opening root == current GR input root;
- GR parent leaf is recomputed from full grant words;
- parent.id == `key_field(parent_id)` used by child;
- parent.subject == child.issuer;
- child.epoch == `nextEpoch`;
- child scope ⊆ parent scope (64-bit bitwise gate);
- child resource prefix == parent prefix (64-bit bitwise gate);
- GR child slot old root == current GR root with empty leaf;
- GR child slot new root is computed from the new child leaf;
- IR read at `low_4(parent.id)` is forced to ACTIVE;
- IR write at `low_4(child.id)` is forced from canonical ABSENT to ACTIVE;
- RR root is copied by `state_transition` with flag 0.

### 3.3 Revoke branch

- GR target opening root == current GR input root;
- target.id == revoke.grant_id == IR write id;
- target.issuer == revoker;
- revoke.epoch == `nextEpoch`;
- RR target slot old root == current RR root with empty leaf;
- RR new root is computed from the revoke leaf;
- IR read at `low_4(target.id)` is forced to ACTIVE;
- IR write is ACTIVE → REVOKED;
- GR root is copied by `state_transition` with flag 0.

### 3.4 IR state integrity

All IR state words are generated from constrained constants through the D3-06-B mux:

- read state: `one_cell = ACTIVE`;
- Grant write-old id/state: `(0, 0)`, the canonical empty leaf;
- Revoke write-old id/state: `(id, ACTIVE)`;
- write-new state: `ACTIVE` for Grant, `REVOKED` for Revoke;
- `REVOKED` is constrained by `c-const-two`.

No prover-supplied `ir_read_state`, `ir_write_old_state` or `ir_write_new_state` field is used in a leaf hash.

### 3.5 Same-path update

For each GR/RR/IR update:

```text
slot_old = slot_new
dir_old[j] = dir_new[j]   for j = 0..3
sib_old[j] = sib_new[j]   for j = 0..3
```

These are copy constraints on assigned path cells. This is the circuit basis for “other IDs are unchanged” within one event.

### 3.6 IR slot binding

`assign_canon_id` performs a canonical 256-bit field decomposition. The low four bits are copied to:

- the slot accumulator (`slot = low_4(id)`);
- each Merkle direction cell of the IR opening.

A prover-chosen slot or direction cannot satisfy these gates unless it equals the low nibble of the full ID. GR/RR keep their witness-slot semantics and are not forced to equal `low_4(id)`.

### 3.7 Implementation note on equality gates

During initial two-event integration, direct copy-only regions for `target.id = revoke.grant_id`, `target.issuer = revoker` and `revoke.epoch = nextEpoch` produced MockProver permutation failures in the second-event layout. The C circuit enforces those equalities with the already-constrained `one_cell` flag through `c-gated-eq`:

```text
one_cell * (left - right) = 0
```

This keeps the equalities unconditional without changing field semantics. All negative tests still enter the circuit and fail on actual gates/copy constraints.

## 4. State commitment

```text
C_prev = H(D3-STATE-v2, GR0, RR0, IR0, prevEpoch, policy)
C_next = H(D3-STATE-v2, GR2, RR2, IR2, nextEpoch, policy)
```

where `H` is `poseidon::<6>`. The old `D3-STATE-P-v2` domain is rejected by N28.

IR roots are included in both commitments. Binding only GR/RR or only one event's intermediate root is rejected by N26/N27.

## 5. Batch commitment and instances

```text
D_E = H(D3-BATCH-v1, 2, C0, C1, Cpad)
```

`C0` is Event 0's commitment, `C1` is Event 1's commitment, and `Cpad` is the canonical padding value. Event order is enforced by binding each event's computed commitment to its own slot.

Instance order remains:

| Index | Value |
| --- | --- |
| 0 | `C_prev` |
| 1 | `prev_epoch` |
| 2 | `C_next` |
| 3 | `next_epoch` |
| 4 | `policy_id` |
| 5 | `transition_version` |
| 6 | `D_E` |
| 7 | `event_count = 2` |

No ninth public value is introduced.

## 6. Gate families

The C config reuses the B gate families, renamed `b-*` to `c-*`:

- canonical decomposition: boolean bit, transition, final;
- control: boolean flag, type split, slot padding, count;
- Merkle path: direction boolean, left/right select;
- 64-bit pair: boolean bits, accumulator A/B, scope subset, prefix equality;
- state/gating: gated equality, state transition;
- IR: slot boolean, slot binding, constant two;
- Poseidon gadget gates from `halo2_gadgets`.

Runtime metadata from Halo2 `pinned()`:

```text
fixed=10, advice=32, instance=1 column (8 values), selectors=27
K=16, max_rows=65536, gate_families_source=22
```

## 7. Honest boundaries

Not proved by this circuit:

- external S0 anchoring, signature or checkpoint validity;
- execution-time freshness;
- revoker authority beyond the E-R1 assumption;
- arbitrary 256-bit raw ID → Pallas field mapping;
- DENY, Cascade, recursive or full-history proofs;
- RG ordering and three-or-more events;
- large IR capacity beyond depth 4 / 16 slots;
- a formal Halo2 soundness proof or general performance superiority.
