# EXP-D3-06-B · Baseline Freeze and Source Audit

## 0. Scope

This document freezes the Phase-0 baseline for **EXP-D3-06-B: Halo2 IR-Bound
Transition Prototype** (single-event Grant/Revoke dual-branch). It records only
facts verified directly against the repository at the frozen commit; no
conclusion here is a cryptographic proof.

- Repository: `kaikai-cao/authz-history-semantic-binding-exp`
- Baseline commit: `b102167cfc0f8a9138f3e4817ce2c9db40dd7cbe`
- New branch: `exp-d3-06-b-ir-transition`
- Upstream semantic baseline: E-R1 (`K_R1 = 15`), unchanged.
- S0 validator baseline: EXP-D3-06-A (`s0_consistency_v2.rs`), unchanged.
- Nature: independent additive Halo2 prototype; frozen implementations untouched.

Phase-0 verification commands actually run:

```
git status --short --branch        -> ## exp-d3-06-a-s0-validator...origin/exp-d3-06-a-s0-validator (clean)
git rev-parse HEAD                 -> b102167cfc0f8a9138f3e4817ce2c9db40dd7cbe
git rev-parse origin/exp-d3-06-a-s0-validator -> b102167cfc0f8a9138f3e4817ce2c9db40dd7cbe
git rev-parse origin/main          -> 09612dbb26422d14cc5628cb39f7ce444be159b5
```

All conditions satisfied: clean working tree, HEAD == required baseline,
origin S0 branch == baseline, `main` frozen at D3-01. Branch created with
`git switch -c exp-d3-06-b-ir-transition b102167`.

## 1. Dependencies (frozen by `Cargo.toml` at baseline)

| Crate | Pin | Notes |
| --- | --- | --- |
| `halo2_proofs` | `=0.4.0` | features `batch`, `floor-planner-v1-legacy-pdqsort`, no default features |
| `halo2_gadgets` | `=0.6.0` | `Pow5Chip`, `Hash`, `Pow5Config` |
| `halo2_poseidon` | `=0.2.0` | host Poseidon (`crate::encoding::poseidon`) |
| `pasta_curves` | `=0.6.0` | `pallas::Base` = Pallas base field `F` |
| `ff`, `group` | `0.14` | field traits |
| `rand` | `0.10` | `StdRng` for proof tests |
| `[profile.release]` | `opt-level = 3` | single profile for all comparisons |

Poseidon parameters: `P128Pow5T3`, width 3, rate 2. IR depth 4 / capacity 16.
ID experiment domain: `F \ {0}`. No 256-bit raw-ID mapping in this round.

## 2. Source files audited (read in full or in sections)

- `src/transition/e_r1_circuit.rs` (1761 lines) — Config, all gates, synthesize
- `src/transition/e_r1_types.rs` (465) — witness, instance helper, scenario builder
- `src/transition/e_r1_constants.rs` (53) — `K_R1 = 15`, two-event slots
- `src/transition/e_r1_types_host.rs` (74) — `blank_r1` keygen witness
- `src/transition/e_r1_uniqueness.rs` (157) — full-tree scan witness model
- `src/transition/b_types.rs` (306) — `GrantFieldsB`, `OpeningB`, `SparseTreeB`
- `src/transition/b_constants.rs` (72) — `d_grant_b`, `d_node_b`, DEPTH=4, TYPE_GRANT=1
- `src/transition/c_types.rs` (232) — `RevokeFieldsC`, `revoke_leaf_c`
- `src/transition/constants.rs` (187) — `d_state()` = `D3-STATE-P-v2`, policy, 8 instances
- `src/transition/s0_consistency_v2.rs` (491) — IR encoding + `C_v2` (frozen)
- `src/transition/mod.rs` (72) — module registry
- `src/encoding.rs` (174) — `domain_field`, `poseidon`, canonical byte encode/decode
- `tests/d3_03_e_r1_proof.rs` — real proof/verify + instance helper pattern

## 3. Frozen public statement (E-R1, unchanged in shape)

E-R1 has exactly **8 public values in one instance column**, in this order
(`e_r1_types.rs::r1_instances`, `e_r1_circuit.rs:1750-1757`):

| idx | field | meaning |
| --- | --- | --- |
| 0 | `C_prev` | `H(D3-STATE-P-v2, GR_in, RR_in, prev_epoch, policy_id)` (5 words) |
| 1 | `prev_epoch` | input epoch |
| 2 | `C_next` | same tag, final roots, `next_epoch` |
| 3 | `next_epoch` | output epoch |
| 4 | `policy_id` | frozen policy field |
| 5 | `transition_version` | u32→field, `=1` |
| 6 | `D_E` | `H(D3-BATCH-v1, n, commitments[0..3])` |
| 7 | `event_count` | number of active events |

**D3-06-B keeps the same 8-instance shape** (interface B from D3-04, confirmed
in D3-05 / D3-05-R1): only the *internal* commitment width changes from 5 to 6
words and the domain tag changes:

```
C_prev = poseidon::<6>([D3-STATE-v2, GR_in, RR_in, IR_in, prev_epoch, policy])
C_next = poseidon::<6>([D3-STATE-v2, GR_out, RR_out, IR_out, next_epoch, policy])
```

`D3-STATE-v2` is provided by frozen `s0_consistency_v2::d_state_v2()` and is
deliberately distinct from frozen v1 `d_state() = D3-STATE-P-v2`. Domain
separation is asserted by a frozen unit test (`v2_domain_is_distinct_from_frozen_v1`).

## 4. Frozen object semantics reused

### 4.1 GR (`b_types.rs`)
- `GrantFieldsB`: `id, issuer, subject, resource_prefix[8], scope:u64, parent_key, epoch`.
- Occupied leaf: `poseidon::<9>([D3-GRANT-v1, id, issuer, subject, prefix_f, scope, parent_key, epoch, valid])`; occupied leaves are always `valid=1`.
- Node: `poseidon::<3>([D3-NODE-v1, L, R])`; depth 4, heap-shaped `SparseTreeB`.
- `OpeningB`: `sibling[l]`, `dir[l]` (0=left at leaf level first), `left[l]`, `right[l]`, `cur[l]`.
- `SparseTreeB::opening(slot)`: `dir[l] = ((16+slot) >> l) & 1` for `l<4`; siblings follow `node ^ 1`.
- `recompute_root_b(leaf, open)` walks leaf→root with the same node hash.

### 4.2 RR (`c_types.rs`)
- `RevokeFieldsC { grant_id, revoker, epoch }`; leaf `poseidon::<4>([D3-REVOKE-v1, grant_id, revoker, epoch])`.
- Same `SparseTreeB` mechanics and node hash as GR (D3-NODE-v1). RR keeps its
  **own witness slot** semantics; no `low_t` mapping is imposed on RR.

### 4.3 IR (`s0_consistency_v2.rs`, frozen at D3-06-A)
- Empty leaf: `L_empty = poseidon::<3>([D3-INDEX-v1, 0, 0])` — single canonical ABSENT encoding.
- Occupied leaf: `poseidon::<3>([D3-INDEX-v1, full_id, state])`, `state ∈ {1=ACTIVE, 2=REVOKED}`; code 0 in an occupied leaf is rejected as non-canonical ABSENT.
- Node: `poseidon::<3>([D3-INDEX-NODE-v1, L, R])`.
- `low_t(id) = to_repr()[0] & 15` (Pallas repr is little-endian; low nibble of the least-significant byte).
- `ir_root_from_leaves` folds 16 leaves with `chunks_exact(2)` per level (depth 4).
- Full S0 checks in that module (zero ID, slot range/collision, duplicate IDs, `R⊆G`, bidirectional GR/RR↔IR, state validity) are **host-only** and are not imported as circuit constraints.

## 5. E-R1 circuit constraint structure (audited, for controlled reuse)

`TransitionCircuitR1::configure` builds these gate families (exact source at
`e_r1_circuit.rs:707-950`):

1. **canonical field decoding** (`root-bit-boolean`, `canonical-transition`,
   `canonical-final`): 256-bit big-endian decomposition with strict `bit < p`
   prefix check; row 256 forces `less = 1`. Used to bind `gr_prev_be`/`rr_prev_be`
   (32-byte BE) to field root cells.
2. **control** (`active-boolean`, `type-flag-boolean`, `type-split`,
   `slot-padding`, `active-monotone`, `active-count`).
3. **Merkle path** (`path-dir-bool`, `path-select`): `dir` boolean;
   `left=(1-dir)*cur+dir*sib`, `right=dir*cur+(1-dir)*sib`; current cell is
   copy-equal to the previous level's hash.
4. **64-bit pair** (`pair-bit-bool`, `pair-acc-a/b`, `scope-subset`,
   `prefix-eq`, `epoch-pref`, `epoch-less`, `epoch-final`, `epoch-plus-one`)
   for grant parent/child semantics and epoch monotonicity.
5. **gated equality** (`gated-eq`: `flag*(l-r)=0`) for all branch semantics.
6. **state transition** (`state-transition`: `out = in + flag*(new-in)`).
7. **scan** (`scan-nonempty-boolean`, `scan-leaf-select`, `scan-id-neq`):
   E-R1's full 16-leaf GR/RR scan; **not reused** in D3-06-B.

Key pattern for same-path update (E-R1 lines 1330-1341 / 1423-1434): old and
new openings of the same slot are each assigned with their own `path_dir`/
`path_sib` cells, then `(dir, sib)` cells are **copy-equal'd across old/new**.
Only the leaf cell differs. This is the circuit basis of "other leaves unchanged"
and is reused for GR child, RR insert and IR target slots in D3-06-B.

Event flags: `is_grant + is_revoke = active` (one-hot when active), padded slots
have `slot = batch_pad()`. D3-06-B forces a single active event, so
`active = 1`, `is_grant + is_revoke = 1`, `event_count = 1`.

## 6. Reuse boundary for D3-06-B

- **Reuse unchanged**: `GrantFieldsB`/`OpeningB`/`SparseTreeB`, `RevokeFieldsC`,
  all frozen domain tags, `poseidon`, `encode_field_i`/`decode_field_i`,
  `d_state_v2()`/`d_index()`/`d_index_node()` from `s0_consistency_v2.rs`,
  `Pow5Chip` config pattern, gate patterns 1/3/5/6 above.
- **New, independent**: `d3_06_b_ir.rs` (IR host tree/opening + gadget contract),
  `d3_06_b_types.rs` (single-event witness/builder/instances),
  `d3_06_b_circuit.rs` (single-event dual-branch circuit), its tests and docs.
- **Not reused**: E-R1 full-tree scan and its 344 permutation budget; the
  goal of this round is to measure what IR local openings cost instead.
- **Not modified**: any frozen file listed in §1.1 of the task package;
  `mod.rs` receives module registrations only.

## 7. Explicitly out of scope this round

Two-event GG/GR/RR sequencing; 3+ events; recursion; in-circuit S0 full
cross-structure validation; DENY proof; 256-bit ID mapping; production-scale IR;
freshness/QC/checkpoint; revoker authority beyond E-R1's existing external
trust assumption. No novelty claim.
