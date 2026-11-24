# EXP-D3-06-C — Security Tests and Gate Attribution

## 1. Test surface

| File | Tests | Purpose |
| --- | --- | --- |
| `tests/d3_06_c_transition.rs` | 31 | MockProver: P01–P03 positives, N01–N28 negatives |
| `tests/d3_06_c_transition_proof.rs` | 3 | GG/GR/RR real proof roundtrip, instance tampering, intermediate-state tampering |
| `tests/d3_06_c_cost.rs` | 2 | E-R1 vs C cost; metadata probe |

Negatives are applied to a fully constructed witness and then passed into `MockProver::run`. A host builder pre-check is never used to claim a rejection. Each negative is checked against the honest public instance (or an instance recomputed only when the test explicitly isolates a gate such as `event_count` or padding).

Full release result for the branch: `362 passed / 0 failed / 3 ignored`.

## 2. Positives

| ID | Combination | Result |
| --- | --- | --- |
| P01 | GG | accept |
| P02 | GR | accept |
| P03 | RR | accept |

Each positive also asserts the expected root behavior:

- GG: GR and IR change, RR unchanged;
- GR: GR and RR change, IR changes;
- RR: GR unchanged, RR and IR change.

Event 1's parent/target opening is built from `S1`; the circuit accepts only because the root cells are chained.

## 3. Negative cases and observed failure attribution

The following table records the first failing constraint observed in this build. `permutation` means the first reported failure was a copy-constraint violation rather than a named custom gate.

| ID | Tampering | First observed failure |
| --- | --- | --- |
| N01 | Event 1 GR input sibling altered | `c-path-select` / permutation |
| N02 | Event 1 RR input sibling altered | `c-path-select` |
| N03 | Event 1 IR input sibling altered | `c-path-select` |
| N04 | Event 1 uses S0 IR opening | `c-gated-eq` |
| N05 | Event 1 uses S0 GR opening | `c-gated-eq` |
| N06 | GG second Grant reuses Event 0 ID | `c-gated-eq` |
| N07 | GG second Grant parent absent | permutation |
| N08 | GR second Revoke target not ACTIVE | `c-gated-eq` |
| N09 | RR second Revoke of same ID | permutation |
| N10 | RR second Revoke writes occupied RR slot | permutation |
| N11 | Event 1 GR/IR different ID | `c-gated-eq` |
| N12 | Event 1 RR/IR different ID | `c-gated-eq` |
| N13 | Event 1 Grant child ID vs IR write ID | `c-gated-eq` |
| N14 | IR old/new sibling mismatch | `c-path-select` |
| N15 | IR old/new direction mismatch | `c-path-select` |
| N16 | IR slot ≠ low4(full ID) | `c-gated-eq` |
| N17 | Truncated-key collision treated as ABSENT | permutation |
| N18 | Event 0 both flags off | `c-type-split` |
| N19 | Event 1 both flags off / no-op | `c-type-split` |
| N20 | One event both flags on | `c-type-split` |
| N21 | Other event both flags off | `c-type-split` |
| N22 | `event_count != 2` | `c-count` |
| N23 | Third batch slot not canonical padding | `c-slot-pad` |
| N24 | Swapped event commitments | `c-gated-eq` |
| N25 | Events use different epochs | `c-gated-eq` |
| N26 | `C_prev` omits IR0 | permutation on instance binding |
| N27 | `C_next` omits IR2 | permutation on instance binding |
| N28 | Old v1 state commitment | permutation on instance binding |

The important cross-event cases are N01–N05. They demonstrate that Event 1 cannot silently fall back to S0 or to an independently supplied intermediate state.

## 4. Real proof tests

### 4.1 Roundtrip

One keygen (`K_C=16`) was shared by all three combinations.

```text
GG: proof verifies
GR: proof verifies
RR: proof verifies
```

### 4.2 Public instance tampering

A valid GG proof was generated once. Flipping any of the eight public values caused `verify_proof` to reject the same proof. This covers `C_prev`, both epoch fields, `C_next`, policy, transition version, `D_E` and `event_count`.

### 4.3 Tampered intermediate state

A GR witness was modified so Event 1's `target_open` used Event 0's old child opening instead of the S1 opening. A proof could be produced locally, but verification against the honest `C_prev/C_next` failed. This demonstrates that an incorrect intermediate state cannot satisfy the fixed public state commitment.

## 5. Development findings

1. **Batch padding row.** The initial C circuit enabled `c-slot-pad` on row 1 as well as the padding row; this incorrectly constrained Event 1's commitment. Fixed by enabling padding only on the third slot row.
2. **Revoke field equalities.** Zero-row copy-only regions for `target.id = revoke.grant_id`, `target.issuer = revoker`, and `revoke.epoch = nextEpoch` caused MockProver permutation failures in the two-event layout. Replaced with unconditional `c-gated-eq` constraints driven by `one_cell`.
3. **Test scenario revoker field.** Initial GR/RR helpers used the RR slot number as `revoker`, which violated target.issuer = revoker. Corrected to derive `revoker` from the grant's issuer.

All fixes were confined to new C files and tests. No frozen B/E-R1 implementation was changed.

## 6. Boundaries

These tests are engineering evidence, not a formal Halo2 soundness proof. They do not cover:

- external S0 anchoring;
- arbitrary raw 256-bit ID mapping;
- RG, three events or recursion;
- DENY/Cascade;
- execution-time freshness;
- large IR capacity.
