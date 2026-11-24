# EXP-D3-06-B · Security Test Matrix and Gate Attribution

## Test harness

- File: `tests/d3_06_b_ir_transition.rs` (MockProver) and
  `tests/d3_06_b_ir_transition_proof.rs` (real proof/verify, N20).
- `MockProver::run(K_B=15, circuit, [instances_b(w)])`, `p.verify()`.
- Negative cases tamper a **witness** but keep the **honest public instance**,
  so acceptance would mean the prover forged a transition under the real
  statement. Cases altering the instance (N16/N17/N18/N20) are stated explicitly.
- Failure attribution records the first failing gate/permutation; the full
  vector is available with `--nocapture`.

## Positive cases (must accept)

| case | scenario | result |
| --- | --- | --- |
| grant_positive | parent A ACTIVE in GR/IR; grant B into empty child slot | accepted |
| revoke_positive | target A ACTIVE; write RR + IR ACTIVE→REVOKED | accepted |

Both also assert the host differential: Grant changes GR and IR roots, keeps RR;
Revoke keeps GR, changes RR and IR. Real proofs for both verify (below).

## Negative cases (must be rejected by Halo2)

| id | tampering | primary failing constraint | result |
| --- | --- | --- | --- |
| N01 | Grant parent IR state REVOKED at S0 | `permute state` (read leaf computed ACTIVE vs host opening cur[0]=REVOKED) | rejected |
| N02 | Grant parent IR ABSENT at S0 | `permute state` (empty leaf vs ACTIVE recompute) | rejected |
| N03 | Grant child IR slot already ACTIVE | `permute state` (write-old leaf id/state mux forces empty vs occupied opening) | rejected |
| N04 | Grant child IR slot already REVOKED | same as N03 (occupied opening vs forced ABSENT) | rejected |
| N05 | IR write id low nibble ≠ opening dir bits | `b-gated-eq` (write id binding) + path dir | rejected |
| N06 | truncated-key collision: child slot occupied by a different full ID | `permute state` (forced empty leaf ≠ occupied opening) — fail-closed | rejected |
| N07 | GR child id ≠ IR child id | `b-gated-eq` `write id = child.id` | rejected |
| N08 | Revoke target IR ABSENT (no record) | `permute state` (write-old ACTIVE vs empty opening) | rejected |
| N09 | Revoke target IR REVOKED | `permute state` (write-old ACTIVE vs REVOKED opening) | rejected |
| N10 | RR new leaf id ≠ IR write id | `b-gated-eq` `RR id = IR write id` | rejected |
| N11 | RR insert slot already holds a record | `permute state` (`rr_old_sel_0`, forced ZERO vs occupied) | rejected |
| N12 | IR old/new openings use different sibling | `b-path-select` index 1 + same-path copy | rejected |
| N13 | IR old/new openings use different direction | `b-path-select` + same-path copy | rejected |
| N14 | IR old/new openings use different slot (dir[1] flipped) | `b-path-select` + same-path copy | rejected |
| N15 | Merkle direction ≠ actual slot bit | `b-path-select` (dir↔low_bits copy) | rejected |
| N16 | `C_prev` instance tampered | verifier permutation on instance 0 | rejected |
| N17 | `C_next` instance tampered | verifier permutation on instance 2 | rejected |
| N18 | frozen v1 5-word commitment used as v2 | verifier permutation (domain/width mismatch) | rejected |
| N19 | inactive event with no-op roots (both flags 0) | `b-type-split` | rejected |
| N19b | both flags 1 | `b-type-split` | rejected |
| N20 | tamper any of the 8 public values, reuse old proof | verifier rejects the same proof for every index 0..7 | rejected |
| extra | padding slot ≠ batch_pad | `b-slot-pad` | rejected |

Notes on coverage: N03/N04 are exercised by the same physical constraint as
N06 (the Grant write-old leaf is forced to canonical ABSENT regardless of
whether the occupying state were ACTIVE or REVOKED); the matrix has a dedicated
N06 collision case and an N01/N09 REVOKED-state case, so all distinct constraint
families required by the task are represented. The exact per-gate index in the
log is stable for this build and may shift if gates are reordered.

## Honest statement about state-tampering cases

Because IR state words are now derived from constrained constants (see
`EXP-D3-06-B-IR-GADGET-SPEC.md` §4), there is **no witness field** for a prover
to set to an arbitrary state. Attempts such as N01/N09 are therefore realized
as S0 openings whose leaf encodes the wrong state; the circuit recomputes the
canonical leaf and the first-level `cur == leaf` copy fails. This is strictly
stronger than constraining a witness state field: a prover cannot even submit a
non-canonical state.

## Real proof / verifier results (this round, same machine/profile)

| case | K | proof bytes | keygen ms | prove ms | verify ms |
| --- | --- | --- | --- | --- | --- |
| keygen (shared) | 15 | — | 14409 | — | — |
| B Grant | 15 | 7008 | — | 17922 | 280 |
| B Revoke | 15 | 7008 | — | 17963 | 283 |

N20: an honest Grant proof verifies; flipping each of the 8 instance values in
turn makes the verifier reject that same proof in all 8 cases. Seeded RNG
`StdRng::seed_from_u64(20261124)`; single release profile; single thread
configuration. These are engineering observations, not a security proof.
