# EXP-D3-06-B · IR Gadget Specification (in-circuit)

## Scope

This document specifies the in-circuit IR constraints of the single-event
Grant/Revoke IR-bound transition prototype. It records source locations in
`src/transition/d3_06_b_circuit.rs` (`TransitionCircuitB`) and the host model in
`src/transition/d3_06_b_ir.rs`. Every claim below is enforced by a Halo2 gate
or a copy constraint, not by the host builder alone; this was verified by the
MockProver negative matrix in `EXP-D3-06-B-SECURITY-TESTS.md`.

## 1. IR leaf / node encoding (must match frozen D3-06-A)

- Empty (ABSENT) leaf: `L_empty = poseidon::<3>([D3-INDEX-v1, 0, 0])`.
- Occupied leaf: `L(id, s) = poseidon::<3>([D3-INDEX-v1, full_id, state])`,
  `state ∈ {1=ACTIVE, 2=REVOKED}`.
- Internal node: `N(L,R) = poseidon::<3>([D3-INDEX-NODE-v1, L, R])`.
- Domain tags `D3-INDEX-v1` / `D3-INDEX-NODE-v1` are re-exports of frozen
  `s0_consistency_v2::d_index()` / `d_index_node()` (`d3_06_b_constants.rs`);
  no domain is redefined. Depth 4 / capacity 16.

All leaf hashes are recomputed **in-circuit** with `hash_words`; none is
accepted from the prover as a precomputed scalar.

## 2. Canonical ID decomposition and `slot = low_4(id)`

`assign_canon_id` performs a 256-bit big-endian decomposition of the full
field ID using the same canonical `< p` gate family as frozen E-R1:

- `b-root-bit-boolean`: each bit bool.
- `b-canonical-transition`: strict prefix `bit < p` via `pref`/`ltacc`, with
  the accumulated field value in `acc`.
- `b-canonical-final`: row 256 forces `less = 1` (canonical representative).

The low nibble is taken from canonical indices `BITS-4..BITS`. Index `t`
carries weight `2^(BITS-1-t)`, so nibble bit position `bpos = BITS-1-t`
(`bpos 0 = LSB`). The four `b_bit` cells at those indices are captured once
(no double-assignment) and referenced by copy constraint.

A dedicated region computes:

```
slot = Σ_{b=0..3} 2^b · bit_b
```

via gates `b-ir-slot-bit-bool` (each slot bit bool) and `b-ir-slot-bind`
(`acc_next = acc_cur + 2^b · bit_b`, rows 0..3; row 4 = final slot). The slot
bit cells are copy-equal to the canonical low-nibble cells, so a prover cannot
present a field-representation alias or an un-constrained 4-bit witness.

This satisfies the task-package requirement that `low_t(id)` be derived from
the canonical field representation with a legal range constraint, not from a
free witness.

## 3. IR opening constraints

`assign_ir_opening` recomputes a depth-4 Merkle root from a leaf cell:

- `path-dir-bool`: direction bit bool.
- `path-select`: `left=(1-dir)·cur+dir·sib`, `right=dir·cur+(1-dir)·sib`;
  the host `left`/`right`/`sib` cells are not trusted — the gate binds them.
- The `cur` cell of each level is copy-equal to the previous level's in-circuit
  node hash; level 0's `cur` is copy-equal to the recomputed leaf cell.
- `d_index_node` is a constrained constant cell (`D3-INDEX-NODE-v1`).

Direction↔slot binding: for the read opening and both write openings, each
`dir[l]` cell is copy-equal to `canon.low_bits[l]` of the corresponding full ID.
Thus the Merkle path direction is forced to equal the actual `low_4(full_id)`
bits; a mismatch (N15) is rejected by `b-path-select`/copy constraints.

## 4. State words come from constrained constants (prover cannot choose state)

A critical design point: **no IR state word is read from a prover-controlled
witness field.** All states are derived from constants through the gated mux
`o = i + f·(n−i)` with `f = is_revoke` (a boolean, type-split constrained):

| word | Grant (`rf=0`) | Revoke (`rf=1`) | construction |
| --- | --- | --- | --- |
| read state | 1 (ACTIVE) | 1 (ACTIVE) | `one_cell` constant |
| write-old id | 0 | `full_id` | mux(`zero`, `write_canon.field`, rf) |
| write-old state | 0 (ABSENT) | 1 (ACTIVE) | mux(`zero`, `one`, rf) |
| write-new state | 1 (ACTIVE) | 2 (REVOKED) | mux(`one`, `revoked_code`, rf) |

Constrained constants:
- `one_cell`: constrained `== 1` by gate `b-grant-valid-one`.
- `revoked_code`: constrained `== 2` by gate `b-const-two` (added this round).
- `zero_cell`: constrained `== 0` by construction in the constants region.

Consequences:
- The Grant ABSENT old leaf is exactly `H(D3-INDEX-v1, 0, 0)` (canonical empty),
  with id forced to 0 — a truncated-key collision cannot be relabelled ABSENT.
- A prover cannot write REVOKED as ACTIVE or vice-versa: there is no witness
  field carrying the state into a hash. The earlier draft (pre-fix) did read
  `ir_read_state`/`ir_write_*_state` from the witness; that was removed because
  it let the prover choose arbitrary state encodings.

## 5. Same-path (old/new share sibling + direction + slot)

For the IR write (and GR child / RR insert) the old and new openings each have
their own `path_dir`/`path_sib` advice cells, then for every level `l`:

```
copy_equal(new.dir[l], old.dir[l])
copy_equal(new.sib[l], old.sib[l])
```

Only the leaf cell differs between old and new. This is the circuit basis of
"all other leaves unchanged" in the induction proof of D3-05-R1; tampering with
either side's path (N12/N13/N14) is rejected by `b-path-select` + copy constraints.

## 6. Event linkage and state commitment

- Single active event: `is_grant + is_revoke = 1` (`b-type-split`), both flags
  bool (`b-bool-flag`), `event_count = 1` (`b-count`), padding slots forced to
  `batch_pad()` (`b-slot-pad`). No `pre_ok` no-op bypass exists: an inactive or
  double-active event fails `b-type-split` (N19/N19b).
- `C_prev`/`C_next` are `poseidon::<6>([D3-STATE-v2, GR, RR, IR, epoch, policy])`
  and bound to instance 0/2. The IR root cells `irprev`/`inext` participate in
  both commitments, so tampering with either instance is rejected (N16/N17),
  and the frozen v1 5-word `D3-STATE-P-v2` commitment cannot substitute (N18).
- `inext` uses the constrained constant `one_cell` as its transition flag: the
  IR root updates on **both** Grant and Revoke. (Earlier draft used the grant
  flag, which would have forced a no-op on Revoke — fixed.)

## 7. Known limits (not implemented this round)

- `low_t` binding is depth 4 / 16 slots with fail-closed collisions; no chaining.
- ID domain is `F \ {0}`; no 256-bit raw-ID→field mapping.
- S0 cross-structure consistency remains a **host-only** trust input (D3-06-A);
  it is not proven inside this circuit.
- revoker authority is inherited from E-R1's external trust assumption.
- Two-event sequencing, DENY, recursion, freshness: out of scope.

## 8. Development note (honest record)

This circuit was initially generated in a single scripted write and had never
been compiled or executed. Compilation and MockProver uncovered and we fixed:
(1) a duplicate cell assignment in canonical decomposition; (2) an unassigned
accumulator chain in the slot gadget; (3) `query_fixed` API misuse; (4) the
Grant ABSENT leaf using the wrong id; (5) dummy-branch openings not matching the
unconditionally recomputed leaves; (6) state words read from prover-controlled
witness fields; (7) the IR transition flag using the grant flag. After all fixes,
the positive cases and the full negative matrix pass. Details in the summary.
