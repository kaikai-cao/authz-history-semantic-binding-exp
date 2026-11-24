# EXP-D3-06-B · Cost Attribution and Same-Machine Comparison

## Measurement protocol

- File: `tests/d3_06_b_cost.rs::cost_er1_vs_b_same_machine`.
- One Rust `release` profile (`opt-level=3`), one machine, one seed, one thread
  configuration. Both circuits use K=15 (the frozen E-R1 K and B's chosen K).
- Each circuit has a single keygen shared by its Grant and Revoke measurements.
- E-R1 single Grant = Grant + Padding (frozen two-slot circuit); E-R1 single
  Revoke = Revoke + Padding. B = genuine single-event dual-branch circuit.
- **Permutation counts below are source call-site counts, not measured times.**
  A drop in permutation count must not be read as a proportional drop in
  proving time (cf. EXP-D3-03-E-R3 attribution).

## Measured results (single Grant / single Revoke, same run)

| metric | E-R1 Grant | B Grant | E-R1 Revoke | B Revoke |
| --- | --- | --- | --- | --- |
| K | 15 | 15 | 15 | 15 |
| proof size (B) | 8160 | 7008 | 8160 | 7008 |
| keygen (ms, shared) | 17579 | 14409 | 17579 | 14409 |
| prove (ms) | 20804 | 17922 | 20909 | 17963 |
| verify (ms) | 283 | 280 | 283 | 283 |

Observations:
- B proof is **1152 bytes smaller** (one instance commit's worth of width
  difference plus a smaller circuit).
- B prove is roughly **13–14% faster** in this single-event workload. This is
  consistent with removing the full-tree scan but is **not** an equal-ratio
  translation of the permutation drop: Halo2 cost also depends on region
  layout, copy constraints, the 256-bit canonical decompositions (4 of them:
  GR/RR root decode + 2 IR IDs), and fixed overhead.
- keygen and verify differences are modest; verify is essentially unchanged.

## Circuit metadata (Halo2 `pinned()` counters)

| counter | E-R1 (frozen R3) | B (this round) |
| --- | --- | --- |
| fixed columns | 9 | 10 |
| advice columns | 39 | 32 |
| instance columns | 1 (8 values) | 1 (8 values) |
| selectors | 30 | 27 |

B uses 7 fewer advice columns and 3 fewer selectors (the E-R1 scan family is
absent); one extra fixed column (the `2^b` slot weights / const-two gate).
Constraint-polynomial and gate-family counts are source-level statistics here,
not probe fields; no claim of exact equality with R3's flattened count is made.

## Poseidon permutation attribution

E-R1 frozen R3 measurement: **505** permutations total = **344** full-tree scan
(GR leaf 160 + RR leaf 64 + root rebuild 120) + 161 baseline. The 344 figure is
the scan the IR design aims to remove.

B single-event circuit call sites (each `hash_words` = 1 permutation; opening
node hashes run 4 levels per opening):

| component | call sites | permutations |
| --- | --- | --- |
| GR/RR leaf hashes (parent, child, target, revoke) | 4 | 4 |
| GR/RR opening node hashes (6 openings × 4 levels) | 24 | 24 |
| IR leaf hashes (read, write-old, write-new) | 3 | 3 |
| IR opening node hashes (3 openings × 4 levels) | 12 | 12 |
| state commitments C_prev / C_next | 2 | 2 |
| event commitments (grant, revoke) + D_E | 3 | 3 |
| **total (single instance, both branches assigned)** | **48** | **48** |

The **IR-specific addition** is 15 permutations (3 IR leaf + 12 IR node). The
**344 full-tree scan permutations are gone**. The 48 total is not directly
comparable to E-R1's 505 because E-R1's number covers its two-slot circuit with
scanning; the like-for-like statement is: removing the scan removes 344
permutations, and the IR local openings add ~15 per event.

Note: GG/GR/RR two-event combinations are out of scope this round. The
per-event IR opening cost (≈15) must be re-measured per two-event combination in
EXP-D3-06-C; a Grant+Revoke batch is not the worst case for every combination.

## Decision on performance claim

No claim that IR beats E-R1 at scale is made. The single-event prototype has a
smaller proof and modestly faster prove under identical conditions, which is a
positive engineering signal, but:
- the depth-4 / 16-slot IR has fail-closed collisions and no production capacity;
- two-event sequencing and its added IR openings are not measured;
- S0 cross-structure checking is host-only and external anchoring is absent.

The result is frozen as engineering feasibility data for EXP-D3-06-C, not as a
performance breakthrough.
