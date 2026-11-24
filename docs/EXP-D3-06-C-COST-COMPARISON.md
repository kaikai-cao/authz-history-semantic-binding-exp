# EXP-D3-06-C — Two-Event Cost Comparison

## 1. Measurement protocol

| Item | Value |
| --- | --- |
| Machine | same Windows host for all measurements |
| Build | Rust `--release`, repository profile unchanged |
| Seed | `20261124` |
| Threading | process default, unchanged across all runs |
| E-R1 keygen | one keygen shared by GG/GR/RR |
| C keygen | one keygen shared by GG/GR/RR |
| Source | `tests/d3_06_c_cost.rs` |

All six proofs verified. The numbers below are engineering observations. They are **not** a claim that permutation-count reductions translate proportionally into proving time.

## 2. Measured results

### E-R1 (frozen full-scan baseline, two events)

| Combination | K | Proof bytes | Keygen ms | Prove ms | Verify ms |
| --- | --- | --- | --- | --- | --- |
| GG | 15 | 8160 | 17255 | 20638 | 280 |
| GR | 15 | 8160 | — | 20528 | 281 |
| RR | 15 | 8160 | — | 20662 | 276 |

### D3-06-C (IR-bound sequential chain, two events)

| Combination | K | Proof bytes | Keygen ms | Prove ms | Verify ms |
| --- | --- | --- | --- | --- | --- |
| GG | 16 | 7072 | 28550 | 35311 | 526 |
| GR | 16 | 7072 | — | 35215 | 518 |
| RR | 16 | 7072 | — | 35199 | 529 |

A separate real-proof roundtrip run recorded C keygen 31659 ms and prove times 43756 / 35823 / 35686 ms for GG / GR / RR; the difference from the table above is run-to-run variance. Proof size was stable at 7072 bytes.

## 3. Interpretation

- C proof size is 1088 bytes smaller than E-R1 (7072 vs 8160).
- C proving time is higher in this two-event configuration: roughly 35–35.3 s vs 20.5–20.7 s.
- C keygen is also higher and requires `K=16` rather than E-R1's `K=15`.
- C verification is slower (about 518–529 ms vs 276–281 ms).

Therefore the correct conclusion is:

> The two-event IR-bound chain removes full-tree scanning and reduces proof size, but under the current layout and K it does not outperform the frozen E-R1 baseline in proving time.

This is consistent with the stage constraint not to pre-announce performance superiority. The result must not be spun as a general win.

## 4. Poseidon permutation attribution

Static call-count attribution from `d3_06_c_circuit.rs`:

| Component | Calls per event |
| --- | --- |
| GR/RR node paths | 24 |
| IR node paths | 12 |
| Leaf hashes (grant/revoke/IR read/write) | 7 |
| Event commitments | 2 |
| **Event total** | **45** |

Two events give 90 event-level calls. Adding `C_prev`, `C_next` and `D_E` gives:

```text
D3-06-C total = 93 permutation calls
GG = 93
GR = 93
RR = 93
```

The counts are identical across combinations because both branches are assigned unconditionally; only the gating flags and witness values differ.

For E-R1, the frozen attribution from E-R3 is:

```text
full-tree scans = 344
E baseline       = 161
E-R1 total       = 505
```

Thus C removes the 344 scan calls and adds the IR-local opening cost (15 per event in the earlier B attribution). But call count is not time: the measured C proving time is higher, likely affected by K, region count, copy constraints and layout.

## 5. Layout metadata

Halo2 `pinned()` metadata for the C config:

```text
fixed=10
advice=32
instance=1 column (8 values)
selectors=27
K=16
max_rows=65536
gate_families_source=22
```

For comparison, D3-06-B used `fixed=10, advice=32, selectors=27, K=15`. The C circuit reuses the same column/selector surface; the increased row requirement comes from assigning the same gadget set twice and chaining roots.

## 6. Cost limitation

No performance claim is made about:

- larger batches;
- larger IR trees;
- different Halo2 layouts or floor planners;
- hardware/thread tuning;
- real deployment proving systems.

The only supported statement is the same-machine table above.
