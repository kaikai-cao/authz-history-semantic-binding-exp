# EXP-D3-03-E-R1 — Phase 6 成本消融：E vs E-R1

**基线**：`56342803d492bb8aaa4ffd44b5586947fd7d0d0c`
**分支**：`exp-d3-03-e-r1`
**测量文件**：`tests/d3_03_e_r1_bench.rs`（ignored）
**运行**：

```bash
RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 cargo test --release \
  --test d3_03_e_r1_bench -- --ignored --nocapture
```

**环境**：与 E 阶段同一 Windows 11 机器，Intel i7-14700（20 核/28 线程），约 31.7 GiB RAM；`rustc 1.98.1` / `cargo 1.98.1`，`x86_64-pc-windows-gnu`；Halo2 0.4 / Pallas-Vesta。固定 1 线程；每对象 3 次完整 keygen+prove+verify，取中位数；同种子 `20261124`。

---

## 1. 同轮中位数对比

| 电路 | K | Proof | Keygen | Prove | Verify |
| --- | --- | --- | --- | --- | --- |
| E-GG | 13 | 7040 B | 6032 ms | 7938 ms | 137 ms |
| E-GR | 13 | 7040 B | 6227 ms | 7590 ms | 133 ms |
| E-RR | 13 | 7040 B | 6110 ms | 7758 ms | 134 ms |
| R1-GG | 15 | 8160 B | 26118 ms | 30998 ms | 456 ms |
| R1-GR | 15 | 8160 B | 25991 ms | 35016 ms | 437 ms |
| R1-RR | 15 | 8160 B | 27784 ms | 30102 ms | 421 ms |

上表为完整日志的中位数，不是“第一个样本”或人工挑选的快样本。E 与 R1 在同轮、同机、同线程配置下测量，不把 A/B/C/E 历史数据冒充本轮数据。

最终中位数输出：

```text
E_R1_MEDIAN circuit=E-GG  k=13 bytes=7040 keygen_ms=6032  prove_ms=7938  verify_ms=137
E_R1_MEDIAN circuit=E-GR  k=13 bytes=7040 keygen_ms=6227  prove_ms=7590  verify_ms=133
E_R1_MEDIAN circuit=E-RR  k=13 bytes=7040 keygen_ms=6110  prove_ms=7758  verify_ms=134
E_R1_MEDIAN circuit=R1-GG k=15 bytes=8160 keygen_ms=26118 prove_ms=30998 verify_ms=456
E_R1_MEDIAN circuit=R1-GR k=15 bytes=8160 keygen_ms=25991 prove_ms=35016 verify_ms=437
E_R1_MEDIAN circuit=R1-RR k=15 bytes=8160 keygen_ms=27784 prove_ms=30102 verify_ms=421
```

样本输出节选（前 17 行；完整 18 个样本行以最终运行日志为准）：

```text
E_R1_BENCH sample=1 circuit=E-GG k=13 bytes=7040 keygen_ms=4459 prove_ms=8586 verify_ms=165
E_R1_BENCH sample=1 circuit=E-GR k=13 bytes=7040 keygen_ms=6228 prove_ms=7582 verify_ms=131
E_R1_BENCH sample=1 circuit=E-RR k=13 bytes=7040 keygen_ms=6110 prove_ms=7758 verify_ms=156
E_R1_BENCH sample=2 circuit=E-GG k=13 bytes=7040 keygen_ms=6045 prove_ms=7938 verify_ms=137
E_R1_BENCH sample=2 circuit=E-GR k=13 bytes=7040 keygen_ms=6227 prove_ms=7590 verify_ms=133
E_R1_BENCH sample=2 circuit=E-RR k=13 bytes=7040 keygen_ms=6366 prove_ms=8014 verify_ms=134
E_R1_BENCH sample=3 circuit=E-GG k=13 bytes=7040 keygen_ms=6032 prove_ms=7554 verify_ms=133
E_R1_BENCH sample=3 circuit=E-GR k=13 bytes=7040 keygen_ms=6031 prove_ms=7604 verify_ms=134
E_R1_BENCH sample=3 circuit=E-RR k=13 bytes=7040 keygen_ms=6101 prove_ms=7692 verify_ms=133
E_R1_BENCH sample=1 circuit=R1-GG k=15 bytes=8160 keygen_ms=19894 prove_ms=28259 verify_ms=456
E_R1_BENCH sample=1 circuit=R1-GR k=15 bytes=8160 keygen_ms=25991 prove_ms=30420 verify_ms=437
E_R1_BENCH sample=1 circuit=R1-RR k=15 bytes=8160 keygen_ms=25587 prove_ms=30102 verify_ms=421
E_R1_BENCH sample=2 circuit=R1-GG k=15 bytes=8160 keygen_ms=26118 prove_ms=30998 verify_ms=437
E_R1_BENCH sample=2 circuit=R1-GR k=15 bytes=8160 keygen_ms=16501 prove_ms=35079 verify_ms=432
E_R1_BENCH sample=2 circuit=R1-RR k=15 bytes=8160 keygen_ms=27852 prove_ms=33247 verify_ms=509
E_R1_BENCH sample=3 circuit=R1-GG k=15 bytes=8160 keygen_ms=28688 prove_ms=35049 verify_ms=520
E_R1_BENCH sample=3 circuit=R1-GR k=15 bytes=8160 keygen_ms=30798 prove_ms=35016 verify_ms=523
```

---

## 2. 开销来源

| 指标 | E | E-R1 | 增量 |
| --- | --- | --- | --- |
| K | 13 | 15 | +2 |
| Selector family | 24 | 27 | +3（`q_scan_bool`, `q_scan_leaf`, `q_scan_neq`） |
| Advice columns | 30 | 37 | +7（scan_fl/lv/hs/bf/ia/ib/inv） |
| Gate family | 25 | 28 | +3 |
| 核心源码行数 | 1948 | 2383（3 个 R1 核心文件） | +435 |
| Proof size | 7040 B | 8160 B | +1120 B |
| Prove（中位，GR） | 7590 ms | 35016 ms | 约 4.6× |

全树扫描的结构开销：

- 每事件 GR 扫描：最多 16 次 9 词 Poseidon（叶子 preimage）+ 15 次 2 词 Poseidon（内部节点）；
- 每事件 RR 扫描：最多 16 次 4 词 Poseidon + 15 次 2 词 Poseidon；
- 两个事件最坏共 124 次 Poseidon hash + 64 次 ID 不等约束（每约束一个逆元 witness）；
- 每次扫描 1 次根 gated-eq（RR 因 Parent 检查额外 1 次）。

这些是结构估算，不是逐门约束数。

---

## 3. 诚实边界

- 未逐门统计约束数、实际使用行数、内存；未做多线程对比。
- R1 的 keygen/prove 数据波动较大（样本间从 16.5s 到 30.8s），受机器负载影响；不声称精确倍率，只记录量级。
- K=15 是实测最小可行值（K=13/14 均 `NotEnoughRowsAvailable`），不是原始设计参数。
- 性能代价是真实的：语义完整性（ID 全局唯一性）在此构造下需要约 4–5× proving time 与 K+2；本轮不优化。
- A/B/C/E 历史数据不冒充同轮数据；上表 E 数据为本轮同轮实测（数值与 E 阶段固定线程数据略有差异，属机器负载噪声）。

---

## 4. 结论

全树扫描可作为语义完整的基线构造：它严格表达 D 状态机的 ID 级唯一性/有效性语义，代价明确（K+2、proof +1120 B、prove 约 4–5×）。这为后续研究提供了真实优化起点：在保持 ID 唯一性与撤销语义前提下减少状态证明开销，而不是削弱语义换性能。
