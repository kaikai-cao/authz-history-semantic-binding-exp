# EXP-D3-03-C — Phase 4 成本测量与 A/B/C 对比

**基线**：`ecc4d06b105b047299e785e7b8e268a70a4e2cb4`
**分支**：`exp-d3-03-c`
**环境**：同一台 Windows 机器、同一 Rust 工具链、`cargo test --release`、Halo2 0.4.0 / Pallas-Vesta / Poseidon P128Pow5T3。
**计时口径**：`keygen_ms` 包含 `keygen_vk + keygen_pk`；`prove_ms` 只含 `create_proof`；`verify_ms` 不含 keygen，只测 `verify_proof`。与 A/B 既有口径一致。

---

## 1. 同轮 A/B/C 真实证明对比

在一次连续测量中依次运行 A17、B14、C08：

| 电路 | K | Proof size | Keygen | Prove | Verify |
| --- | --- | --- | --- | --- | --- |
| A（状态承诺） | 12 | 3904 B | 1519 ms | 2785 ms | 85 ms |
| B（Grant 创建 + Parent Binding） | 12 | 5696 B | 2601 ms | 3616 ms | 76 ms |
| C（DirectOnly 单撤销） | 12 | 5760 B | 2542 ms | 3507 ms | 80 ms |

原始输出：

```text
A17 K=12 proof_bytes=3904 keygen_ms=1519 prove_ms=2785 verify_ms=85
B14 K=12 proof_bytes=5696 keygen_ms=2601 prove_ms=3616 verify_ms=76
C08 K=12 proof_bytes=5760 keygen_ms=2542 prove_ms=3507 verify_ms=80
```

解读边界：

- 这些是同轮单样本墙钟数据，存在机器负载噪声；C 的 prove 时间略低于 B **不是优化结论**，不能声称 C 比 B 更快。
- 可稳定观察的是 proof size：A 3904 B → B 5696 B → C 5760 B；C 相对 B 增加 64 B，符合新增 RR opening/更新与 revoke 事件约束。
- A 的早期冻结记录 `3904B / 1490ms / 2737ms / 76ms` 保留不改；本表只用于同轮增量比较。

---

## 2. K 变体测量

`tests/d3_03_c_bench.rs` 以 ignored test 形式保留，可显式运行：

```bash
cargo test --release --test d3_03_c_bench -- --ignored --nocapture
```

实测：

```text
C_BENCH k=11 result=PASS proof_bytes=5696 keygen_ms=1523 prove_ms=2119 verify_ms=45 verify_ok=true
C_BENCH k=12 result=PASS proof_bytes=5760 keygen_ms=2698 prove_ms=3682 verify_ms=80 verify_ok=true
C_BENCH k=13 result=PASS proof_bytes=5824 keygen_ms=4980 prove_ms=6689 verify_ms=143 verify_ok=true
```

决策：** shipped K 仍为 12**。K=11 虽可通过当前测试，但不以缩小安全余量换取速度；K=13 成本明显更高，没有收益证据。K=12 是工程决策，不是原始设计参数，也不是逐门精确规模推导的结果。

---

## 3. 结构指标（不是约束数）

按源码静态计数（gate 名来自 `meta.selector()` / `meta.advice_column()`）：

| 指标 | A | B | C |
| --- | --- | --- | --- |
| Selector family | 9 | 19 | 19 |
| Advice columns (`meta.advice_column()` 次数) | 10 | 21 | 21 |
| 核心 transition 源码行数 | 990 | 1475 | 1290 |
| 最大 K（本实验冻结/沿用） | 12 | 12 | 12 |

说明：

- B 早期报告写“selector 9→20”；本次按实际 `meta.selector()` 复核为 **19**，以源码计数为准，不在 C 中修改 B 已提交报告。
- C 与 B selector 数同为 19，是因为移除了 B 的 scope/prefix 专用门，新增了 `epoch-plus-one` 与 `event-count-one`。
- 行数与 selector/advice 列数只描述代码结构，**不是约束数量，也不是电路规模**。本阶段没有逐门约束统计工具，明确记为“未精确统计”。

核心行数构成：

```text
A = constants.rs 187 + types.rs 253 + circuit.rs 550 = 990
B = b_constants.rs 72 + b_types.rs 306 + b_circuit.rs 1097 = 1475
C = c_constants.rs 44 + c_types.rs 235 + c_circuit.rs 1011 = 1290
```

---

## 4. 测试成本

完整 release 套件 128 tests 全绿。单次证明测试耗时（同一轮不同二进制）：

```text
A proof tests 2 passed / 16.30s
B proof tests 2 passed / 19.12s
C proof tests 2 passed / 18.82s
```

MockProver 矩阵耗时：

```text
A mock 16 tests / 0.13s
B mock 17 tests / 0.27s
C mock 26 tests / 0.42s
```

---

## 5. 诚实边界

- 未做逐门约束数、实际使用行数或 prover memory 统计。
- 未做多次采样均值/方差；所有 ms 数据为单样本墙钟时间。
- 未尝试更小 K 的测试覆盖削减；K=11 可通过只是记录，不改变 shipped 参数。
- 不能从本表推出“C 比 B 快”或“授权系统端到端性能已达标”等结论。
