# EXP-D3-03-E-R2 执行报告

**任务**：Initial State Completeness and Invariant Boundary
**基线**：`edf4b06401f0431a85978904e2ccae1cccc5d076`（`exp-d3-03-e-r1`）
**分支**：`exp-d3-03-e-r2`
**范围**：只处理两个问题——支持包含历史撤销记录的 S0；明确并验证初始状态唯一性不变量的适用边界。不优化 Poseidon、不引入新 Merkle 结构、不修改 A/B/C/D/E、不增加事件数、不改变 8 个 public instances。

---

## 1. Git 与交付

新增文件：

```text
src/transition/e_r2_types.rs
tests/d3_03_e_r2_mock.rs
tests/d3_03_e_r2_proof.rs
docs/EXP-D3-03-E-R2-INVARIANT-ANALYSIS.md
docs/EXP-D3-03-E-R2-SUMMARY.md
```

`src/transition/mod.rs` 仅新增 R2 模块注册与 re-export。E-R1 的五个 `e_r1_*.rs` 文件、E-R1 固定向量、A/B/C/D/E 电路与 `src/reference/mixed_event_state.rs` 均零改。

---

## 2. 初始 RR preimage 接口

E-R1 builder 只接收 `initial_rr_slots: [F; TREE_CAPACITY]`，但构造扫描 witness 时 `rr_records` 初始为空；`scan_from_slots` 虽然接收 slot 数组，却不能从叶子哈希恢复 `RevokeFieldsC` preimage。因此 S0 若已有历史撤销，扫描根无法与公开根一致。

R2 新增 `InitialRrState` 与 `build_scenario_r2`：

- `InitialRrState::from_preimages(&[(usize, RevokeFieldsC)])`：从完整记录重建每个 RR 叶子与初始 RR root；
- `InitialRrState::from_slots([F; TREE_CAPACITY])`：发现任何非零槽位但没有 preimage 时返回 `MissingPreimage(slot)`，不再静默生成必然失败的 witness；
- `build_scenario_r2`：用 `revoke_leaf_c` + `SparseTreeB` 重建 root，比较公开 `rr_prev_be` 解码值，并按两事件顺序重建每个事件输入的 RR 全树扫描；
- 初始 GR/RR 的重复槽位、重复 ID、越界槽位在 builder 侧被显式拒绝。

R2 witness 类型 `TransitionWitnessR2` 是 E-R1 witness 的类型别名；电路关系、public instances 和固定向量不变。

---

## 3. R2-01–R2-06 测试

| 编号 | 场景 | 预期 | 实际 |
| --- | --- | --- | --- |
| R2-01 | S0 已有 `Revoke(A)`，`Grant(B, Parent=A)` | Reject | Reject；命中 `scan-id-neq @ parent not revoked in RR` |
| R2-02 | S0 已有 `Revoke(A)`，`Grant(B, Parent=C)` | Pass | Pass |
| R2-03 | S0 已有 `Revoke(A)`，再次 `Revoke(A)` | Reject | Reject；命中 `scan-id-neq @ revoke id global unique in RR` |
| R2-04 | S0 已有多个不同撤销记录 | 正确重建 RR root | `rr_prev_be` 等于重建 root，MockProver 通过 |
| R2-05 | RR preimage 与提供的 root 不匹配 | Reject | Reject；命中 `parent scan root binds current RR` 与 instance permutation |
| R2-06 | RR 中相同 ID 被放入两个槽位 | 明确处理初始不变量 | builder 返回 `R2Error::DuplicateId(0,1)` |

额外测试：hash-only 初始 RR（非零 slot 但无 preimage）返回 `R2Error::MissingPreimage(5)`。

**Mock 测试**：`tests/d3_03_e_r2_mock.rs` = **7 passed / 0 failed**。

---

## 4. 真实 proof

新增 `tests/d3_03_e_r2_proof.rs`，用 S0 已含 `Revoke(A)`、事件为 `Grant(B, Parent=C)` 的历史撤销场景做真实证明：

```text
R2-HISTORICAL-RR K=15 proof_bytes=8160 prove_ms=32987 verify_ms=484
```

verifier 接受。这个结果说明 E-R1 冻结电路可直接验证 R2 builder 产生的历史 RR witness，无需修改电路或 public instances。

---

## 5. 初始不变量边界

采用**方案 A：可信初始状态锚定**：

- S0 唯一性由 genesis 或此前已验证状态转换证明链保证；
- R2 builder 在 host 侧拒绝重复槽位/重复 ID/hash-only 输入；
- 电路继续只证明“新 ID 不等于当前扫描中的任何叶子 ID”，即状态转换不引入新重复。

不采用方案 B（电路内 pairwise uniqueness）作为本轮默认：新增完整分析见 `docs/EXP-D3-03-E-R2-INVARIANT-ANALYSIS.md`。最小实验得到 pairwise 比较数：n=2→1、n=4→6、n=8→28、n=16→120；若 GR/RR 都做，满 16 槽最多 240 对。本轮未实现该电路，不声称其 K/prove 成本。

**严谨结论**：

> 在 S0 满足 GR/RR 初始唯一性不变量、且 R2 witness 完整覆盖当前状态 preimage 的前提下，E-R1/E-R2 对最多两个顺序事件约束了 Parent 撤销有效性、Grant ID 不重复和 Revoke ID 不重复。

---

## 6. 验收

- 8 个 public instances：保持不变。
- A/B/C/D/E 与 E-R1 电路/固定向量：零改。
- `cargo fmt --check`：通过。
- `cargo test --release`：**234 passed / 0 failed / 3 ignored**。
- `git diff --check`：通过。
- 提交与 SHA：见本轮最终 Git 记录。

---

## 7. 剩余限制

- 初始状态唯一性仍是外部前提；若 S0 来自任意外部 root，需后续方案 B 或独立初始状态证明。
- `key_field` 的 SHA-256→F 映射单射性仍是外部信任。
- 仍不证明 ALLOW/DENY、完整历史、canonical slot 规范性、Bridge/checkpoint、新鲜性、Cascade、递归、三事件或跨 VK 重放。
- 本轮不是成本优化；E-R1 全树扫描的高 proving cost 仍是下一阶段研究对象。

---

## 8. 最终判断

E-R2 达到本轮目标：**初始 RR preimage 缺口已补齐，初始状态唯一性的验证责任已明确记录，E-R1 电路未被削弱或改写。** 可把 E-R1/E-R2 组合视为带明确初始状态前提的语义完整基线，并进入下一阶段成本优化研究。
