# EXP-D3-03-E-R3 — Final Summary

## 1. Git 与基线

- 仓库：`kaikai-cao/authz-history-semantic-binding-exp`
- 基线 commit：`423da783c9e94f7f4b31d393ac232db733807dea`（`exp-d3-03-e-r2`）
- 工作分支：`exp-d3-03-e-r3`
- Phase 0 核验：HEAD=基线、工作区 clean、本地/远端 E-R2 一致；E-R1/E-R2 文档与测试齐全；K=15、树容量 16、深度 4、事件≤2、8 public instances 均确认
- 冻结边界：A/B/C/D/E、E-R1/E-R2 实现与固定向量零改；8 public instances 不变；事件数不变

## 2. 本轮性质与范围

成本剖析 + 候选构造设计比较 + 最小可行性实验。**不优化 Poseidon、不引入新 Merkle 结构、不修改任何冻结电路、不把未实现的候选写成已验证优化。**

## 3. Phase 1：全树扫描成本归因

四类口径严格区分（Poseidon permutation ≠ 约束数 ≠ 行数 ≠ proving time）。详见 `EXP-D3-03-E-R3-COST-ATTRIBUTION.md`。

**Halo2 结构元数据（运行时精确，经 `pinned()` 官方视图）：**

| 指标 | 值 | 数据来源 |
| --- | --- | --- |
| fixed columns | 9 | 运行时 `CircuitMeta` 探针 |
| advice columns | 39 | 运行时 `CircuitMeta` 探针 |
| instance columns | 1（8 个 public 值占 row 0..7） | 运行时 `CircuitMeta` 探针 |
| selectors | 30（源码显式 27 + Poseidon 内部 3） | 运行时 `CircuitMeta` 探针 |
| constraint polynomials | 43 | 运行时 `CircuitMeta` 探针 |
| gate families | 28 | 源码静态分析（`meta.create_gate` 计数），非探针字段 |
| degree | 3 | 源码静态分析（`scan-id-neq` 三次项），非探针字段 |

**Poseidon permutation 归因（共 505）：**

| 类别 | permutations | 占比 |
| --- | --- | --- |
| GR scan leaf（2事件×16槽×5） | 160 | 31.7% |
| RR scan leaf（2事件×16槽×2） | 64 | 12.7% |
| Merkle 内部节点重建（2事件×2树×15节点×2） | 120 | 23.8% |
| **全树扫描小计** | **344** | **68.1%** |
| E 基线（openings 96 + leaves 34 + commitments 16 + batch 15） | 161 | 31.9% |

**诚实边界**：344/505=68.1% 是 permutation **数量占比**，不是 proving time 占比；未做逐门/逐 region 约束密度画像，不断言 Poseidon 占总时间的 X%。数据由 `tests/d3_03_e_r3_attrib.rs`（Halo2 元数据）、`tests/d3_03_e_r3_cost_model.rs`（permutation 模型）可复现打印。

## 4. Phase 2：四类候选构造比较

详见 `EXP-D3-03-E-R3-CONSTRUCTION-COMPARISON.md`。

| 候选 | 结论 |
| --- | --- |
| A 全树扫描 | 语义完整基线，保留不改 |
| B Poseidon Canonical Slot | 探测完整性最坏退回 O16；与 D3-01 SHA-256 `D3-SLOT-v1` 不兼容、需新 slot 版本；host 算 slot 不可信。理论可行但成本收益不明确，不实现 |
| C 独立 ID 索引树 | 理论最有希望（O(log n) 局部非成员），但需新增索引状态根与一致性约束；公开接口可新增实例或并入 `C_prev/C_next`（不必然增加 8 值数量，但需承诺版本升级）；R3 仅 BTreeSet host 模型、非密码学索引树，不接电路 |
| D 排序 ID 集合 | 相邻关系证明最坏退回 O16；双集合顺序维护复杂；成本收益不明确，不实现 |

## 5. Phase 3：安全分析与成本模型

详见 `EXP-D3-03-E-R3-SECURITY-ANALYSIS.md`。十维度模型逐候选填写。**严格区分**：
- "理论一次 opening"（C/D 设计动机，依赖额外状态承诺，未验证）
- "已 Halo2 实现并测量"（仅 A/E-R1）

所有候选不得用 host 槽位/索引断言替代电路内 ID 关系证明，否则退化为 E-R1 已修复的"witness 指定位置"漏洞。S0 唯一性沿用 E-R2 方案 A（可信锚定前置）。

## 6. Phase 4：最小可行性实验（host ONLY）

测试 `tests/d3_03_e_r3_feasibility.rs`，7/7 通过。独立 Rust host 模型，覆盖 16 槽、不同 ID、冲突 ID、已存在 ID、已撤销 ID、非空初始状态、第二事件更新。

**候选 B（canonical slot 探测）：**
- 8 个不同 ID 最大探测 3 次
- 碰撞 ID (6,7) 同起槽 4，第二个位移到槽 5（2 次探测），未被覆盖
- 已存在 ID 被 `duplicate-id` 拒绝
- 16 个同槽 ID 填满后，第 17 个探测全部 16 槽并报 `tree-full`

→ 验证 Phase 2 论断：B 最坏情况仍需 O16 探测，无渐进优势。

**候选 C（BTreeSet host 模型，非密码学索引树）：**
- 用 `BTreeSet<F>` + 二分搜索模拟；非空 S0（15 个 ID）非成员检查 4 步（=log2 16）vs 全扫描 16 槽
- 该 4 步是排序集合比较次数，**未实现** Poseidon Merkle 索引树、索引 root、电路内 non-membership opening 或索引-GR/RR 一致性约束
- Parent 已撤销被正确拒绝、Parent 活跃可派生、重复 Revoke 在第二事件被检测
- 第二事件能看到事件 0 的插入（状态链在 host 层自洽）

→ C 的逻辑方向在 host 层成立，但这是排序集合模型，**不构成密码学结构验证**；需额外状态根与双树一致性，未接入 Halo2、未测量证明成本。真正的可认证索引结构对比留待 EXP-D3-04。

## 7. 验收检查

- `cargo fmt --check`：通过
- `cargo test --release`：**244 passed / 0 failed / 3 ignored**（E-R2 为 234；R3 新增 10 个测试 = attrib 1 + cost_model 1 + feasibility 7 + stats 模块内 1）
- `git diff --check`：通过
- 新增文件：`e_r3_stats.rs`、`d3_03_e_r3_attrib.rs`、`d3_03_e_r3_cost_model.rs`、`d3_03_e_r3_feasibility.rs`、4 份 R3 文档；`mod.rs` 仅 1 行模块注册
- 8 public instances、事件数、A/B/C/D/E、E-R1/E-R2 零改

## 8. 最终结论（三选一）

**结论落入第 2 类：理论可行但成本收益不明确——保留设计，暂不替换。**

- 候选 C（独立 ID 索引树）是理论上最有希望降低全树扫描成本的方向，但需新增索引状态根与一致性约束；公开接口可新增实例或并入 `C_prev/C_next`（不必然增加 8 个 public 值数量，但需承诺语义/域分离版本升级），超出本轮冻结边界。R3 的"host 层非成员 4 步 vs 16 槽"准确说是 `BTreeSet` 排序集合二分搜索比较次数，**不是密码学索引树的 opening 成本**；"一次 opening 更便宜"未经 Halo2 实测。
- 候选 B/D 在证明无跳过/相邻上最坏退回 O16，成本收益不明确。
- 候选 A（E-R1 全树扫描）继续作为语义完整基线保留，无需回滚或替换。

**主线建议**：E-R1/E-R2 已构成带明确初始状态前提的语义完整基线。后续若要真正替换全树扫描，需进入独立优化原型阶段，并先解除"8 public instances 冻结"这一硬约束以评估候选 C 的索引承诺方案。在此之前不应把任何候选写成已验证优化。
