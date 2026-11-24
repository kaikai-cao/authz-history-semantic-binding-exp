# EXP-D3-03-E-R3 — Phase 3: Candidate Cost Model & Security Analysis

## 0.  ten-dimension cost model

Per candidate, ten required dimensions. "理论" = design-level claim; "已测量" = Halo2 implementation + benchmark in this repo. Nothing is marked measured unless a test exists.

| 维度 | A 全树扫描（E-R1） | B Canonical Slot | C ID 索引树 | D 排序集合 |
| --- | --- | --- | --- | --- |
| 唯一性 | 已测量：完整 F 扫描，跨槽重复命中 `scan-id-neq` | 理论：需证 `slot=H(id)` + 探测完整 | 理论：索引 non-membership | 理论：前驱<新<后继 + 无跳槽 |
| 撤销（Parent） | 已测量：RR 扫描 `id!=parent.id` | 理论：RR 索引 non-membership | 理论：RR 索引 non-membership | 理论：RR 有序集查找 |
| 插入（新 Grant/Revoke） | 已测量：空槽 + 全树重算 root | 探测落点 + 更新 root | 主树 + 索引树双更新 | 有序插入 + 元素移动 |
| 历史状态 S0 | 已测量（E-R2）：preimage 重建 + host 不变量拒绝 | 需可信 slot 布局 S0 | 需可信索引根 S0 | 需可信排序 S0 |
| 多事件绑定 | 已测量：event0 out = event1 in（q_state + copy） | 需保留 | 需保留 | 需保留 |
| 证明大小 | 已测量 8160 B | 预计 ≥ A（探测约束 + SHA/Poseidon slot） | 预计新增索引 opening，未测 | 预计新增比较器，未测 |
| Prove 主要成本 | 已测量：344 扫描 perm 主导 | 探测路径 + slot hash | 索引 opening + 双树一致性 | 排序比较 + 移动约束 |
| Verify | 已测量 437 ms（GR） | 预计相近或略增 | 需验索引根 → 增加 | 预计相近 |
| 信任前提 | S0 唯一性前置 + key_field 单射 | 额外：slot 规则版本、探测完整 | 额外：索引根可信、双树一致 | 额外：排序不变量可信 |
| Public instances 兼容 | 8 值不变 | 8 值不变（但需新 slot 规则外部锚定） | **需新增索引根 → 破坏 8 值冻结** | 8 值不变 |

## 7. 严格区分：理论 opening vs Halo2 实测

本轮必须区分两类陈述（用户明确要求）：

- **"理论上只需一次 opening"**：候选 C/D 的设计动机，即"若维护了索引/排序，则非成员证明可用局部 opening 替代全树扫描"。这是**设计层推断**，依赖额外状态承诺与电路实现，**本轮未验证**。
- **"已在 Halo2 中实现并测量"**：仅候选 A（E-R1）。E-R1 是全树扫描，单事件 16 叶 + 15 内部节点 + 3 类 scan gate，实测 505 permutations、K=15、8160 B、GR prove 35016 ms。

任何把 C/D 的"一次 opening"写成已实现优化的陈述都是错误的。Phase 4 的最小实验只在 **host 层** 验证索引/排序结构的逻辑可行性，不产出可替换 E-R1 的电路。

## 8. 安全性逐项分析

### 8.1 不削弱语义的要求

所有候选必须满足：完整 F 字段 ID 比较（非截断前缀）、Parent 对当前 RR 检查、Revoke 目标对当前 RR 检查、两事件状态链。任何用 host 计算槽位/索引而不在电路内证明与 ID 关系的做法，都会退化回 E-R1 已修复的"witness 指定位置"漏洞。

### 8.2 初始状态不变量（沿用 E-R2 方案 A）

E-R2 已确立：S0 的 GR/RR 唯一性由可信 genesis 或已验证状态转换链保证，host 检查只拒绝明显非法输入。候选 B/C/D 各自引入新的初始结构（slot 布局 / 索引根 / 排序），都需要对应的可信锚定前提，不能声称电路独立验证任意 S0。

### 8.3 外部信任不因候选而消失

`key_field` 的 SHA-256→F 单射性、canonical slot 分配、Bridge/checkpoint、执行时新鲜性、ALLOW/DENY、完整历史、Cascade、递归——这些在 E-R1/E-R2 是外部信任或非目标，候选构造不自动解决。

### 8.4 冻结边界

A/B/C/D/E 五个历史阶段、E-R1/E-R2 实现与固定向量、8 public instances、事件数上限 2 均为本轮硬约束。候选 C 需要新增 public instance（索引根），**本轮不可实现**；只能作为独立原型阶段的候选。

## 9. 本轮结论（Phase 3）

- 候选 A 是唯一"已测量"构造，作为语义完整基线保留。
- 候选 C（ID 索引树）理论上最有希望降低 permutation 数，但**需要新增 public instance 与双树一致性约束**，触及冻结边界，本轮不能接入电路；其"一次 opening"优势未经 Halo2 验证。
- 候选 B/D 在"证明无跳过/相邻"上最坏仍退回 O(16) 扫描，且 B 引入 slot 版本冲突、D 引入复杂顺序维护，成本收益不明确。
- 因此在**本轮冻结边界内**，没有候选能替换全树扫描；结论落入三类中的第 2 类："理论可行但成本收益不明确——保留设计，暂不替换"。真正的替代需进入独立原型阶段（解除 8-instance 冻结后再评估 C）。
