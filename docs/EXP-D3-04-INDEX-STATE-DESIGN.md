# EXP-D3-04 — Phase 1: Unified ID-State Index Design

## 0. 定位与硬边界

本文是**设计文档**，不是电路实现或验证报告。不改 E-R1/E-R2/R3 电路、不动 A/B/C/D/E、不写新 Halo2 电路。

核心问题（承接 E-R3 结论）：**能否用一个经过密码学认证的 ID 状态索引替代 E-R1 的全树扫描（344/505 Poseidon permutations），同时保持原有授权语义？**

Phase 0 已修正 R3 两处口径（见本文附录 A）：候选 C 的 R3 实验只是 `BTreeSet` host 模型；索引根不必然新增 public instance。

## 1. 三态统一索引语义

定义单一 ID 状态索引 `I : F → {ABSENT, ACTIVE, REVOKED}`，对完整 Pallas Base 字段 ID 键：

| 状态 | 含义 | 对应 GR/RR 状态 |
| --- | --- | --- |
| `ABSENT` | 从未授权 | ID 不在 GR 任何非空叶（自然也不在 RR） |
| `ACTIVE` | 存在有效授权 | ID 在 GR 叶且 valid=1，且不在 RR |
| `REVOKED` | 已撤销授权 | ID 在 RR 有记录（GR 叶可保留但 valid=0） |

### 1.1 三类操作归约为状态转换

| 操作 | 前置状态要求 | 后置状态 | 拒绝条件（对应参考模型） |
| --- | --- | --- | --- |
| `Grant(new_id, parent)` | `I[new_id]=ABSENT`，且 `I[parent]=ACTIVE` | `I[new_id]=ACTIVE` | `DuplicateGrant`（new_id≠ABSENT，含 REVOKED）、`ParentNotFound`/`ParentNotValid`（parent≠ACTIVE） |
| `Revoke(target)` | `I[target]=ACTIVE` | `I[target]=REVOKED` | `GrantNotFound`/`AlreadyRevoked`（target≠ACTIVE） |

**关键**：重复 Grant 与重复 Revoke 都由"前置状态必须精确等于某值"这一状态转换规则直接拒绝，不再需要独立的"全树找重复 ID"扫描。这是三态索引相对 E-R1 的本质简化——E-R1 要分别扫描 GR（查 Grant 重复）和 RR（查 Revoke 重复 + Parent 撤销），三态索引把这些查询统一成一次索引状态查询。

### 1.2 与参考模型语义对齐

核对 `src/reference/mixed_event_state.rs:373-427`：
- `apply_grant`：`state.grants.contains_key(id)` → `DuplicateGrant`（含已撤销 ID，因为撤销不删除 GR 记录）；parent 需存在且 `is_valid`。
- `apply_revoke`：`grants` 需存在、`revokes` 需不存在 → 否则 `GrantNotFound`/`AlreadyRevoked`。

三态映射完全对齐：`ABSENT`↔从未进 grants，`ACTIVE`↔在 grants 且不在 revokes，`REVOKED`↔在 revokes。注意 **REVOKED 不能再 Grant**（参考模型保留 GR 记录），所以 `Grant` 要求 `ABSENT` 而非仅仅"非 ACTIVE"——这一点必须保持，否则会放宽语义。

## 2. 索引一致性：本设计的核心难点

不能只"另维护一份由 host 自己声称正确的索引"。索引 `I` 必须与 GR/RR 状态保持一致，否则证明失去意义。此处必须区分两个层次，否则会掉回全树扫描的陷阱：

### 2.1 转换一致性（incremental）——可由电路门控保证

要求：每一次 Grant/Revoke 必须**同时**更新 GR/RR 状态与索引状态，由同一 event 分支 flag 门控。

- `Grant(new)`：`I[new]: ABSENT→ACTIVE` 与"GR 插入 new 的授权 leaf"必须同真同假；
- `Revoke(target)`：`I[target]: ACTIVE→REVOKED` 与"RR 插入 target 的撤销 leaf"必须同真同假。

实现方式（设计层）：两个承诺更新受同一 `is_grant`/`is_revoke` selector 控制，而非在电路内逐 ID 事后比对整棵 GR/RR。这样一致性是**转换规则内建**的，不需要扫描。

### 2.2 初始一致性（S0）——可信锚定前提

S0 的索引状态与 GR/RR 初始状态一致，无法由转换规则自证。沿用 E-R2 方案 A：`I_0` 与 `GR_0/RR_0` 的一致性由可信 genesis 或此前已验证的状态转换证明链保证。R2 builder 的 host 检查只能拒绝明显非法输入。

**诚实边界**：本设计不声称电路独立验证任意 S0 一致性；这是与 E-R1/E-R2 相同的外部信任，不是新引入的弱点，但也没有被消除。

### 2.3 为什么不能逐 ID 事后审计

若在电路内对每个 ID 证明"`I[id]` 与 GR/RR 一致"，就需要像 E-R1 一样枚举所有叶并重算根——那正是要消除的 344 permutations。因此一致性的正确落点是**承诺更新同步 + 初始锚定**，不是逐项审计。这是 Phase 2/4 选择数据结构时必须遵守的约束。

## 3. 多事件顺序状态链

保持 E 的两事件顺序：event0 输出索引状态 `I_1` 必须成为 event1 的输入，不允许 host 代入中间状态。

- event1 的 `Grant(new2,parent2)` 若 new2 在 event0 被 grant，则 `I_1[new2]=ACTIVE`，前置 `ABSENT` 不满足 → 拒绝（对应 E-R1 的 P09 跨槽重复）。
- event1 的 `Revoke(t2)` 若 t2 在 event0 被 revoke，则 `I_1[t2]=REVOKED` → 拒绝（对应 R1 P12/P13）。
- event1 的 Parent 若被 event0 revoke，则 `I_1[parent]=REVOKED` → 拒绝（对应 R1 P04）。

这与 E-R1/E-R2 的攻击覆盖目标一致，索引语义能统一表达这些约束。

## 4. 索引键：完整 ID  vs  截断键

`I` 的键是完整 F 字段 ID。若数据结构为哈希型（Sparse Merkle），直接用完整 254-bit 表示作路径会导致深度过长（Phase 2 详述）。若截断键，则两个不同 ID 可能落到同一索引位置，必须显式处理碰撞——不能静默覆盖。这是 Phase 2 数据结构比较的核心权衡之一，本文不预设结论。

## 5. 与 8 public instances 的关系（承接 Phase 0 修正）

索引根不必然新增 public 值。两种接口：
- **A**：新增公开实例承载索引根（扩展 instance 行数或列）。
- **B**：把索引根并入 `C_prev/C_next` 的输入词。当前 `C_prev = H(D_state,GR_prev,RR_prev,epoch_prev,policy)`（5 words，`e_r1_circuit.rs:1716-1727`），可扩展为 `H(D_state',GR_prev,RR_prev,IR_prev,epoch_prev,policy)`，8 个 public 值数量不变，但需新域分离版本、verifier 与状态锚定协议同步升级。

两种都非零成本，都需证明索引-GR/RR 一致性（§2）。Phase 3 详评。

## 6. 本阶段结论

三态索引语义在逻辑层成立，且与 E-R1/E-R2/D 参考模型的拒绝条件逐项对齐；它把"跨槽重复检测"归约为状态转换前置条件，是相对全树扫描的实质简化。但**是否可认证、是否比扫描便宜，取决于数据结构与承诺接口，尚未验证**。Phase 2 比较候选结构，Phase 4 用真正的密码学 host 模型（非 `BTreeSet`）做最小实验。

## 附录 A：Phase 0 修正的 R3 口径

1. R3 候选 C 的 `BTreeSet` 二分搜索（4 步 vs 16 槽）是排序集合比较次数，不是密码学索引树 opening 成本；R3 四份文档已更正。
2. R3 "必须新增 public instance" 过强，已改为"可新增实例或并入 C_prev/C_next"；见 §5。
3. R3 元数据表中 gate families=28 / degree=3 已标注为源码静态分析，其余五项为运行时探针输出。
