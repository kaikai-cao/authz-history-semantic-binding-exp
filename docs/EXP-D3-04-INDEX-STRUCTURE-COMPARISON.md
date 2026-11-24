# EXP-D3-04 — Phase 2: Authenticated Index Structure Comparison

## 0. 定位

比较两种**真正可认证**的 ID 索引数据结构，用于承载 Phase 1 的三态 `I : F → {ABSENT,ACTIVE,REVOKED}`。本文是设计分析 + host 结构实验（Phase 4），不写 Halo2 电路。

两种候选：
- **S1：Sparse Merkle ID Index** — 以 ID 为键（或其承诺），通过空叶证明 non-membership。
- **S2：Authenticated Ordered Index** — 维护排序 ID 键集合，通过相邻节点关系证明 non-membership。

共同必须回答（用户指定）：ID 键冲突、non-membership 证明、插入与更新、最坏成本、初始状态信任、索引根如何绑定到 `C_prev/C_next`。

## 1. ID 键长度：完整 254-bit F vs 截断键

这是 S1 的首要设计约束，不能一句"O(log n)"带过。

- Pallas Base 字段元素约 254 bit。若 Sparse Merkle Tree 以完整 ID 的每一 bit 作为路径，深度 ≈ 254，non-membership opening 需 ~254 个 sibling。即便只做一次这样的证明，电路内也是 254 层 Poseidon + 254 sibling witness，**远超** E-R1 全树扫描的 16 叶+15 节点量级。完整键 SMT 在本规模下没有成本优势。
- 若截断键（取 ID 的 t bit，`t≈8..16`），路径深度 `t`，但两个不同完整 ID 可能落到同一索引槽 → **键碰撞**。必须显式处理：
  - 方案 a：槽内存完整 ID 列表 / 桶，查询时比对桶内每个完整 ID；桶大小最坏退回线性扫描。
  - 方案 b：桶内再用一棵小结构（二次哈希/子 SMT），把碰撞概率压到可忽略，但需证明"无其他 ID 落此桶且冲突已解决"。
  - 方案 c：把完整 ID 的 Poseidon 承诺作为叶值，槽位只作定位；non-membership 需同时证明"键槽为空或叶的完整 ID ≠ 目标 ID"。
- **结论**：截断键不可避免碰撞处理，这正是 E-R3 候选 B（canonical slot）已暴露的问题（碰撞需位移、最坏 O16）。S1 若用截断键，必须继承同样的碰撞分析，不能假设完美单射。

## 2. S1：Sparse Merkle ID Index

**结构**：深度 t 的稀疏 Merkle 树，叶为三态编码 `state(id)`（ABSENT=0 空叶、ACTIVE、REVOKED），承诺为 `IR`。

| 维度 | 分析 |
| --- | --- |
| ID 键冲突 | 完整键 → 深度 ~254，不实用；截断键 → 需 §1 碰撞处理，最坏桶内线性。 |
| non-membership 证明 | 沿 ID 路径给 opening，证明目标槽为 ABSENT（空叶）或叶的完整 ID≠目标。深度 t 的 opening = t 个 sibling + 路径 bit 布尔约束。 |
| 插入/更新 | 三态转换只改一个叶 + 重算 t 层路径（t 次内部 Poseidon）。比全树 15 节点重算，当 t<15 时单叶更新更便宜。 |
| 最坏成本 | 单操作 O(t)；截断键碰撞桶最坏 O(桶大小)。t=8 时 8 层 vs E-R1 每事件 2 树×15 节点 + 32 叶哈希。 |
| 初始状态信任 | `IR_0` 与 `GR_0/RR_0` 一致由可信锚定（E-R2 方案 A）；host 可拒绝明显非法索引。 |
| 索引根绑定 | 见 Phase 3：接口 A 新增实例，或接口 B 并入 `C_prev/C_next`。 |
| 一致性（§2.1 转换） | Grant/Revoke 同时更新索引叶与 GR/RR，同一 selector 门控；无逐 ID 审计。 |

**优势**：单次状态查询/更新局部化（O(t)），三态统一表达三类检查。
**风险**：截断键碰撞；完整键深度过长；索引三态与 GR/RR 双承诺同步更新的电路约束尚未设计。

## 3. S2：Authenticated Ordered Index

**结构**：维护按完整 ID 排序的键集合，用 Merkle/Poseidon 承诺；non-membership 通过前驱/后继相邻关系证明。

| 维度 | 分析 |
| --- | --- |
| ID 键冲突 | 完整 ID 天然有序，无哈希碰撞；但需处理相等 ID（重复）→ 由排序严格性约束拒绝。 |
| non-membership 证明 | 给目标 ID 的前驱 `p` 与后继 `s`，证明 `p < target < s` 且 `p,s` 在承诺集合中相邻（中间无其他键）。相邻性证明是难点：需对 `p,s` 的 Merkle opening 证明它们是连续叶，或引入有序索引位置约束。 |
| 插入/更新 | 有序插入需移动后继元素（固定容量最坏 O(n) 写），或采用"逻辑删除 + 追加"避免物理移动但破坏排序。三态转换：REVOKED 元素保留在集合中。 |
| 最坏成本 | non-membership 证明本身 O(log n) opening + 相邻性约束；插入更新最坏 O(n) 移动（n≤16 时可控但仍非零）。 |
| 初始状态信任 | 排序不变量 + `IR_0` 可信锚定。 |
| 索引根绑定 | 同 Phase 3 两接口。 |
| 一致性 | 同 §2.1 门控同步。 |

**优势**：完整 ID 无哈希碰撞；non-membership 理论上 O(log n)。
**风险**：相邻性证明复杂；有序插入的最坏 O(n) 移动可能抵消收益；与 E-R3 候选 D 的"最坏退回 O16"论断一致。

## 4. 横向比较（设计层，未验证成本）

| 维度 | S1 Sparse Merkle | S2 Ordered Index |
| --- | --- | --- |
| 完整 ID 可行 | 否（深度~254）→ 需截断 | 是（天然有序） |
| 截断碰撞 | 有，需桶/子结构 | 无（排序区分） |
| non-membership | O(t) opening | O(log n) + 相邻性 |
| 插入更新 | O(t) 单叶 | 最坏 O(n) 移动 |
| 最坏情况 | 桶大小 or t | n |
| 初始信任 | IR_0 锚定 | 排序+IR_0 锚定 |
| 实现复杂度 | 中（路径 opening） | 高（相邻性 + 移动） |

## 5. 与 E-R1 全树扫描的公平对比口径

- E-R1：每事件固定 344/2 = 172 permutations（2 树×16 叶+15 节点），与事件类型无关（region 无条件创建）。
- S1：单操作理论 O(t)，但必须加上索引-GR/RR 一致性更新的约束成本；**未实测**，不能断言总 permutation 更低。
- S2：non-membership O(log n) 但插入最坏 O(n)；**未实测**。
- 三态索引的收益来自"统一三类检查为状态查询"，不是免费的；一致性同步与初始锚定是新增成本，必须计入。

## 6. 本阶段结论

两种结构都**理论可承载**三态索引，但都有明显代价：
- S1 完整键不实用、截断键碰撞未解；
- S2 相邻性证明与有序插入最坏 O(n)。

"O(log n)" 是 opening 深度，**不是总成本**；加上索引-GR/RR 一致性更新、初始锚定、碰撞/相邻处理，是否已优于 E-R1 的 172 permutations/事件，**未经 Halo2 实测不能判定**。Phase 4 用真正密码学 host 模型检验结构与更新关系，而非 `BTreeSet` 逻辑模拟。
