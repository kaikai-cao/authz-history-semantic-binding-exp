# EXP-D3-05 Phase 5 — Cost Model and E-R1 Comparison

## 0. 口径声明（先读）

- E-R1 的 `K=15 / 505 permutations / 344 扫描置换 / 68.1% / advice=39 / selector=30 / constraint polys=43` 是**已实测/已统计**结果（E-R3 探针，见 `EXP-D3-03-E-R3-COST-ATTRIBUTION.md`）
- **68.1% 是 Poseidon permutation 数量占比，不是 proving time 占比**
- 本阶段的 B/C 构造成本是**理论估算**：没有 Halo2 电路、没有实测 K/prove/verify/keygen。所有理论值均标注为"估算"，不得换算成证明时间
- 以下的 Poseidon permutation 计数基于 `P128Pow5T3` rate=2：`hash_words(N) = ceil(N/2)` permutations

## 1. E-R1 基线（构造 A，已实测）

| 项 | 值 | 来源 |
| --- | --- | --- |
| K | 15 | 实测最小可行 |
| 树深度 / 容量 | 4 / 16 | 常量 |
| 每事件全树扫描 | GR 16 叶 + RR 16 叶 + 两棵树各 15 内部节点 | 电路结构 |
| Poseidon permutations（全电路） | 505 | E-R3 静态/结构计数 |
| 其中全树扫描相关 | 344（GR leaf 160 + RR leaf 64 + root rebuild 120） | 同上，68.1% |
| E 基线置换 | 161（openings 96 + leaves 34 + event commit 16 + batch 15） | 同上 |
| proof size | 8160 B | 实测 |
| GR 中位 prove | 35016 ms（fixed RAYON=1/OMP=1, 3 采样） | 实测 |
| advice / selector / constraint polys | 39 / 30 / 43 | 运行时探针 + pinned() |

**E-R1 用 344 次置换换取 ID 全局唯一性与 Parent 撤销有效性，不依赖 IR。**

## 2. 构造 B：纯 IR 索引（理论）

假设：用 `IR(id)` 单次 opening 替代 GR/RR 全树扫描；仍需 GR opening 验证 Parent 授权内容、RR opening 或一致性证明验证撤销。

### 2.1 理论 opening 数（每事件）

| 用途 | opening 数 | 深度 |
| --- | --- | --- |
| IR 新 ID non-membership | 1 | t |
| IR Parent 状态 | 1 | t |
| IR Revoke 目标状态 | 1（Revoke 事件） | t |
| GR Parent 叶子（授权内容） | 1 | 4 |
| GR 新叶写回 | 1（新根重算） | 4 |
| RR 撤销检查 | 1（若用 opening 而非扫描） | 4 |
| RR 新叶写回 | 1（Revoke 时） | 4 |

理论 opening 数约 5–7 次/事件，取决于撤销检查是否仍需扫描。

### 2.2 理论 Poseidon permutation（每事件）

按深度 `t` 和词数：`IR leaf=3 words→2 perm`，`IR node=3 words→2 perm/层`，`GR leaf=9 words→5 perm`，`RR leaf=4 words→2 perm`，`Merkle node=2 perm/层`。

| 类别 | d=4 | d=8 | d=16 |
| --- | --- | --- | --- |
| IR 3 次 leaf | 6 | 6 | 6 |
| IR 3 次 opening path（t×2 perm） | 24 | 48 | 96 |
| GR leaf + path（5 + 4×2） | 13 | 13 | 13 |
| RR leaf + path（2 + 4×2） | 10 | 10 | 10 |
| **合计（估算）** | **53** | **77** | **125** |

注意：这是**每事件**的理论置换数，E-R1 的 344 是**两事件+两树全扫描**的总数；口径不同，不可直接相除比较。

### 2.3 构造 B 的阻断性成本

- **若保留 E-R1 的 RR 全扫描做 Parent 检查（Phase 3 §5 阻断项 1）**：置换数 ≈ E-R1 344 + IR 增量，**比 E-R1 更贵**；此时 B 不是优化
- **若用 IR 替代 RR 扫描**：必须证明 IR↔RR 一致性（N05/N06），目前**没有**无需扫描的证明路径
- IR 深度 t=4 时碰撞不可忽略（16 槽， birthday 界约 4–5 个 ID 就有显著碰撞概率），碰撞处理成本未测
- 新增 advice：IR leaf preimage（full_id + state + inv）3 列、IR path t 个 sibling、slot 分解若干列；selector 增量约 +5–8；gate 增量约 +5–7；K 可能从 15 升到 16+（**估算，未测**）

## 3. 构造 C：混合（IR 查询 + 必要 GR/RR opening）

- 用 IR 做全局唯一性与三态查询，但保留 GR 叶子 opening 验证授权内容、RR 全扫描或一致性证明验证撤销
- 理论置换 ≈ E-R1 344 + IR opening 增量（每事件约 10–25），**大概率高于 E-R1**
- 若能用 IR 消除 GR 全扫描（16→1 opening），理论节省 GR leaf 160+root 60=220，但需证明 IR↔GR 一致（N11），且仍须处理截断键碰撞
- 净效果方向不定：依赖"IR 一致性证明成本"是否低于"被消除的扫描成本"，当前**无实测依据**

## 4. 深度 d ∈ {4,8,16} 的分析

| 深度 | 容量 2^d | 碰撞/可用性 | 对成本的影响 |
| --- | --- | --- | --- |
| 4 | 16 | 碰撞显著；与 E-R1 同容量 | opening 便宜但碰撞处理贵；与 E-R1 公平对照的最小配置 |
| 8 | 256 | 碰撞降低 | opening 路径翻倍（+24 perm/3 opening） |
| 16 | 65536 | 碰撞近似忽略 | opening 路径再翻倍（+48 perm/3 opening），深度 16 的 IR 路径已接近 E-R1 全树 15 内部节点的量级 |

**结论**：d=16 时单次 IR opening 的路径深度（16）已与 E-R1 全树内部节点层数（15）同量级，"局部 opening 更便宜"的优势被深度抵消。要支撑有意义的性能结论，需要实测 IR 一致性证明成本；当前参数**不足以**得出 IR 一定优于 E-R1 的结论。

## 5. 四类成本分别给出

| 维度 | A=E-R1（实测） | B/C（估算） |
| --- | --- | --- |
| 理论 Merkle opening 数 | 全树 16 叶 ×2 树 ×2 事件 | 5–7/事件（B）；见 §3（C） |
| 理论 Poseidon permutation | 505（344 扫描 + 161 基线） | B: 53/77/125（d=4/8/16，每事件） |
| 电路约束数量估算 | constraint polys=43（实测） | 新增 5–7 gate family（未测） |
| advice cells 增量 | 39 列（实测） | IR leaf 3 + path d + slot 分解（估算） |
| selector 增量 | 30（实测） | +5–8（估算） |
| equality constraints | 已有 GR/RR 事件间 2 条 | IR 事件间 +1，cross-id/epoch +若干 |
| K 值风险 | 15 | 可能 16+（估算，未测） |
| 实测 prove/verify/keygen | 有（8160 B / 35016 ms 等） | **无，未实现电路** |

## 6. 与 E-R1 的公平对照

- 对照的基线是**同一语义**：ID 全局唯一、Parent 未撤销、两事件顺序、8 public instance、K15/16 槽
- 不能把 68.1% 当 proving time 下降空间：它只是 permutation 数量占比；IR 的 opening 数下降不代表 Halo2 行数/约束同比下降
- 不能把"理论一次 opening"当"已实现优化"：B/C 未接 Halo2、未测 K/prove/verify
- 真正能支持"IR 更优"的证据需要：IR 一致性证明的电路实测 + 与 E-R1 同轮 benchmark；本阶段两者都没有

## 7. 成本模型结论

理论上 IR 可以消除全树叶子重算（E-R1 的 344 置换主体），但代价是新增 IR 树的 opening/更新与三状态一致性证明。**在保留 E-R1 的 RR 全扫描做撤销检查时，B/C 的理论置换数高于 E-R1；在试图用 IR 替代时，一致性证明路径尚未设计出来。** 因此当前成本模型**不能**支持"IR 值得进入 Halo2 原型"的结论。
