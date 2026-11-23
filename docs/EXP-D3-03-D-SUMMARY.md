# EXP-D3-03-D 执行报告

**任务**：Mixed Multi-Event Authorization Transition
**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**范围**：设计研究、源码审计、状态机冻结、独立参考模型、构造比较、成本模型、Halo2 原型入口规格；不新增 Halo2 电路，不修改 A/B/C。

---

## 1. Git

- 基线 commit：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
- 最终 commit：本文件所在提交（提交完成后以分支 HEAD / 远端 ref 为准）
- 远端 commit：推送完成后与本地 HEAD 一致
- 工作区状态：提交后 clean
- 是否修改 A/B/C：否。A/B/C 源码、固定向量、测试与冻结文档均未改；`src/lib.rs` 只新增 `pub mod reference;` 注册。

---

## 2. Phase 0 源码审计

- GR/RR 是否可以共享接口：电路层不能直接共享。C 的 opening 复用 B 的 `OpeningB` 类型和 `SparseTreeB` 构造，但 B/C 是独立电路/vk，copy 不能跨证明；本仓无 B witness 到 C witness 的转换。
- Merkle 中间根如何连接：同一 Halo2 电路内可用 `Region::constrain_equal` 把事件 i 的 next 根 cell copy 到事件 i+1 的 prev 根 cell；当前 A/B/C 没有中间根 cell，也没有 `inter_gr_roots/inter_rr_roots` 实现。
- B/C 事件编码兼容性：batch 层相同（`Poseidon(D_BATCH,n,c1,c2,c3)`、3 槽 padding/count）；事件承诺层不同，B 为 9 词 `TYPE_GRANT=1`，C 为 5 词 `TYPE_REVOKE=2`。`D3-BATCH-v1/D3-EVENT-v1` 与旧文档 `...-P-v2` 有标签分歧，D 先沿用代码冻结值。
- 固定批次容量：数组上限 3；当前 B/C 实际只允许 1 个有效事件。
- 已知冲突：B/C 各自合法但组合顺序不合法至少六类，包括重复 ID、重复撤销、Grant(A)+Revoke(A) 的 GR 语义分歧、Parent/Child 顺序、epoch 规则差异、槽位冲突。详见 `docs/EXP-D3-03-D-SOURCE-AUDIT.md`。

---

## 3. Phase 1 状态机

- 事件顺序规则：有序事件列表，不做规范排序；有依赖事件不可交换。
- epoch 规则：批次统一 `epoch_prev+1`，所有 active 事件共享该 epoch，最终 epoch 也是该值。这样兼容 C 的严格 `+1` 和 B 的 `≥`。
- Parent/Child 规则：Child 的 Parent 必须在当前 GR 中存在且当前 RR 中无撤销记录；issuer=parent.subject；scope 子集；resource 前 8 字节前缀相等；epoch 不小于 Parent。撤销 Parent 不自动撤销已存在 Child（DirectOnly），但之后不能依赖已撤销 Parent 创建新 Child。
- 重复创建规则：当前 GR 中已有 ID 即拒绝，即使该 ID 已被撤销。
- 重复撤销规则：当前 RR 中已有记录即拒绝，不做幂等成功。
- 失败处理规则：整批拒绝，不产生 final state；仅保留成功前缀用于诊断。

---

## 4. Phase 2 构造比较

- Sequential 设计：每步执行一个事件，相邻步骤的四个根 cell 直接 copy；Grant/Revoke 分别复用 B/C 单步关系，新增 Parent RR 检查和 type 分派。
- Batch Update 设计：把事件列表与更新记录作为整体，需约束 ID 唯一、槽位冲突、更新完整性、顺序/依赖和最终根；可共享路径前缀，但必须证明无遗漏/覆盖。
- 各自优势：Sequential 语义直接、中间状态天然存在、接近现有代码；Batch 理论上可能共享 Merkle 前缀并减少重复 opening。
- 各自限制：Sequential 每步重新 opening，成本随 n 结构增长；Batch 需要排序/冲突/完整性约束，depth=4/n≤3 下共享收益未证实。
- 最终建议：第一版 Halo2 原型采用 Sequential，`n≤2`；依赖感知的局部批量重排只作为后续研究假设，不提前宣称优势。

---

## 5. Phase 3 参考模型

- 实现语言：Rust。
- 测试数量：42 个，全部通过。
- 正向测试：S01–S08、S12、S14、S15 等合法序列；空树、epoch、容量边界中的正向部分。
- 负向测试：S09/S10/S11/S13、重复创建/重复撤销、Parent 不存在/已撤销/scope/resource/issuer/epoch 错误、容量超限、事件过多、epoch 不匹配。
- 性质测试：P1 顺序敏感性、P2 前缀有效性、P3 承诺敏感性、P4 拒绝原子性、P5 等价执行、P6 重复撤销拒绝。
- 全部测试结果：`42 passed / 0 failed`。与 B/C 的单事件语义差分检查通过；字段编码和摘要口径差异已明确标注，不冒充字节兼容。

---

## 6. Phase 4 成本模型

- n=1：Grant 约 22 次 Poseidon，Revoke 约 18 次（含 batch+state 固定 3 次）。
- n=2：Grant+Grant 约 41，Grant+Revoke 约 37，Revoke+Revoke 约 33。
- n=3：Grant+Grant+Grant 约 60，G+G+R 约 56，G+R+R 约 52，R+R+R 约 48。
- Poseidon 调用估算：B 型带 Parent Grant 事件级 15 次；D 新增 Parent RR 空记录检查 4 次，共 19 次；C 型 Revoke 事件级 15 次。
- Merkle 更新估算：depth=4；Grant 12 层（D 型 16 层），Revoke 12 层；Batch 共享路径按 `4*p` 估计，p 为共享路径组数。
- Witness 规模：一个 opening 约 20 个路径相关值；B 型 D Grant 约 4 个 opening，Revoke 约 3 个；n=3 时路径 witness 约 180–240 个字段值。
- 未知指标：逐门约束数、行数、selector/advice 实际数、证明时间、proof size、内存、路径共享真实收益、依赖分析电路成本。未用源码行数或 selector 数冒充约束规模。

---

## 7. Phase 5 原型入口

- 推荐构造：Sequential Transition Circuit。
- 最大事件数：2。
- 支持的事件组合：`Grant+Grant`、`Grant+Revoke`、`Revoke+Revoke`；单事件可由 padding 兼容。
- Public Input：保持 A 的 8 个 instance，`event_count` 允许 1/2，不新增公开字段。
- Circuit 接口：见 `docs/EXP-D3-03-D-PROTOTYPE-SPEC.md`，含 `AuthorizationEvent`、`MixedTransitionInput`、`MixedTransitionCircuit` 概念草图。
- 原型测试矩阵：P01–P17，覆盖合法组合、顺序交换、中间根替换、事件遗漏/重复、重复 ID、非法 Parent、非法撤销者、错误最终根、错误 batch、错误 event_count、非前缀 active、Parent 撤销后创建 Child、Revoke 改 GR 根、修改 public instance 后 proof 被拒。

---

## 8. 未解决问题

- 未实现 Halo2 原型；所有电路成本只有结构估算，无实测。
- Batch Update 的路径共享收益与冲突约束成本未验证。
- 依赖感知重排只做了观察，没有形成可证明规则。
- 类别 II SHA-256 字段映射、canonical slot、Bridge/checkpoint、执行时新鲜性仍属外部信任。
- 不证明 ALLOW/DENY、完整历史、Cascade、递归或跨 vk 重放防护。
- `D3-BATCH-v1/D3-EVENT-v1` 与旧文档 `...-P-v2` 的标签分歧待统一；D 当前沿用代码值。

---

## 9. 最终结论

D 阶段工程目标达成：完成源码审计、混合事件状态机冻结、Sequential/Batch 两种构造比较、独立参考模型（42/42 测试通过）、成本模型和 Halo2 原型规格。

**是否具备进入 Halo2 原型阶段的条件：是。**

推荐下一阶段任务：`EXP-D3-03-E` 实现 Sequential n≤2 Halo2 原型，严格执行本规格的 P01–P17 测试矩阵，不改变 A/B/C 冻结接口，不扩展到 Cascade、递归或完整历史证明。
