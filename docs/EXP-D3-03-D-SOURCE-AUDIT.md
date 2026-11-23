# EXP-D3-03-D — Phase 0 源码审计

**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**性质**：只读源码与冻结文档核对。不修改 A/B/C、不改固定向量、不新增 Halo2 电路。
**证据口径**：每条结论给出 `路径:行号`、函数名或文档名；无法确认者标记 `UNKNOWN`，不用推测替代源码证据。

---

## 0. Phase 0 命令与结论

```text
git status --short              # 空
git branch --show-current       # exp-d3-03-c → 新建 exp-d3-03-d-design
git rev-parse HEAD              # be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2
git rev-parse origin/exp-d3-03-c# be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2
git diff --check                # 干净
```

审计参考文档：

- `docs/EXP-D3-03-C-INTERFACE-AUDIT.md`
- `docs/EXP-D3-03-C-REVOCATION-DESIGN.md`
- `docs/EXP-D3-03-C-TEST-REPORT.md`
- `docs/EXP-D3-03-C-SUMMARY.md`

### 结论先行

1. B/C 不能跨电路直接共享状态树和 Merkle path；只有 `OpeningB`/`SparseTreeB` 等 Rust 类型与编码口径可在离线构造层复用。
2. 当前 A/B/C 都是单事件电路，没有“事件 i 的 next 根 → 事件 i+1 的 prev 根”的 cell 连接。R2 文档曾定义 `inter_gr_roots/inter_rr_roots`，但没有实现。
3. B 创建 Grant 依赖 Parent 已在当前 GR 中打开且 `valid=1`；C 撤销依赖目标 Grant 已在当前 GR 中打开且 `valid=1`。
4. B/C 的 batch 层可复用，但事件承诺层词数与 type tag 不同：B 为 9 词 `TYPE_GRANT=1`，C 为 5 词 `TYPE_REVOKE=2`。
5. 三槽 batch 数组最多容纳 3 个有效事件；当前 B 合法 witness 和 C 的 `event-count-one` 门都把有效事件限制为 1。
6. 同一电路内用 `Region::constrain_equal` 连接中间根在机制上可行；跨电路/vk 不可行，必须递归或聚合，本阶段不做。
7. 槽位由外部 witness 提供，电路只验证给定槽位旧叶为 0 和同路径更新，不证明全局 canonical layout；同一 ID 可被放到不同空槽而不被 B/C 单独电路发现。
8. 存在 B/C 各自合法但组合顺序不合法的情况，包括重复 ID、重复撤销、`Grant(A)+Revoke(A)` 的语义分歧、Parent/Child 顺序、epoch 规则差异。

---

## 1. 十个必答问题

### Q1. B/C 当前是否能直接共享状态树和 Merkle path？

**不能直接共享。** 可复用的只是离线类型与编码规则。

- B 的 GR 树与 opening：`OpeningB`（`src/transition/b_types.rs:71-87`）、`SparseTreeB`（`src/transition/b_types.rs:94-150`，`new` 102-111、`root` 113-115、`opening` 119-149）、`TransitionWitnessB`（`src/transition/b_types.rs:166-191`）持有 `parent_open`、`child_open`、`child_open_new`；构造入口是 `build_scenario`（`src/transition/b_types.rs:196-236`）。
- B 没有 RR 树：`rr_prev_be/rr_next_be` 在 `build_scenario` 中直接写 `let rr_f = F::ZERO`（`src/transition/b_types.rs:214,221,223`），电路只做规范域编码（`src/transition/b_circuit.rs:792-795`）。
- C 的 GR/RR opening 复用 B 的类型：`TransitionWitnessC` 的 `grant_open`、`rr_old_open`、`rr_new_open` 均为 `OpeningB`（`src/transition/c_types.rs:52-75`，import 第 12 行）；C 用 `SparseTreeB::new/opening` 构造三条路径（`src/transition/c_types.rs:107-139`）。
- B/C 是独立电路配置：`TransitionConfigB`（`src/transition/b_circuit.rs:48-99`）与 `TransitionConfigC`（`src/transition/c_circuit.rs:47-92`），各自实现 `Circuit<F>`（`b_circuit.rs:401`、`c_circuit.rs:362`）。copy 约束只在同一电路实例内成立：`copy_equal` 通过 `layouter.assign_region(... region.constrain_equal(...))` 实现（`b_circuit.rs:139-149`、`c_circuit.rs:132-143`）。
- 全仓没有 `TransitionWitnessB → TransitionWitnessC` 的转换，也没有跨 vk 共享路径的机制；跨阶段共享需要递归/聚合，当前不存在。

### Q2. GR/RR 的每次更新是否依赖前一事件的中间根？

**当前不依赖；每个电路只有单事件。**

- A 的四个根各自独立解码为 cell（`src/transition/circuit.rs:400-416`），`C_prev/C_next` 用 `Poseidon(D_STATE, GR, RR, epoch, policy)` 重算（`src/transition/circuit.rs:457-481`），没有 Merkle 更新。
- B 的 `parent_opening.root → gprev`（`src/transition/b_circuit.rs:919-927`），`child_old_opening.root → gprev`（929-938），`child_new_opening.root → gnext`（943-963）；但 `gprev/gnext` 本身来自独立 witness 根（`792-795`），没有事件间链。
- C 的 `grant_opening.root → gprev`（`src/transition/c_circuit.rs:849-857`）、`rr_old → rprev`（859-867）、`rr_new → rnext`（869-889）、`gnext == gprev`（893）；同样没有事件间链。
- R2 冻结接口曾列出 `inter_gr_roots/inter_rr_roots`（`docs/d3_02_r2_transition_interface.md:112-115`），但 `src/` 全仓检索无实现。D 必须新增相邻事件根 copy 链。

### Q3. B 创建 Grant 时是否依赖 parent 已经存在于当前 GR？

**是。Parent 必须在 `GR_prev` 中打开且 `valid=1`。**

- 电路证据：`parent_opening.root` copy 到 `gprev`（`src/transition/b_circuit.rs:919-927`）；parent 叶 9 词重算（`824-843`）；`q_grant_valid` 强制 `valid=1`（`613-617,324-326`）；`child.parent_key = parent.id`（`847`）、`child.issuer = parent.subject`（`849`）。
- 测试证据：篡改 parent sibling/方向/字段均拒绝（`tests/d3_03_b_mock.rs:82-92,94-104,106-116`）。
- 离线构造：`slots_prev[parent_slot] = parent_leaf`（`src/transition/b_types.rs:206-208`）。
- 参考规则：`ParentNotFound/ParentNotValid` 见 `src/policy.rs:126-133`。

### Q4. C 撤销 Grant 时是否依赖目标 Grant 已经存在于当前 GR？

**是。目标 Grant 必须在 `GR_prev` 中打开且 `valid=1`。**

- 电路证据：`grant_opening.root → gprev`（`src/transition/c_circuit.rs:849-857`）；9 词叶重算与 `valid=1` 门（`781-790,265-295,572-576`）；`grant.id = revoke.grant_id`（`824`）、`grant.issuer = revoke.revoker`（`825`）。
- 测试证据：C09/C10/C11/C12 分别拒绝 Grant 不存在、valid=0、ID 不一致、revoker 非法（`tests/d3_03_c_mock.rs:164-203`）。
- RR 旧槽必须为空：零叶 `zero_cell`（`src/transition/c_circuit.rs:709`）重算根 copy 到 `rprev`（859-867）；C13/C24 重复撤销拒绝（`tests/d3_03_c_mock.rs:206-212,291-295`）。

### Q5. B 和 C 的事件承诺能否使用同一个批次编码框架？

**批次层可以；事件承诺层不能无条件混用。**

- 共同批次：`D_E = Poseidon::<5>(D_BATCH, n, c1, c2, c3)`，A/B/C 分别见 `src/transition/circuit.rs:526-531`、`src/transition/b_circuit.rs:1024-1029`、`src/transition/c_circuit.rs:951-956`。
- A 的 active/padding/count gate 保证 `[1,1,0]` 前缀形式并约束 `n = Σ active_i`（`src/transition/circuit.rs:323-355`）；B/C 有对应门（`b_circuit.rs:530-562`、`c_circuit.rs:489-520`）。
- B 事件承诺：`Poseidon::<9>(D_EVENT, TYPE_GRANT=1, id, issuer, subject, prefix, scope, parent, epoch)`（`src/transition/b_types.rs:55-68`；`TYPE_GRANT=1` 在 `b_constants.rs:33`）。
- C 事件承诺：`Poseidon::<5>(D_EVENT, TYPE_REVOKE=2, grant_id, revoker, epoch)`（`src/transition/c_types.rs:31-40`；`TYPE_REVOKE=2` 在 `c_constants.rs:12-20`）。
- 差异：C 有 `event-count-one` 门（`c_circuit.rs:521-525,945`），B 没有；B 的合法 witness 仅在 `build_scenario` 中写 `event_count:1`（`b_types.rs:227`）。
- 文档/代码标签分歧：`docs/d3_02_public_statement.md:230` 写 `D3-BATCH-P-v2/D3-EVENT-P-v2`，代码实际使用 `D3-BATCH-v1/D3-EVENT-v1`（`src/transition/constants.rs:28-38`、`b_constants.rs:20-23`）。D 原型需沿用**代码冻结值**，并把该分歧列为 UNKNOWN/兼容性风险。

### Q6. 当前固定三槽批次承诺最多支持几个有效事件？

**数组层面最多 3 个；当前 B/C 电路实际只允许 1 个。**

- `MAX_EVENTS: usize = 3`（`src/transition/constants.rs:18-19`）；witness 字段 `event_commitments: [F; MAX_EVENTS]`（`types.rs:94-96`、`b_types.rs:176`、`c_types.rs:61`）。
- active/slot 数组长度 3；`active-boolean/slot-padding/active-monotone/active-count` 展开 3 槽（`src/transition/circuit.rs:323-355`；B `530-562`；C `489-520`）。
- batch Poseidon 宽度为 `MAX_EVENTS+2=5`（`circuit.rs:530`、`b_circuit.rs:1028`、`c_circuit.rs:955`）。
- C 强制 `event_count=1`（`c_circuit.rs:521-525`）；B 的合法路径也只有 slot0 非 padding（`b_types.rs:215-227`）。

### Q7. 中间状态根是否可以在同一电路中作为 cell 直接连接？

**机制上可行；当前未实现；不能跨电路/vk。**

- Halo2 0.4 没有 `Layouter::constrain_equal`，本仓统一用 `Region::constrain_equal`：`copy_equal` 见 `src/transition/b_circuit.rs:139-149`、`src/transition/c_circuit.rs:132-143`。
- B/C 已证明“Merkle 重算根 cell”可与“32B 规范域解码根 cell”做 copy（`b_circuit.rs:927,938,963`；`c_circuit.rs:857,867,889,893`）。因此 D 中“事件 i 输出根 cell → 事件 i+1 输入根 cell”可用同样机制。
- 但 A 的 public statement 只承诺首尾根（`src/transition/circuit.rs:457-481`），中间根若不进入新承诺/公开接口，就只是受约束的私有 witness，不构成公开可验证输出。
- copy 不能跨 `TransitionCircuitB` 与 `TransitionCircuitC` 两个独立 vk；跨阶段必须递归或聚合，本阶段不做。

### Q8. 当前 Grant 槽位分配规则是否允许多个事件产生冲突？

**允许；电路不检查全局唯一性与 canonical layout。**

- 槽位来自 witness：B 的 `parent_slot/child_slot`（`src/transition/b_types.rs:181-182`，参数 199-201）；C 的 `grant_slot/revoke_slot`（`src/transition/c_types.rs:66-67`，参数 85、88）。
- 电路只检查给定槽位旧叶为 0：B 子槽零叶 opening（`src/transition/b_circuit.rs:929-938`）、C RR 旧槽零叶 opening（`src/transition/c_circuit.rs:859-867`）。
- canonical assignment 只在离线层存在：`initial_slot` 用 `D3-SLOT-v1`（`src/grant_tree.rs:42,86-95`），`canonical_assignment` 按字节序排序并线性探测保证单射（`src/grant_tree.rs:100-134`）。
- B 审计明确槽位为外部信任（`results/d3_03_b_interface_audit.md:71,145`），C-INT-03 同样（`docs/EXP-D3-03-C-INTERFACE-AUDIT.md:163`）。
- 因此同一 ID 可被两个事件放到不同空槽，各自通过旧叶=0 检查；B/C 单独电路不会拒绝。D3-01 的 `DuplicateGrant` 在 `src/policy.rs:123-125` 拒绝，但这不是 B/C 电路约束。

### Q9. 同一 Grant 创建后立即撤销时，C 能否打开 B 刚刚生成的中间状态？

**离线可构造；电路内没有绑定；当前无实现。**

- 离线可行性：`TransitionWitnessC::build_scenario`（`src/transition/c_types.rs:83-141`）接受任意 `GrantFieldsB`；`sample_child_c()` 就是 B 派生的 child（`157-168`）。只要把 C 的 `gr_prev_be` 设为 B 输出根，并把 revoke epoch 设为 `B.next_epoch+1`，即可写出自洽 witness。
- 但没有任何代码消费 B 的输出：`c_types.rs/c_circuit.rs` 不引用 `TransitionWitnessB`；C 测试中 `sample_child_c` 只用于自造 GR 树（`tests/d3_03_c_mock.rs:297-348`）。
- 电路内 C 只证明给定 `GR_prev/RR_prev/RR_next` 满足单撤销关系（`src/transition/c_circuit.rs:824-893`），没有 gate 证明该 GR 根来自先前 B 证明，也没有 `GR_prev = B.GR_next` 的 copy。
- 语义分歧：D3-01 撤销把 GR 叶 valid 置 0（`src/state.rs:215-233`），C 强制 `GR_next = GR_prev`（`src/transition/c_circuit.rs:893`）；两者不能混称同一语义。

### Q10. 是否存在 B/C 分别合法、但组合顺序不合法的情况？

**存在，至少六类。**

1. `Grant(A)+Revoke(A)`：B 以 `valid=1` 创建 A，C 以 DirectOnly 撤销但 GR 不变（`src/transition/c_circuit.rs:893`）；D3-01 则会把 valid 置 0（`src/state.rs:216-220`）。两个 proof 各自成立，但组合语义与 D3-01 不一致。
2. `Grant(Parent)+Grant(Child)+Revoke(Parent)`：B 允许 Child 从 Parent 派生（`src/transition/b_types.rs:250-263`），C25 只证明撤销 Parent 不改 Child（`tests/d3_03_c_mock.rs:297-326`）；若要求 Parent 当前仍有效，组合后 Child 依赖失效。Cascade 规则见 `src/state.rs:211-214`，但 C 明确不做 Cascade。
3. 重复 ID：两次 B 可把同一 ID 放到不同空槽，各自通过旧叶=0；D3-01 `DuplicateGrant`（`src/policy.rs:123-125`）会拒绝。
4. 重复撤销：两次 C 若不继承前次 RR 状态，各自都能构造空旧叶；C13/C24 只在单电路内旧叶非空时拒绝（`tests/d3_03_c_mock.rs:206-212,291-295`）。
5. epoch：B 只要求 `child.epoch ≥ parent.epoch` 且 `next_epoch = child.epoch`（`src/transition/b_circuit.rs:883-899,851`），C 要求严格 `+1`（`608-613,521-525`）；例如 `parent=10, child=100` 的 B 合法，但与 C 的批次规则不兼容。
6. 槽位冲突：B 的 `child_slot` 与 C 的 `revoke_slot` 是独立外部 witness，可能指向同一或冲突记录（`b_types.rs:181-182`、`c_types.rs:66-67`）。

---

## 2. 可复用组件与 D 新增接口

### 可直接复用

- A 的 8 instance 顺序与 11 字段 statement：`src/transition/types.rs:35-82`、`src/transition/circuit.rs:533-541`。
- 32B 根规范域编码 gadget：`src/transition/circuit.rs:114-177`（B/C 对应 `b_circuit.rs:186-201`、`c_circuit.rs:178-193`）。
- `C_prev/C_next` Poseidon 重算与四根 cell：`src/transition/circuit.rs:400-416,457-481`。
- batch active/padding/count 门与 5 词 `D_E`：`src/transition/circuit.rs:323-355,526-531`。
- `OpeningB`、`SparseTreeB`、`node_hash_b`、`recompute_root_b`：`src/transition/b_types.rs:71-164`。
- Grant leaf 9 词与 fixed 域标签：`src/transition/b_types.rs:40-53`、`src/transition/b_constants.rs:12-23`。
- 4 层 opening 门和逐层 `(dir,sibling)` copy 模式：`src/transition/b_circuit.rs:563-584,951-962`、`src/transition/c_circuit.rs:526-546,877-888`。
- `copy_equal` 的 Halo2 0.4 写法：`src/transition/b_circuit.rs:139-149`、`src/transition/c_circuit.rs:132-143`。
- D3-01 离线规则与槽位规则：`src/policy.rs:103-170`、`src/grant_tree.rs:86-134`、`src/revoke_tree.rs:17-37`。

### 必须新增（D 设计层）

- 事件间中间根 cell 与 copy 链；当前没有 `inter_gr_roots/inter_rr_roots` 实现。
- 混合事件 type 分派（`TYPE_GRANT=1`、`TYPE_REVOKE=2`）和 9 词/5 词事件承诺的长度归一化。
- 统一 `event_count` 规则；不能沿用 C 的硬编码 1 或 B 仅靠 witness 的 1。
- ID 唯一性、重复撤销、槽位冲突约束，或明确的外部信任边界。
- 统一 epoch 规则：B 的 `≥` 与 C 的严格 `+1` 必须合并到多事件语义中。
- “Parent 当前仍未撤销”的检查；B 的 GR opening 看不到 C 的 RR 状态。
- `GR_next = GR_prev` 在 Revoke 子步与 Grant 子步之间的语义一致性规则。
- 域标签定版：代码 `D3-BATCH-v1/D3-EVENT-v1` 与文档 `...-P-v2` 的冲突必须记录。

---

## 3. UNKNOWN 与外部信任

1. D 原型是否使用递归/证明聚合桥接 B 与 C 的 vk：**UNKNOWN**，源码无实现，本阶段明确不做。
2. 中间根是否公开：R2 文档列出但未实现，设计意图未定，**UNKNOWN**；D 原型规格将给出建议但不宣称已定版。
3. `D3-BATCH-v1/D3-EVENT-v1` 与文档 `D3-BATCH-P-v2/D3-EVENT-P-v2` 哪个对 D 生效：代码为冻结实现，D 先沿用代码值；文档分歧标记为待统一。
4. B/C 组合 proof 与 D3-01 full replay 是否要求字节级等价：C 文档明确不声明；D 只要求语义对齐，**UNKNOWN/异口径**。
5. Bridge/checkpoint、跨 vk 重放、执行时并发覆盖、类别 II SHA-256 映射：均为外部信任。

---

## 4. 停止条件判定

| 停止条件 | 判定 | 依据 |
| --- | --- | --- |
| B/C 事件编码无法统一且无版本化方案 | 不触发 | batch 层相同；事件承诺层可按 type tag 版本化，见 Q5 |
| 事件顺序与 D3-01 语义冲突 | 不触发，但需显式定版 | D3-01 逐事件执行；D 采用有序列表、批次统一 epoch，见 Phase 1 |
| 多次 Merkle 更新无法连接中间根 | 不触发（设计层） | 同电路 copy 机制已验证；跨电路不做 |
| 同批次 Parent/Child 依赖无规则 | 不触发 | Phase 1 冻结“当前状态有效 Parent”规则 |
| 无法区分事件分别合法与序列整体合法 | 不触发 | 本研究阶段的核心区分，参考模型显式建模 |
| Batch Update 无法证明无更新遗漏 | 不触发（设计层） | 原型规格要求冲突/顺序/承诺约束，未声称已证明 |
| 需要改 A/B/C 冻结接口 | 不触发 | D 保持 8 instance，不改 A/B/C |

**审计边界**：本报告是代码级只读核对，不是形式化安全证明；“不存在/未实现”来自全仓检索，不以推测替代源码证据。
