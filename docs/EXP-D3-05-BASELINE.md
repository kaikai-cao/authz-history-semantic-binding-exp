# EXP-D3-05 Phase 0 — Baseline and Existing-Implementation Audit

## 0. 范围与冻结

- 仓库：`kaikai-cao/authz-history-semantic-binding-exp`
- 基线：`7cb53354d04f7445031e5a1b2593ed07fe096f16`（`exp-d3-04-r1-c1`）
- 工作分支：`exp-d3-05`（从基线新建）
- Phase 0 核验：`git status --short --branch` 仅显示分支行（clean）；HEAD=基线；远端 `exp-d3-05` 不存在；最近 5 提交为 `7cb5335 / ff11e0d / 8fe8461 / 2bd9624 / 423da78`
- 本阶段**不写 Halo2 电路、不改任何冻结实现**；下列事实全部来自现有源码与文档，不凭空补充字段

## 1. 三种状态结构的实际数据结构

### GR — Grant Tree（`src/transition/b_types.rs`）

- 结构：`SparseTreeB`，depth=4、16 槽，叶子为 Poseidon 承诺，非 preimage
- 叶子 preimage `GrantFieldsB`：`id, issuer, subject, resource_prefix[8], scope, parent_key, epoch` + `valid: bool`
- 叶子承诺：`leaf(valid) = poseidon::<9>([d_grant_b, id, issuer, subject, prefix_f, scope, parent_key, epoch, valid?1:0])`，9 words → 3 permutations
- **GR 叶子自带 `valid` 位**：`valid=0` 是"曾存在但已撤销"的槽，仍占 GR 位置。这是 D 参考模型"撤销不删除 GR 记录"的物理对应
- 叶子哈希不能反推 `id`；要拿 ID 必须提供 preimage 并重算叶子哈希（E-R1 全树扫描正是这么做）

### RR — Revocation Tree（`src/transition/c_types.rs`）

- 结构：同为 16 槽 Poseidon 树
- 叶子 preimage `RevokeFieldsC`：`grant_id, revoker, epoch`
- 叶子承诺：`revoke_leaf_c = poseidon::<4>([d_revoke_c, grant_id, revoker, epoch])`，4 words → 2 permutations
- **RR 叶子无状态位**：存在即"该 `grant_id` 被撤销"，空槽即无记录。RR 不保存"撤销对应哪个 GR 槽位"的显式字段，关联只能靠 `grant_id` 与 GR 的 `id` 相等

### IR — ID-State Index（`tests/d3_04_r1_index_state.rs`，仅 host）

- 结构：host 侧 Poseidon Sparse Merkle，depth=4、16 槽，截断键 `slot = low_4bits(id)` = `id.to_repr()[0] & 15`
- 叶子编码：`Leaf::Empty`（结构变体，独立空槽）或 `Leaf::Occupied { full_id, state }`
- 三态：`Absent=0 / Active=1 / Revoked=2`；ABSENT 不占叶，`full_id != query_id` 也返回 ABSENT
- 叶子哈希：`poseidon::<3>([d_index, full_id, state_code])`，3 words → 2 permutations
- ID=0 在 `slot_of/get/seed/apply_grant/apply_revoke` 全入口拒绝；截断键碰撞显式拒绝（`KeyCollision`）
- 执行器：`apply_grant(new,parent)` 要 new=ABSENT 且 parent=ACTIVE；`apply_revoke(target)` 要 target=ACTIVE；前置检查先于变更，非法转换根严格不变
- `seed()` 明确标注为**可信 S0 锚定**，不是业务转换
- **IR 目前只是 host 测试模型**：无 Halo2 gadget、无电路约束、无与 GR/RR 的连接

## 2. E-R1 当前状态更新方式（`src/transition/e_r1_circuit.rs`）

- 8 个 public instances：`C_prev, prev_epoch, C_next, next_epoch, policy, transition_version, D_E, event_count`
- 状态承诺：`C_prev = poseidon([D_state, GR_prev, RR_prev, prev_epoch, policy])`，5 words → 3 permutations；`C_next` 同理取最终 GR/RR 根
- 每事件输入态的 GR/RR 各提供 16 槽 preimage，电路内重算叶子哈希与 depth-4 根，绑定到当前事件输入根 cell（`scan root binds current GR/RR`）
- 三个 ID 级缺口由全树扫描闭合：
  - Parent 未撤销：扫描 RR 每个非空 `revoke_id != parent.id`
  - Grant ID 全局唯一：扫描 GR 每个非空 `leaf.id != child.id`
  - Revoke ID 全局唯一：扫描 RR 每个非空 `revoke_id != new_revoke_id`
- 中间状态绑定：事件 1 的输入 GR/RR cell **就是**事件 0 的输出 cell（`gated_eq` + state-transition 门），不能从 host 代入 S1
- 槽位来源：`child_slot / revoke_slot / parent_slot / target_slot` 全部由 witness 指定，**电路中没有任何 `slot = low_t(id)` 约束**
- 结构指标（E-R3 已测）：K=15；fixed=9、advice=39、instance=1 列 8 值、selector=30（27 显式 + Poseidon 内部 3）；gate family=28 与 degree=3 是源码统计，constraint polys=43 来自 `pinned()` 官方视图；Poseidon permutations=505（扫描 344 / E 基线 161）

## 3. E-R2 对初始状态的补充（`src/transition/e_r2_types.rs`）

- `TransitionWitnessR2 = TransitionWitnessR1`（类型别名），**电路零改**
- `InitialRrState::from_preimages(&[(slot, RevokeFieldsC)])` 从完整 preimage 重建 RR 槽与根，并与公开 `rr_prev_be` 比对
- `from_slots()` 遇非零哈希但无 preimage 返回 `MissingPreimage(slot)`，避免生成必然失败的 witness
- `check_initial_rr_unique` / `check_initial_gr` 做 host 侧 pairwise 唯一性检查（重复槽、重复 ID、越界拒绝）
- 明确边界：这是**host 前置检查，不是电路约束**；E-R1 电路只检查"新 ID ≠ 扫描到的叶子 ID"，不 pairwise 检查已有叶子

## 4. 接口差异汇总

| 维度 | GR | RR | IR（host） |
| --- | --- | --- | --- |
| 叶子 preimage | `GrantFieldsB` 7 字段 + valid | `RevokeFieldsC` 3 字段，无状态位 | `full_id` + 三态 code |
| 叶子哈希词数 | 9 | 4 | 3 |
| 空/撤销表示 | `valid=0` 槽仍占位 | 空槽=无记录 | `Leaf::Empty`；REVOKED 是显式状态 |
| 槽位规则 | witness 指定 | witness 指定 | `slot = low_4bits(id)`（host 计算） |
| 更新 API | builder 内写槽 | builder 内写槽 | `apply_grant/apply_revoke` 执行器 |
| 认证承诺 | root（`SparseTreeB`） | root（`SparseTreeB`） | root（Poseidon SMT） |
| 电路约束 | 有（E-R1 扫描/更新） | 有（E-R1 扫描/更新） | **无** |

## 5. 已电路约束 vs 仅 host 语义

**已由 E-R1 电路约束（Halo2 可验证）：**

- GR/RR 叶子 preimage 重算与 depth-4 根重建、绑定到输入/输出根
- 新 ID 与全树非空叶子 ID 的不等（`scan-id-neq`）
- Parent 在当前 RR 中无撤销记录
- 事件 1 读取事件 0 输出的根（cell equality）
- epoch 单调、事件类型/commitment 绑定槽位、8 个 public instance

**仅有 host 语义（非电路证明）：**

- S0 的 GR/RR/IR 初始唯一性与三者一致性（E-R2 `check_*`、R1 `seed` 均为可信锚定 + 前置检查）
- IR 三态转换规则（D3-04-R1 的 `apply_grant/apply_revoke`）
- `slot = low_t(id)` 与 `leaf.full_id = id` 的绑定（IR host 模型内部成立，电路未约束）
- **IR 与 GR/RR 的一致性：完全没有定义，也没有任何约束**——这是 EXP-D3-05 要解决的核心问题

## 6. 本阶段不得混淆的边界

1. D3-04-R1 的 16/16 测试通过是 **host 结构测试**，不是 Halo2 证明。
2. E-R2 的初始 RR 重建是 **builder 修复**，电路关系未变。
3. "三棵树 root 一致"不等于"表达同一事件"——root 只是承诺值，字段相等关系必须显式约束（Phase 3）。
4. IR 的局部 opening 不能替代 GR/RR 完整授权语义（issuer/subject/scope/resource/parent 都在 GR 叶子中，IR 只存三态）。
