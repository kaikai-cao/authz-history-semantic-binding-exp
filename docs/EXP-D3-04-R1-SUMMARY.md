# EXP-D3-04-R1 — Summary: Host Index Model Corrections

## 1. Git 与基线

- 仓库：`kaikai-cao/authz-history-semantic-binding-exp`
- 基线：`8fe8461a15dbfe6a8870f6a0a9fcd8f2b990d5df`（`exp-d3-04`）
- 工作分支：`exp-d3-04-r1`
- Phase 0 核验：HEAD=基线、工作区 clean、远端 `exp-d3-04`=基线、`exp-d3-04-r1` 尚不存在
- 冻结边界：E-R1/E-R2/R3 电路、D3-04 四份原始文档、原始测试 `tests/d3_04_index_state.rs`、A/B/C/D/E、8 public instances、事件数上限 2 均未改；本轮**未写任何 Halo2 电路**，也未做性能优化

## 2. 本轮定位

D3-04 设计验收通过，但 Phase 4 只能算 **Poseidon Merkle host 结构原型**，存在两个阻断问题：ID=0 与空槽哨兵歧义、测试用 `set()` 代替业务状态转换。本轮只修正这两点并补齐认证关系测试，使 host 层能真正**执行并拒绝非法转换**；不进入 Halo2 gadget，不替换 E-R1。

## 3. Phase 1：ID 表示与叶子编码修正

| 问题 | D3-04 原模型 | R1 修正 |
| --- | --- | --- |
| 空槽 | `full_id == F::ZERO` 当作空槽哨兵 | 显式 `Leaf::Empty` 结构变体，空槽不再由 ID 值表示 |
| ID=0 | `set(0, ACTIVE)` 未拒绝，可写入后与空槽歧义 | `slot_of/get/seed/apply_grant/apply_revoke` 全部拒绝 `F::ZERO` → `R1Error::ZeroId` |
| 叶子编码 | 未明确区分 | `Empty = (d_index, 0, 0)`；`Occupied = (d_index, full_id, state_code)`，`Absent=0 / Active=1 / Revoked=2` |

- `ABSENT` 不占用叶子：查询 ID 与槽位中 `full_id` 不等即返回 `ABSENT`；`seed(id, Absent)` 直接写 `Leaf::Empty`。
- 截断键碰撞仍显式拒绝（`R1Error::KeyCollision`），未实现桶链/线性探测。
- 新增边界测试：ID=0 在全部入口拒绝；最大合法 ID `p−1` 可读写；`p−1` 与 `id(16)` 在深度 4 同落槽 0，第二个写入返回 `KeyCollision`，根不变。

## 4. Phase 2：状态转换执行器

新增独立 host API，前置检查全部在变更之前完成，因此**非法转换不会改变索引根**：

```
apply_grant(new_id, parent_id)  // ABSENT(new) ∧ ACTIVE(parent) → new=ACTIVE
apply_revoke(target_id)         // ACTIVE(target) → target=REVOKED
```

| 错误 | 触发 |
| --- | --- |
| `ZeroId` | 任一 ID 为 0 |
| `GrantTargetActive` / `GrantTargetRevoked` | 重复 Grant / 对 REVOKED 再 Grant |
| `ParentAbsent` / `ParentRevoked` | 父授权不存在或已撤销 |
| `RevokeTargetAbsent` / `RevokeTargetRevoked` | 撤销不存在或已撤销的目标 |
| `KeyCollision` | 不同完整 ID 落入同一截断槽 |

- 两事件顺序测试：事件 0 `grant(100, parent=1)` 产出 `root1`；事件 1 以 `root1` 为输入根，看到 `100=ACTIVE`，重复 grant 被拒且根不变；随后 `revoke(1)` 产出 `root2`，再以已撤销父授权 grant 被拒且根保持 `root2`。
- `seed()` 明确标注为**可信 S0 锚定**，不是业务转换；测试仅用它构造初始状态，业务路径必须走 `apply_grant/apply_revoke`。

## 5. Phase 3：认证关系测试

新增 16 个 R1 测试（`tests/d3_04_r1_index_state.rs`），按性质分为三类，**不再把数据结构存储测试当作状态转换测试**：

| 类别 | 测试数 | 覆盖 |
| --- | --- | --- |
| 数据结构与 ID 表示 | 3 | ID=0 全入口拒绝、三种叶子哈希互异、最大合法 ID 与槽位碰撞边界 |
| 状态转换执行 | 6 | ABSENT→ACTIVE、重复 Grant、REVOKED 再 Grant、父非 ACTIVE、ACTIVE→REVOKED、重复/不存在 Revoke、两事件顺序 |
| 认证关系 | 7 | opening 重算根、空槽 non-membership、已占槽不同完整 ID 查询、截断键碰撞拒绝、伪造状态/错误路径/错误槽位、跨索引 opening 失败、根随合法转换变化 |

关键结果：
- 合法转换前后根必变；所有被拒转换前后根**严格不变**。
- 已占槽位查询不同完整 ID：槽中存 `id(7)`，查询 `id(23)`（低 4 位同为 7）→ `get` 返回 `ABSENT`；用 `Leaf::Empty` 以外的伪造叶子或错误路径/错误槽位重算根均失败。
- 截断键碰撞在一组 `(1, 17)` / slot=1 上显式拒绝，根不变。

## 6. 下一阶段 Halo2 设计约束（非本轮实现，非阻断）

用户指出的认证关系边界已记录，供后续电路设计正面处理：

1. 电路必须约束 `slot = low_t(id)`，不能让调用者自由提供 slot。
2. 必须约束叶子中的完整 `full_id` 与查询 ID 相等（成员证明）或非成员时目标槽确为空；仅验证 Merkle 路径重算公开根不足以证明目标 ID 的状态。
3. host 与电路的空槽/ID=0 编码必须完全一致：本轮采用 `Leaf::Empty` 结构变体 + ID=0 非法，电路需复用同一编码。
4. 索引根绑定 `C_prev/C_next` 的接口 B、索引三态更新与 GR/RR 双状态根同步约束仍未开始，**不预设其成本低於 E-R1 全树扫描**。

## 7. 验收

- `cargo fmt --check`：通过
- `cargo test --release`：**269 passed / 0 failed / 3 ignored**（D3-04 为 253，R1 新增 16 个，吻合）
- `git diff --check`：通过
- 修改范围：仅新增 `tests/d3_04_r1_index_state.rs` 与本文档

## 8. 结论

R1 修正完成：host 层不仅能存储和证明三态叶子，还能通过独立执行器执行并拒绝非法状态转换（重复 Grant、REVOKED 再 Grant、非 ACTIVE Parent、不存在/重复 Revoke），且非法转换前后索引根不变；ID=0 哨兵歧义已消除。仍未开始 Halo2 一致性约束与成本测量，下一步才是正式设计**索引三态更新与 GR/RR 双状态根同步的 Halo2 约束关系**，仍是设计任务，不预设它一定优于 E-R1。
