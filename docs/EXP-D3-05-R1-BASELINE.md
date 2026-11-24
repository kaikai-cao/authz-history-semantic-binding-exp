# EXP-D3-05-R1 Phase 0 — 基线核验与结构差异

## 0. 执行记录

在本轮分支上执行：

```text
git status --short --branch
→ ## exp-d3-05...origin/exp-d3-05（执行时 clean）

git rev-parse HEAD
→ 81b6d0d401bc44f16cb45e0d109639bdbee494d0

git rev-parse origin/main
→ 09612dbb26422d14cc5628cb39f7ce444be159b5

git log -5 --oneline
→ 81b6d0d EXP-D3-05: design GR/RR/IR synchronization constraints
→ 7cb5335 EXP-D3-04-R1-C1: exercise empty-slot non-membership opening
→ ff11e0d EXP-D3-04-R1: fix index sentinel and add transition executor
→ 8fe8461 EXP-D3-04: design authenticated ID-state index structure
→ 2bd9624 EXP-D3-03-E-R3: attribute full-scan cost and compare alternatives
```

随后从该基线建立本轮分支：

```text
git switch -c exp-d3-05-r1-induction-audit 81b6d0d401bc44f16cb45e0d109639bdbee494d0
git status --short --branch
→ ## exp-d3-05-r1-induction-audit（clean，未跟踪远端）
```

**`origin/main` 状态说明**：远端 `main` 仍指向 `09612db`（D3-01 参考实现），本系列 D3-02 至 D3-05 工作全部在 `exp-d3-*` 功能分支上推进，未合并 `main`。这不是本轮的异常；本轮基线是本轮指定的 `81b6d0d`，且固定上游提交（E-R1 `edf4b06`、E-R2 `423da78`、R3 `2bd9624`、D3-04 `8fe8461`、D3-04-R1 `ff11e0d`、R1-C1 `7cb5335`、D3-05 `81b6d0d`）均未改动。

## 1. 读取材料

本轮实际读取：

- `docs/EXP-D3-05-STATE-INVARIANTS.md`
- `docs/EXP-D3-05-SYNCHRONIZED-TRANSITIONS.md`
- `docs/EXP-D3-05-HALO2-RELATION-DESIGN.md`
- `docs/EXP-D3-05-NEGATIVE-CASES.md`
- `docs/EXP-D3-05-COST-MODEL.md`
- `docs/EXP-D3-05-DECISION.md`
- `src/transition/e_r1_circuit.rs`（重点 1470–1631 行全树扫描段）
- `src/transition/e_r1_uniqueness.rs`
- `src/transition/e_r2_types.rs`
- `src/transition/b_types.rs`、`src/transition/c_types.rs`（叶结构与槽位语义）
- `tests/d3_04_r1_index_state.rs`（host 索引模型与 16 个测试）

## 2. 三种结构的真实差异

| 结构 | 叶子 / preimage | 槽位语义 | 状态表达 | 关键事实 |
| --- | --- | --- | --- | --- |
| **GR** | `GrantFieldsB::{id, issuer, subject, resource_prefix[8], scope, parent_key, epoch}` + `valid` 位；`leaf(valid)` 为 9-word Poseidon | 深度 4、16 槽；`child_slot` / `parent_slot` 由 witness 指定 | 授权内容在叶内；E-R1/E-R2 路径中已占叶一律写 `leaf(true)` | `valid=0` 编码存在但当前语义未使用；撤销只写 RR 不改 GR（`e_r2_types.rs:204-210`） |
| **RR** | `RevokeFieldsC::{grant_id, revoker, epoch}`；4-word Poseidon | 深度 4、16 槽；`revoke_slot` 由 witness 指定 | 只记录“某 grant_id 已被撤销”，无状态位、无 GR 槽位字段 | 叶子不含 issuer/scope/parent，不能表达授权内容；孤立 RR 在 S0 可由 builder 注入（E-R2 只查 RR 内部唯一性） |
| **IR** | `Leaf::Empty` 或 `Occupied{full_id, state∈{ABSENT,ACTIVE,REVOKED}}`；3-word Poseidon | `slot = low_t(full_id)`（`slot_of` 取 `to_repr()[0] & (cap-1)`）；截断键碰撞显式拒绝 | 只表达三态，不表达授权内容 | `ID=0` 全入口拒绝；`seed()` 是可信 S0 锚定而非业务转换；`apply_grant/apply_revoke` 前置检查先于变更 |

**最重要的口径**：`low_t(id)` 只属于 IR。GR/RR 的槽位是各自 witness 给出的 Merkle 位置，E-R1 没有把它们约束成 `low_t(id)`；任何“把 GR/RR opening 改成 IR 槽位映射”的写法都是未经证明的结构改写。GR/RR opening 必须绑定**完整 ID**与正确的 Merkle root，但保留自己的槽位语义。

## 3. E-R1 当前实际闭合了什么

从 `e_r1_circuit.rs` 逐行核对（非引用二手结论）：

1. **GR Grant 唯一性**：16 个 GR 叶 preimage 全部在电路内重算叶哈希并重算根，`scan-id-neq` 以 `grant_cells[i]` 门控，逐个证明非空叶 `grant.id != child.id`；根由 `grant scan root binds current GR` 绑到 `gr_in[i]`。
2. **RR 撤销有效性（Grant 分支）**：16 个 RR 叶 preimage 全部重算，`scan-id-neq` 证明每个非空叶 `grant_id != parent.id`；根既由 `revoke scan root binds current RR` 也由 `parent scan root binds current RR` 绑定，因此 Grant 事件确实检查 Parent 未撤销。
3. **RR 重复撤销（Revoke 分支）**：同一扫描证明每个非空叶 `grant_id != revoke.grant_id`。
4. **局部 opening**：Parent/child/target 的 GR opening、RR 旧槽/新槽 opening 仍存在，门控分别绑到输入根；新根由 `state-transition` 更新。
5. **事件链**：GR/RR 输入根在事件 1 处接事件 0 输出根；IR 尚无对应链，因为 E-R1 没有 IR。

因此 E-R1 的 344 次全树扫描相关置换买的是三件事：**新 Grant ID 全局唯一**、**Parent 未撤销**、**重复 Revoke 拒绝**。这三件正是本轮要判断能否由 IR 归纳继承的性质。

## 4. S0 边界（来自 E-R2 / D3-04-R1）

- E-R2 `InitialRrState::from_preimages` 检查 RR 槽位越界、槽位重复、`grant_id` 重复、hash-only RR；`build_scenario_r2` 另检查 GR 槽位越界/重复/ID 重复并核对公开 RR 根。
- **未检查**：每条 S0 RR 记录的 `grant_id` 是否在 GR 中存在；GR/RR 与 IR 之间的三态一致性；IR 与 GR/RR 之间的完整 ID 对应。
- D3-04-R1 `seed()` 只建立 IR 内部状态，且自己是“可信 S0 锚定”，不是业务转换。
- 结论：S0 三态一致性目前是**外部信任前提**，不是已证明事实。本轮把它作为明确前提，不把它包装成电路结论。

## 5. Phase 0 结论

结构差异清楚，源码事实与 D3-05 设计文档一致，且没有发现上一轮对源码的误读。下一阶段在此基线上做严格不变量定义与归纳证明，不修改任何冻结实现。
