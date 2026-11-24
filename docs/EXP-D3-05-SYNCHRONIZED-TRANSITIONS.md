# EXP-D3-05 Phase 2 — Synchronized Update Relations for Grant / Revoke

## 0. 记号与失败原子性

- 事件 `e` 统一携带：`type ∈ {GRANT, REVOKE}`、`epoch`、`event_id`（见 §3 分析）
- 三棵树的更新写为 `GR' = Update_GR(GR,e)`、`RR' = Update_RR(RR,e)`、`IR' = Update_IR(IR,e)`
- **失败原子性要求**：若任一前置条件不满足，三棵树**全部不改变**（根严格保持输入值）。D3-04-R1 已实现 host 层"前置检查先于变更"；电路层必须由同一 event flag 门控三支路，不允许任何单树局部落盘

## 1. Grant 事件

### 输入

```
e_G = (id, issuer, subject, resource, scope, parent, epoch)
```

实际字段对齐 `GrantFieldsB`：`id, issuer, subject, resource_prefix[8], scope, parent_key, epoch`；`parent_key = key_field(parent_id)`，根授权为 `F::ZERO`。`id` 是完整 `F` 元素（合法 ID ≠ 0）。

### 期望的三树更新

\[
GR'=Update_{GR}(GR,e_G),\qquad RR'=RR,\qquad IR'=Update_{IR}(IR,e_G)
\]

### 前置条件清单（缺一即整批拒绝）

| # | 条件 | 由谁闭合（当前） | IR 方案下应由谁闭合 |
| --- | --- | --- | --- |
| G1 | 新 `id` 在 GR 中不存在（完整 ID 比较） | E-R1 GR 全树扫描 `scan-id-neq` | `IR(id)=ABSENT`（仍需绑定 GR 中确无该 ID） |
| G2 | 新 `id` 在 IR 中为 ABSENT | 无 IR | IR opening at `low_t(id)` = Empty 或不同 full_id |
| G3 | Parent 在 GR 中存在（打开 GR 叶子） | E-R1 GR opening | GR opening（IR 不能替代授权内容） |
| G4 | Parent 在 RR 中无撤销记录 | E-R1 RR 全树扫描 | `IR(parent)=ACTIVE` **且** RR 中无记录（二者需一致） |
| G5 | Parent 在 IR 中为 ACTIVE | 无 IR | IR opening at `low_t(parent)` = ACTIVE |
| G6 | GR 更新叶子 ID == IR 更新叶子 ID == `e_G.id` | E-R1 只更新 GR | 三支路字段相等约束（Phase 3） |
| G7 | IR 更新后状态为 ACTIVE | 无 IR | IR 更新约束 |
| G8 | `RR'=RR`（Grant 不得写 RR） | E-R1 Grant 分支不写 RR | RR 更新 flag=REVOKE 门控，Grant 时零变化 |
| G9 | 三结构 epoch 一致且 == `e_G.epoch` | E-R1 批次 epoch 统一 | 字段相等约束 |
| G10 | 三结构绑定同一 `event_id` / 类型 GRANT | 无显式 event_id | 见 §3 |

### 前置条件之间的冗余与不可省

- G1 与 G2 在 S0 满足不变量时逻辑等价（§2 关系 1），但**电路里不能只留其一**：只查 IR 会把"IR 声称 ABSENT 但 GR 实际有该 ID"的伪造状态放过（N06 同源）；只查 GR 则 IR 支路可写入不一致状态（N01）
- G4 与 G5 同理：IR 的 ACTIVE 是可信 S0 前提下 Parent 有效的捷径，但 RR 是撤销事实的直接载体，二者必须一致（N06）
- G3 不可被 G5 替代：IR 只存三态，Parent 的授权内容（issuer/subject/scope）在 GR 叶子中，Parent 有效性检查需要 GR opening

### 输出（成功后）

- `GR'`：在 witness 指定的 `child_slot` 写 `child.leaf(true)`；全树 root 重算
- `RR'`：与 `RR` 完全相同（root cell 相等约束）
- `IR'`：在 `low_t(id)` 写 `Occupied{full_id=id, ACTIVE}`；IR root 重算
- `epoch_next = epoch_prev + 1`（沿用 D 批次统一递增）
- 事件类型 commitment、800 系列 policy/version gate 沿用 E-R1，不新增 public instance（除接口 B 下 IR 并入 C）

## 2. Revoke 事件

### 输入

```
e_R = (grant_id, revoker, epoch)
```

字段对齐 `RevokeFieldsC`：`grant_id, revoker, epoch`。

### 期望的三树更新

\[
GR'=GR,\qquad RR'=Update_{RR}(RR,e_R),\qquad IR'=Update_{IR}(IR,e_R)
\]

### 前置条件清单

| # | 条件 | 由谁闭合（当前） | IR 方案下应由谁闭合 |
| --- | --- | --- | --- |
| R1 | 目标 Grant 在 GR 中存在 | E-R1 target GR opening | GR opening at witness slot（需绑定 `slot` 与 `id`） |
| R2 | 目标在 RR 中无记录（未撤销） | E-R1 RR 全树扫描 | `IR(target)=ACTIVE` 且 RR 中无记录 |
| R3 | 目标 IR 状态为 ACTIVE | 无 IR | IR opening = ACTIVE |
| R4 | `revoker` 与 Grant 的 issuer 满足协议规则 | E-R1 不含 revoker 权限检查（外部信任） | **仍需外部/独立约束**，IR 不携带 issuer；不可声称 IR 解决 |
| R5 | RR 更新目标 ID == IR 更新目标 ID == `e_R.grant_id` | E-R1 只更新 RR | 三支路字段相等约束 |
| R6 | RR 更新后为"已撤销"叶，IR 更新后为 REVOKED | E-R1 写 `revoke.leaf()` | 各自更新约束 + 状态一致 |
| R7 | 重复撤销拒绝 | E-R1 RR 扫描 `revoke_id != new` | `IR(target)≠ACTIVE` 前置拒绝 |
| R8 | `GR'=GR`（Revoke 不改 GR，valid 位不变） | E-R1 Revoke 分支不写 GR | GR 更新 flag=GRANT 门控，Revoke 时零变化 |
| R9 | 三结构 epoch 一致 | E-R1 批次统一 | 字段相等约束 |

**R4 必须诚实标注**：IR 叶子只有三态，不含 issuer。即使有 IR，revoker 权限仍需 GR 叶子的 `issuer` 字段或外部 policy 提供；本阶段不把它写成"IR 方案已解决"。

### 输出（成功后）

- `GR'`：与 `GR` 完全相同
- `RR'`：在 witness 指定 `revoke_slot` 写 `revoke.leaf()`；全树 root 重算
- `IR'`：在 `low_t(grant_id)` 写 `Occupied{full_id=grant_id, REVOKED}`；IR root 重算
- `epoch_next = epoch_prev + 1`

## 3. 同事件绑定与 `event_id`

### `event_id` 是否需要作为电路输入或承诺字段

- E-R1 当前**没有**独立 `event_id`；事件区分靠 `event_commitment = poseidon([d_event, type, fields…, epoch])` 与 batch slot 绑定，8 个 instance 中的 `D_E` 是整批承诺
- 若引入 IR 三支路，三棵树必须绑定"同一事件"，可选两种做法：
  - **方案 i（不加 instance）**：把 `event_commitment`（已含 type/ID/epoch/字段）作为三支路共享的内部 cell，由同一 flag 门控；不新增 public instance，但**不提供**跨证明的事件唯一性（同一事件 commitment 可重放，需外部 nonce/新鲜性，与 E-R1 现状一致）
  - **方案 ii（加承诺字段）**：把 `event_id` 并入 `C_prev/C_next` 的状态承诺输入（`C = H(..., IR, event_id, ...)`），保持 8 个 public value 数量不变，但改变承诺语义 → 需要 `D3-STATE-v2` 域版本
- 本阶段**不强制**新增 `event_id` 为独立 public instance；优先方案 i + 接口 B 的 v2 承诺，把"是否加 nonce"列为未解决的新鲜性问题（与 E-R1 边界一致）

### 绑定要求（无论选哪种）

- 三支路使用**同一个** `type` flag（GRANT 控制 GR 写 / IR→ACTIVE；REVOKE 控制 RR 写 / IR→REVOKED）
- 三支路使用**同一个** ID cell：Grant 时为 `e_G.id`，Revoke 时为 `e_R.grant_id`
- 三支路使用**同一个** `epoch` cell == `epoch_next`
- 事件 1 的三棵树输入根 cell 分别 == 事件 0 的对应输出根 cell（三条 equality，不只 GR/RR 两条）

## 4. 多事件顺序语义（状态机级，不要求三事件电路）

| 序列 | 预期 | 依据 |
| --- | --- | --- |
| `Grant(A) → Revoke(A)` | 接受 | 事件 0 写 `IR(A)=ACTIVE`，事件 1 读该状态并转 REVOKED；RR 加记录、GR 不变 |
| `Revoke(A) → Grant(B, Parent=A)` | 拒绝事件 1 | 事件 0 后 `IR(A)=REVOKED`，G4/G5 失败；E-R1 现有 RR 扫描同样拒绝 |
| `Grant(A) → Grant(B, Parent=A)` | 接受 | A 为 ACTIVE，满足 Parent 条件；IR 增 ACTIVE 叶 |
| `Grant(A) → Revoke(A) → Grant(B, Parent=A)` | 拒绝事件 3 | A 已 REVOKED，Parent 检查失败；**该序列为三事件，超出当前最多两事件电路限制，仅做状态机语义分析，不实现** |

**顺序约束**：IR 的事件 1 输入必须来自事件 0 的 IR 输出 cell；若从 S0 重建事件 1 的 IR 输入（等于忽略事件 0 的 IR 更新），可产生 N14 类攻击。

## 5. 失败时的局部更新

- 禁止任何"GR 成功但 IR 未更新"、"RR 成功但 IR 未更新"、"IR 成功但 GR/RR 未更新"的中间态（N09/N10/N11）
- 实现手段：三支路更新由同一 event flag + 同一组前置条件 cell 门控；任一前置失败 → flag=0 → 三棵树都不写
- 这一"全有或全无"由单电路内的 cell 共享天然保证（同一 synthesize 中 flag 统一），**不需要跨存储原子性声明**；但若未来拆成多电路/多交易，则需另立原子性协议，属本阶段边界之外
