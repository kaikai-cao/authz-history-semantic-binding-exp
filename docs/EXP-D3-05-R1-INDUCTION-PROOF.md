# EXP-D3-05-R1 Phase 2 — Grant / Revoke 的归纳保持性证明

## 0. 证明目标与前提

设 `Inv(S)` 表示 `GLOBAL-INVARIANTS.md` 中的 (C0)–(C3) 及下列结构前提：

- (U1) GR 内完整 ID 唯一；RR 内 `grant_id` 唯一；
- (U2) IR 无截断键碰撞：每个占用槽的 `full_id` 唯一，且 `slot=low_t(full_id)`；
- (U3) 已占 GR 叶一律 `valid=1`；
- (U4) S0 由可信锚定提供，`Inv(S0)` 成立（当前 host 只部分检查，见 Baseline §4）。

要证：若 `Inv(S_i)` 成立，事件 `e` 的局部同步更新产生 `S_{i+1}`，且满足本轮列出的事件前置条件，则 `Inv(S_{i+1})` 成立。

**基例不是电路证明**。`Inv(S0)` 是外部前提；本轮只审查归纳步。

## 1. Grant 事件

### 1.1 前置不变量与事件前置条件

前置不变量：`Inv(S)`。

事件 `e_G = (id, issuer, subject, prefix, scope, parent, epoch)` 的前置条件（**比任务书多一条 U2 相关项**）：

| 编号 | 条件 | 来源 |
| --- | --- | --- |
| G-pre1 | `IR(id)=ABSENT` | 任务书 |
| G-pre2 | `id∉G` | 由 G-pre1 + (C1) 推出；仍需 GR 侧独立认证 |
| G-pre3 | `IR(parent)=ACTIVE` | 任务书 |
| G-pre4 | `parent∈G ∧ parent∉R` | 由 G-pre3 + (C2) 推出；Parent 授权内容仍需 GR opening |
| **G-pre5** | `low_t(id)` 槽为空，或叶内 `full_id==id` | **新增**：D3-04-R1 的 `KeyCollision` 拒绝；`IR(id)=ABSENT` 单独不够 |
| G-pre6 | GR 中 `child_slot` 为空，且新 GR 叶完整 ID == `id` | E-R1 已有 child-slot 空 opening；IR 方案仍需保留 |

G-pre5 是必须补充的：若 `low_t(id)` 槽被另一个完整 ID `B` 占用，`get(id)` 返回 `ABSENT`，但写入会销毁 `B` 的状态。只写 `IR(id)=ABSENT` 会放过 I06/I12。

### 1.2 状态转换

\[
G'=G\cup\{id\},\qquad R'=R,\qquad I'(id)=ACTIVE,
\]

其他 ID 的 `I` 不变；GR 在 `child_slot` 写 `leaf(true)`，RR 不变，IR 在 `low_t(id)` 写 `Occupied{id,ACTIVE}`。

### 1.3 七项证明义务

| # | 义务 | 证明 | 状态 |
| --- | --- | --- | --- |
| 1 | 新 ID 原先不在 GR | G-pre1 + (C1) ⇒ `id∉G`；GR 侧另由 child-slot 空 opening 保证不覆盖 | 条件闭合 |
| 2 | 新 ID 原先不在 RR | (C0) 且 `id∉G` ⇒ `id∉R`；等价地 G-pre1 收紧后的 (C1') 直接给出 | 条件闭合 |
| 3 | 新 ID 原先不在 IR | G-pre1，且 G-pre5 排除“同槽异 ID 的 ABSENT” | 条件闭合 |
| 4 | 新 ID 不覆盖另一完整 ID | G-pre5（IR 槽）+ G-pre6（GR 槽）分别局部 opening | 条件闭合，需电路约束 |
| 5 | Parent 更新前有效 | G-pre3 + (C2) ⇒ `parent∈G∧parent∉R`；授权内容由 GR Parent opening 提供 | 条件闭合 |
| 6 | 新 GR 叶与新 IR 叶绑定同一 ID | 三支路 `cross-id-eq`：`id_GR==id_IR==e_G.id` | 设计可证，电路未实现 |
| 7 | 其他 ID 三态关系不变 | 只改 `id` 对应的 GR/IR 槽；`parent` 槽只读；RR 完全不变；故对 `x≠id`，`(x∈G',x∈R',I'(x))=(x∈G,x∈R,I(x))` | 条件闭合 |

### 1.4 事件后不变量

对 `x=id`：`x∈G'`、`x∉R'`、`I'(x)=ACTIVE`，满足 (C2)；对 `x=parent`：未改，仍满足 (C2)；对其它 `x`：三元组不变。`R'⊆G'` 因 `R'=R⊆G⊆G'`。U1/U2/U3 由 G-pre5/G-pre6 与同 flag 门控保持。故 `Inv(S')` 成立。

## 2. Revoke 事件

### 2.1 前置条件

| 编号 | 条件 | 来源 |
| --- | --- | --- |
| R-pre1 | `IR(id)=ACTIVE` | 任务书 |
| R-pre2 | `id∈G` | 由 R-pre1 + (C2) 推出 |
| R-pre3 | `id∉R` | 由 R-pre1 + (C2) 推出；这是“无重复撤销”的关键 |
| R-pre4 | GR 目标叶真实且完整 ID == `id` | E-R1 已有 target opening；IR 不携带授权内容，不能替代 |
| R-pre5 | RR `revoke_slot` 为空 | E-R1 已有 RR 旧槽空 opening；保留即可 |
| R-pre6 | `revoker` 权限 | E-R1 外部信任；IR 不含 issuer，不解决 |

### 2.2 状态转换

\[
G'=G,\qquad R'=R\cup\{id\},\qquad I'(id)=REVOKED,
\]

GR 不变，RR 在 witness 指定槽写撤销叶，IR 在 `low_t(id)` 写 `REVOKED`。

### 2.3 六项证明义务

| # | 义务 | 证明 | 状态 |
| --- | --- | --- | --- |
| 1 | 目标存在于 GR | R-pre4 局部 GR opening；R-pre1+(C2) 给出集合层事实 | 条件闭合 |
| 2 | 目标原先无撤销记录 | R-pre1+(C2) ⇒ `id∉R`，无需扫描 RR | 条件闭合 |
| 3 | 目标 IR 为 ACTIVE | R-pre1，由 IR opening 认证 | 条件闭合 |
| 4 | RR 新记录与 IR 更新绑定同一完整 ID | 三支路 `cross-id-eq` 的 Revoke 形式 | 设计可证，电路未实现 |
| 5 | 其他 ID 三态关系不变 | 只改 `id` 的 RR/IR 槽，GR 不变；`x≠id` 三元组不变 | 条件闭合 |
| 6 | 重复撤销拒绝 | 第二次 Revoke 时 `IR(id)=REVOKED≠ACTIVE`，R-pre1 失败 | 条件闭合 |

### 2.4 事件后不变量

`x=id`：`x∈G'`、`x∈R'`、`I'(x)=REVOKED`，满足 (C3)；其他三元组不变；`R'⊆G'` 因 `id∈G`。故 `Inv(S')` 成立。

## 3. 不能跳过的证明义务汇总

每步转换都必须同时具备下表六项，缺一即标记未闭合：

| 项目 | Grant | Revoke | 当前状态 |
| --- | --- | --- | --- |
| 前置不变量 | `Inv(S)` | `Inv(S)` | S0 外部信任；归纳步可证 |
| 事件前置条件 | G-pre1..6 | R-pre1..6 | G-pre5/R-pre5 需局部 opening |
| 状态转换 | 三树同 flag 更新 | 三树同 flag 更新 | host 执行器有；电路未实现 |
| 事件后不变量 | 已证（条件） | 已证（条件） | 依赖前三项 |
| 外部信任假设 | `key_field` 单射、S0 锚定、revoker 权限（Revoke） | 同左 | 与 E-R1 边界一致 |
| Halo2 约束需求 | `cross-id-eq`、`ir-state-transition`、`ir-slot-low-t`、`ir-full-id-eq`、`pre-ok-gate`、三条根链、`C_v2` | 同左 | **设计级，未实现** |

**未闭合项判定**：

- 数学归纳步在 `Inv(S)` 与上述前置条件下**闭合**。
- GR/RR 全树扫描不是归纳步的必要条件：ID 唯一性与撤销有效性由 IR 三态 + 归纳不变量继承；局部 opening 只负责防止槽位覆盖与认证授权内容。
- 尚未闭合的是工程/认证落地项：S0 跨结构一致性检查尚未实现；IR 相关 Halo2 约束尚未实现；`C_v2` 与 IR 事件链尚未实现。这些不改变归纳证明本身的成立性，但决定能否进入原型。

## 4. 与上一轮 B 决策的关系

D3-05 的核心阻断写作“IR↔RR 一致性没有无需全树扫描的证明路径”。本轮证明了这条路径就是**可信 S0 + 归纳保持 + 局部同步更新**：每一步不需要打开 RR 全树来证明 `x∉R`，因为 `IR(x)=ACTIVE` 与不变量共同蕴含它。上一轮的阻断因此从“逻辑不可能”降级为“约束与初始检查尚未落地”。这不削弱 E-R1 作为语义基线；它只说明 IR 路线不是死路。
