# EXP-D3-05-R1 Phase 3 — 局部 opening 是否足以支撑归纳证明

## 1. 逐个操作的认证需求

| 操作 | 必须认证的事实 | 局部 opening / 约束 | 是否需全树扫描 |
| --- | --- | --- | --- |
| Grant 新 ID | `IR(id)=ABSENT`，且槽未被另一个完整 ID 占用；GR 中确无该完整 ID | IR opening at `low_t(id)`：叶 `Empty` 或 `full_id==id`；`ir-slot-low-t`、`ir-full-id-eq`；GR child-slot 空 opening | 否。GR 唯一性由不变量继承，child-slot 空由局部 opening 保证 |
| Grant Parent | GR Parent 叶真实且授权内容正确；`IR(parent)=ACTIVE` | GR Parent opening（完整 ID 与 root 绑定）+ IR Parent opening（完整 ID、状态、root） | 否。不需要打开 RR 全树 |
| Revoke 目标 | GR 目标叶真实；`IR(id)=ACTIVE` | GR target opening + IR target opening | 否 |
| Revoke 更新 | RR 新叶写入 `grant_id=id`；IR 写 `REVOKED`；两者同一事件 | RR 旧槽空 opening + RR 新根重算；IR 新叶重算 + IR 新根重算；`cross-id-eq`、`pre-ok-gate` | RR 局部写 opening 需要；RR 全树扫描不需要 |
| 事件连接 | 事件 1 读事件 0 的三棵树输出根 | `GR_in[1]==GR_out[0]`、`RR_in[1]==RR_out[0]`、`IR_in[1]==IR_out[0]`；`C_v2` 绑定三根 | 否 |

## 2. 核心问题：IR 已证明 Parent 为 ACTIVE，还需打开 RR 吗？

需要分清三种“打开”：

1. **RR 全树扫描**（E-R1 的 16 叶 preimage + 根重算）：为了证明 `parent∉R`。
2. **RR 单点 opening**：为了在 Revoke 时写新叶并重算根，或证明目标槽为空。
3. **RR 语义查询**：判断某 ID 是否已在 RR 中。

本轮结论：

- 在 `Inv(S_i)` 成立且归纳步被约束保持的前提下，`IR_i(parent)=ACTIVE` 由 (C2) 蕴含 `parent∈G_i∧parent∉R_i`，所以**第 1 类 RR 全树扫描可以去掉**。
- 第 2 类 RR 单点 opening **仍然需要**，因为 Revoke 必须写 RR 叶、防覆盖并重算根；这与“是否扫描 RR”是两件事。
- 第 3 类语义查询由 IR 状态承担，不再逐事件查 RR。

该结论依赖完整链条：

\[
S_0\text{ 正确} \;\Rightarrow\; S_i\text{ 正确} \;\Rightarrow\; S_{i+1}\text{ 正确},
\]

且

\[
IR_i(parent)=ACTIVE \Rightarrow parent\notin R_i.
\]

**不能**因为 IR 有一条 Merkle opening 就自动认为它能证明 RR 中不存在该 ID。单独的 opening 只证明“IR 树里某叶重算出某个根”；上述蕴含关系来自不变量与归纳证明，不来自哈希路径本身。

## 3. 每个 opening 的四字段绑定

沿用 D3-05 的四字段要求，本轮进一步明确：

| 字段 | IR | GR | RR |
| --- | --- | --- | --- |
| `root` | 当前事件输入 IR 根，来自 `C_v2` 或事件链 | 当前事件输入 GR 根 | 当前事件输入 RR 根 |
| `key` | 完整 `full_id`，必须 == 事件 ID | 完整 `grant.id`，必须 == Parent/target ID | 完整 `grant_id`，必须 == 事件 ID |
| `slot` | **必须** `low_t(full_id)` | 由 witness 指定，但须与路径一致；不强制改成 `low_t(id)` | 由 witness 指定，但须与路径一致；不强制改成 `low_t(id)` |
| `leaf` | 电路内重算 `poseidon([D_INDEX,full_id,state])`，并约束 state ∈ {0,1,2} | 电路内重算 9-word 叶，`valid=1` | 电路内重算 4-word 叶 |

### 3.1 上一轮设计问题的修正

D3-05 曾写“每个 opening 必须约束 `slot=low_t(key)`”。本轮修正为：

- `slot=low_t(id)` 只对 **IR** 成立；
- GR/RR 保留各自已有的槽位语义，由 witness 指定，但必须通过路径重算绑定到正确 root，并绑定完整 ID；
- 不得未经证明强行把 GR/RR 槽位改写为 IR 的低位映射。

这不影响归纳证明：GR/RR 的槽位只承担“写哪里、路径是否自洽”，不承担“ID 属于哪个桶”。ID 归属由完整 ID 与 IR 三态承担。

### 3.2 截断键碰撞的局部处理

若 `IR(id)=ABSENT` 但 `low_t(id)` 槽被 `B≠id` 占用：

- host 模型 `get(id)` 返回 `ABSENT`；
- `apply_grant` 另有 `KeyCollision` 前置拒绝，根不变；
- 电路必须实现同样的拒绝：Grant 时要求目标 IR 叶为 `Empty`（或 `full_id==id`），不能只查 `get()` 语义。

这是局部 opening 可判定的条件，不需要扫描全树。若省略，I06/I12 成立。

## 4. 事件间状态连接

E-R1 已有 GR/RR 两条根连接；IR 方案必须新增第三条，并把 IR 根放进状态承诺：

\[
C_{v2}=H(D_{state}^{v2},GR,RR,IR,epoch,policy).
\]

若 `C_prev/C_next` 不含 IR 根，验证器无法绑定事件 0 与事件 1 的 IR 输入/输出，事件 1 可从 S0 重建 IR 状态，I11 成立。接口 B 保持 8 个 public value 数量不变，但改变承诺语义，需 `D3-STATE-v2` 域分离与 `transition_version` 版本区分。

## 5. 必须存在的约束族（设计需求，不是已实现事实）

1. `ir-leaf-hash` / `ir-state-range`：IR 叶重算与三态合法值。
2. `ir-slot-low-t`：`slot=low_t(full_id)` 的位分解（仅 IR）。
3. `ir-full-id-eq`：叶内完整 ID == 查询/事件 ID。
4. `ir-state-transition`：Grant 仅 `ABSENT→ACTIVE`，Revoke 仅 `ACTIVE→REVOKED`。
5. `ir-collision-reject`：目标槽被异 ID 占用时拒绝写入。
6. `cross-id-eq` / `cross-epoch-eq` / 同 flag 门控：三支路同一事件。
7. `pre-ok-gate`：失败时三棵树根都不变。
8. `three-root-chain` + `C_v2`：三棵树跨事件连接与承诺绑定。

## 6. 本阶段结论

**局部 opening 足以支撑归纳证明**，条件是上述 8 类约束全部存在，且 `Inv(S0)` 由可信锚定与一次性 host 检查建立。由此：

- 不再需要逐事件全树扫描 GR/RR 来证明 ID 唯一性与 Parent 未撤销；
- 仍需 GR Parent/target 与 RR 写槽的局部 opening；
- IR 的引入不是“靠一条 Merkle opening 证明 RR 不存在”，而是把全局事实转化为可信初始状态上的归纳不变量。

约束尚未写进 Halo2；本结论是设计审查结论，不是电路安全证明。
