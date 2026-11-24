# EXP-D3-05 Phase 4 — Adversarial Counterexamples and Negative-Validation Design

> 每个反例按四要素展开：① 攻击者可控 witness；② 应拒绝的具体约束；③ 若无约束造成的状态不一致；④ 需新增的约束或信任假设。
> 本阶段只做设计，**未实现电路、未运行负向测试**；"拒绝"指设计中的约束应当拒绝，不是已验证事实。

## N01 — GR 更新 A，IR 更新 B

1. 攻击者控制：GR 支路 `id=A`、IR 支路 `id=B`，两条 Merkle 路径各自自洽
2. 拒绝约束：`cross-id-eq`：`id_GR == id_IR == e.id`（Phase 3 §2 约束 1）
3. 无约束后果：GR 记录 A 授权但 IR 把 B 标 ACTIVE；后续查 B 得到虚假有效状态，查 A 得到 ABSENT → 授权状态被静默改写
4. 新增：三支路共享 ID cell 的相等约束；不能只靠 host witness 同名字段

## N02 — RR 更新 A，IR 更新 B

1. 攻击者控制：RR 支路 `grant_id=A`、IR 支路 `id=B`
2. 拒绝约束：`cross-id-eq` 的 Revoke 形式：`id_RR == id_IR == e_R.grant_id`
3. 无约束后果：A 被撤销但 IR 显示 B=REVOKED；A 在 RR 中撤销却仍 IR=ACTIVE → 可继续作为 Parent
4. 新增：同 N01，Revoke 类型下同样门控

## N03 — IR 从 ABSENT 直接变 REVOKED

1. 攻击者控制：IR 旧叶=Empty，新叶 state=2，跳过 ACTIVE 阶段
2. 拒绝约束：`ir-state-transition`：`state' = f(state, type)`，Revoke 要求 `state==ACTIVE`；Grant 要求 `state==ABSENT`
3. 无约束后果：可对从未授权的 ID 写入 REVOKED；与 GR 无对应记录，破坏 §2 一致性
4. 新增：IR 状态转换门（D3-04-R1 的 `apply_revoke` 前置检查需电路化）

## N04 — IR 从 REVOKED 重新变 ACTIVE

1. 攻击者控制：IR 旧叶 state=2，新叶 state=1
2. 拒绝约束：`ir-state-transition`：Grant 仅允许 `ABSENT→ACTIVE`
3. 无约束后果：已撤销 ID 被复活，违反"撤销永久"不变量；D 参考模型的 `DuplicateGrant` 被绕过
4. 新增：同 N03；需 range 约束保证 state ∈ {0,1,2}

## N05 — Parent 已撤销但 GR 中仍存在

1. 攻击者控制：打开 GR 中 Parent 叶子（valid=1）作为 Parent 证据，但 RR 中已有该 `grant_id` 的撤销记录
2. 拒绝约束：Parent 有效性需同时满足 GR 存在 ∧ RR 无记录（E-R1 RR 扫描 `scan-id-neq @ parent not revoked`）；IR 方案下需 `IR(parent)=ACTIVE` 且与 RR 一致
3. 无约束后果：从已撤销 Parent 派生子授权，撤销的语义链式失效（这不是 Cascade，但破坏 Parent 有效性）
4. 新增：保留 E-R1 的 RR 扫描，或证明 IR↔RR 一致的电路关系（Phase 3 §5 阻断项 1）

## N06 — IR 声称 Parent ACTIVE，但 RR 中已有撤销记录

1. 攻击者控制：伪造 IR opening 使 `IR(parent)=ACTIVE`，同时 RR 中已有撤销
2. 拒绝约束：Parent 检查必须同时查 GR + RR（或电路证明 IR 与 RR 一致）；仅信 IR 会被伪造
3. 无约束后果：同 N05，但攻击面从 GR 转到 IR，说明 IR 不能单独替代撤销事实载体
4. 新增：`IR(parent)=ACTIVE ⇒ parent ∉ RR` 的约束，或保留 E-R1 RR 全扫描作为 Parents 检查的权威来源

## N07 — IR 叶子 ID 与 opening 查询 ID 不一致

1. 攻击者控制：提供 slot s 的 opening，叶中 `full_id=X`，但声称查询 ID=Y；路径重算根正确
2. 拒绝约束：`ir-full-id-eq`：`leaf.full_id == key == e.id`
3. 无约束后果：仅验证"某个叶子重算出公开根"就接受，实际证明的是别的 ID 的状态
4. 新增：完整 ID 相等约束；D3-04-R1 测试 `r1_auth_occupied_slot_different_full_id_query` 已覆盖 host 层，电路需等价

## N08 — Merkle slot 与 ID 截断映射不一致

1. 攻击者控制：为 ID=Y 提供 slot=low_t(X) 的 opening（其叶恰为空或期望状态）
2. 拒绝约束：`ir-slot-low-t`：`slot == low_t(id)`（电路内位分解），配合 `ir-full-id-eq`
3. 无约束后果：空槽 non-membership 可被伪造在任意 ID 的槽上；截断键碰撞也无法检测
4. 新增：低 t 位分解约束；完整 ID 绑定（同 N07）

## N09 — GR 更新成功但 IR 未更新

1. 攻击者控制：Grant 事件下 GR 输出根改变，IR 输出根=输入根
2. 拒绝约束：`pre-ok-gate` + 三支路同步：成功事件的三棵树输出根必须全部按事件类型更新（`grant flag ⇒ IR'≠IR` 且 `GR'≠GR`）
3. 无约束后果：授权写入 GR 但 IR 显示 ABSENT；后续重复 Grant 可通过 IR 前置检查 → 双花式授权
4. 新增：三支路 flag 门控；不允许只绑定"允许更新"而不绑定"必须更新"

## N10 — RR 更新成功但 IR 未更新

1. 攻击者控制：Revoke 事件下 RR 加记录，IR 保持 ACTIVE
2. 拒绝约束：同 N09 的 Revoke 形式：`revoke flag ⇒ IR'=REVOKED 且 RR'≠RR`
3. 无约束后果：已撤销 Grant 仍 IR=ACTIVE，可作 Parent 或被再次 Revoke
4. 新增：同 N09

## N11 — IR 更新成功但 GR/RR 未更新

1. 攻击者控制：Grant 事件下只写 IR=ACTIVE，GR 根不变
2. 拒绝约束：`grant flag ⇒ GR'≠GR`；`revoke flag ⇒ RR'≠RR`；配合 `RR'=RR`（Grant）/ `GR'=GR`（Revoke）的反向不变约束
3. 无约束后果：IR 声称存在授权但 GR 无记录，授权内容（scope 等）无来源，验证者被误导
4. 新增：正向必须更新 + 反向必须不变，两向都门控

## N12 — 同一 ID 被重复 Grant

1. 攻击者控制：第二次 Grant 仍传 `id=A`，伪造 IR 旧叶为 ABSENT 或 GR 新槽为另一个空槽
2. 拒绝约束：`IR(id)=ABSENT` 前置（状态转换门）+ GR 全树扫描 `scan-id-neq`（E-R1 现有）+ `leaf.full_id==key`
3. 无约束后果：同一 ID 多份授权，撤销只覆盖其中一个 → 未撤销副本仍有效
4. 新增：完整 ID 全局唯一检查（保留 E-R1 扫描或用可信 IR + 一致性证明）

## N13 — 同一 ID 被重复 Revoke

1. 攻击者控制：第二次 Revoke 传 `grant_id=A`，伪造 RR 新空槽或 IR 旧叶=ACTIVE
2. 拒绝约束：`IR(target)=ACTIVE` 前置 + RR 全树扫描 `revoke_id != new`
3. 无约束后果：重复撤销产生的 RR 记录可被用来构造虚假状态一致性
4. 新增：同 N12 的 Revoke 形式

## N14 — 两事件顺序颠倒

1. 攻击者控制：把 Revoke(A) 放在事件 0、Grant(B,Parent=A) 放在事件 1；或事件 1 的 IR 输入从 S0 重新构造而非事件 0 输出
2. 拒绝约束：`three-root-chain`：`IR_in[1] == IR_out[0]`（GR/RR 已有对应 cell equality）；状态机前置：事件 1 的 Parent 检查看到事件 0 后的状态
3. 无约束后果：本应拒绝的 `Revoke(A)→Grant(B,Parent=A)` 被接受；或者事件 1 看不到撤销
4. 新增：IR 的事件间根连接 equality；`IR_1` 不能从 host 代入

## N15 — 三棵树使用不同 epoch

1. 攻击者控制：GR 更新用 epoch=5、RR 用 epoch=6、IR 用 epoch=7
2. 拒绝约束：`cross-epoch-eq`：`epoch_GR == epoch_RR == epoch_IR == epoch_next`；epoch 单调由 E-R1 已有门控
3. 无约束后果：同一事件在三棵树中时间不一致，状态承诺 `C_next` 只绑一个 epoch，状态语义分裂
4. 新增：三支路 epoch cell 相等约束

## N16 — 使用旧状态根拼接新事件

1. 攻击者控制：事件 1 使用 `C_prev` 对应的旧 GR/RR/IR 根，但携带新事件的 commitment 与 epoch
2. 拒绝约束：`C_prev` 电路内由 `GR_in[0]/RR_in[0]/IR_in[0]/epoch_prev` 重算并绑 instance 0；事件 1 输入根必须 == 事件 0 输出根（N14 约束）；epoch 单调
3. 无约束后果：重放旧状态 + 新事件，绕过之前发生的撤销（撤销被"回滚"）
4. 新增：v2 承诺包含 IR 根；三棵树事件间根连接；与 E-R1 现有旧根门一致

## 汇总表

| 编号 | 核心拒绝约束 | 当前状态 |
| --- | --- | --- |
| N01/N02 | `cross-id-eq` | 设计级，未实现 |
| N03/N04 | `ir-state-transition` + range | D3-04-R1 host 有执行器，电路未实现 |
| N05/N06 | Parent GR+RR 双查或 IR↔RR 一致 | E-R1 已有 RR 扫描；IR 一致未实现 |
| N07/N08 | `ir-full-id-eq` + `ir-slot-low-t` | host 测试有，电路未实现 |
| N09/N10/N11 | 三支路双向 flag 门控 | 设计级，未实现 |
| N12/N13 | 全局唯一 + 状态前置 | E-R1 已有扫描；IR 前置仅 host |
| N14 | 三棵树事件间根 equality | E-R1 GR/RR 已有，IR 未实现 |
| N15 | `cross-epoch-eq` | 设计级，未实现 |
| N16 | v2 承诺 + 根连接 + epoch 单调 | E-R1 部分有，IR/版本部分未实现 |

**诚实边界**：以上 16 个反例的"拒绝"均为**设计意图**；本阶段未实现电路、未跑负向测试。任何声称"这些攻击已被验证拒绝"的表述都超出本阶段事实。
