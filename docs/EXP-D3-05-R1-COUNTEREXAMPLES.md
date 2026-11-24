# EXP-D3-05-R1 Phase 4 — 12 个归纳相关反例审查

> 每个反例按五问展开：① 攻击者控制哪些 witness；② S0 已可信时是否仍能发生；③ 哪条局部约束拒绝；④ 是否需全树扫描；⑤ 若不能拒绝，问题归类。
>
> “拒绝”均指设计约束应当拒绝；本轮未实现 Halo2、未跑负向证明测试。

## I01 — S0 中 GR 存在 A，但 IR 显示 ABSENT

1. witness：S0 的 GR 叶 preimage 含 `id=A`，IR 在 `low_t(A)` 的叶为 `Empty` 或异 ID。
2. S0 可信时：**不能发生**；`Inv(S0)` 的 (C1') 直接排除。
3. 拒绝约束：S0 一致性前置检查（host/可信锚定），不是单步电路约束。
4. 全树扫描：建立 S0 时需一次跨结构检查；之后逐事件不需要。
5. 归类：**S0 信任缺陷**。若把它归咎于单步转换，是错误归责。

## I02 — S0 中 RR 存在 A，但 GR 不存在 A

1. witness：S0 RR 叶 `grant_id=A`，GR 无 A。
2. S0 可信时：**不能发生**；(C0) `R⊆G` 排除。注意任务书原始的 C1 单独写不出这条，必须补 C0。
3. 拒绝约束：S0 孤立 RR 检查；E-R2 当前只查 RR 内部唯一性，未查此项。
4. 全树扫描：S0 一次检查需要看 RR 叶集合；逐事件不需要。
5. 归类：**S0 信任缺陷**。这是 E-R2 已识别但未闭合的边界，本轮明确列入 S0 检查清单。

## I03 — S0 中 GR 存在 A、RR 已撤销，但 IR 显示 ACTIVE

1. witness：GR 叶 A、RR 叶 A、IR(A)=ACTIVE。
2. S0 可信时：**不能发生**；(C3) 要求 `REVOKED`。
3. 拒绝约束：S0 三态一致性检查；运行时若由合法转换产生，则由 `ir-state-transition` + 同 flag 门控保证。
4. 全树扫描：逐事件不需要；S0 需一次检查。
5. 归类：**S0 信任缺陷**（若来自初始状态）或**转换约束缺陷**（若由某步错误写入产生）。

## I04 — S0 中 IR 有 A，但 GR 不存在 A

1. witness：IR 叶 `Occupied{A,ACTIVE}`，GR 无 A。
2. S0 可信时：**不能发生**；(C1') 要求 `ABSENT`。
3. 拒绝约束：S0 跨结构检查；运行时由 `cross-id-eq` + `pre-ok-gate` 防止“只写 IR”。
4. 全树扫描：不需要逐事件扫描；S0 一次性检查。
5. 归类：**S0 信任缺陷**；若由单步产生则是 N11 类转换缺陷。

## I05 — Grant A 时，GR 插入 A，IR 插入 B

1. witness：三支路使用不同 ID：GR 支路 `id=A`，IR 支路 `full_id=B`。
2. S0 可信时：**仍能发生**，因为这是转换约束缺失，不是初始状态问题。
3. 拒绝约束：`cross-id-eq`：`id_GR==id_IR==e_G.id`，并由同一 flag 门控。
4. 全树扫描：不需要；字段相等是局部约束。
5. 归类：**转换约束缺陷**（D3-05 N01）。

## I06 — Grant A 时，IR 误把碰撞的 B 当作 ABSENT

1. witness：`low_t(A)==low_t(B)`，该槽叶为 `Occupied{B,...}`，攻击者让 IR 查询返回 `ABSENT` 并写入 A。
2. S0 可信时：**仍能发生**，只要电路只实现 `get()` 的“异 ID ⇒ ABSENT”语义而不实现碰撞拒绝。
3. 拒绝约束：`ir-collision-reject` / Grant 目标槽必须为 `Empty`（或 `full_id==id`）+ `ir-slot-low-t` + `ir-full-id-eq`。host 中对应 `apply_grant` 的 `KeyCollision`。
4. 全树扫描：不需要；只需打开 `low_t(A)` 一个槽。
5. 归类：**转换约束缺陷 + 认证绑定缺陷**。若省略，IR 方案会用局部碰撞破坏 U2，不能靠 S0 可信开脱。

## I07 — Revoke A 时，RR 插入 A，IR 更新 B

1. witness：RR 支路 `grant_id=A`，IR 支路 `full_id=B`。
2. S0 可信时：**仍能发生**。
3. 拒绝约束：`cross-id-eq` 的 Revoke 形式：`id_RR==id_IR==e_R.grant_id`。
4. 全树扫描：不需要；局部字段相等即可。
5. 归类：**转换约束缺陷**（D3-05 N02）。

## I08 — Revoke A 时，IR 从 ABSENT 直接变 REVOKED

1. witness：IR 旧叶 `Empty`，新叶 `state=REVOKED`，攻击者同时伪造 RR 新记录。
2. S0 可信时：**仍能发生**，若没有状态转换门。
3. 拒绝约束：`ir-state-transition`：Revoke 要求旧状态 `ACTIVE`；配合 `ir-state-range`。
4. 全树扫描：不需要；单叶状态检查。
5. 归类：**转换约束缺陷**（D3-05 N03）。注意即便 RR 写入合法，IR 的 ABSENT→REVOKED 也破坏 (C3)。

## I09 — Revoke A 后，IR 仍为 ACTIVE

1. witness：RR 写入 A 的新根正确，IR 输出根=输入根（仍 ACTIVE）。
2. S0 可信时：**仍能发生**，若三支路不强制同步写。
3. 拒绝约束：`pre-ok-gate` + `revoke flag ⇒ IR'=REVOKED 且 RR'≠RR`。
4. 全树扫描：不需要；根变化由事件 flag 门控。
5. 归类：**转换约束缺陷**（D3-05 N10）。这是归纳步失败，不是 S0 问题。

## I10 — Grant A 后，GR 有 A，但 IR 未更新

1. witness：GR 新根正确，IR 根不变（A 仍 ABSENT）。
2. S0 可信时：**仍能发生**。
3. 拒绝约束：`grant flag ⇒ IR'=ACTIVE 且 GR'≠GR`，反向 `RR'=RR`。
4. 全树扫描：不需要。
5. 归类：**转换约束缺陷**（D3-05 N09）。若不拒绝，下一次 Grant A 会由 `IR(A)=ABSENT` 通过，形成重复授权。

## I11 — 第二个事件读取旧 IR 根，而不是第一个事件的输出根

1. witness：事件 1 的 `IR_in[1]` 从 S0 IR 根代入，而非 `IR_out[0]`；GR/RR 链正确。
2. S0 可信时：**仍能发生**，因为这是事件间连接缺失。
3. 拒绝约束：`IR_in[1]==IR_out[0]`，并把三根纳入 `C_v2`（`C_prev/C_next`）。
4. 全树扫描：不需要；根相等是局部约束。
5. 归类：**转换约束 / 状态承诺缺陷**（D3-05 N14/N16）。若 `C` 不含 IR 根，验证器无从感知该错误。

## I12 — 通过错误 ID 映射，让两个不同完整 ID 共享一个 IR 状态

1. witness：攻击者令 `slot` 为 witness 自由指定，或让电路用截断值代替完整 ID 比较，使 `A≠B` 却共用同一 IR 叶。
2. S0 可信时：**仍能发生**，若 `ir-slot-low-t` 与 `ir-full-id-eq` 缺失。
3. 拒绝约束：`slot=low_t(full_id)` 位分解 + `leaf.full_id==key`；写入时若槽已被异 ID 占用则拒绝。
4. 全树扫描：不需要；单槽 opening 即可判定。
5. 归类：**认证绑定缺陷**（D3-05 N07/N08 + I06）。这不是 Merkle 根本身不真实，而是“真实的是另一个 ID 的叶”。

## 汇总分类

| 类别 | 反例 | 是否可由逐事件局部约束解决 |
| --- | --- | --- |
| S0 信任缺陷 | I01 / I02 / I03 / I04 | 否；需一次性 S0 检查与可信锚定，不能归咎于单步转换 |
| 转换约束缺陷 | I05 / I07 / I08 / I09 / I10 / I11 | 是；均为局部 flag / ID / 状态 / 根链约束 |
| 碰撞与完整 ID 绑定缺陷 | I06 / I12 | 是；单槽 opening + `low_t` 位分解 + 完整 ID 相等 |
| Merkle 根真实性缺陷 | I12 的“错路径”变体 | 是；路径重算 + root 绑定，但不是全局扫描问题 |

**关键判断**：12 个反例中没有一个必须靠“每事件全树扫描 GR/RR”才能拒绝。S0 类反例靠一次性可信锚定；其余靠局部约束。这是归纳路线成立的必要条件，本轮审查满足它。
