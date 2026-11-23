# EXP-D3-02-R2-05 — 原型测试矩阵冻结规范

**基线**：`023a5d1641354dc7f7257a09cc23a28787b33b0d`
**分支**：`exp-d3-02-r2`
**性质**：设计冻结。T01–T16 每项明确输入构造、拒绝组件、测试层级、是否需真实证明、支持/不支持的结论。

---

## 0. 测试层级缩写与判定原则

| 缩写 | 层级 | 含义 |
| --- | --- | --- |
| **MP** | Halo2 MockProver | 检查约束可满足性，不需生成真实 proof，快 |
| **RP** | 真实 proof / verifier | 生成真实证明并验证；`create_proof` 成功 != `verify` 成功 |
| **BV** | Anchor Bridge Validator | 链下验证 BridgeStatement 签名/版本/freshness/nonce |
| **LV** | Layout Validator | 链下验布局签名 + 独立重算 `assignment_digest` |
| **VK** | VK 注册表检查 | 查 `vk_hash → (policy_id, D_circuit, version, active)` |
| **GV** | 网关集成 | 组合上述所有检查 + epoch 高水位 + fencing |

**判定原则（必须遵守，否则测试结论失真）**：
1. "拒绝"必须写明**哪个组件**拒绝；电路层接受但网关拒绝的，如实写两层。
2. `create_proof` 失败与 `verify_proof` 失败是不同事件——D2-A-R1 口径：
   prover 可能对一个失败约束"出 proof"（若实现允许），但 verifier 拒绝。
   本矩阵统一表述为"MP 拒绝 / RP verifier 拒绝"。
3. 需要真实密码学证明的测试（RP）明确标注；只在 MP 层验证的不声称"真实证明被拒"。
4. "电路层接受"不是 bug，而是明确的信任边界（布局规范性、跨 vk 重放在电路外）。

---

## 1. T01–T16 测试矩阵

### T01 — 正常 DirectOnly 授权转换
- **输入构造**：合法 root grant + child grant（scope 不扩大、resource 前缀一致、parent 存在），
  `policy_id`=R2-01 DirectOnly 冻结值，`C_prev`/`C_next` 按 Poseidon 正确算，Bridge/Layout 签名有效。
- **预期**：接受。
- **测试层级**：MP（约束全绿）+ RP（真实 proof/verifier 通过）+ BV + LV + VK + GV 全通过。
- **需真实证明**：✅（RP 验证端到端可用性）。
- **支持结论**：冻结接口可产生并可验证一个合法 DirectOnly 状态转换证明。
- **不支持结论**：不支持"历史完整/状态新鲜/授权决策 ALLOW"——这些靠外部链。

### T02 — 正常撤销转换
- **输入构造**：合法 revoke（revoker==issuer、目标存在且 valid=1、未重复撤销），其余同 T01。
- **预期**：接受。
- **层级**：MP + RP + BV + LV + VK + GV。
- **需真实证明**：✅。
- **支持**：撤销语义（DirectOnly 只置 valid_flag=0 + 写 RR 叶子）在电路中可执行且双根更新正确。
- **不支持**：不支持"撤销反映到工具执行时"——新鲜性/fencing 是外部（security §2）。

### T03 — GR 字节非规范编码
- **输入构造**：`grant_root_be` 大端 32B = `p`（`4000…0001`）或 `2^255`（`8000…00`），其余合法。
- **预期**：拒绝。
- **拒绝组件**：RV `DecodeField_I` 返 `NonCanonicalField` 拒签（Bridge 层）；MP 规范范围检查失败（R2-02 §4.1a）。
- **层级**：BV + GV + MP。
- **需真实证明**：❌（MP + Bridge 检查足够；非规范输入在约束层就失败，无需 RP）。
- **支持**：R2-02 方案 A′ 的"拒绝非规范、禁止静默模约简"被验证。
- **不支持**：不支持"所有非规范编码形式都被拒"——仅测试列出的边界值（p, 2^255），
  完整证明依赖 §3 的双射论证而非穷举测试。

### T04 — RR 字节非规范编码
- **输入构造**：同 T03，但 `revoke_root_be` 非规范。
- **预期/拒绝组件/层级/需证明/支持/不支持**：同 T03（对称）。

### T05 — 修改 policy_id
- **输入构造**：保持 vk=DirectOnly，把公开 `policy_id` 改成 Cascade 冻结值（或任意别的域元素）。
- **预期**：拒绝。
- **拒绝组件**：MP 电路 `policy_id_pub == policy_id_const` gate 失败；RP verifier 拒绝；
  BV（BridgeStatement.policy_spec_digest 不符）；VK（注册表 policy_id 不符）；GV。
- **层级**：MP + RP（verifier 拒绝）+ BV + VK + GV。
- **需真实证明**：✅——需验证"prover 可能出 proof 但 verifier 拒绝"的真实行为（沿用 D2-A-R1 口径）。
- **支持**：电路常量 gate + 注册表双重绑定有效，证明者不能在该 vk 下改策略身份。
- **不支持**：不支持"跨 vk 的策略混淆也被电路拒绝"——那是 R09/T14，靠注册表。

### T06 — 错误 VK 与策略注册表映射
- **输入构造**：用有效 proof + 一个 `vk_hash` 在注册表中不存在，或存在但 `active=false`，
  或 entry 的 `policy_id`/`D_circuit`/`transition_version` 与 statement 不符。
- **预期**：网关拒绝。
- **拒绝组件**：VK（注册表查不到/字段不符/inactive）+ GV。注意：Halo2 verifier 可能仍能验证
  （若用的 vk 真的对应电路），**拒绝发生在网关查表环节，不是 verifier**。
- **层级**：VK + GV（电路层不参与）。
- **需真实证明**：❌（注册表是链下检查，不需 proof；可用 MP 生成的证明材料）。
- **支持**：vk 注册表作为策略/版本身份的可审计绑定有效。
- **不支持**：不支持"电路能检测错误 vk 映射"——不能，网关外的 verifier 无注册表概念。

### T07 — 修改 Bridge 中 GR/RR
- **输入构造**：篡改 `SignedBridgeStatement` 的 `grant_root`/`revoke_root` 字段（保留原签名或重签无效）。
- **预期**：拒绝。
- **拒绝组件**：BV 验签失败（签名覆盖完整状态元组）；GV 交叉核对 `poseidon_state_commitment == C_prev` 失败；
  若篡改后仍强行出 proof，MP 开承诺失败（C_prev 与 GR/RR 不符）。
- **层级**：BV + GV + MP。
- **需真实证明**：❌（验签 + MP 足够）。
- **支持**：Bridge 签名覆盖完整状态元组 + 电路开承诺双重绑定有效。
- **不支持**：不支持"Bridge 签名者合谋伪造"——那是 B-F1 外部信任，电路无法检测。

### T08 — 旧 Bridge 重放
- **输入构造**：用 epoch 已过期的 BridgeStatement（`expires_at < now` 或 nonce 已用），其余合法。
- **预期**：网关拒绝。
- **拒绝组件**：BV（过期/nonce 已用/版本不符）+ GV。
- **层级**：BV + GV。
- **需真实证明**：❌（链下 freshness/nonce 检查）。
- **支持**：Bridge 消息级防重放（TTL + nonce + 版本）有效。
- **不支持**：不支持"执行时授权仍有效"——Bridge 未过期不代表工具执行时未撤销（fencing 独立）。

### T09 — 非规范 canonical layout
- **输入构造**：构造一个不满足 `canonical_assignment(ids,d)` 的 `id→slot` 布局（如把 id 放到
  非 `D3-SLOT-v1` 初始槽探测结果的位置），但 Merkle 路径在该布局下自洽。
- **预期**：**电路层接受**；布局验证器 + 网关拒绝。
- **拒绝组件**：LV 重算 `assignment_digest' != layout_digest`（或验签失败）；GV。
  电路层：MP 接受（电路只验给定布局下路径重算，R1-02 §5.1）。
- **层级**：MP（**接受**，如实记录）+ LV + GV。
- **需真实证明**：❌（MP 证明"电路接受"的结论即可；LV/GV 链下）。
- **支持**：布局规范性的信任边界被正确实现——电路不证，外部验证器证。
- **不支持**：**不能**声称"电路拒绝非规范布局"——明确写电路层接受（与 P11/R07 同口径）。

### T10 — 删除后错误重插
- **输入构造**：删除一个 id 后重插，displaced id 被放到非规范槽位（违反 `try_upsert` 的规范位移），
  但 Merkle 路径自洽。
- **预期**：**电路层接受**；布局验证器 + 网关拒绝。
- **拒绝组件**：LV（重算完整 assignment_digest 不符，含 displaced 集合）+ GV。MP 接受。
- **层级**：MP（接受）+ LV + GV。
- **需真实证明**：❌。
- **支持**：displaced id 集合被布局摘要完整覆盖（R2-03 §8），遗漏被 LV 发现。
- **不支持**：不支持电路约束位移规则——电路不检查（R1-02 §4）。

### T11 — 事件批次摘要不匹配
- **输入构造**：篡改公开 `event_batch_commitment` 或 witness 中某个 `c_i`，使
  `D_E == Poseidon(D_BATCH, n, c_1..c_n)` 不成立。
- **预期**：电路拒绝。
- **拒绝组件**：MP Batch Commitment 约束失败；RP verifier 拒绝。
- **层级**：MP + RP。
- **需真实证明**：✅（验证批次绑定在真实证明层成立）。
- **支持**：事件批次与公开承诺的密码学绑定有效。
- **不支持**：不支持"批次来源完整"——篡改 D_E 到另一个自洽批次，电路只看承诺一致，
  完整性靠 D1-E 日志 + 批次来源（security §1）。

### T12 — 修改 next_state_commitment
- **输入构造**：篡改公开 `next_state_commitment`，使与末步 GR/RR 重算的 C_next 不符。
- **预期**：电路拒绝。
- **拒绝组件**：MP State Binding 约束 `C_next == Poseidon(...)` 失败；RP verifier 拒绝。
- **层级**：MP + RP。
- **需真实证明**：✅。
- **支持**：后状态承诺与双根更新结果的电路绑定有效。
- **不支持**：不支持"后状态是真实权威状态"——需下一轮 Anchor/checkpoint 确认。

### T13 — 使用旧状态转换证明
- **输入构造**：复用一个 epoch 已旧的合法 π_trans（含当时的 C_prev/C_next/epoch），
  在当前（更高 epoch）网关提交。
- **预期**：网关拒绝。
- **拒绝组件**：GV epoch 高水位检查（`previous_epoch`/`next_epoch` < 本地高水位）+ Bridge freshness
  失效；电路层该证明自身仍"有效"（它证明的是旧转换）。
- **层级**：GV + BV（电路验证会通过，如实记录）。
- **需真实证明**：❌（epoch 检查链下）。
- **支持**：历史证明重放被网关 epoch 高水位拒绝。
- **不支持**：不支持"旧证明在数学上失效"——它仍是一个有效证明，只是被策略层拒绝。

### T14 — DirectOnly 电路声称 Cascade
- **输入构造**：用 `vk_DO` 生成证明，但 statement 的 `policy_id` 填 Cascade 值（或 Bridge 声明 Cascade）。
- **预期**：VK 注册表拒绝（最终拒绝点）。
- **拒绝组件**：MP gate 失败（`vk_DO` 内 const=DO，填 CAS 值失败）；RP verifier 可能拒绝；
  VK（vk_hash=DO 但 statement 称 CAS）最终拒绝；GV。
- **层级**：MP + RP + VK + GV。
- **需真实证明**：✅（验证"跨策略混淆在电路/verifier 层的行为"需真实证明确认——
  R1-03 §5 指出：若用 `vk_CAS` 验一个恰好满足的 DO 证明，verifier 可能接受，
  只有注册表能拒；本测试用 `vk_DO` 填 CAS 值，MP 层必失败）。
- **支持**：vk 注册表是跨策略混淆的最终拒绝点；电路常量 gate 是第一道。
- **不支持**：不支持"电路单独防所有跨策略重放"——R09 场景 verifier 层可能接受，靠 VK。

### T15 — 非法 parent grant
- **输入构造**：child grant 的 parent 不存在，或 `issuer != parent.subject`，或 parent `valid_flag=0`。
- **预期**：电路拒绝。
- **拒绝组件**：MP Parent Binding 约束失败（parent 路径打不开 / issuer 不等 / valid_flag=0）；RP verifier 拒绝。
- **层级**：MP + RP。
- **需真实证明**：✅（验证 parent 语义在真实证明层成立）。
- **支持**：Parent Binding 与撤销状态检查在电路中有效（D2-A-R1 的 valid_flag 专用列教训已应用）。
- **不支持**：不支持"parent 本身是合法来源"——root grant 的合法性靠 Bridge/外部信任。

### T16 — 撤销后继续使用 grant
- **输入构造**：对已撤销（`valid_flag=0`）的 grant 生成一条 child grant 或使用其授权路径。
- **预期**：电路拒绝。
- **拒绝组件**：MP `s_not_revoked` 门失败（valid_flag 专用列）；RP verifier 拒绝。
- **层级**：MP + RP。
- **需真实证明**：✅。
- **支持**：撤销状态在电路内被强制检查，撤销后不能派生新授权。
- **不支持**：不支持"撤销已在执行时生效"——同一撤销的时序新鲜性靠 fencing（security §2）。

---

## 2. 测试矩阵总表（速览）

| ID | 场景 | 预期 | 拒绝组件 | 层级 | 真实证明 |
| --- | --- | --- | --- | --- | --- |
| T01 | 合法 DirectOnly 转换 | 接受 | —— | MP+RP+BV+LV+VK+GV | ✅ |
| T02 | 合法撤销转换 | 接受 | —— | MP+RP+BV+LV+VK+GV | ✅ |
| T03 | GR 非规范编码 | 拒绝 | Bridge 解码 + MP 范围检查 | BV+GV+MP | ❌ |
| T04 | RR 非规范编码 | 拒绝 | 同 T03 | BV+GV+MP | ❌ |
| T05 | 改 policy_id | 拒绝 | MP gate + RP verifier + BV + VK + GV | MP+RP+BV+VK+GV | ✅ |
| T06 | 错误 VK 映射 | 网关拒绝 | VK 注册表 + GV | VK+GV | ❌ |
| T07 | 改 Bridge GR/RR | 拒绝 | BV 验签 + GV + MP 开承诺 | BV+GV+MP | ❌ |
| T08 | 旧 Bridge 重放 | 网关拒绝 | BV(TTL/nonce) + GV | BV+GV | ❌ |
| T09 | 非规范 layout | **电路接受**/网关拒绝 | LV + GV（MP 接受） | MP+LV+GV | ❌ |
| T10 | 删除后错误重插 | **电路接受**/网关拒绝 | LV + GV（MP 接受） | MP+LV+GV | ❌ |
| T11 | 批次摘要不匹配 | 电路拒绝 | MP + RP verifier | MP+RP | ✅ |
| T12 | 改 next_state_commitment | 电路拒绝 | MP + RP verifier | MP+RP | ✅ |
| T13 | 旧转换证明 | 网关拒绝 | GV epoch 高水位 + BV | GV+BV | ❌ |
| T14 | DO 电路称 Cascade | VK 拒绝 | MP gate + VK + GV | MP+RP+VK+GV | ✅ |
| T15 | 非法 parent grant | 电路拒绝 | MP + RP verifier | MP+RP | ✅ |
| T16 | 撤销后继续用 grant | 电路拒绝 | MP `s_not_revoked` + RP | MP+RP | ✅ |

---

## 3. 必须诚实记录的"非电路拒绝"点

以下测试的最终拒绝**不在电路层**，测试报告必须原样标注，不得写成"电路拒绝"：

| 测试 | 电路层行为 | 真实拒绝点 |
| --- | --- | --- |
| T06 | 不参与 | VK 注册表 + 网关 |
| T08 | 不参与 | Bridge Validator + 网关（TTL/nonce） |
| T09 | **接受** | Layout Validator + 网关 |
| T10 | **接受** | Layout Validator + 网关 |
| T13 | 旧证明自身有效 | 网关 epoch 高水位 + Bridge freshness |
| T14 | 跨 vk 场景 verifier 可能接受 | VK 注册表（最终） |
| T03/T04 | MP 范围检查拒绝 | Bridge 解码器（拒签）+ MP |

这些点共同构成本设计的诚实边界：**电路保证的是"给定可信外部锚，违规批次无接受证明"，
不是"所有攻击都在电路内被拒"**。

---

## 4. D3-03 / D3-04 实施顺序建议（测试角度）

1. **D3-03 原型**：先跑 MP 层 T01/T02/T11/T12/T15/T16（纯电路语义），
   再跑 T03/T04（规范编码约束）、T05/T14（policy 常量 gate）。
2. **D3-04 真实证明**：对 T01/T02/T05/T11/T12/T14/T15/T16 跑 RP，记录约束数/证明时间/验证时间/大小/内存。
3. **D3-05 端到端**：实现 BV/LV/VK/GV，跑 T03–T10/T13 的链下检查，
   特别验证 T09/T10 的"电路接受但网关拒绝"行为被正确记录。
