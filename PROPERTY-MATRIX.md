# PROPERTY-MATRIX.md — D3-14-01 性质对照矩阵

基准日期：2026-11-25。矩阵单元格严格限定四值之一：
`Explicitly solved` / `Partially addressed` / `Out of scope` / `Not specified`。
引用证据放在文末「证据索引」，用 `[行号列号]` 编号回指，避免单元格内混入解释文本。

判定口径：
- `Explicitly solved` = 原文给出明确定义 + 构造 / 协议 / 规范性要求，并说明边界。
- `Partially addressed` = 原文明确讨论该性质，但只给问题、需求、假设或子集构造。
- `Out of scope` = 原文明确声明不处理，或命题对象根本不同（不是遗漏）。
- `Not specified` = 原文既未解决也未明确排除，仅零星提及或完全未提。

---

## 主矩阵

| 性质 | CVA | PoE | SCITT | Rampertab | Baek | Zhu/Wang |
|---|---|---|---|---|---|---|
| 请求授权绑定 | Explicitly solved | Partially addressed | Partially addressed | Explicitly solved | Out of scope | Out of scope |
| 授权历史重放 | Out of scope | Partially addressed | Out of scope | Explicitly solved | Partially addressed | Partially addressed |
| 执行证据绑定 | Out of scope | Explicitly solved | Explicitly solved | Partially addressed | Out of scope | Partially addressed |
| 事件捕获完整性 | Out of scope | Partially addressed | Partially addressed | Partially addressed | Partially addressed | Partially addressed |
| 区间权限缺失 | Out of scope | Out of scope | Out of scope | Partially addressed | Partially addressed | Out of scope |
| 撤销后迟到效果 | Out of scope | Partially addressed | Partially addressed | Partially addressed | Partially addressed | Explicitly solved |
| 跨域路径覆盖 | Out of scope | Out of scope | Partially addressed | Partially addressed | Partially addressed | Partially addressed |
| 独立第三方验证 | Explicitly solved | Explicitly solved | Explicitly solved | Explicitly solved | Partially addressed | Explicitly solved |
| 委派拓扑隐私 | Partially addressed | Partially addressed | Partially addressed | Partially addressed | Partially addressed | Out of scope |
| ZK 选择性证明 | Explicitly solved | Not specified | Out of scope | Partially addressed | Not specified | Out of scope |
| 完整性来源与假设 | Partially addressed | Explicitly solved | Explicitly solved | Explicitly solved | Partially addressed | Explicitly solved |

---

## P1–P6 命题归属（任务包 §1 要求）

| 命题 | 定义（任务包原文） | 覆盖情况 |
|---|---|---|
| P1 | 没有实际工具调用记录 | 各文均可给出记录层面的「无记录」，但 Baek §4.1 明确这**不等于** P3 |
| P2 | 没有授权记录 | Rampertab 可重建「已记录授权」；Baek §4.2 指出「未授权」与「经未记录路径授权后撤销」可呈现同一 prior state |
| P3 | 指定权限在区间内从未可用 | **Baek 定义为问题 + REQ + 场景，无协议/算法**；其余文献未给出区间级可用性判定 |
| P4 | 旧授权在撤销后不再能产生新的受保护效果 | **Zhu/Wang 在绑定 manifest 与配置内形式化解决**；Baek/ Rampertab 仅给需求或局部规则 |
| P5 | 所有可能路径均处于已声明且可检查的覆盖范围 | **七篇均未给出对未登记路径的全局可检查证明**；均为「有界内成立，界外不成立 / INDETERMINATE」 |
| P6 | 隐藏内部拓扑时第三方可验证 P3/P4 | **无一篇明确解决**；Rampertab §12 最接近（私有 authority profile），但不含区间命题或 quiescence 证书 |

**硬边界（与任务包一致）**：P1/P2 不能推导 P3/P4；P6 不能替代 P5。矩阵中 Baek 对 P3 只标 `Partially addressed`，因为其原文明确 *"It does not define a protocol, a data format, or a verification algorithm."*

---

## 证据索引

### 行 1：请求授权绑定
- `[1-A]` CVA 摘要 / §3 / §5.2：`R_CVA` 联合绑定 principal、request、context、policy；Groth16 PoC 实例化 principal/request/policy 绑定。
- `[1-B]` PoE §3 `Check_{I_2}`：每步携带 contract 与 Gateway 级授权，`gateway_ref` 指向权威决策；不是策略满足性证明。
- `[1-C]` SCITT §6.7 / §9.1：admission records 与 `admission_basis` 记录调用被接纳的依据，不证明策略满足。
- `[1-D]` Rampertab §6 / §11.2：`decision reproduction`——每次 admission 在所指 head 上被授权。
- `[1-E]` Baek §3：问题对象是 usability，不是「某请求是否被正确授权」。
- `[1-F]` Zhu/Wang §3.5：资产是「使用已退役 root-epoch atom 产生新的受保护效果」，不是单请求策略判定。

### 行 2：授权历史重放
- `[2-A]` CVA §6：单 Agent-Gateway 交互；多跳委派 scope 约束未形式化，明确列为未来工作。
- `[2-B]` PoE §3 replay context `R` 与 determinism envelope；重放的是执行轨迹，不是授权状态机。
- `[2-C]` SCITT §6.7：回执 hash chain，非授权转换链。
- `[2-D]` Rampertab §4 / §5.4 / §11.2：完整历史与确定性重放、captured authority at any position。
- `[2-E]` Baek §4.1：承认有序授权转换记录可重建「已记录」的当时授权，但额外要求「无记录外转换」。
- `[2-F]` Zhu/Wang §3–§4：root ledger / support provenance / cut / fence 记录可重放，但服务于 quiescence 判定。

### 行 3：执行证据绑定
- `[3-A]` CVA §4.5 / §7：runtime execution binding 明确为开放问题，ZKP 授权层无法覆盖。
- `[3-B]` PoE §6 / 摘要：EAC 仅在 `PoE=1` 时签发，绑定 contract、trace root、replay context。
- `[3-C]` SCITT §6.7 / §9.1：Execution Receipt Statement 与 Linked Verification。
- `[3-D]` Rampertab §9.1 / §10.2 / §11.2：intent→admission→submission→consumption→outcome→observation→receipt；但验证者不确立「动作在世界产生效果」。
- `[3-E]` Baek §3：不涉及执行回执。
- `[3-F]` Zhu/Wang §3–§4：以 protected-effect commitment / PRE_FENCE_COMMITTED receipt 为判定对象，范围限于受保护效果。

### 行 4：事件捕获完整性
- `[4-A]` CVA §7：模型不覆盖全部自主执行失败。
- `[4-B]` PoE §4.2 A5–A7 / §7.1：trace completeness 是**部署假设**，由 Effector-exclusive credentialing 规约，非密码学保证。
- `[4-C]` SCITT §9.2：*"A PASS does not establish that the Harness recorded every call..."*；Harness completeness 需远程证明组合，本文未定义绑定。
- `[4-D]` Rampertab §10.1 表 15：`enforced` / `recorded` / `open` 三类覆盖；无覆盖表即不支持 "governed" 主张。
- `[4-E]` Baek REQ-4 / §8：要求可检查 completeness property，但明确不抵抗操作者伪造/漏报。
- `[4-F]` Zhu/Wang §3.4 A6 / A5：manifest 与 stable-scan watermark 是安全前提；`effect path absent from the registered manifest` 在定理域外。

### 行 5：区间权限缺失
- `[5-A]` CVA：全文无区间可用性命题。
- `[5-B]` PoE：验证的是「执行是否合规」，不是「能力在区间内是否可用」。
- `[5-C]` SCITT：回执链无授权状态区间语义。
- `[5-D]` Rampertab §11.2 captured authority at any position + §12 absence 主张必须覆盖全部可改变结论的记录；**未定义区间级三值结论**；关键词 `interval absence` 全文零命中。
- `[5-E]` Baek 摘要 / §4.1–4.5 / §5 REQ-1–13 / §6 T-1–22：完整问题定义与测试场景；明确无协议/格式/算法。
- `[5-F]` Zhu/Wang：quiescence 针对 retired atom 的新受保护效果，不回答「能力在区间内可不可用」（ lingering session 可仍可用但无效果）。

### 行 6：撤销后迟到效果
- `[6-A]` CVA §6 lifecycle（PoE）：见下 `[6-B]`；CVA 自身无撤销收敛协议。
- `[6-B]` PoE §6：EAC revocation 只改变当前可接受性，*"Historical PoE validity is not rewritten"*。
- `[6-C]` SCITT §6 Revocation Statement：可撤销注册/凭证，无 sink fence 或 late-effect 判定。
- `[6-D]` Rampertab §9.1：*"a cancellation after APPLIED MUST be reported as too late"*；destination 在 commit boundary 重查 control tuple；late report 只作证据，不制造回执或执行许可。
- `[6-E]` Baek REQ-8 / T-3 / §4.3：lingering authority 与 revocation debt，问题级。
- `[6-F]` Zhu/Wang 摘要 / §7.2：17/17 注册结果；cancellation-only 与 cut-only 接受迟到效果，cut-plus-fence / restart / stale-process 拒绝；三值判定。

### 行 7：跨域路径覆盖
- `[7-A]` CVA §6：多跳委派留作未来工作。
- `[7-B]` PoE §10：*"Single-Gateway scope; composition open."*
- `[7-C]` SCITT §9.1 Linked Verification / §9.2：*"It does not establish ... that every hop of the Call Chain is present."*
- `[7-D]` Rampertab §10.1 覆盖表 / §11.3 远程 witness / §11.4 公共链锚定；跨信任域边界明确。
- `[7-E]` Baek REQ-11 / §4.5：跨域名输入视作 REQ-4 的路径；单域结论不蕴含组合域结论。
- `[7-F]` Zhu/Wang §3.4 A6–A7 / §3：manifest 覆盖所有可达 runtime/provider/effect sink/channel class；跨端 token 精确记账；界外为 INDETERMINATE。

### 行 8：独立第三方验证
- `[8-A]` CVA §5.1 / §3.4：网关无状态验证 proof；验证者仍依赖 trusted setup 与电路正确实现（§7）。
- `[8-B]` PoE §3 / §6：validator-checkable invariants + EAC，外部可验。
- `[8-C]` SCITT §8 Bundle / §9 离线验证。
- `[8-D]` Rampertab §11.2：*"a verifier that trusts neither agent nor operator"* 可确立的具体项与不可确立项并列。
- `[8-E]` Baek REQ-12：*"A relying party can check the outcome against the evidence without relying on the operator's own conclusion."*——要求级，无构造。
- `[8-F]` Zhu/Wang §3：独立 verifier 检查签名、epoch、manifest 覆盖、leaf 兼容、support witness、fence、watermark。

### 行 9：委派拓扑隐私
- `[9-A]` CVA 摘要 / §3：selectively preserving confidentiality of private authorization attributes；多跳拓扑未形式化。
- `[9-B]` PoE §6：*"Privacy-preserving variants ... are open work."*
- `[9-C]` SCITT §10：`principal_link`、pepper hashing、epoch roots；同时明示 `txn`/`actor_chain` 揭示参与运营者。
- `[9-D]` Rampertab §12 private authority profile：*"keeping delegators and terms private"*；但 verifier 必见 public statement，且证据范围/假设必须报告。
- `[9-E]` Baek §9：*"may use selective-disclosure techniques"*（一句，无机制）。
- `[9-F]` Zhu/Wang：全文无隐私/ZK 机制；verifier 需公开检查 manifest 覆盖与 leaf 集合。

### 行 10：ZK 选择性证明
- `[10-A]` CVA §5.1–5.2：Groth16 / bn128 / Circom / snarkjs PoC，私有策略谓词。
- `[10-B]` PoE §6：ZK EAC 为 open work，无构造。
- `[10-C]` SCITT §10：仅摘要与承诺，无 ZK。
- `[10-D]` Rampertab §12 + 附录 B：关系/语句/证据范围/假设规范性定义；七个合成负载 Groth16 证明，*"establish neither authority, completeness nor freshness"*；无区间或 quiescence profile。
- `[10-E]` Baek §9：只提 selective disclosure，未提 ZK。
- `[10-F]` Zhu/Wang：无 ZK。

### 行 11：完整性来源与假设
- `[11-A]` CVA §4.6 / §5.2：knowledge-soundness、Poseidon RO 假设、原型未独立审计、runtime trust anchor 缺失。
- `[11-B]` PoE §4.2 A1–A7：*"A5–A7 are deployment assumptions, not cryptographic ones."*
- `[11-C]` SCITT §9.2 Meaning of PASS + §11 Security Considerations：明确 PASS 成立与不成立的边界。
- `[11-D]` Rampertab §10.1 / §11.2 / §14 / 附录 C：覆盖表、freshness 机制强弱表、威胁模型、Lean 模型与「模型≠TypeScript」边界。
- `[11-E]` Baek REQ-4 / REQ-12 / §8：完整性属性须由系统声明且验证者可检查；三类遗漏分类；明确不抵抗伪造与完全失陷。
- `[11-F]` Zhu/Wang §3.4 表 2 A1–A11 + §3.5 verdict discipline：安全前提与活性前提分离；除 `QUIESCENT` 外不得被超时/重试/多数投票改写。

---

## 矩阵读法限制（我方推论）

- `Explicitly solved` 只表示「该文在其**自身声明范围内**给出构造或规范」，不表示全局成立。F 的 `Explicitly solved`（撤销后迟到效果）受「bound manifest and configuration」约束；D 的 `Explicitly solved`（授权历史重放）受「外部锚定与 freshness」约束。
- 唯一同时为六列全 `Out of scope` / `Not specified` 的行为「区间权限缺失」在 CVA/PoE/SCITT/Zhu-Wang 四列，以及「ZK 选择性证明」在 SCITT/Baek/Zhu-Wang 三列。它们描述的是**对象不同**，不是这些工作有缺陷。
- 因此不能由「某格为空」直接推出研究缺口；缺口判定须叠加 `GO-NO-GO.md` 的停止条件。
