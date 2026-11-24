# D3-11 形式化性质：E1–E4

日期：2026-11-24｜说明：形式化的是**要检验的目标**，不是声称已实现的保证。每项严格区分"安全定义 / 公共输入 / 私有见证 / 攻击者能力 / 成败条件 / 所需信任假设"。

记号为审计自定义（非任何论文原文记号）；证据引用见 `RELATED-WORK.md`。

---

## 通用记号

- `call`：一次工具调用。`req`：请求字节，`resp`：响应字节。
- `A`、`S`：调用方 Agent 与被调用 Serving Party（可能分属不同组织）。
- `σ_X(m)`：实体 X 对消息 m 的签名（COSE_Sign1 / Ed25519）。
- `H`：抗碰撞摘要。`cd = H_canonical(req)`：`call_digest`，双方对同一请求表示计算（SCITT -02 §6.7.3）。
- `VDS`：透明服务的 append-only 可验证数据结构（SCITT）；`Reg(r)`：回执 r 的注册证明。
- `chain`：Evidence Chain（`seq, prev_hash` 链接的回执序列）。
- `P`：策略；`Dec(P, ctx)`：在上下文 ctx 下的合规判定。

---

## E1 — Event Authenticity（事件真实性）

**要证明的内容**：一条回执能证明"某个工具调用或结果确实由指定执行主体产生"。

### 严格拆分（不允许合并）
必须区分三件事：
1. **签名归属**：回执由实体 X 的密钥签署。—— 签名算法可证。
2. **记录真实性**：回执里写的 `req/resp/target` 是 X 实际看到/执行的。—— 大部分基线不证。
3. **执行一致性**：工具内部行为与回执描述一致。—— 基线普遍不证。

### 安全定义
给定回执 `r = (target, req_digest, resp_digest, actor, sig_X)` 与验证公钥 `pk_X`：
- 签名可靠性：`Verify(pk_X, r, sig_X) = 1` ⇒ 存在持有 `sk_X` 的实体产生该签名（除可忽略概率）。
- 真实性（**强定义，基线均不满足**）：`Verify=1` ⇒ `r.target/req/resp` 与 X 内部实际执行一致。

### 公共输入
`pk_X`、`r`、`Reg(r)`（若注册）、X 的 credential/身份声明。

### 私有见证
X 的内部执行轨迹 `trace_X`（工具内部日志、模型权重摘要、TEE quote 等）。

### 攻击者能力
控制网络与部分 Verifier；可重放别人的回执；可控制恶意 key custodian（NovaFabric TCB）。

### 成败条件
- 伪造签名成功 → 攻破签名可靠性（标准假设下不可行）。
- **持有 `sk_X` 的实体签一条描述虚假的回执** → 攻破强真实性。NovaFabric 原文承认这无法被下游检出（"no amount of downstream verification detects it"）。此处所有基线仅达"签名归属"，未达"记录真实性/执行一致性"。

### 信任假设
签名密钥未泄露且存于 HSM（SCITT Profile §11.3）；X 忠实记录其观察到的字节（SCITT -02 `response_digest` 定义前提）；若要求执行一致性，需 TEE 远程证明或 zkAgent 式 zkTLS/zkVM 观察绑定（**引入新信任基**）。

### 判定
- SCITT -02 / Profile、NovaFabric、Receipts：**仅保证签名归属 + 承诺后不可篡改**；不保证记录真实性与执行一致性。
- 结论：**"签名有效"≠"事件真实"**，E1 强定义在所有基线中未达成，且缺口在外部信任基，不在证明系统。

---

## E2 — Evidence Completeness（证据完整性）

**要证明的内容**：在**明确的观测边界内**，真实发生的调用是否都能被发现。

### 反不可能声明（ kritisch ）
不定义"证明世界上没有遗漏任何事件"——这在信息论上不可能（验证者无法观测未提交给它的事件，D3-10 已证）。必须相对化到三要素：**观测边界 O / 独立观察者集合 W / 通信通道 C**。

### 相对化安全定义
设观测边界 O = {Harness 决策点, Serving Party admission 入口, 独立网络遥测, TEE quote} 中实际部署的子集。设真实调用集合 `T`，证据链记录集合 `E ⊆ T`。
- 序列完整性：`E` 内无删除/替换/重排（可由 `seq, prev_hash` + VDS 一致性证明保证）。
- **观测完整性（相对 O）**：`T∩O ⊆ E`，即"落在观测边界内的真实调用都被记录"。若 O 只含 Harness，则 O 之外的调用（如 Harness 完全不记录的调用）不在保证范围。

### 公共输入
`chain`、`VDS` 的一致性证明、序列缺口检测 `∃ gap(seq)`。

### 私有见证
真实调用集合 `T`（验证者不持有）、独立观察者的观测记录。

### 攻击者能力
单方恶意 Harness 跳过某调用；双方串谋删除；多组织选择性不提供记录；向不同 Verifier 展示不同链。

### 成败条件
- 若某调用被记录后删除/替换 → `prev_hash` 断裂或 VDS 一致性证明失败 → `BLOCKED`（内部篡改）。
- 若某调用**从未进入观测边界**（Harness 不产生回执、工具不产生 admission）→ 无序列缺口 → `NOT_BLOCKED`（SCITT Profile 原文："An action that was never recorded leaves no gap"）。
- 若两组织串谋且共用同一 Custodian → 可无检测伪造/抑制 → `BLOCKED_WITH_ASSUMPTION`（要求 TS 独立且诚实）。

### 信任假设
TS 与 Issuer 结构独立且操作诚实（SCITT Profile §11.2）；capture hooks/proxy 忠实观察、spool/collector 不丢（NovaFabric TCB）；外部 gossip/审计者检测 VDS 分叉（分布式假设，非 SNARK 属性）。

### 判定
- SCITT -02：PASS 明说"does not establish that the Harness recorded every call"；Harness completeness 与远程证明组合，**本文不定义该绑定**。
- SCITT Profile：序列缺口只证"产生但未注册"，未记录操作不留缺口。
- NovaFabric：completeness 0.652±0.064（AUTHOR-CLAIM），未达 1.0；capture 数字自报，只证内部一致性。
- 结论："日志可追加"≠"日志无遗漏"。E2 只在相对观测边界 O 内可达，且依赖外部锚点（远程证明/网络遥测/独立观察者），**不是密码学证明属性**。这直接延续 D3-10 的递归证明 ≠ 外部历史完整。

---

## E3 — Cross-Provider Binding（跨方绑定）

**要证明的内容**：不同组织对**同一次调用**的请求、响应和主体具有一致的密码学关联。

### 安全定义
对调用 `call`，设 A 侧回执 `r_A` 含 `cd_A = H(req as sent)`，S 侧 admission `r_S` 含 `cd_S = H(req as received)`，另有 `actor_chain / principal_link / txn / caller_ref`。
- 关联成立：`cd_A = cd_S ∧ actor_chain_A = actor_chain_S ∧ principal_link_A = principal_link_S ∧ txn_A = txn_S`。
- 抗移植：不存在两次不同调用 `call ≠ call'` 使 `r_A(call)` 与 `r_S(call')` 满足上述关联（除摘要碰撞）。

### 公共输入
`r_A`、`r_S`（含各自 `call_digest`、身份链字段）、两侧的独立验证结果。

### 私有见证
请求/响应原文 `req/resp`（SCITT 明确不进回执，见 §10）；Verifier 只需摘要比对。

### 攻击者能力
双方对同一物理调用展示不同参数；把 A 的回执移植到 B 的任务；中间代理重写请求（call_digest 排除 scheme/authority）。

### 成败条件
- `cd_A ≠ cd_S` → 关联失败（`NOT_BLOCKED` 于"证明同一次调用"，但此时是**正确拒绝**）。
- 双方合谋对同一调用算相同的**假** `cd` 并对外部一致展示 → `BLOCKED_WITH_ASSUMPTION`（依赖双方各自独立验证并签名，SCITT -02 "parties each of which verified on its own"）。
- 同 host 多服务：`call_digest` 无法区分 → `NOT_BLOCKED`（SCITT -02 §9.2 明说）。
- 中间代理改写 call_digest 覆盖之外的部分 → `NOT_BLOCKED`（SCITT -02 §14 representation mapping open issue）。
- 回执移植（X5）：`actor_chain/principal_link/txn` 提供绑定，但前提是这些字段本身可信（依赖 E1）。

### 信任假设
双方对同一请求表示计算 `call_digest`（协议绑定存在）；身份链字段可信；Verifier 独立持有双方公钥与策略。

### 判定
- SCITT -02 的 linked verification **已实现** E3 的核心（盲摘要比对 + 身份链一致性），这是本轮最强的现成构造。
- 但 E3 只保证"两边记录的摘要一致"，不保证"这条摘要对应真实物理调用"（归 E1）或"没漏掉其他调用"（归 E2）。
- 方向 A 的"隐私化关联"要在 E3 之上隐藏 `call_digest/actor_chain/principal` 明文，同时仍证明关联与合规——见 `DECISION.md` 门禁 H1/H2。

---

## E4 — Privacy-Preserving Verification（隐私化验证）

**要证明的内容**：第三方验证必要合规性质，而不获得完整请求、响应和身份关联信息。

### 安全定义
设合规判定 `Dec(P, ctx) = 1` 表示调用符合策略。隐私化验证要求：Verifier 仅获知 `(Dec=1, 绑定信息)`，不获知：
- 每步请求/响应原文 `req/resp`；
- 完整调用轨迹 `chain` 的内容字段；
- 中间累计/身份链 `actor_chain/principal_link` 的明文值；
- 关键元数据（调用频率、时序、动作量）。

### 公共输入
合规结论 `Dec=1`、public 锚点（VDS 中已签名的承诺）、必要的绑定信息。

### 私有见证
`req/resp`、`actor_chain`、`principal`、完整 `chain` 内容、累计计数。

### 攻击者能力
Verifier 通过公开摘要/元数据推断敏感内容（X7）；观察者关联同一 agent 的多次活动。

### 成败条件
- 若回执含明文内容 → `NOT_BLOCKED`。四篇基线均**不含内容**，只含 digest（SCITT -02 §6.7：`Content MUST NOT be included in a receipt`）——此点 `BLOCKED`。
- 但元数据泄漏仍在：SCITT Profile §12：`COSE protected header exposes agent_id, action_timestamp_ms, and sequence_number`，可推断频率/时序/量 → 对 X7 只 `BLOCKED_WITH_ASSUMPTION`（靠访问控制，非密码学隐藏）。
- 若进一步要求"隐藏合规判定之外的全部信息且仍可验证 Dec=1" → 需 ZKP；四篇基线**均未提供**。这是方向 A 的候选增量，但受 H1/H2 门禁约束。

### 信任假设
摘要函数单向；访问控制限制元数据可见性；若用 ZKP 则需在 public 锚点上绑定（否则退化为 D3-07-B private-only 陷阱）。

### 判定
- 内容隐私（不泄漏 req/resp）：四篇基线靠"只存摘要"已达成。
- 元数据隐私：靠访问控制，非密码学。
- 合规判定的隐私化验证（隐藏一切、只证 Dec=1）：**未被四篇基线覆盖**——这是本轮唯一残存的候选密码学缺口，但是否构成"值得独立研究的性质"需过 H1/H2。

---

## 四项性质关系（不可混为一谈）

| 性质 | 现成机制能达成的核心 | 缺口位置 | 缺口性质 |
|---|---|---|---|
| E1 事件真实 | 签名归属 + 篡改可检 | 记录真实 / 执行一致 | 外部信任基（TEE/zkTLS/密钥 custodian） |
| E2 完整无遗漏 | 链内不可篡改 + 序列缺口 | 从未记录 / 观测边界外 | 外部锚点 + 分布式假设，非 SNARK |
| E3 跨方绑定 | `call_digest` 盲关联（已实现） | 同 host 多服务 / 代理改写 / 真实性 | 协议绑定 + E1 |
| E4 隐私验证 | 内容不入回执 | 元数据 + 合规判定隐私化 | 访问控制；合规隐私化是本轮唯一候选 |
