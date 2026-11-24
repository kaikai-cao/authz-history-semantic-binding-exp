# D3-11 构造级比较与 X1–X7 攻击分析

日期：2026-11-24｜分类：`BLOCKED` / `BLOCKED_WITH_ASSUMPTION` / `NOT_BLOCKED` / `NOT_APPLICABLE`

---

## 第一部分：五类机制的构造级比较

### 机制 1：Ed25519 / COSE 签名回执

| 维度 | 结论 |
|---|---|
| 能证明什么 | 签名归属：某条记录由持有 `sk_X` 的实体签署；承诺后内容不可篡改 |
| 不能证明什么 | 记录内容真实（X3）；工具内部行为与回执一致；无遗漏（X1/X4）；跨方关联（需额外 `call_digest`） |
| 谁采集真实事件 | 签名方 X 自己在 Decision Point 记录——即"谁签名谁自证" |
| 谁能遗漏 | 任何负责产生回执的一方（Harness、Serving Party） |
| 谁能伪造 | 密钥持有者（NovaFabric：key custodian 可签假，下游检不出） |
| 谁能看到完整请求/响应 | 签名方 X（Verifier 只看摘要） |
| 谁处理撤销/状态更新 | 签名机制本身不处理；需外部状态 |

### 机制 2：哈希链 + Merkle Transparency Log + SCITT

| 维度 | 结论 |
|---|---|
| 能证明什么 | 链内不可篡改（`prev_hash`）、append-only + inclusion/consistency proof（VDS）、跨方 `call_digest` 盲关联（SCITT §9）、注册证明 |
| 不能证明什么 | Harness 记录每次调用（§9.2 明确 NOT）；未记录操作（"leaves no gap"）；同 host 多服务区分；代理改写部分 |
| 谁采集真实事件 | Harness / Serving Party 的 Decision Point；TS 只保证已提交内容的只增 |
| 谁能遗漏 | **Harness（产生回执之前）**——TS 无法看见从未提交的东西 |
| 谁能伪造 | Issuer（有签名密钥）；Issuer+TS 串谋（two-party 根本限制） |
| 谁能看到完整请求/响应 | 无（只存摘要）；但元数据 agent_id/timestamp/seq 可见 |
| 谁处理撤销/状态更新 | SCITT -02 有 assurance 状态 suspended/withdrawn（§9.2 提到）；本质是外部状态 |

### 机制 3：独立 Evidence Custodian + 双边回执

| 维度 | 结论 |
|---|---|
| 能证明什么 | TS 与 Issuer 独立时的防篡改（B §11.2）；第三方持有回执可离线索验；sequence gap 检测"产生未注册" |
| 不能证明什么 | 未记录操作（§11.5）；Issuer 不准确记录；Issuer+TS 串谋（§11.8 根本限制）；记录真实性 |
| 谁采集真实事件 | Issuer 的 capture pipeline（可被攻破，§11.5） |
| 谁能遗漏 | capture pipeline（未记录即无缺口）；串谋双方 |
| 谁能伪造 | 攻破 capture pipeline 者；串谋的 Issuer+TS |
| 谁能看到完整请求/响应 | TS 可访问记录内容（B §12 要求权限控制）；元数据对外可见 |
| 谁处理撤销/状态更新 | 外部，机制不自带 |

**关键回答**：独立 Custodian **没有消除** Agent Operator 信任，而是**把一部分信任从 Operator 转移到 Custodian**；同一实体运营两角色则 tamper-evidence 作废（§11.2）。

### 机制 4：TEE / Remote Attestation / zkVM

| 维度 | 结论 |
|---|---|
| 能证明什么 | 某代码在受信任硬件/VM 内执行（RATS/EAT/quotes）；zkAgent 式可证 provider 忠实执行推理 + 工具观察真实 |
| 不能证明什么 | 授权合规（zkAgent 不碰）；无遗漏（TEE 外未执行无法观测）；SCITT §9.2 把 Harness completeness 指向远程证明但"本文不定义该绑定" |
| 谁采集真实事件 | TEE 内的测量代码 / zkVM 执行轨迹 |
| 谁能遗漏 | TEE 外部、或测量范围之外的事件 |
| 谁能伪造 | 攻破 TEE 者；持有租户签名密钥者（NovaFabric TCB 仍要求 custodian 诚实） |
| 谁能看到完整请求/响应 | TEE 内部可见；对外可零知识隐藏（zkVM） |
| 谁处理撤销/状态更新 | 外部 |

**定位**：TEE/zkVM 是关闭 E1 强定义（执行一致性）与部分 E2（Harness completeness）的**唯一现成路径**，但引入硬件信任基或 zkVM 完备性假设，且不是"换一个证明系统"那么简单。

### 机制 5：ZKP / 递归 SNARK / 隐私证明

| 维度 | 结论 |
|---|---|
| 能证明什么 | 对已给定公开输入的关系证明（如"两条已签承诺满足关联+合规，隐藏细节"）；commit-and-prove；范围/集合证明 |
| 不能证明什么 | 输入是否真实（D3-10：证明关系不含的事件无法被证明）；外部是否遗漏；签名是否由真实工具产生——这些是 E1/E2，在证明系统之外 |
| 谁采集真实事件 | 证明者从外部拿到 witness；ZKP 不采集 |
| 谁能遗漏 | 证明者可选择性提交子集（D3-10 X2′）——正是递归证明的盲区 |
| 谁能伪造 | 若 witness 无 public 锚点，证明者可自造（D3-07-B private-only 陷阱） |
| 谁能看到完整请求/响应 | 可隐藏（这是 ZKP 相对基线的真正增量） |
| 谁处理撤销/状态更新 | 需外部新鲜状态；ZKP 只证关系 |

**定位**：ZKP 唯一明确新增的是**E4 的隐私化验证**（隐藏细节仍可证合规），前提是要有 public 锚点绑定证据真实性（E1/E2 由外部机制提供）。ZKP **不能**独立解决 E1/E2。

### 五类机制一句话分工

> 签名管"谁说的"，哈希链/TLog 管"改没改过"，Custodian 管"托管独不独立"，TEE/zkVM 管"是不是真在受信环境执行"，ZKP 管"能不能隐藏着证明"。**"事件有没有真发生、有没有漏"不在任何一类的能力内。**

---

## 第二部分：X1–X7 攻击验证

对每个攻击，给出"跨全部机制的总体判定"以及关键方案的阻断条件。不写"加 ZKP 就能解决"。

### X1 — Agent 遗漏一次真实工具调用（目标 E2）
- **攻击过程**：Agent A 的 Harness 实际调用了 Tool X，但决定不为该调用产生/注册回执；由于无回执，`seq` 无缺口。
- **A（SCITT）**：`BLOCKED_WITH_ASSUMPTION` —— 只有该调用进入某个 Decision Point 才会留痕；§9.2 明确 PASS 不保证 Harness 记录了每次调用，补救是 RATS/EAT 远程证明绑定，但"本文不定义该绑定"。
- **B（Profile）**：`NOT_BLOCKED` —— §11.5 原文："An action that was never recorded leaves no gap."
- **C（NovaFabric）**：`BLOCKED_WITH_ASSUMPTION` —— 依赖 capture hooks/proxy 忠实、spool/collector 不丢（TCB）；完整性自报未达 1.0。
- **D（Receipts）**：`NOT_APPLICABLE` —— 只承诺已记录轨迹的绑定，trusted runner 前提。
- **ZKP**：`NOT_APPLICABLE` —— 未进入 witness 的事件无法证明（D3-10 X2′）。
- **总体**：`BLOCKED_WITH_ASSUMPTION`（唯一路径是让事件在产生时进入受信采集面 + 远程证明/独立观察）。

### X2 — 调用方和服务方对同一次调用提供不同参数（目标 E3）
- **攻击过程**：A 对外展示 `req_A`，S 对外展示 `req_S ≠ req_A`，声称是同一次调用。
- **A（SCITT）**：`BLOCKED_WITH_ASSUMPTION` —— `cd_A ≠ cd_S` 时 linked verification 正确拒绝；但若双方**合谋**对同一物理调用算相同的假 `cd` 并一致展示，验证者无法分辨（依赖"parties each of which verified on its own"）。
- **B**：`BLOCKED_WITH_ASSUMPTION` —— 依赖双方独立签名，串谋则破（§11.8）。
- **总体**：`BLOCKED_WITH_ASSUMPTION`（双方各自独立验证并签名是前提；合谋场景非密码学可解）。

### X3 — 工具执行成功但返回伪造/错误回执（目标 E1）
- **攻击过程**：Tool X 实际执行了操作 q，但回执声称执行了 p（或返回伪造 `resp_digest`）。
- **A（SCITT）**：`BLOCKED_WITH_ASSUMPTION` —— `call_digest` 由 S 对自己收到的请求算、不照抄（§6.7.3），但 §9.2 明确不保证"Serving Party checked more than admission_basis"、不保证"decision correct"、不保证"api-bound model 就是命名的那个"。
- **C（NovaFabric）**：`NOT_BLOCKED` —— key custodian 可签一条断言虚假的合法 capsule，"no amount of downstream verification detects it"。
- **TEE/zkVM**：`BLOCKED_WITH_ASSUMPTION` —— zkAgent 可证观察真实，但引入 zkTLS/zkVM 信任基，且证明的是忠实执行不是合规。
- **D（Receipts）**：`BLOCKED_WITH_ASSUMPTION` —— 绑定已记录内容 + 外部 observation anchor；trusted runner 前提。
- **总体**：`BLOCKED_WITH_ASSUMPTION` —— **签名有效 ≠ 事件真实**，需外部信任基（TEE/zkTLS/可信 runner）。

### X4 — 两个组织串谋删除或隐瞒执行记录（目标 E2）
- **攻击过程**：Issuer（Org A）与 Custodian 串谋，联合删除某段记录并重签链。
- **A（SCITT）**：`BLOCKED_WITH_ASSUMPTION` —— append-only VDS + 外部 witness/gossip 可检测分叉，但依赖分布式审计生态。
- **B（Profile）**：`NOT_BLOCKED` —— §11.8 原文：串谋双方可"fabricate, suppress, or modify evidence without detection"；"fundamental limitation of any two-party evidence system"。
- **总体**：`BLOCKED_WITH_ASSUMPTION`（强前提是 Custodian 与 Issuer 结构独立 + 操作诚实 + 外部见证）。B 的立场更悲观：仅靠其机制 `NOT_BLOCKED`。

### X5 — 将一个 Agent 的回执移植到另一个 Agent 的任务（目标 E3）
- **攻击过程**：把 `r_A(task1)` 伪装成 `r_A(task2)` 的证据。
- **A（SCITT）**：`BLOCKED_WITH_ASSUMPTION` —— `actor_chain / principal_link / txn / caller_ref` 提供绑定（§6.7.3）；若 txn 唯一且字段可信，则移植被拒。前提是这些字段本身可信（归 E1）。
- **D（Receipts）**：`BLOCKED` —— cross-object transplant 检出率 1.0000（AUTHOR-CLAIM，针对 source-version/evidence transplant）。
- **总体**：`BLOCKED_WITH_ASSUMPTION`（绑定字段 + 唯一 txn；字段真实性依赖 E1）。

### X6 — 向不同验证者展示不同的证据链（目标 E2）
- **攻击过程**：对 Verifier1 展示含调用 a 的链，对 Verifier2 展示含调用 b 的链。
- **A/B（SCITT）**：`BLOCKED_WITH_ASSUMPTION` —— 一致性证明 + 外部审计者/gossip 可检测 VDS 分叉；但依赖"有见证者在看"这一分布式假设（D3-10 已证非 SNARK 属性）。若 Custodian 与 Issuer 同实体且无外部见证，`NOT_BLOCKED`。
- **总体**：`BLOCKED_WITH_ASSUMPTION`。

### X7 — 验证者通过公开摘要/元数据推断敏感调用内容或身份（目标 E4）
- **攻击过程**：观察 `agent_id / action_timestamp_ms / sequence_number`、`call_digest` 稳定性，推断调用频率/时序/动作量或关联同一 agent。
- **A（SCITT §10）/D**：`BLOCKED` 于"请求/响应原文"——内容不入回执，只存摘要；原文 "Content MUST NOT be included in a receipt"。
- **B（Profile §12）**：`BLOCKED_WITH_ASSUMPTION` 于元数据——"Even without payload access, the COSE protected header exposes agent_id, action_timestamp_ms, and sequence_number... infer activity frequency, timing patterns, and action volume"；靠访问控制，非密码学隐藏。
- **ZKP**：`BLOCKED_WITH_ASSUMPTION` 于"隐藏全部细节只证合规"——技术上可行（方向 A），但需 public 锚点绑定证据真实性，否则 D3-07-B private-only 陷阱。四篇基线均未实现。
- **总体**：`BLOCKED_WITH_ASSUMPTION`（内容层已达成；元数据与合规判定的隐私化仍靠访问控制或待建 ZKP）。

### 攻击判定汇总

| 攻击 | 目标 | 总体判定 | 阻断能力来源 |
|---|---|---|---|
| X1 遗漏真实调用 | E2 | `BLOCKED_WITH_ASSUMPTION` | 受信采集面 + 远程证明/独立观察（非密码学） |
| X2 双方不同参数 | E3 | `BLOCKED_WITH_ASSUMPTION` | 双方独立签名；合谋不可解 |
| X3 伪造/错误回执 | E1 | `BLOCKED_WITH_ASSUMPTION` | 外部信任基（TEE/zkTLS/可信 runner） |
| X4 串谋删除 | E2 | `BLOCKED_WITH_ASSUMPTION` | Custodian 独立 + 外部见证；B 判 `NOT_BLOCKED` |
| X5 回执移植 | E3 | `BLOCKED_WITH_ASSUMPTION` | 身份链/txn 绑定 + 字段真实性 |
| X6 多版本证据链 | E2 | `BLOCKED_WITH_ASSUMPTION` | VDS 一致性 + gossip（分布式假设） |
| X7 摘要推断隐私 | E4 | `BLOCKED_WITH_ASSUMPTION` | 内容层已达成；元数据靠访问控制，合规隐私化待建 |

**七个攻击没有一个由纯密码学构造 `BLOCKED`。** 六个是 `BLOCKED_WITH_ASSUMPTION`（阻断能力来自外部信任基/分布式假设），内容层 X7 部分 `BLOCKED`。这是本轮裁决的核心实证：缺口不在证明系统，在信任边界。
