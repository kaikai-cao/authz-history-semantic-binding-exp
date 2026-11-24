# D3-11 相关工作：逐篇核查、关键原文与差异

日期：2026-11-24｜证据等级说明：

- `FULL-TEXT`：已下载全文并逐字核对正文/定理/局限段。
- `REFERENCE-ONLY`：仅从引用列表提取元数据，未单独抓全文。
- `ABSTRACT-ONLY`：复用 D3-09 的摘要+缓存片段证据。
- `AUTHOR-CLAIM`：作者报告、本审计未复现（性能数字一律此类）。
- `OUR-INFERENCE`：本审计基于原文Evidence的推论，明确标注。

---

## A. Agent Execution Evidence: A SCITT Profile for Verifiable Records of AI Agent Runs

- 作者：S. Thaha, S. Shamsudeen（Individual Contributor）
- 版本：`draft-thaha-scitt-agent-execution-evidence-02`，November 2026，Intended status: Standards Track，Expires 5 May 2027
- **状态：Internet-Draft，不是 RFC**（原文 §status："Internet-Drafts are working documents... in no stage of development"）。
- 证据等级：`FULL-TEXT`（IETF archive txt，184994 字节）
- 依赖：`draft-ietf-scitt-scrapi-11`（SCITT Reference APIs, Birkholz/Geater/Delignat-Lavaud, June 2026, `REFERENCE-ONLY`）

### 覆盖的机制（原文可验证）
- **执行回执（§6.7, Execution Receipt Statement）**：每个 Decision Point 对每次调用产生一条回执，含 `seq, prev_hash, target, request_digest, response_digest, ts, agent_sig, actor_chain, principal_link, txn, call_digest` 等；CDDL key 映射：20=caller_agent_id, 21=caller_ref, 22=admission_basis, 23=actor_chain, 24=principal_link, 29=call_digest。
- **内容不入回执（§6.7）**：原文 "Content MUST NOT be included in a receipt (Section 10)"——只存摘要。
- **`response_digest` 承诺未篡改响应**：原文 "response_digest commits to the octets as received, before the Harness alters, truncates or withholds anything it passes to the agent"。即 Harness 被明确视为可能改动方。
- **`call_digest` 跨方盲绑定（§6.7.3）**：原文 "both sides compute call_digest over the same representation. It is therefore equal for one call and different for calls that ask for different things"；"A Serving Party computes its own value over the request it received and never takes it from the evidence presented"。HTTP 具体化：`SHA-256 over deterministic CBOR [method, request-target, content-digest]`，scheme/authority 因代理重写被排除。
- **Evidence Chain（§6.7.1）**：`seq, prev_hash` 有序链，注册进 VDS。
- **Admission（§6.7.2）**：Serving Party 对收到的每个调用产生 admission receipt，含 `call_digest`。
- **Linked Verification（§9）**：验证两侧回执的 `call_digest / principal / txn / Actor Chain` 一致，"parties each of which verified on its own"。

### §9.2 Meaning of PASS（决定性边界，逐字）
> "A PASS establishes that: the TS committed to each statement in its append-only VDS; each statement was signed by the named Issuer; the receipts form an unbroken chain sealed into that VDS; every call was recorded under a registered policy and configuration; each runtime identifier was declared for that time... A PASS of Linked Verification establishes, in addition, that each linked pair of receipts commits to the same request, as represented by call_digest, sent to a host the Serving Party declared, for the same Principal, transaction and Actor Chain, by parties each of which verified on its own."

> "It does not establish that the Serving Party is the service the caller meant where several services share that host, that every hop of the Call Chain is present, that an intermediary forwarded the request unchanged in the parts call_digest excludes, or that a Serving Party checked more than its admission_basis records."

> "A PASS does not establish that the Harness recorded every call, that a decision was correct, that an api-bound model was the one named, that a Policy Pack semantically tightens its parent, that monitoring observed every relevant behaviour, or that an Agent Assurance Assessor's suite is adequate. **Harness completeness is the composition point with remote attestation.** A Harness can produce RATS Evidence [RFC9334], for example an EAT [RFC9711] whose measurements cover the image named by harness.digest; a Relying Party MAY require that Evidence, with the Agent Credential payload digest as nonce. **This document does not define that binding.**"

### §14 Open Issues（原文）
- "Delegation scope: a mechanical test that a delegated Task's, or a later Actor's, effective scope is no wider than its parent's needs a common representation of scopes"—未定义。
- "Representation mapping: a defined mapping between different representations of one request, including proxies that rewrite the path... call_digest compares the request as sent with the request as received and cannot match a request that an intermediary changed."
- "Admission on the full actor history"——IETF 127 提议讨论，本文未定义。

### 对本轮的意义
A 是**跨组织执行证据的最强现成基线**：E3（跨方盲关联）已由其 `call_digest` + linked verification 实现。但 E1（事件真实）、E2（无遗漏）被 §9.2 明确划为范围外，且与远程证明的绑定"本文不定义"。不能把"多组织回执+哈希链+第三方验证"当创新——A 已覆盖。

---

## B. AI Agent Execution Profile of SCITT

- 作者：P. Emirdag, D. Feichtinger（Veridic Inc.）
- 版本：`draft-emirdag-scitt-ai-agent-execution-01`，October 2026，Intended status: Informational，Expires 15 April 2027
- **状态：Internet-Draft，不是 RFC**。
- 证据等级：`FULL-TEXT`（IETF archive txt，78448 字节）

### 覆盖的机制
- 独立 Evidence Custodian（Transparency Service）持有 append-only Evidence Chain；Issuer（Agent Operator）签名的 AIR（action record）；第三方持有 Evidence Receipt。
- `sequence_number + prev_chain_hash + captured_timestamp_ms` 防重放（§11.4）。
- Redaction Receipt（§12）：`content_hash` 覆盖脱敏形式，`original_hash` 供授权方验证特定字段，原始 PII 不进 TS。

### 信任假设（§11.2，逐字）
> "(a) The Transparency Service (Evidence Custodian) is structurally independent of the Issuer (Agent Operator). If the same entity operates both roles, the tamper-evidence guarantees are void. (b) The Transparency Service is operationally honest. (c) The Issuer's signing key is not compromised at the time of signing."

### 关键边界（逐字）
- §11.1 Threat Model："This profile does not address an Issuer that records an action inaccurately or not at all (Section 11.5)."
- §11.5 Capture Pipeline Compromise："A gap in sequence_number is evidence that a record was produced and not registered. **An action that was never recorded leaves no gap.**"
- §11.6 Custodian Compromise：被攻破的 TS "cannot forge Issuer signatures on existing AIRs or retroactively alter hash chain values without detection by any Relying Party holding a prior Evidence Receipt"。
- §11.7 Append-Only Integrity："enforced by both the hash chain structure and the Transparency Service operational policy. Neither alone is sufficient." 要求 WORM 语义。
- §11.8 Collusion："If the Issuer and the Transparency Service collude, they can jointly fabricate, suppress, or modify evidence without detection by Relying Parties who rely solely on receipts from the compromised Transparency Service. **This is the fundamental limitation of any two-party evidence system.**"
- §12 Privacy："Even without payload access, the COSE protected header exposes agent_id, action_timestamp_ms, and sequence_number. An observer with access to chain metadata can infer activity frequency, timing patterns, and action volume for a given agent deployment."

### 对本轮的意义
B 回答了"独立第三方证据托管是否消除 Agent Operator 信任"：**部分消除但引入 Custodian 信任**；结构独立性一旦破坏（同实体运营两角色），tamper-evidence 作废；双方串谋是根本限制。**E2 的"未记录操作不留缺口"在 B 中是原文明确的。**

---

## C. NovaFabric: Tamper-Evident, Replayable Evidence for Autonomous AI Agent Runs

- 来源：arXiv:2609.12582
- 证据等级：`FULL-TEXT`（arXiv HTML v1，转纯文本 192526 字节）
- 性能数字：全部 `AUTHOR-CLAIM`，未复现。

### 覆盖的机制
Run Capsule + 15 实体 + DSSE 签名 + RFC 3161 时间戳 + Merkle 日志 + 红action attestation；四模式 replay（exact/mocked/semantic/forensic）；stock-tool verifier；provider-neutral。

### Trusted Computing Base（§3.1，逐字，决定性）
> "Every guarantee below is conditional. The conditions belong before the guarantees, so we state them here. NovaFabric verification assumes: the capture hooks and proxy observe the process faithfully; the local spool and node collector do not selectively drop; the signing-key custodian is honest; the timestamp authority, transparency-log operator and its witnesses behave as their protocols specify; the object store preserves and returns stored objects...; and the verifier obtains its trusted key and policy independently of the bundle it is checking. **The sharpest of these is the key custodian: a holder of a tenant signing key can produce a validly signed capsule asserting something false, and no amount of downstream verification detects it.** What NovaFabric provides is therefore **conditional verifiability** — detection of post-hoc modification by anyone outside that trusted set—not evidence that is true irrespective of who produced it."

（§5.1 亦称 "a key custodian can still sign a false... detection, not prevention"。）

### 完整性与重放的缺口（逐字）
- §4.11："Capture completeness is not yet at unity. The fidelity fixes... restore the three lost evidence streams—mean per-scenario completeness 0.652 ± 0.064—but completeness is not yet 1.0... subprocess/CLI, scheduler, and cross-service events have no capture surface yet. Driving completeness toward 1.0... is explicit future work."
- §4.11："a second limit... they are self-reported. Both the completeness metric and the 100% model- and tool-call capture result are computed from records NovaFabric itself wrote, so they establish internal consistency and not, on their own, correspondence with what actually happened."
- §4.3 工具响应替换："only 2 of 10 replayed workloads completed within our 300s budget... tool responses are not substituted at all, so a replayed workload issues its tool calls against the live environment... full reproduction of a tool-using workload is not demonstrated by this evaluation... Wiring the tool dispatcher—which exists but is not installed—is future work."
- D4/D5 缺陷：replay 记录把 capsule 中以 `tool_calls_mocked`（schema 定义 "served from cache"）字段存在的工具调用计入 —— "every mocked replay record for a tool-using run asserted substitutions that never occurred"，且该假值被封进 outcome digest。作者修了记录但未加能力。

### 对本轮的意义
C 是最直接面对"捕获完整性 + 重放真实性"的系统论文，但结论是**明确的条件性**：key custodian 可签假无法下游检测；完整性未达 1.0 且自报；工具响应替换没实现；实现自身出现"记录无法信任自己的 provenance"。这是 E1/E2 缺口的系统级实证。

---

## D. Actions with Receipts: Jointly Binding Claims, Evidence, and Execution for Replayable Tool-Agent Auditing

- 来源：arXiv:2610.00327（系统名 EC-Agent）
- 证据等级：`FULL-TEXT`（arXiv HTML v1，转纯文本 135646 字节）
- 性能数字：`AUTHOR-CLAIM`，未复现。

### 覆盖的机制
Claim-anchored execution contract，联合绑定四项：emitted claim c、exact source span、ordered execution prefix、source version/access state。收据含 `emission anchor ρ_c, evidence refs R_c, execution commitment D_exec, manifest identity m, source version/access identity ν`。七个可测性质 P1–P7：claim-emission / source / ordered-execution / oracle separation / persisted-object replay / execution-rerun consistency / version-access binding。

### 关键数据（AUTHOR-CLAIM）
- 1280 cross-object attacks 检测 1275（0.9961）；移除目标性质后针对攻击检出率降到 0.0156–0.0625。
- 语义支持：conflict-aware guard F1 0.8865 / 误接受 0.0729；unseen failure families 0.8679 / 0.0938。
- lexical-adversarial mutation：16/16 **全部接受**——"cryptographic integrity and semantic adequacy are independent properties"。
- 成本：serialization 0.19ms / online verify 0.47ms / bundle replay 1.31ms；execution rerun 16.88s（AUTHOR-CLAIM）。

### 信任边界（§A.5 与 §3，逐字，决定性）
> "The trusted components are the runner, the observation logger, the local corpus manifest, the verifier implementation, and the replay environment. Under this trust model, the contract provides record integrity after commitment, source-content binding, and execution-order binding... **Observation authenticity remains an external property supplied by an anchor such as a signed append-only log, an authenticated event source, or hardware-backed attestation**, combined with a document-version and access-control identity."

> "the runner and observation logger are trusted during execution, and the digest commits the recorded trace after the answer event. The online policy never receives the separate oracle labels."

§4.10 Limitations："The integrity guarantee assumes a trusted runner and observation logger... compromised recorders require additional evidence."

### 对本轮的意义
D 把"绑定"做到 claim/span/执行序/版本级，但**明确把观测真实性外包给外部锚点**，且 runner/logger 执行期可信。它是"绑定做什么"的强基线，不解决"事件怎么可信地诞生"（E1 强定义）与"无遗漏"（E2）。

---

## E. 复用 D3-09 的三篇（不重复全文抓取）

| 文献 | 证据等级 | 与本轮的关系 |
|---|---|---|
| zkAgent: Verifiable LLM Agent Execution via One-Shot Transcript Proofs（ePrint 2026/199, CCS 2026, DOI 10.1145/3830454.3846564） | `ABSTRACT-ONLY`+缓存片段 | 证 provider 忠实执行推理 + zkTLS/zkVM 工具观察真实；**不碰授权合规、不隐藏轨迹**。若要求 E1 的"执行一致性"，zkAgent 是唯一现成构造，但它证明的是忠实执行不是合规 |
| PoE: Proof of Execution（arXiv 2607.05397） | `FULL-TEXT` | 签名+哈希+ECES 绑定授权/效果/历史/重放，明文 trace + 单 Gateway；§10 明确"不替代 TEE/zkVM/共识"，trace completeness 是部署假设 |
| CVA: Cryptographically Verifiable Authorization（Frontiersin 1966725） | `FULL-TEXT` | Groth16 PoC（531 约束）单次 request/principal/context/policy 绑定；§4.5 runtime execution binding 是 structural gap（ZK 电路证明时无运行时状态访问权）；§6 多跳 `scope_k ⊆ scope_{k-1}` 明示 future work；§7 context binding 未实现、安全归约只是 informal sketch |

## F. 从 References 追踪的相关工作方向（登记，未逐篇展开全文）

以下方向由上述论文 Related Work / References 指向，本轮登记其角色，不据此声称已读全文：
- **Proof-Carrying Code / Authentication**（D3-09 已涉）、**Verifiable Computation / zkVM**（PoE/CVA/zkAgent 覆盖）、**Recursive SNARK / IVC**（D3-10 已裁：递归连续状态转换 ≠ 外部历史完整）、**Authenticated Data Structures**（D 引 Merkle/CT）、**Transparency Logs**（A/B 引 SCITT VDS、CT；D3-10 已证只增/分叉检测靠一致性证明+gossip，是分布式假设）、**Capability-Based Security / Information-Flow Security**（D3-08 AgentCap/DelegateGuard 已裁）。

## G. 差异分析（OUR-INFERENCE，基于以上原文）

1. **四篇强基线形成完整互补但共享同一外部信任边界**：A/B 解决跨组织回执关联与托管独立性；C 解决篡改可检与条件重放；D 解决 claim/执行联合绑定。它们一致地把"事件是否真实发生、是否无遗漏"推给外部锚点（远程证明 / 独立 Custodian / 网络遥测 / 可信 runner）——**没有一篇把它当作可纯密码学证明的性质**。
2. **E3 已被 A 的 `call_digest` 覆盖**：这是本轮最需承认的既成事实。任何"跨组织同一次调用关联"的 ZKP 方案，必须说明相对明文 `call_digest` 盲比对新增了什么。
3. **唯一残存的候选是 E4 的"合规判定隐私化"**：四篇做到"内容不入回执"（只存摘要）+ 元数据靠访问控制，但没有一篇给出"隐藏全部细节、只证 Dec=1"的密码学构造。这构成方向 A 的候选增量，但需过 `DECISION.md` 的 H1/H2 门禁，且必须警惕 D3-07-B 的 private-only 自洽陷阱。
