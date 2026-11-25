# RELATED-WORK.md — D3-14-01 有限研究缺口审计

基准日期：2026-11-25。文献核查日期：2026-11-25。
任务性质：只读文献审计与安全性质对照。本文不宣布选题成立、不定义新协议、不建电路。

**核验口径**：
- `原文已核对` = 本次审计取得全文并逐节读取，引用给出章节号 / 行号锚点。
- `摘要已核对` = 仅取得官方摘要页与部分正文，引用限于摘要明确表述。
- 凡作者自述的性质、限制、实验结果均标注为「作者声称」；本次审计的推论标注为「我方推论」。
- Internet-Draft 一律标注为个人 / 非 RFC / 无正式标准地位，不写作「标准」。

---

## A. CVA — Cryptographically Verifiable Authorization for Autonomous AI Agents

- **元数据**：Mar Llambí-Morillas, Daniel Fernández-Fernández. *Frontiers in Computer Science*, vol. 8, art. 1966725, 2026-09-24, DOI `10.3389/fcomp.2026.1966725`. 作者版本 arXiv:2607.21325v3。
- **文献类型**：**peer-reviewed 期刊论文**（Frontiers "Hypothesis and Theory" 栏目）。
- **核验状态**：原文已核对（HTML 全文）。
- **原文明确提出的贡献**（摘要 / §1 / §3）：把 Agent 授权形式化为关系 `R_CVA`，联合绑定 principal、具体请求 `q_i`、执行上下文 `c` 与策略 `P_j`；给出候选性质集（authorization soundness、principal binding、request binding、policy binding、replay resistance）；给出 Groth16 zk-SNARK 可执行 PoC；把「身份绑定 / 授权请求绑定 / 运行时执行绑定」三者的**结构性分离**形式化为中心开放问题。
- **实际构造 / 原型**（§5.1–5.2）：Groth16 over bn128、Circom 2.x、snarkjs、FastAPI 网关；用随机化双输入 Poseidon 实现 `CommitID`；电路只实例化 principal binding、plan-level request binding 与私有策略谓词。
- **作者明确声明的限制**（§6 / §7）：形式模型是 preliminary，完整安全归约留作未来工作；原型未经独立电路审计；context binding 在模型中但未实现；**runtime execution binding 是开放问题，ZKP 授权层自身无法解决**；多跳委派 scope 约束 `scope_k ⊆ scope_{k−1}` 未形式化；完整多 Agent 符号敌手模型留作未来工作。原文 §4.5：*"A ZK circuit is evaluated at proof generation time over a committed representation of the intended request; it has no access to the runtime state at execution time..."*；*"Closing this gap requires a trust anchor that operates at execution time rather than at proof generation time."*
- **与本研究问题的重叠**：仅覆盖请求级授权绑定与属性隐私；**未覆盖**区间权限缺失、撤销收敛、覆盖完整性。作者本人把运行时绑定判为需外部信任锚（TEE / 远程证明 / 可验证执行回执）的问题，与 D3-13 结论一致。
- **我方推论**：CVA 不能作为 P3/P4/P6 的基线，只能作为「请求级 ZK 绑定已解决」的边界证据。

## B. PoE — Proof of Execution: Runtime Verification for Governed AI Agent Actions

- **元数据**：James Rhodes, George Kang. arXiv:2607.05397v1。arXiv 摘要页显示 `[Submitted on 26 Apr 2026]`（与编号月份 2607 不一致；本审计按页面显示记录，不推断原因）。comments：14 pages，含 formal soundness 与 replay theorems。
- **文献类型**：**arXiv preprint**（cs.CR; cs.AI），非同行评审版本。
- **核验状态**：原文已核对（HTML 全文）。
- **原文明确提出的贡献**（摘要 / §3）：把执行定义为三元组 `x=(C,T,R)`（contract、Execution Causal Event Stream、replay context）；给出良构谓词与五个 validator-checkable invariants；五个语义保证（授权、路径合规、deny 零效果、历史完整性、可重放）；在显式密码学与部署假设下证明 soundness；Prime Execution Model 分离 planning/enforcement/effect/recordkeeping 四个 authority planes；仅在 `PoE=1` 时签发 Execution Attestation Certificate（EAC）。
- **实际构造 / 原型**：单节点 TypeScript 原型；作者报告约 2.7 ms 最小流程开销、并发批 4.4% 开销、八事件轨迹约 1.1 KB、注入的 Gateway-bypass 与 trace-mutation 被拒。
- **作者明确声明的限制**（§4.2 A1–A7 / §6 / §10）：A3 single-logical-Gateway integrity、A4 Recorder integrity、A5 trace completeness、A6 dependency-declaration completeness、A7 recorder-clock monotonicity；原文明确 *"A5–A7 are deployment assumptions, not cryptographic ones."*；§5 trace completeness 由 Effector-exclusive credentialing 规约；§6 *"Privacy-preserving variants — selective disclosure or zero-knowledge EACs proving PoE=1 without revealing the full trace — are open work."*；§10 *"Single-Gateway scope; composition open."*；摘要明确 *"PoE does not replace consensus, TEEs, or zkVMs."*
- **与本研究问题的重叠**：覆盖执行事件流、因果与执行证据绑定；**不覆盖**授权状态区间语义，ZK 隐私变体被作者列为开放工作。
- **我方推论**：PoE 是「执行轨迹完整性来自架构纪律而非密码学」的强证据，不能据此推导覆盖完整性。

## C. SCITT Agent Execution Evidence — draft-thaha-scitt-agent-execution-evidence-02

- **元数据**：S. Thaha, S. Shamsudeen（Individual Contributor），`draft-thaha-scitt-agent-execution-evidence-02`，2026-11，expires 2027-05-05；Intended status: Standards Track。
- **文献类型**：**Internet-Draft（个人提交，非 RFC，无标准地位）**，SCITT profile。
- **核验状态**：原文已核对（全文）。
- **原文明确提出的贡献**（摘要 / §6.7 / §8 / §9）：把已注册身份、声明能力、风险评级、受监督运行状态绑定到每次调用的 hash-chained record；定义 admission records、跨运营者调用的 linking、Registration Policy、离线验证与 Bundle 要求。明确不定义认证方案、通用风险分级、标识方案或策略语言。
- **实际构造 / 原型**：Signed Statements + Verifiable Data Store（TS）+ Execution Receipt Statement（只放请求/响应摘要）、Revocation Statement、Assurance Statement；Linked Verification 用 `call_digest` 关联两端回执。
- **作者明确声明的限制**（§9.2）：*"A PASS does not establish that the Harness recorded every call, that a decision was correct..."*；Linked Verification 不证明 *"that every hop of the Call Chain is present"*；*"Harness completeness is the composition point with remote attestation... This document does not define that binding."* §10 用 `principal_link`（双方已有 token 的摘要）、pepper 哈希、epoch roots 做隐私，且明示 `txn`/`actor_chain` 会揭示参与运营者。全文无 ZK 机制、无区间缺失或授权历史重放关系。
- **与本研究问题的重叠**：每调用回执与跨组织隐私关联已覆盖；**不覆盖** P3/P4/P5 的授权状态与收敛判定。
- **我方推论**：与 D3-11/D3-12 结论一致——"隐藏调用关联"已由 `principal_link`/epoch roots 覆盖，不能当新增量。

## D. Replayable Authority Histories — draft-rampertab-audit-agent-authority-history-00

- **元数据**：draft-rampertab-audit-agent-authority-history-00，2026-10，expires 2027-05-02；个人 Internet-Draft，Intended status: Informational。
- **文献类型**：**Internet-Draft（个人提交，非 RFC）**。
- **核验状态**：原文已核对（全文 4704 行，重点 §9/§10/§11/§12/§14/附录 B/C）。
- **原文明确提出的贡献**：可重放授权历史（Grant、Delegation、Revocation、拒绝记录、duty、session/epoch、owner key rotation）；确定性重放与状态根；外部锚定/witness/freshness；可选 ZK profiles。
- **实际构造 / 原型**（附录 B）：IronTrellis 1.0.0-rc.2 开源实现（2026-10-29）；七个 Groth16/BN254 ZK 证明用于合成负载（revocation、three-period、count、cumulative、exhaustion、handover of both、handover of state）。附录 C：Lean 4 对规则模型的形式化，15 个 headline theorems；集成版 186 modules / 2,048 theorems，仅依赖 Lean 三条标准公理。
- **作者明确声明的限制**：
  - §12：*"A claim relying on absence, revocation status, intersecting authority or accumulated usage MUST cover every record that can change the answer, by complete replay, authenticated exhaustive ranges or another specified completeness relation; an inclusion proof for a granting record alone does not establish the absence of a prohibition."* 且 *"universally quantified claims require coverage of their whole domain."*
  - §12：*"Zero knowledge limits disclosure beyond the public statement; it does not conceal the statement."*；*"A hidden-record inclusion result MUST NOT be reported as authority, revocation freshness, budget compliance, duty closure, complete capture or external truth..."*
  - §10.1：覆盖分类 enforced / recorded / open；*"A claim that an agent is 'governed' without this table is not supported by the model."*
  - §11.2：验证者**不能**确立「动作在世界产生效果」「每次调用都经过决策点」「时间戳为真」「export 是最新状态（无外部 freshness 证据时）」。
  - 附录 B：七个 ZK 证明 *"are not production-qualified ... they establish neither authority, completeness nor freshness."*
  - 附录 C：*"The largest open piece is a proof that replaying any history always rebuilds exactly the same state."*；模型不是 TypeScript 本身。
- **关键词检索结果**：全文对 `interval absence` / `quiescence` / `ever usable` / `root-epoch` / `late effect` **零命中**（本次审计 grep 核验）。
- **与本研究问题的重叠**：授权历史 ZK 披露与「缺失/撤销证明必须覆盖全部相关记录」的规范性要求已明确提出；私有 authority profile 已可隐藏 delegators 与 terms；**未提出**区间级缺失命题或 root-scoped quiescence。
- **我方推论**：这使「ZK 隐藏委派拓扑」与「完整性覆盖要求」都不再是空白；剩余部分只能是把 ZK profile 作用到另一份证书上的实例化问题。

## E. Interval Absence Claims in Agent Auditing — draft-baek-audit-absence-claims-00

- **元数据**：Jungsoo Baek（Certum Systems），`draft-baek-audit-absence-claims-00`，2026-10-31，expires 2027-05-04；Intended status: Informational；个人 Internet-Draft。
- **文献类型**：**Internet-Draft（个人提交，非 RFC）**。
- **核验状态**：原文已核对（全文 952 行，§4.1–4.5 / §5 REQ-1–13 / §6 T-1–22 / §7–9 全部读取）。
- **原文明确提出的贡献**：把「区间内权限是否可用（usability）」与「是否使用（use）」分离；三值语义 ABSENT / PRESENT / INDETERMINATE，偏置防 false-safe；REQ-1–13（含 REQ-4 stated completeness、REQ-8 lingering authority / revocation debt、REQ-9 recovery、REQ-10 enforcement link、REQ-11 cross-domain inputs、REQ-12 stated assumptions & independent checking、REQ-13 attribution by effect）；22 个场景 T-1–T-22（T-1 unused grant、T-3 lingering session、T-4 late completion after recovery、T-8 unrecorded path、T-14 sub-agent、T-22 quiet interval）。
- **实际构造 / 原型**：**无**。摘要原文：*"It does not define a protocol, a data format, or a verification algorithm."*
- **作者明确声明的限制**：§4.1 若授权与撤销都发生在两次快照之间，快照也看不到；§8 *"An ABSENT outcome holds only under its stated assumptions (REQ-12). It does not hold against an operator that fabricates evidence or omits evidence..."*；§8 PRESENT 不表示被使用或滥用；§9 *"Deployments that share such evidence with external auditors consider what it discloses and may use selective-disclosure techniques."*（仅一句，未定义机制）；§7 指出 transparency log 的非包含结论仅在日志已知包含全部相关事件时支持 ABSENT。
- **与本研究问题的重叠**：**直接定义了候选命题本身（P3）与三值口径、完整性与跨域要求**，但明确把协议/格式/算法留空。
- **我方推论**：候选的「问题定义」来源已完全落在 Baek；任何构造都必须满足 REQ-2/REQ-4/REQ-8/REQ-12，否则会退化为 false-safe。

## F. Root-Scoped Quiescence — arXiv:2609.21284

- **元数据**：Genliang Zhu, Chu Wang. *Authorization Revocation for Long-Running AI Agents: Root-Scoped Quiescence under Delegation and Asynchronous Execution*，arXiv:2609.21284v1，2026-09-18；39 pages，cs.PL / cs.AI / cs.CR；含完整证明附录。
- **文献类型**：**arXiv preprint**。
- **核验状态**：原文已核对（HTML 全文）。
- **原文明确提出的贡献**（摘要 / §3–§4）：定义 root-scoped authorization quiescence；协议线性化 root cut、fence 旧根扩展与受保护 sink、用 minimal sufficient root sets 的反链表示 alternative/conjunctive authority、把 provider-frontier certificates 组合为已注册旧根路径上的 cutset、精确 channel-token 记账；缺失或冲突证据保持 `INDETERMINATE`；在假设下证明 post-cut issuer non-expansion、support-sound projection、compositional soundness、independent-support preservation、merge-order independence、crash/replay stability。三值判定 `QUIESCENT` / `NOT_QUIESCENT` / `INDETERMINATE`。
- **实际构造 / 原型**：17 例 late-effect 测试套件（2 个 cancellation-only 与 1 个 cut-only 接受同一已调度迟到效果；2 个 cut-plus-fence、1 restart、1 stale-process 拒绝）；独立实现的 checker 验证 17/17 轨迹并拒绝 44/44 语义回归（作者报告）。
- **作者明确声明的限制**（摘要 / §3.4 / §3.5）：证书 *"establishes root-relative authorization quiescence within its bound manifest and configuration, not global idleness, rollback, or business completion."*；A6 registry/manifest completeness 是安全前提；*"an effect path absent from the registered manifest [is] outside the theorem domain"*；*"Neither of the other verdicts is converted to success by timeout, retry exhaustion, majority vote, or an agent's assertion that it has stopped."*
- **隐私 / ZK 覆盖**：全文 `zero-knowledge` / `privacy` / `hide topology` 仅出现在参考文献或 CCS 分类词，**无隐私机制、无 ZK 构造、无第三方隐藏拓扑的验证语句**。
- **与本研究问题的重叠**：**P4/P5 的形式化与构造已由本文明确解决（在有界 manifest 内）**；P6 未被触及。
- **我方推论**：任何新的「区间撤销收敛证明」若只复述本文的 cut/fence/frontier/manifest 结构，属于拼装而非新性质。

## G. Agent Tool Recovery — arXiv:2611.23353

- **元数据**：Song Xu. *Idempotency Is Not Recovery: A Fault-Injection Study of Language-Model Agent Tool Actions*，arXiv:2611.23353v2（v1 2026-11-17，v2 2026-11-20）；cs.SE / cs.AI。
- **文献类型**：**arXiv preprint**（作者自述：早期单作者预印本，后续增加作者的修订版已投 *IEEE Transactions on Reliability* —— 投稿非录用，本审计不视为 peer-reviewed）。
- **核验状态**：摘要已核对（官方摘要页 + 提交历史）。
- **原文明确提出的贡献**（作者声称）：在受控 Agent runtime 中组合 authorization、action ledger、target-side idempotency、reconciliation、evidence sealing；注入十类单机故障，四个配置 + 三个消融；Windows/Linux 各 7,513 trials；200 组已知 crash/replay 对中完整配置 0/200 重复效果 vs 更简单基线 117/200；ledger 消融 170/170 orphaned effects；关闭 reconciliation 后 100/100 已知 post-effect crash 结果模糊；full runtime 吞吐约 fail-open 的七分之一；注入 evidence-write faults 后每平台 75/100 未解决。
- **与本研究问题的重叠**：与 D4/D5/D6 通用恢复方向**直接重合**（授权、账本、目标端幂等、对账、证据封存、故障注入与消融）。不能作为新创新主张。
- **我方推论**：任何「恢复/幂等/对账框架」方向在论文竞争力上已被本文抢占；本文不处理区间可用性语义与拓扑隐私。

---

## 汇总判断（我方推论，非任一作者声称）

1. 请求级 ZK 授权（A）、执行轨迹证据（B/C）、授权历史与 ZK 披露（D）、区间缺失问题定义（E）、有界撤销收敛构造（F）、恢复工程（G）均已存在。
2. 七篇中**没有任何一篇同时给出**：区间级可用性缺失 + 撤销收敛 + 隐藏委派拓扑的第三方验证关系。
3. 但其中两部分分别由 D（§12 私有 authority profile + 完整性覆盖要求）与 F（quiescence 证书）给出；「交集未被单独写下」与「存在需要新密码机制的性质缺口」不是同一件事。
4. 唯一在七篇中完全缺席的是 **F 的隐私化验证**；PoE 把 ZK EAC 列为 open work，Baek 只用一句话提到 selective disclosure，Rampertab 的私有 profile 不覆盖 quiescence 证书。是否构成可立题缺口，在 `GO-NO-GO.md` 中按强制停止条件裁决。

## 引用可回溯性

| 代号 | 原文入口（2026-11-25 抓取） |
|---|---|
| A | https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2026.1966725/full ；作者版 https://arxiv.org/html/2607.21325v3 |
| B | https://arxiv.org/abs/2607.05397 ；全文 https://arxiv.org/html/2607.05397v1 |
| C | https://www.ietf.org/archive/id/draft-thaha-scitt-agent-execution-evidence-02.txt |
| D | https://www.ietf.org/archive/id/draft-rampertab-audit-agent-authority-history-00.txt |
| E | https://www.ietf.org/archive/id/draft-baek-audit-absence-claims-00.txt |
| F | https://arxiv.org/abs/2609.21284 ；全文 https://arxiv.org/html/2609.21284v1 |
| G | https://arxiv.org/abs/2611.23353 |
