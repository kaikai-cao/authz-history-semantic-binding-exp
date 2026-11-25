# SOURCES.md — D3-15-01 原文来源与可回溯性

基准日期：2026-11-25。抓取日期：2026-11-25。
本文件是其余六份文档所有引用的唯一索引。凡本文未列出的「原文引用」不得使用。

## 核验口径

- `FULL-TEXT` = 本次取得全文并逐节读取；引用给出章节 / 页码 / 直引。
- `ABSTRACT` = 只取得官方摘要页，引用限于摘要原文。
- `AUTHOR-INTERVIEW` = 作者本人访谈 / 演讲报道，非论文正文；引用时标明，不作为论文原文命题。
- `UNVERIFIED` = 无法取得可靠原文；不得作为正面证据，只在说明为何无法确认时使用。
- 区分：**作者声称** / **原文可验证** / **我方推论**。

---

## Phase 0 基线（本地冻结 commit，只读）

| ID | 仓库 / 路径 | commit | 本次用途 |
|---|---|---|---|
| BASE-D3-13 | `D:\Research\d3-13-independent-execution-evidence\DECISION.md` 等 | `48b5d5e9f1294dd24a4fd2cbed2a41cddbb6dbb9` | H4/T8/T9/Oracle 假设/CONDITIONAL_HOLD 原文 |
| BASE-D3-13-V | `...\ZKP-INCREMENTAL-VALUE.md` | 同上 | 「证明声明电路化不解决 H4」「解禁条件」 |
| BASE-D3-14 | `D:\Research\d3-14-01-private-quiescence-audit\GO-NO-GO.md` | `19e24b5036a364585fc6d7dd20c862a486e15250` | 外部信任基开放问题；STOP 不关闭 H4 |

原文直引（BASE-D3-13，§2 表 H4）：*"C 的 T8 UER=1.0（签名有效但假声明，ASR=0）、T9 UER=1.0 DR=0；D 靠 Oracle-assisted Observer 使 T8/T9 均 B 类 100/100、UER=0 ... 检出依赖 'Oracle 通道如实记录 DS 执行' 这一未解决假设——H4 保持 OPEN"*。
原文直引（BASE-D3-13-V，第 6 点）：*"把 DS 声明做进 ZK，只会让 'DS 的假声明' 有一个漂亮的证明"*。
原文直引（BASE-D3-14，§5）：*"方向必须是外部信任基 / 协议工程，而非 ZKP 证明关系创新：1. Manifest / 执行端注册表的真实性与完整性来源 ... 2. 执行事件真实采集与远程证明绑定（CVA §4.5 明确需要执行时信任锚；D3-13 的 H4 仍 OPEN）"*。

## A 组：可验证数据库与查询证明

### A1 vSQL — vSQL: Verifying arbitrary SQL queries over dynamic outsourced databases
- 作者 / 会议：Yupeng Zhang, Daniel Genkin, Jonathan Katz, Dimitrios Papadopoulos, Charalampos Papamanthou；IEEE S&P 2017, pp. 863–880。
- 类型：**peer-reviewed 会议论文**。
- 入口：IEEE Xplore / 作者主页（Google Scholar 条目可回溯）；本次抓取 PDF 尝试返回 202/空响应。
- 核验级别：`ABSTRACT` + 多方二手引用（meta-review）；具体信任模型直引 `UNVERIFIED`。因此本文对 vSQL 只写「标准外包模型：可信 data owner 承诺并外包，不可信 server 执行查询并给证明」这一由 PoneglyphDB 表 1 / AD SoK 引文交叉确认的边界，不写 vSQL 独有原文直引。

### A2 ZKSQL — ZKSQL: Verifiable and Efficient Query Evaluation with Zero-Knowledge Proofs
- 作者 / 出处：Xiling Li, Chenkai Weng, Yongxin Xu, Xiao Wang, Jennie Rogers；PVLDB 16(8):1804–1816, 2023；DOI `10.14778/3594512.3594513`。
- 类型：**peer-reviewed 期刊论文（PVLDB）**。
- 原文：https://www.vldb.org/pvldb/vol16/p1804-li.pdf（`FULL-TEXT`，13 页 PDF 提取 93,585 字符）。
- 关键原文（§1，p.1804）：*"ZKSQL enables V (e.g., the DoE) to get authenticated answers ... while P may be untrusted. Its proofs are with respect to a public commitment of the private data."*
- 关键原文（§3.1 Security Model）：*"ZKSQL supports two adversaries – a malicious P and a malicious V. Owing to FZK, ZKSQL guarantees the soundness of all query answers."*；*"it is impossible for the prover to change the contents of D after this setup"*。
- 我方推论：P = data owner，proof 关于 P 自己承诺的库；不解决 P 认证错误 / 不完整数据（对应 H6/H7）。

### A3 PoneglyphDB — PoneglyphDB: Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification
- 作者 / 出处：Binbin Gu, Juncheng Fang, Faisal Nawab；arXiv:2411.15031v1（2024-11-22）；SIGMOD 2025（HTML 页写 Conference: SIGMOD, June 22–27 2025, Berlin）。
- 类型：**peer-reviewed 会议论文 + arXiv preprint**（版本以 arXiv v1 为准）。
- 原文：https://arxiv.org/html/2411.15031v1（`FULL-TEXT`）。
- 关键原文（§1 Introduction）：*"it is important for users to trust that the database owner is using the correct database (i.e., one that is consistent with the claimed database) and that the provided answers accurately reflect the intended computations."*
- 关键原文（§3 Trust Model）：*"There is an additional entity, the auditor, that both the prover and verifier trust"*；*"The prover may use a fake database: The client does not trust the prover to be using the correct database to run the query."*
- 关键原文（§3 缓解措施 (1) Cryptographic Commitment to the Database）：*"The commitment is made public and shared in an irrevocable and immutable manner, e.g., by utilizing a decentralized blockchain such as Ethereum ... The database commitment can also be audited by a third-party auditor (e.g., a regulatory or government entity trusted by both the prover and verifiers). The auditor in this case reads the raw database from the database owner, verifies its authenticity, and validates that the database commitment of the authentic database corresponds to the commitment that is shared in the blockchain and accessible by the verifiers."*
- 关键原文（§3 效果）：*"PoneglyphDB ensures that the hospital H uses an authentic database to process queries. This is by utilizing a trusted third-party auditor that verifies that the publicly shared irrevocable and immutable database commitment corresponds to an authentic database."*
- **这是本轮最重要的基线**：「ZK 查询证明 + 独立认证数据根（链上承诺）+ 可信 auditor 核原始数据」已在 2025 SIGMOD 论文中明确写出。

### A4 TruthTable — TruthTable: A Verifiable Query Engine
- 作者 / 出处：Bharath Namboothiry, Alireza Shirzad, Spencer Solit, Ryan Marcus, Pratyush Mishra；IACR ePrint 2026/1260（received 2026-06-15, approved 2026-06-19）；Preprint；ZKProof VIII / SeQureDB 2026 演讲。
- 类型：**arXiv/ePrint preprint（非 peer-reviewed，除非 SeQureDB 2026 有正式论文集——本次未核实，标 UNVERIFIED）**。
- 原文入口：https://eprint.iacr.org/2026/1260 （`ABSTRACT` + 作者页摘要）；PDF `https://eprint.iacr.org/2026/1260.pdf` 被 Cloudflare 拦截（`Just a moment...`），本次无法取得正文，标 `UNVERIFIED`。
- 摘要原文：*"a verifiable database engine that allows a prover to produce a succinct proof that convinces a verifier of the correct execution of the verifier's SQL query over the prover's committed database."*；*"proving times are between 6.3×-63× better"*；TPC-H 100 万行：proving 55 s / verify 32 ms / proof 24 kB。
- `AUTHOR-INTERVIEW`（非论文原文，须标明）：作者 Namboothiry 访谈，https://orply.com/articles/microsoft-research/truthtable-a-verifiable-query-engine-a53994fa （2026-08-27）：
  - Agent 场景（叙述者转述）：*"He gives high-stakes AI agents as another: a legal agent may retrieve precedent from a database ... The desired response would include ... a small cryptographic proof that the result genuinely came from the relevant public legal database."*
  - 信任模型（叙述者转述）：*"A trusted data owner takes the database, commits to it cryptographically, leaves the database with an untrusted server, and gives the commitment to a computationally weak client."*
  - 边界（访谈直引 + 叙述）：*"TruthTable proves correct execution against the committed database, while trust in the underlying data and in the correctness of its commitment remains with the trusted data owner."*；*"The system does not establish that the committed data was collected honestly, complete, or otherwise fit for purpose."*；*"a broader system could also prove provenance — for example, with a chain of commitments from an empty state and a transition function — but that is outside the model described for TruthTable."*
- **使用限制**：用户任务包称「作者已明确提出验证其他 Agent 返回结果是应用场景、明确把数据库承诺的可信启动留给应用层」——本次只取得作者访谈可回溯证据，**论文正文未核实**；在 `DECISION.md` 中按 `AUTHOR-INTERVIEW` 标注，不冒充论文原文。

### A5 Rogue — Rogue: Updatable Matrix Lookup Arguments and Applications to Verifiable Databases
- 作者 / 出处：Christodoulos Pappas, Zhuo Cai, Dimitrios Papadopoulos；IACR ePrint 2026/1890（received 2026-09-04, approved 2026-09-07）；**Published elsewhere: ACM CCS 2026 (Major revision)**。
- 类型：**peer-reviewed 会议论文 + ePrint preprint**。
- 原文入口：https://eprint.iacr.org/2026/1890 （`ABSTRACT`；PDF 同被 Cloudflare 拦截，正文 `UNVERIFIED`）。
- 摘要原文：*"Rogue, the first lookup argument with sublinear prover time and updates that always take time proportional only to the number of incurred changes."*；*"RogueDB, the first verifiable database system for arbitrary SQL queries that supports authenticated indexes, hence achieves prover time sublinear to the database."*；相对 vSQL / PoneglyphDB 的 prover 加速 ×42.8–×8624.1 / ×149.6–×11362.4（作者声称）。
- 我方推论：动态更新效率已被解决；摘要未声称 root authenticity / freshness / grant binding。

### A6 ZkChainDB — ZkChainDB: A Verifiable and Privacy-Preserving SQL Query Engine for Off-Chain Database Using zk-SNARKs and Blockchain
- 作者 / 出处：Lulu Li, Wei Wang, Jianan Hong, Jing Fu, Junyu Wang；IEEE ICBC 2026, Brisbane, June 1–5 2026, pp. 1–9；DOI `10.1109/ICBC67748.2026.11575456`（DBLP `conf/icbc2/LiWHFW26`）。
- 类型：**peer-reviewed 会议论文**。
- 入口：IEEE Xplore proceedings / DBLP（本次 `ABSTRACT` 级，正文 `UNVERIFIED`）。
- 摘要原文（IEEE Xplore）：*"raw data is stored off-chain for scalability while data integrity is anchored on-chain ... a template-based verifiable SQL engine"*（IEEE Xplore 摘要截断，仅此可逐字引用）。

## B 组：数据根与认证状态

### B1 SoK: Cryptographic Authenticated Dictionaries
- 作者 / 出处：Harjasleen Malvai, Francesca Falzon, Andrew Zitek-Estrada, Sarah Meiklejohn, Joseph Bonneau；NDSS Symposium 2026。
- 类型：**peer-reviewed 会议论文（SoK）**。
- 原文：https://www.ndss-symposium.org/wp-content/uploads/2026-f1465-paper.pdf （`FULL-TEXT`，18 页，111,269 字符；备用 https://oaklandsok.github.io/papers/malvai2026.pdf）。
- 关键原文（§III-C / Appendix C）：
  - *"This read-write consistency definition is the strongest we have considered and (where applicable) implies other properties as follows: Read-write consistency ⇒ History-binding ⇒ Value-binding."*
  - *"Value binding and history binding are purely syntactic: they ensure that any two query views for the same commitment agree, but do not guarantee that a read returns the most recent write. This distinction is intentional, as transparency models lack a trusted authority to authorize updates, while trusted-data-source settings allow update correctness to be verified cryptographically."*
  - *"achieving read-write consistency requires each writer (or client) to manage cryptographic keys robustly ... in fully decentralized or 'no trusted source' scenarios, history-binding emerges as the most appropriate security notion"*
  - *"transparency-oriented schemes can be upgraded to full read-write consistency by incorporating signatures from a trusted data source ... the number of dictionary changes aligns with expectations following an update ... update proofs ... implicitly encode the count of changes between dictionary versions, facilitating straightforward rollback detection."*
  - 开放问题（原文）：*"Can we design a compiler that transforms any AD satisfying history- or value-binding into one with full read-write consistency, without introducing new requirements ... ?"*
- 关键原文（§Public Outsourced Storage / Cryptographic trust assumptions）：*"A trusted data source defines and signs the dictionary along with its periodic commitments ... Clients verify responses using the source's public key ... updates, and possibly verification, become impossible if the trusted data source's key is lost or compromised."*
- 关键原文（No Trusted Party / Non-cryptographic trust assumptions）：*"There is no trusted data source and any party may arbitrarily deviate from the protocol ... An individual client's claim about a malicious update for its label is not cryptographically verifiable, but inconsistent views for the same label or for the commitment at the same timestep are."*
- 审计问题（原文）：*"Who will perform this non-trivial auditing task and how will they be incentivized?"*；*"There is not yet clear evidence of a large upside for applications deploying authenticated dictionaries."*

### B2 GlassDB — GlassDB: An Efficient Verifiable Ledger Database System Through Transparency
- 作者 / 出处：Cong Yue, Tien Tuan Anh Dinh, Zhongle Xie, Meihui Zhang, Gang Chen, Beng Chin Ooi, Xiaokui Xiao；PVLDB 16(6):1359–1371, 2023；DOI `10.14778/3583140.3583152`。
- 类型：**peer-reviewed 期刊论文（PVLDB）**。
- 原文：https://www.vldb.org/pvldb/vol16/p1359-ooi.pdf （`FULL-TEXT`，13 页，81,008 字符）。
- 关键原文（Definition 1）：*"Integrity: the database server cannot tamper with the user operation without being detected ... Append-only: the database server cannot fork the history log without being detected."*
- 关键原文（§2.2.2 Threat model）：*"the most common model involves a single untrusted database provider that behaves in a Byzantine manner. It has been shown that in this setting, it is only possible to achieve fork consistency, i.e., users cannot prevent misbehavior but can only detect it by communicating with each other."*；三类模型：单不可信 provider + gossip/auditor、多数可信副本 + BFT、恶意 server + TEE。
- 我方推论：GlassDB 证明的是「用户操作执行正确 + 历史 append-only」，不是「写入数据等于真实世界事实」。

### B3 相关背景（作为 AD SoK 内的引用处理，不单独计入文献数）
- transparency log / public bulletin board / auditor / monitor：AD SoK §II、§VI-D 已系统整理；不另列独立原文。
- rollback / freshness：AD SoK §V、Appendix C（上文直引）；TEE 路线见 C1/C2。

## C 组：Agent 执行可信性近邻

### C1 I-EIB — A Trusted Provenance and TEE-Based Reference Architecture for Intent-Execution Binding in LLM Agents
- 作者 / 出处：Haewon Byeon；*Int. J. Computational Methods and Experimental Measurements*, 14(2), 2026；DOI `10.18280/ijsse.160810`（IIETA 版）/ `10.56578/ijcmem140207`（ACADlore 版，同为 2026-06-27）——两个 DOI 对应不同站点版本，本次按 IIETA 全文页为准， DOI 差异记为 `UNVERIFIED` 细节，不影响性质判断。
- 类型：**peer-reviewed 期刊论文（IIETA / Acadlore）**。
- 原文：https://iieta.org/download/file/fid/198791 （`FULL-TEXT` 片段可回溯）；https://www.iieta.org/node/24077 。
- 关键原文：Invariant 1 Capability Sealing / Invariant 2 Chain Completeness / Invariant 3 Atomic Verification；Theorem 1：*"an execution E violating user policy P or chain layout L cannot occur within the defined system boundary"*；作者自限：*"This argument remains construction-based rather than a fully mechanized proof ... establishes architectural and cryptographic resistance under the stated model, not universal formal completeness."*
- 摘要原文（作者声称）：*"100% detection rate for bounded step-omission attacks and a false positive rate below 0.1%"*；平均额外开销 14.2 ms。
- 边界：只处理「定义好的系统边界内」；非外部数据源真实性。

### C2 TRACE — TRACE: Runtime Governance, Containment, and Evidence for Autonomous AI Agent Operations
- 出处：IEEE Access, 2026（具体卷页 / DOI 本次 `UNVERIFIED`）；参考实现 AEGIS。
- 类型：**peer-reviewed 期刊论文**（IEEE Access）——摘要经 IEEE Access 中文转述页核对。
- 入口：https://www.ebiotrade.com/newsf/2026-9/20260915171107327.htm （`ABSTRACT` 中文逐字转述；英文原文页 `UNVERIFIED`）。
- 关键摘要原文（中文转述）：*"通过签名策略包、网关调解、独立遥测、确定性触发线、分级遏制以及防篡改证据链来获取运行时保证"*；*"所有 1,440 条被篡改的链均被拒绝"*；*"一项仪器审计发现，已存档的对抗检测与副作用测量仪器并未测量到其预期结果"*；*"一个单独注册的边界观察者记录了 3,703 个已执行副本中零个禁止的副作用，但硬件截断导致无法做出确认性声明"*；*"仪器有效性、阈值校准及跨平台延迟仍存局限"*。
- **同名消歧**：另有 Linux Foundation/CoSAI 治理的 TRACE（Trust, Runtime Attestation and Compliance Evidence，OPAQUE 提出，v0.2 草案，整合 RATS RFC 9334 / EAT RFC 9711 / SCITT / SLSA / SPIFFE / EAR），是**开放规范草案**，与本条 IEEE Access 论文不是同一工作；后者才是任务包所述「独立边界遥测 + 运行时拦截 + 防篡改证据链」。引用时必须写明哪一个。
- 边界：即便有独立遥测与边界观察者，副作用真实性因硬件截断仍无法确认。

### C3 Execution-Finality Enforcement — draft-das-execution-finality-enforcement-00
- 作者 / 版本：Sangam Kumar Das；`draft-das-execution-finality-enforcement-00`，2026-10-23，1036 页；**Active Internet-Draft (individual), Informational, no IETF consensus**。
- 入口：https://datatracker.ietf.org/doc/draft-das-execution-finality-enforcement/ ；I-D announce：https://mailarchive.ietf.org/arch/msg/i-d-announce/5tVpzAggcYr6DAI7NQtDWu-Fb8s （`ABSTRACT`）。
- 摘要原文：*"An enforcing Finality Sink distinguishes authorization for an actual pending operation from a prior request approval or a reusable bearer credential."*；*"The document presents implementation points and deployment considerations, not a complete interoperable wire protocol or IETF consensus position."*；*"not a claim of ... endorsement or patent coverage"*。
- 同系列 `draft-das-agent-execution-finality-00`（2026-10-16, 1074 页）摘要：*"A Candidate Act remains non-effective until ... authority, purpose, destination, execution scope, runtime context, policy epoch, freshness, revocation ... have been validated."*
- 边界：草案自述是部署考虑，不是完整协议；**不得称为 RFC 或 IETF 共识**。
- 注意：任务包未给准确草稿名；正确名是 `draft-das-execution-finality-enforcement-00`（不是 kuehlewind 系列）。

### C4 PoE（基线复用，不重复抓取）
- arXiv:2607.05397；本轮只复用 D3-14-01 `RELATED-WORK.md` 已核对结论：A5 trace completeness 是部署假设；§10 single-Gateway scope, composition open；§6 ZK EAC 为 open work。原文入口见 D3-14-01 同文件引用表。

---

## 未取得原文 / 明确标注

| 项 | 状态 | 影响 |
|---|---|---|
| vSQL 正文 | `UNVERIFIED`（IEEE PDF 202 空响应） | 只写被交叉引用的标准模型，不给独有直引 |
| TruthTable 正文 | `UNVERIFIED`（Cloudflare） | Agent 场景 / 可信启动只用 `AUTHOR-INTERVIEW` 标注 |
| Rogue 正文 | `UNVERIFIED`（Cloudflare） | 只用 ePrint 摘要，动态更新效率属作者声称 |
| ZkChainDB 正文 | `UNVERIFIED`（IEEE 付费墙） | 只用摘要截断文本 |
| TRACE 英文原文 | `UNVERIFIED` | 用 IEEE Access 摘要中文转述，标明转述 |
| I-EIB 两个 DOI 差异 | `UNVERIFIED` 细节 | 不影响性质判断，已注明 |
| 所有 peer-reviewed 标注 | 以期刊 / 会议页为准 | ePrint 版本单独标注，不混为正式论文 |
