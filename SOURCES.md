# D3-18-01 来源索引与证据等级

基准日期：2026-11-25。本文件记录本轮引用的全部原始来源、出版状态、原文位置与证据等级。

## 证据等级定义

| 等级 | 含义 |
|---|---|
| `[原文]` | 已取得原文正文并逐节核对，可给出章节号与逐字引文 |
| `[摘要]` | 仅取得官方摘要页（arXiv abs / ePrint 页面），正文未取得 |
| `[二手]` | 仅取得第三方聚合页、新闻页或镜像，非作者原文 |
| `[推断]` | 本审计基于原文证据的推论，非原文陈述 |
| `[UNVERIFIED]` | 无法取得，或来源不可达，明确标记证据缺口 |

严格原则：作者声称 ≠ 原文可验证 ≠ 我方推论。任何结论不得越过其证据等级。

---

## S1. SealCall（候选的问题来源）

- **标题**：When Safety Checks Become Privacy Risks: A Privacy-Preserving Paradigm for LLM Agent Safety Auditing
- **作者**：Yixiang Luo, Ziheng Ma, Ke Chang, Jian Wang, Jiqiang Liu（北京交通大学）
- **来源**：arXiv:2610.41401v1，2026-10-30 提交；cs.CR + cs.AI；12 页 / 2 图 / 10 表；DOI 10.48550/arXiv.2610.41401
- **可得性**：HTML 全文可得（arxiv.org/html/2610.41401v1），已解析逐节核对
- **证据等级**：`[原文]`
- **关键原文位置**：
  - §2.1 Threat model（威胁模型）：L205–226，"The audit provider is semi-honest: it follows the agreed computation but attempts to infer private content from its observations."
  - §2.2 Three-domain auditing model（三域模型）：L236–272，agent execution / user control / audit service 三域；trusted controller C 持密钥与放行权，server S 持 pk/evk、无解密密钥、无放行权
  - §2.3 Requirements：L273–284，第四要求 "release must bind the decision to the audited call and expected state"
  - §3.1–3.2 计算分解与加密表示：L287–410，`F` 返回点积供 trusted 聚合、非线性操作留给 controller；"Multiplication depth, vector dimension, and output count affect the required HE parameters"
  - §3.3 输出接口：L411–419，controller 可查询任意基向量恢复参考坐标；"Protecting a provider's reference assets against the controller is a separate goal"
  - §3.4 Trusted decision and execution control：L420–443，"A decision becomes an execution constraint by being attached to a specific pending operation... checks stale state, replay, argument changes, and failure handling."
  - **§3.5 Misconduct boundary（决定性证据）**：L444–472，"Correct evaluation relies on the semi-honest assumption: a malicious server could return a well-formed ciphertext encoding a false score. Extending the protocol to such servers requires a computation-integrity mechanism, such as verifiable evaluation, alongside call binding."
  - §3.6 / §4.4 实验配置：L477–479（参考集 Θ=B={p_j}）、L788–809（d=256, K=16, Intel Core Ultra 5 225H, 32GB, 1 thread, TenSEAL 0.3.18, poly modulus degree 8192, coefficient-modulus [60,40,40,60], scale 2^40；F1=0.895 / 0.176 s / 0.131 MB packed / 3.761 MB raw on the pre-selected fold）
  - 摘要指标：mean F1 = 0.840（1,252 public binary candidates, grouped nested evaluation）；0.176 s / encrypted scoring operation；760 model–layout records 加密决策一致
  - Appendix E / Table 10（构造策略诊断）：L1531–1557，"SealCall reaches F1 0.607 on source authority and 0.171 on purpose scope; no family yields an all-four-correct world."；recipient_binding 0.455 / purpose_scope 0.171 / source_authority 0.607 / prior_precondition 0.598

## S2. PRISM（拟对接的密码学机制）

- **标题**：PRISM: Efficient zkSNARKs for RNS-Based Homomorphic Encryption
- **作者**：Zhelei Zhou, Yun Li, Zhaomin Yang, Cheng Hong, Tao Wei（Ant Group）
- **来源**：IACR ePrint 2026/1956；2026-09-10 received / 09-13 approved；ACM CCS 2026（full version）；DOI 10.1145/3830454.3846611
- **可得性**：**正文不可得**——eprint.iacr.org PDF 被 Cloudflare 拦截（返回 "Just a moment..." 挑战页），带浏览器 UA、archive 路径、ia.cr 短链、agent mail 镜像等多途径均失败；acm.org 页面仅列摘要与参考文献
- **证据等级**：`[摘要]`（性能对比数字、三项技术、CCS 收录状态均来自官方 ePrint 摘要页，可逐字引用）；任何超出摘要的操作覆盖/验证者模型/成本细节标 `[UNVERIFIED]` 或 `[推断]`
- **摘要可验证要点**（逐字）："the first practical zkSNARK for standard RNS-based HEs"；三项技术 (1) MF-PCS for cross-field modulo relations，(2) PIOP for (inverse) NTT with O(N) prover time and O(log N) verifier time "in a model with an offline phase"，(3) "upgrading MF-PCS and PIOPs to achieve zero-knowledge with small overhead via Vector Oblivious Linear Evaluation (VOLE) correlations"；性能对比：比 Zhou et al.（S&P 2025，最快 prover）prover 3.5× 慢、verifier 最多 7.8× 快、proof 7.8× 小；比 Atapoor et al.（CiC 2024，最小 proof）proof 5.5× 大、prover 约 10.1× 快、verifier 2.6× 快
- **明确证据缺口**：支持的具体 CKKS 操作清单、是否覆盖点积/旋转/rescale、ZK 的确切 witness/statement 定义、是否指定验证者、离线 VOLE 相关性的生成成本与复用限制、绝对 prover/verifier/proof-size 数字、实现代码可得性——**全文未取得，全部 `[UNVERIFIED]`**

## S3. Batch, Pack, and Prove（CKKS vHE 强基线 / PRISM 竞争者）

- **标题**：Batch, Pack, and Prove: More Efficient Verifiable Computation for CKKS
- **作者**：Ignacio Cascudo, Anamaria Costache, Daniele Cozzo, Dario Fiore, Antonio Guimarães, Eduardo Soria-Vazquez
- **来源**：IACR ePrint 2026/2878；2026-11-12 received / 11-16 approved；ASIACRYPT 2026 major revision
- **可得性**：主站 eprint.iacr.org/2026/2878 摘要页可得；用户给的镜像域名 `eprint.iacr.asia` 返回 Cloudflare 523（Origin unreachable），已记录
- **证据等级**：`[摘要]`
- **摘要要点**：针对 Cascudo et al. CRYPTO 2025 的可扩展性瓶颈（承诺证明大小、range proof 的 O(N) 开销、缺少显式 sublinear 验证）；提出更高效的 CKKS 算术化、BatchFold 多项式承诺、packing 代数技术、SparsePack；在通用神经网络架构上评估，proof 比先前 "several orders of magnitude smaller and faster"
- **与本轮关系**：这是把"现成 vHE 接到 SealCall"的**更强、更直接的候选机制**——必须正面比较，不能只盯 PRISM。摘要未明确声明 ZK 属性（关键词含 zero-knowledge proofs，但摘要正文只说 verifiable computation），其 ZK 能力 `[UNVERIFIED]`

## S4. Verifiable Computation for Approximate Homomorphic Encryption Schemes（CKKS vHE 基础）

- **标题**：Verifiable Computation for Approximate Homomorphic Encryption Schemes
- **作者**：同 S3 作者组（Cascudo et al.，NTNU / IMDEA / TII）
- **来源**：IACR ePrint 2025/286；CRYPTO 2025（major revision，含 range check 章节勘误）；DOI 10.1007/978-3-032-01907-3_21
- **可得性**：主站摘要页可得
- **证据等级**：`[摘要]`
- **摘要要点**：处理 RingLWE（尤其 CKKS）密文计算有效性；无需 emulation overhead 处理 Rq 上的密文算术；以小成本处理 modulus switching / key switching / rescaling；构造 Rq 上多项式 PIOP 与 multilinear PCS；已实现并实验，小电路与 SOTA 相当、可扩展到更大电路
- **注释**：这是 PRISM 摘要中点名的 "Cascudo et al., Crypto 2025"——即被批评"designed for a modified HE scheme"的工作（PRISM 摘要原话），但 S3 摘要显示 CRYPTO 2025 方案本身是 standard CKKS 方向；**PRISM 对它的批评措辞与其自身摘要存在张力**，需正文核对，当前 `[UNVERIFIED]`

## S5. zk-MCP（最直接的 Agent 审计近邻）

- **标题**：Zero-Knowledge Audit for Internet of Agents: Privacy-Preserving Communication Verification with Model Context Protocol
- **作者**：Guanlin Jing, Huayi Qi
- **来源**：arXiv:2512.14737v1，2025-12-11 提交；cs.CR + cs.AI
- **可得性**：HTML 全文可得，已解析
- **证据等级**：`[原文]`
- **关键原文位置**（L134–149 / L258–278 / L289 / L351–451 / L489）：
  - 五实体：agents / MCP registry / Model Registry（MR）/ **Audit Service Provider（ASP）**；ASP 是 independent third-party certification/auditing organization，"serves as a neutral verification authority... has no stake in any transaction"
  - 不诚实方是 **agent**："under the assumption that agents can be untrusted, how to ensure the correctness and privacy of audit information becomes challenging"（L149）；agent 自己生成 π_token / π_output 证明 token 用量与输出真实性，ASP 只做验证
  - 安全目标：data authenticity + communication privacy；消息内容不泄露，ASP 只见 type counts 与 message hashes
  - 实现：Circom + snarkjs；MAX_JSON=64 / MAX_TYPE=20 / NUM_TYPES=8；proof generation overhead < 4.14% of communication cost（异步）
  - 自述边界（L489）："offers an initial exploration of the framework's practical feasibility... further testing and refinement will be needed"
- **与本轮关系**：威胁模型**相反**——zk-MCP 防的是 agent 谎报（prover=agent），本候选防的是 audit service 伪造（prover=server）；且 zk-MCP 不涉及 CKKS/密文相似度/工具调用执行绑定。可作为"ZK 用于 Agent 审计"的强基线，但不能替代本候选的问题

## S6. 用户冻结基线（Phase 0 只读核验）

- `agent-exec-binding-mvp`：HEAD `e327a9444ed8cea17baefbac01587b7fa77e8d39`，分支 `experiment/independent-execution-proxy`，dirty=0，remote `kaikai-cao/agent-exec-binding-mvp.git`
- 既有能力（据 D3-13 R1.1 冻结结论，非本轮重测）：request/context/tool/schema 绑定 + 独立执行代理签名证据；`[原文]`（前序轮次已核）
- 8 个冻结仓库 HEAD 全部未变且 dirty=0：D3-17-02 `eb97300`、D3-17-01 `ee7628f`、D3-16 `cdf4691`、D3-15 `0bb4e78`、D3-14 `19e24b5`、D3-13 `48b5d5e`、zcash-orchard-engineering `d291c49`、主仓 `89caad7`

## 来源获取失败记录（证据缺口，如实标注）

- `eprint.iacr.asia/2026/2878`：Cloudflare 523（Origin is unreachable），2026-11-25 05:52 UTC —— 主站替代路径有效，已用 S3
- `eprint.iacr.org/2026/1956.pdf`：多途径被 Cloudflare 拦截，PRISM 全文 `[UNVERIFIED]`；已以官方摘要页为上限，不外推
- 用户给出的"PRISM 线性代数/NN 测试中证明端开销随规模明显增长""指定验证者离线 VOLE 相关性"等表述：与摘要"via VOLE correlations"和"model with an offline phase"方向一致，但**具体绝对数字与"指定验证者"身份在正文中未取得核验**，标 `[摘要]` + `[推断]`，不作为已验证事实
