# SOURCES.md — D3-16-01 引用索引

日期：2026-11-25
任务性质：只读研究空间重置与候选池更新。所有文献结论均可回溯到下列原文 URL 与标注章节。

## 0. 证据分级约定

本轮对每个引用标注以下四级之一，全文统一遵守：

- **[原文]** 已取得 ePrint / arXiv / 官方仓库 / 官方草案正文，可直接按章节或文件核对。
- **[二手]** 仅取得社区索引、聚合站、技术博客或他人转述；不得作为论文原文主张使用。
- **[UNVERIFIED]** 已知标题/编号但正文未取得（反爬、限流、撤稿等）；只记元数据，不引申结论。
- **[我方推论]** 由上述证据推导，明确与原文陈述分离。

文献类型严格区分：`peer-reviewed`（顶会/顶刊）、`arXiv preprint`、`IACR ePrint`、`Internet-Draft`（个人/工作组草案，**非 RFC**）、`implementation artifact`（开源仓库/工具）。Internet-Draft 一律按工作草案评价，不称标准。

---

## 1. 点名的强基线工作（用户要求纳入，本轮新增）

### S1 · Verifiable Usage Accounting for Internet of Agents
- **类型 / 状态**：Internet-Draft，个人提交，Informational，`draft-zhang-ioa-usage-accounting-01`，2026-11-02，Expiry 2027-05-06。**不是 RFC、无 IETF 共识**。
- **作者**：L. Zhang, W. Qiao, W. Zhang, H. Yang, Y. Li（AsiaInfo Technologies (China) Inc.）
- **URL [原文]**：https://www.ietf.org/archive/id/draft-zhang-ioa-usage-accounting-01.txt
- **关键章节与直引**：
  - §7.6 Measurement Availability and Incomplete Coverage：*"A summary MUST identify its coverage boundary... Completeness is assessed against a declared or otherwise established expected set, not just the records that happened to arrive. Without that basis, a collector MUST NOT claim a globally complete task tree."*
  - §7.8 Retries, Duplicates, and Record Identity：*"A timeout does not prove that execution failed or that consumption was zero."*
  - §7.9 Verification Claims and Evidence Limits：*"A signature binds protected bytes to a signing key under its validation assumptions... Neither mechanism alone proves that usage counters are accurate, an observation point was complete, an action occurred, a business result is correct, or a payment was settled. A hash chain can reveal some interior gaps given trusted sequencing information, but does not by itself prove that no final records were omitted. Completeness requires a declared expected set or other explicit coverage evidence."*
- **对本轮作用**：排除项 6（通用 Agent 使用计量框架）的强基线；其 §7.9 直接给出"签名不能证明计量值准确/事件无遗漏"的原文依据。

### S2 · Fault-Tolerant Budget Conservation in Distributed Multi-Agent Delegation
- **类型 / 状态**：arXiv preprint，`arXiv:2610.00349v1` [cs.AI/cs.CR/cs.DC]，2026-09-29 提交，67 页（含形式化证明、TLA+ 有界检验、JavaScript explorer、SQLite 崩溃注入）。**未经同行评审**。
- **作者**：Genliang Zhu（Accentrust / Georgia Tech）, Chu Wang（Accentrust / UIUC）
- **URL [原文]**：https://arxiv.org/abs/2610.00349 ；摘要与评论：https://arxiv.org/abs/2610.00349
- **关键原文**：摘要 *"We prove ownership partition, ledger and effect conservation, descendant non-amplification, at-most-once settlement, late-completion safety, and partition confinement under explicit mediation, durability, authentication, normalization, and gateway assumptions."*；*"Bounded TLA+ checking, an independent JavaScript explorer, and crash-injected two-process SQLite experiments exercise the declared scope..."*
- **[二手]** 范围解读：https://rogueaitracker.com/research/arxiv-fault-tolerant-delegation-budget （指出"有限测试不建立任意运行时精化/生产会计"）——仅作提示，以摘要原文为准。
- **对本轮作用**：排除项 6（委派预算守恒）的强基线；其"conservation ≠ 外部效果真实"与本轮既有结论同构。

### S3 · zkRAG: Efficiently Proving RAG Retrieval in Zero Knowledge
- **类型 / 状态**：IACR ePrint `2026/709`，2026；作者 Yanze Jiang, Xinyang Yang, Xuanming Liu, Yanpei Guo, Jiaheng Zhang。
- **URL [原文]**：https://eprint.iacr.org/2026/709 ；IACR 新闻摘要：https://iacr.org/news/item/28208
- **关键原文**：首个面向 HNSW ANNS 的 PIOP；*"prover time linear in the HNSW search trace length"*；基准 10^6 向量/128 维，单线程 50 秒，验证轻量（作者报告）。
- **对本轮作用**：排除项 7（ZK-RAG 直接复现）与 C 类"可验证检索"的强基线。

### S4 · VERIF: An Efficient Zero-Knowledge Proof System for Verifying IVF-Flat Retrieval in RAG Services
- **类型 / 状态**：IACR ePrint `2026/1802`，2026-08 更新；作者 Zhiwen Zhang, Yuao Zhou, Ge Chang, Cong Li, Yuejian Fang, Qingni Shen。
- **URL [原文]**：https://eprint.iacr.org/2026/1802
- **关键原文**：*"first dedicated zero-knowledge polynomial interactive oracle proof (PIOP) for complete, service-consistent IVF-Flat retrieval"*；32M/8M 向量 5.90/11.57 秒，验证 0.62–1.48 秒；相对 Plonky2 最高 86.5× prover 加速、99.1% 峰值内存下降（作者报告）。
- **注意**：VERIF 是 RAG 检索 ZK 证明，**不是**电路 fuzzing 工具；用户点名时与 zkFuzz/zkCraft 并列，本轮消歧后归入 ZK-RAG 类。
- **对本轮作用**：排除项 7 的第二强基线。

### S5 · zkFuzz: Foundation and Framework for Effective Fuzzing of Zero-Knowledge Circuits
- **类型 / 状态**：**peer-reviewed**，IEEE Symposium on Security and Privacy (S&P) 2026，pp.3055–3074，DOI 10.1109/sp63933.2026.00049；作者 Hideaki Takahashi, Jihwan Kim, Suman Jana, Junfeng Yang（Columbia University）。开源实现。
- **URL [原文]**：https://github.com/Koukyosyumei/zkFuzz ；项目页 https://zkfuzz.xyz/ ；[二手 DOI/元数据] https://lacuna.tiptreesystems.com/work/zkfuzz-foundation-and-framework-for-effective-fuzzing
- **关键原文**：提出 Trace-Constraint Consistency Test (TCCT) 统一刻画 under-/over-constrained；452 个 Circom 电路中发现 85 个 bug（含 59 zero-day，39 个被开发者确认修复）。
- **作者自述局限 [二手，以原文项目页为准]**：不能证明无 bug；仅 Circom；单维护者研究项目。
- **对本轮作用**：排除项 8 的核心基线。

### S6 · zkCraft: Prompt-Guided LLM as a Zero-Shot Mutation Pattern Oracle for TCCT-Powered ZK Fuzzing
- **类型 / 状态**：arXiv preprint，**已撤稿（withdrawn）**。v1 2026-01-31，v7 2026-10-29；arXiv 管理员注记：*"This submission has been withdrawn by arXiv administrators as authors were added without their knowledge or consent"*。
- **URL [原文]**：https://arxiv.org/abs/2602.00667
- **关键原文**：R1CS-aware 定位 + Row-Vortex 多项式 + Violation IOP + LLM 引导变异模板，检测 under-/over-constrained。
- **处理决定**：**不得作为有效同行评审基线引用**；仅记录其代表的技术方向已属排除项 8（通用 under-constrained fuzzing + LLM mutation 组合）。这是本轮明确标注的撤稿项。

### S7 · VeriRAG: Efficient Zero-Knowledge Proofs for Verifiable Retrieval-Augmented Generation
- **类型 / 状态**：IACR ePrint，2026；作者 Chenqi Lin, Yubo Cui, Zhelei Zhou, Cheng Hong, Yufei Wang, Zhaohui Chen, Meng Li。
- **URL [原文元数据]**：https://scholar.google.com/citations?view_op=view_citation&citation_for_view=VzU4b8sAAAAJ:QIV2ME_5wuYC ；摘要 [二手索引]：同上。正文未逐节核对 → 标 [UNVERIFIED] 仅用摘要级主张（37GB 数据集、prover 96s、verifier 3s，作者报告）。
- **对本轮作用**：ZK-RAG 拥挤度的补充证据。

---

## 2. A 类（ZK 系统与工程优化）近邻

### S8 · ZKPoG: Accelerating WitGen-Incorporated End-to-End ZKP on GPU
- **类型 / 状态**：arXiv preprint + 实现，ePrint `2025/765`，2025；清华 / Cysic。
- **URL [原文]**：https://eprint.iacr.org/2025/765
- **关键原文**：*"optimizing memory usage to accommodate large-scale circuits on affordable GPUs with limited memory"*；22.8× vs CPU、12.7× vs GPU（作者报告）；RTX 4090、Plonkish、依赖自定义门编译器。
- **作用**：A1 候选"分阶段内存剖面"的最强基线（但只报端到端倍数）。

### S9 · MegaZK: A Memory Efficient GPU System Accelerating End-to-end ZKP
- **类型 / 状态**：**peer-reviewed**，ICS'26，DOI 10.1145/3797905.3807842；同组（含 Gao）。
- **URL [原文元数据]**：https://doi.org/10.1145/3797905.3807842
- **关键原文**：*"GPU memory usage is also reduced by 80.9%"*；37.4×/24.3×/6.1× vs CPU/GPU/ASIC（作者报告）；局限 *"ZKP workloads often span tens of gigabytes"*，仅 Plonkish+FRI/GPU。
- **作用**：A1 最强基线。

### S10 · Performance Bottlenecks in Computing ZK Proofs on a GPU
- **类型 / 状态**：arXiv preprint `2611.09569`，2026-11-06，8 页，无 venue。
- **URL [原文]**：https://arxiv.org/abs/2611.09569
- **关键原文**：*"trade-offs between increased parallelization on GPUs and the resultant memory management problems"*，指向多 GPU/RDMA。
- **作用**：A1 拥挤度证据（GPU 侧瓶颈已被专门研究）。

### S11 · MicroNova: Folding-based arguments with efficient (on-chain) verification
- **类型 / 状态**：**peer-reviewed**，IEEE S&P 2025；ePrint `2024/2099`；作者 Zhao, Setty, Cui, Zaverucha。
- **URL [原文]**：https://eprint.iacr.org/2024/2099
- **关键原文**：*"MicroNova's prover incurs minimal overheads atop its baseline Nova's prover"*；≈2.2M gas；局限：需通用可信设置（复用 KZG SRS）。
- **作用**：A3 候选（递归深度 Pareto）基线。

### S12 · Interstellar: Efficient GKR-based IVC Scheme with Privacy-Preserving Collaborative Folding
- **类型 / 状态**：**peer-reviewed**，PKC 2026；ePrint `2025/1294`；作者 J. Long（Theta Labs）。
- **URL [原文]**：https://eprint.iacr.org/2025/1294
- **关键原文**：*"1.59x to 6.74x prover speedup per folding round"*；*"up to 2.93x for MiMC chains"*；GKR+circuit interpolation，非 Halo2/Pallas 栈。
- **作用**：A3 基线。

### S13 · Consistency Verification for Zero-Knowledge Virtual Machine on Circuit-Irrelevant Representation
- **类型 / 状态**：arXiv preprint / ePrint `2025/2204`，2025；作者 Ke, Liang, Li。
- **URL [原文]**：https://eprint.iacr.org/2025/2204
- **关键原文**：*"witness-generation code is consistent with these constraints has become a major source of subtle and hard-to-detect bugs"*；*"without expanding the full circuit"*；仅验证 SP1 chip。
- **作用**：A2 候选（spec-first 一致性）最接近基线——已占 witness-vs-约束一致性。

### S14 · ZKP Security Tools and Verification（综述）
- **类型 / 状态**：arXiv preprint `2607.23752`，2026-07-26；作者 Kolozyan 等。
- **URL [原文]**：https://arxiv.org/abs/2607.23752
- **关键原文**：*"most target Circom"*；检测率 *"45.7% on isolated targets…drops to 19.6% on full codebases"*；*"focuses primarily on constraint correctness"*。
- **作用**：A2 拥挤度证据，并指出"规格本身 / 全代码库 / 非 Circom DSL"为稀疏处。

### S15 · Automating Bitvector and Finite Field Equivalence Proofs in Lean
- **类型 / 状态**：arXiv preprint `2605.15163`，2026；作者 Pertseva, Robert, Barrett, Parker。
- **URL [原文]**：https://arxiv.org/abs/2605.15163
- **关键原文**：*"solving 19% more ZKP arithmetization benchmarks"*；限转换/不等式 tactic。
- **作用**：A2 基线（形式化等价证明方向已有人在推）。

### S16 · ZK-CEC / Proving Circuit Functional Equivalence in Zero Knowledge
- **类型 / 状态**：arXiv preprint `2601.11173`，v1 2026-01-16，v3 2026-07-30；作者 Sirui Shen, Zunchen Huang, Chenglu Jin。Related DOI 10.1145/3830454.3832697。
- **URL [原文]**：https://arxiv.org/abs/2601.11173
- **关键原文**：*"ZK-CEC, the first privacy-preserving framework for hardware formal verification"*；*"existing zero-knowledge protocols for formal verification are designed to prove statements of public formulas. However, in a privacy-preserving verification context where the formula is secret, these protocols cannot prevent a malicious prover from forging the formula"*；验证 AES S-Box。
- **作用**：A 类与 C 类交叉的近邻——面向**硬件 IP**（公开规格 vs 秘密设计），与本项目 ZK 电路 witness/constraint 一致性不同场景。

### S17 · TensorZKP: Repurposing GPU Tensor Cores for High-Performance Zero-Knowledge Proofs
- **类型 / 状态**：**peer-reviewed**，USENIX Security 2026；IACR ePrint `2026/1250`；NUS / ZJU。
- **URL [原文]**：https://eprint.iacr.org/2026/1250
- **关键原文**：首个用 Tensor Core 加速 ZKP；HyperPlonk PIOP + Brakedown PCS；端到端证明生成加速（作者报告）。
- **作用**：A 类硬件加速拥挤度证据。

### S18 · Celer: A Lookup Argument for Large-Scale Queries
- **类型 / 状态**：**peer-reviewed**，CRYPTO 2026；ePrint `2026/1453`；NUS / ZJU。
- **URL [原文]**：https://eprint.iacr.org/2026/1453
- **关键原文**：查询规模远大于表规模场景；*"25.9 prover-time speedup over plookup and ... 9.4 faster than LogUp"*（Llama 推理场景，作者报告）。
- **作用**：A 类原语优化拥挤度证据。

---

## 3. B 类（Agent 系统安全）近邻

### S19 · From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents
- **类型 / 状态**：arXiv preprint `2606.04329`，v1 2026-06-03，v2 2026-06-18；作者 Dash, Ge, Jain, Shah, Shang。
- **URL [原文]**：https://arxiv.org/abs/2606.04329
- **关键原文**：四类 memory 写入通道、九类结构漏洞、六类攻击 taxonomy、MPBench；*"existing prompt injection defenses fail to cover memory poisoning attacks"*。
- **作用**：B 类 memory 方向拥挤度核心证据。

### S20 · Plant, Persist, Trigger: Sleeper Attack on Large Language Model Agents
- **类型 / 状态**：arXiv preprint `2605.28201`，v1 2026-05-27，v2 2026-10-05；作者 Li 等（USTC/NUS/SMU/上海AI实验室）。
- **URL [原文]**：https://arxiv.org/abs/2605.28201
- **关键原文**：1,896 实例、六类有害结果、三攻击策略、三状态目标（会话上下文/记忆/可复用技能）；跨交互潜伏激活。
- **作用**：B 类跨任务污染已有系统研究。

### S21 · Utility Under Attack（Aegis Memory / provenance weighting）
- **类型 / 状态**：arXiv preprint `2608.21230`，2026-08-21；[原文]来自社区结构化摘要仓库，正文未逐节核对 → 关键数字标 [二手]。
- **URL**：https://arxiv.org/abs/2608.21230 ；结构化摘要 https://github.com/H20Zhang/Agent-Memory-Radar/blob/main/papers/2026/2608.21230.md
- **关键发现 [二手]**：additive provenance weight 在 shipped 配置下与无防御无显著差异（p=.80）；更强权重使正确证据 recall 从 99.17% 降至 0%。bounded occupancy 仅提案未实现。
- **作用**：B 类"来源权重不是免费 trust bonus"的证据。

### S22 · MCP 工具描述供应链 / rug pull / 版本漂移
- **类型 / 状态**：**implementation artifact + 行业指南**，非同行评审论文。多个技术站点一致描述同一类问题。
- **URL [二手，多源交叉]**：
  - https://www.alyria.ai/agentpedia/tool-poisoning （描述 poisoning / rug pull / shadowing / cross-server chaining 分类）
  - https://nhimg.org/ai-agent-tool-and-plugin-security-guide （ATLAS AML.T0109 / OWASP MCP01-10 / digest pinning）
  - https://secagentlabs.com/blog/tool-description-poisoning-mcp-rug-pull （hash-pin + re-verify on every call）
  - https://shrikesecurity.com/blog/the-mcp-tool-that-vets-your-other-mcp-tools （TOFU pin + mcp_schema_drift）
  - https://laoujin.github.io/Atlas/research/2026-06-24-testing-and-regression-checking-claude-code-agent-extensions-before-shipping-to-a-team-2026/regression-testing-plugins-and-mcp-servers-plus-catching-rug-pulls/views/threatboard.html （hash-diff / golden snapshot / digest pinning 对照）
- **关键原文（博客级）**：*"You cannot stop a server from lying in its description. You can make sure the lie does not have the authority to do anything."*；*"native MCP support: ✗ none — no re-approval on change"*；*"pin to content, not the reference"*。
- **作用**：B1 候选（工具定义运行时语义绑定）的基线——**已有工程工具与 pin 机制，缺密码学可验证绑定与跨服务器组合语义的正式研究**。无顶会论文支撑 → 候选质量受限，故列为备选而非优先。

### S23 · OWASP Top 10 for Agentic Applications（2026）
- **类型 / 状态**：行业指南，非论文。[二手] 见 S22 中 nhimg / CSDN 引述。ASI-06 = 记忆与上下文污染。
- **作用**：B 类风险重要性证据，不作为学术贡献基线。

---

## 4. C 类（密码学与 AI 交叉）近邻

### S24 · FlashProve — Zero-Knowledge Proofs of AI Inference
- **类型 / 状态**：**implementation artifact**，Anthropic 官方仓库，v0.16.0，**research artifact: not maintained**，首发 commit 2026-10-30。Apache 2.0。
- **URL [原文]**：https://github.com/anthropics/FlashProve
- **关键原文（README）**：*"FlashProve lets an AI provider prove which model answered a request, without revealing the model's weights."*；Llama 4 Maverick / H100 / 1024-token；*"The protocol's soundness is proved in Lean 4"*；but *"The commitment ID: get it from a party your user trusts, never from the server being checked or from files sent with the proof."*
- **关键原文（guide/known-limits.md）**：*"The provider chooses the model. A yes does not say whose weights they are, that the shipped committer made the commitment, or which real model it is."*；*"A new commitment has a new ID, and no proof links the two."*；*"The C++ verifier and the CUDA prover are written to follow the same protocol and are tested against it, not themselves proved."*；*"The honest prover in these theorems is a Lean definition, not the CUDA prover: nothing is proved for the programs."*
- **URL [原文]**：https://github.com/anthropics/FlashProve/blob/main/guide/known-limits.md
- **作用**：C1（承诺版本谱系）与 C2（来源锚定）的基石——**官方自述空白，且是具体、可形式化、可实验的问题**。

### S25 · ZKPROV: Zero-Knowledge Proofs for Verifiable AI Inference
- **类型 / 状态**：arXiv preprint `2506.20915`，2025-06-26 / 2025-12-18；作者 Namazi, Nemecek, Ayday。
- **URL [原文]**：https://arxiv.org/abs/2506.20915
- **关键原文**：HyperNova + KZG + BLS 绑定数据集-权重-回复；8B 模型 3.3s（作者报告）；来源真实性外包给"权威签名数据集"，不覆盖权重版本。
- **作用**：C1 基线（来源外包，未解决版本谱系）。

### S26 · SAG / Provably Secure RAG
- **类型 / 状态**：arXiv preprint `2508.01084`，2025-08-01；作者 Zhou, Feng, Yang。
- **URL [原文]**：https://arxiv.org/abs/2508.01084
- **关键原文**：全加密存储 + 形式化 confidentiality/integrity、抗投毒；证的是存储完整，不绑定外部世界真值。
- **作用**：C3 基线（存储完整 ≠ 快照真实）。

### S27 · SoK: Verifiable Federated Learning
- **类型 / 状态**：IACR ePrint `2025/2292`，2025-12-22（ePrint 报告）；作者 Bruschi 等。
- **URL [原文]**：https://eprint.iacr.org/2025/2292
- **关键原文**：系统化 VC/ZKP 的"计算正确"；Sybil/串通仍开放。
- **作用**：C 类"证明正确 vs 来源真实"的系统性证据。

### S28 · P²RAG
- **类型 / 状态**：arXiv preprint `2603.14778`，2026-03-16 / 05-27；作者 Ming 等。
- **URL [原文]**：https://arxiv.org/abs/2603.14778
- **关键原文**：两方秘密共享、二分免排序、任意 top-k；比 PRAG 快 3–300×（k=16–1024，作者报告）；开放：半诚实不串通假设、大 k 验证开销。
- **作用**：C3 基线（查询隐私下的 PIR-RAG）。

### S29 · PIR-RAG
- **类型 / 状态**：arXiv preprint `2509.21325`，2025-09；作者 Wang, Lou, Zheng, Zhao。
- **URL [原文]**：https://arxiv.org/abs/2509.21325
- **关键原文**：聚类 + 格 PIR 整簇取回；RAG-Ready Latency 指标；基线 PACMANN/Tiptoe。[二手 codeofpaper] 无可靠代码。
- **作用**：C3 基线。

### S30 · VeLoPIR
- **类型 / 状态**：arXiv preprint `2506.12761`，2025-06-15，代码开源；作者 Yoo, Kim, Yoon。
- **URL [原文]**：https://arxiv.org/abs/2506.12761
- **关键原文**：TFHE 位置 PIR，11.55× 加速（作者报告）。
- **作用**：C3 部署基线。

### S31 · RECPIR
- **类型 / 状态**：IACR ePrint `2025/756`，**已于 2025-12-06 撤稿**；不得作为有效基线。
- **URL**：https://eprint.iacr.org/2025/756

---

## 5. 冻结基线（Phase 0 只读核验，未修改）

- **D3-13 R1.1**：`D:\Research\d3-13-independent-execution-evidence` @ `48b5d5e9f1294dd24a4fd2cbed2a41cddbb6dbb9`，`CONDITIONAL_HOLD`，H4 仍 OPEN。
- **D3-14-01**：`D:\Research\d3-14-01-private-quiescence-audit` @ `19e24b5036a364585fc6d7dd20c862a486e15250`，`STOP`（private quiescence）。
- **D3-15-01**：`D:\Research\d3-15-01-agent-query-root-binding-audit` @ `0bb4e7891c1e83289cdaca72a073df584843400d`，`STOP`（B3 组合无独立贡献）。其 `DECISION.md` §5 保留四个开放问题，均为 DO 之外的真实事件信任基。
