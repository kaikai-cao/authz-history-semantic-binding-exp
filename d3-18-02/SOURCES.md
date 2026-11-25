# D3-18-02 来源索引与证据等级

基准日期：2026-11-25。本文件记录本轮全部原始来源、出版状态、原文位置、取得方式与证据等级。

## 证据等级定义（沿用 D3-18-01）

| 等级 | 含义 |
|---|---|
| `[原文]` | 已取得原文正文并逐节/逐段核对，可给出章节号与逐字引文 |
| `[摘要]` | 仅取得官方摘要页（arXiv abs / ePrint 页面 / USENIX 官方论文首页与摘要），正文未逐节核对 |
| `[二手]` | 仅第三方聚合页、新闻页或镜像 |
| `[推断]` | 本审计基于原文证据的推论，非原文陈述 |
| `[UNVERIFIED]` | 无法取得或来源不可达，明确标记证据缺口 |

严格原则：作者声称 ≠ 原文可验证 ≠ 我方推论。任何结论不得越过其证据等级。**本轮未实现 CKKS、未实现 SNARK、未运行任何攻击实验、未修改任何 Agent 执行逻辑**；Phase 2 的"恢复"分析为数学推导，不是已执行的攻击。

---

## S1. SealCall（`[原文]`）

- **标题**：When Safety Checks Become Privacy Risks: A Privacy-Preserving Paradigm for LLM Agent Safety Auditing
- **作者**：Yixiang Luo, Ziheng Ma, Ke Chang, Jian Wang, Jiqiang Liu（北京交通大学）
- **来源**：arXiv:2610.41401v1，2026-10-30；HTML 全文 `https://arxiv.org/html/2610.41401v1` 本轮重新下载（237,421 字节 HTML / 77,360 字符纯文本）并逐段核对
- **证据等级**：`[原文]`
- **本轮核对的原文位置**：
  - §2.1 Threat model：审计服务 semi-honest；另有 passive observer 试图从加密参考库推断审计规则；参考库对"拥有密文但无密钥的观察者"保密，但**对持有解密密钥的 controller 不承诺保密**
  - §2.2 Three-domain model：controller C 读取明文、构造并加密表示、持密钥、持放行权；server S 只有 pk/evk、无解密密钥、无放行权；provider 可作为数据拥有者把参考集加密到 C 的公钥下
  - §3.3 Delegating audit computation through HE（"输出接口"段）：见 REFERENCE-LEAKAGE.md 逐字引文 R1——任意基向量查询可恢复参考坐标，"present trust model permits this access within C"，保护参考资产是 "a separate goal" 并指向 GAZELLE(Juvekar 2018) 与 Chen 2020 的 output-restricted protocol
  - §3.4 Trusted decision and execution control：decision 绑定具体 pending operation，检查"结果属于该请求、call 与状态仍匹配、replay/参数变化/失败闭合"；representation+audit data+arithmetic+decision rule 构成一个 versioned configuration，provider 更新需重新验证后才由 C 激活
  - §3.5 Confidentiality and conditions：见 RELATED-WORK-MATRIX.md 逐字引文 M1——恶意服务可返回编码虚假分数的良构密文，需 computation-integrity mechanism + call binding
  - §4.2 Detection utility：Table 3（1,252 候选，grouped nested，B_F1）——SealCall 0.840 / center 0.818 / LR 0.913 / RBF-SVM 0.905 / direct cosine 0.666；引用："LR and RBF-SVM achieve F1 of 0.913 and 0.905"；"The reference scorer's B_F1 F1 difference from LR is −0.072, familywise paired interval [−0.112, −0.035]"
  - §4.4 Encrypted fidelity and computation costs：见 COST-AND-OUTSOURCING.md 全部数字与逐字引文
  - Appendix E / Table 10：purpose_scope F1=0.171、recipient_binding 0.455、source_authority 0.607、prior_precondition 0.598；"no world has all four decisions correct"

## S2. PRISM（`[摘要]`；正文 `[UNVERIFIED]`）

- **标题**：PRISM: Efficient zkSNARKs for RNS-Based Homomorphic Encryption
- **来源**：IACR ePrint 2026/1956；ACM CCS 2026 full version；DOI 10.1145/3830454.3846611
- **可得性**：官方 ePrint 摘要页可得（本轮重新抓取 18,220 字节，逐字核对摘要）；PDF 多途径仍被 Cloudflare 挑战页拦截（`eprint.iacr.org/2026/1956.pdf` 返回 5,477 字节 HTML 挑战页，archive 路径同），IACR News 页与 ACM 作者页仅重复摘要
- **证据等级**：`[摘要]`；超出摘要的操作覆盖/验证者模型/绝对成本/是否输出受限/是否约束查询来源 → `[UNVERIFIED]`
- **摘要逐字可验证要点**：HE "does not guarantee the integrity or correctness of the performed operations"；PRISM 是 "the first practical zkSNARK for standard RNS-based HEs"；三项技术（MF-PCS、带 offline phase 的 (inverse) NTT PIOP、VOLE 升级到 zero-knowledge）；相对 Zhou et al. prover 3.5× 慢 / verifier 与 proof 最多 7.8× 优；相对 Atapoor et al. proof 5.5× 大 / prover 约 10.1× 快 / verifier 2.6× 快

## S3. Batch, Pack, and Prove（`[摘要]`；正文 `[UNVERIFIED]`）

- **标题**：Batch, Pack, and Prove: More Efficient Verifiable Computation for CKKS
- **来源**：IACR ePrint 2026/2878；ASIACRYPT 2026 major revision（2026-11-12 received / 11-16 approved）
- **可得性**：官方摘要页可得（18,725 字节，逐字核对）；PDF 同样被 Cloudflare 拦截（5,477 字节挑战页）
- **证据等级**：`[摘要]`；ZK 属性仍 `[UNVERIFIED]`（关键词含 zero-knowledge proofs，但摘要正文只写 "verifiable computation"）
- **摘要逐字可验证要点**：目标是"确保加密计算完整性"；修复 CRYPTO 2025 的承诺证明规模、range proof 的 O(N) 开销、缺少显式 sublinear 验证三大瓶颈；BatchFold PCS / packing / SparsePack；通用 NN 上 "proofs several orders of magnitude smaller and faster than prior approaches"

## S4. SOTERIA（`[原文]`）

- **标题**：SOTERIA: Private Neural Network Inference with Homomorphic Encryption and Garbled Circuits
- **来源**：arXiv:2007.12934；本轮下载 PDF 274,766 字节、15 页、提取 64,430 字符
- **证据等级**：`[原文]`（§Introduction 逐段核对）
- **逐字可验证要点**："We consider an honest-but-curious threat model. In addition, we assume the two parties do not trust, nor include, any third entity in the protocol."；目标是"protects the confidentiality of client data as well as the prediction results against the server"与"preserve the confidentiality of the model parameters with respect to the client"；明确排除："the protection against the indirect inference attacks that aim at reconstructing model parameters or its training data, by exploiting model predictions, is not our goal."

## S5. SANNS（`[原文]`）

- **标题**：SANNS: Scaling Up Secure Approximate k-Nearest Neighbors Search
- **来源**：USENIX Security 2020（29th USENIX Security Symposium, pp.2111–2128）；本轮下载官方 PDF `files.usenix.org/s3fs-public/cdn/sec20-chen-hao.pdf`（620,675 字节，19 页，89,638 字符）并提取
- **证据等级**：`[原文]`
- **逐字可验证要点**（摘要 + §1）："keeps client's query and the search result confidential"；"We prove the security of both protocols in the standard semi-honest model"；问题定义逐字："the server—who holds the dataset—should learn nothing about the query or the result, while the client—who has the query—should not learn anything about the dataset besides the k-NNS result."；18–31× faster、首个扩展到 1,000 万条数据库
- **获取记录**：错误 URL `usenix.org/.../presentation/zhu` 返回的是另一篇 VirusTotal 论文，已纠正为 `chen-hao`

## S6. GAZELLE（`[原文]`）

- **标题**：GAZELLE: A Low Latency Framework for Secure Neural Network Inference
- **来源**：USENIX Security 2018（27th, pp.1651–1669）；本轮下载官方 PDF `usenix.org/system/files/conference/usenixsecurity18/sec18-juvekar.pdf`（716,598 字节，19 页，88,483 字符）
- **证据等级**：`[原文]`
- **逐字可验证要点**（§Threat Model, p.1654）："we consider semi-honest corruptions ... A and B adhere to the software that describes the protocol, but attempt to infer information about the other party's input (the network parameters or the image, respectively)"；"we hide all the weights and biases in the convolution and the fully connected layers"；"We do reveal the number of layers and the size of each layer"；"we hide the entire image, but not its size, from party A"；模型窃取 residual："a potential model stealing adversary could train such classifer without access to B"，建议 "limit the number of classification queries that A is allowed to make of the model"
- **获取记录**：`files.usenix.org/s3fs-public/cdn/sec18-juvekar.pdf` 返回 XML 错误页；`usenix.org/system/files/sec18-juvekar.pdf` 返回 HTML 首页；正确路径为 `usenix.org/system/files/conference/usenixsecurity18/sec18-juvekar.pdf`

## S7. zk-MCP（`[原文]`，沿用 D3-18-01 核对结果）

- **标题**：Zero-Knowledge Audit for Internet of Agents: Privacy-Preserving Communication Verification with Model Context Protocol
- **来源**：arXiv:2512.14737v1；D3-18-01 已核对 HTML 全文，本轮未重复抓取，结论引用其 SOURCES.md S5
- **证据等级**：`[原文]`（前序轮次）
- **关键差异**：威胁模型相反——不诚实方是 agent（prover=agent），Audit Service Provider 只验证；不涉及 CKKS/密文相似度/工具调用执行绑定

## S8. D3-18-01 基线（`[原文]`）

- **仓库**：`D:\Research\d3-18-01-verifiable-agent-audit-feasibility`
- **Phase 0 核验**：分支 `exp-d3-18-01-verifiable-agent-audit-feasibility`；HEAD `b111cedec7fe1859e1bd3c35955b58f575d6ba62`；`git status --porcelain` 空；根提交即 HEAD（orphan 单根）；远端 `kaikai-cao/authz-history-semantic-binding-exp.git`
- **本轮新分支**：`exp-d3-18-02-two-sided-privacy-audit`，从上述 HEAD 建立；新增内容仅在 `d3-18-02/`，D3-18-01 六份文档未改动

## 获取失败与证据缺口（如实标注）

- PRISM 与 Batch,Pack&Prove 正文 PDF：Cloudflare 挑战页，多途径失败；两篇的 ZK 属性细节、绝对成本、是否支持 SealCall 的 256维×16点积负载 → `[UNVERIFIED]`
- 用户上轮消息中的"CKKS 0.176 s / 本地 19 μs / 9,263 倍"：本轮已在 §4.4 原文核实两个数字本身 `[原文]`；但"9,263 倍"是用户计算，本审计复核为 9,263.16×，并额外指出该比值只覆盖评分子阶段，不含共享的 ≈0.487 s trusted preparation（见 COST-AND-OUTSOURCING.md）
- 未发现任何"带来维护参考数据的外部审计服务 + 恶意服务 + 双边隐私 + Agent 调用绑定"的真实生产部署报告；此事实按 `[UNVERIFIED]`（检索未检出，不等于不存在）记录
