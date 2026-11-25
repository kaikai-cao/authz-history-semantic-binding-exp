# SOURCES.md — D3-17-01 原始来源、出版状态与证据等级

日期：2026-11-25。所有引用均标注类型与证据等级：
- **[原文]** = 直接抓取的官方文档/论文原文页面或 PDF 文本，含逐字引文与章节。
- **[原文片段]** = 原文存在于搜索引擎索引的 PDF 正文中，但直接抓取受阻；引文来自索引片段，标为部分可回溯。
- **[二手]** = 第三方综述/评论站/索引摘要，不得冒充论文原文。
- **[UNVERIFIED]** = 未取得可回溯原文，仅作线索。

Internet-Draft 一律按草案评价，不称 RFC；预印本不称同行评审成果。

---

## A. FlashProve（implementation artifact，核心案例）

### A1 · README.md
- 类型 / 状态：**implementation artifact**，Anthropic 官方仓库，v0.16.0，*"A research artifact: not maintained, not accepting contributions."*，Apache 2.0。
- URL [原文]：https://github.com/anthropics/FlashProve ；https://raw.githubusercontent.com/anthropics/FlashProve/main/README.md
- 逐字：
  - *"FlashProve lets an AI provider prove which model answered a request, without revealing the model's weights."*
  - *"The protocol's soundness is proved in Lean 4."*
  - *"The commitment ID: get it from a party your user trusts, never from the server being checked or from files sent with the proof."*
  - 规模：Llama 4 Maverick / 1,024-token / 单 H100；route 4 需 330 GB RAM、245 GB disk。

### A2 · guide/known-limits.md
- URL [原文]：https://raw.githubusercontent.com/anthropics/FlashProve/main/guide/known-limits.md
- 逐字（本轮裁决基石）：
  - *"The provider chooses the model. A yes does not say whose weights they are, that the shipped committer made the commitment, or which real model it is."*
  - *"A commitment runs out. At full size and the default setting each leaf table (a masked encoding of the weights) serves 688,127 batches, by calculation ... Nothing warns you before that limit, and a commitment cannot be extended. A new commitment has a new ID, and no proof links the two."*
  - *"The C++ verifier and the CUDA prover are written to follow the same protocol and are tested against it, not themselves proved."*
  - *"The honest prover in these theorems is a Lean definition, not the CUDA prover: nothing is proved for the programs."*
  - *"There has been no independent security audit."*
- 注意：这是**作者自述限制**，不是数学不可能性的证明；本审计不把作者声明当作定理。

### A3 · guide/how-it-works.md
- URL [原文]：https://raw.githubusercontent.com/anthropics/FlashProve/main/guide/how-it-works.md
- 逐字：
  - *"The commitment ID is a hash, in 64 hex digits, of the configuration, the Merkle root and shape of the first weight table, a masked encoding of the weights, and the out-of-domain (OOD) seeds and answers."*
  - *"The ID does not cover the leaf files or the key file's proofs, which cp_verify checks on reading."*
  - *"The client must trust what no call checks: the commitment ID, the expected policy and its numbers, the tokenizer and chat template, and cp_verify itself."*

### A4 · guide/verify-a-proof.md §"When the commitment ID changes"
- URL [原文]：https://raw.githubusercontent.com/anthropics/FlashProve/main/guide/verify-a-proof.md
- 逐字：
  - *"Under one commitment ID, each proof is checked against the same first table of weights."*
  - *"Each copy's public file, `leaf/<k>.bin`, holds a link proof that it encodes the same weights as the first table; `cp_verify` checks it on every call. All copies share one ID."*
  - ***"Between two IDs there is no proof. Nothing public shows that two commitment IDs stand for the same weights: you have only the provider's word. A renewal looks exactly like a switch to another model."***
  - *"The exception: public weights committed under a published seed, as in `examples/maverick`: anyone who has the weight files and makes the calibration set can make that commitment again and compare the ID."*
  - *"Compare the new configuration files with the old ones. A provider that only renews can keep all three byte for byte; a change shows what it changed. By design, nothing else in the public files of two IDs can be compared: each commitment has randomness of its own."*
  - *"Keep some prompts with their replies and the proofs you accepted, and send the same prompts under the new ID: that compares the two at those prompts only."*
  - *"From a new ID alone, do not conclude that the model has changed; from equal files and replies, do not conclude that it has not."*
  - *"What is known to force a new ID: a copy that is used up; a second GPU; any change to a configuration file ... a move of the service to another machine ..."*
  - *"By arithmetic from three short sessions, one copy is about a year and a quarter for one GPU that never pauses, at 1 request per batch."*

### A5 · docs/protocol.md §4, §6.2
- URL [原文]：https://raw.githubusercontent.com/anthropics/FlashProve/main/docs/protocol.md
- 逐字：
  - *"A new commitment to the same weights gives those weights a second key file. The design then needs conditions that no program checks. Among them: the new commitment has a seed of its own, drawn independently, and counters of its own, it keeps the same configuration, scales included, the weights were fixed beforehand, and no counter is ever copied or restored."*
  - *"Leaf tables cannot be added later (6.2), so decide how many the commitment will need over its whole lifetime."*
  - *"Each link opens columns of the anchor too, so the anchor's query bound limits the number of leaf tables."*
  - *"the link proof ties the leaf table to the anchor, and the commitment ID fixes the anchor's root and the configuration"*
  - §6.2：*"the committer folds the rows of the anchor and the rows of the leaf table with the same random factors, and commits to both folded vectors. Then it opens random columns of both tables. A proximity test shows two things: each folded vector fits the opened columns of its own table, and the two folded vectors agree at a random point in the part that holds the weights."*

### A6 · guide/weight-hiding.md
- URL [原文]：https://raw.githubusercontent.com/anthropics/FlashProve/main/guide/weight-hiding.md
- 逐字（关键边界）：表格行 *"Batches; a second commitment; timing; what the public files themselves tell of the weights | nothing"*；*"A lost disk or a second GPU means a new commitment ... Lean has no statement on hiding for more than one commitment"*；*"The counter. ... The prover counts the batches that each encoding (a leaf table) serves and stops at a limit (688,127 at full size)."*

### A7 · docs/limits.md
- URL [原文]：https://raw.githubusercontent.com/anthropics/FlashProve/main/docs/limits.md
- 逐字：*"The link proof. Before hashing, at full size, Lean proves perfect honest-verifier zero knowledge for it (`homeExactAt`) ... with no error and no premise."*；*"up to 710,324 copies ... with 688,127 requests each"*。

---

## B. 非 ZK 模型供应链基线

### B1 · RFC 9943
- 类型 / 状态：**Standards Track RFC**，*"An Architecture for Trustworthy and Transparent Digital Supply Chains"*，June 2026。
- URL [原文]：https://www.rfc-editor.org/rfc/rfc9943.html ；https://www.rfc-editor.org/rfc/rfc9943.txt
- 逐字 §9.2 Accuracy of Statements：*"Issuers can make false Statements either intentionally or unintentionally; registering a Statement only proves it was produced by an Issuer."*
- in-toto 在文中作为供应链描述元数据 payload 列出（*"Supply chain description metadata [in-toto]"*）。**注意**：本次全文检索未发现 `DSSE` 字符串；DSSE 来自 B2 的 sigstore 项目，不是 RFC 9943 本身。不得混引。

### B2 · sigstore/model-transparency
- 类型 / 状态：**开源工程 artifact**（与 OpenSSF 协作；README 未自称"官方 Sigstore 项目"，本审计按工程 artifact 处理）。
- URL [原文]：https://github.com/sigstore/model-transparency ；https://raw.githubusercontent.com/sigstore/model-transparency/main/README.md
- 逐字：
  - *"The focus is on providing verifiable claims about the integrity and provenance of the resulting models"*
  - *"The bundle contains ... a payload as a DSSE envelope ... The DSSE envelope contains an in-toto statment and the signature over that statement."*
  - *"the statement itself contains subjects which are a list of (file path, digest) pairs"*
  - *"When using Sigstore, signing events are recorded to Sigstore's append-only transparency log."*
  - *"users can check that the signature comes from a known or trusted identity and thus that the model hasn't been tampered with after training."*
- 限制：README 未给出"签名不证明模型内容真实"的逐字段落；该类限制由 RFC 9943 §9.2 与通用签名语义提供，**不得伪装成该 README 的原话**。

---

## C. ZK 模型训练/更新证明

### C1 · Kaizen
- 类型 / 状态：**同行评审**，ACM CCS 2024，DOI 10.1145/3658644.3670316，pp. 4316–4330；ePrint 2024/162（2024-02-04 received，2024-07-22 last revision）。
- URL [原文]：https://eprint.iacr.org/2024/162 ；https://dlnext.acm.org/doi/10.1145/3658644.3670316
- 逐字（摘要）：*"at the end of each iteration, the prover generates a commitment to the trained model parameters attached with a succinct zkPoT, attesting to the correctness of the executed iterations."*；*"VGG-11 with 10 million parameters and batch size 16 ... 15 minutes per iteration ... 24× faster ... 1.63 megabytes ... 130 milliseconds"*。
- 边界：证的是**梯度下降执行正确性**，不是"两个独立承诺同一权重"。

### C2 · Verifiable Fine-Tuning (VFT)
- 类型 / 状态：**预印本**，arXiv:2510.16830 v1 2025-10-19 / v3 2025-12-29，20 pages，cs.CR/cs.CL。**非同行评审**。
- URL [原文]：https://arxiv.org/abs/2510.16830
- 逐字（摘要）：*"produces succinct zero knowledge proofs that a released model was obtained from a public initialization under a declared training program and an auditable dataset commitment"*；五要素含 *"commitments that bind data sources, preprocessing, licenses, and per epoch quota counters to a manifest"*、*"update circuits restricted to parameter efficient fine tuning"*、*"recursive aggregation"*、*"optional trusted execution property cards"*。

### C3 · zkLLMPoT
- 类型 / 状态：**预印本**，arXiv:2610.08258 v1 2026-10-06 / v2 2026-10-11，comments 明示 "Preprint"，cs.AI。**非同行评审**。
- URL [原文]：https://arxiv.org/abs/2610.08258
- 逐字（摘要）：*"certifies auditor-defined properties of a trained checkpoint through forward evaluation rather than verification of its optimization trajectory"*；*"proving times of 41-59 seconds for 1.1-1.5B-parameter models and 131 seconds at 13B ... verification below half a second at a sequence length of 512"*。
- 边界：作者自述不做完整训练轨迹证明。

---

## D. 跨承诺等值证明（引用纠错，重要）

### D1 · 用户给出的两个链接实际指向同一篇工作
- ePrint **2024/1209** [原文]：https://eprint.iacr.org/2024/1209 标题为 ***"Collaborative CP-NIZKs: Modular, Composable Proofs for Distributed Secrets"***（Alghazwi, Bontekoe, Visscher, Turkmen；Preprint，2024-07-29 approved）。
- Springer DOI **10.1007/s10207-026-01209-1** [原文]：https://link.springer.com/article/10.1007/s10207-026-01209-1 为同文期刊版，*International Journal of Information Security* 25, article 64，published **2026-03-03**，Regular Contribution，Open access。
- 两者内容是**分布式 witness 的 collaborative commit-and-prove NIZK**（基于 LegoSNARK 设计），其中使用 CPlink 作为构件；**不是**"两个承诺不同密钥同一向量"的原始定义文献。

### D2 · CP_link 的真实出处：LegoSNARK
- 类型 / 状态：**同行评审**，Campanelli, Fiore, Querol，ACM CCS 2019；ePrint 2019/142。
- URL：https://eprint.iacr.org/2019/142 ；PDF 索引片段 https://eprint.iacr.org/2019/142.pdf
- 证据等级 **[原文片段]**（直接抓取 PDF 受 Cloudflare/401 拦截，引文来自搜索引擎索引的 PDF 正文）：
  - §4.1 CP-SNARK for Pedersen Verification：*"Our scheme CP_link is designed to work with, as global commitment scheme, any Com such that Com.VerCommit = Ped.VerCommit."*
  - *"Let us stress that although the verification algorithm is the same the commitment keys are not."*
  - 关系：*`R^link(c', (u_j)_j, o') = 1 ⇔ c' = (o', u₁ᵀ, …, u_ℓᵀ) · [f]₁`*，见证为各承诺的 opening。
- 关键含义：**CP_link 要求 Pedersen 型群承诺验证算法**（线性同态），不能直接套到 FlashProve 的 BLAKE2b Merkle + Reed–Solomon/距离测试承诺。此点为本轮裁决的核心之一；因直取受限，按 **[原文片段]** 标注，不冒充全文逐字核对。

### D3 · CPILC / CPlink（ICICS 2025）
- 类型 / 状态：**会议论文**，Zhengzhou Tu 等，ICICS 2025，DOI 10.1007/978-981-95-3540-8_3，pp. 40–61。
- URL [二手/摘要]：https://dlnext.acm.org/doi/10.1007/978-981-95-3540-8_3
- 摘要片段：*"we develop CPlink, a sub-proof of commitment equivalence, showing that a matrix of Pedersen commitment opens to a matrix of values committed in the ideal linear commitment model."*
- 证据等级 **[二手]**（仅摘要，未取全文）；同样限于 Pedersen 型。

---

## E. 相邻草案

### E1 · draft-mw-spice-inference-chain-00
- 类型 / 状态：**Expired Internet-Draft (individual)**，2026-03-18，expires 2026-09-19，Intended Status: Informational，**不是 RFC、无 IETF 背书**。
- URL [原文]：https://datatracker.ietf.org/doc/html/draft-mw-spice-inference-chain-00
- 逐字：*"This document defines the inference_root claim ... providing cryptographic proof that a claimed AI model actually performed the inference that produced a given output."*；*"ZKML proofs ... and TEE attestation quotes"*；*"verification keys ... MUST be versioned alongside model versions ... SHOULD be pinned by deployers to prevent key substitution attacks."*
- 用途：仅作"AI 推理证明 + 透明日志结合"的相邻工作，不解决跨承诺同一性。

---

## F. 基线链（只读核验，未修改）
- D3-16-01 `cdf469169311aee711186a7e5af19267b74f7e38`（本轮 Phase 0 起点，HEAD 精确匹配、clean）。
- D3-15-01 `0bb4e789...`、D3-14-01 `19e24b5...`、D3-13 R1.1 `48b5d5e...`、MVP `e327a94`、主仓 `89caad7`：HEAD 复核未变且 clean。
