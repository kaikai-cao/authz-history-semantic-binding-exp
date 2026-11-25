# RELATED-WORK.md — 逐篇相关工作与重叠分析

日期：2026-11-25。每项标注：类型/状态、原文关键主张、与 R_eq / R_update 的关系、重叠程度。

---

## 1. FlashProve（A1–A7，implementation artifact，v0.16.0，not maintained）

**原文关键主张**：
- 证明"回复来自承诺模型"且不泄露权重；soundness 在 Lean 中证明（针对 Lean verifier）。
- 承诺 ID = hash(配置, anchor Merkle root/shape, OOD seeds/answers)；三份配置由验证者持有。
- **同 ID 内**：每个 leaf file 带 link proof，证明 leaf table 与 anchor 编码同一权重；*"cp_verify checks it on every call"*（A4）；Lean 证明 perfect HVZK（A7）。
- **跨 ID**：*"Between two IDs there is no proof ... A renewal looks exactly like a switch to another model."*（A4）；容量 688,127 batches/leaf table，710,324 leaf tables 的 ZK 预算（A2/A6/A7）。
- 新承诺的设计条件程序不检查：独立 seed/counters、同配置、权重先固定、counter 不恢复（A5）。

**与本轮关系**：
- **R_eq 的关系在同 ID 内已经实现**（anchor↔leaf link proof），且是 ZK 的。
- 官方自述空白是**跨 ID** 的同类关系，不是"从零发明跨承诺等值证明"。
- **重叠程度：直接/最高**。它是本轮问题定义与反例的主要来源，也是"新关系是否足够新"的判据。

---

## 2. Kaizen（CCS 2024，同行评审）

**原文关键主张**：每个梯度下降迭代结束时对训练参数生成承诺 + 简洁 zkPoT，递归组合；proof 与 verifier 时间独立于迭代数；VGG-11 10M 参数、15 min/迭代、1.63 MB、130 ms。

**关系**：证的是 **R_update 的梯度下降子集**："从承诺数据集经声明训练程序得到承诺权重"。它**不**声称两个独立承诺同一权重，也**不**处理权重隐藏下的承诺轮换。

**重叠程度：中**。排除"用 ZK 证明模型更新"作为创新点；但不覆盖 R_eq 窄问题。

---

## 3. Verifiable Fine-Tuning / VFT（arXiv:2510.16830 v3，**预印本**）

**原文关键主张**：从 public initialization + 声明训练程序 + 可审计数据集承诺得到发布模型；五要素：manifest 绑定数据源/预处理/许可/epoch 配额、可验证 sampler（公开可重放 + 私有索引隐藏）、PEFT/AdamW 更新电路与显式误差预算、递归聚合、provenance binding + 可选 TEE property cards；policy quota 零违反、私有采样无可测索引泄漏。

**关系**：R_update 的 LoRA/PEFT 子类 + provenance。仍**不是** R_eq。

**重叠程度：中**。且必须标注预印本状态；不得把其实验数字当独立验证结果。

---

## 4. zkLLMPoT（arXiv:2610.08258 v2，**预印本**，comments 标注 "Preprint"）

**原文关键主张**：*"certifies auditor-defined properties of a trained checkpoint through forward evaluation rather than verification of its optimization trajectory"*；审计者选挑战序列防 trainer 改 checkpoint；1.1–1.5B 41–59 s，13B 131 s，512 长度验证 <0.5 s。

**关系**：证已承诺 checkpoint 的**审计属性**（前向评估），明确不是完整训练轨迹证明。与 R_eq 无关。

**重叠程度：低—中**。作为 zkML 成本参照有用；不构成 R_eq 基线。

---

## 5. CP_link（LegoSNARK，CCS 2019，ePrint 2019/142，§4.1）— **引用纠错**

**用户给出的两个链接（ePrint 2024/1209、Springer 10.1007/s10207-026-01209-1）实际指向**：
*"Collaborative CP-NIZKs: Modular, Composable Proofs for Distributed Secrets"*（Alghazwi et al.；ePrint 预印本 2024-07-29；Springer IJIS 25, article 64，2026-03-03 published）。该文用 CPlink 作为**构件**，研究**分布式 witness** 的 collaborative CP-NIZK，**不是**"两个承诺不同密钥同一向量"的原始定义。

**CP_link 的真实出处**：LegoSNARK §4.1，*"CP-SNARK for Pedersen Verification"*；原文片段（[原文片段]，直取 PDF 受阻）：*"Our scheme CP_link is designed to work with, as global commitment scheme, any Com such that Com.VerCommit = Ped.VerCommit."*；*"although the verification algorithm is the same the commitment keys are not."*

**关系**：
- 一般性的"不同密钥下两个 Pedersen 类承诺同一 witness"**确实已有**（2019 年同行评审）。
- **前提**：承诺的验证算法必须是 Pedersen 型线性同态。FlashProve 是 BLAKE2b Merkle + RS 编码/距离测试，不满足该前提。
- CPILC（ICICS 2025，[二手] 摘要）的 CPlink 同样限 Pedersen 矩阵承诺。

**重叠程度：决定性**。它把"通用跨承诺等值证明"从空白降为已解决；同时以代数结构前提划出了 FlashProve 类非同构承诺的边界。

---

## 6. sigstore/model-transparency + RFC 9943（工程 artifact + Standards Track RFC）

见 NON-ZK-BASELINES.md §1–2。**重叠程度：高（对场景 A）**，**低（对场景 B）**。

---

## 7. draft-mw-spice-inference-chain-00（**已过期 Internet-Draft，非 RFC**）

**原文关键主张**：`inference_root` claim；ZKML + TEE 双机制；有序日志，Merkle root 入 OAuth token；verification key 必须与模型版本一起版本化、部署者应 pin 以防 key substitution。

**关系**：AI 推理证明 + 透明日志的相邻工作；**不处理**两个承诺同一权重，也不提供权重隐藏下的跨承诺等值证明。

**重叠程度：低**。

---

## 8. D3-13 / D3-15 / D3-16 冻结链

- D3-13 R1.1：H4（DS 是否撒谎）OPEN；签名+字段绑定挡 Proxy，不挡 DS 自身。
- D3-15：B3（查询证明 + 独立认证根 + Grant/nonce）在 ATK-DS 内解决；DO 来源真实性/更新完整性外置 → STOP。
- D3-16：C1 由 FlashProve 官方自述空白列为优先候选；本轮按 D3-16 指定的"ZK 必要性反例审计"执行。

**关系**：本轮是这条信任链在 zkML 承诺轮换场景的延续；不得把外部信任基问题当成已解决。

---

## 9. 重叠总表

| 工作 | R_eq（同权重跨承诺） | R_update（更新正确） | 来源真实性 | 权重隐藏 | 类型 |
|---|---|---|---|---|---|
| FlashProve 同 ID link proof | ✅ 仅同 ID | ❌ | ❌（外置） | ✅（Lean） | artifact |
| FlashProve 跨 ID | **❌ 官方自述** | ❌ | ❌ | — | artifact |
| Kaizen | ❌ | ✅ 梯度下降 | 数据集承诺 | ✅ | CCS'24 |
| VFT | ❌ | ✅ PEFT + provenance | manifest + TEE 卡 | 部分 | 预印本 |
| zkLLMPoT | ❌ | 前向属性 | 审计者挑战 | ✅ | 预印本 |
| CP_link / CP-NIZKs | ✅（Pedersen 型） | — | — | ✅ | CCS'19 / IJIS'26 |
| 签名 + 日志 | ❌ | ❌ | 声明层 | 无关 | RFC / artifact |
