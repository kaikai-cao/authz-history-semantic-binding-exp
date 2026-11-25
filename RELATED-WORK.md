# D3-18-01 相关工作与重叠分析

证据等级同 SOURCES.md。逐篇记录：发表状态 / 目标系统 / 原文主张 / 自述限制 / 与本候选的重叠。

## 1. SealCall（S1，`[原文]`）

- **状态**：arXiv:2610.41401v1 预印本（2026-10-30），非同行评审。北京交通大学。
- **主张**：三域隐私保护审计范式；CKKS 加密相似度评分；执行绑定；1,252 候选 mean F1=0.840；代表配置 0.176 s。
- **自述限制**：semi-honest 审计服务假设；§3.5 明确恶意服务需 computation-integrity mechanism；§4.3/App.E 诊断显示 purpose_scope F1=0.171、recipient_binding F1=0.455，"do not reliably distinguish these policy changes"；输出接口下 controller 可恢复参考坐标，保护参考资产是独立目标。
- **重叠**：本候选的问题**直接来自**它的 §3.5 缺口。它不是竞争者，是待加固的基线系统。

## 2. PRISM（S2，`[摘要]`；正文 `[UNVERIFIED]`）

- **状态**：IACR ePrint 2026/1956，**ACM CCS 2026**（已接收，full version），Ant Group。
- **主张**：首个 standard RNS-based HE（BFV/BGV/CKKS）的实用 zkSNARK；MF-PCS + (I)NTT PIOP + VOLE 升级 ZK；比 Zhou et al. S&P2025 prover 3.5× 慢但 verifier 7.8× 快 / proof 7.8× 小，比 Atapoor et al. CiC2024 proof 5.5× 大但 prover 10.1× 快 / verifier 2.6× 快。
- **自述限制**：摘要仅提 "in a model with an offline phase" 与 "via VOLE correlations"；具体支持哪些 CKKS 操作、ZK 是否指定验证者、绝对成本——正文未取得。
- **重叠**：本候选拟对接的可验证计算机制。但**只能确认它证明"对标准 RNS-HE 的密文计算正确"，不能确认它直接支持 SealCall 的 256维×16参考点积负载**，也不能确认 ZK 属性在本负载是否为必需。用户给的"线性代数/NN 测试证明端开销随规模增长"与摘要方向一致但数字 `[UNVERIFIED]`。

## 3. Batch, Pack, and Prove（S3，`[摘要]`）

- **状态**：IACR ePrint 2026/2878，ASIACRYPT 2026 major revision（2026-11-12/16）。
- **主张**：改进 Cascudo et al. CRYPTO 2025 的 CKKS vHE；BatchFold PCS + packing + SparsePack；通用 NN 上 proof "several orders of magnitude smaller and faster"。
- **自述限制**：摘要未声明 ZK 属性（关键词有 zero-knowledge proofs，摘要正文只写 verifiable computation）`[UNVERIFIED]`；针对 modified HE 还是 standard CKKS 与 PRISM 摘要措辞有张力 `[UNVERIFIED]`。
- **重叠**：**这是把"现成 vHE 接到 SealCall"的更直接候选**。本候选若只用"计算完整性"（非 ZK），这篇可能比 PRISM 更合适——必须在协议设计中正面比较，不能预设 PRISM 是唯一选择。存在直接组合 CKKS vHE + Agent 审计的可能性，但截至本轮未检出已发表的具体系统 `[推断]`。

## 4. Verifiable Computation for Approximate HE（S4，`[摘要]`）

- **状态**：IACR ePrint 2025/286，CRYPTO 2025 major revision，DOI 10.1007/978-3-032-01907-3_21。
- **主张**：RingLWE/CKKS 密文计算有效性；modulus switching / key switching / rescaling 小成本；Rq 上 PIOP + multilinear PCS；已实现，小电路与 SOTA 相当、可扩展更大电路。
- **自述限制**：摘要注明 range check 章节有勘误。
- **重叠**：CKKS vHE 的学术基础。PRISM 摘要把它列为"designed for a modified HE scheme"的先前工作，但 S4 摘要自述处理 standard CKKS——此张力需正文核对 `[UNVERIFIED]`。对本候选的意义：可验证 CKKS 计算**不是新问题**，已有至少三篇顶会/顶刊级工作（CRYPTO'25 / CCS'26 / ASIACRYPT'26）。

## 5. zk-MCP（S5，`[原文]`）

- **状态**：arXiv:2512.14737v1 预印本（2025-12-11），非同行评审。
- **主张**：IoA 中基于 MCP 的零知识通信审计；五实体含独立 ASP；agent 生成 π_token / π_output，ASP 验证；data authenticity + communication privacy；Circom + snarkjs；proof 开销 <4.14%。
- **自述限制**："initial exploration of the framework's practical feasibility... further testing and refinement will be needed"。
- **重叠**：同为"ZK + Agent 审计"，但威胁模型**相反**——不诚实方是 agent（prover=agent，谎报 token/输出），本候选不诚实方是 audit service（prover=server，伪造分数）。zk-MCP 不涉及 CKKS、密文相似度、恶意审计服务计算完整性、工具调用执行绑定。**是强基线，不是直接解**。

## 6. 执行绑定近邻（D3-13 / MVP，`[原文]`，前序轮次已核）

- `agent-exec-binding-mvp`（HEAD `e327a944`）已实现 request/context/tool/schema 绑定 + 独立执行代理签名证据；D3-13 R1.1 裁决 `CONDITIONAL_HOLD`，C 架构挡 Proxy 单方面作恶，但 DS 自身撒谎（H4）开放。
- **重叠**：MVP 的绑定能力可作为"审计结果 → 工具调用"的执行侧基础；但 SealCall §3.4 已有 call binding，MVP 不填补新的密码学缺口，只提供工程连接点。D3-15 已证伪"查询正确性绑定数据来源真实性"，须避免重蹈覆辙。

## 7. 覆盖矩阵（候选问题是否被直接解决）

| 性质 | SealCall | PRISM | Batch,Pack&Prove | zk-MCP | MVP/D3-13 | 本候选需补 |
|---|---|---|---|---|---|---|
| 密文审计输入隐私 | 已解决(semi-honest) `[原文]` | N/A | N/A | 不同场景 | N/A | 保持 |
| 恶意服务计算完整性 | **缺失(作者自述)** `[原文]` | 提供(zkHE) `[摘要]` | 提供(vHE) `[摘要]` | 不涉及 | 不涉及 | **核心** |
| 审计结果↔调用绑定 | 已解决 `[原文]` | 不涉及 | 不涉及 | 不涉及 | 已部分解决 | 复用，非创新 |
| 模型/参考库版本承诺 | 未覆盖 `[推断]` | 不涉及 | 不涉及 | MR 有承诺但不涉 Θ `[原文]` | 不涉及 | 需补 |
| 审计判断准确性 | 短板(F1=0.171) `[原文]` | 不解决 | 不解决 | 不解决 | 不解决 | **密码学无解** |
| ZK 不可替代性 | 未要求 `[原文]` | 提供 ZK `[摘要]` | ZK `[UNVERIFIED]` | 提供 ZK `[原文]` | 不涉及 | 待证 |

## 8. 相关工作结论 `[推断]`

1. **是否存在直接组合 CKKS+ZK/vHE 的 Agent 安全审计系统？** 截至本轮检索未检出。SealCall 是 CKKS Agent 审计但半诚实；PRISM/BatchPack 是通用 vHE/zkHE 但非 Agent；zk-MCP 是 Agent 审计但非 CKKS、威胁模型相反。存在组合空间。
2. **组合本身是否构成贡献？** 不构成密码学贡献——计算完整性的密码学原语已由三篇顶会工作提供。最多是系统工程/应用层组合。
3. **是否有 Agent 系统层贡献？** 有限：恶意审计服务威胁模型（SealCall 未建模）+ 模型/参考库版本承诺绑定（SealCall 未覆盖）是真实缺口；但执行绑定 SealCall 已有，不能重复计入。
4. **是否有性能空间？** 未知：代表负载 0.176 s 是纯 CKKS，叠加 vHE/zkHE 的成本无目标负载实测数据 `[UNVERIFIED]`，不能编造预测。
5. **是否必须用 Halo2？** 否。任务包不预设；若用通用 SNARK 验证 HE 计算，PRISM/BatchPack 是更贴合的现成机制；Halo2 无明确必要性 `[推断]`。
