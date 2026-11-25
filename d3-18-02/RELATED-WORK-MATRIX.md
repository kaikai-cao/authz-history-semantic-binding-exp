# D3-18-02 Phase 3–4：相关工作直接比较与安全性质矩阵

基准日期：2026-11-25。证据等级见 SOURCES.md。**不根据摘要宣布已有工作解决全部问题**；PRISM / Batch,Pack&Prove 正文仍 `[UNVERIFIED]`，只按摘要可验证范围比较。

## 1. Phase 3：七篇逐篇结论

### 1.1 SealCall（S1，`[原文]`）
- 双边隐私现状：保护用户输入对 semi-honest server；**不保护参考对 controller**（§3.3 明确 permitted + separate goal）。
- 恶意服务完整性：**明确缺失**，§3.5 逐字："Correct evaluation relies on the semi-honest assumption: a malicious server could return a well-formed ciphertext encoding a false score. Extending the protocol to such servers requires a computation-integrity mechanism, such as verifiable evaluation, alongside call binding."（引文 M1）`[原文]`
- 输出限制：返回 individual similarities，无 prescribed-prediction 裁剪 `[原文]`。
- 工具调用绑定：§3.4 已实现（结果↔请求、状态/replay/参数变化/失败闭合）`[原文]`。

### 1.2 PRISM（S2，`[摘要]`；正文 `[UNVERIFIED]`）
- **能否抵御恶意 CKKS 计算服务？**摘要可确认：它针对 "HE does not guarantee the integrity or correctness" 问题，提供 standard RNS-based HE（含 CKKS）的 zkSNARK，即证明服务端的密文计算正确 → 对"恶意服务伪造分数"这一性质，**在通用层提供**。但能否直接覆盖 SealCall 的 256维×16参考点积+阈值前计算、绝对成本、指定验证者身份 → `[UNVERIFIED]`，不声称可即插即用。
- **是否同时解决模型隐私/输出限制/查询来源约束？**摘要给出的 statement 是"对 RNS-HE 计算的正确性"，**未声明**模型参数对验证者隐藏、未声明输出只披露约定预测、未声明查询来源认证。这三项在 PRISM 中 `[未见]`/`[UNVERIFIED]`。ZK 属性隐藏的是 prover 的 witness，不等于自动获得"模型隐私"或"输出限制"——这是两个不同性质。
- 性能：摘要只有相对倍数（3.5×/7.8×/5.5×/10.1×/2.6×），无绝对数；**不套用其 NN 负载倍数到 SealCall 负载** `[推断禁止]`。

### 1.3 Batch, Pack, and Prove（S3，`[摘要]`；正文 `[UNVERIFIED]`）
- 提供 CKKS 的**可验证计算**（integrity），针对 CRYPTO'25 的可扩展性瓶颈；摘要未明确 ZK 属性 `[UNVERIFIED]`。
- 与 PRISM 的区别：更直接的"非 ZK vHE"候选，若只需计算完整性、不需 witness 隐藏，它可能是更贴合的选择（D3-18-01 已记此点）`[推断]`。
- 同样**不声明**模型隐私、输出限制、查询来源约束。NN 评估的 "orders of magnitude" 是相对先前 vHE，不是相对明文 `[原文摘要]`。

### 1.4 SANNS（S5，`[原文]`）
- **是否已解决双边隐私下的安全近邻检索？是，在 semi-honest 下。**逐字："keeps client's query and the search result confidential"；"We prove the security of both protocols in the standard semi-honest model"；"the server ... should learn nothing about the query or the result, while the client ... should not learn anything about the dataset besides the k-NNS result."
- 安全边界：**semi-honest only**；不含恶意服务计算完整性证明；不处理 Agent 工具调用绑定；输出限制是"只给 k-NNS 结果"，正是 §2 所要求的 output-restricted 形态。
- 与本候选关系：**它直接覆盖 Phase 2 的参考泄露修复路线**——SealCall §3.3 明确引用 Juvekar 2018 与 Chen 2020 作为 output-restricted 路线，SANNS 是同类问题的成熟解法（近邻场景）`[原文 + 推断]`。

### 1.5 GAZELLE（S6，`[原文]`）
- **是否已解决客户端输入与服务商模型的双边隐私？是，在 semi-honest 下。**逐字："we consider semi-honest corruptions ... A and B adhere to the software ... but attempt to infer information about the other party's input"；"we hide all the weights and biases"；"we hide the entire image, but not its size"。
- 自述边界：揭示层数与各层大小；model stealing 通过输出查询仍可行，建议限制查询次数 `[原文]`。**说明"双边隐私"在原文也是有限语义**，不等于"模型绝对不可恢复"。
- 与 SealCall 的直接关系：SealCall §3.3 引用 Juvekar et al. 2018（即 GAZELLE）作为 output-restricted protocol 路线 `[原文]`。这是"双边隐私已有成熟研究"的最强证据。

### 1.6 SOTERIA（S4，`[原文]`）
- 双边隐私：honest-but-curious；单服务器、无第三方；"protects the confidentiality of client data as well as the prediction results against the server" + "preserve the confidentiality of the model parameters with respect to the client"。
- 自述边界：明确排除"通过预测间接重建模型参数/训练数据"的攻击 `[原文]`。与 GAZELLE 同构——双边隐私的语义是"不直接泄露"，不是"抗所有推断"。
- 无恶意服务完整性、无 Agent 绑定。

### 1.7 zk-MCP（S7，`[原文]`，前序轮次）
- 威胁模型**相反**：prover=agent（agent 自证 token/输出），ASP 只验证；不涉密文相似度、恶意审计服务伪造分数、工具调用执行绑定。是"ZK 用于 Agent 审计"的强基线，不是本候选的解 `[原文]`。

## 2. Phase 4：八项安全性质矩阵

证据标记：**✅明确提供** / **◐特定假设下提供** / **❌未提供** / **❔证据不足**。

| 安全性质 | SealCall | PRISM | Batch,Pack&Prove | SANNS | GAZELLE | SOTERIA | zk-MCP |
|---|---|---|---|---|---|---|---|
| 用户输入隐私（服务看不到任务/工具参数） | ◐ semi-honest 输入保密 `[原文]` | ❔摘要未涉输入侧 `[摘要]` | ❔`[摘要]` | ✅查询对 server 保密 `[原文]` | ✅图像对 A 保密（大小除外）`[原文]` | ✅客户端数据与预测对 server 保密 `[原文]` | ◐通信隐私，内容不泄露给 ASP `[原文]` |
| 服务商模型隐私（用户无法恢复参考/模型） | ❌对 C 不保密，作者明言 permitted + separate goal `[原文]` | ❔未声明隐藏 Θ `[摘要]` | ❔`[摘要]` | ✅只给 k-NNS 结果 `[原文]` | ◐隐藏权重，但泄露层数/层大小，抗 model stealing 未解决 `[原文]` | ◐隐藏参数，但明确排除经预测间接重建 `[原文]` | ❔MR 有承诺但不涉 Θ `[原文]` |
| 恶意服务计算完整性（能否伪造/修改/跳过） | ❌作者自述缺失 `[原文 M1]` | ✅通用 RNS-HE 正确性 zkSNARK `[摘要]` | ✅CKKS vHE `[摘要]` | ❌semi-honest only `[原文]` | ❌semi-honest `[原文]` | ❌honest-but-curious `[原文]` | ◐验证 agent 声明，非防服务伪造 `[原文]` |
| 输出限制（只给约定审计结果） | ❌返回 individual similarities `[原文]` | ❔`[摘要]` | ❔`[摘要]` | ✅只给 k-NNS 结果 `[原文]` | ◐只给分类结果，但 model stealing 残存 `[原文]` | ◐只给预测结果 `[原文]` | ◐只给 type counts + hashes `[原文]` |
| 查询来源约束（服务如何判断请求来自合法 Agent 上下文） | ❌S 侧无认证；C 侧 call binding 是结果检查非来源认证 `[原文]` | ❔未提 `[摘要]` | ❔未提 `[摘要]` | ❌未提 `[原文]` | ❌未提 `[原文]` | ❌未提 `[原文]` | ❌未提 `[原文]` |
| 版本真实性（模型/参考/阈值绑定可信版本） | ◐流程性 versioned config，无外部可信锚 `[原文 §3.4]` | ❔未提 `[摘要]` | ❔未提 `[摘要]` | ❌未提 `[原文]` | ❌未提 `[原文]` | ❌未提 `[原文]` | ◐MR 有承诺但不涉审计模型 `[原文]` |
| 工具调用绑定（放行只适用于被审计调用） | ✅§3.4 结果↔请求+状态/replay/参数/失败闭合 `[原文]` | ❌不涉及 | ❌不涉及 | ❌不涉及 | ❌不涉及 | ❌不涉及 | ❌不涉及（通信审计）`[原文]` |
| 模型判断质量（证明是否掩盖语义错误） | ❌purpose_scope F1=0.171、recipient_binding 0.455 `[原文]`；密码学无解 | ❌不解决 | ❌不解决 | ❌不解决 | ❌不解决 | ❌不解决 | ❌不解决 |

## 3. 关键区分（任务包特别强调）

- **计算完整性 ≠ 模型判断正确性**：PRISM/BatchPack 证明"服务按约定电路算对了"，不证明"约定的模型/参考集/阈值做出了正确的安全判断"。SealCall Appendix E 的 F1=0.171/0.455 是模型/表示层的硬伤，密码学无法补齐。`[原文 + 推断]`
- **双边隐私 ≠ 恶意服务完整性**：GAZELLE/SANNS/SOTERIA 双边隐私都在 semi-honest / honest-but-curious 下；它们**不防服务伪造结果**。反之 PRISM 防伪造但摘要未声明模型隐私。两类性质在现有工作中是**正交的**，不是一方覆盖另一方。`[原文 + 摘要]`
- **输出限制是独立机制**：SealCall §3.3 已把 output-restricted protocol 列为未来路线并引用两个成熟工作 `[原文]`；说明"防止用户恢复参考"不是新研究缺口，是**已有方案未被本系统采用**。`[推断]`

## 4. 矩阵支持的结论 `[推断]`

1. 八项性质中，**没有任何单一方案全部提供**；但也没有任何一项"只能靠新密码学原语"才能提供。
2. 三项核心候选性质各有现成覆盖：用户输入隐私（SealCall/GAZELLE/SANNS/SOTERIA）、服务商模型隐私（SANNS 完全；GAZELLE/SOTERIA 有限）、恶意计算完整性（PRISM/BatchPack）。
3. 真正全表皆弱的两项是**查询来源约束**与**版本真实性外部锚**——但这两项本质是**系统信任边界 / 身份与认证问题**，不是 HE/SNARK 能单独补齐的密码学性质；D3-13 H4、D3-15 root authenticity 已多轮得出同构结论 `[推断，跨轮次]`。
4. 因此"把双边隐私 + 恶意服务完整性 + Agent 调用绑定放在一起"= **GAZELLE/SANNS（双边）+ PRISM/BatchPack（完整性）+ SealCall §3.4 / MVP（绑定）的系统集成**，不是新的安全性质。`[推断]` 是否值得作为研究问题，见 DECISION.md。
