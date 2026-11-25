# PROPERTY-COVERAGE.md — D3-15-01 性质对照矩阵

基准日期：2026-11-25。单元格严格四值：
`Explicitly solved` / `Partially addressed` / `Out of scope` / `Not specified`。
证据放文末「证据索引」，用 `[编号]` 回指。

## 主矩阵（性质 × 文献/基线）

| 性质 | vSQL | ZKSQL | PoneglyphDB | TruthTable | Rogue | ZkChainDB | AD SoK | GlassDB | D3-13 C |
|---|---|---|---|---|---|---|---|---|---|
| Query Correctness | Explicitly solved | Explicitly solved | Explicitly solved | Explicitly solved | Explicitly solved | Explicitly solved | Not specified | Partially addressed | Out of scope |
| Root Authenticity | Partially addressed | Partially addressed | Explicitly solved | Partially addressed | Not specified | Partially addressed | Partially addressed | Partially addressed | Partially addressed |
| History Binding | Not specified | Not specified | Partially addressed | Not specified | Not specified | Partially addressed | Explicitly solved | Explicitly solved | Out of scope |
| Freshness | Not specified | Not specified | Partially addressed | Not specified | Not specified | Not specified | Explicitly solved | Partially addressed | Partially addressed |
| Update Completeness | Not specified | Not specified | Partially addressed | Out of scope | Not specified | Not specified | Partially addressed | Partially addressed | Out of scope |
| Authorization Binding | Out of scope | Out of scope | Out of scope | Out of scope | Out of scope | Out of scope | Out of scope | Out of scope | Explicitly solved |
| Confidentiality | Partially addressed | Explicitly solved | Explicitly solved | Not specified | Not specified | Explicitly solved | Partially addressed | Out of scope | Partially addressed |
| 动态更新效率 | Partially addressed | Not specified | Not specified | Not specified | Explicitly solved | Not specified | Partially addressed | Explicitly solved | Out of scope |

## 基线 B0–B4 覆盖

| 性质 | B0 = D3-13 C 签名 DS 响应 | B1 = 查询证明无 Grant 绑定 | B2 = B1 + 独立认证根 | B3 = B2 + Grant/nonce 绑定 | B4 = B3 + 独立最新状态与历史一致性 |
|---|---|---|---|---|---|
| H1 固定根下伪造结果 | Partially addressed（被签名挡的是 Proxy 替换，不是 DS 自造） | Explicitly solved | Explicitly solved | Explicitly solved | Explicitly solved |
| H2 过期 root | Not specified | Not specified | Partially addressed（可验签旧根，但不知是否最新） | Partially addressed | Explicitly solved（需外部 epoch 锚） |
| H3 root equivocation | Not specified | Not specified | Partially addressed（签了不同根但需比对） | Partially addressed | Explicitly solved（history binding + gossip/auditor） |
| H4 换查询绑定 | Explicitly solved（D3-13 C 十字段绑定） | Out of scope | Out of scope | Explicitly solved | Explicitly solved |
| H5 证明重放 | Explicitly solved（nonce） | Not specified | Not specified | Explicitly solved | Explicitly solved |
| H6 DO 漏记更新 | Out of scope | Out of scope | Out of scope | Out of scope | **Partially addressed only**（能查已发布更新序列内部一致，不能发现未发布事件） |
| H7 DO 故意认证假数据 | Out of scope | Out of scope | Out of scope | Out of scope | **Out of scope**（签名有效≠数据真实） |
| H8 多源版本不一致 | Not specified | Not specified | Partially addressed | Partially addressed | Explicitly solved（若多源都纳入已声明 history/manifest） |

## 任务包七性质精确判定

| 性质 | SNARK 查询证明能否单独实现 | 判定依据 |
|---|---|---|
| Query Correctness | **可以** | A2/A3/A4/A5 均在固定承诺下证明查询语义 |
| Root Authenticity | **不可以，需来源认证** | A4 作者访谈；B1 公开外包模型用 source 公钥 |
| History Binding | **不可以，需一致性机制** | B1 Def.3 是 AD 的性质，不是 SNARK 的性质；B2 Appendix-only |
| Freshness | **不可以，需独立当前状态锚** | B1：`value/history binding ... do not guarantee that a read returns the most recent write`；D3-12 电路内自断公开输入不 sound |
| Update Completeness | **不可以，仅有哈希链或签名不够** | B1：read-write consistency 只约束已认证序列；A4：数据收集诚实/完整不在模型内 |
| Authorization Binding | **可通过现有签名绑定或证明关系实现** | D3-13 C 已实测 H1/H2 成立；无需新密码机制 |
| Confidentiality | **需明确隐私目标后才能讨论 ZK** | A2/A3 的 ZK 针对数据库内容；本轮无档案场景，不能预设 ZK 增益 |

## 证据索引

- `[1]` ZKSQL §1 / §3.1：P may be untrusted；proofs with respect to a public commitment；malicious P 下 soundness of all query answers；setup 后 prover 不能改 D 内容。
- `[2]` PoneglyphDB §1 / §3 Trust Model：trusted data owner + untrusted server；双方都信任的 auditor 读取原始库核真实性并链上承诺。
- `[3]` TruthTable ePrint 2026/1260 摘要：correct execution of the verifier's SQL query over the prover's committed database；55s/32ms/24kB（作者声称）。
- `[4]` TruthTable 作者访谈（非论文原文）：高价值 AI Agent 场景；trusted data owner 模型；*"does not establish that the committed data was collected honestly, complete, or otherwise fit for purpose"*；provenance chain 在模型外。
- `[5]` Rogue ePrint 2026/1890 摘要：updatable matrix lookup；RogueDB authenticated indexes；相对 vSQL/PoneglyphDB 加速（作者声称）。
- `[6]` AD SoK §Appendix C：Read-write consistency ⇒ History-binding ⇒ Value-binding；value/history binding purely syntactic；no trusted source 下 history binding 最合适；rollback detection 来自 update proof 中的变更计数。
- `[7]` AD SoK §Public Outsourced Storage：trusted data source defines and signs dictionary；key 丢失/失陷则更新与验证不可行。
- `[8]` GlassDB §2.2.2：单不可信 provider 只能 fork consistency，需 gossip；三类威胁模型（Byzantine provider / BFT 副本多数可信 / TEE）。
- `[9]` I-EIB §3：closed system boundary 内 intent-execution integrity；bounded step-omission 100% 检出；construction-based，非形式化完备证明。
- `[10]` TRACE IEEE Access 摘要（中文转述）：1,440 篡改链全拒；仪器未测到预期结果；边界观察者零禁止副作用但硬件截断无法确认；阈值/跨平台延迟限制。
- `[11]` D3-13 C（R1.1 DECISION §2）：H1/H2 成立、H4 OPEN；T8 有效签名假声明。
- `[12]` D3-12 / D3-11 冻结结论：无外部锚自造公开输入不 sound；签名有效≠事件真实、日志可追加≠无遗漏。
- `[13]` Execution-Finality Enforcement draft-00 摘要：Finality Sink 区分实际 pending operation 与请求批准/ bearer credential；非完整协议、非 IETF 共识。

## 矩阵读法限制

- `Explicitly solved` 只表示该文**在其声明范围内**给出构造 / 定义，不表示解决了 H6/H7。
- B1 的 `Explicitly solved`（H1）是相对固定承诺的查询正确性；若 DS 与 DO 合谋换根，仍落入 H7。
- B4 对 H6 只标 `Partially addressed`：能发现「已发布更新序列」内部矛盾，不能发现「根本没有发布」的真实事件。
- 任何空格不得直接推出研究缺口；缺口判定在 `DECISION.md` 结合停止条件进行。
