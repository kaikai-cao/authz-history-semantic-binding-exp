# TRUST-AND-THREAT-MODEL.md — D3-15-01 角色、信任边界与攻击者能力

基准日期：2026-11-25。与 `SOURCES.md` 配套；所有引用见该文件。

## 1. 角色与信任边界（候选设定）

| 角色 | 拥有什么 | 可控什么 | 是否可信（候选假设） | 现实对应 |
|---|---|---|---|---|
| Agent | 工具调用请求、当前 Grant | 生成 query 内容 | 不可信（可被 prompt injection 操纵） | 工具调用 Agent |
| Gateway | 验证授权与证明 | 接受 / 拒绝结果 | 可信验证方（但**从哪获得 root/epoch 是外部假设**） | D3-13 的 Gateway |
| Data Owner (DO) | 真实数据、认证密钥 | 定义数据集、生成并签名 root | **独立于 DS 的可信源**——但「可信」到底覆盖什么必须拆分 | 监管方 / 数据提供方 |
| Data Service (DS) | 数据副本、执行环境 | 执行查询、生成证明与响应 | **不可信执行方**（D3-13 H4 的对象） | 外包查询服务 |
| Bulletin Board / Auditor | 历史 root、时间戳 | 提供一致性与历史证据 | 提供一致性，不保证写入真实 | CT log / 链 / 第三方审计 |
| Observer（不引入） | — | — | D3-13 的 Oracle-assisted Observer 是实验上界，不迁移到本候选 | — |

**硬边界（任务包第二节）**：Data Owner 与 DS 不能是同一信任主体。若 DS 既决定数据又认证自己生成的 root，则 H6/H7 直接成立，`Root Authenticity` 与 `Update Completeness` 不可声称。

## 2. Data Owner「可信」必须拆成三件事

`SOURCES.md` A4/A3/B1 一致表明：现有系统里的「trusted data owner」是一个复合假设，不能被当成一个整体继承。

| 子假设 | 内容 | 现有一致做法 | 本轮性质对应 |
|---|---|---|---|
| DO-1 承诺绑定 | DO 对自己持有的数据正确计算承诺，之后不能换库 | ZKSQL commit-and-prove；PoneglyphDB 不可撤销链上承诺 + auditor | Query Correctness 相对 root 成立 |
| DO-2 来源真实 | DO 认证的数据确实来自真实世界、完整、未被篡改 | **A4 作者访谈明确留给可信 data owner，不在模型内**；A3 由「双方都信任的 auditor 读取原始库核真实性」承担 | Update Completeness / Root Authenticity |
| DO-3 更新如实 | 所有真实更新都进入已认证状态 | AD SoK：read-write consistency 只在有 trusted writer/每 key 签名时成立；无信任源模型下只有 history binding（防 equivocation，不保证最新写） | Update Completeness / Freshness |

**关键区分**：DO-1 可由密码学强制；DO-2/DO-3 在现有文献中都是**外部信任假设**。本轮若只把 DO-1 电路化，H6/H7 原样保留。

## 3. 攻击者模型（必须分开，不得合并）

### ATK-DS：恶意 Data Service（D3-13 H4 的直接对象）
- 能力：可返回任意结果、伪造查询证明输入、重放旧证明、对两个 Gateway 展示不同 root（equivocation）、替换 query_digest 绑定。
- **不能**：伪造 DO 的签名；不能控制 DO 的认证密钥；不能改写 Bulletin Board 已发布历史（假设一致性机制成立）。
- 对应攻击历史：H1、H2（部分）、H3、H4、H5、H8（部分）。
- 现有方案态度：ZKSQL/PoneglyphDB/TruthTable/Rogue 的 soundness 都假定 prover 恶意但承诺固定——ATK-DS 在其模型内，**可由查询结果证明 + root 绑定处理**。

### ATK-DO-negligent：数据所有者漏记 / 认证不完整（H6）
- 能力：真实世界发生更新，但 DO 没把它写入已认证状态；或延迟写入。
- **不是**密码学敌手：没有伪造签名，没有打破承诺绑定。
- 对应：H6。
- 现有方案态度：**全部无解且明确外置**——AD SoK 的 read-write consistency 只约束「已认证更新序列」，不约束「现实更新是否都进序列」；PoneglyphDB 的 auditor 只能核「它读到的原始库」与承诺一致，若原始库本身就是漏记后的库则照样通过；TruthTable 作者访谈明确 *"The system does not establish that the committed data was collected honestly, complete, or otherwise fit for purpose."*

### ATK-DO-malicious：数据所有者故意认证错误数据（H7）
- 能力：DO 用自己的合法密钥对虚假数据集签名并发布 root。
- 对应：H7。
- 现有方案态度：**签名有效 ≠ 数据真实**（与 D3-11/D3-13 同构）。AD SoK 公开外包模型明说客户用 source 公钥验证，且 *"updates, and possibly verification, become impossible if the trusted data source's key is lost or compromised"*；**没有文献声称仅靠 SNARK 或签名可以解决合法密钥持有者自签假数据**。
- 可能的外部缓解：独立观察源 / 多方交叉认证 / TEE 内的采集程序——但它们都引入新信任锚，属于 D3-13 H4 的同类问题。

### ATK-COLLUDE：DS + DO 合谋
- 能力：DO 签假 root，DS 对假库给出正确查询证明。
- 对应：H7 + H1 的组合；D3-13 T9 的类比。
- 结论：若 DO 被完全信任，合谋不可检测；这与 D3-13 C 架构的 T9 完全同构。

### ATK-OBSERVER 不存在
- 本候选**不引入** D3-13 的 Oracle-assisted Observer。任何「独立观测」都必须先回答它看到什么、谁给它授权、它自己是否被劫持——这是开放问题，不是可默认的前提。

## 4. 对任务包七性质的作用力分析

| 性质 | 谁破坏 | 需要什么 | SNARK 单独够吗 | 原文依据 |
|---|---|---|---|---|
| Query Correctness | ATK-DS | 查询结果证明 | **够**（相对固定承诺） | A2/A3/A4/A5 |
| Root Authenticity | ATK-DS 或 ATK-DO-malicious | DO 签名 + Gateway 独立获得 DO 公钥 | 不够，需来源认证 | A4 访谈；B1 公开外包模型 |
| History Binding | ATK-DS | 历史承诺链 / 一致性 gossip | 不够，需一致性机制 | B1 Def.3 / B2 Append-only |
| Freshness | ATK-DS 重放 | 独立最新 epoch 锚 + 时戳 | 不够，不能在电路内自断 | B1 §VI-C；B2 threat model |
| Update Completeness | ATK-DO-negligent | 外部真实事件源 | **不够**，所有已知方案外置 | B1 read-write consistency 前提；A4 访谈 |
| Authorization Binding | ATK-DS 换 query | grant/nonce/query_digest 绑定 | 够（签名或电路中约束均可） | D3-13 C 已实测 H1/H2 |
| Confidentiality | 旁观者 | 明确隐私目标后再选 ZK | 取决于目标 | A2/A3 已有 ZK 审计 |

**本轮最重要句子（应写入 DECISION）**：证明结果正确地来自某个 root，不等于证明这个 root 是真实、最新、完整的。ATK-DO-negligent 与 ATK-DO-malicious 不是证明系统能补的缺口。

## 5. 信任假设清单（构造草案必须显式列出）

1. Gateway 独立获得 DO 公钥与当前 epoch 锚，且锚的更新不经过 DS。
2. DO 的认证密钥未被攻破；若攻破，方案不承诺检测（B1 明确）。
3. Bulletin Board 提供 append-only 与一致性；单不可信服务器模型下只能得到 fork consistency（B2 §2.2.2）。
4. 查询证明的 soundness 依赖底层 SNARK 与正确实现的电路；本次不建电路、不声称实现正确。
5. Grant/query 绑定的字段集合与 D3-13 C 一致；不重新定义授权语义。
6. 若引入 auditor 核原始数据真实性，auditor 是新的可信方（A3 明确）；不能把它的结论写成密码学证明。

## 6. 与冻结链的一致性

- D3-11：签名有效 ≠ 事件真实；日志可追加 ≠ 无遗漏。本轮 H6/H7 是这两条的直接实例。
- D3-12：无外部锚定时把公开输入放进电路可被证明者自造。本轮 `epoch = latest_epoch` 若在电路内自断，属于同一陷阱。
- D3-13：H4 保持 OPEN；C 的签名绑定解决 H1/H2 但不解决 DS 自身撒谎。本轮只有通过「root 来自独立 DO」把 H4 的一部分（结果相对数据状态撒谎）转化为可证明问题，**不解决 DO 撒谎**。
- D3-14：STOP 只关闭 private quiescence；外部信任基开放问题与本轮一致，但本轮不得借它重新立项「通用执行可信」。
