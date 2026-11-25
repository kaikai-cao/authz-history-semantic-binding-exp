# DECISION.md — D3-15-01 最终裁决

**裁决：`STOP`**（仅关闭「Authorization-Bound Freshness-Aware Verifiable Query」作为新密码学选题；不关闭 Agent 安全与信任机制整体方向）
日期：2026-11-25
任务性质：只读文献审计 + 性质形式化 + 构造可行性分析。未实现协议、未写 Halo2 电路、未改任何冻结仓库。

---

## 一页摘要

**总体回答**：D3-13 的 H4 可以部分转化——把「DS 返回的结果是否来自认证数据状态」交给查询证明 + 独立数据根后，ATK-DS（恶意 DS）下的 H1/H4/H5 与「结果相对给定 root 的正确性」确实可解；但 DS 之外的数据所有者真实性（H6 漏记 / H7 故意认证假数据）仍外置，且这是所有公开工作的共同边界。**在已有 SNARK 数据库证明与认证字典基础上，未找到值得发表的独立密码学贡献。**

**最关键一句话**：证明结果正确地来自某个 root，不等于证明这个 root 是真实、最新、完整的；后三者分别需要来源认证、独立当前状态锚与真实事件信任基，都不是证明系统能生成的。

**直接回答用户验收点「B3 是否已经解决了问题？」**：
- 在 **ATK-DS 模型内**：**是**。B3（ZK 查询证明 + 独立认证根 + Grant/nonce 绑定）解决 H1、H4、H5，且查询正确性有强基线（ZKSQL / PoneglyphDB / TruthTable / Rogue）。
- 在 **ATK-DO-negligent / ATK-DO-malicious 模型下**：**否**，且 B4 也否——H6/H7 需要 DO 之外的真实事件源，属于 D3-13 H4 与 D3-14 外部信任基的同类开放问题。
- 因此 **不能为使用 Halo2 再造 B4**；这正是任务包要求如实报告的「组合已足够」情形。

**裁决理由速览**：命中 STOP 条件第 1、3、5 条（见第五节）：
1. 方案是 TruthTable/Rogue 类查询证明 + 独立认证数据根（PoneglyphDB 已写出）+ D3-13 Grant 绑定的直接组合；
2. 数据所有者必须被完全信任（DO-2/DO-3），本轮没有降低或改善该信任成本；
3. ZK 没有不可替代增益——六项关系里只有 R4 本质需要查询证明，R1/R2/R3/R5 是策略/认证/一致性，R6 是普通公开输入绑定。

---

## 1. 七个必答问题的答法（与 D3-13 H4 对齐）

### Q1：H4 是否能通过独立认证数据状态解决？
**部分能，且只能解决 H4 的一半。**
- D3-13 H4 原文：*"DS 本身没撒谎？C 不成立；D 仅在可信 Oracle 下检出；正式状态 OPEN"*；T8 是「签名有效但假声明」。
- 本轮把「假声明」拆成两类：
  - **结果相对给定 root 的假声明**（H1/H4/H5）：可由查询证明 + 独立 root + Grant/nonce 绑定解决——这是**可解的一半**。
  - **root 所代表的数据状态本身是假的或过期的**（H6/H7）：查询证明无能为力——这是**仍然 OPEN 的一半**。
- 因此 D3-13 H4 的表述应更新为：*"结果相对认证状态的正确性可解；认证状态相对真实世界的可信性仍是外部信任基问题"*。这不是关闭 H4，而是把它精确定位。

### Q2：哪个性质没有被现有工作明确覆盖？
没有找到**可由新密码机制独立补齐**的性质。
- `Update Completeness`（真实更新都入认证状态）确实无人覆盖，但它是外部事件采集问题，AD SoK / TruthTable 作者访谈都明确外置，不是「未被发明的证明关系」。
- `Freshness` 与 `History Binding` 已被 AD SoK / GlassDB 形式化并给出实现路径（witness、公告板、gossip、变更计数）。
- `Authorization Binding` 已被 D3-13 C 用签名解决。

### Q3：能否给出严格形式化安全定义？
**能写出关系草案（`CONSTRUCTION-SKETCH.md`），但不是新的安全定义。**
- R1–R6 中只有 R4（`QueryExec(database, query) = result`）是查询证明的标准关系，已被 A2–A5 覆盖。
- R5 若写成 `epoch = latest_epoch` 在电路内自断，正是 D3-12 证伪的「无外部锚自造公开输入」陷阱。
- `CONSTRUCTION-SKETCH.md` 因此把 R5 明确移到电路外。

### Q4：ZK 是否增加实质安全属性？
**没有额外安全属性；只在已有 ZKSQL/PoneglyphDB 的隐私方向上有已知增益。**
- 六项检查对照表（`CONSTRUCTION-SKETCH.md` §4）显示：查询结果正确性需要查询证明；root 认证、Grant 绑定、freshness、history binding 都可以用签名 / AD / witness 完成且更直接。
- PoneglyphDB 已把「ZK 隐藏数据 + 查询正确性 + auditor 核源 + 链上承诺」写进 SIGMOD 2025 论文；TruthTable 已把 Agent 检索场景作为动机（作者访谈级）。
- 若本轮再把这些检查拼起来并电路化，属于 STOP 条件 5。

### Q5：Completeness 是否有独立可检查来源？
**在「认证状态内」有；在「真实世界」没有。**
- 认证状态内：AD SoK 的 read-write consistency（有 trusted writer 时）、update proof 的变更计数、GlassDB 的 append-only 与 gossip 都是可检查来源。
- 真实世界层：H6/H7 无法从任何认证结构推出——TruthTable 作者访谈明确 *"does not establish that the committed data was collected honestly, complete"*；AD SoK 明说 no-trusted-source 下只有 history binding，且审计激励仍是开放问题。

### Q6：强基线是否已建立？
**是，而且强于本轮可设想的 ZK 版本。**
- B0 D3-13 C（签名 DS 响应，H1/H2 实测成立）；
- B1 查询证明（ZKSQL / PoneglyphDB / TruthTable / Rogue / ZkChainDB）；
- B2 查询证明 + 独立认证根（PoneglyphDB 已含 auditor + 链上承诺）；
- B3 B2 + Grant/nonce 绑定（D3-13 C 字段绑定可直接复用）；
- B4 B3 + 独立最新状态与历史一致性（AD SoK / GlassDB 的 witness/bulletin board/gossip）。

### Q7：相比已有方案能否定义可量化增益？
**不能。**
- 已有可量化基线：TruthTable 55 s / 32 ms / 24 kB；Rogue 相对 vSQL/PoneglyphDB 加速 ×42.8–×8624.1 / ×149.6–×11362.4；ZKSQL 两个数量级；I-EIB 14.2 ms + 有界遗漏 100% 检出；TRACE 1,440 篡改链全拒、16.1 ms 中位治理成本（作者报告）。
- 本轮未提出场景度量、隐私泄露度量、误接受率改进量；`CONTINUE` 的「可量化实验指标」不满足。

---

## 2. Phase 4 六问逐条回答

1. **B3 是否已解决全部实际攻击？** 在 ATK-DS 模型内是（H1/H4/H5 全解，查询正确性可证）。在 ATK-DO-negligent/malicious 下没有（H6/H7）。
2. **B4 相比 B3 是否增加独立安全性质？** 增加的是 Freshness 与 History Binding 的**外部可检查性**（H2/H3），但这是 AD SoK/GlassDB 已有性质的实例化，不是新性质；且对 H6/H7 无帮助。
3. **哪些攻击需要 SNARK，哪些只需签名或认证数据结构？** 需要 SNARK：H1 的结果相对给定 root 的正确性（通用 SQL）。只需签名/AD：H2/H3（freshness/history）、H4/H5（Grant/nonce）、H8（多源版本一致性策略）。无法由二者解决：H6/H7。
4. **数据所有者漏记更新时，协议究竟能否发现？** 不能。auditor 核的是它读到的库与承诺一致（A3）；read-write consistency 只约束已认证更新序列（B1）；若真实事件未进入 DO 的采集，所有验证输入都自洽。唯一路径是 DO 之外的独立事件源，属外部信任基。
5. **ZK 是否存在明确的隐私必要性？** 本轮无。若未来出现「Gateway 不可见 query/result 明文但需确信其满足授权策略且来自承诺数据集」的场景，ZKSQL/PoneglyphDB 的隐私证明已覆盖；D3-13 R1.1 的解禁条件也是这么写的，但本轮没有新场景。
6. **与 TruthTable、Rogue、Authenticated Dictionaries 的差别在哪里？** 差别只在「组合了 Agent Grant 绑定」——而这部分 D3-13 C 已用签名解决并实测。TruthTable 已提出 Agent 检索场景与可信启动外置（作者访谈级）；Rogue 已推进动态更新；AD SoK 已形式化 value/history/read-write consistency。**没有发现超出项。**

---

## 3. 与冻结链的一致性

- D3-13 R1.1：`CONDITIONAL_HOLD`、H4 OPEN 未变；本轮不修改其分支 `48b5d5e`。
- D3-14-01：STOP 只关闭 private quiescence；本轮不重开它，也不修改 `19e24b5`。
- D3-11/D3-12：签名有效≠事件真实；无外部锚自造公开输入不 sound —— 本轮 H7/H2 分别复现这两条。
- 本轮**不**把 ZKP 引入作为默认下一步；若用户未来要求进入原型，必须先接受「只针对认证状态内的 ACCEPT 语义」，并提供真实 DO / 外部事件源。

---

## 4. 强制停止条件逐条判定

| 条件 | 命中 | 证据 |
|---|---|---|
| 方案只是 TruthTable/Rogue + 认证数据根 + D3-13 Grant 的直接组合 | **命中** | PoneglyphDB 已写「ZK 查询正确性 + 可信 auditor 核源 + 链上承诺」；D3-13 C 已有 Grant/nonce 绑定 |
| 新性质可由已有认证字典安全定义直接覆盖 | **命中** | AD SoK Def.3–5：H3=history binding、H2=read-write/rollback；H6 明确外置 |
| 数据所有者必须被完全信任，工作没有降低信任成本 | **命中** | DO-2/DO-3；TruthTable 作者访谈、AD SoK 公开外包模型；H6/H7 无解 |
| ZK 没有明确的不可替代增益 | **命中** | 六检查中只有 R4 需要查询证明；R1/R2/R3/R5 可用非 ZK 机制 |
| 不能给出有效反例或可量化贡献 | **部分命中** | 反例 H6/H7 有效但对所有方案成立；无可量化增益 |

`CONTINUE` 六条件：独立性质（否）、现有基线无法解的有效攻击（仅 ATK-DO 有，但非本方案可解）、构造增益（无）、现实可部署假设（DO-2/3 未满足）、可量化指标（无）——**不满足**。
`CONDITIONAL_HOLD` 的「存在可研究问题但缺真实数据源 / 更新事件 / 部署证据」客观上部分成立；但任务包 STOP 条件是「满足任意一项即可」，且用户明确要求「不能为了使用 Halo2 再造 B4」，故按条款优先级取 STOP。

---

## 5. 保留但不立项的开放问题

未来若另立任务包，方向必须是**DO 之外的真实事件信任基**，而非查询证明：
1. 独立采集：谁有资格证明一笔真实更新发生过（D3-13 H4 的同类）。
2. 远程证明绑定：把采集程序 / 数据源锚定到可验证硬件或协议，而非自述。
3. 多源跨域版本一致性的策略层定义（H8），并明确可接受 skew。
4. 审计激励与 auditor 独立性（AD SoK §VI-D 明确开放）。

上述问题与 D3-11/12/13/14 的结论同构：缺口在信任边界，不在证明系统。本轮按停止条件停止，不追加第五轮架构拼装。

---

## 6. 交付自检

- [x] 仅在 `D:\Research\d3-15-01-agent-query-root-binding-audit` 创建七份文档。
- [x] 未修改 D3-13（仍 `48b5d5e9...`）、D3-14-01（仍 `19e24b5...`）、MVP 或任何冻结仓库；未写电路；未开始真实数据库实现。
- [x] 八个攻击历史 H1–H8 全部写出，DO 恶意与 DS 恶意严格分开；每例给出六项要求。
- [x] 七性质表、B0–B4 覆盖表、六关系分析、普通方案 vs ZK 对照均已给出。
- [x] 文献类型区分 peer-reviewed / preprint / Internet-Draft；Internet-Draft 未称 RFC；同名 TRACE 已消歧。
- [x] 所有引用回溯 `SOURCES.md`；vSQL/TruthTable/Rogue/ZkChainDB 正文未取得的均标 `UNVERIFIED`；TruthTable 的 Agent 场景与可信启动只按 `AUTHOR-INTERVIEW` 使用。
- [x] 裁决仅三值之一：`STOP`。提交推送与远端 SHA 核验见最终汇报。
