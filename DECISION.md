# DECISION.md — D3-16-01 研究空间重置与候选池更新

日期：2026-11-25
任务性质：只读横向候选池更新。**不宣布论文题目、不启动原型、不写电路、不改任何冻结仓库。**

---

## 一页摘要

本轮在 D3-08 至 D3-15 系列审计之后重置研究空间，核查 31 项来源（6 篇顶会/顶刊、14 篇预印本/草案、若干 artifact 与行业指南），产出 **7 个候选（A 类 3 / B 类 2 / C 类 2）**，最终保留 **2 个优先候选 + 2 个备选 + 3 个暂缓/排除**。

**最重要的判断**：经过 D3-08 至 D3-15，Agent 执行可信性这条线上的"授权绑定 / 执行证据 / 历史完整性 / 查询正确性 / 资源计量守恒"都已被强基线覆盖，继续找小缝隙的边际收益很低。**本轮唯一带"原文逐字自述空白"的候选出现在 C 类**：Anthropic FlashProve 在 `known-limits.md` 明写 *"A new commitment has a new ID, and no proof links the two"* 与 *"A yes does not say whose weights they are, that the shipped committer made the commitment, or which real model it is"*——这是官方 artifact 亲手写下的未解边界，不是我们推测的缺口。

**裁决**：`CANDIDATE-POOL UPDATED`——候选池更新完成；**不进入原型**；两个优先候选各自需要一个独立深度审计任务包（建议 D3-17-01 / D3-17-02）验证其不可替代性后才决定是否立项。

---

## 1. 对任务包四-phase 的执行结果

| Phase | 要求 | 完成情况 |
|---|---|---|
| Phase 1 候选生成 | 每类至少 2 个，共 5–8 个，每个七要素 | 7 个（A3/B2/C2），全部含研究对象/真实问题/攻击者或系统模型/最强基线/独立贡献/验证方式/最小原型资源。见 `CANDIDATE-POOL.md` |
| Phase 2 相关工作核查 | 原文优先，区分发表/预印/草案/自述，特别查 2025–2026 | 31 项来源逐条分级；zkCraft/RECPIR 标注撤稿；Internet-Draft 不称 RFC；FlashProve 直引来自官方仓库 known-limits.md。见 `SOURCES.md` / `RELATED-WORK.md` |
| Phase 3 候选淘汰 | 每候选六问 | 7 个候选全部逐条答六问。见 `RANKING.md` |
| Phase 4 最终候选池 | 2 优先 + 2 备选 + 其余暂缓/排除，每个优先给下一轮任务范围 | C1/A1 优先，C2/B1 备选，A2/A3 暂缓、B2 排除；D3-17-01/02 任务范围已写。见 `RANKING.md` §二 |

---

## 2. 三个大类的整体判断

### A 类 · ZK 系统与工程优化 —— 拥挤但可做扎实系统工作
- 本轮核查到 6 篇顶会论文（zkFuzz S&P'26、MegaZK ICS'26、MicroNova S&P'25、Interstellar PKC'26、TensorZKP USENIX'26、Celer CRYPTO'26）密集覆盖电路 fuzz、GPU 加速、lookup 原语、folding。
- **排除项 8 已实证**：zkFuzz 开源且发表（452 电路 85 bugs），zkCraft 因作者问题被撤稿——"TCCT + LLM 变异"不是空白。
- **可做**：A1（分阶段内存剖面）是原文支持的稀疏处（S8–S10 只报端到端倍数），与用户既有 Orchard F4-A 能力直接衔接，风险在"贡献是工程基准而非密码学新性质"。
- **谨慎**：A2 的规格 oracle 缺口与 D3-15 root 真实性同构，暂缓。

### B 类 · Agent 系统安全 —— 最拥挤，学术形式化稀疏但工程工具已多
- 记忆污染（S19/S20/S21 + FARMA/TRACE-Memory/OWASP ASI-06）与 MCP 工具描述供应链（S22 多 artifact）在 2026 年已有密集工作。
- **B2 排除**：S21 的 bounded occupancy 未实现是唯一窗口，但属系统机制、非密码学、窗口极窄。
- **B1 备选**：跨服务器组合语义的可验证绑定有真实缺口，但问题定义缺顶会论文支撑，且 hash-pin + 透明日志可覆盖单服务器场景；ZK 必要性待证伪，暂不进优先。

### C 类 · 密码学 × AI —— 空白最实，本轮主推
- S24 FlashProve（Anthropic 官方 artifact，2026-10-30，Lean 4 soundness）证明"回复来自承诺模型"，但**逐字自述不证明承诺来源、不链接两次承诺**；README 还要求验证者从可信方而非被验证服务器获取承诺 ID。
- S25 ZKPROV 把来源外包给"权威签名数据集"，不覆盖权重版本；S27 SoK VFL 指出可验证联邦学习只证计算正确、Sybil/串通开放。
- **C1（版本谱系）/ C2（来源锚定）**是由官方自述空白直接支撑的候选，其中 C1 需要新 ZK 关系、拥挤度低，列优先候选 1。

---

## 3. 关键证据链（全部可回溯）

1. **用户点名的四项已全部纳入基线并原文核对**：
   - `draft-zhang-ioa-usage-accounting-01`（S1，2026-11-02，Informational 个人草案非 RFC）§7.9 原文写"签名不证明计量值准确/事件无遗漏"；
   - Zhu/Wang 预算守恒（S2，arXiv 2610.00349，2026-09-29）TLA+ 有界检验 + 崩溃注入，作者自述有限范围；
   - zkRAG（S3，ePrint 2026/709）+ VERIF（S4，ePrint 2026/1802）——注意 **VERIF 是 RAG 检索 ZK，不是电路 fuzz**，本轮消歧；
   - zkFuzz（S5，S&P 2026，已发表开源）+ zkCraft（S6，arXiv 2602.00667，**已撤稿**，不得作有效基线）。
2. **C 类基石**：FlashProve 仓库 README + known-limits.md 逐字引用（S24）。
3. 全部 URL、类型、直引、撤稿状态见 `SOURCES.md`。

---

## 4. 与冻结链的一致性

- 未修改 D3-13 R1.1（`48b5d5e`，`CONDITIONAL_HOLD`，H4 OPEN）、D3-14-01（`19e24b5`，STOP）、D3-15-01（`0bb4e789`，STOP）、MVP、主仓或任何冻结仓库。
- C1/C2 触及的"承诺/数据来源真实性"与 D3-13 H4、D3-15 H6/H7、D3-14 外部信任基**同构**；本轮没有声称解决它，而是把它定位到 zkML 新场景并找到官方自述空白——是否可形成独立贡献须由 D3-17 深度审计判定。

---

## 5. 下一步（不自动启动）

- 若用户决定推进：**D3-17-01**（C1 承诺版本谱系的 ZK 必要性与反例审计）与 **D3-17-02**（A1 Halo2 分阶段基准的重复性与贡献定位审计）是两个建议的独立深度审计任务包，范围见 `RANKING.md` §二。
- 本轮**不**进入任何原型、**不**写电路、**不**宣布论文题目。
- 停止条件：若 D3-17-01 找不到 B0/B1（签名+日志）无法通过而 ZK 谱系能过的反例，或 D3-17-02 发现已有 stage-level 基准 → 相应候选 STOP，按既有标准如实报告，不改名重立。

---

## 6. 交付自检

- [x] 六份文档齐全：`EXCLUSION-MAP.md`、`CANDIDATE-POOL.md`、`RELATED-WORK.md`、`RANKING.md`、`SOURCES.md`、`DECISION.md`。
- [x] 候选 7 个（每类至少 2，总计在 5–8 区间），每个含七要素。
- [x] Phase 3 六问逐候选回答；最终 2 优先 + 2 备选 + 3 暂缓/排除。
- [x] 每个优先候选给出下一轮独立深度审计任务范围。
- [x] 所有引用可回溯 `SOURCES.md`；区分原文/二手/UNVERIFIED；Internet-Draft 不称 RFC；撤稿工作（zkCraft、RECPIR）明确标注。
- [x] 未修改任何冻结仓库；未写电路、未启动原型；未提前宣布论文题目。
