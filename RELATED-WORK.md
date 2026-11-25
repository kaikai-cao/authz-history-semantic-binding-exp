# RELATED-WORK.md — D3-15-01 逐篇相关工作对照

基准日期：2026-11-25。逐篇记录：元数据 / 文献类型 / 原文贡献 / 实际构造 / 作者自述限制 / 与本问题重叠。引用见 `SOURCES.md`。

文献类型严格区分：peer-reviewed / arXiv preprint / Internet-Draft / independent proposal / implementation artifact。

---

## A 组：可验证数据库与查询证明

### A1 vSQL（IEEE S&P 2017）
- **类型**：peer-reviewed 会议论文。作者 Zhang, Genkin, Katz, Papadopoulos, Papamanthou。
- **贡献（原文可验证程度：交叉引用级）**：任意 SQL 查询在动态外包数据库上的验证；标准模型 = 可信 data owner 承诺并外包、不可信 server 执行并证明。
- **实际构造**：基于多项式承诺 / 交互式协议的查询证明；Rogue 摘要称其为有简洁证明的 verifiable database 先驱。
- **作者限制**：本次未取得正文（`UNVERIFIED`）；用 PoneglyphDB 表 1 / Rogue / AD SoK 交叉确认其位置。
- **重叠**：Query Correctness 的早期基线；无 Agent Grant、无独立 epoch 锚。

### A2 ZKSQL（PVLDB 2023）
- **类型**：peer-reviewed 期刊论文。作者 Li, Weng, Xu, Wang, Rogers。DOI `10.14778/3594512.3594513`。
- **贡献（原文 §1/§3.1）**：零知识证明下 ad-hoc SQL 查询的 authenticated answers；证明相对公开承诺正确且完备，不泄露输入记录；TPC-H 两个数量级加速（作者声称）。
- **实际构造**：commit-and-prove；逐 operator 构造 ZK 证明；authenticated set operations 加速。
- **作者限制**：P 是 data owner 且可恶意，但承诺是 P 自己生成的（"proofs with respect to a public commitment of the private data"）；模型不覆盖「P 认证的数据是否就是真实世界数据」。
- **重叠**：R4（查询正确性证明）+ Confidentiality 已覆盖；无 Grant / freshness / 更新真实性。

### A3 PoneglyphDB（arXiv 2411.15031 / SIGMOD 2025）
- **类型**：peer-reviewed 会议论文 + arXiv preprint。
- **贡献（原文 §1/§3）**：非交互 ZK 证明任意 SQL 查询正确性；**明确设置 trusted auditor**：审计员读原始数据库、核真实性，并验证链上不可变承诺与真实库一致。
- **实际构造**：PLONKish 电路、递归证明组合、低阶多项式约束；Halo2；无 trusted setup（公共参数 + 可验证随机）。
- **作者限制**：信任模型要求「prover 与 verifier 都信任的 auditor」；prover 可用假库的担忧由 auditor 而非密码学解决；auditor 看到原始数据，隐私依赖 ZK。
- **重叠**：**这是与本候选最接近的已发表工作** —— 「ZK 查询证明 + 独立认证数据根 + 第三方核源」已明确写出。差别：无 Agent Grant / request / nonce 绑定（这是 D3-13 C 的部分），无独立最新 epoch 协议。
- **我方推论**：本候选若只是把 D3-13 C 的签名字段接到 PoneglyphDB 上，命中 STOP 条件 1。

### A4 TruthTable（IACR ePrint 2026/1260）
- **类型**：**preprint**（ePrint，非 peer-reviewed；ZKProof VIII / SeQureDB 2026 为演讲）。
- **贡献（摘要原文）**：在 prover 承诺数据库上证明 verifier 的 SQL 查询正确执行；TPC-H 22 中支持 17；100 万行 55 s / 32 ms / 24 kB（作者声称）。
- **实际构造**：表的新多项式表示 + 关系算子子协议 + 以证明时间为目标的 query planner；约 54,000 行 Rust（访谈口径）。
- **作者自述限制（AUTHOR-INTERVIEW，非论文原文）**：
  - 高价值 AI Agent 是明确应用场景（法律 Agent 检索先例，需要「结果确实来自相关公共法律库」的证明）——用户任务包的说法得到**访谈级**支持，论文正文本次未核实。
  - 标准可信 data owner 模型：可信第三方承诺数据库，数据留在不可信 server。
  - *"proves correct execution against the committed database"*；*"does not establish that the committed data was collected honestly, complete, or otherwise fit for purpose"*；provenance chain（从空状态 + 转移函数的承诺链）*"outside the model described for TruthTable"* —— 用户所说「把数据库承诺的可信启动留给应用层」得到**访谈级**支持。
- **重叠**：确认「验证其他 Agent 返回的查询结果」与「可信启动外置」两项均已被作者提出；即便按用户转述，也不构成本轮新缺口。

### A5 Rogue（IACR ePrint 2026/1890 / ACM CCS 2026）
- **类型**：peer-reviewed 会议论文 + ePrint preprint。
- **贡献（摘要原文）**：首个更新总是与变更数成正比的可更新 matrix lookup argument；RogueDB 支持 authenticated indexes、prover 时间对数据库次线性；较 vSQL / PoneglyphDB 加速（作者声称）。
- **实际构造**：矩阵 lookup argument、动态更新、认证索引。
- **作者限制**：摘要未声称解决 root authenticity / freshness / 授权绑定。
- **重叠**：**动态更新本身已被推进到高效率，不能再作为创新点**；与本候选的新鲜度「独立锚」问题不同。

### A6 ZkChainDB（IEEE ICBC 2026）
- **类型**：peer-reviewed 会议论文。DOI `10.1109/ICBC67748.2026.11575456`。
- **贡献（摘要）**：链上/链下混合架构的模板化可验证 SQL 引擎，原始数据链下、完整性链上锚定。
- **实际构造**：摘要未全文，标 `UNVERIFIED`。
- **作者限制**：摘要未声称 Agent 授权绑定或 DO 真实性。
- **重叠**：「数据根链上锚定 + 查询证明」的又一实例，强化 B2/B3 已是公开路线。

## B 组：数据根与认证状态

### B1 AD SoK（NDSS 2026）
- **类型**：peer-reviewed 会议论文（SoK）。作者 Malvai, Falzon, Zitek-Estrada, Meiklejohn, Bonneau。
- **贡献（原文 Appendix C）**：统一五种部署场景；三性质 `Read-write consistency ⇒ History-binding ⇒ Value-binding`；指出 value/history binding 是纯语法性质，不保证读到最新写；no-trusted-source 下 history binding 最合适；trusted source + 签名可升级到 read-write consistency；update proof 隐含变更计数从而支持 rollback detection。
- **开放问题（作者原文）**：把任意 value/history-binding AD 编译成 read-write consistency 的编译器；审计激励；真实审计模型；"There is not yet clear evidence of a large upside for applications deploying authenticated dictionaries."
- **重叠**：**任务包要求「必须证明自己的问题超出这些已有性质」——本轮未能给出超出项**。H3 对应 history binding；H2 对应 read-write/rollback；H6 对应「现实更新是否入账」这一 SoK 明确外置的问题。

### B2 GlassDB（PVLDB 2023）
- **类型**：peer-reviewed 期刊论文。DOI `10.14778/3583140.3583152`。
- **贡献（原文 Definition 1 / §2.2.2）**：可验证账本数据库；Integrity（操作执行正确）+ Append-only（历史不可分叉）；三类威胁模型：单不可信 provider 只能 fork consistency（需 gossip/auditor）、多数可信副本 + BFT、恶意 server + TEE。
- **作者限制**：安全定义不含机密性；单 provider 模型只能检测不能阻止；TEE 假设无漏洞。
- **重叠**：H2/H3 的权威基线；「日志可追加 ≠ 无遗漏」与 D3-11 一致。

## C 组：Agent 执行可信性近邻

### C1 I-EIB（IIETA / Acadlore 2026）
- **类型**：peer-reviewed 期刊论文。
- **贡献（原文）**：TEE 隔离 + 能力封装 + 签名 provenance chain + 有界步骤遗漏检测；三条 invariant；构造式定理「在定义边界内违反策略的执行不能发生」。
- **作者限制**：*"construction-based rather than a fully mechanized proof ... not universal formal completeness"*；100% step-omission 检出是**有界**攻击；依赖 TEE 可用性、策略精度、wrapper 管理。
- **重叠**：不解决外部数据真伪；用户任务包已指出「TEE 做可信记录不能直接当新贡献」，原文支持这一收窄。

### C2 TRACE（IEEE Access 2026）
- **类型**：peer-reviewed 期刊论文（摘要经 IEEE Access 中文转述核对；英文原文 `UNVERIFIED`）。
- **贡献（摘要转述）**：签名策略包、网关调解、独立遥测、确定性触发线、分级遏制、防篡改证据链；1,440 条篡改链全拒。
- **作者限制**：仪器审计发现部分检测/副作用仪器未测到预期结果；边界观察者记录零禁止副作用但硬件截断无法确认；阈值校准与跨平台延迟未解决。
- **消歧**：另有 Linux Foundation / CoSAI 的同名 TRACE 开放规范草案（RATS/EAT/SCITT/SLSA/SPIFFE/EAR 组合，v0.2），非本条。
- **重叠**：再次表明"独立边界遥测"不直接等于"外部结果真实性"。

### C3 Execution-Finality Enforcement（draft-das-...-00, 2026-10-23）
- **类型**：**Internet-Draft（个人提交，Informational，非 RFC，无 IETF 共识）**。
- **贡献（摘要原文）**：源绑定委派、操作描述符、执行时重验、protected consumption、replay prevention、多 sink 效果、uncertain outcome recovery；Finality Sink 区分实际 pending operation 与先前请求批准 / 可复用 bearer credential。
- **作者限制**：*"implementation points and deployment considerations, not a complete interoperable wire protocol or IETF consensus position."*
- **重叠**：与 D3-13/D3-14 的 sink fence 方向相近；本轮不据此主张新贡献。

### C4 PoE（基线复用）
- 见 D3-14-01 `RELATED-WORK.md`：trace completeness 是部署假设；single Gateway scope；ZK EAC open work。

---

## 汇总：与本候选的直接关系

1. **查询正确性 + 数据根认证 + Grant 绑定**三块都有对应公开工作（A2/A3/A4/A5、B1/B2、D3-13 C），且 PoneglyphDB 已把前两块组合。
2. **独立 epoch 最新锚与历史一致性**在 AD SoK / GlassDB 中有形式定义与实现路径，但属外部基础设施。
3. **H6/H7（DO 漏记 / 恶意认证）**在七篇中一致外置；没有一篇声称可由 SNARK 或签名解决。
4. 用户要求「证明自己的问题超出这些已有性质」——本轮审计结论：**未能找到超出项**；详见 `DECISION.md`。
