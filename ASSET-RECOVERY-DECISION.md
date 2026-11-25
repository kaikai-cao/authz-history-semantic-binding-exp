# Research Asset Recovery — 裁决与下一步建议

**阶段**：RESEARCH-ASSET-RECOVERY-01｜日期：2026-11-25
**性质**：资产回收裁决，**不是新审计、不是 GO/NO-GO 立项**。本轮不对任何冻结成果做改动，不重启 D3-08~D3-12。

---

## 1. 直接继承的资产（无需改造即可作为基线）

| 资产 | 继承方式 | 证据等级 |
|---|---|---|
| MVP E2.2 反例 + 三类独立探针 | 作为**首要 adversarial baseline**：任何新机制必须在同一夹具下重放 E2.2 并报告 UER/DR/ASR/PR | SOURCE-VERIFIED + EXPERIMENT-REPORTED |
| MVP P1–P7 性质定义与不可互推表（v0.1 冻结） | 作为性质语言与判定纪律；继续严守"检测≠阻止、结构≠语义" | SOURCE-VERIFIED |
| MVP `verify_proxy_evidence` 9 字段绑定 + IndependentEvidenceGateway | 作为"执行者分离"的工程起点（不是已验证解法） | SOURCE-VERIFIED + TESTED（5 项） |
| MVP D6 外部工具能力契约草案 + durable journal / 进程崩溃恢复 | 作为"执行效果可观测性"的工程基线 | SOURCE-VERIFIED + EXPERIMENT-REPORTED |
| D3-06-C 双事件状态链 + 8 public instances + prove/verify 成本 | 作为状态侧 baseline；复用其证明链结构与 fail-closed 测试纪律 | SOURCE-VERIFIED + EXPERIMENT-REPORTED |
| D3-07-A 锚定顺序（config→QC→time→anti-rollback→binding→Halo2→commit）与 proof-fail-no-commit | 作为组合顺序纪律；锚定仅 host-side 的边界继续保持 | SOURCE-VERIFIED |
| D3-09/10/11/12 的反例库（X1/X2/X5、X2′、X1–X7、H1/H2） | 作为未来实验的 adversarial baseline 集合 | SOURCE-VERIFIED |
| Halo2/Poseidon host 工具链（MVP `zk-v2-host` + Orchard 测量纪律） | 复用构建/测试/成本归因方法；不包装成 Agent 安全贡献 | REPO-VERIFIED + SOURCE-VERIFIED |

---

## 2. 需要改进的资产（有缺口，但值得投入）

| 资产 | 缺口 | 改进方向 | 证据 |
|---|---|---|---|
| MVP 独立 proxy | 5 测试无"proxy 自身作恶"臂；结构同 E2.2 | 新增 proxy 自签自洽虚假 evidence 的攻击臂；引入数据服务侧独立观测 | SOURCE-VERIFIED + INFERENCE |
| MVP Halo2 配额电路 | 固定三动作、未覆盖 16-leaf root / 8 元素 C_statement / 可变 n / schema；未与 Python 信封集成 | 扩展可变 n 与完整 statement 承诺，端到端集成；用 X1/X2/X5 反例检验新增保证 | SOURCE-VERIFIED |
| MVP README 测试数字 | 声称 80（59+11+10），源码 Python 定义 80 + Rust 21，已滞后 | 后续如做工程同步，按实际重跑结果更新（本轮不改） | SOURCE-VERIFIED + INFERENCE |
| P5/P6 字段级缺口（G1/G2） | `RECEIPT_INVALID`/`OUTCOME_UNKNOWN` 缺 grant/receipt/output hash；尾部删除未覆盖（G5） | 补全字段 + 尾部删除检测；不得把"有日志"当审计完整 | SOURCE-VERIFIED |
| D3-07-B G1/G2/G3 | 规格表达 / 外部持久化前提 / 单调性未机器验证 | 另立分支做规格显式化或模型检查（本轮不启动） | SOURCE-VERIFIED |
| D6 外部工具能力契约 | 仅草案（D6.2/D6.3 未实现） | 在隔离实验分支实现四类能力 + 五态 lookup + 延迟可见性 / 幂等过期测试 | SOURCE-VERIFIED |

---

## 3. 暂时不应继续投入的具体方案（写明原因，防改名重立项）

| 方案 | 不投入原因 | 裁决来源 |
|---|---|---|
| "把 Agent 请求/上下文/策略放进 ZKP"作为主要创新 | CVA（FULL-TEXT）已做 Groth16 PoC；MVP 已有 request-bound 工程，二者对象重合 | D3-09/D3-11 + 本轮 §A.5 |
| Proof Memory = IVC + Accumulator + Range 作为独立 ZKP 贡献 | 组合可达但 P1/P2/P3 全 `BLOCKED_WITH_ASSUMPTION`；X2′ 反例成立；差异不来自证明系统 | D3-10 `REJECT_AS_KNOWN_COMPOSITION` |
| 跨组织回执隐私化关联（方向 A 原方案） | H1_FAIL（SCITT `call_digest`/`principal_link` + RFC 9901 覆盖）+ H2_FAIL（equality proof 已知且无锚定不 sound） | D3-12 `REJECT_AS_KNOWN_PROBLEM` |
| 泛化匿名委托/多源授权作为新密码学问题 | RDAC 2011 + 匿名凭证 / 累加器已覆盖 | D3-08 |
| "签名有效 = 事件真实" / "日志可追加 = 无遗漏" 类论证 | 已被 E2.2、NovaFabric TCB、SCITT §11.5 明确证伪 | D3-11 + MVP E2.2 |
| 单纯扩展 Halo2 电路规模作为贡献 | 换证明系统 / 加约束不等于新增可验证性质 | 用户任务包 + D3-10/D3-12 纪律 |

> 以上均为**特定构造 / 特定命题**的排除，不代表"Agent 安全无价值"或"ZKP 无用"。

---

## 4. 最值得优先研究的 1–2 个问题

### 首选：候选 1 — 授权到真实执行效果的绑定（以 E2.2 反例重放为核心）

**选择理由**
1. **有可复现的硬反例**：E2.2 是本地冻结 R3 结果（`UER=1.0`），比文献边界更具体；它直接命中用户的核心问题"获准请求是否就是实际产生外部效果的请求"。
2. **有工程基础而非从零**：独立 proxy（541 行）、D6 能力契约、durable recovery、三类独立探针都已存在，可作为"改进 + 对照实验"的起点。
3. **有明确的待测缺口**：proxy 自身作恶臂缺失；D6 §7 明示 Gateway 回执不是 provider 副作用证明；CVA §4.5 明示 ZK 电路的运行时 structural gap。这三点共同构成"现有方案不能满足、可验证"的性质缺口。
4. **强基线齐备**：MVP 签名基线、PoE 运行时对象、TEE/zkVM/zkAgent、CVA 单次 ZK——足以做构造级比较而不重复 D3-08~D3-12 的文献证伪。
5. **符合用户期待**：用户明确"下一阶段应该逐渐增加构造、实验和性能比较的比重"，而候选 1 是唯一已有完整实验夹具可直接进入增量实验的方向。

**尚未解决的疑问（进入下一阶段前必须先回答）**
- **Q1**：独立观测的信任基从哪来？数据服务侧回执 / 权威状态查询 / TEE / zkTLS——哪一种在目标场景可得？未回答前不能选具体构造。
- **Q2**：proxy 自身作恶臂下，9 字段绑定是否仍退化为"自洽虚假声明"？这是判断"是否只是换了可信执行者"的关键实验，必须先做。
- **Q3**：若引入 ZKP，新增性质是"隐私化验证"还是仅"把签名比对电路化"？须过 D3-12 H1/H2 教训，避免 private-only 自洽。
- **Q4**：E2.2 的反例是否能在非 mock 工具（只读 SQLite 之外）复现？D6 §8 明确当前不验证生产外部工具。

### 次选：候选 2 — 多步执行中的动态策略约束（以 X1/X2/X5 反例重放为核心）

**选择理由**
MVP 三动作 Halo2 电路 + D3-06-C 双事件链 + v0.2 规格 + X1/X2/X5 反例已构成完整链条；若候选 1 的 Q1/Q2 受阻，可先在此方向做"可变 n + 完整 statement 承诺 + 反例检验"的增量。

**尚未解决的疑问**
- **Q5**：扩展后的电路相对三动作版本 / D3-06-C，究竟新增什么可验证性质？若只是规格实现完，不构成研究问题。
- **Q6**：与 Python 授权信封集成后，public inputs 语义是否仍与冻结的 8 instance 顺序一致？
- **Q7**：策略更新 / 撤销对**已生成历史证明**的影响如何界定？（D3-10 P3-forward vs P3-retro 已给出区分，需沿用）

---

## 5. 仍存在的证据缺口（本轮无法关闭）

| 缺口 | 状态 | 影响 |
|---|---|---|
| MVP 当前测试通过数 | `UNVERIFIED`（本轮未跑；README 数字与源码计数不一致） | 下一阶段如需引用测试数，须先重跑并记录时点 |
| Orchard / Sapling / SRS / DeepProve 具体文档内容 | `UNVERIFIED`（仅核 HEAD/分支/目录） | 不影响本轮结论；若要用其测量数据需另读原文 |
| zkAgent 全文（PDF Cloudflare 拦截） | `ABSTRACT-ONLY`+缓存片段 | 候选 1 若依赖 zkTLS/zkVM 观察绑定，须先取全文或明确标注未核 |
| Agent-Sentry 正式出处（用户所述 IJIS 卷期） | `UNVERIFIED`（正式标题为 arXiv:2603.22868） | 不作为本轮证据；仅说明 provenance 启发式非密码学 |
| 用户给出的 "Authenticated Delegation" PDF | `UNVERIFIED`（`images.openai.com` 静态链接，无书目信息） | 不引用，待用户提供正式出处 |
| proxy 自身作恶实验结果 | `OPEN`（无此测试臂） | 候选 1 的第一实验目标 |
| D6 外部能力契约实现 | `OPEN`（仅草案） | 候选 1 的 Q1 前提 |

---

## 6. 本轮结束状态

- 四份文档完成：`ASSET-INVENTORY.md`、`PROPERTY-MATRIX.md`、`RESEARCH-OPPORTUNITIES.md`、`ASSET-RECOVERY-DECISION.md`。
- 本轮**未**修改任何既有仓库，未写新电路、未跑新实验、未启动候选 1/2 的实施。
- 提交、推送、远端 SHA 核验状态见汇报（本文件落盘后执行）。
- **停止点**：本轮完成后立即停止，等待从候选 1 / 候选 2 中选一个，另立任务包再进入构造与实验阶段。
