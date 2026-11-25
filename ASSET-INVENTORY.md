# Research Asset Recovery — 资产盘点清单

**阶段**：RESEARCH-ASSET-RECOVERY-01
**日期**：2026-11-25
**性质**：只读盘点。本轮未修改任何既有仓库、未跑新实验、未写新电路。
**证据等级口径**：
- `SOURCE-VERIFIED`：已读原始源码并定位到具体符号 / 行号；
- `REPO-VERIFIED`：已核对仓库 HEAD / 分支 / commit / tag / 工作区状态；
- `EXPERIMENT-REPORTED`：已有实验报告数字，本轮**未重跑**；
- `INFERENCE`：基于以上证据的推论；
- `UNVERIFIED`：尚未核实（明确列出，不当事实用）。

---

## 0. 仓库与版本快照（REPO-VERIFIED）

| 资产 | 本地路径 | 当前分支 / HEAD | 工作区 | 远端 / tag |
|---|---|---|---|---|
| Agent Exec Binding MVP | `D:\Research\agent-exec-binding-mvp` | `experiment/independent-execution-proxy` @ `e327a944` | clean（0 dirty） | `kaikai-cao/agent-exec-binding-mvp`；提交链：`610b280`→`f304857`→`3f47481`→`e327a944` |
| 授权状态信任链主仓库 | `D:\Research\authz-history-semantic-binding-exp` | `exp-d3-07-a-r1-config-hardening` @ `89caad7a` | clean | 远端 `kaikai-cao/authz-history-semantic-binding-exp.git`；25 个 `exp-d3-*` tag（D3-06-C=`exp-d3-06-c-two-event-ir-transition`，D3-07-A=`exp-d3-07-a-external-anchor-freshness`） |
| D3-07-B 协议审计 | `D:\Research\d3-07-b-protocol-audit` | `exp-d3-07-b-binding-clarification-01` @ `a8c552d9` | clean | orphan 单根 + 独立分支；8 份文档 |
| D3-08 | `D:\Research\d3-08-crypto-gap-audit` | 非 git 目录 | — | 3 份文档 |
| D3-09 | `D:\Research\d3-09-agent-trace-proof-audit` | 非 git 目录 | — | 6 份文档 |
| D3-10 | `D:\Research\d3-10-proof-memory-falsification` | 非 git 目录 | — | 7 份文档（含 `D3-10-CLOSURE.md`） |
| D3-11 | `D:\Research\d3-11-agent-execution-evidence-audit` | `exp-d3-11-execution-evidence-audit` @ `61e9cd10` | clean | 远端一致（已核） |
| D3-12 | `D:\Research\d3-12-private-cross-org-binding-audit` | `exp-d3-12-private-cross-org-binding-audit` @ `35f13e4b` | clean | 远端一致（已核） |
| Orchard 工程 | `D:\Research\zcash-orchard-engineering` | `main` @ `d291c49` | 未核 dirty | 本地 |
| Sapling 工程 | `D:\Research\zcash-sapling-engineering` | `security/sensitive-path-guard-20261110` @ `46b907f` | 未核 dirty | 本地 |
| SRS 优化 | `D:\Research\srs-optimization` | `experiment/m5-attribution` @ `d35b612` | 未核 dirty | 本地 |
| DeepProve 顺序性 | `D:\Research\deep-prove-eos-sequentiality` | `exp-01-b3-eos-witness` @ `b10730a` | 未核 dirty | 本地 |

> 注：本轮只盘点与 Agent 安全相关的部分；Orchard / Sapling / SRS / DeepProve 的 dirty 状态未逐一核（标记 `UNVERIFIED`），因本轮不修改也不在这些仓操作。

---

## A. Agent Exec Binding MVP（SOURCE-VERIFIED + REPO-VERIFIED）

### A.1 代码资产（均定位到符号）

| 文件 | 行数 | 关键符号 | 实现内容 | 证据 |
|---|---|---|---|---|
| `agent_exec_binding.py` | 715 | `ExecutionContext` L99、`Policy` L113、`SignedGrant` L193、`SignedReceipt` L206、`AuditChain` L282、`ToolGateway` L375 | Ed25519 请求绑定授权、入口快照、nonce/expiry/schema、工具签名回执、签名哈希链审计、四态终局 | SOURCE-VERIFIED |
| `data_access.py` | 581 | data-query-v2-poseidon host | Poseidon 编码、plan tree、quota/statement commitment、public input 编码（host 参考实现，非电路约束） | SOURCE-VERIFIED（符号级）；REPO-VERIFIED（文件存在） |
| `plan_batch.py` | 481 | `PlannedAction` L65、`PlanPolicy` L190、`PlanGrant` L206、`PlanAuthority` L237、`PlanExecutionGateway` L382 | 有序计划 Merkle root 签名、逐步 inclusion proof、nullifier、计划级批量授权（**非 ZKP**，预算由可信 authority 检查） | SOURCE-VERIFIED |
| `independent_execution_proxy.py` | 541 | `_verify_issuer_grant` L54、`_execute_owned_query` L124、`verify_proxy_evidence` L457、`IndependentEvidenceGateway` L512 | 独立进程执行查询并签 evidence；Gateway pin proxy 公钥后验签并绑定 grant/request/context/query/output | SOURCE-VERIFIED |
| `zk-v2-host/src/quota_circuit.rs` | 593 | `QuotaCircuit`、`MockProver` L493 | 固定三动作配额子关系 Halo2 电路（budget/limit/max_rows 范围 + 承诺一致 + 求和≤预算） | SOURCE-VERIFIED |
| `zk-v2-host/src/lib.rs` | 617 | host 函数 | Poseidon action 编码、plan tree、commitment、public input | SOURCE-VERIFIED |

### A.2 测试资产（源码计数，本轮未执行）

| 范围 | `def test_` 计数 | 说明 | 证据 |
|---|---|---|---|
| `tests/test_agent_exec_binding.py` | 40 | 含 E1.1–E1.3、E2.0–E2.2、快照 TOCTOU、并发变异反证 | SOURCE-VERIFIED |
| `tests/test_data_access.py` | 21 | host 数据访问 | SOURCE-VERIFIED |
| `tests/test_plan_batch.py` | 14 | 计划级绑定 | SOURCE-VERIFIED |
| `tests/test_independent_execution_proxy.py` | 5 | 诚实查询 / adapter 篡改 / 重放 / 输出替换 / 并发 | SOURCE-VERIFIED |
| Rust (`#[test]` grep) | 21 | host 11 + quota circuit 10（README 口径） | SOURCE-VERIFIED（计数）；README 分布为 `EXPERIMENT-REPORTED` |

- README 声称 **80 passing**（59 Python + 11 Rust host + 10 Halo2）；源码当前 Python 定义合计 80、Rust 21 → **README 数字已滞后于新提交**（`3f47481`/`e327a944` 增加 proxy 与 durable 测试）。本轮未跑测试，**不声称当前通过数**。证据：`EXPERIMENT-REPORTED` + `INFERENCE`。

### A.3 形式化与实验资产

| 资产 | 内容 | 状态 / 证据 |
|---|---|---|
| `research/security-properties-v0.1.md` | P1–P7 七项性质可操作定义、`Legit(r,c,g,S,t)` 判定式、性质不可互推表（P7⇏P1 等）、结构层/语义层分离 | **v0.1 定稿冻结**；SOURCE-VERIFIED |
| `research/threat-model-v0.1.md` | 攻击者 / 信任边界 / D1–D5 决定、U1（Gateway 不可独立观测 e） | 冻结；REPO-VERIFIED（文件存在） |
| `research/attack-experiment-matrix-v0.1.md` | ASR/PR/DR 三率定义、A/B/C/D 互斥分类 | 冻结；SOURCE-VERIFIED（经 e-stage 引用） |
| `research/e1-results-v0.1.md` / `e-stage-results-v0.1.md` | E1 四组 ASR=0/PR=1；E2.0 控制 10/10；**E2.1 ASR=1,PR=0,DR=1**；**E2.2 ASR=1,PR=0,DR=0,UER=1** | **冻结 R3 结果**；EXPERIMENT-REPORTED（本轮未重跑） |
| `_staging/e486-d1/D4_RECOVERY_VALIDATION.md` / `D5_...` / `D6_EXTERNAL_TOOL_SEMANTICS.md` | durable journal + SQLite 预算 + 进程崩溃恢复 2/2；外部工具四类能力契约草案（幂等键 / 权威状态查询 / INDETERMINATE） | SOURCE-VERIFIED（文档）；测试数 `EXPERIMENT-REPORTED` |
| `docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md` | 完整 v0.2 关系规格（含 16-leaf plan root、8 元素 `C_statement`、可变 n、schema 兼容） | SOURCE-VERIFIED；**规格，非已实现电路** |

### A.4 MVP 的关键结论资产（EXPERIMENT-REPORTED + INFERENCE）

> **E2.2 核心结论**：合法密钥持有者（Adapter）用自洽虚假 Receipt 使 Gateway 接受实际越权结果，`UER=1.0`、`DR=0`、`ASR=1`、`PR=0`；`AuditChain.verify()` 10/10 通过但语义错误。
> 推论（INFERENCE）：这把 D3-11 的"签名有效≠事件真实"和 D3-12 的 private-only 陷阱**在 MVP 内具体复现**——但复现位置在工具执行边界，而非跨组织回执层。

### A.5 与 CVA 的重合 / 差异（INFERENCE；CVA 为 FULL-TEXT，见 §E）

- 重合：两者都做 request / principal / context / policy 绑定的单次证明关系；CVA Groth16 PoC 531 约束，MVP Python Ed25519 + 独立 Halo2 配额电路。
- 差异：**MVP 有 CVA 明确列为 structural gap 的运行时执行侧实验**（E2.0/E2.1/E2.2 独立探针 + adapter deviation），而 CVA §4.5 自承 ZK 电路证明时无运行时状态访问权；MVP 另有 durable recovery 与独立 proxy 工程。MVP 的弱点恰是 CVA 的强项：无密码学隐私绑定（P5 结构/语义分离仍 OPEN）。
- 不可声称：MVP 未解决 CVA 的 runtime binding，只是**提供了可复现的反例与信任边界定位**。

---

## B. D3-06-C / D3-07-A / D3-07-B（SOURCE-VERIFIED + REPO-VERIFIED + EXPERIMENT-REPORTED）

### B.1 D3-06-C：双事件 IR-bound Halo2 状态链

| 项 | 内容 | 证据 |
|---|---|---|
| 电路 | `src/transition/d3_06_c_{constants,types,circuit}.rs`；`event_count=2`；8 个 public instance（顺序 `C_prev,prev_epoch,C_next,next_epoch,policy_id,transition_version,D_E,event_count`）；`gr_in[1]=gr_out[0]` 等根 cell 直连 | SOURCE-VERIFIED |
| 测试 | Mock 31/31；N01–N28 由电路/复制约束拒绝（非 host 前置）；GG/GR/RR 真证明生成并 verify；翻转 8 个 public 值均失败 | EXPERIMENT-REPORTED (`EXP-D3-06-C-SUMMARY.md`) |
| 成本 | K=16；prove 35.1–35.3s（GG 35311ms / GR 35215ms / RR 35199ms）；proof 7072B；对照 E-R1 K=15 / 20620–20662ms / 8160B | EXPERIMENT-REPORTED；**明确不宣称性能优势** |
| 安全假设 | ID 域 `F\{0}`、IR depth 4 / 16 slots、E-R1 revoker 假设、IR state 由受约束常量 mux、low4 slot 256-bit 分解 | SOURCE-VERIFIED (`EXP-D3-06-C-SUMMARY.md` §9) |
| 明确不证明 | 外部 S0 锚定、签名 / checkpoint、执行时 freshness、形式化 soundness、普遍性能优势 | SOURCE-VERIFIED |

### B.2 D3-07-A：外部锚定 + freshness host trust bridge

| 项 | 内容 | 证据 |
|---|---|---|
| 源码 | `src/anchor/{canonical,types,state,verifier,combined}.rs`；D1 九字段编码 / SHA256 / Ed25519 3-of-4 QC / witness_set_root；`C_prev` 以 64-hex Pallas bytes 入 signed `state_root` | SOURCE-VERIFIED |
| 顺序 | `validate_witness_set_config` → profile check → envelope/QC → time → anti-rollback → instance binding → Halo2 → commit（proof 失败不 commit） | SOURCE-VERIFIED (`EXP-D3-07-A-SUMMARY.md` §6) |
| R1 硬化 | threshold=3 强制、四 witness、`NO_LOG` / `log_size=0`；A29–A36 含 threshold=0 零签名拒；profile 检查先于 QC（A35/A36 勘误） | SOURCE-VERIFIED |
| 测试 / 成本 | release `374 passed / 0 failed / 3 ignored`；Halo2 proof verify 838.41ms；envelope/QC/canonical/proof = 1121B/609B/560B/7072B | EXPERIMENT-REPORTED |
| 明确不证明 | S0 全局最新；anchor 仅在 host 侧（无电路内 anchor proof）；time validity ≠ global freshness；D1 witness 持久锁不检查 | SOURCE-VERIFIED |
| 可复用 | 配置先于 QC 的 fail-closed 顺序、epoch 作 sequence、本地 JSON 原子 high-water 防回滚、proof-fail-no-commit 组合顺序 | INFERENCE（可作后续 baseline 设计纪律） |

### B.3 D3-07-B：多 Witness 协议模型（结构证据 + 规则层论证）

| 项 | 内容 | 证据 |
|---|---|---|
| P1 状态机 | Model B：`locked_round < polc_round < current_round`；`current_round` 仅 `timeout_advance()` 推进；`can_sign()` 只读；49 场景 / 19 unittest（P1-R1-C1） | SOURCE-VERIFIED / EXPERIMENT-REPORTED |
| P2 设计 | 七状态、四层纪律（收到≠接受≠PoLC≠QC≠commit）、八类崩溃、Gateway 7 步 | SOURCE-VERIFIED |
| S-A 安全论证 | 固定较早 QC 锚点 + 相对最小冲突 PoLC；旧鸽巢"≥2 honest"论证作废；结论 `PROOF_SUPPORTED`（带显式模型假设） | SOURCE-VERIFIED |
| Halo2 结论 | `STOP_HALO2_DIRECTION` + `REJECT_PRIVATE_ONLY_BINDING`：§5.1 反例——private `H_evidence` 与预像均可由证明者自造并重算，验证者无法区分 | SOURCE-VERIFIED |
| 阶段状态 | `ACCEPTED_WITH_EXPLICIT_MODEL_ASSUMPTIONS`；G1/G2/G3 未关闭（lock_key 验证清单表达 / 写锁-签名原子性外部持久化 / `locked_round` 单调未机器验证） | SOURCE-VERIFIED (`EXP-D3-07-B-CLOSURE.md`) |
| 可复用 | 规则层安全论证的"四层纪律 + 显式假设"写作范式、private-only 反例结构 | INFERENCE |

---

## C. D3-08 ~ D3-12 审计结论资产（SOURCE-VERIFIED）

| 阶段 | 最终裁决 | 可复用资产（类型） | 不是 |
|---|---|---|---|
| D3-08 | `REJECT_AS_KNOWN_PROBLEM` | 匿名可委托凭证已知能力清单（AgentCap/DelegateGuard/RDAC/累加器） | 非"Agent 授权无价值" |
| D3-09 | `CONDITIONAL_HOLD`（B 推荐） | 三层次区分（执行忠实 / 授权合规 / 执行一致）；X1/X2/X5；NoCert OP4/5/6 原文开放问题 | 非"已证 B 有创新" |
| D3-10 | `REJECT_AS_KNOWN_COMPOSITION` + `D3-10-CLOSED` | **X2′ 反例**：10 次调用第 7 次违规，提交 9 次 + 正确递归证明，验证者无法知道第 7 次发生过；P1/P2/P3 vs A/B/C 构造表 | 非"递归证明无用"；仅"连续状态转换 ≠ 外部历史完整" |
| D3-11 | `CONDITIONAL_HOLD`（方向 A，后被 D3-12 证伪） | E1–E4 形式化；X1–X7；"签名≠事件真实"、"日志可追加≠无遗漏"；SCITT PASS 边界 | 非"跨组织证据无价值" |
| D3-12 | `REJECT_AS_KNOWN_PROBLEM` | H1/H2 判定链；`principal_link`=双方 token 摘要已覆盖隐藏关联；equality proof=CP93 已知且无外部锚定不 sound | 非"隐私验证无需求"；仅"方向 A 特定构造失败" |

**可作为未来实验 adversarial baseline 的反例（INFERENCE，均可直接复用）**：
1. **E2.2 自洽虚假 Receipt**（MVP，R3）——执行者用合法密钥对真实越权执行作不真实声明；
2. **X2′ 轨迹遗漏**（D3-10）——提交合法子序列 + 正确递归证明；
3. **X1 累计超限**（D3-09/10）——各步合法、累计超限；
4. **X2 历史裁剪 / X5 策略漂移**（D3-09）——删超限步 / 旧证明绕过；
5. **H2-A private-only 自造**（D3-12 / D3-07-B §5.1）——证明者自造全部私有输入并重算公开值。

---

## D. Orchard / Halo2 / Sapling 工程积累（仅盘点与 Agent 安全相关部分）

| 资产 | 可迁移内容 | 边界（不得包装） | 证据 |
|---|---|---|---|
| `zcash-orchard-engineering`（`main`@`d291c49`） | `docs/orchard/01`–`27`：circuit instance / configure / synthesize / cost map / create-proof timing / CPU sampling / 21 constraint recon / F4A cross-circuit recon 等；**预注册 → 实施 → 资源校验**的实验纪律 | 这些是 Orchard 电路优化，不是 Agent 安全贡献；只迁移方法与测量纪律 | REPO-VERIFIED（目录/文件）；内容细节 `UNVERIFIED`（本轮未逐篇读） |
| `zcash-sapling-engineering`（`security/sensitive-path-guard-20261110`@`46b907f`） | 敏感路径 guard 分支存在（与安全路径守护相关） | 分支名不等于已验证的 Agent 安全机制 | REPO-VERIFIED；内容 `UNVERIFIED` |
| `srs-optimization`（`experiment/m5-attribution`@`d35b612`） | M5 归因实验方法 | SRS 优化 ≠ Agent 系统性能 | REPO-VERIFIED |
| `deep-prove-eos-sequentiality`（`exp-01-b3-eos-witness`@`b10730a`） | B3 NO_WITNESS_WITHIN_BUDGET 的顺序性实验边界 | 与 Agent 执行顺序性无直接证明关系 | REPO-VERIFIED（读自 MEMORY/目录） |
| MVP `zk-v2-host` | Poseidon 编码、承诺、public input 编码的**已跑通 host 工具链**（cargo test --locked） | 只覆盖固定三动作配额子关系；完整 v0.2 未实现 | SOURCE-VERIFIED |

---

## E. 相关工作元数据核对（复用 D3-09/D3-11 已核；新增一项已核）

| 工作 | 准确题目 / 出处 / 版本 | 证据等级 | 与资产的关系 |
|---|---|---|---|
| CVA | *Cryptographically Verifiable Authorization for Autonomous AI Agents: A Falsifiable Hypothesis and Proof of Concept*，Front. Comput. Sci. 2026-09-23, Vol.8, DOI 10.3389/fcomp.2026.1966725，Llambí-Morillas & Fernández-Fernández | `FULL-TEXT`（D3-09） | 与 MVP 对象最接近；runtime execution binding 为其 structural gap |
| zkAgent | *zkAgent: Verifiable LLM Agent Execution via One-Shot Transcript Proofs*，ePrint 2026/199 + CCS 2026 DOI 10.1145/3830454.3846564，Wang/Lou/Li/Yu/Hu | `ABSTRACT-ONLY`+缓存片段（D3-09；PDF 被 Cloudflare 拦截） | 证执行忠实 + zkTLS/zkVM 工具观察；不碰授权合规 |
| No Certificate | *No Certificate, No Execution: Certified Traces as a Foundation for Trustworthy AI Agents*，arXiv:2605.24462，Liu/Yang/Wang/Capponi | `FULL-TEXT`（D3-09） | OP4/5/6 开放问题；"framework, not a completed stack" |
| PoE | *Proof of Execution: Runtime Verification for Governed AI Agent Actions*，arXiv:2607.05397，Rhodes & Kang | `FULL-TEXT`（D3-09） | 签名+哈希运行时对象；明文 trace + 单 Gateway（MVP 的普通密码学基线） |
| SCITT AEE | *Agent Execution Evidence: A SCITT Profile for Verifiable Records of AI Agent Runs*，`draft-thaha-scitt-agent-execution-evidence-02`，2026-11，Standards Track **Internet-Draft（非 RFC）** | `FULL-TEXT`（D3-11） | §9.2 PASS 边界；§10 `call_digest`/`principal_link`；§14 Harness completeness 开放 |
| SCITT Profile | *AI Agent Execution Profile of SCITT*，`draft-emirdag-scitt-ai-agent-execution-01`，2026-10，Informational **Internet-Draft（非 RFC）** | `FULL-TEXT`（D3-11） | "An action that was never recorded leaves no gap"；custodian/collusion |
| Agent-Sentry（新增核对） | *Agent-Sentry: Bounding LLM Agents via Execution Provenance*，arXiv:2603.22868，Sequeira/Damianakis/Iqbal/Psounis（USC/WUSTL） | `ABSTRACT-ONLY`+二级摘要（本轮 WebSearch；**未取全文**） | 运行时启发式防御（provenance 图 + allowlist + LLM judge，blocking >90%），非密码学；其 mimicry attack 弱点说明 provenance 本身不足以绑定执行真实性。用户所述"IJIS 综述"标题与本正式标题不符，期刊卷期 `UNVERIFIED` |
| Authenticated Delegation（用户链接） | 用户给出的是 `images.openai.com` 静态 PDF 链接，未能核对正式书目信息 | `UNVERIFIED` | 不作为本轮证据，仅登记待核 |

---

## F. 盘点结论（INFERENCE）

1. **本轮最重要的可继承资产不是某个 ZK 电路，而是 E2.2 反例 + 独立探针测量方法**：它把"签名有效≠事件真实"从文献边界变成可复现、可计数的本地实验（`UER=1.0`），并给出三类来源分离的观测（探针 / receipt / gateway）。
2. **MVP 的独立 proxy 是尚未验证的改进方向**：它把执行者从 Adapter 移到独立进程，但 5 个测试**不含 proxy 自身作恶臂**；按 E2.2 方法重做攻击，proxy 仍可用合法密钥签自洽虚假 evidence。这是"已有工程基础 + 明确待测缺口"的组合。
3. **D3-06-C + D3-07-A 提供可复用的状态链与锚定纪律，但都明确不覆盖执行真实性**：二者可作为"状态侧 baseline"，与 MVP 的"执行侧缺口"拼接，不是现成解法。
4. **D3-08~D3-12 排除的是特定构造与泛化命题，其 X1–X5 / X2′ / H1-H2 反例是现成 adversarial baseline**；把这些反例重放到 MVP 增强机制上，比重新做文献证伪更有价值。
5. **工程积累（Orchard/Sapling/SRS/DeepProve）只迁移测量纪律与工具链**（预注册、成本归因、Poseidon/host 编码）；不得写成 Agent 安全贡献。
