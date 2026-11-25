# Research Asset Recovery — 可继续研究的问题

**阶段**：RESEARCH-ASSET-RECOVERY-01｜日期：2026-11-25
**原则**：不因相关工作存在就直接否决候选；每项都给出强基线、可验证指标与主要风险。本文件是**候选问题清单，不是立项裁决**；立项裁决见 `ASSET-RECOVERY-DECISION.md`。

---

## 候选 1（第一优先）：授权 → 真实执行效果的绑定，以"独立观测 + 反例重放"为核心

**现实场景**
Agent 经 Gateway 获签一个只读数据查询授权（如 `Sales/2026`）；外部 Tool Adapter 实际查询 `Finance/2026` 返回越权数据，并用自己持有的合法工具密钥签一份"看起来合法"的回执（`request_hash` 填获准值、`output_hash` 填真实越权结果）。第三方需判断"实际产生外部效果的请求是否就是获准请求"。

**现有方案**
- MVP 单调用 Gateway：Ed25519 请求绑定 + 入口快照 + receipt 绑定 + 审计链（**E2.2 下失效**）；
- MVP `IndependentExecutionProxy`：独立进程执行 + proxy 签 evidence + Gateway pin 公钥验签（5 测试，无 proxy 作恶臂）；
- PoE：签名 + 哈希 + ECES 运行时可检查对象（明文 trace、单 Gateway 假设）；
- CVA：Groth16 单次 request/policy 绑定，但 runtime execution binding 自承 structural gap；
- zkAgent：证 provider 忠实执行推理 + zkTLS/zkVM 工具观察，不碰授权合规。

**已知不足（证据）**
MVP E2.2（冻结 R3）：`ASR=1, PR=0, DR=0, UER=1`，AuditChain 结构通过但语义错误；D6 §7："Gateway-signed receipt attests to the Gateway's recorded execution result. It is not automatically a provider-signed proof of an external side effect."；CVA §4.5：ZK 电路证明时无运行时状态访问权。

**我们已有的可复用资产**
E2.2 反例与三类独立探针（`actual_query_log`/`actual_result_log`/`gateway_observation`）；`verify_proxy_evidence` 9 字段绑定；D6 外部工具能力契约草案（幂等键 / 权威状态查询 / INDETERMINATE）；durable journal + 进程崩溃恢复测试；D3-07-A 的 proof-fail-no-commit 顺序纪律。

**可能的改进方法（待验证，不预设成立）**
1. 把"执行主体"从 Adapter 分离：proxy 独立进程 + 数据访问层可信观测（例如由数据服务本身签发"实际过滤条件"回执），使 `query_hash` 不再来自被验证方自报；
2. 用权威状态查询（D6 类 C）替代 receipt 自证：Gateway 向工具服务查询 operation_id 的权威状态，绑定原始 request_digest；
3. 对"获准请求 = 实际请求"给出**可验证关系**而非仅声明比对：若需要隐私，考察 zkTLS/zkVM 观察绑定的适用边界（zkAgent 已有构造，须先查清它证明的是"忠实执行"还是"合规"）。

**强基线**
- 普通签名 + Gateway（MVP 现状，E2.2 已证失败）；
- TEE / 远程证明（NovaFabric TCB 反例：key custodian 可签假断言，下游验证检不出）；
- zkVM / zkAgent（证执行忠实，不直接给授权合规）；
- CVA 单次 ZK 绑定（structural gap）。

**可验证的实验指标**
- 在**同一 E2.2 夹具**下重放攻击，比较 `UER`、`DR`、`ASR`、`PR`（禁止合并）；
- 新增"proxy / 观测者自身作恶"臂：观测者用合法密钥签自洽虚假 evidence 时，`UER` 是否仍为 1；
- 独立探针与实际查询的一致性（comparison_events / scanned_rows）；
- 若引入密码学：prove/verify 时间、proof 大小、电路约束数、多余信任假设数量。

**主要风险**
- **最大风险**：只是"又换了一个可信执行者"（Adapter → proxy → TEE），E2.2 结构原样重现；必须新增观测者作恶臂才有效。
- 权威状态查询依赖工具服务真实实现，D6 明确其能力声明是"trusted configuration claim"，不是被证明的事实。
- zkVM/zkTLS 成本与可集成性未知（`NOT_MEASURED`）；不得声称性能优势。
- 不能声称"解决执行真实性"——D3-11 已明确缺口在信任边界。

---

## 候选 2（第二优先）：多步执行中的动态策略约束（累计预算 + 状态转换 + 隐私保护）

**现实场景**
Agent 执行多步数据访问计划（3 步示例已实现），每步读取行数受 per-action limit 约束、总读取行数受 aggregate budget 约束；验证者需确认"整个计划合规"，但不应看到每步具体行数或计划细节。策略在执行中可更新（预算变更 / 撤销）。

**现有方案**
- MVP plan_batch：有序计划 Merkle root 签名 + 逐步 inclusion proof + nullifier（**非 ZKP**，预算由可信 authority 检查）；
- MVP Halo2 三动作配额电路：Poseidon 承诺 + 范围 + ∑max_rows ≤ budget（**固定三动作、未与 Python 信封集成**）；
- D3-06-C：双事件 IR-bound Halo2 状态链（GG/GR/RR，K=16）；
- D3-10：IVC + Accumulator + Range 组合分析（P1/P2/P3 全 `BLOCKED_WITH_ASSUMPTION`）。

**已知不足（证据）**
D3-10：`REJECT_AS_KNOWN_COMPOSITION`——组合能达成但依赖外部假设（成本来源、日志完整性、新鲜撤销状态）；X1（各步合法累计超限）、X2（历史裁剪）、X5（策略漂移）反例有效；每步资源量在工具边界的真实性（`A_cost`）属候选 1 的 structural gap；完整 v0.2 关系（16-leaf root / 8 元素 C_statement / 可变 n / schema 兼容）仅规格未实现。

**我们已有的可复用资产**
MVP `zk-v2-host` Poseidon / plan tree / commitment / public-input 编码（cargo test --locked 已跑通）；Halo2 三动作电路与 MockProver 测试；D3-06-C 双事件状态链（可作为多步扩展起点）；D3-07-A 锚定与 epoch 纪律；D3-09 X1/X2/X5 反例。

**可能的改进方法**
1. 把三动作电路扩展到可变 n（含 inactive slots）与完整 statement commitment，并与 Python 授权信封集成；
2. 与 D3-06-C 状态链拼接：每步配额状态进入 IR / GR / RR 状态，用状态根承接；
3. 用反例驱动验证：把 X1/X2/X5 重放到增强电路，检验是否真正降低（而不是转移）攻击面；
4. 隐私增量若要做，须先过 D3-12 的 H1/H2 教训——公开锚点必须来自已签对象，不能 private-only 自洽。

**强基线**
- 可信 authority 检查 + 签名（MVP plan_batch，已实现）；
- Bulletproofs 聚合范围证明（隐藏 counter 无密码学困难，D3-10 已核）；
- IVC + Accumulator + Range（D3-10 已裁，无独立贡献）；
- 完整 v0.2 规格本身（若只是把规格写完，不算新研究）。

**可验证的实验指标**
- 约束数、K、prove/verify 时间、proof 大小 vs 三动作电路 / E-R1 / D3-06-C（**不宣称性能优势**）；
- X1/X2/X5 在增强前后的检出率；
- 可变 n 下 inactive slot 正确性与复制约束通过率；
- 与 Python 信封集成后端到端 verify 成功率。

**主要风险**
- 很容易退化成"把规格实现完"的工程任务，而非研究问题；必须先明确新增的可验证性质（例如"可变 n + 已签 statement 承诺"是否给出新保证）。
- D3-10 已证组合层面无独立贡献；增量必须落在**MVP 已有工程 + 真实反例**，不是重做组合分析。
- 与 D3-07-A 拼接时须保持 public instance 顺序与 fail-closed 纪律，否则破坏已冻结基线。

---

## 候选 3（继续观察）：跨组织执行证据的隐私验证——不重复 H1 失败方案

**现实场景**
多组织工具回执（SCITT AEE / Profile）下，第三方审计者需验证合规但不看完整轨迹 / 身份关联。

**现有方案与证据**
D3-11 `CONDITIONAL_HOLD`、D3-12 `REJECT_AS_KNOWN_PROBLEM`：SCITT `call_digest` = 双方对同一请求表示计算的摘要、`principal_link` = 双方共有 token 的摘要，已实现"不集中披露建立可验证关联"；RFC 9901 SD-JWT 为更低成本选择性披露；H1/H2 双失败。

**已知不足**
D3-12 明确：失败原因是"关联内核已覆盖 + 谓词证明空间被验签循环封死 + equality proof 已知且无锚定不成立 + freshness/completeness 全外包"；这是**特定构造证伪**，不是"隐私需求不存在"。

**可复用资产**
D3-11 E1–E4 形式化、X1–X7 攻击分类、SCITT §9.2/§10/§11 FULL-TEXT 证据、D3-12 H1/H2 失败记录（防改名重立项）。

**可能的改进方法（仅观察，不启动）**
只有当出现"审计者完全不可信、且 VDS 已签承诺字段可直接作为公开锚点"的真实场景证据时才重估；否则不投 ZKP。

**强基线**：SCITT 明文 + 访问控制；SD-JWT / BBS；equality proof + VDS 锚定。
**可验证指标**：若重估，须给出 H1（明文+访问控制+简单密码学不够）与 H2（公开锚点来自外部已签对象）同时成立的证据。
**主要风险**：换名字重立项（D3-12 已写死失败原因）；本轮建议**继续观察，不投入**。

---

## 候选 4（储备）：Agent 执行事件的"可信采集"而非"证明系统创新"

**现实场景**
D3-10 X2′：10 次调用第 7 次违规，提交 9 次链 + 正确递归证明，验证者无法知道第 7 次发生过。缺口不是证明系统，而是"真实事件在产生时是否进入可验证过程"。

**现有方案**：SCITT Harness 回执 + admission receipt + 远程证明（§14 明确 Harness completeness 未定义）；NovaFabric capture（completeness 0.652±0.064，自报）；Actions with Receipts（Runner / Observation Logger 执行期可信）。

**已知不足**：D3-11 两条核心边界——签名有效≠事件真实、日志可追加≠无遗漏；X1–X7 无一由纯密码学 BLOCKED。

**可复用资产**：X2′ 反例、D3-11 威胁模型（七参与方 / 六类攻击）、D6 外部工具能力契约、MVP durable execution journal。

**可能的改进方法**：从"工具边界可信采集"出发（谁产生第一份不可否认的事件证据），考察 TEE / 远程证明 / zkTLS 观察的**具体信任基**，而不是再设计证明关系；若有真实场景证据再评估密码学增量。

**强基线**：SCITT + 远程证明；NovaFabric；PoE；TEE 远程证明（注意 NovaFabric TCB 反例）。
**可验证指标**：事件遗漏检出率（相对独立观测）；capture completeness；跨组织观测一致性。
**主要风险**：这是外部信任基问题，不是 ZKP 证明关系创新（用户已多次确认此边界）；若立项需明确"非 ZKP 创新"的定位。

---

## 候选 5（工程储备）：协议规格显式化与机器验证（G1/G2/G3）

**现实场景**
D3-07-B 审计留下 G1（PoLC 验证清单未显式 lock_key 绑定）、G2（写锁-签名原子性依赖具体存储实现）、G3（`locked_round` 单调性未机器验证）。

**现有方案**：P1 状态机模拟 + P2 设计文档 + S-A 规则层论证（`PROOF_SUPPORTED`，带显式假设）。

**已知不足**：G1/G2/G3 是规格表达与外部实现前提，不是密码学缺口；P1 是确定性模拟非形式化验证。

**可复用资产**：D3-07-B P1 状态机（49 场景 / 19 unittest）、S-A 论证、四层纪律、G1/G2/G3 清单。

**可能的改进方法**：用模型检查 / TLA+ 显式化 G3 单调性；用具体存储实现验证 G2 的原子原语；补全 G1 验证清单。

**强基线**：现有书面规则 + 单元测试（已是 `PROOF_SUPPORTED` 规则层）。
**可验证指标**：机器验证覆盖的定理数；反例检出数；存储实现下的原子性测试通过率。
**主要风险**：这是协议工程，不是 ZKP 研究；且修改 D3-07-B 冻结成果需另立分支，本轮不启动。

---

## 优先级建议（供裁决参考，非本轮决定）

| 优先 | 候选 | 理由 |
|---|---|---|
| 1 | 候选 1（授权→真实执行效果 + 反例重放） | 唯一同时具备"可复现反例（E2.2）+ 已有工程（proxy / D6 / durable）+ 明确待测缺口（proxy 作恶臂）"的方向；直接回应用户"证明获准请求是否就是产生外部效果的请求" |
| 2 | 候选 2（多步动态约束） | 有现成电路与规格、反例（X1/X2/X5）清晰，但需先界定新增可验证性质以免退化为规格实现 |
| 观察 | 候选 3 | D3-12 刚证伪，不重复 |
| 储备 | 候选 4 | 真实但属外部信任基，非 ZKP 创新 |
| 储备 | 候选 5 | 协议工程，非本研究主线 |
