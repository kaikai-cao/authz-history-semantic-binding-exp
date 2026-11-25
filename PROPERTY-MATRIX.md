# Research Asset Recovery — 安全性质状态矩阵

**阶段**：RESEARCH-ASSET-RECOVERY-01｜日期：2026-11-25
**状态标签（严格区分，不得互换）**：
- `IMPLEMENTED`：源码中存在对应实现路径（SOURCE-VERIFIED）；
- `TESTED`：存在可运行的正向 / 负向测试（SOURCE-VERIFIED，本轮未重跑则注明）；
- `FORMALIZED`：有可操作 / 数学形式化定义（文档级，不等于证明）；
- `EXPERIMENTALLY-EVALUATED`：有冻结实验结果数字（EXPERIMENT-REPORTED，本轮未重跑）；
- `ASSUMPTION-DEPENDENT`：成立依赖明确的外部假设，无该假设则不成立；
- `OPEN`：尚未解决 / 仅规格 / 明确未证明。

> **硬规则**：`TESTED` ≠ `FORMALIZED` ≠ 形式化安全证明；`IMPLEMENTED` ≠ `ASSUMPTION-DEPENDENT` 解除；一个性质可同时有多个标签（例如既 IMPLEMENTED 又 TESTED 又 ASSUMPTION-DEPENDENT），但不得以强标签覆盖弱标签的缺口。

---

## 1. MVP 七项性质（定义来自冻结 `security-properties-v0.1.md`，实测来自 `e-stage-results-v0.1.md`）

| 性质 | 定义 / 状态 | 标签 | 证据与边界 |
|---|---|---|---|
| **P1 授权完整性** | `Execute(r) ⇒ Authorized(r,g)`；授权集合 = `Grant-authorized`（非 `Policy-compliant`） | `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY-EVALUATED`, `ASSUMPTION-DEPENDENT` | E1.1 请求替换 10/10 拒；对 Planner 预防性；**对 Adapter 仅检测**（E2.2 越权仍发生）；排除项 2（Gateway 被攻破）不成立则全失效 |
| **P2 上下文完整性** | `C_verify = C_execute`；入口快照单一来源 | `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY-EVALUATED`, `ASSUMPTION-DEPENDENT` | E1.2 tenant_id 替换 10/10 拒；上下文无独立可信来源（若 Issuer 据伪造上下文签发则不可识别）；G9 无 user 维度 |
| **P3 请求完整性** | `R_execute = R_authorized`；无共享可变状态 | `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY-EVALUATED`, `ASSUMPTION-DEPENDENT` | E2.1 如实偏离时检测（`DR=1`）；**E2.2 自洽虚假 receipt 使 `DR=0`**；对 Adapter 是声明级检测，不是执行级证明（G3/U1） |
| **P4 防重放** | `SuccessfulUses(g) ≤ 1`；实测更强 `ToolInvocations(g) ≤ 1` | `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY-EVALUATED`, `ASSUMPTION-DEPENDENT` | E1.3-a/b 10 组串行 + 10 组阻塞并发，0 额外执行；变异反证（移除 `_nonce_lock`）有区分力；**依赖单进程内存状态 S1**，非 crash-safe / 非跨副本（G4/G6） |
| **P5 审计绑定完整性** | 终态条目关联 ⟨g,r,ρ,output,nonce,decision,t⟩ | `IMPLEMENTED`（部分）, `TESTED`, `OPEN`（字段齐全 / 尾部删除） | `ALLOW_EXECUTED` 完整；`RECEIPT_INVALID`/`OUTCOME_UNKNOWN` 缺 grant/receipt/output hash（G1/G2）；尾部删除未覆盖（G5）；E2.2 中**结构通过、语义错误** |
| **P6 故障可观测性** | 四态互斥且与真实执行一致 | `IMPLEMENTED`（状态级）, `TESTED`, `OPEN`（字段级） | DENY / ALLOW_EXECUTED / OUTCOME_UNKNOWN / RECEIPT_INVALID 四态有独立写入路径；P6-f 缺 receipt_hash；Gateway 崩溃无条目（S1）；**审计记录了攻击 ≠ 攻击被阻止**（ASR=1/PR=0/DR=1） |
| **P7 密码学不可伪造性** | 攻击者无 Issuer 私钥不能造有效 Grant | `IMPLEMENTED`, `TESTED`, `ASSUMPTION-DEPENDENT` | Ed25519 + canonical_json；变异测试（无效签名 / 可变 payload）通过；**这是对 Ed25519 安全假设的引用，非本项目证明**；无密钥轮换 / 吊销 |

**MVP 不可互推关系（FORMALIZED，来自冻结文档 §3）**：
`P7 ⇏ P1`｜`Policy-compliant ⇏ Grant-authorized`｜`P1 ⇏ P2/P3`｜`P4 需要 S1`｜`P5 ⇏ P6`｜`P6 ⇏ P5`｜`P5/P6 ⇏ 阻止`｜`检测 ⇏ 阻止`｜`R2 ⇏ R3`。

---

## 2. MVP 新增 / 规格级资产

| 性质 / 组件 | 标签 | 证据与边界 |
|---|---|---|
| 独立执行证据（`verify_proxy_evidence` + `IndependentEvidenceGateway`） | `IMPLEMENTED`, `TESTED`（5 项）, `ASSUMPTION-DEPENDENT`, `OPEN`（proxy 自身作恶） | 验签 proxy 公钥 + 9 字段绑定（grant/request/context/tool/schema/nonce/query/output/row_count）；测试覆盖 adapter 篡改 / 输出替换 / 重放 / 并发；**无 proxy 自身恶意臂**——若 proxy 用合法密钥签自洽虚假 evidence，结构同 E2.2 |
| Durable 恢复（journal + SQLite 预算 + 进程崩溃） | `IMPLEMENTED`, `TESTED`（2 进程重启测试 `EXPERIMENT-REPORTED`）, `ASSUMPTION-DEPENDENT` | 崩溃点 after_tool_effect / after_receipt_commit 恢复；durable counter=1、journal COMMITTED；**不与任意外部服务原子**（D6 §8），无真实 TPM |
| 外部工具能力契约（D6 草案） | `FORMALIZED`（草案，非实现）, `OPEN` | 四类能力（自然幂等 / 幂等键 / 权威查询 / 无保证）+ 五态 lookup + 恢复规则；D6.2/D6.3 明确为下一步计划，未实现 |
| 计划级配额（预算隐藏于 authority） | `IMPLEMENTED`, `TESTED`, `ASSUMPTION-DEPENDENT` | 14 个 plan_batch 测试；**非 ZKP**——独立验证者不能密码学验证隐藏预算谓词（README 自述） |
| Halo2 三动作配额子关系 | `IMPLEMENTED`, `TESTED`（MockProver）, `FORMALIZED`（规格）, `OPEN`（完整 v0.2） | 私钥 budget/limit/blinding 匹配公开 Poseidon 承诺 + 范围 + 求和≤预算；**不证明** 16-leaf plan root / 8 元素 C_statement / 可变 n / schema 兼容 / receipt / 执行真实性 / Ed25519 信封；未与 Python 授权信封集成 |
| v0.2 完整关系（plan root + statement + 可变 n + schema） | `FORMALIZED`（规格文档 v0.2）, `OPEN`（实现） | `docs/agent-exec-binding-mvp-step3-relation-spec-v0.2.md`；仅规格 |

---

## 3. D3-06-C / D3-07-A / D3-07-B 性质

| 性质 | 标签 | 证据与边界 |
|---|---|---|
| 双事件有序状态链（GG/GR/RR） | `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY-EVALUATED`, `ASSUMPTION-DEPENDENT` | Mock 31/31；真证明 verify；翻转 8 public 均失败；依赖 ID 域 `F\{0}`、IR depth 4/16、E-R1 revoker 假设；K=16 / 7072B / prove≈35s |
| 8 public instances 固定顺序 | `IMPLEMENTED`, `TESTED` | 无第 9 值；与 D3-06-B 顺序一致 |
| 外部锚定（`C_prev` → signed `state_root`） | `IMPLEMENTED`, `TESTED`, `ASSUMPTION-DEPENDENT` | D1 九字段 + SHA256 + 3-of-4 Ed25519 QC；**host-only，无电路内 anchor proof**；配置来源真实性外部假设 |
| Freshness（max-age / skew / 本地 high-water） | `IMPLEMENTED`, `TESTED`（A01–A36）, `ASSUMPTION-DEPENDENT` | 本地防回滚 + 时间策略；**不证明全局最新**；time validity ≠ global freshness |
| 组合顺序（anchor → binding → Halo2 → commit） | `IMPLEMENTED`, `TESTED` | proof 失败不 commit（A22–A28） |
| 多 Witness 锁转移 `locked_round < polc_round < current_round` | `FORMALIZED`, `TESTED`（状态机 49 场景 / 19 unittest）, `ASSUMPTION-DEPENDENT` | 规则层语义；P1 是确定性模拟非密码学；G1/G2/G3 开放 |
| 多 Witness S-A 安全性 | `FORMALIZED`（规则层数学论证 `PROOF_SUPPORTED`）, `ASSUMPTION-DEPENDENT` | 带显式模型假设（书面规则 + 外部持久化）；**非 BFT 形式化证明** |
| `STOP_HALO2_DIRECTION` / private-only 反例 | `FORMALIZED`（反例论证） | §5.1 证明者自造 checkpoint/signer_set/round 重算哈希，验证者无法区分——D3-12 H2 的本项目先例 |

---

## 4. 审计结论层面的性质（D3-08 ~ D3-12）

| 性质 / 命题 | 标签 | 结论 |
|---|---|---|
| "泛化匿名委托 + 撤销 + 多源 = 新密码学问题" | `OPEN`→已裁决 `REJECT_AS_KNOWN_PROBLEM`（D3-08） | 已知构造覆盖 |
| "跨会话累计预算 + 撤销 + 隐藏 counter = 新证明关系" | `FORMALIZED`→已裁决 `REJECT_AS_KNOWN_COMPOSITION`（D3-10） | 组合可达但全 `BLOCKED_WITH_ASSUMPTION`；**X2′ 反例有效** |
| "递归连续状态转换 ⇒ 外部执行历史完整" | `FORMALIZED`→**证伪**（D3-10/D3-11） | 不成立；X2′ 是反例 |
| "签名有效 ⇒ 事件真实" | `FORMALIZED`→**证伪**（D3-11 + MVP E2.2） | 不成立；NovaFabric 原文 + E2.2 双重支撑 |
| "日志可追加 ⇒ 无遗漏" | `FORMALIZED`→**证伪**（D3-11 + D3-10） | 不成立；SCITT §11.5 "never recorded leaves no gap" |
| "跨组织回执隐私化关联需要 ZKP" | `FORMALIZED`→已裁决 H1_FAIL/H2_FAIL（D3-12） | `call_digest`/`principal_link` 已覆盖关联内核；equality proof 已知且无锚定不 sound |

---

## 5. 矩阵使用纪律（供下一阶段）

1. 任何"新增保证"的主张必须同时给出：`FORMALIZED` 的精确关系 + 一个能区分新旧机制的反例实验结果（重放 E2.2 或 X2′）。
2. 不能把 `TESTED`（如 E2.1 `DR=1`）写成"问题已解决"——E2.2 同一机制 `DR=0`。
3. 不能把 `ASSUMPTION-DEPENDENT` 的阻断写成"密码学阻断"——D3-11 X1–X7 全部 `BLOCKED_WITH_ASSUMPTION`。
4. `OPEN` 项（proxy 自身作恶、D6 外部能力契约、完整 v0.2 电路、P5/P6 字段级）是下一阶段最明确的**可验证缺口**，而非"已失败方向"。
