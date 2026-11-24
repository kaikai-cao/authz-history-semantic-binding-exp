# EXP-D3-07-B-CLOSURE — D3-07-B 阶段收束总结

> 任务编号：`D3-07-B-CLOSURE-01`
> 基线：分支 `exp-d3-07-b-p2-security-argument-r1` @ `643a10d17e67d8ada7668202b7f56cde592cce9e`
> 本文件是**成果归档与研究边界整理**，不新增协议规则、不新增实验、不修改 Halo2 电路、不改动任何已冻结成果。
> 阅读对象：后来接手的研究者。目标是在一份文档内说明 D3-07-B 做了什么、每项结论由什么证据支撑、仍有哪些限制、以及下一阶段（Halo2 电路化）还缺什么。
> 本文件不重新推导 S-A 证明全文、不重新审计协议；所有结论均**引用**已冻结的 P1/P2/P2-SA 文档，并标注证据等级。

---

## §1 研究目标与问题定义

### 1.1 核心问题

当多个独立 Witness 参与授权状态确认时，Gateway 可能面对：候选已签名但 QC 未被观察到（pending lock）、不同主体的局部观察差异、已锁定状态下的撤销/冲突转换请求。研究问题是：

> 如何设计一套有明确假设边界的规则，使 Gateway 不会仅凭局部消息观察就接受相互冲突的 checkpoint；并在网络分区、消息延迟、节点重启下给出可分析的安全与活性边界？

### 1.2 本阶段的确切范围

- 研究对象是 **Model B（Tendermint 风格的轮次锁定与恢复机制）的受限协议设计**，服务于 D3-07-A 的 checkpoint 锚定。
- 本阶段完成的是：**P1 确定性模拟对照实验** + **P2 协议设计审计** + **P2-SA 独立数学论证审计与正式论证整合**。
- 本阶段**不是**完整 BFT 共识协议实现，不实现 FC（finality certificate），不新增 Halo2 电路或 public instance。
- 固定模型：`N=4`、`Q=3`、`f≤1` Byzantine Witness、按 Witness 身份等权计数、不引入墙上时钟。

### 1.3 与相邻阶段的关系

- 上游：D3-06-B/C（Halo2 单/双事件状态链）、D3-07-A（外部 anchor 与 freshness、8 instance 绑定）提供被锚定的 checkpoint 与状态转换证明。
- 本阶段：回答"这些 checkpoint 能否由有明确安全假设的 Witness 协议可信维护"。
- 下游：Halo2 电路化评估是**独立、尚未开始**的下一阶段，本文件只做概念级交接（§7），不提前承诺电路覆盖 P2 全部规则。

---

## §2 P1：确定性模拟实验成果

> 依据：`README.md`、`RESULTS.md`、`SAFETY-INVARIANTS.md`、`PROTOCOL-MODELS.md`、`ATTACK-SCENARIOS.md`、`tests/test_all.py`、`results/p1_p10.json`。
> 冻结基线：`exp-d3-07-b-p1-r1-c1` @ `2b84300`。

### 2.1 三种模型对照

| 模型 | 机制 | 安全性观察 | 活性观察 |
| --- | --- | --- | --- |
| A Permanent Lock | 一旦锁定永久不解锁 | 安全边界最易描述（P1/P4/P8 无 S1–S5 违规） | 未完成候选可无限阻塞；AL1 显示持久化全损破坏 S5 |
| B Tendermint-style | timeout 仅推进轮次；严格 PoLC/lock transfer 才改锁 | P1–P10 诚实 Witness 无 S1–S5 违规；P8-B 为活性反例 | 不依赖可信时钟；有解锁 quorum 才恢复 |
| C Bounded Lease | 租约到期后可恢复可用性 | CK1–CK7 显示安全与活性都绑定单调可信时钟 | Gateway 时钟回拨可重新接受旧 QC（CK7） |

结论：B 为主、A 作安全基线、C 仅在明确可信时钟时作对照。

### 2.2 Model B 的严格锁转移规则

```
locked_round < polc_round < current_round
```

三段均为**严格**不等式：同轮、旧轮 PoLC 不得解锁；仅进入更高轮但无合格 PoLC 也不得解锁。PRECOMMIT 还要求本轮对同一 checkpoint 的 PREVOTE 与精确同轮 PoLC。

### 2.3 R1 对 R0 的修正

| 项 | R0（已推翻） | R1 |
| --- | --- | --- |
| 锁转移 | `round > locked_round` 无需 PoLC 即允许冲突 prevote；同轮 PoLC 可解锁 | 严格三段不等式；仅进入更高轮次不解锁 |
| PoLC 证据 | 只统计收到的消息，漏 Witness 自己的投票 | 合并投票日志与消息，按 `(witness, vote.binding())` 去重 |
| P2-B | W2/W3 未收到 W1 prevote 却报告 QC 形成 | W1 prevote 交付 W2/W3，各自形成 3-of-4 PoLC 后 precommit |
| P3-B | 利用错误锁转移构造冲突 PoLC | 改为不可达性测试 |
| P8-B | 声称 heal 后高轮次可恢复 | 记录真实不可达：锁定节点无解锁 quorum |
| Liveness | 场景作者手写 L1–L4 | 从事件与最终状态机器推导；前置缺失记 `not_applicable` |
| 场景数 | 39 | 48（+ FRESH-B + R1-B1–B8） |

R0 的手写标注以 `author_liveness_r0` 字段保留，仅用于对照，不参与 R1 结论。

### 2.4 R1-C1 对隐式轮次推进的修正

| 项 | R1（有漏洞） | R1-C1 |
| --- | --- | --- |
| 轮次推进 | `can_sign` 用 `max(current_round, request_round)`，`sign_vote` 写回 `max(...)`，签名请求可隐式抬高轮次 | `current_round` 只由 `timeout_advance()` 单调推进；`can_sign` 纯检查且请求轮次必须严格等于当前轮次；`sign_vote` 不写回 |
| 测试夹具 | `_set_lock` 直接赋值 `current_round` | 改为显式 `timeout_advance()`，事件日志可见 |
| 专项场景 | R1-B1–B8 | 新增 R1-C1-B1（子测试 A–E）；场景数 48 → 49 |
| 既有结论 | P2/P3/P8、R1-B1–B8 | 全部保持；Safety 无违规，协议规则未放宽 |

`current_round` 运行时唯一推进点为 `timeout_advance()`；测试 `test_can_sign_source_is_read_only` 对源码做静态断言。

### 2.5 49 个场景的覆盖

P1–P10（A/B/C 三模型）+ U1（timeout 解锁反例）+ AL1（持久化全损）+ CK1–CK7（Model C 时钟边界）+ FRESH-B（三层状态区分）+ R1-B1–B8（Model B 锁/PoLC/双签/重启/旧轮专项）+ R1-C1-B1（显式推进专项）。全部使用确定性事件序列，无随机测试替代指定攻击场景。

测试结果：**49 场景、19 项 unittest 全部通过**，两次生成结果 SHA 一致。

### 2.6 已观察的安全与活性边界

- **U1（不安全恢复）**：把 timeout 当解锁证明后，两个诚实 Witness 改签冲突 checkpoint，配合 1 个 Byzantine 形成第二个 QC，S2 被破坏——已由模拟器验证。
- **AL1（持久化全损）**：pending lock 与签署日志同时丢失后 S5 失效——已由模拟器验证；"持久化锁可信"本身是外部假设。
- **P8-B（活性反例）**：两个诚实 Witness 已锁定一个未形成 QC 的状态后，即使网络愈合也不能单靠更高轮次恢复——它们无法自行制造解锁所需的冲突 quorum。
- **FRESH-B**：区分 Gateway committed QC、Witness durable lock、Witness volatile observed 三层状态；有效 QC 不等于全局最新。

### 2.7 P1 的证据性质（必须准确）

- P1 是**确定性状态机模拟**，Vote 只是结构化绑定对象，不是密码学实现。
- 模拟器验证**不等于**密码学安全证明；通过测试**不等于** BFT soundness；**不是**真实分布式部署结果。
- P1 的作用是提供**具体状态机行为与反例边界的结构性证据**；它不能替代 S-A 的数学论证（§4）。
- Liveness 由机器从事件推导，`X`（not_applicable）表示前置条件缺失，而非通过。

**核心答案**：不引入可信墙上时钟时，安全恢复可由 quorum-evidence 的严格轮次切换规则支撑；但活性不能无条件保证，仍需最终通信/部分同步假设与解锁 quorum 的形成条件。

---

## §3 P2：协议设计成果

> 依据：`EXP-D3-07-B-P2-{PROTOCOL,STATE-MACHINE,CRASH-ANALYSIS,SECURITY-ARGUMENT,REFERENCES}.md`。
> 冻结基线：`exp-d3-07-b-p2-design` @ `b18a0c6`。本阶段**不重新设计**这些规则。

### 3.1 状态变量与主体（七个状态严格区分）

| 状态 | 主体 | 持久化 | 关键约束 |
| --- | --- | --- | --- |
| `committed_checkpoint` | Gateway（权威） | 是 | 冲突 digest 已存在时拒绝更新（S2） |
| `durable_lock` = `(locked_round, locked_digest)` | 各 Witness | 是 | 仅满足解锁规则后改写 |
| `pending_vote` | 各 Witness | 是 | 签名准备阶段先写 pending；不构成 quorum 证据 |
| `observed_votes` | 各 Witness | 否（易失） | 局部视图，按 `(witness, binding)` 去重 |
| `current_round` | 各 Witness | 否（易失、单调） | 唯一入口 `ROUND_ADVANCE`，签名请求不得推进 |
| `polc` | 各 Witness | 否（证据，可重验） | 绑定 `(chain_id,set_id,epoch,round,digest)` |
| `witness_set` | Gateway + Witness | 是 | 受信任配置；轮换协议未定义 |

`lock_key=(chain_id,set_id,epoch)`：同一 lock_key 下不同 digest 互为冲突。

### 3.2 PREVOTE / PRECOMMIT / PoLC / QC 的关系

- **PoLC**：`Q=3` 个不同 Witness 对同一轮 `r_p`、同一 digest 的有效 PREVOTE；是解锁证据与进入 precommit 的前提。
- **QC**：`Q=3` 个不同 Witness 对同一轮、同一完整 checkpoint 的有效 PRECOMMIT；是 Gateway commit 的依据。
- 四层纪律：**收到消息 ≠ 接受投票 ≠ 形成 PoLC/QC ≠ commit ≠ 所有 Witness 观察到 commit**。
- PRECOMMIT 必须绑定**同轮、同 digest 的精确 PoLC**（`r_p == r`）。

### 3.3 current_round 的显式推进纪律

- 唯一入口是 `ROUND_ADVANCE`/`timeout_advance()`，单调不回退、同轮幂等。
- timeout 只推进轮次，**不写** `durable_lock`、**不单独构成**解锁证明。
- 签名请求不隐式推进轮次（`can_sign` 纯检查，请求轮次必须严格等于当前轮次）。

### 3.4 严格锁转移条件

```
locked_round < polc_round < current_round
```

同轮、旧轮、未来轮 PoLC 以及缺少/不完整/签名不足的 PoLC 一律 fail-closed；Byzantine 双签交由 quorum 交集与 S1 处理。该不等式与 CometBFT `Prevote Step` 的 `LastLockRound < PoLC-Round < R` 逐字对应，但本设计只借用这一条结构，不继承其安全证明。

### 3.5 Gateway 验证与提交边界

Gateway 收到 QC 后按**不可调换**的顺序验证：① Witness set 配置可信（强制 profile：4/3、唯一 ID、合法 Ed25519 公钥、`log_root=NO_LOG`、`log_size=0`）→ ② QC 签名有效（按 `(witness,binding)` 去重）→ ③ checkpoint 链关系有效 → ④ epoch/policy/transition_version 绑定 → ⑤ freshness → ⑥ Halo2 proof 验证 → ⑦ 本地 anti-rollback。步骤 ①–③ 属 P2 设计层，④–⑦ 属 D3-07-A 既有职责；本设计**不修改** D3-07-A 的验证代码与边界。

### 3.6 八类崩溃位置分析结果

| # | 崩溃点 | 双签风险 | 人工恢复 | P1 覆盖 |
| --- | --- | --- | --- | --- |
| 1 | 写 pending 前 | 否 | 否 | 否 |
| 2 | pending 后、签名前 | 否（需重校验） | 否 | 否 |
| 3 | 签名后、发送前 | 否（由 `S` 约束） | 否 | 否 |
| 4 | 发送后、记录日志前 | **可能**（最危险） | 视情况 | 否 |
| 5 | 写锁后、签名返回前 | 否（原语成立时） | 否 | 否 |
| 6 | 完整重启 | 否（`L`/`S` 保留） | 否 | 是（P5/P6/R1-B7） |
| 7 | pending 丢失、日志在 | 否（从 `S` 重建） | 否 | 是（P5/P6） |
| 8 | 全部本地状态丢失 | **可能** | **是** | 是（AL1 失败） |

- 崩溃 4 的缓解规则：把"追加 `S`"放在"广播"之前（签名 → 写 `S` → 广播）。
- 崩溃 8：空状态节点 fail-closed 拒绝签名，须从可信来源重建，属未解决问题。
- 崩溃点 1–5 在 P1 中**未被建模**，结论是规则推导而非模拟验证。
- 分析使用抽象原语 `durable_write`/`atomic_write_two`；**不声称**任何已实现存储是 crash-safe，P1 的"持久化"只是 Python 字典 dump/restore。

### 3.7 Model B 与完整 Tendermint/CometBFT 的区别

本设计缺少 proposer 选举、完整 round-change、证据传播、validator set 轮换、equivocation slashing、nil 投票与投票权模型；CometBFT 的活性依赖递增 timeout，本设计刻意不把 timeout 当解锁证据。文献核验（Tendermint/CometBFT consensus、TUF 1.0.37、RFC 9162）给出逐字可定位条款与"不适用/不可直接借用"清单，见 `EXP-D3-07-B-P2-REFERENCES.md`。

---

## §4 S-A 正式安全论证

> 依据：`EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` §2（正式论证）、`EXP-D3-07-B-P2-SA-REVIEW.md`（独立数学审计，已冻结）。
> 本文件仅引用结论，不重新推导证明全文。

### 4.1 当前结论

- 阶段状态：`ACCEPTED_WITH_EXPLICIT_MODEL_ASSUMPTIONS`
- 证据等级：`PROOF_SUPPORTED`——在书面状态机规则、模型假设与外部持久化前提下，S-A 得到规则层数学论证支持。
- 性质：同一 `lock_key=(chain_id,set_id,epoch)` 下，两个不同 digest 的冲突 checkpoint 不可能同时形成满足当前协议规则的有效 QC。

### 4.2 论证要点（摘要，指向正式文档）

1. **旧鸽巢论证无效（已作废）**：两个 3-of-4 quorum 交集至少 2，但 `f≤1` 只能保证其中至少 **1 个**诚实 Witness，不是 2 个；且 S1 只禁止同轮双签，跨轮改签须由 R-LOCK 分析。早期"至少两个诚实双签者"的推理不成立，已判定无效并从正式文档移除。
2. **固定较早 QC 为锚点**：反设 `QC(A,r_A)`、`QC(B,r_B)` 同时成立（`r_A < r_B`），固定较早者 `QC(A,r_A)` 为唯一锚点。
3. **相对锚点的最小冲突 PoLC**：`s = min{ ρ > r_A : 存在 D≠A.digest、同 lock_key、PoLC(D,ρ) 成立 }`。集合非空由较晚 QC 的精确同轮 `PoLC(B,r_B)` 保证（`r_B>r_A`），故 `r_A < s ≤ r_B`。
4. **quorum 交集**：`QC(A,r_A)` 的 PRECOMMIT 签名者 ≥3（其中 ≥2 honest 已锁 A），`PoLC(D,s)` 的 PREVOTE 签名者 ≥3，交集 ≥2 且含 ≥1 诚实 Witness W。
5. **第一次离开 A**：W 在 s 改签冲突 digest，取第一次从 A 离开的转移，得 `r_A ≤ locked_round < p_1 < current_round_1 ≤ s`，即 `r_A < p_1 < s`——一个严格位于 `(r_A,s)`、相对 A 冲突的 PoLC。
6. **最小性矛盾**：`p_1` 属于 s 的定义集合却 `< s`，矛盾。同轮冲突 QC 由 S1 独立排除。反设不成立，S-A 得证。

### 4.3 边界（不得夸大）

- 这是**人工审计的规则层数学推导**，**不是**机器检查的形式化证明；未经证明助手机器校验。
- P1 模拟器只提供结构性证据，**不能**替代数学论证，**不能**作为 BFT soundness 证明。
- 不引用原鸽巢论证，不声称对应完整 CometBFT `Proof of Safety`，不声称已验证 crash-safe 存储，不声称 QC/PoLC 证明 globally latest。

完整证明、逐步规则追溯与反例搜索见 `EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` §2 与 `EXP-D3-07-B-P2-SA-REVIEW.md`。

---

## §5 证据等级与结论矩阵

> 不同证据等级**不得**合并成一个笼统的"已验证"。

| 结论 | 证据来源 | 当前状态 | 不能据此声称 |
| --- | --- | --- | --- |
| 显式轮次推进 | P1 R1-C1 | 模拟器路径验证 + 源码只读静态断言 | 真实分布式部署安全 |
| 严格锁转移 | P1 + P2 状态机 | 模拟器验证与规则定义 | 完整 Tendermint 安全性 |
| S-A 冲突 QC 不可共存 | P2-SA 审计与正式论证 | 模型假设下人工数学推导（`PROOF_SUPPORTED`） | 形式化机器证明 / BFT soundness |
| 崩溃一致性 | P2 Crash Analysis | 抽象持久化原语下的规则推导 | 具体存储 crash-safe |
| Gateway 最新性 | D3-07-A / P2 边界 | 依赖外部 freshness/checkpoint 机制 | QC 或 PoLC 自身证明 globally latest |
| 活性 | P1 场景与 P2 假设 | 条件性（部分同步 + 解锁 quorum） | 无条件恢复和进展 |

证据标签统一取自正式文档：`已由 P1 模拟器验证` / `由协议规则推导` / `仍依赖外部假设` / `当前无法证明`。

---

## §6 未解决问题与限制

| 项 | 内容 | 类别 |
| --- | --- | --- |
| G1 | 外部 PoLC 验证清单（STATE-MACHINE §2.3）未逐项写出 `lock_key` 与本地锁绑定的检查；语义在 §3.1/§3.2 已定义，但验证清单未显式 | 规格表达 |
| G2 | `durable_write` / `atomic_write_two` 尚未由具体存储实现验证；PRECOMMIT 的锁写入-签名原子性依赖此抽象原语 | 实现前提（外部假设） |
| G3 | `locked_round` 单调性可由现有状态转移规则推导（R-ROUND + R-LOCK + `locked_round ≤ current_round`），但尚未机器验证，应在正式规格中显式表达 | 规格表达（可推导性质） |
| 全部本地状态丢失后的可信恢复 | 崩溃 8：空状态节点须从外部证据重建，流程未定义（AL1 显示 S5 失效） | 恢复 |
| Witness set 轮换协议 | `set_id` 与成员/公钥的轮换流程未定义（P10 混合投票风险） | 协议设计（外部信任边界） |
| 解锁 quorum 形成条件 | 网络恢复后由谁、以何规则形成合格解锁 quorum 未定义（P8-B 反例） | 活性 |
| 部分同步 / GST 量化 | 最终通信假设未量化 GST 上界 | 活性（外部条件） |
| Gateway 局部可见性与全局 freshness | quorum 可能共同持有旧视图；有效 QC 不等于全局最新，需外部 latestness 机制 | 外部信任边界 |
| 异质投票权模型 | 若引入权重，`Q=3`/`f=1` 的计数关系需重证 | 规格扩展 |

说明：G1/G2/G3 的分类与边界与 P2-SA 冻结审计一致；G2 是外部持久化前提而非规则缺口，G3 不是新协议规则。本文件不解决这些问题。

---

## §7 Halo2 后续接口评估（概念级交接）

> 仅做链下/链上边界的概念级评估，**不新增电路、不修改 public instance 布局、不声称已有电路覆盖 P2 全部协议规则**。
> 既有事实：D3-06-B/C 已有单/双事件 IR-bound 状态链电路；D3-07-A 已有外部 anchor 与 8 instance 绑定。本阶段未改这些电路。

| 候选环节 | (1) 可能适合进入 Halo2 的约束 | (2) 必须链下验证的签名/持久化/网络状态 | (3) 依赖外部可信源、电路无法独立证明 | (4) 尚缺明确电路接口定义 |
| --- | --- | --- | --- | --- |
| checkpoint 与 lock_key 字段绑定 | 约束 `(chain_id,set_id,epoch,digest,parent,version)` 与状态摘要的一致性 | — | chain_id/set_id 的权威来源 | 字段编码与实例映射 |
| 授权状态转换前后摘要 | 转换前后 `D3-STATE-v2` 摘要的合法演进（沿用 D3-06-C 双事件链） | — | — | 与 Witness 轮次/锁状态的接口尚未定义 |
| PoLC/QC 结构化证据摘要 | 若纳入，需对 Q 份签名集合做结构化摘要约束 | Ed25519 签名验签、按 `(witness,binding)` 去重、PoLC/QC 形成 | quorum 证据的真实性来源 | 是否引入 Merkle/集合承诺、instance 布局未定 |
| 锁 → 冲突状态合法转换 | `locked_round < polc_round < current_round` 的不等式约束（若选择电路化） | `durable_lock` 的持久化与重启恢复、PoLC 的可重验性 | PoLC 证据是否为当前有效视图 | 轮次/锁是否进入电路 witness 与 public instance 未定 |
| Gateway 验证结果与 freshness checkpoint | 绑定已验证结果到状态摘要 | Gateway 的 7 步验证顺序、本地 anti-rollback | freshness 来自外部 checkpoint/可信时钟，电路无法独立证明 globally latest | 与 D3-07-A anchor 的衔接接口未定 |

**明确边界**：

- 电路可约束的是**结构化关系与摘要一致性**；签名验签、持久化状态、网络观察与 quorum 形成属链下。
- **freshness / globally latest 依赖外部可信来源**，不能由 Halo2 电路独立证明。
- 是否把 PoLC/QC、轮次/锁纳入电路，以及 public instance 布局，**均尚未确定**，需下一阶段单独论证。

---

## §8 阶段结论与下一步

### 8.1 阶段状态

| 工作项 | 状态 |
| --- | --- |
| P1 确定性模拟实验 | 完成当前版本（`exp-d3-07-b-p1-r1-c1` @ `2b84300`） |
| P2 协议设计审计 | 完成当前版本（`exp-d3-07-b-p2-design` @ `b18a0c6`） |
| P2-SA 数学审计 | 冻结（`exp-d3-07-b-p2-sa-r1-c1` @ `67c646b`，`ACCEPTED_WITH_EXPLICIT_MODEL_ASSUMPTIONS`） |
| S-A 正式论证 | 已整合（`exp-d3-07-b-p2-security-argument-r1` @ `643a10d`，`P2_SA_FORMAL_ARGUMENT_INTEGRATED`） |
| D3-07-B 阶段收束 | 本任务完成后关闭当前阶段 |
| Halo2 电路化评估 | **独立下一阶段，尚未开始** |

### 8.2 进入 Halo2 阶段前必须重新确认的输入、约束与未解决问题

- **输入**：被锚定的 checkpoint 字段规范、`D3-STATE-v2` 摘要定义、D3-07-A 的 8 instance 顺序与 anchor 数据、D3-06-C 双事件状态链证明的现有接口。
- **约束**：§7 表中哪些关系值得电路化；若纳入 PoLC/QC 与轮次/锁，需重新论证其摘要约束的可满足性与成本。
- **未解决问题**：G1/G2/G3 的规格显式化与实现验证；崩溃 8 恢复流程、Witness set 轮换、解锁 quorum 形成条件、GST 量化、Gateway 全局 freshness 机制。
- **不得继承的假设**：不把本阶段的规则层论证当作电路已覆盖的证明；不把 freshness/globally latest/crash-safe 当作已解决。

### 8.3 最终边界声明

D3-07-B 提供的是一套**有明确假设边界的受限协议设计与论证**，不是完整 BFT 实现、不是形式化安全证明、不证明 crash-safe 持久化、不证明 globally latest。下一阶段是否进入 Halo2 电路化、可证明语句为何、public instance 边界如何，须单独评估，不回头反复修改已冻结的 P1/P2 成果。
