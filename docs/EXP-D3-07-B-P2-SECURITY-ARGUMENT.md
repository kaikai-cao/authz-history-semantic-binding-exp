# EXP-D3-07-B-P2 — 安全性/活性论证草案与 Gateway 集成边界

> 设计审计产物，不含实现。基线 `exp-d3-07-b-p1-r1-c1` @ `2b84300`。
> 本文件给出 Safety / Liveness 性质草案（P2-5）与 Gateway 接入 D3-07-A 的边界（P2-6）。
> **本文件不是形式化安全证明**；每条性质按"假设 / 论证 / 失败边界 / P1 覆盖 / 证据标签"五栏给出。

## 1. 模型与假设

- 模型：`N=4`、`Q=3`、最多 `f=1` Byzantine Witness；honest Witness 遵守状态机规则。
- 网络：分区、消息延迟、节点重启可能发生；采用**部分同步**假设（存在 GST，之后消息最终送达），但本设计不量化 GST。
- 密码学：签名为 Ed25519 类型、不可伪造；摘要/绑定字段抗碰撞（沿用 D3-07-A 假设）。
- 持久化：`durable_lock` 与 `signed_votes` 的恢复原语成立（见 CRASH-ANALYSIS §0）；此为外部假设。
- 配置：`witness_set` 与阈值来自受信任配置（D3-07-A-R1 强制 profile：4 Witness / 3-of-4 / log_root=NO_LOG / log_size=0）。

## 2. Safety 性质

### S-A：两个冲突 checkpoint 不会同时获得诚实协议认可的 QC

> 本节为正式论证，已与独立数学审计的冻结结论 `EXP-D3-07-B-P2-SA-REVIEW.md`（状态 `ACCEPTED_WITH_EXPLICIT_MODEL_ASSUMPTIONS`）对齐。早期版本使用的简单鸽巢论证已被该审计判定无效并从本文件移除。

**性质定义。** 在固定 Witness 集合 `N=4`、`Q=3`、最多 `f≤1` Byzantine Witness 的模型下，同一 `lock_key=(chain_id,set_id,epoch)` 下、两个不同 `digest` 的冲突 checkpoint 不可能同时形成满足当前协议规则的有效 QC。其中：冲突指同一 `lock_key` 而 `digest` 不同——不同 `epoch` 或不同 `set_id` 的 checkpoint **不是**冲突，本性质不适用；有效 QC 需要 3 个不同 Witness 对同一 `round`、同一完整 checkpoint 的有效 PRECOMMIT；本结论依赖 honest Witness 遵守状态机规则（§1）。

**假设与前提。**

- `N=4`、`Q=3`、`f≤1`，`witness_set` 固定，按 Witness 身份等权计数（非按权重）。
- 签名不可伪造；摘要与绑定字段抗碰撞。
- honest Witness 遵守 S1、R-PREVOTE、R-PRECOMMIT、R-LOCK、R-ROUND（STATE-MACHINE §1–§3）。
- PRECOMMIT 要求本轮已对同一 checkpoint PREVOTE，并观察到精确同轮 PoLC（`r_p == r`，STATE-MACHINE §2.4）。
- PoLC 必须绑定同一 `lock_key`，且解锁时目标 digest 与当前锁冲突（STATE-MACHINE §3.1/§3.2）。
- `durable_lock` 与 `signed_votes` 的恢复语义依赖 CRASH-ANALYSIS §0 所述抽象持久化原语；本设计未验证任何具体存储实现。

**G1/G2/G3 的准确处理。**

- **G1（规格表达缺口）**：STATE-MACHINE §2.3 的外部 PoLC 验证清单未逐项写出"PoLC 的 `lock_key` 与本地锁绑定相等"检查；虽然 §3.1/§3.2 已定义这些语义要求，本证明把它们作为**前提**，**不声称已有独立实现验证**。
- **G2（外部实现前提）**：PRECOMMIT 的锁写入与签名证据原子持久化依赖 `durable_write` / `atomic_write_two` 等抽象原语；本设计**没有验证**任何具体存储实现满足这些原语。
- **G3（可推导状态性质）**：`locked_round` 单调不减**不是额外引入的新协议规则**，可由现有规则推导：`current_round` 单调推进（R-ROUND）；锁更新发生在当前轮；冲突锁转移要求 `locked_round < polc_round < current_round`（R-LOCK）；结合不变量 `locked_round ≤ current_round`，锁轮次不会倒退。该推导仅为书面规则层推导，**不是**已实现或机器验证的事实。

**论证（正式证明，跨轮与同轮分列）。**

*第一步：旧鸽巢论证为何无效。* 两个 3-of-4 quorum 的交集至少为 2，但 `f≤1` 只能保证交集中至少 **1 个**诚实 Witness，不能保证至少 2 个诚实 Witness。并且 S1 只禁止同轮双签，跨轮改签必须由 R-LOCK 分析。因此早期版本"至少两个诚实双签者"的鸽巢推理无效，不能作为本性质依据。

*第二步：反设两个冲突 QC，固定较早者为锚点。* 反设 `QC(A,r_A)` 与 `QC(B,r_B)` 同时成立，A、B 同一 `lock_key`、digest 不同。同轮情况在第七步单独处理；跨轮时不失一般性令 `r_A < r_B`，固定较早的 `QC(A,r_A)` 为唯一锚点。

*第三步：定义相对锚点的最小冲突 PoLC。* 令

```
s = min{ ρ > r_A : 存在 D，D.digest ≠ A.digest、同 lock_key，且 PoLC(D,ρ) 成立 }
```

这是相对 A 的最小冲突 PoLC，**不是**全局最早冲突 PoLC。集合非空：较晚 `QC(B,r_B)` 中至少有诚实 PRECOMMIT，诚实 PRECOMMIT 要求精确同轮 `PoLC(B,r_B)`，且 `r_B > r_A`、`B.digest ≠ A.digest`，故 `r_B` 属于该集合。因而 `r_A < s ≤ r_B`。

*第四步：构造两个 quorum 并取交集。* `QC(A,r_A)` 的 PRECOMMIT 签名者集合至少 3，其中至少 2 个诚实 Witness（由 R-PRECOMMIT 动作，它们已在 `r_A` 锁定 A）；`PoLC(D,s)` 的 PREVOTE 签名者集合至少 3。两集合交集至少 2（`3+3−4=2`），由 `f≤1` 交集中至少 **1 个**诚实 Witness，记为 W。W 在 `r_A` 已锁 A，却在 s 对与 A 冲突的 D PREVOTE。

*第五步：使用第一次离开 A 的转移。* W 诚实且在 s 为冲突 digest PREVOTE，必须满足 R-LOCK。若 W 在 `r_A` 与 s 之间经过多个中间 digest 转移，取**第一次从 A 离开**的转移：离开前 W 仍锁定 A（`locked_digest = A.digest`），故该次 PoLC 目标必与 A.digest 冲突。由于 W 在 `r_A` 已锁 A、`locked_round` 不倒退故第一次离开时 `locked_round ≥ r_A`、R-LOCK 要求 `locked_round < p_1 < current_round_1`、且该次转移受最终 s 轮约束故 `current_round_1 ≤ s`，得到

```
r_A ≤ locked_round < p_1 < current_round_1 ≤ s
```

因此 `r_A < p_1 < s`。这给出一个轮次严格位于 `(r_A,s)`、且相对 A 冲突的 PoLC。

*第六步：导出最小性矛盾。* `p_1` 属于 s 的定义集合却满足 `p_1 < s`，与 s 的最小性矛盾。故跨轮情况下两个冲突 QC 不可能同时成立。

*第七步：同轮情况。* 若两个冲突 QC 位于同一轮 r，各自要求同轮精确 PoLC；两个 3-of-4 PREVOTE 集合交集至少 2，其中至少 1 个诚实 Witness，该 Witness 必须在同一轮对两个冲突 digest PREVOTE，违反 S1。故同轮冲突 QC 也不可能。

综上，反设不成立，S-A 得证。

**失败边界。**

- 若签名可伪造、`f≥2`、honest 节点违反 S1/R-LOCK/R-PRECOMMIT/R-ROUND、或持久化丢失导致节点忘记已签事实（AL1），论证失效。
- G1 的实现若漏检 `lock_key` 绑定、G2 的持久化原语若不成立，前提被破坏，结论不再保证。
- 本论证不覆盖异质投票权模型（若引入权重，`Q=3` 与 `f=1` 的计数关系需重证）。

**P1 覆盖。** P3-B（冲突 PoLC 不可达）、R1-B1–B8、U1（timeout 解锁反例，S2 失败）提供具体状态机行为与反例边界的**结构性证据**；P1 模拟器测试**不能**替代上述数学论证，也**不能**作为 BFT soundness 证明。

**证据标签。** `PROOF_SUPPORTED`：在当前书面状态机规则、模型假设及外部持久化前提下，S-A 得到规则层数学论证支持。这是**人工审计的数学推导，不是机器检查的形式化证明**；不引用原鸽巢论证，不声称对应完整 CometBFT Proof of Safety，不声称已验证 crash-safe 存储，不声称 QC/PoLC 证明 globally latest。

### S-B：诚实 Witness 不违反锁转移规则

- **假设**：`can_sign` 为纯检查、请求轮次严格等于 `current_round`（R1-C1）；状态机按 STATE-MACHINE §2 实现。
- **论证**：所有 prevote/precommit 路径都先过 §2 的前置检查；解锁仅在合格 PoLC 满足严格不等式时发生；timeout 不改锁。
- **失败边界**：实现若在 `can_sign`/签名接口写入 `current_round`（R1 的旧漏洞）或绕过检查，则不成立。
- **P1 覆盖**：S6 / R1-C1-A–E（源码静态断言 + 五项真实路径）验证。
- **证据标签**：已由 P1 模拟器 + 源码断言验证（状态机纪律层面），非形式化证明。

### S-C：旧轮消息不能混入新轮形成有效 PoLC/QC

- **假设**：`round` 进入签名体；Gateway 与 Witness 按 `round` 过滤。
- **论证**：PoLC 要求同一 `r_p`、QC 要求同一 `round`；旧轮签名的 sign-bytes 含旧轮号，无法在新轮重解释（S4）。precommit 还要求 `(r,C)` 精确 PoLC（R1-B8）。
- **失败边界**：若签名体不含 round 或过滤被绕过，失效。
- **P1 覆盖**：S4 / P2 / P8 / CK5 / R1-B8 通过。
- **证据标签**：已由 P1 模拟器验证。

### S-D：Witness 重启不静默丢失已生效的安全约束

- **假设**：`L`/`S` 持久化原语成立；重启后按 `S` 判定已签事实。
- **论证**：full/lost_pending 保留锁；pending 丢失可从 `S` 重建；解锁 inequality 以持久化的 `locked_round` 为准。
- **失败边界**：AL1（pending 与日志同时丢失）下 S5 失败；current_round 归零不得否定 L。
- **P1 覆盖**：S5 / P5 / P6 / R1-B7 通过；AL1 失败已记录。
- **证据标签**：已由 P1 模拟器验证其通过/失败边界；持久化本身依赖外部假设。

## 3. Liveness 性质

### L-A：网络恢复后 honest 节点能推进轮次并获取 PoLC、继续形成 QC

- **假设**：部分同步（GST 后消息最终送达）；存在能形成合格解锁 quorum 的诚实节点；持久化延续。
- **论证**：GST 后：`ROUND_ADVANCE` 单调推进 `current_round`；节点交换 prevote 形成 PoLC；满足 `locked_round < polc_round < current_round` 时 unlock；precommit 汇聚成 QC。不依赖 timeout 自动解锁。
- **失败边界**：**P8-B** —— 两个 honest 节点已锁未形成 QC 的状态后，缺乏合格解锁 quorum，网络愈合也不能单靠更高轮次恢复（记为 `not_achieved`，非 fail-closed 成功）。GST 未量化。
- **P1 覆盖**：L1/L2 由 P1、P4、P8 等机器推导；P8-B 为反例。
- **证据标签**：由协议规则推导 + P1 机器推导；**仍依赖**最终通信与解锁 quorum 形成条件。

### L-B：不依赖 timeout 自动释放安全锁

- **假设**：R1-C1 状态纪律；timeout 只推进轮次。
- **论证**：`ROUND_ADVANCE` 不写 `L`、不构成解锁证明；解锁必须另有合格 PoLC（R1-C1-E）。
- **失败边界**：若实现把 timeout 当解锁证据，退化为 U1 反例（S2 失败）。
- **P1 覆盖**：S6 / R1-C1-E / U1。
- **证据标签**：已由 P1 模拟器验证。

## 4. Gateway 与 D3-07-A 集成验证顺序（P2-6）

Gateway 收到 QC 后，按以下顺序验证。**顺序不可调换**：前置失败即拒绝，不进入后续步骤。

```text
1. Witness set 配置可信     —— set_id / 成员 / 公钥来自受信任配置；强制 profile 校验
                              （D3-07-A-R1: validate_witness_set_config，4/3、非空唯一 ID、
                               合法 Ed25519 公钥、log_root=NO_LOG、log_size=0）
2. QC 签名有效              —— Q=3 份不同 Witness 的同轮同 checkpoint 有效签名；按 (witness,binding) 去重
3. checkpoint 链关系有效    —— parent_digest / epoch / transition_version 与既有链衔接；
                              同一 lock_key 下无冲突 committed（S2）
4. epoch / policy / transition_version 绑定 —— 与 D3-07-A 的 8 instance 对应字段一致
5. checkpoint freshness      —— 满足协议约定的新鲜性（如 epoch 单调、约定的最大年龄/偏移策略）
6. Halo2 proof 验证成功      —— D3-06-C 的两事件状态链 proof；8 instance 逐一绑定
7. 本地 anti-rollback        —— 写入前检查 local high-water，不回退
```

步骤 1–3 对应 P2 设计层，步骤 4–7 对应 D3-07-A 既有职责。本设计**不修改** D3-07-A 的验证代码与边界。

### 4.1 明确边界（不得扩大 D3-07-A）

- **QC 不自动证明 globally latest**：QC 只证明某 checkpoint 被 quorum 在某一轮 commit；Witness quorum 可能共同持有旧视图（FRESH-B）。
- **PoLC 不自动证明全局最新**：PoLC 只证明某轮出现 Q 份 prevote，不涉及状态新旧。
- **quorum 共同旧视图**：若所有可达 Witness 都停留在旧 epoch，它们仍可形成对旧状态的有效 QC；Gateway 无法仅凭 QC 察觉（P3 + FRESH-B）。
- **首次接入**：仍依赖外部信任或同步假设（同 D3-07-A：不证明 S0 全局最新）。
- **不扩大边界**：D3-07-A 只证明"从可信且相对本地未回滚的 S0 出发执行两事件转换"；P2 不把它升级为"全局最新状态下的转换"。
- **FC 接口**：本轮不实现 FC；与 freshness 的结合仅作设计描述。

## 5. 证据标签汇总

| 标签 | 含义 | 本文件适用处 |
| --- | --- | --- |
| 已由 P1 模拟器验证 | `results/p1_p10.json` 有对应事件与决策 | S-B/S-C/S-D、L-B 的 P1 列 |
| 由协议规则推导 | 来自状态转换定义；S-A 另经独立数学审计对齐（见 `SA-REVIEW.md`），为人工推导、非形式化，P1 仅作结构性辅助证据 | S-A（`PROOF_SUPPORTED`）、L-A 的论证 |
| 仍依赖外部假设 | honest quorum、GST、持久化、配置来源、解锁 quorum | 所有 Safety/Liveness 的失败边界 |
| 当前无法证明 | BFT soundness、globally latest、crash-safe、完整轮换 | §4.1、§6 |

## 6. 明确不声明

- 不是形式化安全证明；不是完整 Tendermint/CometBFT。
- 不证明 globally latest、不证明 crash-safe 持久化、不证明部分同步的 GST 上界。
- 不修改 D3-07-A/Halo2 的边界、instance 或验证代码。
- 模拟器通过不等于协议安全证明；fail-closed 拒绝不等于活性达成。
