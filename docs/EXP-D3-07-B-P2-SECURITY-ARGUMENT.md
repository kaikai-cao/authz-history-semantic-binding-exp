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

- **假设**：f=1；签名不可伪造；honest Witness 遵守锁转移规则；Q=3。
- **论证**：一个 QC 需 3 份同轮同 digest 的有效 precommit。两个冲突 QC 需共 6 份签名，来自 4 个 Witness，故至少 2 个 Witness 必须为两个冲突 digest 都签了 precommit（鸽巢原理）。但 honest Witness 在同一 `lock_key` 同一轮只能 precommit 一个 digest（S1），且换 digest 需满足 `locked_round < polc_round < current_round` 的合格 PoLC。f=1 下最多 1 个 Byzantine 双签，无法凑出第二个含 ≥2 honest 双签者的 QC。此论证结构对应 CometBFT "Proof of Safety"（见 REFERENCES §1）。
- **失败边界**：若签名可伪造、f≥2、或 honest 节点违反锁规则、或持久化丢失导致节点忘记自己签过（AL1），论证失效。
- **P1 覆盖**：P3-B（冲突 PoLC 不可达）、R1-B1–B8、U1（timeout 解锁反例，S2 失败）支持该结构；但不是形式化证明。
- **证据标签**：由协议规则推导 + P1 模拟器验证结构性证据；**非** BFT soundness 证明。

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
| 由协议规则推导 | 来自状态转换定义 | S-A、L-A 的论证 |
| 仍依赖外部假设 | honest quorum、GST、持久化、配置来源、解锁 quorum | 所有 Safety/Liveness 的失败边界 |
| 当前无法证明 | BFT soundness、globally latest、crash-safe、完整轮换 | §4.1、§6 |

## 6. 明确不声明

- 不是形式化安全证明；不是完整 Tendermint/CometBFT。
- 不证明 globally latest、不证明 crash-safe 持久化、不证明部分同步的 GST 上界。
- 不修改 D3-07-A/Halo2 的边界、instance 或验证代码。
- 模拟器通过不等于协议安全证明；fail-closed 拒绝不等于活性达成。
