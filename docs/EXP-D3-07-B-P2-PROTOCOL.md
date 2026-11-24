# EXP-D3-07-B-P2 — Model B Witness 协议设计（Protocol）

> 本文件是 D3-07-B-P2 的**设计审计**产物，只描述协议状态、消息与规则，不含实现。
> 基线与工作位置：审计目录 `d3-07-b-protocol-audit`，基线分支 `exp-d3-07-b-p1-r1-c1`，
> 基线 commit `2b84300d907d0d4129e4e32a0ea64581087b2a47`。
> 本轮不实现协议、不改 Halo2、不改任何冻结仓库、不改 P1 的 `src/`、`tests/`、`results/`。
> 本文所有结论的标签见 `EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` 第 5 节；模拟器验证不等于形式化证明。

## 0. 设计目标与核心问题

在 `N=4`、`QC threshold=3`、最多 `f=1` Byzantine Witness 的模型下，能否通过**显式轮次推进**、**PoLC 锁转移**与**持久化状态**，为 D3-07-A 的 checkpoint 提供一个有明确假设边界的恢复机制？

本设计给出肯定回答的**条件版本**：在部分同步、honest quorum 持续可用、持久化状态不被静默丢失的前提下，Model B 的锁转移规则可以阻止两个冲突 checkpoint 同时被诚实协议认可；但它**不能**无条件保证活性，也**不能**证明 checkpoint 是 globally latest。这些边界在第 4、5 节和 `EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` 中逐条声明。

## 1. 术语与符号

| 符号 | 含义 |
| --- | --- |
| `W = {W1,W2,W3,W4}` | 当前生效的 Witness 集合（成员公网身份），`N=4` |
| `f = 1` | 可容忍 Byzantine Witness 上限 |
| `Q = 3` | QC / PoLC / FC 的签名门限（`-2/3` 语义下的 3-of-4） |
| `C = (chain_id, set_id, epoch, digest, parent_digest, transition_version)` | checkpoint 对象 |
| `digest` | checkpoint 内容摘要（本设计中沿用 D3-07-A 已锚定的 checkpoint digest 概念） |
| `lock_key` | `(chain_id, set_id, epoch)`，同一 `lock_key` 下不同 `digest` 互为冲突 |
| `r` | 轮次，非负整数，只单调增 |
| `[m]_i` | Witness `Wi` 对消息/字段 `m` 的有效签名 |

本设计**不引入墙上时钟**：`epoch` 是 checkpoint 链上的单调递增状态号，`round` 是共识协议内部轮次，二者独立，不得混用。`round` 只由显式事件推进（见 §4.3）。

## 2. 协议状态定义（P2-1）

以下七个状态严格区分，不得互相代替。每个状态给出：所属主体、是否持久化、更新条件、重启恢复、以及消息延迟下的观察不一致可能性。

### 2.1 `committed_checkpoint`

- **主体**：Gateway（权威持有者）；Witness 只持有各自观察副本。
- **持久化**：是。Gateway 必须将其写入本地 anti-rollback 存储；D3-07-A 已实现类似的 high-water 本地防回滚。
- **更新条件**：Gateway 收到针对同一 `lock_key` 的 `Q=3` 份同轮同 `C` 的有效 `PRECOMMIT`，且通过全部验证顺序（见 `EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` §4），才写入。已存在冲突 `digest` 时拒绝更新（S2）。
- **重启恢复**：从 Gateway 持久化存储读取；不得因 Witness 重发旧消息而回退。
- **观察不一致**：是。Gateway 已 commit 时，个别 Witness 可能尚未观察到对应 QC；这正是"收到 QC ≠ 所有 Witness 观察到 commit"的来源。

### 2.2 `durable_lock`

- **主体**：每个 Witness（本地）。
- **持久化**：是。必须写入可恢复存储（持久化要求见 `EXP-D3-07-B-P2-CRASH-ANALYSIS.md`，本设计**不**声称普通 JSON 文件即 crash-safe）。
- **更新条件**：
  - precommit 一个具体 `digest` 时写入 `locked_round=r, locked_digest=digest`；
  - 只有当某 PoLC 满足 `locked_round < polc_round < current_round` 并绑定冲突 digest 时，才允许在 prevote 阶段解锁并随后改写（见 §4.2）。
- **重启恢复**：完整状态恢复时保留 `locked_round/locked_digest`；pending 记录丢失但 signed-vote 日志仍在时，从日志重建（P1 的 P5/P6、R1-B7）。
- **观察不一致**：否（对本 Witness 自身而言是本地权威状态）；但不同 Witness 的锁可能处于不同轮次/不同 digest，Gateway 无全局可见性。

### 2.3 `pending_vote`

- **主体**：每个 Witness（本地）。
- **持久化**：是。签名准备阶段先写 pending，再签名（写入顺序见 §4.4 与崩溃分析）。
- **更新条件**：收到合法 `PROPOSAL` 且 `can_sign` 通过后、产生签名前写入；签名完成或明确拒绝后清除。
- **重启恢复**：从持久化 pending 读取；若 pending 丢失但签名日志存在，可从日志重建为"已签"事实；二者皆失则本地无法推断（P1 的 AL1，S5 失败）。
- **观察不一致**：是。Witness A 有 pending 而 Witness B 无，是分区常见状态；pending 不构成任何 quorum 证据。

### 2.4 `observed_votes`

- **主体**：每个 Witness（本地，易失）。
- **持久化**：否（本设计视为易失；重启后可由重发的投票消息重建，但不得据此放松锁）。
- **更新条件**：收到有效投票消息并验证签名/绑定后追加；按 `(witness, binding)` 去重（P1 的 R1-B5 修正）。
- **重启恢复**：不保证恢复；若需重建，必须重新验证消息有效性，不得用未验证缓存。
- **观察不一致**：是。这是 P3 的核心——Gateway 与 Witness 看到的投票集合可能不同，`observed_votes` 是**局部视图**。

### 2.5 `current_round`

- **主体**：每个 Witness（本地，易失但单调）。
- **持久化**：否（重启后可重置为 0 或从恢复流程给定初值；P1 中 `restart()` 的 full/lost_pending 保留、lost_all 归零）。
- **更新条件**：**唯一**入口是显式 `ROUND_ADVANCE`/`timeout_advance()`，单调不回退、同轮幂等；**签名请求不得推进轮次**（P1 的 R1-C1、S6）。
- **重启恢复**：依恢复策略而定；重置为 0 时不得用它去否定已有 `durable_lock`（锁轮次独立保存）。
- **观察不一致**：是。不同 Witness 可处于不同 `current_round`；高轮 Witness 的消息可帮助低轮 Witness 推进，但不改变后者锁。

### 2.6 `polc`（proof of lock change）

- **主体**：每个 Witness 本地形成/持有；`PROPOSAL` 可携带其已知 PoLC 的轮次提示。
- **持久化**：否（作为证据对象，可随投票日志留存以便追责，但形成 PoLC 本身不写锁）。
- **更新条件**：观察到 `Q=3` 个不同 Witness 对**同一轮次 `r_p`、同一 `digest`（或 nil）**的有效 `PREVOTE` 时形成；记为 `polc_round=r_p, polc_digest=digest`。Witness 自己的投票计入并参与去重（P1 的 R1-B5）。
- **重启恢复**：不作为必须恢复的安全状态；但用于解锁的 PoLC 必须是**当前可重新验证**的有效证据集合。
- **观察不一致**：是。Witness A 有 PoLC 而 Witness B 没有；单方观察不构成全局事实。PoLC 对象绑定 `(chain_id, set_id, epoch, round, digest)`。

### 2.7 `witness_set`

- **主体**：Gateway 与所有 Witness 共同依赖；版本化配置对象。
- **持久化**：是。必须作为受信任配置分发（D3-07-A-R1 的 4 Witness/3-of-4 profile 是强制配置，不是可调阈值）。
- **更新条件**：仅在明确的集合轮换流程下变更 `set_id` 与成员/公钥；本设计**不定义**轮换协议（列为未解决问题，见 P1 的 P10）。
- **重启恢复**：从受信任配置读取，不从网络消息推断。
- **观察不一致**：是（危险）。若不同主体对 `witness_set` 版本认识不同，可能导致 P10 类混合投票被接受；Gateway 必须按 `set_id` 隔离投票。

### 2.8 状态主体汇总表

| 状态 | 主体 | 持久化 | 重启恢复 | 延迟下不一致 |
| --- | --- | --- | --- | --- |
| `committed_checkpoint` | Gateway（权威） | 是 | 本地存储读取 | 是 |
| `durable_lock` | 各 Witness | 是 | 保留或从签名日志重建 | 否（自身权威）/ 跨节点是 |
| `pending_vote` | 各 Witness | 是 | pending 或签名日志重建 | 是 |
| `observed_votes` | 各 Witness | 否 | 需重发并重验 | 是 |
| `current_round` | 各 Witness | 否 | 依策略，不否定锁 | 是 |
| `polc` | 各 Witness | 否（可留证据） | 需可重验 | 是 |
| `witness_set` | Gateway+Witness | 是 | 受信任配置 | 是（危险） |

## 3. 协议消息与字段（P2-2）

### 3.1 公共绑定字段

每条协议消息必须携带并签名以下公共字段（FC 另含 nonce）：

```text
chain_id, set_id, round, checkpoint_digest, parent_digest, epoch,
transition_version
```

- `round` 和 `checkpoint_digest` 进入签名体，旧轮签名不得在新轮重新解释（S4）。
- `set_id` 隔离不同 witness set，防止 P10 混合投票。
- 一条消息"存在"与一条消息"被接受"是不同概念（见 §3.3）。

### 3.2 消息类型

| 类型 | 发送者 | 关键字段 | 作用 |
| --- | --- | --- | --- |
| `PROPOSAL(r, C, polc_hint?)` | 本轮 proposer | 公共字段 + `proposer` + 可选 `polc_round` | 提出本轮 checkpoint；`polc_round < r` 提示解锁安全性（对应 CometBFT "proposal includes optional PoLC-Round"） |
| `PREVOTE(r, C)` | Witness | 公共字段 + `voter` | 表明本轮对该 digest 的 prevote；`Q` 份同轮同 digest 构成 PoLC |
| `POLC(r_p, C, [PREVOTE]_i…)` | Witness（证据对象） | `polc_round=r_p` + `polc_digest` + ≥Q 份 prevote 签名 | 可随 `PROPOSAL` 或解锁请求传播，证明存在解锁证据 |
| `PRECOMMIT(r, C)` | Witness | 公共字段 + `voter` | 锁转移写入 `durable_lock` 后产生；`Q` 份同轮同 digest 构成 QC |
| `QC(C, [PRECOMMIT]_1..Q)` | 聚合者/Gateway | 公共字段 + Q 份 precommit 签名 | Gateway 形成 commit 的依据 |
| `ROUND_ADVANCE(from, to, trigger)` | Witness 本地事件 | `from_round`, `to_round`, `trigger` | 显式推进 `current_round`；`to>from` 单调；签名请求不是合法 trigger |

说明：`POLC` 是证据对象而非新投票种类；`QC` 是 ≥Q 份 `PRECOMMIT` 的聚合结果。本设计不新增 public instance，也不改变 D3-07-A 的 8-instance 顺序（见 `EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` §4）。

### 3.3 消息处理的四层区分

以下四层必须逐步执行，任一层不得跳过：

```text
(1) 收到消息  ──签名有效 + 公共字段绑定正确 + set_id 匹配──>  (2) 接受为有效投票
(2) 接受投票  ──同一 (round, digest) 达 Q 份不同 Witness──>  (3) 形成 PoLC / QC
(3) 形成 PoLC ──Gateway 通过全部验证顺序并写持久存储──>      (4) commit
```

- **收到 ≠ 接受**：签名无效、字段不匹配、`set_id` 不符的消息只记录不采信。
- **接受投票 ≠ 形成 PoLC**：单份或少于 Q 份投票只是 `observed_votes`。
- **形成 PoLC ≠ 形成 QC**：PoLC 来自 prevote，QC 来自 precommit；PoLC 只是解锁证据/进入 precommit 的前提。
- **Gateway 收到 QC ≠ 所有 Witness 观察到 commit**：Gateway 有局部视图，个别 Witness 可能仍处旧轮或未收到 QC。
- **timeout 只推进轮次**：`ROUND_ADVANCE` 不写 `durable_lock`、不单独构成解锁证明（R1-C1-E）。
- **签名请求不隐式推进轮次**：`can_sign` 为纯检查，请求轮次必须严格等于 `current_round`（R1-C1，S6）。

## 4. 锁转移规则（P2-3，摘要）

完整状态转移与拒绝条件见 `EXP-D3-07-B-P2-STATE-MACHINE.md`。此处给出不变量：

```text
locked_round < polc_round < current_round
```

- `current_round`：Witness 真实所在轮次，只能由显式 `ROUND_ADVANCE` 推进，签名请求不得抬高。
- `polc_round`：PoLC 证据的轮次，必须**严格大于** `locked_round` 且**严格小于** `current_round`。
- 三段均为严格不等号：同轮、旧轮 PoLC 不得解锁；仅进入更高轮但无合格 PoLC 也不得解锁。

本规则与 CometBFT 规范 Prevote Step 的 `LastLockRound < PoLC-Round < R` 逐字对应（见 `EXP-D3-07-B-P2-REFERENCES.md` §1），但本设计只借用这一条结构，不继承其安全证明，也不宣称实现完整 Tendermint。

## 5. 不声明事项

- 不是完整 Tendermint/CometBFT：没有 proposer 选举细节、完整 round-change、证据传播、validator set 轮换、equivocation slashing。
- 不声称 BFT 形式化安全证明，不声称 crash-safe 持久化存储。
- 不声称 QC 或 PoLC 证明 globally latest；不扩大 D3-07-A 的边界。
- 不把模拟器验证升级为协议安全性证明。

## 6. 与其他 P2 文档的关系

| 文档 | 覆盖任务包条目 |
| --- | --- |
| 本文 | P2-1 状态定义、P2-2 消息与状态转移概览 |
| `EXP-D3-07-B-P2-STATE-MACHINE.md` | P2-3 锁转移完整规则与拒绝条件 |
| `EXP-D3-07-B-P2-CRASH-ANALYSIS.md` | P2-4 八类崩溃场景 |
| `EXP-D3-07-B-P2-SECURITY-ARGUMENT.md` | P2-5 Safety/Liveness、P2-6 Gateway 集成边界 |
| `EXP-D3-07-B-P2-REFERENCES.md` | 第四节 文献核验 |
