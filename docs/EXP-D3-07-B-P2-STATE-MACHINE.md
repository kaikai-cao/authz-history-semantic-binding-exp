# EXP-D3-07-B-P2 — Model B 消息状态机与锁转移规则（State Machine）

> 设计审计产物，不含实现。基线 `exp-d3-07-b-p1-r1-c1` @ `2b84300`。
> 本文件把 `EXP-D3-07-B-P2-PROTOCOL.md` 的概览展开为可逐步执行的规则与拒绝条件。
> 所有"已由模拟器验证"标签来自 P1-R1-C1 的 `RESULTS.md`，不是形式化证明。

## 1. 状态变量与合法取值

每个 Witness 维护：

```text
durable_lock   = (locked_round : Nat, locked_digest : Digest)   # 持久化
current_round  : Nat                                            # 易失，单调
signed_votes   : list[Vote]                                     # 持久化证据
observed_votes : set[(witness, binding)]                        # 易失，去重
polc           : (polc_round, polc_digest, [Vote])              # 易失证据，可重验
```

不变量（每个消息处理后必须成立）：

- `locked_round <= current_round`（锁轮次不超过当前轮次）；
- 同一 `lock_key` 下，同一 `current_round` 至多对一个 `digest` 产生有效 `PREVOTE`/`PRECOMMIT`（S1）；
- `durable_lock` 只能在满足 §3 的解锁规则后改写。

## 2. 消息处理状态机（逐步）

### 2.1 `ROUND_ADVANCE(r → r')`

```text
前置: r' > r（严格增）；trigger ∈ {timeout, 显式推进事件}，不得是签名请求
动作: current_round := max(current_round, r')   # 单调、幂等
禁止: 不改 durable_lock；不写 signed_votes；不构成解锁证据
记录: 事件日志 (from, to, trigger)               # 可审计（R1-C1 状态纪律）
```

拒绝条件：`r' <= r`、trigger 非法、来源是签名接口。对应 P1 的 S6 / R1-C1-A/E：未推进时高轮签名被拒，推进后仍须满足 PoLC 才能解锁。

### 2.2 `PREVOTE(r, C)`

```text
前置:
  (a) r == current_round                         # R1-C1 硬约束
  (b) 本 Witness 本轮尚未对冲突 digest 签过 PREVOTE（S1）
  (c) 下面二选一:
      (c1) 无 durable_lock，或 locked_digest == C.digest   # 自由/同锁
      (c2) 已锁冲突 digest，且存在合格 PoLC 满足 §3        # 解锁路径
动作:
  写入 pending_vote(C) → can_sign 通过 → 签名 →
  追加 signed_votes → 广播 PREVOTE
拒绝（任一即拒绝）:
  - r != current_round（高轮/低轮都不行）
  - 同轮已对本 lock_key 的另一 digest 签过 PREVOTE
  - 已锁冲突 digest 但无合格 PoLC，或 PoLC 不满足严格不等式
  - 仅进入更高轮次而无 PoLC（"进入新轮 ≠ 解锁"）
```

这是 P1 的 R1-B1/B2/B4、R1-C1-A/B/C/E 的原型。R1-B3 展示合格 PoLC（例 `2 < 3 < 4`）才放行。

### 2.3 `POLC` 形成与验证

```text
形成条件（本地）:
  observed_votes 中，同一 (chain_id,set_id,epoch) 下，
  对同一 round=r_p、同一 digest（或 nil）的 PREVOTE 来自 >= Q=3 个不同 Witness
  且每个签名有效、round 进入签名体
  且本 Witness 自己的投票计入并以 (witness,binding) 去重（R1-B5）
记录: polc = (r_p, digest, [>=3 PREVOTE 签名])
验证外部 PoLC（用于解锁）:
  逐份验签；检查 Q 份互不重复、同一 r_p 同一 digest、round 在签名体内
  检查 r_p 与当前锁/轮次满足 §3
拒绝: 签名无效、重复 witness、跨轮混合、不足 Q、无法重新验证
```

PoLC 只证明"某轮曾出现 Q 份 prevote"，**不证明**该 checkpoint 是全局最新（FRESH-B）。

### 2.4 `PRECOMMIT(r, C)`

```text
前置:
  (a) r == current_round
  (b) 本 Witness 本轮已对同一 C 签过 PREVOTE（自己投过）
  (c) 观察到 (r, C) 的精确 PoLC（r_p 必须 == r，旧轮 PoLC 不可复用，R1-B8）
  (d) 若已锁冲突 digest，PoLC 满足 §3 解锁不等式
动作（顺序敏感，见崩溃分析）:
  1. 写 durable_lock = (r, C.digest)    # 先持久
  2. 追加 signed_votes（PRECOMMIT）
  3. 广播 PRECOMMIT
拒绝（任一即拒绝）:
  - r != current_round
  - 本轮未对同一 C prevote
  - 无 (r,C) 精确 PoLC，或 PoLC 轮次 != r
  - 已锁冲突 digest 且解锁不等式不满足
```

对应 P1 的 R1-B5/B8（缺精确 PoLC 拒绝）、R1-B7（重启后锁保持）。

### 2.5 `QC` 形成（Gateway）

```text
条件:
  >= Q=3 份 PRECOMMIT，来自不同 Witness，
  同一 (chain_id,set_id,epoch)、同一 round、同一完整 C 字段
  set_id 与当前 witness_set 一致（防 P10 混合）
动作: 进入 Gateway 验证顺序（见 SECURITY-ARGUMENT §4）；全部通过后写 committed_checkpoint
拒绝: 旧轮 precommit 混入新轮（S4）、冲突已 commit（S2）、字段不一致（S3）、签名不足
```

Gateway 只基于自己收到的投票判断；它**没有全局可见性**，这是 P3 的核心限制。

### 2.6 `FC`（若接入 D3-07-A 的新鲜性桥）

```text
条件: >= Q 份绑定同一 C 与同一 nonce 的 FC 签名
拒绝: 观察到更高轮、冲突 checkpoint 的 PoLC 时，拒绝为旧 digest 签 FC
边界: 本轮不实现 FC；接口与 D3-07-A 的集成在 SECURITY-ARGUMENT §4 描述
```

## 3. 锁转移规则（P2-3 完整定义）

### 3.1 不变量

```text
允许从 locked_digest 解锁并改签冲突 digest 的充要条件：
  存在可重新验证的 PoLC，满足：
    locked_round < polc_round < current_round
  且该 PoLC 绑定同一 (chain_id, set_id, epoch)，且目标为冲突 digest。
```

三段均为**严格**不等号。与 CometBFT Prevote Step 原文 `LastLockRound < PoLC-Round < R` 对应（见 REFERENCES §1）。

### 3.2 PoLC 必须针对的对象

- 必须是 `PREVOTE`（不是 precommit、不是 pending、不是单个签名）；
- 必须针对**冲突 digest**（同 digest 无需解锁）；
- 必须绑定同一 `lock_key=(chain_id,set_id,epoch)`，跨 epoch/set 的 PoLC 无效；
- 必须来自 `Q=3` 个不同 Witness，含自身投票且去重。

### 3.3 三类 PoLC 的处理

| PoLC 轮次相对关系 | 处理 | 依据 |
| --- | --- | --- |
| `polc_round == locked_round`（同轮） | 拒绝解锁 | 严格不等式要求 `locked_round < polc_round`；R1-B2/B4 |
| `polc_round < locked_round`（旧轮） | 拒绝解锁 | PoLC 太旧，不能支撑新轮转移；旧轮签名不得重解释（S4） |
| `locked_round < polc_round < current_round` | **允许**解锁 | 合格 PoLC；R1-B3（例 2<3<4） |
| `polc_round >= current_round`（未来轮） | 拒绝（本轮无法使用） | 必须严格小于 `current_round`；防止未来证据倒灌 |
| 无 PoLC / PoLC 不完整 / 签名不足 | 拒绝（fail-closed） | 单方观察不构成证据；P8-B |

### 3.4 仅进入更高轮次不解锁

```text
timeout_advance() 只改 current_round。
若 current_round 提升但无满足 §3.1 的 PoLC：
  冲突 prevote 仍被拒（R1-C1-E），锁不变。
```
这推翻 P1-R0 "进入更高轮次即可恢复"的结论；P8-B 显示锁定节点无解锁 quorum 时网络愈合也不可恢复。

### 3.5 原子持久化要求

- precommit 时"写 `durable_lock`"必须先于"返回签名"（§2.4 顺序）；
- 解锁与随后的新锁写入之间，不能出现"锁已清但新锁未写"的可利用窗口；
- 本设计要求这两步在同一恢复单元内完成（如同一事务日志条目），但**明确声明**：本设计不指定具体 crash-safe 存储实现，也不把内存字典/普通 JSON 写当作 crash-safe（见 CRASH-ANALYSIS §0）。

### 3.6 Byzantine 双签处理

- 同一 Witness 对冲突 digest 双签被记为 `adversarial_observations`，不计入诚实 Witness 的 S1；
- 诚实 Witness 不因 BYZ 双签而放松自身锁（R1-B6）；
- 双签证据可用于追责（slash），但本设计**不实现** slashing；
- 冲突 QC 不可同时形成的结论**不能仅由 quorum 交集和诚实签名者数量推出**：两个 3-of-4 集合交集至少含 1 个诚实 Witness，但跨轮改签还需分析锁转移规则（旧表述"至少 2 个诚实签名者"已判定无效）。完整 S-A 论证见 `SECURITY-ARGUMENT.md` §2：固定较早 QC 为锚点，利用相对锚点最小冲突 PoLC 与第一次离开锚点 digest 的 R-LOCK 约束导出矛盾。

## 4. 与 P1 场景的对应

| 规则 | P1 场景 | 结果 |
| --- | --- | --- |
| 同轮同 Witness 不双签 | S1 / P4 / P7 / R1-B6 | 诚实 Witness 通过 |
| 已 commit 不被冲突替代 | S2 / P2/P3/U1 | P1–P10 通过；U1 失败（timeout 解锁反例） |
| 旧轮签名不重解释 | S4 / R1-B8 | 通过 |
| 重启不回退锁 | S5 / R1-B7 / AL1 | P5/P6/R1-B7 通过；AL1 全损失败 |
| 严格轮次推进 | S6 / R1-C1-A–E | 五项通过 |
| 无解锁 quorum 不可恢复 | P8-B | `not_achieved`，非 fail-closed 成功 |

## 5. 明确不声明

- 本状态机是协议设计草案，不是 Tendermint 完整 round-change 实现；
- 表格中的场景结果是 P1 模拟器证据，不构成 BFT soundness 证明；
- 崩溃安全性、quorum 形成条件、部分同步量化仍属外部工作（见 CRASH-ANALYSIS / SECURITY-ARGUMENT）。
