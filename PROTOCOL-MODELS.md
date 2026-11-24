# PROTOCOL-MODELS.md

本文件定义 A/B/C 三种恢复模型在模拟器中的**最小状态机**。它们是对协议思想的对照抽象，不是 Tendermint 或 HotStuff 的完整实现，也不继承其安全证明。

## 0. 公共对象

### Checkpoint

```text
(chain_id, witness_set_id, epoch, checkpoint_digest,
 parent_digest, transition_version)
```

- `lock_key = (chain_id, witness_set_id, epoch)`；
- 两个 checkpoint 若 `lock_key` 相同而 `checkpoint_digest` 不同，则互为 sibling conflict；
- QC/FC 必须绑定完整 checkpoint 字段；模拟器中以 `full_key` 表示。

### Vote

```text
(kind, witness, round, checkpoint, issued_at, expires_at?, nonce?)
```

`kind ∈ {candidate, prevote, precommit, fc}`。轮次、checkpoint、nonce 都进入绑定；旧轮签名不能在新轮重新解释。

### Gateway

Gateway 只根据自己收到的 Vote 做 QC/FC 判定。它没有全局可见性；这是 P3 的核心。

## 1. Model A — Permanent Pending Lock

### 状态

每个 Witness 持久化：

```text
pending[lock_key]  = (digest, round, expires_at?)
committed[lock_key] = digest
signed_votes[]      = Vote...
```

### 规则

1. 签名候选前写入 `pending`；
2. 同一 `lock_key` 下，若存在不同 digest 的 pending，则拒绝签名；
3. timeout 不释放 pending；
4. 只有显式 `trusted_recovery` 可以清除 pending；
5. 重启时从持久化状态恢复 pending；若 signed_vote 日志仍在但 pending 记录丢失，可从日志重建；
6. 若 pending 与 signed_vote 日志同时丢失，本地无法推断遗忘状态，S5 可能失败（AL1）。

### 安全/活性边界

- 安全：拒绝本地双签，但**不能证明 QC 不存在**；
- 活性：一个未完成候选可永久阻塞旧状态；
- 假设：持久化锁可信；可信恢复流程存在；
- 结论标签：规则推导 + 模拟器验证。

## 2. Model B — Tendermint-style Round and Lock Reference

参照：

- Tendermint 共识规范（用户提供）：<https://docs.tendermint.com/master/spec/consensus/consensus.html>
- HotStuff 的 `prepareQC` / `lockedQC` 状态组织思想（作为对照，不作为实现来源）。

### 状态

每个 Witness 持久化：

```text
locked[lock_key]    = (round, digest)
committed[lock_key] = digest
signed_votes[]      = Vote...
```

易失：

```text
current_round
observed_votes[]
polc[]              # (lock_key, round, digest)，由 >=3 个 prevote 形成
```

> **R1 修正**：R0 的规则把锁转移条件写反了（`round > locked_round` 时无需 PoLC 就允许冲突
> prevote；`round <= locked_round` 时反而允许同轮 PoLC 解锁）。R1 按 Tendermint 规范改为
> 严格三段不等式，并显式区分五个状态量：
>
> ```text
> current_round   : 由 timeout 推进的当前轮次
> locked_round    : 持久化锁的轮次（precommit 时写入）
> locked_digest   : 持久化锁绑定的 digest
> polc_round      : 观察到 3-of-4 prevote 集合的轮次
> polc_digest     : 该 PoLC 绑定的 digest
> ```
>
> 禁止混用 `polc_round` 与 `current_round`。

### 规则（R1）

1. `prevote`：
   - 无锁或锁的 digest 与提案相同：允许；
   - 已锁定冲突 digest：只有当存在 PoLC 满足
     `locked_round < polc_round < current_round`，且该 PoLC 绑定同一 chain/witness_set/epoch
     与不同 digest 时，才允许解除原锁并 prevote 新 digest；
   - **仅进入更高轮次不允许改变锁定目标；同轮或低轮 PoLC 不允许解锁**（R1-B1/B2/B4）；
   - 同轮同 Witness 不得对两个冲突 digest prevote（S1）。
2. `precommit`：
   - 必须观察到**同一轮次、同一 checkpoint** 的精确 PoLC（旧轮 PoLC 不复用，R1-B8）；
   - 若已锁定冲突 digest，还须满足同一严格解锁不等式；
   - 自己必须在该轮次 prevote 过同一 checkpoint；
   - 先写持久化 `locked`，再追加投票日志，两者都在返回签名前完成（仅模拟器状态纪律，
     不声称 crash-safe storage）。
3. `timeout`：
   - 只推进 `current_round`；
   - 不清除 `locked`，不单独构成解锁证明。
4. `PoLC`：
   - 由至少 3 个**不同** Witness 的同轮同 digest prevote 形成；
   - Witness 自己的投票与收到的消息合并统计，按 `(witness, vote.binding())` 去重（R1-B5）；
   - 单个签名或单方观察不构成 PoLC。
5. Gateway QC：
   - 至少 3 个同轮、同 checkpoint 的 precommit；
   - 旧轮 precommit 不计入新轮 QC（S4）；
   - 冲突已提交 checkpoint 被拒（S2）。
6. FC：
   - Witness 若观察到更高轮、冲突 checkpoint 的 PoLC，拒绝为旧 digest 签 FC；
   - Gateway 要求 3 个绑定同一 checkpoint 与 nonce 的 FC 签名。
7. 重启：
   - 完整状态恢复时保留 `locked_round` / `locked_digest`（R1-B7）；
   - pending 记录丢失时，从 signed precommit 重建 locked；
   - 若所有持久化投票状态丢失，本模型无法本地恢复，属外部假设（AL1）。

### 明确不声明

- 不是完整 Tendermint；
- 没有实现 proposal 选举、完整投票门限、证据传播、validator set 轮换、equivocation slashing；
- 不声称继承 Tendermint/HotStuff 的安全证明；
- 只比较“锁何时可以转移”这一条协议结构。

### 结论标签（R1）

由协议规则推导 + 模拟器验证；活性仍依赖最终通信与解锁 quorum 的形成条件。
R1-B1–B8 验证严格锁转移；P8-B 显示锁定节点无解锁 quorum 时不可恢复。

## 3. Model C — Bounded Lease

### 状态

每个 Witness 持久化：

```text
pending[lock_key] = (digest, round, expires_at)
committed[lock_key] = digest
signed_votes[] = Vote...
```

Gateway 使用时间 `now_g`，Witness 使用 `now_w = global_time + clock_offset`。

### 规则

1. 候选签名绑定 `proposal_round` 与 `expires_at`；
2. QC 必须由同轮、同 checkpoint 的有效签名构成；
3. Gateway 接受条件：

```text
now_g + epsilon >= issued_at
now_g - epsilon <= expires_at
```

4. Witness 只有在本地时间 `now_w > expires_at + epsilon` 且无已提交冲突时，才允许释放旧 pending；
5. 租约过期后，旧签名不得组成新 QC；
6. 时钟回拨或不可用不是安全释放依据；
7. 重启需要持久化 pending 与 signed_vote 日志。

### 边界

- 不把本地系统时间视为天然可信时钟；
- CK1/CK2 验证“提交时刻”而非“本地形成时刻”决定有效性；
- CK3 验证 epsilon 边界；
- CK4/CK7 显示时钟回拨/不可用会破坏租约语义；
- CK5/CK6 验证旧轮/过期签名不混入或被重放。

### 结论标签

已由模拟器验证；可信单调时钟与 epsilon 仍是外部假设。

## 4. 对照乌托邦/反例模型：UNSAFE timeout unlock

该模型只用于 U1 反例：Witness 本地 timeout 后直接清除 pending 并允许改签。它不是候选方案，只用于说明：

```text
Timeout ≢ No QC exists
```

U1 中该策略使两个诚实 Witness 在已提交 checkpoint 后改签冲突 checkpoint，触发 S2 失败。
