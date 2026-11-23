# EXP-D3-03-E — Circuit Design (Phase 1, frozen)

目标：在单个 Halo2 电路中证明两事件顺序状态转换
`S0 --e0--> S1 --e1--> S2`，其中 `Si = (GR_i, RR_i, epoch_i)`，
`e_i ∈ {Grant, Revoke}`，且 **S1 的根完全由 e0 的电路内输出产生并作为 e1 的输入**。

复用 A 的状态承诺与 batch 布局；不修改 A/B/C。域标签、字段编码见
`EXP-D3-03-E-INTERFACE-AUDIT.md`。

---

## 1. 统一事件接口与两槽结构

```
EventWitnessE {
    active: bool,              // 该槽是否承载有效事件
    is_grant: bool,            // 类型选择（受约束；is_grant + is_revoke = active）
    is_revoke: bool,
    // --- Grant 分支 witness ---
    parent: GrantFieldsB,      // e0 的 Parent（或 e1 的 Parent）
    child:  GrantFieldsB,      // 本事件创建的 Grant
    parent_slot, child_slot,
    parent_open: OpeningB,     // 在当前 GR 输入根中打开 parent
    child_old_open: OpeningB,  // 在当前 GR 输入根中打开 child 槽（空叶 0）
    child_new_open: OpeningB,  // 在更新后 GR 中打开 child 槽
    // --- Revoke 分支 witness ---
    target: GrantFieldsB,      // 被撤销的 Grant
    revoke: RevokeFieldsC,
    target_slot, revoke_slot,
    target_open: OpeningB,     // 在当前 GR 输入根中打开 target
    rr_old_open: OpeningB,     // 在当前 RR 输入根中打开撤销槽（空叶 0）
    rr_new_open: OpeningB,     // 在更新后 RR 中打开撤销槽
}
TransitionWitnessE {
    gr_prev_be, rr_prev_be,    // 仅 S0 两根来自 witness（做规范编码检查）
    prev_epoch, next_epoch,
    events: [EventWitnessE; 2],
    event_count,               // 1 或 2
}
```

`MAX_ACTIVE_EVENTS = 2`。第二槽 padding 时 `active_1 = 0`、`is_grant_1 = is_revoke_1 = 0`，
所有分支 witness 填**自洽的合法 dummy**（parent = child，epoch 相等），使无条件语义门天然满足；
关键跨值绑定由 gated 门按 `is_grant`/`is_revoke` 关闭。

---

## 2. 状态根：S0 解码、S2 电路内产生

- `gr_prev`、`rr_prev`：由 witness 的 32 字节经 A 的规范编码 gadget 解码（bytes < p 完全在电路内检查）。
- **S1、S2 的 GR/RR 根不来自 witness**：它们由 Merkle opening 的 Poseidon 重算 cell 产生。
- `C_prev = Poseidon(D_STATE, gr_prev, rr_prev, prev_epoch, policy)`（A 规则，电路内重算）。
- `C_next = Poseidon(D_STATE, gr2, rr2, next_epoch, policy)`，其中 `gr2/rr2` 是 e1 输出的状态 cell。
- 因此 prover 不能通过"提供两个碰巧满足的 S2 根字节"伪造最终状态——最终根由中间状态链唯一决定。

---

## 3. Cell 连接规则（本阶段最重要的实现约束）

维护每步的"状态线"：输入 `(gr_in, rr_in)`、输出 `(gr_out, rr_out)`。
`step0` 输入 = S0 解码根；`step1` 输入 = **step0 输出的同一批 cell**（通过 state-wire region 的
`constrain_equal` 连接，而非重新读取 witness）。

每步的状态转移用无条件算术门（`state-transition`）：

```
gr_out = is_grant · gr_gnew + (1 - is_grant) · gr_in
rr_out = is_revoke · rr_rnew + (1 - is_revoke) · rr_in
```

- `gr_gnew`：e 的 Grant 分支 child-new-opening 重算根（把 child leaf 插入 `gr_in`）。
- `rr_rnew`：e 的 Revoke 分支 rr-new-opening 重算根（把 revoke leaf 插入 `rr_in`）。
- 未被事件修改的树根保持相等：Grant 事件 `rr_out = rr_in`，Revoke 事件 `gr_out = gr_in`（由上式自动成立）。
- **Grant+Revoke 核心场景**：e0 的 `gr_out` cell 直接成为 e1 的 `gr_in`；e1 的 Revoke Grant opening
  用 gated 门绑定到该 cell，而非 S0 根。攻击"e1 打开旧 GR"会因 gated-eq 失败被拒。

### 3.1 受约束的类型选择与连续性

```
active, is_grant, is_revoke ∈ {0,1}            // 三个 boolean 门
is_grant + is_revoke = active                   // type-split 门（穷尽且互斥）
active_1 · (1 - active_0) = 0                   // prefix-monotone：禁止 [0,1]
event_count = active_0 + active_1               // count 门；instance[7] 绑定同一 cell
```

### 3.2 gated-eq 门（门控的跨 cell 相等）

Halo2 0.4 的 `copy_equal` 是无条件置换，不能门控。E 新增"gated 相等"门：
查询三列 `gate_flag, gate_l, gate_r`（`Rotation::cur()`），约束 `flag·(l − r) = 0`。
helper `gated_eq(flag, left, right)` 在一个共享 region 内把三个外部 cell 用
`constrain_equal` 拷入三列并启用该门。跨 Region cell 连接由此成立（不比较 Rust `Value`）。

各语义绑定的门控（flag = is_grant 或 is_revoke）：

**Grant 分支（flag = is_grant）**
- `parent_opening.root == gr_in`（parent 确实存在于当前 GR）
- `child_old_opening.root == gr_in`（child 槽当前为空，ID 未占用）
- `child.parent_key == parent.id`、`child.issuer == parent.subject`
- `child.epoch == next_epoch`；scope 子集、resource 前缀相等、epoch≥parent（64-bit 门）
- child-new-opening 与 child-old-opening 逐层 copy `(dir, sibling)`（同一槽、仅叶变化）

**Revoke 分支（flag = is_revoke）**
- `target_opening.root == gr_in`（目标 Grant 确实存在于当前 GR）
- `revoke.grant_id == target.id`、`revoke.revoker == target.issuer`
- `revoke.epoch == next_epoch`；目标 Grant `valid = 1`
- `rr_old_opening.root == rr_in`（旧撤销槽为空，未撤销过）
- rr-new-opening 与 rr-old-opening 逐层 copy `(dir, sibling)`

**Epoch（批次统一递增一次）**
- `next_epoch − prev_epoch − 1 = 0`（field gate，沿用 C 的 `epoch-plus-one`）
- 所有 active 事件的 epoch cell 均 copy 到 `next_epoch`（Grant 的 child.epoch、Revoke 的 revoke.epoch），
  故 e0/e1 使用同一 epoch，第二个事件不再 +1。

### 3.3 padding 约束

- 三槽 batch（`MAX_EVENTS=3`）：slot0 = e0 承诺、slot1 = e1 承诺、slot2 恒 `batch_pad`。
- `slot-padding` 门：`(1 − active_i)·(slot_i − pad) = 0`（沿用 A，A 的 active 数组按 `i<event_count` 生成，
  E 改为直接取 `active_0, active_1` 并令 `active_2 = 0`）。
- `active-prefix` 门：禁止第一个槽 inactive 而第二个 active。
- 事件承诺在电路内从事件字段重算：`c_grant`（9 词）、`c_revoke`（5 词）；
  `is_grant·(c_grant_i − slot_i) = 0`、`is_revoke·(c_revoke_i − slot_i) = 0`。
- `D_E = Poseidon<5>(D_BATCH, n, slot0, slot1, slot2)` 电路内重算，不接受 witness 直接给的 D_E。

---

## 4. Public instance（A 的 8 个，原样保留）

`0 C_prev, 1 prev_epoch, 2 C_next, 3 next_epoch, 4 policy_id,
5 transition_version, 6 D_E, 7 event_count`。`event_count ∈ {1,2}`。

---

## 5. 支持的组合（E1/E2/E3 统一在同一电路）

| 组合 | e0 | e1 | S0→S1 | S1→S2 |
| --- | --- | --- | --- | --- |
| E1 Grant+Grant | Grant(A, 根) | Grant(B, parent=A) | GR 插 A，RR 不变 | GR 插 B（打开 S1 的 A），RR 不变 |
| E2 Grant+Revoke | Grant(A) | Revoke(A) | GR 插 A，RR 不变 | GR 不变，RR 插 revoke（打开 S1 的 A） |
| E3 Revoke+Revoke | Revoke(A) | Revoke(B) | GR 不变，RR 插 revokeA | GR 不变，RR 插 revokeB（打开 S1 的 RR） |
| 单事件 | 有效事件 | padding | 正常 | 无状态变化（active_1=0） |

"第二个 Grant 用 S0 的 Parent Opening" / "Grant+Revoke 用旧 GR" /
"Revoke+Revoke 用旧 RR" 三类攻击均因 gated 根绑定指向 S1 cell 而被拒。

---

## 6. 诚实边界与不声明

- 不证明 ALLOW/DENY、完整授权历史、canonical slot 规范性、Bridge/checkpoint 可信性、执行时新鲜性。
- 类别 II SHA-256 字段映射仍是外部信任；不实现 Cascade、递归、三事件、Batch Update。
- 本电路证明的是"给定 S0 根与两事件，按 Sequential 规则得到 S2"的关系，
  不是"所有授权当前有效/无效"的全局结论。
- `k` 是工程决策（继承 A 的 12，必要时上调），不是原始设计参数；未逐门统计约束数。
