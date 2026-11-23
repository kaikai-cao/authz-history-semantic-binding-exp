# EXP-D3-03-E — Interface Audit (Phase 0)

基线：`b9a8fc7f0e66119f23877317836d70d01b174c1b`（分支 `exp-d3-03-e` 由 `exp-d3-03-d-design` 创建）。
审计对象：A（`circuit.rs`）、B（`b_circuit.rs`）、C（`c_circuit.rs`）、D 参考模型（`src/reference/mixed_event_state.rs`）与 D 冻结规格。
所有结论均给出源码位置；无法从代码确认的项标注 `UNKNOWN`。本审计未修改任何 A/B/C 文件。

---

## 1. 域标签分歧（E 阶段首要任务）

任务书指出的三个标签 `D3-BATCH-v1` / `D3-EVENT-v1` / 旧 `...-P-v2` 已逐一核对实际调用链：

| 用途 | 代码冻结值 | 源码位置 | 结论 |
| --- | --- | --- | --- |
| State commitment | `D3-STATE-P-v2` | `src/transition/constants.rs:24-26` `d_state()` | 一致，非漂移项 |
| Batch commitment | `D3-BATCH-v1` | `src/transition/constants.rs:29-31` `d_batch()` | **以代码为准** |
| Batch padding | `D3-BATCH-PAD-v1` | `src/transition/constants.rs:36-38` `batch_pad()` | 一致 |
| Grant event / Revoke event | `D3-EVENT-v1` | `src/transition/b_constants.rs:21-23` `d_event_b()`；C 复用同一函数（`c_circuit.rs:699`） | **以代码为准** |
| Grant leaf | `D3-GRANT-v1` | `b_constants.rs:13-15` `d_grant_b()` | 一致 |
| Merkle node | `D3-NODE-v1` | `b_constants.rs:17-19` `d_node_b()` | 一致 |
| Revoke leaf | `D3-REVOKE-v1` | `src/encoding.rs:20` `DOMAIN_REVOKE`；`c_constants.rs:18-20` `d_revoke_c()` | 一致 |

旧 `D3-BATCH-P-v2` / `D3-EVENT-P-v2` 仅出现于两份**过时的 R1 文档**：
- `docs/d3_02_public_statement.md:230`
- `results/d3_02_r1_design_summary.md:181`

它们与全部源码冻结值冲突，且 `EXP-D3-03-D-SOURCE-AUDIT.md:87,162,170` 已明确"E 沿用代码冻结值、把该分歧列为兼容性风险"。

**结论：这是 R1 旧文档未同步 R2 冻结的命名漂移，不是源码冲突。** E 采用代码冻结值
`D_BATCH = D3-BATCH-v1`、`D_EVENT = D3-EVENT-v1`、`D_STATE = D3-STATE-P-v2`、
`D_PAD = D3-BATCH-PAD-v1`。不修改 A/B 常量，因而不改变 `policy_id` / `circuit_spec_digest`
（`constants.rs:48-116`，其中 tags 数组 `:54-61` 已冻结这些值）。

D 参考模型使用**独立命名空间** `D3D-*-v1`（`mixed_event_state.rs:194,210,223,455`）的 SHA-256 摘要，
文件头 `:9-12` 明确声明"不是 Halo2 batch commitment、不声称与 B/C 字段编码字节兼容"。
因此 D 模型只作**语义差分基准**，E 电路按字段级冻结编码实现，二者不做字节级兼容声明。

---

## 2. 事件编码定义（E 采用的实际方案）

| 事件 | 电路内承诺（Poseidon 输入顺序） | 输入词数 | 域标签 | TYPE |
| --- | --- | --- | --- | --- |
| Grant | `d_event, TYPE_GRANT(1), id, issuer, subject, resource_prefix_f, scope, parent_key, epoch` | 9 | `D3-EVENT-v1` | 1（`b_constants.rs:33`） |
| Revoke | `d_event, TYPE_REVOKE(2), grant_id, revoker, epoch` | 5 | `D3-EVENT-v1` | 2（`c_constants.rs:15`） |

源码证据：Grant `b_types.rs:55-68` / `b_circuit.rs:966-981`；Revoke `c_types.rs:32-40` / `c_circuit.rs:896-907`。
两种事件**共用同一 event 域但 type tag 不同**，因此类型混淆会在承诺层被区分。

Batch 承诺布局（A/B/C 一致）：`D_E = Poseidon<5>(d_batch, n, slot0, slot1, slot2)`，
`MAX_EVENTS=3`（`constants.rs:19`），数组长度 `MAX_EVENTS+2=5`（`circuit.rs:526-531`）。
E 固定两槽有效事件，第三槽恒为 `batch_pad`；`n = active_0 + active_1 ∈ {1,2}`。

> UNKNOWN：D 规格 `EXP-D3-03-D-PROTOTYPE-SPEC.md:59,148` 写作
> `D_E = Poseidon(D_BATCH, n, c1, c2, pad)`，与代码的三槽字面布局语义一致
> （n≤2 时第 3 槽为 pad），但规格与代码未逐字对照。E 以**代码冻结的三槽布局**为准。

---

## 3. 可复用组件与"新增接口"判定

审计发现 A/B/C 的可复用逻辑**全部是私有 `fn`**，且 `mod.rs` 未重导出：

| 组件 | 位置 | 可见性 | E 能否直接调用 |
| --- | --- | --- | --- |
| A `hash_words::<N>` | `circuit.rs:179-191` | 私有 | 否 |
| A `assign_root_encoding` | `circuit.rs:117-177` | 私有 | 否 |
| B `assign_opening_path` | `b_circuit.rs:338-383` | 私有 | 否 |
| B `assign_grant_words` | `b_circuit.rs:295-328` | 私有 | 否 |
| C `assign_opening_path` / `assign_grant_words` | `c_circuit.rs:302` / `265` | 私有 | 否 |
| 跨区 `copy_equal` | `b_circuit.rs:139-149`、`c_circuit.rs:134-143` | 私有 | 否 |

可直接复用的是**公开常量与类型**（`mod.rs:17-37` 重导出）：
`d_state/d_batch/batch_pad/policy_id/transition_version/MAX_EVENTS/K`、
`d_grant_b/d_node_b/d_event_b/TYPE_GRANT`、`d_revoke_c/TYPE_REVOKE`、
`GrantFieldsB/OpeningB/SparseTreeB/recompute_root_b/node_hash_b`、
`RevokeFieldsC/revoke_leaf_c/revoke_event_commitment_c`、`TransitionInstances`。

**判定**：E 不修改任何 A/B/C 源码（避免触碰冻结向量与 vk），而是在 `src/transition/e_*.rs`
独立实现同语义的门与 gadget。这与 B、C 相对 A 的既有做法一致（各自独立电路、共享常量）。
E 复用的是"冻结语义与常量"，不是"可调用的 Rust 函数"。

---

## 4. 中间状态连接方式（源码可行性）

Halo2 0.4 无 `Layouter::constrain_equal`；项目既有机制是
`layouter.assign_region(|| ..., |r| r.constrain_equal(a.cell(), b.cell()))`
（`b_circuit.rs:139-149`、`c_circuit.rs:134-143`），前提是列已 `enable_equality`
（A `circuit.rs:251-256`、B `b_circuit.rs:454-460`、C `c_circuit.rs:414-420`）。

**跨 Region 的 cell 连接是可行的**（B/C 的新旧 opening 路径 copy 已大量使用）。
E 据此把 step0 的输出根 cell 通过 `copy_equal`（或 gated 算术门，见设计文档）绑定到 step1 的输入根 cell。

**关键实现差异**：B/C 的 opening 根被硬绑定到 witness 解码的 `gprev/gnext/rprev/rnext`
（`b_circuit.rs:927,938,963`；`c_circuit.rs:857,867,889,893`）。E 的中间根是
**电路内 Poseidon 重算值**，不能来自 witness bytes；因此 E 的状态根绑定必须走
gated 算术门，而不是 B/C 那种无条件 `copy_equal`。详见 `EXP-D3-03-E-CIRCUIT-DESIGN.md`。

---

## 5. 8 个 public instance（原样保留）

定义 `src/transition/types.rs:41-53`：`TransitionInstances`，`COUNT = 8`。顺序：
`0 C_prev, 1 prev_epoch, 2 C_next, 3 next_epoch, 4 policy_id, 5 transition_version,
6 D_E, 7 event_count`。E 不改此顺序。C_prev/C_next 仍按 A 的
`Poseidon(D_STATE, GR, RR, epoch, policy)`（`types.rs:133-147`）在电路内重算。
区别：E 的 `C_next` 由电路内两步演化的最终根计算，而非 witness bytes 解码。

---

## 6. 需要新增的 E 接口汇总

1. `e_constants.rs`：复用 A/B/C 常量；新增 `MAX_ACTIVE_EVENTS = 2`、`TYPE_GRANT/TYPE_REVOKE` 的重导出。
2. `e_types.rs`：`EventWitnessE`（type tag + active + Grant/Revoke 两套字段与 openings）、
   `TransitionWitnessE`（仅 S0 根字节 + epochs + 2 事件 + count）、off-circuit 场景构造器。
3. `e_circuit.rs`：两槽 sequential 电路——类型选择布尔门、active 连续与 count、
   Grant/Revoke 条件门控、S1 中间根 cell 连接、epoch 批次 +1、batch/padding、8 instance。

---

## 7. 尚未解决的问题 / UNKNOWN

- D 规格 `D_E` 字面写法与代码三槽布局的逐字等价性（见 §2 UNKNOWN），E 以代码为准。
- `Grant + Revoke` 第二步打开"刚创建 Grant"所需的中间 GR opening witness 需由
  off-circuit 参考树构造（D 参考模型 `apply_batch` 可作 oracle），但**电路只信任
  step0 输出的 GR 根 cell**，不信任 host 计算的 S1。
- 类别 II SHA-256 字段映射、canonical slot 分配、Bridge/checkpoint、执行时新鲜性仍是外部信任，未变。
- 本阶段不证明 ALLOW/DENY、完整历史、Cascade、递归或跨 VK 重放防护。

## 8. 停止条件检查

逐条核对任务书 §11：B/C 事件编码可在 E 中统一（§2）；A 8 instance 无需改（§5）；
中间 GR/RR 打开可用电路内根（§4，待实现验证）；第二事件输入由 cell copy（§4）；
active 连续由门约束（设计文档）；Parent/Child 与 D 规则一致（D 已冻结）。
**未触发任何停止条件**，可直接进入 Phase 1。
