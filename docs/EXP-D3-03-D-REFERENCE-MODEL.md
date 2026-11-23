# EXP-D3-03-D — Phase 3 独立参考状态机

**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**实现语言**：Rust
**文件**：

- `src/reference/mod.rs`
- `src/reference/mixed_event_state.rs`
- `tests/d3_03_d_reference.rs`
- `src/lib.rs` 仅新增 `pub mod reference;` 注册

---

## 1. 独立性声明

参考状态机**不调用**：

- Halo2 / MockProver / create_proof / verify_proof；
- `src/transition/` 下任何 B/C 电路或 witness 生成函数；
- D3-01 的字段编码、Poseidon 叶子或固定向量。

它直接使用 `Id=u64`、BTreeMap 和 SHA-256 规范化字节编码，只验证 `docs/EXP-D3-03-D-STATE-MACHINE.md` 冻结的设计语义。模型摘要 `D3D-MIXED-BATCH-v1` 仅用于顺序/类型/负载敏感性测试，**不是** Halo2 的 `D_E`，也不声称与 B/C 的 Poseidon field 承诺字节兼容。

---

## 2. 核心数据结构

```text
GrantEvent  = (id, issuer, subject, resource_prefix[8], scope:u64, parent:Option<id>, epoch:u64)
RevokeEvent = (grant_id, revoker, epoch:u64)
Event       = Grant(GrantEvent) | Revoke(RevokeEvent)

State = {
  grants:  BTreeMap<Id, GrantEvent>,
  revokes: BTreeMap<Id, RevokeEvent>,
  epoch:   u64,
  event_count: u64,
  gr_slots: BTreeMap<Id, usize>,
  rr_slots: BTreeMap<Id, usize>,
}
```

`State::is_valid(id) = grants.contains(id) && !revokes.contains(id)`。

这实现了 D 阶段的核心语义选择：DirectOnly 撤销不改变 GR 根，但通过 RR 改变逻辑有效性。

---

## 3. 执行接口

```rust
pub fn apply_batch(initial: &State, events: &[Event]) -> TransitionOutcome
```

`TransitionOutcome` 输出：

- `initial_root` / `batch_digest`；
- `intermediate_states`：每个成功事件后的状态；
- `event_results`：每个事件的接受/拒绝原因、GR/RR 根前后值；
- `final_state` / `final_root`：仅整批成功时存在；
- `rejection`：失败时的 `(index, reason)`。

拒绝时 `final_state=None`，不产生部分成功输出；前序中间状态只作诊断保留。

批次执行前检查：

- `events.len() ≤ MAX_EVENTS (=3)`；
- `initial.epoch.checked_add(1)` 不溢出；
- 每个事件的 epoch 必须等于该批次 epoch。

---

## 4. 事件规则实现

### Grant

1. ID 不在当前 `grants`，否则 `DuplicateGrant`；
2. 若有 Parent：当前 `grants` 存在、当前 `is_valid(parent)`、issuer=parent.subject、scope 子集、resource 前 8 字节相等、epoch 不小于 parent；
3. depth=4 容量 16，线性探测得到当前空槽；
4. 更新 GR 根与 `event_count`，RR 不变。

### Revoke

1. `grant_id` 在当前 `grants`，否则 `GrantNotFound`；
2. `grant_id` 不在当前 `revokes`，否则 `AlreadyRevoked`；
3. `revoker` 等于 grant 的 issuer，否则 `RevokerNotAllowed`；
4. RR 写入撤销记录，GR 不变。

### 批次承诺

`batch_commitment(events)` 使用显式字节编码，绑定：

- 事件数；
- 每个事件的 type tag（Grant=`0x01`，Revoke=`0x02`）；
- 全部 payload 字段；
- 事件在列表中的位置。

---

## 5. 测试覆盖

测试文件：`tests/d3_03_d_reference.rs`
运行结果：**42 passed / 0 failed**

### 5.1 基础序列（6）

- `s01_single_grant_accepted`
- `s02_revoke_existing_grant_accepted`
- `s03_two_grants_accepted`
- `s14_two_revokes_accepted`
- `empty_state_roots_are_deterministic_and_distinct`
- `event_count_matches_accepted_events`

### 5.2 混合序列（7）

- `s04_grant_then_revoke_accepted`
- `s05_grant_grant_revoke_first_accepted`
- `s06_grant_revoke_grant_accepted`
- `s07_revoke_then_grant_accepted`
- `s08_grant_grant_revoke_second_accepted`
- `s15_grant_and_unrelated_revoke_accepted`
- `grant_then_revoke_changes_validity_without_deleting_grant_record`

### 5.3 父子依赖（7）

- `s12_parent_then_child_accepted`
- `s11_child_before_parent_rejected`
- `s13_parent_revoked_then_child_rejected`
- `parent_scope_escalation_rejected`
- `parent_resource_prefix_mismatch_rejected`
- `parent_issuer_mismatch_rejected`
- `parent_epoch_regression_rejected`

### 5.4 重复与冲突（5）

- `s09_duplicate_revoke_rejected`
- `s10_duplicate_grant_rejected`
- `duplicate_grant_after_revoke_rejected`
- `grant_capacity_exhausted_rejected`
- `too_many_events_rejected`

### 5.5 状态边界（5）

- `epoch_mismatch_rejected`
- `batch_epoch_applies_to_all_events`
- `empty_tree_grant_root_changes_on_grant`
- `revoke_does_not_change_grant_root`
- `rejection_does_not_produce_final_state`

### 5.6 事件编码（4）

- `type_tag_change_changes_batch_digest`
- `event_order_change_changes_batch_digest`
- `payload_change_changes_batch_digest`
- `event_count_change_changes_batch_digest`

### 5.7 性质测试（6）

- P1：`p1_dependent_events_are_order_sensitive`、`p1_independent_grants_commute`
- P2：`p2_prefix_validity_matches_intermediate_states`
- P3：由 5.6 四个 digest 测试覆盖
- P4：`p4_rejected_batch_has_no_partial_final_state`
- P5：`p5_independent_revokes_commute`
- P6：`p6_duplicate_revoke_is_rejected_not_idempotent`

### 5.8 与 B/C 的差分语义检查（2）

- `diff_b_single_grant_semantics_match_reference`
  - 用 `sample_witness_b()` 对照 Parent/Child 的 scope、resource prefix、epoch 和 batch 数量；
  - 语义一致，但 witness 中的 `F` 域字段不与该模型的 `u64` 标识做字节级比较。
- `diff_c_single_revoke_semantics_match_reference`
  - 用 `sample_witness_c()` 对照 `prev_epoch=10`、`next_epoch=11`、`event_count=1`、GR 根不变、RR 根变化；
  - 语义一致，但 C 的域元素 revoke leaf 与模型 SHA-256 摘要不兼容。

---

## 6. S01–S15 覆盖确认

S01–S15 全部有独立测试或由组合测试直接覆盖：

- S01/S02/S03/S04/S05/S06/S07/S08/S09/S10/S11/S12/S13/S14/S15 均有 `sNN_` 前缀测试；
- 每个测试的 `docs/EXP-D3-03-D-STATE-MACHINE.md` 预期结论与实测 `accepted/rejection` 对齐；
- Revoke 步的 `grant_root_before == grant_root_after` 在 `revoke_does_not_change_grant_root` 与 `grant_then_revoke...` 中断言。

---

## 7. 已知边界

- 参考模型不是 Halo2 约束证明；
- 模型摘要不是密码学承诺，只用于敏感性测试；
- 未复现 B/C 的 Pallas field 编码、Poseidon 节点哈希、类别 II SHA-256 映射；
- 未证明 canonical slot 的全局规范性；
- 不做 Bridge/checkpoint/freshness 建模；
- 依赖分析只以固定测试体现，尚未形成通用证明规则。
