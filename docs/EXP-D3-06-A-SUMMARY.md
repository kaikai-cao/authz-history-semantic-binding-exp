# EXP-D3-06-A 总结 — Trusted S0 跨结构验证器

## 1. 本轮完成内容

基线 `2e9ca62`，分支 `exp-d3-06-a-s0-validator`。本轮是 **host-only** 实现，不写 Halo2 电路。

新增：

- `src/transition/s0_consistency_v2.rs`：S0 输入模型、三棵树根重算、双向一致性检查、`C_v2` 计算与期望值比较；
- `tests/d3_06_a_s0_consistency.rs`：16 项正负测试，逐项对应用户给出的 1–16 清单；
- `docs/EXP-D3-06-A-BASELINE.md`
- `docs/EXP-D3-06-A-S0-VALIDATOR-SPEC.md`
- `docs/EXP-D3-06-A-SUMMARY.md`

`src/transition/mod.rs` 仅新增一行模块注册。冻结实现零改动：E-R1、E-R2、R3、D3-04、D3-04-R1、D3-05、D3-05-R1 的实现、测试与既有文档均未触碰。

## 2. 验证器行为

核心 API：

```rust
pub fn compute_s0_v2(input: &S0InputV2) -> Result<S0ValidationV2, S0Error>;
pub fn validate_s0_v2(input: &S0InputV2, expected: &S0ExpectedV2)
    -> Result<S0ValidationV2, S0Error>;
```

输入不含缓存 root；验证器从显式 GR/RR/IR preimage 重算：

\[
GR_{root},\quad RR_{root},\quad IR_{root},\quad
C_{v2}=H(D3\text{-}STATE\text{-}v2,GR,RR,IR,epoch,policy).
\]

一致性检查包含两个方向：

1. `GR/RR → IR`：每个 GR ID 必须有 IR 叶，且状态等于 `(id∈RR? REVOKED : ACTIVE)`；
2. `IR → GR/RR`：每个占用 IR 叶的 `full_id` 必须存在 GR 记录。

另含 C0（`R⊆G`）、GR/RR 重复 ID、槽位越界/重复、IR `low_t` 绑定、IR 异 ID 碰撞、非规范 ABSENT、非法 state、零 ID 全入口拒绝。

## 3. 测试结果

```text
cargo test --release
→ 288 passed / 0 failed / 3 ignored

cargo fmt --all -- --check
→ pass

git diff --check
→ pass
```

其中本轮新增测试：

- 模块单测 3 项：`v2_domain_is_distinct_from_frozen_v1`、`low_t_only_uses_low_byte_for_depth_four`、`canonical_empty_leaf_is_stable`；
- 集成测试 16 项：`t01`–`t16`，覆盖合法 ACTIVE/REVOKED、孤立 RR、GR 缺 IR、IR 状态错、幽灵 ACTIVE/REVOKED、GR/RR 重复 ID、IR 截断键碰撞、IR 错槽、IR full_id 不匹配、非规范 ABSENT、三结构零 ID、GR/RR 非 `low_t` 槽位合法接受、篡改根/承诺拒绝。

16 项集成测试逐项对应关系：

| 编号 | 测试 | 结果 |
| --- | --- | --- |
| 1 | `t01_valid_active_grant_is_accepted` | pass |
| 2 | `t02_valid_revoked_grant_is_accepted` | pass |
| 3 | `t03_orphan_revoke_is_rejected` | pass |
| 4 | `t04_grant_without_ir_record_is_rejected` | pass |
| 5 | `t05_grant_and_revoke_with_wrong_ir_state_is_rejected` | pass |
| 6 | `t06_ghost_active_ir_record_is_rejected` | pass |
| 7 | `t07_ghost_revoked_ir_record_is_rejected` | pass |
| 8 | `t08_duplicate_grant_id_is_rejected` | pass |
| 9 | `t09_duplicate_revoke_id_is_rejected` | pass |
| 10 | `t10_ir_truncated_key_collision_is_rejected` | pass |
| 11 | `t11_ir_slot_not_equal_low_t_is_rejected` | pass |
| 12 | `t12_ir_leaf_full_id_mismatch_is_rejected` | pass |
| 13 | `t13_noncanonical_absent_ir_leaf_is_rejected` | pass |
| 14 | `t14_zero_id_is_rejected_in_gr_rr_and_ir` | pass |
| 15 | `t15_gr_rr_slots_need_not_follow_low_t_but_roots_match` | pass |
| 16 | `t16_tampered_root_and_commitment_are_rejected` | pass |

## 4. 重要实现记录

在首次定向测试中，IR 树根重算使用 `std::array::from_fn` 逐层构造，因该宏固定生成 16 个元素而在第二层越界。已修正为 `Vec` + `chunks_exact(2)` 逐层折半；测试独立的期望值计算器也同步修正。该 bug 属于本轮新增代码，未影响任何冻结实现，修正后 16/16 通过。

## 5. 边界声明

`validate_s0_v2` 成功只代表：

- 本地显式 preimage 内部满足跨结构不变量；
- 重算的三根与 `C_v2` 等于调用方提供的期望值。

它**不代表**外部 checkpoint / 签名 / freshness 已建立，不代表 Halo2 安全性已验证，也不代表任意 256-bit ID 映射或深度 4 的 16 槽 IR 支持大规模授权记录。进入 Halo2 原型前必须落实 `S0-VALIDATOR-SPEC.md` §4 的三项义务：同路径旧/新 opening、`pre_ok` 不得绕过 ALLOW、ID 域与容量如实限定；并按 GG/GR/RR 组合重算 IR 置换成本。
