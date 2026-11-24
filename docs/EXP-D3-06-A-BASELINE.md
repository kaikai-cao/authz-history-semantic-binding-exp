# EXP-D3-06-A Phase 0 — 基线冻结与实际接口记录

## 0. 分支核验

执行结果：

```text
git status --short --branch
→ ## exp-d3-05-r1-induction-audit...origin/exp-d3-05-r1-induction-audit（clean）

git rev-parse HEAD
→ 2e9ca62c254af259969f9553dcb54ef15ed1cff0

git rev-parse origin/exp-d3-05-r1-induction-audit
→ 2e9ca62c254af259969f9553dcb54ef15ed1cff0

git rev-parse origin/main
→ 09612dbb26422d14cc5628cb39f7ce444be159b5
```

随后从该提交建立：

```text
git switch -c exp-d3-06-a-s0-validator 2e9ca62c254af259969f9553dcb54ef15ed1cff0
git status --short --branch
→ ## exp-d3-06-a-s0-validator
```

基线 `2e9ca62` 是 D3-05-R1 审查文档提交（前 `81b6d0d`），相对该基线本轮从零新增验证器与测试。`main` 仍停在 D3-01 的 `09612db`，与本系列此前分支策略一致。

**冻结范围**：未修改 E-R1、E-R2、R3、D3-04、D3-04-R1、D3-05、D3-05-R1 的任何实现、测试或既有文档。`src/transition/mod.rs` 仅新增一行 `pub mod s0_consistency_v2;` 注册。

## 1. 实际使用的类型与构树方法

| 结构 | 实际类型 / 函数 | 叶编码 | 节点哈希 | 槽位语义 |
| --- | --- | --- | --- | --- |
| **GR** | `GrantFieldsB` + `SparseTreeB` | `GrantFieldsB::leaf(true)`，9-word Poseidon，域 `D3-GRANT-v1`；已占叶一律 `valid=1` | `SparseTreeB` 内部 `d_node_b()` = `D3-NODE-v1` | 原有 witness slot，深度 4 / 16 槽；不施加 `low_t(id)` |
| **RR** | `RevokeFieldsC` + `revoke_leaf_c` + `SparseTreeB` | `poseidon::<4>([D3-REVOKE-v1, grant_id, revoker, epoch])` | 同 GR，`D3-NODE-v1` | 原有 witness slot，深度 4 / 16 槽；不施加 `low_t(id)` |
| **IR** | 本模块 `IrSlotInputV2` / `ir_root_from_leaves` | 空叶 `poseidon::<3>([D3-INDEX-v1, 0, 0])`；占用叶 `poseidon::<3>([D3-INDEX-v1, full_id, state])`，state 1=ACTIVE / 2=REVOKED | `poseidon::<3>([D3-INDEX-NODE-v1, left, right])` | `slot = low_t(full_id)`，取 `to_repr()[0] & 15`；异 ID 占同槽 fail-closed |

IR 编码沿用 D3-04-R1 `tests/d3_04_r1_index_state.rs` 的域标签与 `Leaf::Empty` 语义；本模块把“规范空”实现为**不在 `index` 列表中登记该槽**，从而不存在同一逻辑 ABSENT 的第二种编码。占用叶写 state=0 会被显式拒绝为 `IrNonCanonicalAbsent`。

## 2. Poseidon 参数

统一使用 `crate::encoding::poseidon`，即 `halo2_poseidon::Hash<F, P128Pow5T3, ConstantLength<L>, 3, 2>`，Pallas Base field，`rate=2`。本轮出现的宽度：

- `L=3`：IR 叶、IR 节点；
- `L=4`：RR 叶（冻结 `revoke_leaf_c`）；
- `L=6`：`C_v2` 状态承诺；
- `L=9`：GR 叶（冻结 `GrantFieldsB::leaf`）。

## 3. 状态承诺接口

冻结 v1（只读查档，未改）：

\[
C_{v1}=H(D_{state}^{v1}=D3\text{-}STATE\text{-}P\text{-}v2,\;GR,\;RR,\;epoch,\;policy)
\quad (5\ words)
\]

本轮新增 host v2：

\[
C_{v2}=H(D_{state}^{v2}=D3\text{-}STATE\text{-}v2,\;GR,\;RR,\;IR,\;epoch,\;policy)
\quad (6\ words)
\]

字段顺序固定如上，不把 IR 插到 GR 之前。`D3-STATE-v2` 与 `D3-STATE-P-v2` 由同一 `domain_field` 派生但标签不同，因此承诺值不可混用。该接口只计算并比对承诺，不实现签名、远程 checkpoint、freshness provider，也不增加 public instance 数量（E-R1 的 8 值冻结未触碰）。

## 4. 新增文件

```text
src/transition/s0_consistency_v2.rs   （新增，host-only）
tests/d3_06_a_s0_consistency.rs       （新增，16 测试）
src/transition/mod.rs                 （仅 +1 行模块注册）
docs/EXP-D3-06-A-BASELINE.md
docs/EXP-D3-06-A-S0-VALIDATOR-SPEC.md
docs/EXP-D3-06-A-SUMMARY.md
```
