# EXP-D3-03-E-R2 — 初始状态唯一性不变量边界分析

**基线**：`edf4b06401f0431a85978904e2ccae1cccc5d076`
**分支**：`exp-d3-03-e-r2`
**范围**：只分析 S0 唯一性不变量的验证责任与成本，不修改 E-R1 电路、A/B/C/D/E、8 个 public instances 或事件数。

---

## 1. 问题定义

E-R1 电路证明的是**状态转换约束**：

- 新 Grant ID 不等于当前 GR 扫描中任何非空叶子 ID；
- 新 Revoke ID 不等于当前 RR 扫描中任何非空叶子 ID；
- Parent 不在当前 RR 扫描中；
- 第二事件输入根绑定第一事件输出根。

它并**不**单独证明“当前 GR/RR 中所有已有记录两两唯一”。如果 S0 本身已经含有两个相同 ID 的非空叶子，E-R1 的扫描仍可重建根，且新事件只要不匹配该 ID 就不会触发 `scan-id-neq`。因此初始状态唯一性必须作为显式前提或额外约束处理。

R2 还修正了一个独立的接口缺口：E-R1 builder 只接收 `initial_rr_slots: [F; TREE_CAPACITY]`，却以空 `rr_records` 构造扫描 witness，无法为非零历史 RR 提供叶子 preimage。R2 现在要求通过 `InitialRrState::from_preimages(&[(usize, RevokeFieldsC)])` 显式提供完整记录，并用 `revoke_leaf_c` + `SparseTreeB` 重建根；仅给哈希的 `from_slots` 遇到非零槽位返回 `MissingPreimage`。

---

## 2. 方案 A：可信初始状态锚定（本轮采用）

**定义**：S0 的 GR/RR 唯一性由外部可信来源保证，例如：

1. genesis 状态由受控程序构造；或
2. S0 是此前已验证状态转换证明链的末状态（如 D1 checkpoint + 连续有效转换）。

在此前提下，电路只需要归纳地证明：若 S0 满足不变量，则 S2 也满足不变量。这正是 E-R1 的 `scan-id-neq` 提供的内容。

**R2 的 host 侧前置检查**：

- `check_initial_rr_unique`：拒绝 RR 重复槽位、重复 grant_id、越界槽位；
- `build_scenario_r2` 内部的 `check_initial_gr`：对初始 GR 做同样的槽位/ID 检查；
- `InitialRrState::from_slots`：拒绝“只有哈希、没有 preimage”的非零 RR 输入；
- builder 重算 RR root 并与 `rr_prev_be` 解码结果比较，不一致返回 `RootMismatch`。

这些检查在构造 witness 时执行，不是电路约束。它们阻止 builder 接受明显的非法输入，但不能替代 verifier 对外部 root 的信任判断。

**信任边界**：如果 verifier 只看到任意外部提供的 `C_prev/rr_prev_be`，而没有 S0 来源证明，则方案 A 不成立。此时必须要求调用方承诺 S0 来自可信锚定，或采用方案 B / 独立初始状态证明。

**成本**：0 个新增电路约束；K、proof size、public instances 均不变。历史 RR 真实 proof 实测 K=15、proof 8160 B、prove 32987 ms、verify 484 ms，与 E-R1-GR 同量级。

---

## 3. 方案 B：电路内 pairwise uniqueness（本轮不采用）

**定义**：在电路中额外证明任意两个非空初始记录 ID 两两不等。对 n 个非空记录，需要检查 `n(n-1)/2` 对。

复用 E-R1 的 ID 不等 gadget 时，每对需要一个逆元 witness `inv` 和一个 `fl·bf·((a-b)·inv−1)=0` 门。若对 GR 与 RR 都做，则初始状态检查量约为两次 pairwise。

### 最小实验：host 侧配对计数

`initial_rr_pairwise_checks(n)` 已实现并由单元测试验证：

| 非空初始 RR 记录数 n | pairwise 比较数 |
| --- | --- |
| 0 | 0 |
| 2 | 1 |
| 4 | 6 |
| 8 | 28 |
| 16 | 120 |

16 槽满树对应最多 120 次 RR 内部 ID 不等检查；GR 若同样检查再多 120 次。该数字只是比较次数，不是精确约束数或行数。

### 结构成本估计

- 每对比较新增 1 个逆元 witness 与 1 组 gated 约束；
- n=16 时 RR+GR 最多 240 对，带来显著 advice 分配和 region 行数；
- 当前 E-R1 在 K=15 已接近行数上限（K=13/14 不足），方案 B 很可能再次提高 K；
- 本轮未实现方案 B 电路，也未测其 K/prove 成本，因此不给出具体数值。

### 为什么不默认采用

如果 S0 已由可信 genesis 或连续状态转换证明链保证，重复 pairwise 检查会为每次转换重新支付 O(n²) 成本，且 n 上限 16 时开销不小。下一阶段成本优化应先研究“证明链保证初始状态”与“局部检查”哪个更划算，而不是直接扩大电路。

---

## 4. 决策

**采用方案 A**：将 S0 唯一性记录为可信状态锚定的前置条件；R2 builder 执行 host 侧明确检查，既不静默忽略哈希-only RR，也不接受明显重复的初始记录。

**保留方案 B 作为后备**：若未来 S0 来自任意外部 root、没有可验证来源，则必须在 R2 之后单独设计初始状态 pairwise uniqueness 证明或独立初始状态证明，并重新测量 K/proof/prove/verify 成本。

本轮结论应严格表述为：

> 在 S0 满足 GR/RR 初始唯一性不变量、且 R2 witness 完整覆盖当前状态 preimage 的前提下，E-R1/E-R2 对最多两个顺序事件约束了 Parent 撤销有效性、Grant ID 不重复和 Revoke ID 不重复。

---

## 5. 验证记录

- `r2_01`：S0 已有 Revoke(A)，Grant(B, Parent=A) → Reject，命中 `parent not revoked in RR`；
- `r2_02`：S0 已有 Revoke(A)，Grant(B, Parent=C) → Pass；
- `r2_03`：S0 已有 Revoke(A)，再次 Revoke(A) → Reject，命中 `revoke id global unique in RR`；
- `r2_04`：S0 多个不同撤销记录 → RR root 正确重建，MockProver 通过；
- `r2_05`：preimage/root 不匹配 → Reject，命中 `parent scan root binds current RR`；
- `r2_06`：S0 RR 相同 ID 双槽 → builder 返回 `DuplicateId(0,1)`；
- 额外：hash-only RR 输入 → builder 返回 `MissingPreimage(5)`；
- 真实 proof：历史 S0 RR 场景 K=15、proof 8160 B、prove 32987 ms、verify 484 ms，verifier 接受。

详细测试证据见 `docs/EXP-D3-03-E-R2-SUMMARY.md` 与 `tests/d3_03_e_r2_mock.rs`。
