# EXP-D3-03-D — Phase 1 混合事件状态机冻结

**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**前置**：`docs/EXP-D3-03-D-SOURCE-AUDIT.md`
**原则**：先冻结语义，再谈电路。本文只定设计；不新增 Halo2 电路，不修改 A/B/C。

---

## 1. 状态与事件定义

### 1.1 状态

\[
S_i=(G_i,R_i,e_i,\pi)
\]

- \(G_i\)：授权记录集合，键为 `grant_id`，值为 Grant 字段与 GR 叶存在性。
- \(R_i\)：撤销记录集合，键为 `grant_id`，值为 `(grant_id, revoker, epoch)`。
- \(e_i\)：状态 epoch。
- \(\pi\)：冻结的 policy/version 常量。

**逻辑有效性定义（本阶段冻结）**：

\[
\operatorname{valid}_{S}(g) \iff g\in G_S \land g\notin R_S
\]

这一点很重要：B 的 GR 叶在电路内始终写 `valid=1`，C 的 DirectOnly 撤销保持 GR 根不变、只写 RR。因此 D 不把 GR 叶里的 `valid` 位当作当前有效性，而是用“GR 中存在且 RR 中无撤销记录”作为当前有效性的唯一语义来源。D3-01 通过改写 GR 叶 valid 位表达同一策略；字节编码不同，但策略层等价。

### 1.2 事件

\[
e_i=(type_i,payload_i),\quad type_i\in\{\operatorname{Grant},\operatorname{Revoke}\}
\]

```text
Grant   = (id, issuer, subject, resource_prefix[8], scope:u64, parent:Option<id>, epoch:u64)
Revoke  = (grant_id, revoker, epoch:u64)
```

`type` 必须参与事件承诺，防止 Grant/Revoke 类型混淆：

```text
TYPE_GRANT  = 1
TYPE_REVOKE = 2
c_grant  = Poseidon(D_EVENT, TYPE_GRANT,  id, issuer, subject, prefix, scope, parent_key, epoch)
c_revoke = Poseidon(D_EVENT, TYPE_REVOKE, grant_id, revoker, epoch)
D_E      = Poseidon(D_BATCH, n, c_1, c_2, c_3)
```

两类承诺词数不同（9 词 vs 5 词），但都归约为一个 field 元素进入三槽 batch；不要求同词数，也不能省略 type tag。

---

## 2. 六项语义决策

### 决策一：事件顺序具有语义

采用**有序事件列表**：

\[
[Grant(A),Revoke(A)] \neq [Revoke(A),Grant(A)]
\]

不做规范排序、不做无序集合化。序列中的第 \(i\) 个事件只能看到 \(S_{i-1}\)。

依据：Grant/Revoke 存在状态依赖，B/C 都是对“当前状态根”的 opening；排序会改变依赖对象（`docs/EXP-D3-03-D-SOURCE-AUDIT.md` Q2/Q10）。

### 决策二：epoch 按批次递增一次

令：

\[
E = e_{\mathrm{prev}}+1
\]

本批次内所有 active 事件的 `epoch` 必须等于 \(E\)，最终状态 epoch 也是 \(E\)：

\[
\forall i,\ e_i.\mathrm{epoch}=E,\qquad e_{\mathrm{next}}=E
\]

理由：

- 与 C 的 `next_epoch = prev_epoch + 1` 和 `revoke.epoch = next_epoch` 完全一致；
- 与 B 的 `child.epoch ≥ parent.epoch` 一致：同批次 Parent/Child 取相同 \(E\)，非严格递增即满足；
- 与 D3-01 的 `last_epoch = event.epoch` 一致：同批次内 epoch 可相等，不要求逐事件加一；
- 若改为逐事件加一，则 n 个事件会要求 `next_epoch = prev_epoch+n`，直接冲突于 C 冻结门，必须改 C，故不采用。

### 决策三：中间状态必须存在

逐事件执行：

\[
S_0\xrightarrow{e_1}S_1\xrightarrow{e_2}\cdots\xrightarrow{e_n}S_n
\]

第二个事件必须作用于第一个事件产生的状态；“先各自从 \(S_0\) 验证，再合并根”不是合法构造。中间根是状态转换的一部分，不只是一个 host 变量。

### 决策四：Parent/Child 依赖采用当前状态有效性

创建 Child 时要求：

1. Parent 在当前 \(G_{i-1}\) 中存在；
2. Parent 在当前状态未被撤销，即 \(\operatorname{valid}_{S_{i-1}}(Parent)=true\)；
3. `issuer_child = subject_parent`；
4. `scope_child ⊆ scope_parent`（u64 bitmask 子集）；
5. `resource_prefix_child = resource_prefix_parent`（前 8 字节前缀相等，不用普通整数比较）；
6. `epoch_child ≥ epoch_parent`。

这对应任务书中的第二种策略：不允许在 Parent 已撤销后创建 Child。它比 B 单电路更强：B 只看 GR 中 `valid=1` 的 Parent opening，看不到 RR；D 必须额外检查 Parent 不在当前 RR。该检查是 D 新增语义，不修改 B。

DirectOnly 保持：撤销 Parent 不自动撤销已经存在的 Child；但后续新创建的 Child 不能依赖已撤销 Parent。

### 决策五：允许同批次创建后立即撤销

```text
Grant(A) → Revoke(A)
```

第二步必须打开第一步更新后的 GR，并在 RR 中空槽写入撤销记录。最终 GR 根包含 A 的叶，RR 根包含 A 的撤销记录；逻辑上 A 无效。该语义对齐 D3-01 的“记录存在但 valid=false”，但与 C 的“GR 根不变”编码保持一致。

### 决策六：重复事件一律拒绝

- 重复 Grant ID：只要当前 \(G\) 已含该 ID，就拒绝 `DuplicateGrant`，即使它已被撤销也不允许重新创建。依据 D3-01 `src/policy.rs:123-125`。
- 重复 Revoke：当前 \(R\) 已含该 ID，就拒绝 `AlreadyRevoked`。依据 D3-01 `src/policy.rs:161-163` 与 C 的旧叶非空约束。
- 容量：depth=4，GR/RR 各 16 槽；超出拒绝 `CapacityExhausted`。
- 重复检查必须作用于**当前中间状态**，而不只是批次开始时的旧状态。

### 失败处理

非法事件导致**整批拒绝**：

- 不产生 `final_state`；
- 不把已成功前缀当作可用输出；
- 参考模型返回 `rejection = (index, reason)`，并保留前序 `intermediate_states` 仅用于诊断；
- 电路原型中，失败 witness 不应被表述为“部分成功的状态转换”。

---

## 3. 逐事件执行规则

### Grant

给定 \(S_{i-1}\) 与 Grant 事件 \(g\)：

1. 校验 `g.epoch = E`；
2. 校验 `g.id ∉ G_{i-1}`；
3. 若 `g.parent = None`，跳过父检查；否则执行决策四；
4. 插入 \(G_i = G_{i-1}\cup\{g\}\)，GR 根变化；
5. RR 不变：\(R_i=R_{i-1}\)；
6. 事件承诺写入 batch slot \(i\)。

### Revoke

给定 \(S_{i-1}\) 与 Revoke 事件 \(r\)：

1. 校验 `r.epoch = E`；
2. 校验 `r.grant_id ∈ G_{i-1}`，否则 `GrantNotFound`；
3. 校验 `r.grant_id ∉ R_{i-1}`，否则 `AlreadyRevoked`；
4. 校验 `r.revoker = G_{i-1}[r.grant_id].issuer`；
5. 插入 \(R_i = R_{i-1}\cup\{r\}\)，RR 根变化；
6. GR 不变：\(G_i=G_{i-1}\)（DirectOnly）；
7. 事件承诺写入 batch slot \(i\)。

### 批次承诺与状态承诺

- `event_count = n`，padding 槽为 `batch_pad`；
- `active` 必须为 `[1,...,1,0,...,0]` 前缀，禁止跳过中间事件；
- \(C_{\mathrm{prev}}\) 与 \(C_{\mathrm{next}}\) 继续用 A 冻结公式，只承诺首尾状态；
- 中间状态根是私有 witness，但必须被相邻事件 copy 约束连接。

---

## 4. S01–S15 预期结果

记号：`GR+` 根变化，`GR=` 根不变；`RR+` 根变化，`RR=` 根不变；`E+1` 表示批次 epoch 从 \(e\) 变为 \(e+1\)。
S02/S07/S14/S15 假定 A、B 是初始状态中已存在的授权；其余序列中的 A/B/Child/Parent 为批次内新建或已定义符号对象。

| 编号 | 事件序列 | 逐步 GR/RR 变化 | 最终结论 |
| --- | --- | --- | --- |
| S01 | `Grant(A)` | `GR+ RR=`；`E+1` | Accept，A 存在且有效 |
| S02 | `Revoke(A)` | `GR= RR+`；`E+1` | Accept，A 逻辑无效，GR 根不变 |
| S03 | `Grant(A), Grant(B)` | `GR+ RR=` → `GR+ RR=`；单一 `E+1` | Accept，两个不同 ID 不同槽 |
| S04 | `Grant(A), Revoke(A)` | `GR+ RR=` → `GR= RR+` | Accept，GR 含 A 叶，RR 含 A 撤销 |
| S05 | `Grant(A), Grant(B), Revoke(A)` | `GR+ RR=` → `GR+ RR=` → `GR= RR+` | Accept，B 不受 A 撤销影响 |
| S06 | `Grant(A), Revoke(A), Grant(B)` | `GR+ RR=` → `GR= RR+` → `GR+ RR=` | Accept，新 B 使用同一批次 epoch |
| S07 | `Revoke(A), Grant(B)` | `GR= RR+` → `GR+ RR=` | Accept，先撤销旧授权再创建无关新授权 |
| S08 | `Grant(A), Grant(B), Revoke(B)` | `GR+ RR=` → `GR+ RR=` → `GR= RR+` | Accept，后创建授权可被撤销 |
| S09 | `Grant(A), Revoke(A), Revoke(A)` | 前两步 `GR+ RR=` → `GR= RR+`；第三步拒绝 | Reject：`AlreadyRevoked`（index 2） |
| S10 | `Grant(A), Grant(A)` | 第一步 `GR+ RR=`；第二步拒绝 | Reject：`DuplicateGrant`（index 1） |
| S11 | `Grant(Child), Grant(Parent)` | 若 Parent 初始不存在，第一步即拒绝 | Reject：`ParentNotFound`（index 0）；无状态变化 |
| S12 | `Grant(Parent), Grant(Child)` | `GR+ RR=` → `GR+ RR=` | Accept，Parent/Child 同批次依赖，epoch 相同 |
| S13 | `Grant(Parent), Revoke(Parent), Grant(Child)` | `GR+ RR=` → `GR= RR+`；第三步拒绝 | Reject：`ParentNotValid`（index 2） |
| S14 | `Revoke(A), Revoke(B)` | `GR= RR+` → `GR= RR+` | Accept，连续撤销两个不同初始授权 |
| S15 | `Grant(A), Revoke(B)` | `GR+ RR=` → `GR= RR+` | Accept，撤销无关初始授权 B |

注意：S04/S05/S08 中“GR 根变化”指 Grant 事件插入叶子；Revoke 事件不改写 GR。A/B 在该状态下是否“有效”由 RR 决定，不由 GR 叶中的冻结 valid 位决定。

---

## 5. 与 A/B/C/D3-01 的兼容性与差异

| 对象 | 兼容点 | 差异 / D 新增 |
| --- | --- | --- |
| A | 8 public instance、状态承诺公式、规范域编码、batch gadget 原样沿用 | 中间根仅私有 witness；不新增公开字段 |
| B | Grant leaf、scope/prefix/epoch gate、GR 单叶更新模式 | 增加“Parent 当前未撤销”检查；B 单电路看不到 RR |
| C | `next_epoch=prev_epoch+1`、DirectOnly GR 不变、RR 单叶更新、Revoke 事件承诺 | 事件数从固定 1 扩到 1–3；`event-count-one` 不能沿用；需 type 分派 |
| D3-01 | 有序逐事件执行、重复 ID/重复撤销拒绝、Parent 当前有效、.issuer 规则 | D3-01 撤销改写 GR 叶 valid；D 用 RR 派生逻辑有效性；编码不是字节级兼容 |

---

## 6. 信任边界

本阶段状态机证明/验证的是：**给定初始状态、有序事件列表和冻结规则，逐步执行后的最终根关系**。它不证明：

- 初始 GR/RR 根来自真实完整授权历史；
- 事件本身来自真实外部请求；
- slot 的全局 canonical 分配正确；
- Bridge/checkpoint 可信或最新；
- 执行时没有并发覆盖；
- Cascade 语义；
- ALLOW/DENY 决策或完整 DENY 证明。

Phase 1 冻结结论：**有序事件列表 + 批次统一 epoch + 当前状态 Parent 有效性 + DirectOnly + 重复拒绝 + 整批原子失败**。
