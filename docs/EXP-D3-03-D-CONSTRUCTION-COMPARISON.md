# EXP-D3-03-D — Phase 2 两种构造比较

**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**前置**：`docs/EXP-D3-03-D-STATE-MACHINE.md`
**范围**：结构分析与待验证假设；不实现 Halo2 电路，不给出未经实测的性能结论。

---

## 0. 共同约束

两种构造都必须满足 Phase 1 冻结语义：

1. 事件是有序列表，不做规范排序；
2. 批次 epoch 统一为 \(E=e_{\mathrm{prev}}+1\)，所有 active 事件使用该 epoch；
3. `valid(S,g) = g∈G_S ∧ g∉R_S`；
4. DirectOnly：Revoke 不改 GR 根，只写 RR；
5. 重复 Grant ID、重复 Revoke、容量超限均拒绝；
6. A 的 8 个 public instance 不变；
7. 批次最多 3 槽，active 必须是前缀形式；
8. 事件承诺必须含 type tag，顺序变化必须反映到 batch commitment。

源码依据：A 的 batch 门（`src/transition/circuit.rs:323-355`）、B 的 GR 单叶更新（`src/transition/b_circuit.rs:919-963`）、C 的 RR 单叶更新（`src/transition/c_circuit.rs:849-893`）、当前无中间根实现（`docs/EXP-D3-03-D-SOURCE-AUDIT.md` Q2/Q7）。

---

## 1. 方案 A：Sequential Transition Circuit

### 1.1 构造

\[
S_{i+1}=T(S_i,e_i),\qquad S_n=T(\cdots T(S_0,e_1),e_2\cdots)
\]

每个 active 事件占用一个 transition step：

```text
public S0
  step 1: event witness e1 + opening witnesses against S0
          enforce T relation -> S1 root cells
  step 2: event witness e2 + opening witnesses against S1
          copy_equal(S1 roots, step2 prev-root cells)
          enforce T relation -> S2 root cells
  ...
public Sn
```

### 1.2 中间状态绑定

- 每个事件维护四个根 cell：`GR_prev, RR_prev, GR_next, RR_next`。
- 第 \(i+1\) 步的 `GR_prev/RR_prev` cell 必须通过 `Region::constrain_equal` 连接到第 \(i\) 步的 `GR_next/RR_next` cell。
- 本仓已验证同类 copy：B 的 opening 根→规范域根 cell（`src/transition/b_circuit.rs:927,938,963`）、C 的 opening 根→`rprev/rnext`（`src/transition/c_circuit.rs:857,867,889,893`）。
- 中间根可以只为私有 witness；公开语句仍只承诺 \(S_0,S_n\)。但“私有”不等于“不受约束”：copy 链和每一步 T 关系必须成立。
- 不能把 \(S_1\) 作为 host Rust 变量算好后无约束塞进第二步；这正是本构造要避免的核心风险。

### 1.3 Chip / gate 复用

- Grant step 复用 B 的 Grant leaf、scope/prefix/epoch gate、GR opening 与单叶更新门。
- Revoke step 复用 C 的 Grant opening、RR 空叶 opening、RR 单叶更新、`GR_next=GR_prev` copy。
- 差异：B 要求 Parent 在当前 GR 中有效；D 还要求 Parent 不在当前 RR。Sequential 中第二步可以直接把第一步的 RR root cell作为 Parent 非撤销检查的输入，因此比跨 B/C 两电路更自然。
- 两类 step 可共用底层 `path-dir-bool/path-select/copy_equal`，但事件 type 分派 gate 必须不同：`TYPE_GRANT=1` 走 Grant 规则，`TYPE_REVOKE=2` 走 Revoke 规则。

### 1.4 Opening 与更新

- 每个事件需要针对其输入状态重新生成 opening。
- `Grant(A), Revoke(A)`：Revoke 的 Grant opening 必须针对 B 更新后的 GR 根；不能复用 Grant 事件之前的 opening。
- 同一叶连续更新（如 `Grant(A), Revoke(A)` 或 `Revoke(A), Revoke(A)`）在 Sequential 中天然表达：第二步看到第一步的根；重复撤销因 RR 旧叶非空被拒。
- 固定 3 槽下，未使用 step 以 `active=0` padding，要求 active 前缀连续；否则会出现“跳过 step 2 但 step 3 使用 S1”的漏洞。

### 1.5 风险

- 主要风险是**中间根连接错误**：若 prover 能为第二步提供任意 \(S_1'\)，则事件虽各自合法，整体序列不成立。
- 每个事件独立 opening 会带来更多 witness 与 Poseidon 路径重算；是否显著更贵未实测。
- 若把 B/C 的 proof 直接拼接而不在同一电路/vk 内 copy，则中间根没有密码学链接；D 原型必须在同一电路内实现，不能靠两个独立 proof 串接。

---

## 2. 方案 B：Batch State Update Circuit

### 2.1 构造

\[
S_n=\operatorname{BatchUpdate}(S_0,E),\qquad E=(e_1,\ldots,e_n)
\]

候选流程：

```text
读取完整事件列表 + 每个事件对 GR/RR 的更新记录
约束 type / 顺序 / ID 唯一 / 槽位不冲突
按更新记录重算最终 GR/RR 根
绑定 public Sn 与 batch commitment
```

### 2.2 中间状态表达

Batch 方案不能只有“事件列表 + 最终根”，否则无法表达 `Grant(A) → Revoke(A)` 的状态依赖。必须至少选择一种中间状态表达：

1. 仍保留每个事件后的中间根，只是不逐步展开 chip；
2. 把所有叶子更新排序后一次性应用，并用冲突规则证明等价于某个顺序执行；
3. 为每个 grant_id 维护“首次创建/最后撤销”状态摘要，再证明摘要与最终根一致。

当前 A/B/C 没有第 2/3 类组件，均属新增设计。若只验证“每个事件单独合法 + 最终根由 prover 给出”，会犯“事件集合合法即序列合法”的错误。

### 2.3 路径共享与冲突

潜在收益：

- 同一棵树的多个更新若落在相同前缀，可共享部分 sibling 哈希；
- 固定 3 事件、depth=4 时，共享机会有限但可分析；
- 同一叶子连续更新可合并为“旧叶→最终叶”的单次变化，但这要求证明中间撤销/创建没有被跳过。

必须新增的约束：

- 事件 ID 唯一性与槽位单射，或显式冲突解决规则；
- 更新顺序约束：同一 ID 的 Grant/Revoke 必须按声明顺序，不能重排；
- 更新完整性：每个 active 事件恰好贡献一次状态影响；
- 最终根必须等于所有更新按序应用后的根，不能是“挑几个更新重算”的结果；
- type 与 payload 顺序进入 batch commitment。

### 2.4 排序/规范化问题

若为了路径共享而对事件排序，必须证明排序后的执行与原有序列表等价。对有依赖关系事件不成立：

- `Grant(Parent), Grant(Child)` 不能交换；
- `Grant(A), Revoke(A)` 不能交换；
- `Revoke(A), Grant(A)` 与前者语义不同。

因此第一版 Batch 不能静默规范化排序。只能对经依赖分析确认独立的事件做局部重排；这又引入新的依赖证明问题。

### 2.5 风险

- 最大风险是**更新遗漏与覆盖**：事件全部合法但某个更新没进入最终根。
- 同一叶多次更新需要“谁覆盖谁”的规则；与 Phase 1 的重复拒绝语义兼容的方案是：对重复 ID/重复撤销直接拒，而不是幂等覆盖。
- 路径共享收益可能被排序、去重、冲突约束抵消；本阶段不预判。

---

## 3. 两方案比较表

| 维度 | Sequential | Batch Update |
| --- | --- | --- |
| 事件顺序 | 显式顺序执行，天然满足 Phase 1 | 需要显式顺序约束或依赖证明，不能默认可排序 |
| 中间状态 | 天然存在，必须相邻 copy | 需额外表达；仅事件集合+最终根不足 |
| Grant/Revoke 复用 | 可直接复用 B/C 单步关系，新增 RR-aware parent 检查 | 需要批量更新接口与 type 分派 |
| 同一叶多次更新 | 顺序执行自然；重复撤销由旧叶非空拒绝 | 需冲突/覆盖规则，避免遗漏或错误幂等 |
| Merkle 路径共享 | 较少，每步针对当前根重新 opening | 可能更充分，但 depth=4/n≤3 收益待测 |
| 约束规模 | 预计随 n 近似线性增长 | 取决于路径共享与冲突/排序成本，不能预判 |
| Witness 大小 | 每步一套 opening，可能较大 | 需更新记录+冲突证明，总量未知 |
| 证明生成成本 | 待测 | 待测 |
| 实现复杂度 | 中间根 copy 链较直接 | 更新完整性与冲突约束更复杂 |
| 完整性风险 | 中间状态连接被伪造 | 更新遗漏、错误覆盖、非法重排 |
| 与当前代码距离 | 接近 B/C 现有模式 | 需要新批量更新 gadget |

---

## 4. 事件依赖与可交换性观察

这是本阶段最有价值的待验证方向之一，但目前只是结构性观察，不宣称创新性。

定义两个事件“独立”当且仅当它们对当前状态的读写集合不产生依赖：

- `Grant(A)` 与 `Grant(B)`（A≠B，均无父子依赖）通常可交换；
- `Grant(Parent)` 与 `Grant(Child)` 不可交换；
- `Grant(A)` 与 `Revoke(A)` 不可交换；
- `Revoke(A)` 与 `Revoke(B)`（A≠B）通常可交换；
- `Revoke(A)` 与 `Grant(B)` 若 B 不依赖 A，通常可交换。

可能的研究路径：

1. 在参考模型中显式计算读写依赖；
2. 只允许独立事件局部重排；
3. 对冲突事件保留顺序约束；
4. 只在共享前缀时做路径复用；
5. 对比“全顺序执行”与“依赖感知批量更新”的成本。

这需要电路中证明依赖关系，代价尚未建模；D 不实现，只记录为 Phase 5 之后的候选研究方向。

---

## 5. 最终建议（设计层，不是性能结论）

**第一版 Halo2 原型推荐 Sequential Transition Circuit。**

理由：

1. Phase 1 的状态依赖与原子失败语义在 Sequential 中最直接；
2. 当前 A/B/C 的代码模式已经提供单步关系与 copy 机制，新增的只是相邻事件根 copy 链；
3. Batch Update 的路径共享收益在 depth=4、n≤3 下未被证实，却需要额外证明更新完整性、冲突和顺序；
4. 不把“Batch 一定更省约束”或“Sequential 一定更慢”写成结论；两者都需要后续同环境实测。

建议的后续研究顺序：

- 先实现 Sequential n≤2 原型，验证中间根 copy、事件依赖与负向测试；
- 再在独立参考模型中实现依赖分析，比较独立事件局部重排；
- 最后才评估 Batch Update 的路径共享是否值得引入冲突/排序约束。

---

## 6. 本阶段不成立的断言

- 未实测证明 Sequential 比 Batch 慢或快；
- 未证明 Batch Update 在 depth=4/n≤3 下有收益；
- 未证明依赖感知重排可安全压缩电路；
- 未把 selector 数、源码行数或 Poseidon 调用次数当作精确约束数；
- 未把参考模型结果当作 Halo2 约束成立证明。
