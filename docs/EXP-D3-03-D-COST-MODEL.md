# EXP-D3-03-D — Phase 4 成本模型

**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**口径**：结构成本模型，不是约束数统计，不是实测性能。当前没有逐门统计工具时，所有 `C` 均表示待估算的电路成本。

---

## 1. 统一参数

| 参数 | 基准 |
| --- | --- |
| Grant Tree 深度 | 4（B 冻结，`src/transition/b_constants.rs:25-27`） |
| Revoke Tree 深度 | 4（C 冻结，`src/transition/c_constants.rs` 与 C-INT-02） |
| 容量 | \(2^4=16\) 叶 |
| Poseidon | P128Pow5T3 |
| Grant 字段 | B 冻结 9 词 leaf：`D_GRANT + id + issuer + subject + prefix + scope + parent + epoch + valid` |
| Revoke 字段 | C 冻结 4 词 leaf：`D_REVOKE + grant_id + revoker + epoch` |
| 事件承诺 | Grant 9 词、Revoke 5 词，均归约为一个 field 元素 |
| 状态承诺 | A 冻结：`Poseidon(D_STATE, GR, RR, epoch, policy)` |
| Public instance | 原有 8 个 |
| 最大事件数候选 | 1、2、3；这不是已确定的电路上限 |

---

## 2. 单事件结构计数

以下只数 Poseidon 调用和 Merkle 层数；门约束、copy 约束、bool 分解均为 `UNKNOWN` 或不在此处换算成约束数。

### 2.1 Grant 事件（B 型，带 Parent）

| 组件 | Poseidon 调用 | Merkle 层 | 说明 |
| --- | ---: | ---: | --- |
| Parent Grant leaf | 1 | 0 | 9 词，重算被打开的有效叶 |
| Parent GR opening | 4 | 4 | `node_hash_b` 逐层 |
| Child leaf（新叶） | 1 | 0 | 9 词 |
| Child 旧槽 opening（叶=0） | 4 | 4 | 证明目标槽原为空 |
| Child 新槽 opening（叶=child leaf） | 4 | 4 | 与旧路径逐层 copy `(dir,sibling)` |
| Event commitment | 1 | 0 | 9 词，绑定 batch slot |
| **小计** | **15** | **12** | 不含 D 新增 Parent 未撤销检查 |
| D 新增：Parent RR 空记录 opening | 4 | 4 | 证明 Parent 当前未被撤销 |
| **D 型 Grant 小计** | **19** | **16** | 见状态机决策四 |

无 Parent 的 root grant 可省掉 Parent leaf/opening 与 RR 检查，约减少 9 次 Poseidon；但 B 冻结电路本身以 Parent opening 为前提，是否支持 root grant 属于原型范围决策。

### 2.2 Revoke 事件（C 型）

| 组件 | Poseidon 调用 | Merkle 层 | 说明 |
| --- | ---: | ---: | --- |
| 目标 Grant leaf | 1 | 0 | 9 词，重算目标有效叶 |
| Grant opening | 4 | 4 | 绑定 `GR_prev` |
| RR 旧槽 opening（叶=0） | 4 | 4 | 证明尚未撤销 |
| Revoke leaf | 1 | 0 | 4 词 |
| RR 新槽 opening | 4 | 4 | 与旧路径同 `(dir,sibling)` |
| Event commitment | 1 | 0 | 5 词 |
| **小计** | **15** | **12** | DirectOnly：GR 不更新 |

### 2.3 每批固定成本

| 组件 | Poseidon 调用 | 说明 |
| --- | ---: | --- |
| Batch commitment | 1 | `Poseidon(D_BATCH, n, c1, c2, c3)` |
| State commitment | 2 | `C_prev`、`C_next` |
| 4 个根规范域编码 | 0 Poseidon | 4 × 256-bit bool 分解与 `< p` 检查 |
| active/padding/count | 0 Poseidon | 最大 3 槽前缀约束 |

---

## 3. Sequential 构造

\[
C_{\mathrm{seq}}(n)=\sum_{i=1}^{n}C(e_i)+C_{\mathrm{link}}(n)+C_{\mathrm{batch}}(1)+C_{\mathrm{state}}(1)+C_{\mathrm{decode}}(4)
\]

其中：

- \(C_{\mathrm{link}}(n)\) 是相邻事件根 cell 的 copy 约束；不增加 Poseidon，但增加 permutation/equality 关系；
- 每个 active step 都需要针对其输入状态重新 opening；
- padding step 仍占用固定容量行，除非电路用 active 条件完全关闭，但域大小仍由最大事件数决定。

### Poseidon 调用估算（含 batch + state 固定 3 次）

| n | 事件组合 | 事件级 Poseidon | 固定 | 合计 |
| ---: | --- | ---: | ---: | ---: |
| 1 | Grant | 19 | 3 | 22 |
| 1 | Revoke | 15 | 3 | 18 |
| 2 | Grant + Grant | 38 | 3 | 41 |
| 2 | Grant + Revoke | 34 | 3 | 37 |
| 2 | Revoke + Revoke | 30 | 3 | 33 |
| 3 | Grant + Grant + Grant | 57 | 3 | 60 |
| 3 | Grant + Grant + Revoke | 53 | 3 | 56 |
| 3 | Grant + Revoke + Revoke | 49 | 3 | 52 |
| 3 | Revoke + Revoke + Revoke | 45 | 3 | 48 |

这些数字是结构估算，不代表约束数或运行时间。Grant 含 D 新增的 Parent RR 检查；若未来采用 root grant 模式，数字会下降。

### Sequential 的线性性

从结构看，事件级成本随 n 近似线性增长；非线性部分只有 batch/state 固定成本和 copy 链。是否在实际 Halo2 中线性，受 k、行数填充、selector 复用影响，**待测**。

---

## 4. Batch Update 构造

\[
C_{\mathrm{batch}}(n)=C_{\mathrm{updates}}(n)+C_{\mathrm{conflict}}(n)+C_{\mathrm{order}}(n)+C_{\mathrm{commitment}}(n)+C_{\mathrm{decode}}(4)
\]

令：

- \(k_G\)：批内不同 GR 叶更新数；
- \(k_R\)：批内不同 RR 叶更新数；
- \(p\)：可共享路径前缀的路径组数。

理想路径共享下：

```text
node hashes ≈ 4 * p + (不共享叶子树重算成本)
leaf hashes ≈ k_G + k_R
```

最坏无共享时退化为：

```text
node hashes ≈ 4 * (k_G + k_R)
```

这还未计入：

- 事件 ID 唯一性检查；
- 重复撤销检查；
- 同 ID 多事件顺序/覆盖规则；
- 事件列表完整性检查（防遗漏更新）；
- Parent 当前有效性检查；
- type 分派与 9/5 词承诺归一化。

### Batch 的成本优势条件

只有在以下条件下，Batch 才可能优于 Sequential：

1. 多个更新确实共享深度 4 路径前缀；
2. 冲突/排序/完整性约束成本低于省下的 opening 成本；
3. 同一叶连续更新可以合并为有限状态转移，而不是引入更复杂证明。

当前 depth=4、n≤3 下，共享收益有限；本阶段不假定成立。

---

## 5. 回答任务书问题

1. **Sequential 是否近似线性增长？** 结构上近似线性；实际约束/时间待测。
2. **Batch 能否复用公共 Merkle 前缀？** 可能，但需同路径组；depth=4/n≤3 收益未知。
3. **重复 ID 增加多少检查？** D 规则直接拒绝；需要当前中间状态的 ID 查找。若用 Merkle 非存在证明，成本另行建模；本模型把它记为 \(C_{\mathrm{conflict}}\) / `UNKNOWN`。
4. **Grant 后立即 Revoke 是否需第二次 Grant Opening？** 是。Revoke 必须打开 Grant 事件更新后的 GR 根；不能复用旧 opening。
5. **第二次 Opening 能否绑定前一事件输出根？** 能，在同一电路内用与 B/C 相同的 root cell copy 机制；跨 vk 不行。
6. **Batch 是否需要排序约束？** 需要显式顺序或依赖等价证明。不能无证明排序 `Grant(Parent),Grant(Child)` 或 `Grant(A),Revoke(A)`。
7. **固定容量与 active 数如何影响成本？** 电路规模按最大 3 事件设计；实际 n<3 时部分行被 active 关闭，但域大小不会自动缩小。原型可选 k=12 起步，另测更小 k，但不以降低测试覆盖换 k。

---

## 6. Witness 规模估算（结构项）

每个 depth-4 opening 的 witness 字段：

```text
sibling[4] + dir[4] + left[4] + right[4] + cur[4] = 20 个 field/byte 级值
```

- B 型 Grant：3 个 GR opening + D 新增 1 个 RR opening = 4 个 opening ≈ 80 个路径相关 witness 值；
- Revoke：3 个 opening ≈ 60 个路径相关 witness 值；
- 每个 active step 另需 4 个中间根 cell；
- n=3 时，Sequential 路径 witness 约 180–240 个路径字段值，外加事件字段和根编码 witness。

这不是字节序列化大小，也不是 Halo2 advice 列数；只用于比较 witness 结构增长。

---

## 7. 未知指标

- 逐门约束数；
- 实际使用行数 / 域大小；
- selector 与 advice 列数（未实现电路）；
- keygen/prove/verify 时间与 proof size；
- 内存峰值；
- Batch 路径共享的真实节省；
- 依赖分析在电路内的证明成本；
- 更小 k 是否可行。

这些必须在后续 Halo2 原型阶段用同环境实测，不得从本模型外推。
