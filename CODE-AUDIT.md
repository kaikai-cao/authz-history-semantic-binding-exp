# D3-17-02 · 现有工程能力审计（只读代码）

> 审计对象：`D:\Research\zcash-orchard-engineering\experiments\transaction_e2e\`
> - vendored `halo2_proofs 0.4.0`（`vendor/halo2_proofs-0.4.0/src/`）
> - harness（`harness/Cargo.toml`、`harness/src/bin/`）
> - F4-A 诊断补丁（`vendor/*.patch`）
>
> **本轮未编译、未运行、未修改任何代码，未生成任何 RSS 数字。**
>
> 三分类标记：
> - **[代码事实]** 可从源码逐行直接证明；
> - **[推测-需实验]** 由代码结构提出、必须运行实验才能验证；
> - **[上游已实现]** 上游已存在的机制，不得当作新贡献。

---

## 1. Advice / Fixed / Instance 列的分配与生命周期

### 1.1 三份表示同时存活 — [代码事实]

`src/plonk/prover.rs:216–221`：

```rust
struct AdviceSingle<C: CurveAffine> {
    pub advice_values: Vec<Polynomial<C::Scalar, LagrangeCoeff>>,
    pub advice_polys: Vec<Polynomial<C::Scalar, Coeff>>,
    pub advice_cosets: Vec<Polynomial<C::Scalar, ExtendedLagrangeCoeff>>,
    pub advice_blinds: Vec<Blind<C::Scalar>>,
}
```

构造链（`src/plonk/prover.rs:415–432`）：

```rust
let advice_polys: Vec<_> = advice
    .clone()                              // ← Lagrange → Coeff 时先 clone
    .into_iter()
    .map(|poly| domain.lagrange_to_coeff(poly))
    .collect();

let advice_cosets: Vec<_> = advice_polys
    .iter()
    .map(|poly| domain.coeff_to_extended(poly.clone()))  // ← Coeff → Extended 再 clone
    .collect();

Ok(AdviceSingle { advice_values: advice, advice_polys, advice_cosets, advice_blinds })
```

`src/poly/domain.rs:178–222` 证实三种基的形状：
- `empty_lagrange` / `empty_coeff`：`vec![F::ZERO; self.n]`，长度 `n = 2^k`；
- `empty_extended`：`vec![F::ZERO; self.extended_len()]`，扩展域长度约 `2n`（由 D25 的 quotient 工作量与扩展域定义可推出，具体倍数属 [推测-需实验] 的精确值，`extended_len()` 源码可查）。

**含义**：每个 advice 列在 `AdviceSingle` 里同时持有 Lagrange 系数与 Coeff 与 Extended 三份；`advice.clone()` 与 `poly.clone()` 各产生一次整列拷贝。

### 1.2 三份表示的使用时分 — [代码事实] + [推测-需实验]

`grep` 结果（行号为 vendored 文件）：

| 表示 | 使用点 | 阶段归属（据 D25 §2.3 九阶段表对照） |
|---|---|---|
| `advice_values` | `prover.rs:449, 528, 576, 624` | permutation / lookup 构造与求值；**在 quotient 之后不再出现** |
| `advice_cosets` | `prover.rs:483, 528, 624, 658, 679` | quotient 的约束表达式求值（`expressions = advice_cosets ...`） |
| `advice_polys` | `prover.rs:750, 823` | opening（`poly: &advice.advice_polys[column.index()]`） |

**[代码事实]**：三种表示最后一次使用点不同，且 `AdviceSingle` 在整个 `create_proof` 期间不被拆分。
**[推测-需实验]**：若 `advice_values` 在其最后使用点之后释放、`advice_cosets` 在 quotient 之后释放，可降低 quotient / opening 阶段的存活集合；是否真的降低峰值 RSS、降低多少，必须实测。这不是「释放一个变量」级别的重构：`AdviceSingle` 是跨阶段共享的结构，拆分涉及生命周期与借用重构，属于**有算法含义的生命周期调度候选**。

### 1.3 上游已有的提前释放 — [上游已实现]

- `src/plonk/prover.rs:409`：`drop(advice_commitments_projective);` — 在 `batch_normalize_vartime` 后显式释放投影坐标承诺。
- `src/plonk/vanishing/prover.rs:96`：`drop(h_poly);` — 在切成 `h_pieces` 后显式释放完整 h 多项式。

**判定**：上游已经在这两个大对象上做了显式生命周期控制。因此「加几个 drop」本身不是贡献；只有**系统性地把多表示生命周期按阶段调度并验证迁移性**，才可能构成方法。

## 2. FFT 中间缓冲区

`src/poly/domain.rs:228–330`：
- `lagrange_to_coeff(&self, mut a: Polynomial<F, LagrangeCoeff>)` 内调用 `Self::ifft(&mut a.values, ...)`，即**原地 IFFT** — [上游已实现]。
- `coeff_to_extended(&self, poly)` 返回新分配 `empty_extended()` 后写入，非原地 — [代码事实]。
- `extended_to_coeff(&self, mut a)` 返回 `Vec<F>`，配合 `divide_by_vanishing_poly` 使用 — [代码事实]。

D25 §2.3 的九阶段中，FFT 类工作分散在 `advice_commit`（`lagrange_to_coeff`/`coeff_to_extended`）与 `quotient`（扩展域求值、`extended_to_coeff`）内。

**[代码事实]**：FFT 主体是原地的；非原地部分来自**基变换时保留原表示**（见 §1.1），不是 FFT 算法本身。
**[推测-需实验]**：把「原表示 + 新表示」的双存活改成按需重算，可能以时间换空间；时间代价不可从代码推断。

## 3. MSM 输入与临时向量

`src/poly/commitment/msm.rs:88–95`：

```rust
} else {
    let mut g_scalars = vec![C::Scalar::ZERO; self.params.n as usize];
    g_scalars[0] += &constant;
    self.g_scalars = Some(g_scalars);
}
```

- `add_constant_term` 在首次需要时分配**满长 `n`** 的标量向量 — [代码事实]。
- `msm.rs:168–169`：`Vec::with_capacity(len)` 分别收集 `scalars` 与 `bases` — [代码事实]。
- `src/poly/commitment/prover.rs:81,155`、`src/poly/commitment.rs:48–141`：SRS 向量、`tmp_scalars`/`tmp_bases` 均为整段预分配 — [代码事实]。

**[代码事实]**：MSM 侧的临时向量是「按多项式满长」分配，且与 IPA 轮数无关的 `g_scalars` 是 `n` 长度。
**[推测-需实验]**：`g_scalars` 满长分配是否是某阶段的峰值贡献者，需要分配点级采样；D26 §20 的 2.2 MiB 未定位项也点名需要这种采样。

## 4. Polynomial commitment / opening

`src/poly/commitment/prover.rs` 与 `src/poly/multiopen/prover.rs:49–50`：
- `q_polys: Vec<Option<Polynomial<..., Coeff>>> = vec![None; point_sets.len()]`、`q_blinds` 同长度 — [代码事实]。
- `src/plonk/vanishing/prover.rs:92–96`：`h_pieces` 用 `v.to_vec()` 复制每个 chunk，然后 `drop(h_poly)` — [代码事实] + [上游已实现]（显式释放）。

**[代码事实]**：quotient 的 h 多项式经历 `evaluate → divide → extended_to_coeff → h_pieces (to_vec)`，其中 `h_pieces` 是全量再拷贝一份后释放母向量；瞬时双份由代码保证，但峰值是否落在这一段未知。

## 5. Permutation 与 lookup 中间数据

- `src/plonk/permutation/prover.rs`、`src/plonk/lookup/prover.rs`：均按 column 维度构造多项式向量。
- D25 §2.3 的九阶段中 `lookup_permute / permutation / lookup_product` 三段在 F4-A A/B 对比中均在噪声内（1P 分别 −0.1 / +0.0 / +1.5 ms），**说明 F4-A 的内存/memo 改动未触及这些阶段的耗时**；这不等于这些阶段不占内存 — [代码事实 + 边界]。
- **[推测-需实验]**：`advice_values`（§1.2）主要在这些阶段使用，其生命周期可能与 permutation/lookup 的临时数据重叠；需要阶段级内存采样才能定位。

## 6. Selector compression 的作用

- `src/plonk/circuit/compress_selectors.rs`、`src/plonk/keygen.rs`：每条 keygen 路径无条件调用 `cs.compress_selectors(...)`，产生 `q·∏(i−q)` 恢复链。
- 这是库侧机制，不是 Orchard 电路手写；D27 §6 给出可先验判定条件 C1 `d_s ≤ D−1`、C2 `occ ≥ 2`、C3 消费者在约束根。
- F4-A 的优化（只读 memo 共享）作用点是 quotient；D25 §9.4 证实 1P 100.4% / 8P 101.2% 的收益落在 quotient。
- **[代码事实]** 恢复链在 keygen 阶段生成；**[推测-需实验]** 恢复链求值是否也是 quotient 阶段内存峰值的来源之一，本轮无数据。

## 7. Rayon 并行导致的内存峰值

`src/multicore.rs`：
- 文件头注释原文：`"It's currently just a (very!) thin wrapper around rayon but may be extended in the future to allow for various parallelism strategies."` — [代码事实]。
- `try_fold_and_reduce` 的 `identity: impl Fn() -> T` 在每个 fold 被调用：`self.try_fold(&identity, &fold_op)` — [代码事实]。这意味着每个 worker 持有一份 fold 初值对象。
- `pub use maybe_rayon::{iter::IntoParallelIterator, join, scope}`；`#[cfg(feature="multicore")]` 决定真实并行或串行回退 — [代码事实]。

D25 §2.1 已明确：1P 的 chunk 串行、`chunk_net_peak_bytes` 就是进程增量主项；8P 并行，进程增量 ≈ 8 × 单 chunk 峰值，两者必须分别报 — [上游实验方法学]。

**[推测-需实验]**：线程数 T 与峰值 RSS 的关系可能是 `O(T × 每线程 fold 状态 + 并发 chunk 数 × 每 chunk 缓冲)`；这是 A1-C 的核心假设，**代码只能支持提出假设，不能验证**。

## 8. 临时对象释放时机与重复分配

汇总表（全部为 [代码事实]，除末列为 [推测-需实验]）：

| 对象 | 分配形状 | 现存释放/复用机制 | 可否按阶段调度 |
|---|---|---|---|
| `advice_values` Lagrange | `num_advice × n` | 无提前释放 | 可能（最后用在 permutation/lookup）— 需实验 |
| `advice_polys` Coeff | `clone() → n` | 无提前释放 | 用于 opening，难释放 |
| `advice_cosets` Extended | `clone() → extended_len` | 无提前释放 | 可能（最后用在 quotient）— 需实验 |
| `advice_commitments_projective` | `num_advice × n` | **`drop()` 显式** [上游已实现] | 已做 |
| `h_poly` | `extended_len` 后转 `n×degree` | **`drop()` 显式** [上游已实现] | 已做 |
| `h_pieces` | `to_vec()` 全量拷贝 | 无 | 需实验 |
| `g_scalars` (MSM) | `vec![ZERO; n]` | `Option` 延迟分配 [上游已实现] | 需实验 |
| per-thread fold 状态 | 每 worker 一份 | 无限制接口 | 需实验（线程扫描） |
| F4-A memo | `49 × chunk_size × 32 B` | 每 chunk 生命周期内驻留 | F4-A 已测：1P 6.125 MiB / 8P 0.766 MiB |

## 9. 上游已实现优化清单（不得作为新贡献）

1. IFFT 原地执行（`domain.rs:lagrange_to_coeff`）。
2. `batch_invert_assigned` 过滤平凡分母，缩小 batch inversion 规模（`poly.rs:148–154`，注释原文 `"If the denominator is trivial, we can skip it, reducing the size of the batch inversion."`）。
3. `drop(advice_commitments_projective)`（`prover.rs:409`）。
4. `drop(h_poly)`（`vanishing/prover.rs:96`）。
5. `g_scalars` 的 `Option` 延迟分配（MSM）。
6. `Val::{Owned, Borrowed}` 就地折叠与 F4-A 的只读 memo（本仓库 F4-A 补丁，D24 §2；注意 D25 §11 指出就地折叠来自同一补丁，A/B 只差开关，不能把 1.6 GiB 分配减少全归给共享机制）。
7. `compress_selectors` 库侧恢复链（上游，D27 §1）。

## 10. 代码审计的结论边界

- **[代码事实]** 只能证明「三份表示同时存活」「某些对象有显式 drop」「MSM 满长分配」「Rayon 每 worker 一份 fold 初值」。
- **[推测-需实验]** 不能由代码结构推出：任何阶段的实际峰值 RSS、2.2 MiB 的来源、三表示生命周期调度的收益量级、线程数与峰值的函数形状。
- **本轮没有做任何测量**，因此没有发现「可复现的内存瓶颈」——只发现了一个**结构上有依据、尚未验证的优化候选**（§1.2 的分阶段释放）和一个**已由 F4-A 文档点名的未定位量**（D26 §20 的 2.2 MiB）。
