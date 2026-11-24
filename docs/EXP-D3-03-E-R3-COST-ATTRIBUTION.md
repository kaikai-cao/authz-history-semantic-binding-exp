# EXP-D3-03-E-R3 — Phase 1: Full-Scan Cost Attribution

## 0. 范围与口径

本轮对**冻结的 E-R1 电路**做成本归因，不修改 E-R1/E-R2/A/B/C/D/E 任何实现。

固定参数（Phase 0 核验，来自冻结源码）：

| 参数 | 值 | 来源 |
| --- | --- | --- |
| 基线 commit | `423da783...` | `exp-d3-03-e-r2` HEAD |
| K (log2 rows) | 15 | `e_r1_constants.rs::K_R1` |
| 树容量 | 16 | `b_constants.rs::TREE_CAPACITY = 1<<4` |
| 树深度 | 4 | `b_constants.rs::DEPTH` |
| 事件数上限 | 2 | `MAX_ACTIVE_EVENTS` |
| public instances | 8 个值，单列 8 行 | `constrain_instance(.., row 0..7)` |
| Rust | 1.98.1 / cargo 1.98.1 | `rustc --version` |
| 机器 | i7-14700, 20c/28t, ~31.7 GiB | E-R1 benchmark 记录 |
| 线程 | `RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1` | E-R1 benchmark 冻结配置 |
| profile | release, `opt-level=3` | `Cargo.toml` |

**关键口径声明（避免常见错误）：**
- **Poseidon 调用次数 ≠ 约束数 ≠ 行数 ≠ proving time**。本文件分别统计这四类，互不替代。
- `hash_words(N words)` 使用 `P128Pow5T3`（rate=2），每次调用执行 `ceil(N/2)` 次 Poseidon permutation。下文"permutation 数"按此计算。
- 列数/selector/门多项式数来自 Halo2 自身的 `pinned()` debug 视图（运行 `Circuit::configure` 后读取），**不是**源码行数估算。
- proving time 为 E-R1 benchmark 的固定单线程 3 采样中位数，属墙钟实测，不构成严格分布结论。

## 1. Halo2 电路结构元数据（运行时精确）

读取方式：`src/transition/e_r3_stats.rs` 调用公开的 `Circuit::configure` 填充 `ConstraintSystem`，再经公开的 `cs.pinned()` debug 视图取 Halo2 内部计数。该模块为 R3 新增只读探针，不触碰任何冻结电路文件。测试入口：`tests/d3_03_e_r3_attrib.rs`。

| 指标 | E-R1 值 | 说明 |
| --- | --- | --- |
| fixed columns | 9 | Poseidon rc_a/rc_b 各 3 + p_bit + weight + bit_weight |
| advice columns | 39 | 37 显式 + state[3]（`(0..3).map` 一行分配 3 列） |
| instance columns | 1 | 8 个 public 值占用 row 0..7 |
| selectors | 30 | 源码显式 27 + Poseidon `Pow5Chip::configure` 内部 3（`s_full/s_partial/s_pad_and_add`） |
| gate families | 28 | 源码 `meta.create_gate` 调用数 |
| constraint polynomials | 43 | Halo2 `pinned()` gates 扁平化后顶层元素数 |
| degree | 3 | `scan-id-neq` 三次项决定 |
| blinding factors | — | Halo2 按 advice 查询数计算 |

**为什么源码 grep 与运行时值不同：** advice 列源码 `meta.advice_column()` 出现 37 处文字，但其中 `(0..3).map(|_| meta.advice_column())` 一行分配 3 列，故运行时 39。selector 源码 27 处，但 Poseidon chip 内部另建 3 个，故运行时 30。这正是必须用 Halo2 运行时计数而非文本计数的原因。

**R1 相对 E 的结构增量：** 新增 7 个 advice 列（`scan_fl/lv/hs/bf/ia/ib/inv`）+ 3 个 selector（`q_scan_bool/q_scan_leaf/q_scan_neq`）。E 的 advice/selector 基座不变。

## 2. Poseidon permutation 归因

模型测试：`tests/d3_03_e_r3_cost_model.rs`（可复现打印）。总 permutation = **505**，其中全树扫描 **344（68.1%）**，E 基线 **161（31.9%）**。

### 2.1 全树扫描类（E-R1 新增）

| 类别 | 计算式 | permutations |
| --- | --- | --- |
| GR 叶子重算 | 2 events × 16 slots × ceil(9/2) | 160 |
| RR 叶子重算 | 2 events × 16 slots × ceil(4/2) | 64 |
| Merkle 内部节点（GR+RR root rebuild） | 2 events × 2 trees × 15 nodes × ceil(3/2) | 120 |
| **扫描小计** | | **344** |

- 每棵树内部节点数 = 8+4+2+1 = 15（`2^DEPTH − 1`）；每节点 hash 输入 3 words（domain, left, right）→ 2 permutations。
- GR scan leaf 输入 9 words（`assign_grant_words`）→ 5 permutations；RR scan leaf 输入 4 words（domain, id, revoker, epoch）→ 2 permutations。

### 2.2 E 基线类（R1 之前已存在）

| 类别 | 计算式 | permutations |
| --- | --- | --- |
| Merkle openings | 2 events × 6 openings × depth 4 × ceil(3/2) | 96 |
| 业务叶子重算 | 2 events × (3×ceil(9/2) + ceil(4/2)) | 34 |
| 事件承诺 | 2 events × (ceil(9/2) + ceil(5/2)) | 16 |
| 冻结 batch 承诺 | 3 × ceil(9/2)（C_prev/C_next/D_E） | 15 |
| **基线小计** | | **161** |

### 2.3 非 Poseidon 的扫描约束

- **ID 不等检查**：`scan-id-neq` 门，`fl*bf*((a−b)*inv − 1)=0`，每非空叶一次。逆元 `inv` 是 host witness，电路内只验证乘法关系。GOOD 路径非空叶才约束生效（empty slot 的 `fl=0`）。
- **empty boolean / leaf select**：`q_scan_bool` 约束 `fl²=fl`，`q_scan_leaf` 约束 `lv = fl*hs`。
- **Parent 检查**：RR 扫描中 `revoke.id != parent.id`，门同为 `scan-id-neq`，无额外 Poseidon。
- **多事件状态连接**：`q_state` 门 `out = in + flag*(new−in)` + copy_equal 把 event0 输出 cell 接到 event1 输入 cell，纯算术约束，无 Poseidon。
- **Witness 分配**：`assign_grant_words`/`assign_scan_leaf`/`scan_id_neq` 每次都在 region 中新增 advice 赋值；region 创建**无条件**（keygen blank 与 prove real 必须同布局），因此行数与事件类型无关。

## 3. 结构指标 → 成本的映射（不作等同）

| 维度 | 值 | 与 proving time 的关系 |
| --- | --- | --- |
| Poseidon permutations | 505（扫描 344） | 主要但非唯一驱动；每个 permutation 展开为多轮 S-box 约束 |
| constraint polynomials | 43 | 决定 quotient 多项式与零知识 check 规模；与 permutation 数非线性相关 |
| advice columns | 39 | 决定 witness 多项式数量与 MSM 规模 |
| selectors | 30（含压缩前） | 经 Halo2 selector compression 压入 fixed 列 |
| K=15 → rows | 32768 | 行数上限；实际占用由 region 分配决定，未逐 region 精确统计）

**诚实边界：**
- 未做逐门/逐 region 的约束密度画像，故不能断言"Poseidon 占 proving time 的 X%"。344/505=68.1% 是 **permutation 数量占比**，不是时间占比。
- 未拆分 keygen / prove / verify 各自的 Poseidon 开销。
- benchmark 为墙钟中位数，含内存分配、MSM、FFT 等与约束数无简单线性关系的成本。

## 4. 归因结论（供 Phase 2/4 使用）

1. **全树扫描是主要的可优化对象**：344 个 permutation（68.1%）来自扫描；若能用局部证明替代全树枚举，理论上有下降空间。
2. **叶子重算占扫描的一半以上**：GR scan leaf 160 + RR scan leaf 64 = 224，占扫描 344 的 65%。这两项来自"必须提供叶子 preimage 并在电路内重算"的约束（因为叶子是 Poseidon 承诺，无法从哈希反推 ID）。
3. **root rebuild 是固定开销**：120 permutations，随树容量线性（每节点 2 perm）。要降低需改变 Merkle 结构或承诺方式，触及 D3-01 冻结规则。
4. **ID 不等与状态连接是廉价算术**：不产生 Poseidon，不是首要优化目标。
5. **成本与事件类型无关**：region 无条件创建，GG/GR/RR 三者 permutation 数相同（均 505），与 benchmark 观测到的相近 prove 时间一致。

下一步（Phase 2/4）据此聚焦：**能否用更少的叶子哈希/局部非成员证明替代 344 个扫描 permutation**，同时不削弱完整 ID 唯一性与 Parent 撤销有效性。
