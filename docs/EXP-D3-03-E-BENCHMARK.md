# EXP-D3-03-E — Phase 4 成本测量与 A/B/C/E 对比

**基线**：`b9a8fc7f0e66119f23877317836d70d01b174c1b`
**分支**：`exp-d3-03-e`
**测量文件**：`tests/d3_03_e_bench.rs`（ignored，显式运行）
**运行命令**：

```bash
RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  cargo test --release --test d3_03_e_bench -- --ignored --nocapture
```

---

## 1. 环境与方法

| 项目 | 值 |
| --- | --- |
| 操作系统 | Windows 11 家庭版 Insider Preview 中文版，10.0.26320 |
| CPU | Intel(R) Core(TM) i7-14700，20 核 / 28 逻辑线程 |
| 内存 | 34,031,325,184 bytes（约 31.7 GiB） |
| Rust | `rustc 1.98.1 (48a229cea 2026-09-01)`，`x86_64-pc-windows-gnu` |
| Cargo | `cargo 1.98.1 (797e8a9bc 2026-08-05)` |
| 线程 | `RAYON_NUM_THREADS=1`、`OMP_NUM_THREADS=1`；机器可见 28 线程，但本测量固定为 1 |
| 模式 | `cargo test --release`；Halo2 0.4.0 / Pallas-Vesta / Poseidon P128Pow5T3 |
| 采样 | 每电路 3 次完整 keygen+prove+verify，取中位数（第 2 个样本） |
| 随机源 | `StdRng::seed_from_u64(20261123)`，每次采样同种子 |
| 预热 | 无预热；冷启动包含首次 assembly/JIT-like 缓存效应，但三组采样趋势稳定 |

**计时口径**：`keygen_ms` 包含 `keygen_vk + keygen_pk`；`prove_ms` 只含 `create_proof`；`verify_ms` 只含 `verify_proof`。`Params::new` 与 host 侧 instance 重算在计时区间外。口径与 A/B/C 既有测量保持一致。

---

## 2. 三次采样原始输出

```text
E_BENCH sample=1 circuit=A k=12 proof_bytes=3904 keygen_ms=795 prove_ms=1431 verify_ms=42 verify_ok=true
E_BENCH sample=2 circuit=A k=12 proof_bytes=3904 keygen_ms=796 prove_ms=1406 verify_ms=42 verify_ok=true
E_BENCH sample=3 circuit=A k=12 proof_bytes=3904 keygen_ms=787 prove_ms=1427 verify_ms=42 verify_ok=true
E_BENCH sample=1 circuit=B k=12 proof_bytes=5696 keygen_ms=1381 prove_ms=1845 verify_ms=42 verify_ok=true
E_BENCH sample=2 circuit=B k=12 proof_bytes=5696 keygen_ms=1342 prove_ms=1816 verify_ms=41 verify_ok=true
E_BENCH sample=3 circuit=B k=12 proof_bytes=5696 keygen_ms=1331 prove_ms=1816 verify_ms=41 verify_ok=true
E_BENCH sample=1 circuit=C k=12 proof_bytes=5760 keygen_ms=1331 prove_ms=1805 verify_ms=43 verify_ok=true
E_BENCH sample=2 circuit=C k=12 proof_bytes=5760 keygen_ms=1331 prove_ms=1813 verify_ms=41 verify_ok=true
E_BENCH sample=3 circuit=C k=12 proof_bytes=5760 keygen_ms=1334 prove_ms=1792 verify_ms=42 verify_ok=true
E_BENCH sample=1 circuit=E-GG k=13 proof_bytes=7040 keygen_ms=3327 prove_ms=4106 verify_ms=73 verify_ok=true
E_BENCH sample=2 circuit=E-GG k=13 proof_bytes=7040 keygen_ms=3300 prove_ms=4154 verify_ms=73 verify_ok=true
E_BENCH sample=3 circuit=E-GG k=13 proof_bytes=7040 keygen_ms=3276 prove_ms=4065 verify_ms=72 verify_ok=true
E_BENCH sample=1 circuit=E-GR k=13 proof_bytes=7040 keygen_ms=3343 prove_ms=4087 verify_ms=74 verify_ok=true
E_BENCH sample=2 circuit=E-GR k=13 proof_bytes=7040 keygen_ms=3324 prove_ms=4059 verify_ms=73 verify_ok=true
E_BENCH sample=3 circuit=E-GR k=13 proof_bytes=7040 keygen_ms=3303 prove_ms=4098 verify_ms=73 verify_ok=true
E_BENCH sample=1 circuit=E-RR k=13 proof_bytes=7040 keygen_ms=3307 prove_ms=4058 verify_ms=74 verify_ok=true
E_BENCH sample=2 circuit=E-RR k=13 proof_bytes=7040 keygen_ms=3339 prove_ms=4158 verify_ms=74 verify_ok=true
E_BENCH sample=3 circuit=E-RR k=13 proof_bytes=7040 keygen_ms=3315 prove_ms=4113 verify_ms=76 verify_ok=true
```

---

## 3. 中位数汇总

| 电路 | K | Proof size | Keygen | Prove | Verify |
| --- | --- | --- | --- | --- | --- |
| A（状态承诺） | 12 | 3904 B | 795 ms | 1427 ms | 42 ms |
| B（Grant 创建 + Parent Binding） | 12 | 5696 B | 1342 ms | 1816 ms | 41 ms |
| C（DirectOnly 单撤销） | 12 | 5760 B | 1331 ms | 1805 ms | 42 ms |
| E-GG（Grant+Grant） | 13 | 7040 B | 3300 ms | 4106 ms | 73 ms |
| E-GR（Grant+Revoke，核心） | 13 | 7040 B | 3324 ms | 4087 ms | 73 ms |
| E-RR（Revoke+Revoke） | 13 | 7040 B | 3315 ms | 4113 ms | 74 ms |

程序输出摘要：

```text
E_BENCH_MEDIAN samples=3 rayon=1 omp=1 mode=release
E_BENCH_MEDIAN circuit=A k=12 proof_bytes=3904 keygen_ms=795 prove_ms=1427 verify_ms=42
E_BENCH_MEDIAN circuit=B k=12 proof_bytes=5696 keygen_ms=1342 prove_ms=1816 verify_ms=41
E_BENCH_MEDIAN circuit=C k=12 proof_bytes=5760 keygen_ms=1331 prove_ms=1805 verify_ms=42
E_BENCH_MEDIAN circuit=E-GG k=13 proof_bytes=7040 keygen_ms=3300 prove_ms=4106 verify_ms=73
E_BENCH_MEDIAN circuit=E-GR k=13 proof_bytes=7040 keygen_ms=3324 prove_ms=4087 verify_ms=73
E_BENCH_MEDIAN circuit=E-RR k=13 proof_bytes=7040 keygen_ms=3315 prove_ms=4113 verify_ms=74
```

解读边界：

- 本表是 **固定单线程** 的同轮测量；与 C 阶段未固定线程的单样本记录（`A 3904/1519/2785/85`、`B 5696/2601/3616/76`、`C 5760/2542/3507/80`）不可直接比较绝对 ms。旧的 A 冻结记录 `3904B / 1490ms / 2737ms / 76ms` 与 C 阶段记录均保持不变。
- 可稳定观察的是结构量：A → B → C → E 的 proof size 分别为 3904 → 5696 → 5760 → 7040 B。E 相对 C 增加 1280 B，与“两事件槽 + 中间状态 cell 连接 + gated equality”一致。
- 三种 E 组合的 proof size 完全相同（7040 B），说明当前实现使用统一两槽电路形状，不按事件类型裁剪电路。证明时间差异落在采样噪声范围内，不能声称 E-GG/E-GR/E-RR 有稳定快慢顺序。
- `K_E=13` 是 E 阶段的工程决策，不是原始设计参数，也不是逐门精确规模推导的结果。本阶段未做 E 的 K 变体可行性/成本扫描。

---

## 4. 结构指标（不是约束数）

按源码静态计数：

| 指标 | A | B | C | E |
| --- | --- | --- | --- | --- |
| Selector family | 9 | 19 | 19 | 24 |
| Advice columns | 10 | 21 | 21 | 30 |
| `create_gate` 调用数 | — | — | — | 25 |
| 核心 transition 源码行数 | 990 | 1475 | 1290 | 1948 |
| 最大 K（本实验冻结/沿用） | 12 | 12 | 12 | 13 |

E 的源码行数构成：

```text
e_constants.rs   52
e_types.rs      414
e_types_host.rs  72
e_circuit.rs   1410
--------------------
total          1948
```

说明：

- E 的 25 个 gate family 复用 24 个 selector：`epoch-pref` 与 `epoch-less` 共用 `q_epoch`。
- E 新增的关键门是 `gated-eq` 与 `state-transition`；其余大多沿用 A/B/C 的规范编码、Merkle opening、字段派生、epoch 与 batch 约束。
- selector 数、advice 列数、gate family 数和源码行数都只是代码结构指标，**不是约束数量，也不是电路规模**。本阶段没有逐门约束统计工具，明确记为“未精确统计”。

---

## 5. 测试成本

完整 release 套件：**199 passed / 0 failed / 2 ignored**（两个 ignored 分别是 C 与 E 的显式基准）。

单次测试二进制汇总：

```text
E mock   22 passed / 0.56s
E proof   2 passed / 25.87s
full release suite (fixed 1 thread) 199 passed / 2 ignored
```

其中 `E proof` 包含四种 E 组合真实证明与 P17 verifier 拒绝；详细输出见 `docs/EXP-D3-03-E-TEST-REPORT.md`。

---

## 6. 诚实边界

- 未做逐门约束数、实际使用行数、prover/verifier 内存或峰值 RSS 统计。
- 未做多线程对比；本表只固定 1 线程，不能外推到默认并行配置。
- 未做 E 的 K=11/12/13 变体扫描；不声称 K=13 是最小可行值。
- 三次采样足以观察量级与 proof size 稳定性，不构成严格性能分布结论；没有均值/方差/置信区间声明。
- 不能从本表推出“E 比 C 慢多少是固有代价”或“授权系统端到端性能已达标”；K 从 12 提升到 13、事件槽固定为 2、gated equality 的额外 region 都混杂在一起，未做消融。
