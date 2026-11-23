# EXP-D3-03-A — 基线审计（A1）

**日期**：2026-11-23
**基线**：`31f3765465d108c5540631be9f762af05d33770c`（`exp-d3-02-r2`）
**开发分支**：`exp-d3-03-a`
**阶段**：最小状态承诺绑定电路 + 真实证明验证；仅 DirectOnly，不实现完整状态机。

---

## 1. 基线核对

| 项 | 值 | 结论 |
| --- | --- | --- |
| `git rev-parse HEAD`（建分支前） | `31f3765…` | ✅ 与任务书基线一致 |
| 工作区（`git status --short`） | 空 | ✅ 干净 |
| 冻结实现 D3-01 / D2-A / D2-B | 未改 | ✅ 本轮仅新增 `src/transition/`，`src/lib.rs` 只加模块声明 + 更新顶部说明 |
| 固定向量 / 历史实验数据 | 未改 | ✅ |
| Halo2 依赖 | 本仓库原先**无** `halo2_proofs`/`halo2_gadgets` | 本轮按 D2-A 同版本引入 |

## 2. 工具链与实际版本（一手 `Cargo.lock` / `--version`）

| 组件 | 版本 | 来源 |
| --- | --- | --- |
| rustc | `1.98.1 (48a229cea 2026-09-01)` | `rustc --version` |
| cargo | `1.98.1 (797e8a9bc 2026-08-05)` | `cargo --version` |
| Halo2 | `halo2_proofs 0.4.0`（features `batch`, `floor-planner-v1-legacy-pdqsort`） | D2-A `Cargo.toml` 对齐 |
| halo2_gadgets | `0.6.0` | 同上 |
| halo2_poseidon | `0.2.0` | 本仓库 R2 既有 |
| pasta_curves | `0.6.0`（`glv`） | 本仓库 R2 既有 |
| ff / group | `0.14` | 本仓库 R2 既有 |
| Poseidon 参数 | P128Pow5T3，width=3 / rate=2 / R_F=8 / R_P=56 | 一手 `halo2_poseidon-0.2.0` |
| Halo2 k（实测采用） | **12**（R2 目标 13） | A 骨架实际需求约 1100 行，k=12 充分；k=13 keygen/create_proof >20 分钟未完成 |

**没有升级任何依赖版本来绕过编译问题**；新增的两项均锁定到 D2-A 已验证的精确版本。k 从 13 降到 12 是因实测性能（非依赖问题），已在 `docs/d3_03_a_circuit_notes.md` §7 与 `results/d3_03_a_summary.md` §13 如实记录。

## 3. 可复用模块（来自 D2-A / D3-01 一手审查）

| 模块 | 来源 | 复用方式 |
| --- | --- | --- |
| `Pow5Chip` + `Hash<..., ConstantLength<L>, 3, 2>` 电路 Poseidon | D2-A `circuit.rs` `hash_words` | 直接复用配置与调用模式 |
| `label → field` 域标签常量 | D3-01 `encoding::domain_field`/`field_from_bytes` | 直接调用，域标签 `D3-STATE-P-v2`、`D3-BATCH-v1` 为 fixed 常量 |
| `keygen_vk/pk → create_proof → SingleVerifier` 真实证明流程 | D2-A `tests/test_proof_roundtrip.rs` | 直接复用 0.4 API 与 seeded `StdRng` |
| Pallas Fp 模数与规范编码 | `pasta_curves-0.6.0/src/fields/fp.rs` + R2-02 | 域常量写在 `constants.rs`，电路内做字典序比较 |

## 4. 当前缺失模块（本阶段补齐）

- Halo2 依赖与 `src/transition/` 模块（原仓库无电路代码）。
- `TransitionInstances`（8 字段固定顺序）、`TransitionPublicInputs`（11 字段）、`TransitionWitness`。
- 电路内 Pallas Fp 规范域编码检查（`int_BE(b) < p`）——R2-02 类别 (I)，此前仅链下。
- `C_prev`/`C_next`/`D_E` 的电路内 Poseidon 重算与 instance 绑定。
- `policy_id`/`transition_version` 常量 gate，批次 padding/顺序/计数约束。
- A01–A18 测试矩阵与真实 proof 流程。

## 5. 本阶段新增 / 修改文件清单

**新增**
```
src/transition/mod.rs
src/transition/constants.rs
src/transition/types.rs
src/transition/circuit.rs
tests/d3_03_a_smoke.rs
tests/d3_03_a_mock.rs
tests/d3_03_a_proof.rs
docs/d3_03_a_circuit_notes.md
results/d3_03_a_baseline_audit.md   (本文件)
results/d3_03_a_perf.txt            (真实证明计时，由测试 stdout 捕获)
```

**修改（仅两处，均为计数勘误 / 模块注册，不涉及冻结语义）**
```
Cargo.toml                              (新增 halo2_proofs / halo2_gadgets / rand 依赖)
src/lib.rs                              (pub mod transition; + 顶部范围说明)
docs/d3_02_r2_transition_interface.md   (11 字段 / 3 Hash32 勘误)
results/d3_02_r2_freeze_report.md       (同上勘误)
```

> R2 接口计数勘误依据任务书第 2 节：结构体实为 11 字段（3 Hash32 + 4 Field + 2 u64 + 2 u32），
> 其中 3 个 Hash32 不进电路，8 个进 instance。R2 文档原写"12 字段 / 4 个 Hash32"为计数笔误；
> 本阶段只改数字与勘误说明，字段语义、域标签、顺序均未变。

## 6. 范围边界（本阶段明确不做）

- 不实现 Grant/Revoke 状态机、Parent Binding、Scope/Resource、Merkle 更新。
- 不引入 Cascade 策略；不扩展 Bridge / QC / 共识。
- 不声称本电路证明 ALLOW 或 DENY；不声称历史完整性或执行时新鲜性。
- 不修改 R2 冻结的编码规则与域标签（仅修正文档计数）。
