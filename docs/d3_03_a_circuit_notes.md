# EXP-D3-03-A — 电路骨架、状态承诺绑定与规范域编码说明

**基线**：`31f3765…`（R2 冻结）｜**分支**：`exp-d3-03-a`｜**Halo2**：0.4 / Pallas / Poseidon P128Pow5T3｜**k**：12（R2 目标 13，见 §7 说明）

---

## 0. 一句话结论

A 阶段把 R2 冻结接口中的 8 个电路 instance 真正落到 Halo2 约束系统：`C_prev`/`C_next` 由电路内 Poseidon 从 witness 重算并 copy 到 instance；GR/RR 的 32B 规范域编码（`int_BE(b) < p`）由电路内布尔分解 + 字典序比较门强制；`policy_id`/`transition_version` 由常量 gate 绑定；批次承诺 `D_E` 由电路重算。A01–A16 在 MockProver 层全过，A17 真实 proof/verifier roundtrip 成功，A18 错误 instance 被 verifier 拒绝。**本电路不证明授权语义、历史完整性或新鲜性。**

## 1. 8 个 instance 的固定顺序（任务书第 2 节）

```
0 previous_state_commitment   (Field)
1 previous_epoch              (u64 → F::from，单射)
2 next_state_commitment       (Field)
3 next_epoch                  (u64 → F::from)
4 policy_id                   (Field，常量 gate)
5 transition_version          (u32 → F::from，常量 gate)
6 event_batch_commitment      (Field)
7 event_count                 (u32 → F::from)
```

`TransitionPublicInputs` 仍是 11 字段；3 个 Hash32（`previous_anchor_digest`/`layout_digest`/`vk_hash`）不进电路，由网关电路外核对。R2 文档计数勘误见 `results/d3_03_a_baseline_audit.md` §5。

## 2. 模块与职责

| 模块 | 文件 | 作用 |
| --- | --- | --- |
| `TransitionConfig` | `circuit.rs` | advice/fixed/instance/selector + Pow5Config |
| 规范域编码检查 | `circuit.rs::assign_root_encoding` | 32B → 256 bool + `< p` 字典序 + 域元素重构 |
| 状态承诺绑定 | `circuit.rs::hash_words`（C_prev/C_next） | 电路内 Poseidon 重算 → instance |
| `PolicyBindingChip` | `bind-policy` gate | `policy_id_pub == frozen constant` |
| `VersionBindingChip` | `bind-version` gate | `transition_version_pub == frozen constant` |
| `BatchCommitmentChip` | `slot-padding`/`active-*` gates + `hash_words` | 固定 3 槽 + padding + 顺序 + 计数 + 重算 |
| `TransitionCircuit` | `circuit.rs` | 汇总 + 8 instance copy |

> 说明：本阶段把 chip 实现为同一 config 下的门 + assign 函数，而非独立 struct；职责划分与上表一一对应，模块粒度符合"先跑通骨架、不提前拆分过度工程"的目标。

## 3. C_prev / C_next 的电路约束

```
D_STATE = domain_field("D3-STATE-P-v2")            // fixed，非 witness
C_prev  = Poseidon(D_STATE, gr_prev_f, rr_prev_f, prev_epoch, policy_id)
C_next  = Poseidon(D_STATE, gr_next_f, rr_next_f, next_epoch, policy_id)
```

- `D_STATE`、域标签与 `policy_id` 由 `constants.rs` 冻结；`gr_*_f`/`rr_*_f` 来自 witness 字节，经规范编码 gadget 重构。
- Poseidon 用 `halo2_gadgets` `Pow5Chip`，`ConstantLength<5>`，与 R2 §3.1 / §3.8 一致。
- 结果用 `constrain_instance(..., 0/2)` 绑定。A02/A03 改 instance、A04–A07 改 witness 均被拒。

**禁止 host 端计算后直接赋值 instance**：`expected_instances()` 仅供测试构造合法 statement；电路 `synthesize` 从不调用它，所有承诺在电路内重算。

## 4. GR/RR 规范域编码检查（本轮核心）

R2-02 类别 (I)：GR/RR 是域元素规范编码，必须 `int_BE(b) < p`、禁止静默模约简。

**电路实现**（完全 in-circuit，无 host 检查替代）：

1. 将 32B 大端字节分解为 256 个 bool（`q_bool_bit`）。
2. 模数 `p` 的每一位放入 fixed 列 `p_bit`（常量，非 witness）。
3. 逐位维护两个累加器（用 `Rotation::next()` 跨行）：
   - `pref[t+1] = pref[t] · (1 − (bit_t − p_t)²)` —— 前缀相等标志；
   - `less[t+1] = less[t] + pref[t] · (1 − bit_t) · p_t` —— 首次出现 `bit<p_bit` 后置 1。
4. 末行 `q_final` 约束 `less == 1` ⇒ 严格小于 p（`b == p` 时 less 恒 0 → 拒绝）。
5. 同时 `acc[t+1] = acc[t] + bit_t · 2^(255−t)`（fixed `weight` 列），`acc` 即 int_BE(b) 的域表示，直接作为 Poseidon 输入。

- 拒绝 `b == p`（A14）：字典序全等，`less` 不置位。
- 拒绝 `b > p`（A15）：最高不同位为 `bit=1,p_bit=0`，`less` 不置位。
- 字节序固定为**大端**（A16）：反序字节给出不同域元素，承诺失配被拒。
- 零值 / 边界值 / p−1 均可通过（规范域内）；一一对应性由 R2-02 §3 双射证明给出，电路只强制"落在规范定义域内"。

> 每个根占 257 行、4 个根必须放在**独立 region**（否则共享 advice 列会重叠覆盖——实现中已通过 4 次独立 `assign_region` 修正，并由冒烟测试验证）。

## 5. Policy / Version 绑定

- `policy_id` 由 R2-01 冻结规范计算（`SHA256(CircuitSpec)` → `field_from_bytes`），作为 `Expression::Constant` 嵌入 `bind-policy` gate；公开 instance[4] 必须等于它。
- `transition_version = 1` 嵌入 `bind-version` gate；instance[5] 必须等于它，旧证明在新规范下被拒。
- 注意边界：常量 gate 保证"公开 policy_id == 本电路常量"，但**注册表核对 vk_hash↔policy_id↔D_circuit 仍在网关电路外**（R1-03 / R2-01 §4）。跨 vk 重放靠注册表，非本电路。

## 6. Batch Commitment 与 padding

```
D_E = Poseidon(D_BATCH, n, c_1, c_2, c_3)          // 固定 3 槽，ConstantLength<5>
D_BATCH = domain_field("D3-BATCH-v1")              // fixed
```

- 未用槽 `c_i = batch_pad() = domain_field("D3-BATCH-PAD-v1")`，由 `slot-padding` gate 按 `active_i` 强制：`(1−active_i)(c_i−pad)=0`。
- `active_i` 布尔（`q_bool_active`）且单调（`active_{i+1}(1−active_i)=0`），保证序列 `[1,1,0]` 而非任意置位。
- `q_count` 约束 `n = Σ active_i`，`n` copy 到 instance[7]；顺序由 Poseidon 输入顺序绑定。
- 因此不同批次（不同 n 或不同 c_i 顺序）不会编码成同一承诺；padding 不会造成歧义。

## 7. 真实证明

`A17`：`Params::new(12)` → `keygen_vk` → `keygen_pk` → `create_proof`（seeded `StdRng`）→ 独立 `verify`。`A18`：同一 proof 在 `instance[0]+1` 下被 verifier 拒绝。实测 `proof_bytes=3904`、`keygen=1490ms`、`prove=2737ms`、`verify=76ms`，见 `results/d3_03_a_perf.txt`。

**k 从 13 降到 12 的原因**：任务书初始参数为 13，但 A 骨架实际行需求约 1100（4 根 × 257 + Poseidon + 批次），k=13 下 keygen/create_proof 在实测中 >20 分钟未完成；k=12（4096 行）充分容纳，16s 完成全部测试。本阶段验收不以规模达标为条件，故采用 k=12 并如实记录；升回 13 只需一处常量改动，留待 D3-03-B/C 电路扩展后重测。

## 8. 本电路不能声称的内容（诚实边界）

- 不是 ALLOW 证明：没有 Grant 叶子/路径、没有请求摘要，需与 D2-A π_path 组合。
- 不是 DENY 证明：非存在性语句，电路不覆盖。
- 不证明历史完整性（删撤销/跳事件/旧批次），不证明布局规范性，不验 Bridge 签名，不保证执行时新鲜性。
- 规范域编码只保证"落在 `< p` 的规范定义域"，类别 (II) SHA-256 摘要仍按 R2-02 走链下 `field_from_bytes`，本电路不碰。
- 约束数 / 证明时间为 A 阶段实测，不代表 D3-03-B/C 完整语义电路的规模。
