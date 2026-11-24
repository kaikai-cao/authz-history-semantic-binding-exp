# EXP-D3-04 — Phase 3: State-Commitment Interface & Security Boundary

## 0. 定位

设计两种把索引根 `IR` 暴露给 verifier 的公开接口，比较其 verifier 兼容性、状态锚定成本与电路开销。承接 Phase 0 修正：`IR` 不必然新增 public instance。

## 1. 当前状态承诺结构（冻结事实）

`e_r1_circuit.rs:1716-1739`：

```
C_prev = H(D_state, GR_prev, RR_prev, epoch_prev, policy)   // 5 words
C_next = H(D_state, GR_next, RR_next, epoch_next, policy)   // 5 words
```

8 个 public 值（单 instance 列 row 0..7）：
`[C_prev, epoch_prev, C_next, epoch_next, policy_id, transition_version, D_E, event_count]`。

`D_state = domain_field("D3-STATE-v1")`（`a_constants` / 编码域标签）。

## 2. 接口 A：新增公开实例承载索引根

**方案**：扩展 instance，新增 `IR_prev`、`IR_next`（两个值）。

- 电路：`constrain_instance(ir_prev, instance, row 8)`、`(ir_next, row 9)`；`IR` 由索引电路更新并绑定。
- verifier：实例数量从 8 → 10，verifier 与状态锚定协议需读取新值。
- `C_prev/C_next` 可保持不变（索引根独立公开）。

| 维度 | 评价 |
| --- | --- |
| verifier 兼容 | 需改 verifier 实例解析（8→10），破坏"8 值冻结"的字面约束 |
| 状态锚定成本 | 锚定方需额外提供 `IR_prev/IR_next`，并证明其与 GR/RR 一致 |
| 电路开销 | 索引状态更新电路 + 2 个 instance 绑定 |
| 域分离 | 可复用 `D3-STATE-v1` 或为 IR 加新标签 |
| 语义清晰 | IR 独立可见，审计直接 |

## 3. 接口 B：索引根并入 C_prev/C_next（推荐研究方向）

**方案**：不改 public 值数量，扩展状态承诺输入：

```
C_prev' = H(D_state', GR_prev, RR_prev, IR_prev, epoch_prev, policy)   // 6 words
C_next' = H(D_state', GR_next, RR_next, IR_next, epoch_next, policy)   // 6 words
```

8 个 public 值数量不变（仍是 row 0..7 的 C_prev/epoch_prev/C_next/...），只改 `C_prev/C_next` 承诺的内部语义。

| 维度 | 评价 |
| --- | --- |
| verifier 兼容 | 实例数量不变（8），但 verifier 对 `C_prev/C_next` 的语义解释需升级；若 verifier 只做透明重算则天然兼容 |
| 状态锚定成本 | 锚定方需在承诺里纳入 IR；不改实例接口，但需新域标签版本 `D3-STATE-v2` 区分 |
| 电路开销 | 每个承诺多 1 word（6 而非 5），Poseidon 输入从 5→6 words（rate 2，permutation 3→3，不变）；索引更新电路仍在 |
| 域分离 | **必须新版本** `D3-STATE-v2`（或 `D3-STATE-IR-v1`），避免旧承诺语义混淆 |
| 语义清晰 | IR 隐含在承诺内，需 verifier/锚定协议理解新格式 |

**关键观察**：`H(5 words)` 与 `H(6 words)` 在 rate=2 下都是 `ceil(6/2)=3` permutations（`hash_words` 对 5 words 也是 3），所以接口 B 的承诺哈希成本**不增加 permutation 数**。主要新增成本是索引结构本身与一致性约束，不是承诺哈希。

## 4. 两种接口对比

| 维度 | A 新增实例 | B 并入承诺 |
| --- | --- | --- |
| public 值数量 | 8→10 | 保持 8 |
| verifier 实例解析 | 需改 | 不变 |
| 承诺语义版本 | 可不变 | 需新 `D3-STATE-v2` |
| 承诺哈希 perm | 不变 | 不变（5→6 words 仍 3 perm） |
| 审计可见性 | IR 独立可见 | IR 隐含于 C |
| 状态锚定升级 | 加两个锚定值 | 改承诺格式 + 域版本 |
| 推荐度 | 备选 | **优先研究**（保持 8 值冻结） |

## 5. 安全边界

两种接口都**不自动解决**：
- 索引与 GR/RR 的转换一致性（Phase 1 §2.1，需电路门控同步更新）；
- S0 索引与 GR/RR 初始一致性（Phase 1 §2.2，可信锚定）；
- `key_field` SHA-256→F 单射性、canonical slot、Bridge/checkpoint、新鲜性、ALLOW/DENY、完整历史、Cascade、递归——这些仍是外部信任或非目标。

接口改变只解决"IR 如何被 verifier 看到"，不解决"IR 是否可信"。任何声称"把 IR 塞进承诺就证明了索引正确"的说法都是错误的。

## 6. 本阶段结论

接口 B（并入 `C_prev/C_next`，保持 8 个 public 值）是更契合冻结约束的研究方向，且承诺哈希 permutation 不增加；代价是需新状态承诺域版本与 verifier/锚定协议同步理解新格式。接口 A 更直观但需扩展实例接口、破坏 8 值冻结字面约束。两者都需额外索引一致性约束，非零成本。决策留待 Phase 5，结合 Phase 4 实验结果。
