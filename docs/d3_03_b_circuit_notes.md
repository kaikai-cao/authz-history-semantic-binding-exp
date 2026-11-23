# EXP-D3-03-B — Parent Binding + 单 Grant 创建电路说明

**基线**：`cae2ec722c1beac7b7b5e366dffbe6338466f6ba`（D3-03-A 冻结）
**分支**：`exp-d3-03-b`｜**Halo2**：0.4 / Pallas / Poseidon P128Pow5T3｜**k**：12（沿用 A，实测容纳）
**接口来源**：`results/d3_03_b_interface_audit.md`（B1 审计 + B-INT-01~05 版本化补充）

---

## 0. 一句话结论

B 阶段在 A 的独立新模块里加入了一条真实的授权状态转换语义：`GR_prev` 中打开一个有效 Parent Grant（4 层 Merkle，方向位受门约束），再从该 Parent 派生一个 Child Grant（`issuer_child = subject_parent`、`parent_grant_id` 绑定、`scope` 子集、`resource` 前缀相等、`epoch` 单调、`valid=1`），并通过相同路径把 `GR_prev` 更新到 `GR_next`。B01–B14 + 5 个边界测试全过；真实 proof roundtrip 成功、错误 instance 被 verifier 拒绝。**不实现 Revoke/Cascade/多事件，仍不是 ALLOW/DENY 证明。**

## 1. 模块隔离（A 零改动）

新增 `src/transition/{b_constants,b_types,b_circuit}.rs` 与 `tests/d3_03_b_*.rs`；`mod.rs` 仅加注册与 re-export。A 的 `circuit.rs`/`types.rs`/`constants.rs`、A 固定向量、R2 Field 编码定义、D2-A/D2-B/D3-01 冻结实现**全部零改动**。完整 release 套件确认 A01–A18、D3-01 全部测试继续通过。

## 2. 叶子与节点哈希（B-INT-01/02）

```
GRANT_LEAF_B = Poseidon(D_GRANT, id_f, issuer_f, subject_f,
                        resource_prefix_f, scope_f, parent_key_f, epoch_f, valid_f)
node_hash    = Poseidon(D_NODE, left, right)
D_GRANT = domain_field("D3-GRANT-v1")   // fixed 常量，非 witness
D_NODE  = domain_field("D3-NODE-v1")
D_EVENT = domain_field("D3-EVENT-v1")
```
- 域标签走 D3-01 `domain_field`（SHA-256→域），与 A 的 `D3-STATE-P-v2` 同口径。
- `id/issuer/subject/parent_key` 是预映射域元素 witness（类别 II SHA-256 属 EXTERNAL_TRUST，电路不重算，R2-02）。
- `resource_prefix_f = Σ_{i=0}^{7} byte_i·256^(7−i)`，与 D3-01 前 8 字节前缀模型一致。
- 因叶子编码采用 B 专用 `resource_prefix_f` 且字段映射为 witness 域元素，**B 的 GR 根与 D3-01 固定向量根不相同**（B1 审计 §1-Q8 已声明，不声称兼容）。

## 3. 保持 8 个 instance 顺序不变

`0 C_prev · 1 prev_epoch · 2 C_next · 3 next_epoch · 4 policy_id · 5 transition_version · 6 D_E · 7 event_count`。11 字段 public statement、3 个 Hash32 网关锚均沿用 A，未新增公开输入。

## 4. Parent Opening（B2）

witness：parent 9 词 + 每层 `(dir, sibling, left, right, cur)`（d=4）。电路门：
- `q_grant_valid`：`valid` 词 == 1（专用 selector，D2-A-R1 教训）。
- `path-dir-bool`：`dir·(dir−1)=0`。
- `path-select`：`left=(1−dir)·cur+dir·sib`、`right=dir·cur+(1−dir)·sib`（每层启用）。
- `copy_equal(cur_cell, 上一层 node)`：链上一致；首层 `cur` copy 到 `GRANT_LEAF_B(parent)`。
- 顶层 root `copy_equal` 到 A 的 `gr_prev` 规范编码域元素 cell → 进入 `C_prev`（Poseidon 重算 + instance copy）。

篡改 Parent 字段（B04）、路径 sibling（B02）、方向位（B03）均被门或 copy 约束拒绝。**Parent 关键字段随即参与后续 issuer/scope/resource/epoch 关系**（见 §5），不是"只证明某 Field 在树中"。

## 5. Child Grant 创建关系（B3）

| 关系 | 电路机制 |
| --- | --- |
| `parent_grant_id` 绑定 | `copy_equal(child.parent_key, parent.id)` |
| `issuer_child = subject_parent` | `copy_equal(child.issuer, parent.subject)` |
| `scope_child ⊆ scope_parent` | 两侧 u64 各 64-bit bool 分解 + 逐位 `c·(1−p)=0`（`scope-subset` 门）+ 累加器 copy 回叶子 scope 词 |
| `resource_child ⪯ resource_parent` | 前缀 8 字节打包域元素；两侧各 64-bit 分解 + 逐位相等（`prefix-eq` 门）+ 累加器 copy 回叶子 resource 词 |
| `epoch_child ≥ epoch_parent` | 两侧 64-bit 分解 + 前缀相等/小于累加器（`epoch-pref`/`epoch-less` 门）+ 末位 `less==0`（`epoch-final`） |
| `epoch_next ≥ epoch_prev` | 同上 State 模式，copy 回公开 epoch cell |
| `valid_child = 1` | `q_grant_valid` 门 |
| 新 ID 不冲突 | 子槽位在 `GR_prev` 的旧叶子固定为 ZERO，opening 根 copy 到 `gr_prev`（B09） |

## 6. 新旧 Grant Root（B3/B4）

- `GR_prev`：Parent opening 重算根 == `gr_prev`。
- 子槽位旧根：以 `leaf=0` + `child_open` 重算 == `gr_prev`。
- 子槽位新根：以 `leaf=GRANT_LEAF_B(child)` + `child_open_new` 重算 == `gr_next`。
- `copy_equal` 两条子路径逐层 `(dir, sibling)`，强制"插入前后同一槽位"，故 `GR_prev → GR_next` 只差一个叶子（B10 改新路径被拒）。
- `C_prev/C_next` 由 A 的 Poseidon  gadget 从 `gr/rr/epoch/policy` 电路内重算 → instance。

## 7. Batch 绑定（B-INT-05）

`c_child = Poseidon(D_EVENT, TYPE_GRANT, child 字段...)` 在电路内重算并 `copy_equal` 到 `event_commitments[0]`；A 的 batch gadget 重算 `D_E = Poseidon(D_BATCH, 1, c_child, pad, pad)` → instance[6]。改 child 字段而 batch 不变即被拒（B12）。

## 8. 测试结果（详见 results/d3_03_b_summary.md）

- B01–B12（MockProver）+ 5 边界：17/17 过。
- B13 错误 instance：Verifier 拒绝。B14 真实 proof roundtrip：通过。
- 全部为 code-level 自测，非独立第三方审计。

## 9. 诚实边界

- 不是 ALLOW（无请求摘要/D2-A π_path）也不是 DENY（非存在性）。
- 不重算类别 II SHA-256（字段映射外部信任）；不证明 canonical slot 布局规范性（R2-03 外部信任）。
- 不实现 Revoke/Cascade/多事件/递归；epoch 新鲜度属外部；Bridge/Layout/VK 信任沿用 R2。
- D3↔D2-A 域标签仍未对齐；约束数为结构估算（见 summary），非逐门精确统计。
