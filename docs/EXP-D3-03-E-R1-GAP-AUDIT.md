# EXP-D3-03-E-R1 — Phase 0 缺口与 ID/槽位映射审计

**基线**：`56342803d492bb8aaa4ffd44b5586947fd7d0d0c`（`exp-d3-03-e`）
**工作分支**：`exp-d3-03-e-r1`
**审计对象**：E 双事件 Halo2 电路、E witness builder、D 参考状态机、D3-01 canonical slot 规则。
**结论摘要**：三个缺口同源——E 只证明 prover 指定的单个 Merkle slot 的空/非空与字段关系，没有证明 ID 在整棵 GR/RR 中的唯一性与撤销状态。全树扫描可作为语义完整的基线构造，但叶子是 Poseidon 承诺，必须同时提供每个非空叶子的 preimage 并在电路内重算叶子哈希；不能只扫描叶子哈希值。

---

## 1. 基线与工作区

Phase 0 开始时：

```text
branch = exp-d3-03-e
HEAD   = 56342803d492bb8aaa4ffd44b5586947fd7d0d0c
remote exp-d3-03-e = 56342803d492bb8aaa4ffd44b5586947fd7d0d0c  (GitHub API 核验)
git status --short = empty
git diff --check = clean
```

随后创建 `exp-d3-03-e-r1`。GitHub 代理一度返回 502，`git fetch origin` 不可用；远端一致性以 GitHub API `/git/ref/heads/exp-d3-03-e` 核验。未覆盖其他分支。

用户任务书列出的 `src/transition/e_event.rs` 与 `src/transition/e_transition.rs` 在本仓库不存在；实际 E 源码为 `e_circuit.rs`、`e_constants.rs`、`e_types.rs`、`e_types_host.rs`，以实际路径审计。

---

## 2. 三个缺口的最小反例与源码事实

### 2.1 Parent 撤销有效性缺口

**源码事实**：

- `src/transition/e_circuit.rs:1148-1155`：Parent 只做一次 GR opening，叶子由 `e.parent` 的 9 词重算。
- `src/transition/e_circuit.rs:1279-1285`：`gated_eq(grant_cells[i], parent_opening.root, gr_in[i], "grant parent in GR")`。
- 同一 Grant 分支没有对 `rr_in[i]` 做任何 Parent ID 检查；`rr_in` 只在 Revoke 分支的 `"revoke slot empty in RR"` 使用（`e_circuit.rs:1303-1310`）。

**最小反例**：

```text
S0: GR slot1 = Parent A; RR slot5 = revoke(A)
Event 0: Grant B, parent_slot=1, child_slot=2
```

当前 E 会通过：Parent opening 在 GR 中成立，child slot 空，字段派生成立；但 D 参考模型要求 `valid_S(A) = A∈G ∧ A∉R = false`（`mixed_event_state.rs:186-190`），`apply_grant` 返回 `ParentNotValid`（同文件 `373-384`）。

**双事件最小反例**：

```text
Event 0: Revoke(A)  → RR_1 含 A
Event 1: Grant(B, Parent=A)
```

当前 E 的第二个 Grant 只检查 `gr_in[1]`（来自事件 0 输出），完全不看 `rr_in[1]`；这是 P04 的目标缺口。

---

### 2.2 Grant ID 全局唯一性缺口

**源码事实**：

- `src/transition/e_circuit.rs:1156-1163`：只把 `child_slot` 的 opening 叶子固定为 `zero_cell`（空叶）。
- `src/transition/e_circuit.rs:1287-1294`：`gated_eq(grant_cells[i], child_old_opening.root, gr_in[i], "grant child slot empty")`。
- `child_slot` 来自 witness（`e_types.rs:63-64`、`202-216`），没有任何电路约束把它绑定到 ID。
- 事件承诺绑定的是 child 字段（`e_circuit.rs:1348+`），但没有检查 child.id 是否已存在于树中。

**最小反例**：

```text
S0: GR slot2 = Grant A (id=1001)
Event 0: Grant(A, child_slot=3)     // 新槽位
```

当前 E 会通过：`slot3` 为空，事件字段自洽；但 D 参考模型 `state.grants.contains_key(&g.id)` 成立，返回 `DuplicateGrant`（`mixed_event_state.rs:374-375`）。这说明“某槽位为空”不等于“该 ID 不存在”。

**双事件跨槽反例（P08/P09）**：事件 0 创建 ID=A 到 slot2，事件 1 用 slot3 再创建 ID=A；第二个事件的 `GR_1` 中 slot3 为空，当前约束无法拒绝。

---

### 2.3 Revoke ID 全局唯一性缺口

**源码事实**：

- `src/transition/e_circuit.rs:1249-1256`：只把 `revoke_slot` 的 RR opening 叶子固定为 0。
- `src/transition/e_circuit.rs:1303-1310`：`gated_eq(revoke_cells[i], rr_old_opening.root, rr_in[i], "revoke slot empty in RR")`。
- `revoke_slot` 来自 witness（`e_types.rs:72-73`、`255-259`），没有电路约束绑定到 grant_id。
- target opening 只证明选定 GR 槽位含目标 Grant（`e_circuit.rs:1295-1302`），不证明 RR 中不存在同一 ID。

**最小反例**：

```text
S0: GR slot2 = Grant A; RR slot5 = revoke(A)
Event 0: Revoke(A, revoke_slot=6)
```

当前 E 会通过：`slot6` 为空，target 在 GR 中存在，revoker=issuer；但 D 参考模型 `state.revokes.contains_key(&r.grant_id)` 成立，返回 `AlreadyRevoked`（`mixed_event_state.rs:418-419`）。

**双事件跨槽反例（P12/P13）**：事件 0 Revoke(A, slot2)，事件 1 Revoke(A, slot3)。当前 E 只看事件 1 的 `RR_1.slot3` 是否为空，无法拒绝。

---

## 3. ID 编码与槽位映射审计

### 3.1 Grant ID / Revoke ID 的 Field 编码

| 问题 | 审计结论 |
| --- | --- |
| Grant ID 在电路中是什么类型？ | `GrantFieldsB.id: F`，Pallas Base field 元素（`src/transition/b_types.rs:20-27`）。 |
| 如何编码成 Field？ | 由类别 II `key_field(grant_id)` 预映射得到；映射到电路是 `EXTERNAL_TRUST`，R2-02 冻结，不在 E/E-R1 电路中重算 SHA-256（`b_types.rs:6-8`）。 |
| Revoke ID 是否同编码？ | 是。`RevokeFieldsC.grant_id: F` 与 `GrantFieldsB.id: F` 同为 Pallas Base 域元素，电路用 `copy_equal(target_words[1], rv_id)` 绑定（`e_circuit.rs:1220`）。 |
| 是否存在 Field 编码碰撞？ | 在“已给定外部映射输出”的前提下比较完整 F 元素；E-R1 不证明 SHA-256→F 映射的全局单射性。若外部映射不同 ID 映射到同一 F，E-R1 仍会视为同一 ID。该风险记为外部信任，不是本轮可修复项。 |

### 3.2 GR/RR 槽位规则

| 问题 | 审计结论 |
| --- | --- |
| 槽位由什么决定？ | E 中由 witness 显式给出：`parent_slot`、`child_slot`、`target_slot`、`revoke_slot`（`e_types.rs:60-76`）。场景 builder 按指定 slot 写树（`e_types.rs:212-218`、`255-260`）。 |
| 槽位是否由 ID 确定？ | **否**。当前 E 没有 `slot = f(ID)` 约束；同一 ID 可写任意空槽，这是三个跨槽攻击的根因。 |
| 是否有碰撞处理？ | E 电路没有 canonical probing；仅在 host builder 中“指定即写”。D3-01 有完整 canonical assignment。 |
| Merkle Opening 能否证明 ID 全局不存在？ | **不能**。depth-4 opening 只证明某一条路径的叶子值和根，不能推出其他 15 个槽位没有同一 ID。 |
| D3-01 `D3-SLOT-v1` 与 E 是否一致？ | **不一致，且不可直接拼接**。D3-01 用 SHA-256 `field_from_bytes("D3-SLOT-v1", 32-byte key)` 取低位 + 按 32-byte ID 排序的线性探测（`src/grant_tree.rs:42,79-134`）；E 用 Poseidon 树与预映射的 F 字段 ID，没有 SHA-256 电路、没有 32-byte key、没有排序探测约束。 |

---

## 4. 可复用 Chip / 需要新增的约束

### 可复用

- 现有 `hash_words` gadget：电路内重算 9 词 Grant leaf / 4 词 Revoke leaf / 2 词 Node（`e_circuit.rs:373-378`、`1083-1094`、`1230-1240`）。
- 现有 `assign_opening_path`：depth-4 path-select 与 root 重算（`e_circuit.rs:341-382`）。
- 现有 `gated_eq`：`flag·(left-right)=0`，用于按事件类型开启/关闭检查（`e_circuit.rs:387-411`）。
- 现有 `state_transition` / cell copy：事件 1 输入绑定事件 0 输出（`e_circuit.rs:417-447`、`1342-1345`）。
- 现有 u64 pair gadget：scope/prefix/epoch 语义（不修改）。

### 必须新增（方案 A：全树扫描）

1. 对当前 `gr_in[i]` 的 16 个 GR 叶子提供 **preimage witness**：每个槽位给出 `GrantFieldsB`（id/issuer/subject/prefix/scope/parent/epoch，valid 固定 1；空槽用独立 empty flag）。
2. 电路内对每个非空 preimage 重算 `Poseidon(D_GRANT, ...)` 得到叶子，构建 16 叶 depth-4 Merkle 树并重算根，用 `gated_eq` 绑定到 `gr_in[i]`。
3. 对每个非空 GR 叶子检查 `leaf.id != target_id`；空叶不能被当成 ID=0 的有效记录（必须单独 empty flag 门控）。
4. 对当前 `rr_in[i]` 的 16 个 RR 叶子提供 preimage（`grant_id, revoker, epoch`），重算 4 词 revoke leaf 与 RR 根，绑定 `rr_in[i]`，检查 `leaf.grant_id != target_id`。
5. Parent 未撤销：Grant 分支对 `parent.id` 在 RR 全树执行 ID 不存在检查，绑定当前 `rr_in[i]`。
6. Revoke 未重复：Revoke 分支对 `revoke.grant_id` 在 RR 全树执行 ID 不存在检查，绑定当前 `rr_in[i]`。
7. 新增 “ID 不等” gadget：两个 F 元素 `a != b` 的约束表达（`a-b` 非零需 witness inverse + `(a-b)*inv=1`，或后续评估更省的方案）；不能用 host 布尔值。

**最小修改范围**：只新增 E-R1 模块/适配层与两个事件槽的 witness 字段；A/B/C/D 零改；`mod.rs` 仅注册。8 个 public instance 不变。

---

## 5. 预计新增开销（结构估算，非精确约束数）

| 项目 | 每次全树扫描 |
| --- | --- |
| GR 叶子 preimage Poseidon（9→1） | 最多 16 次（空槽可省） |
| RR 叶子 preimage Poseidon（4→1） | 最多 16 次（空槽可省） |
| 内部节点 Poseidon（2→1） | 每个树 15 次，GR/RR 合计 30 次 |
| Merkle root 绑定 | GR/RR 各 1 次 gated_eq |
| ID 不等 gadget | 每个非空叶子 1 次；GR/RR 分开 |

两事件最多需要 GR 全树扫描（Grant 唯一性、Parent 存在/未撤销）与 RR 全树扫描（Parent 未撤销、Revoke 未重复），每事件两类树都可能触发。当前估算只能说明量级明显增加，不能替代实测；Phase 1 需要先实测/估算 K 与证明时间。未逐门统计约束数。

---

## 6. 当前方案能否严格保持 D 状态机语义

**可以，但必须采用“全树扫描 + preimage 重算”，不能采用“只比较叶子哈希”**。

理由：

- D 的语义是 ID 级别：`valid(id) = id∈G ∧ id∉R`、`DuplicateGrant(id)`、`AlreadyRevoked(id)`；键是 grant_id，而不是 Merkle slot。
- E 当前叶子是 Poseidon 承诺，不是明文记录；电路不能从叶子哈希反推出 ID。要实现 `∀i, ID(L_i)≠ID`，必须让 prover 提供每个叶子的 preimage，并在电路内重算 `leaf_hash` 与 Merkle root，才能把“叶子值”解释为“某个 ID 的记录”。
- 若只比较叶子哈希值，目标 ID 的未知字段（issuer/scope/epoch 等）无法构造完整叶子哈希；无法证明“没有同一个 ID 记录在别的槽位”。
- 全树扫描 + preimage 能直接对齐 D：`G_i`/`R_i` 的键集合被电路内 16 个 preimage 枚举并逐项比较；第二事件扫描 `GR_1`/`RR_1` cell，绑定中间状态。

若采用方案 B（canonical slot），需要引入 SHA-256 电路或新 Poseidon slot 版本、排序/探测约束、历史迁移与固定向量版本化；当前 E 与 D3-01 的编码不兼容，不能在 E-R1 中静默替换。因此 Phase 1 优先方案 A。

---

## 7. 停止条件检查

| 条件 | 结果 |
| --- | --- |
| ID Field 编码碰撞导致无法证明完整 ID 唯一性 | 未触发；E-R1 比较完整 F 元素，SHA-256→F 映射属外部信任。 |
| 全树扫描无法从当前 Merkle Root 重建原状态 | 未触发；现有 `hash_words` / Merkle gadget 可复用，需 Phase 1 实测成本。 |
| D3-01 canonical slot 与 E 树结构不兼容 | **已确认不兼容**；因此不采用方案 B，走方案 A。 |
| Parent 撤销检查无法绑定当前 RR 中间根 | 未触发；`rr_in[i]` 是 cell，可用 gated_eq 绑定。 |
| Revoke ID 唯一性无法通过当前 RR 证明 | 未触发；RR 全树扫描 + preimage 可证明。 |
| 全树扫描成本不可接受且无论证替代 | 待 Phase 1 成本评估。 |
| 必须修改 A/B/C/D | **未触发**；本轮只新增 E-R1 模块。 |

**Phase 0 结论**：继续 Phase 1。推荐方案 A（全树扫描 + 叶子 preimage 重算），并在构造设计文档中冻结成本与最小修改范围。
