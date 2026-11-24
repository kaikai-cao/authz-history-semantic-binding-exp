# EXP-D3-03-E-R1 — Phase 1 构造设计（冻结）

**基线**：`56342803d492bb8aaa4ffd44b5586947fd7d0d0c`
**分支**：`exp-d3-03-e-r1`
**前置**：`docs/EXP-D3-03-E-R1-GAP-AUDIT.md`
**决策**：选择 **方案 A：全树扫描 + 叶子 preimage 重算**；不修改 A/B/C/D，不引入 canonical slot 新规则，不扩展到三事件。

---

## 1. 选择方案 A 的理由

任务书建议优先方案 A，本审计后仍坚持该选择，原因是：

1. **语义完整性优先**：三个缺口都是 ID 级别，而不是槽位级别；要证明 `ID_new ∉ G` / `ID ∈ R` / `Parent ∉ R`，必须枚举当前状态记录的键集合。depth=4、capacity=16 使枚举可接受。
2. **不引入新信任假设**：方案 B 要么在电路内做 SHA-256（当前工程没有该 chip），要么定义新的 Poseidon slot 版本并迁移状态/固定向量；这两者都会在本轮引入尚未验证的 canonical slot 规则。
3. **与 D 语义一致**：D 参考模型把状态建模为 `BTreeMap<Id, GrantEvent>` 与 `BTreeMap<Id, RevokeEvent>`（`src/reference/mixed_event_state.rs:165-172`），逻辑有效性按 ID 键判断。全树扫描在电路内枚举 16 个叶子并比较完整 ID，直接对应这一抽象。
4. **成本是真实研究结论**：若全树扫描成本偏高，这本身是本轮要交付的“真实优化问题”，不能为了省成本偷偷换语义。

**不选择方案 B**：D3-01 的 `slot(ID)=SHA256(D3-SLOT-v1, full_32byte_ID) mod 16` 与 E 的 F 字段 ID + Poseidon 树不兼容；线性探测还要求电路证明排序、前置空槽、插入规范性与无重复 ID。当前没有 SHA-256 gadget，也没有冻结新版本。见 GAP-AUDIT §3.2。

---

## 2. 全树扫描的正确实现形态：叶子 preimage 重算

当前 GR 叶子是：

```
L = Poseidon(D_GRANT, id, issuer, subject, prefix_f, scope, parent_key, epoch, 1)
```

RR 叶子是：

```
R = Poseidon(D_REVOKE, grant_id, revoker, epoch)
```

叶子是承诺值，不是明文 ID。**不能**从 `L` 或 `R` 提取 ID；因此电路不能“解析叶子 ID”。

本轮采用的形式是：

- prover 为 16 个槽位分别提供叶子 preimage（GrantFieldsB / RevokeFieldsC 或 empty flag）；
- 电路内重算每个非空叶子的 Poseidon 承诺；
- 电路内用 16 个叶子按 depth-4 结构重算 Merkle root；
- 用 gated_eq 把该 root 绑定到当前输入根 `gr_in[i]` / `rr_in[i]`；
- 在 preimage 的 ID 字段上执行 `ID != target_id` 检查。

空槽必须有独立的 boolean flag；空槽的 preimage 字段可任意，但电路不把它们解释为有效记录，也不参与 ID 比较。非空叶子的 `valid` 固定为 1，沿用 B/E 的 `q_grant_valid`。

---

## 3. 约束结构

### 3.1 数据结构新增

对每个事件 `i` 与每棵树（GR/RR）新增：

```text
grant_preimages[i][16]: GrantFieldsB   // 每个槽位的候选 preimage
grant_nonempty[i][16]: bool            // 该槽位是否是有效 Grant 记录
revoke_preimages[i][16]: RevokeFieldsC
revoke_nonempty[i][16]: bool
```

这些是私有 witness。第二事件的 preimage 对应 `S1`，不是 `S0`；由 gated_eq 绑定到 `gr_in[1]` / `rr_in[1]` cell。

### 3.2 全树 root 重算

对 GR：

```text
leaf_j = grant_nonempty[j] ? Poseidon(D_GRANT, preimage_j fields..., 1) : 0
node   = Poseidon(D_NODE, left, right)  逐层至根
gated_eq(event_flag, recomputed_gr_root, gr_in[i])
```

对 RR：

```text
leaf_j = revoke_nonempty[j] ? Poseidon(D_REVOKE, preimage_j...) : 0
node   = Poseidon(D_NODE, left, right)  逐层至根
gated_eq(event_flag, recomputed_rr_root, rr_in[i])
```

不要求 prover 提交“未发现重复”的布尔值；该布尔值必须由电路逐项比较产生。

### 3.3 ID 不等 gadget

对两个完整 Pallas field 元素 `a,b`，引入 witness `inv`：

```text
d = a - b
d * inv = 1
```

这约束 `d != 0`，即 `a != b`。`inv` 由 prover 提供；若 `a=b` 则不存在满足的 `inv`。该 gadget 不依赖截断前缀，不引入额外 ID 语义。需要在后续实现中检查 field inverse 的边界（a-b=0 时不可满足；非 0 时 witness 可取逆）。

### 3.4 三类检查的门控

| 检查 | 触发条件 | 比较对象 | 绑定根 |
| --- | --- | --- | --- |
| Grant ID 全局唯一 | `is_grant` | `grant_preimages[j].id != child.id`，对所有 `grant_nonempty[j]` | `gr_in[i]` |
| Parent 未撤销 | `is_grant` | `revoke_preimages[j].grant_id != parent.id`，对所有 `revoke_nonempty[j]` | `rr_in[i]` |
| Revoke ID 全局唯一 | `is_revoke` | `revoke_preimages[j].grant_id != revoke.grant_id`，对所有 `revoke_nonempty[j]` | `rr_in[i]` |
| Revoke 目标存在 | `is_revoke` | 沿用已有 target opening，绑定 `gr_in[i]` | `gr_in[i]` |

Parent 存在仍沿用现有 Parent opening（`grant parent in GR`）；新增的是 Parent 在 RR 中不存在的检查。

现有单槽空检查保留：它仍表达“写入槽为空”；新增全树扫描表达“ID 全局不存在”。两者互补，不能互相替代。

---

## 4. 与 D 参考模型的一致性

| D 语义 | 本构造对应 |
| --- | --- |
| `DuplicateGrant(id)`：`state.grants.contains_key(id)` | GR 全树 preimage 枚举 + `id != child.id` |
| `ParentNotValid(id)`：`parent∈G ∧ parent∉R` | Parent opening（∈G） + RR 全树 parent ID 不存在（∉R） |
| `AlreadyRevoked(id)`：`state.revokes.contains_key(id)` | RR 全树 preimage 枚举 + `id != revoke.grant_id` |
| 中间状态检查 | 第二事件全树 root 绑定 `gr_in[1]` / `rr_in[1]` cell |
| DirectOnly | 保持 GR/RR 现有 state-transition，不级联 |

D 参考模型不修改；其 `free_slot` 与 slot 分配只用于模型内部，不进入 E-R1 电路语义。E-R1 证明 ID 键集合性质，不证明 canonical slot 规范性。

---

## 5. 成本估计（结构估算）

实测：K=15 是最小可行值（K=13/14 均 `NotEnoughRowsAvailable`）。E 原电路 K=13；full-tree scan 使 K 提升 2。当前只给量级，不声称精确约束数：

- 每事件最多 16 个 GR preimage Poseidon(9→1) + 15 个 GR 内部节点 Poseidon(2→1)；
- 每事件最多 16 个 RR preimage Poseidon(4→1) + 15 个 RR 内部节点 Poseidon(2→1)；
- 非空叶子的 ID 不等 gadget：每个叶子 1 个乘法门 + inverse witness；
- root 绑定：每棵树 1 次 gated_eq；
- 两事件最坏组合下上述结构重复两次（S0/S1 各一次）。

这是 E 原电路之外的显著增量，K、selector、advice 与证明时间必须由 Phase 6 实测。若 K 增长或证明时间明显不接受，记录为优化问题，不回退语义。

---

## 6. 对 E 原有结构的最小修改范围

- 保留 `TransitionCircuitE` 作为原 E 冻结电路，不修改。
- 新增 `src/transition/e_r1_types.rs`、`src/transition/e_r1_uniqueness.rs`、`src/transition/e_r1_revocation_validity.rs`（或等价模块），在独立配置中实现 R1 全树扫描与 ID 检查。
- 新增独立 circuit `TransitionCircuitR1`，复用 8 个 instance、两事件控制、grant/revoke 单事件语义、状态链与 batch；把三类 R1 检查作为新增 gated 层接入。
- `src/transition/mod.rs` 仅注册/re-export。
- A/B/C/D 与固定向量零改。

---

## 7. 设计冻结结论

**进入 Phase 2**。实现顺序：

1. 先实现 ID 不等 gadget 与全树 root 重建 helper；
2. 接入 Parent 未撤销检查；
3. 接入 Grant ID 全局唯一性；
4. 接入 Revoke ID 全局唯一性；
5. 用 P01–P18 验证三类语义与跨槽攻击。

若 Step 1 的 field inverse gadget 或 Merkle root 重建无法通过 MockProver，先报告具体问题，不改写 D 参考模型。
