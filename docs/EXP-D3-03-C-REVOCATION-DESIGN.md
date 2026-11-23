# EXP-D3-03-C — Phase 1 DirectOnly 撤销关系冻结

**基线**：`ecc4d06b105b047299e785e7b8e268a70a4e2cb4`
**分支**：`exp-d3-03-c`
**前置**：`docs/EXP-D3-03-C-INTERFACE-AUDIT.md`（Phase 0 已确认无停工阻断）
**实现原则**：新增独立 C 模块，不改 A/B 冻结源码、不改 8 public instance、不引入 Cascade/多事件/递归。

---

## 1. 范围冻结

只处理：

- 1 个目标 Grant，来自 `GR_prev` 的有效叶子；
- 1 条 Revoke 事件 `(grant_id, revoker, epoch)`；
- DirectOnly：只写 RR 的一个叶子，**GR 完全不变**；
- 单事件固定槽位：`event_count = 1`。

明确不做：Cascade、多事件批次、递归、完整历史证明、ALLOW/DENY 决策证明、canonical slot 规范性证明、Bridge/freshness 证明。

---

## 2. 字段与编码

复用 B 的 Grant 域元素口径（`GrantFieldsB`），新增 C 专用 Revoke 字段：

```text
Grant = (id_f, issuer_f, subject_f, resource_prefix_f, scope_f, parent_key_f, epoch_f)
GRANT_LEAF_C = Poseidon::<9>(D_GRANT, id_f, issuer_f, subject_f,
                             resource_prefix_f, scope_f, parent_key_f,
                             epoch_f, 1)        // valid=1 by gate

Revoke = (grant_id_f, revoker_f, epoch_f)
D_REVOKE_C  = domain_field("D3-REVOKE-v1")      // fixed 常量
L_REVOKE_C  = Poseidon::<4>(D_REVOKE_C, grant_id_f, revoker_f, epoch_f)
c_revoke    = Poseidon::<5>(D_EVENT, TYPE_REVOKE=2, grant_id_f, revoker_f, epoch_f)
```

- `grant_id_f` 与 `revoker_f` 为域元素 witness，电路不重算类别 II SHA-256（EXTERNAL_TRUST）。
- `D_EVENT` 沿用 B 的 `d_event_b()`；`TYPE_REVOKE=2` 与 B 的 `TYPE_GRANT=1` 分离，不静默拼接。
- Revoke leaf 与 D3-01 的 4 词语义一致，但字段→域口径不同；C RR 根与 D3-01 固定向量不兼容，已写入审计。

---

## 3. Merkle 关系

### 3.1 Grant Opening（GR_prev）

目标 Grant 在 `GR_prev` 中打开：

- 9 词叶子在电路内重算；
- 第 9 词 `valid` 由 `q_grant_valid` 强制为 1；
- 4 层路径 `dir` bool gate + `path-select` gate；
- 重算根 Equality copy 到 A 的 `gprev` 规范域 cell。

直接约束：

```text
grant.id_f        = revoke.grant_id_f      (copy_equal)
grant.issuer_f    = revoke.revoker_f       (copy_equal)
```

### 3.2 RR 旧槽位为空

```text
RR_prev = MerkleOpen(leaf = 0, revoke_open_old)
```

旧叶子使用专用 `zero_cell`，不是 witness 自称的零；重算根 copy 到 `rprev`。若槽位已有撤销记录，则电路用 0 重算的根与 `rprev` 不等，拒绝。

### 3.3 RR 单叶更新

```text
RR_next = MerkleOpen(L_REVOKE_C, revoke_open_new)
```

- `revoke_open_new` 与 `revoke_open_old` 逐层 `(dir, sibling)` Equality copy，保证同一槽位；
- 只有叶子从 0 变为 `L_REVOKE_C`；
- 新根 copy 到 `rnext`。

### 3.4 GR 不变

在电路内直接约束：

```text
copy_equal(gnext, gprev)
```

不接受 prover 分别提供两个“碰巧相同”的根。DirectOnly 下 `GR_next` 与 `GR_prev` 必须复用同一规范域 cell 值。

---

## 4. Epoch 与状态承诺

```text
next_epoch = prev_epoch + 1
revoke.epoch = next_epoch
```

实现方式：复用 B 的 64-bit `State` 比较 gadget 证明 `next_epoch ≥ prev_epoch`；新增 `q_epoch_plus_one` gate 约束 `next_cell - prev_cell - 1 = 0`。两者合起来排除 64-bit 溢出回绕，同时避免另写完整加法器。

A 的状态承诺公式保持不变：

```text
C_prev = Poseidon(D_STATE, gprev, rprev, prev_epoch, policy_id)
C_next = Poseidon(D_STATE, gnext, rnext, next_epoch, policy_id)
```

`D_STATE`、policy、version、4 根规范编码全部沿用 A/B 冻结 gadget。

---

## 5. Batch 绑定

```text
D_E = Poseidon(D_BATCH, 1, c_revoke, pad, pad)
```

- `c_revoke` 在电路内由 `d_event + TYPE_REVOKE + grant_id_f + revoker_f + epoch_f` 重算；
- copy 到 `event_commitments[0]`；
- `event_count=1` 由 A 的 active/count gate 与 instance[7] 绑定；
- 其余 2 槽固定 `batch_pad`。

---

## 6. Public instance（冻结不变）

索引顺序与 A/B 完全一致：

| Index | Public instance |
| --- | --- |
| 0 | `C_prev` |
| 1 | `prev_epoch` |
| 2 | `C_next` |
| 3 | `next_epoch` |
| 4 | `policy_id` |
| 5 | `transition_version` |
| 6 | `D_E` |
| 7 | `event_count` |

C 不新增公开字段；所有 Revoke/Opening 信息均为 private witness。

---

## 7. 约束清单（实现检查表）

1. `root-bit-boolean` / `canonical-transition` / `canonical-final`：4 个根 32B `< p` 规范编码；
2. `bind-policy` / `bind-version`：常量 gate；
3. `path-dir-bool` / `path-select`：GR 与 RR 两类 opening 的方向与左右选择；
4. `grant-valid-one`：目标 Grant `valid=1`；
5. `epoch-state-pref/less/final`：`next_epoch ≥ prev_epoch`；
6. `epoch-plus-one`：`next_epoch - prev_epoch - 1 = 0`；`event-count-one`：`event_count = 1` 独立常量门；
7. `copy_equal(grant.id, revoke.grant_id)`；
8. `copy_equal(grant.issuer, revoke.revoker)`；
9. `copy_equal(revoke.epoch_cell, epoch_next)`；
10. `copy_equal(grant_opening.root, gprev)`；
11. `copy_equal(rr_old_opening.root, rprev)`；
12. `copy_equal(rr_new_opening.root, rnext)`；
13. 逐层 `copy_equal(rr_new.dir/sib, rr_old.dir/sib)`；
14. `copy_equal(gnext, gprev)`；
15. `copy_equal(c_revoke, slots[0])`；
16. batch active/padding/count gate；
17. 8 个 instance copy。

---

## 8. 信任边界

电路证明：**给定 GR/RR 根及其 Opening，存在一次满足上述关系的 DirectOnly 撤销转换。**

电路不证明：

- RR 记录来自完整授权事件历史；
- `revoke_slot` 是全局规范分配（R2-03 EXTERNAL_TRUST）；
- 类别 II SHA-256 字段映射正确；
- Bridge 签名、外部 checkpoint 可信或最新；
- 执行生效前没有并发覆盖；
- Child Grant 在 Parent 撤销后仍“有效”这一外部语义——C25 只验证 DirectOnly 不修改 GR。

---

## 9. 测试矩阵（实现目标）

### 正向（MockProver）
C01 合法单次撤销；C02 合法 Grant Opening；C03 合法 RR 空槽 Opening；C04 合法 RR 单叶更新；C05 GR 根不变；C06 新旧状态承诺正确；C07 撤销事件绑定 Batch。

### 负向（MockProver）
C09 Grant 不存在；C10 `valid=0`；C11 ID 不一致；C12 revoker 非 issuer；C13 旧 RR 已撤销；C14 新 RR 根伪造；C15 旧 RR 根与 Opening 不匹配；C16 direction 篡改；C17 sibling 篡改；C18 `GR_next ≠ GR_prev`；C19 event epoch ≠ next_epoch；C20 epoch 非 +1；C21 batch 不一致；C22 event_count ≠ 1。

### 边界
C24 同一 Grant 重复撤销拒绝；C25 撤销 Parent 不改 Child（DirectOnly）通过；C26 撤销 Child 通过；C27 slot 哈希碰撞按 canonical 规则处理；C28 非规范 Field 编码拒绝。

### 真实证明
C08 合法 witness 的 keygen→prove→verify；C23 修改 public instance 后原 proof 被 verifier 拒绝。负向 witness 只用 MockProver 断言拒绝来源；不把“proof 生成成功”当成约束成立。

每个负向测试必须记录主要拒绝来源（如 `grant-valid-one`、`epoch-plus-one`、`copy_equal(root,instance)`），不能仅以最终失败冒充目标语义已证明。
