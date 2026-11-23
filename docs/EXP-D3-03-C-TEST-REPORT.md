# EXP-D3-03-C — Phase 3 测试报告

**基线**：`ecc4d06b105b047299e785e7b8e268a70a4e2cb4`
**分支**：`exp-d3-03-c`
**测试文件**：`tests/d3_03_c_mock.rs`、`tests/d3_03_c_proof.rs`
**总计**：C01–C28 全过；MockProver 26/26，真实 proof 2/2；完整 release 套件 128 passed / 0 failed。

---

## 1. 测试口径

- MockProver 拒绝 ≠ Verifier 拒绝。C09–C22/C24–C28 是 MockProver 层；C23 是真实 verifier 层，分层记录。
- 大多数负向用例保持 public instance 为原始合法值，只改私有 witness；需要重绑定根/epoch 的用例（C14/C15/C18/C19/C20/C21/C22）会从修改后 witness 重算 instance，确保失败定位到目标 gate，而不是泛化的 instance 失配。
- 每条负向测试打印实测 MockProver 错误；下表“拒绝来源”来自实测错误中的 gate 名或 permutation 位置。

---

## 2. 正向测试（C01–C07）

| 编号 | 测试 | 结果 | 说明 |
| --- | --- | --- | --- |
| C01 | 合法单次撤销 | Pass | 完整 C 电路所有 gate 与 8 instance 成立 |
| C02 | 合法 Grant Opening | Pass | `recompute_root_b(grant.leaf(true), grant_open) == GR_prev` |
| C03 | 合法 RR 空槽 Opening | Pass | `recompute_root_b(0, rr_old_open) == RR_prev` |
| C04 | 合法 RR 单叶更新 | Pass | `recompute_root_b(revoke_leaf, rr_new_open) == RR_next`；两条路径 `(dir,sibling)` 逐层相等 |
| C05 | GR 根保持不变 | Pass | `gr_prev_be == gr_next_be`，并由电路内 `copy_equal(gnext,gprev)` 约束 |
| C06 | 新旧状态承诺正确 | Pass | host 重算的 instance[0]/[2] 与 A 公式一致 |
| C07 | 撤销事件绑定 Batch | Pass | slot0 = `c_revoke`，slot1/2 = `batch_pad`，`event_count=1` |

---

## 3. 负向测试（C09–C22）

| 编号 | 恶意情况 | 结果 | 实测主要拒绝来源 |
| --- | --- | --- | --- |
| C09 | Grant 不存在（改 grant.id） | Reject | `target grant words` 与 `grant_select_0` 的Permutation；同时命中 id copy |
| C10 | Grant `valid=0` 构造 GR 树 | Reject | `constants`/`grant_select_0` root copy permutation（电路强制 valid=1，根不匹配） |
| C11 | Grant ID 与 revoke ID 不一致 | Reject | `target grant words` 与 revoke 输入域的 permutation（id copy） |
| C12 | revoker 不是 issuer | Reject | `target grant words` 与 revoke/batch 输入 permutation（issuer copy） |
| C13 | 旧 RR 槽位已撤销 | Reject | `constants` 的 `zero_cell` 与 `rr_old_select_0` permutation（旧叶必须为 0） |
| C14 | 新 RR 根伪造 | Reject | `rr_next` root cell 与 rr_new opening 根 permutation |
| C15 | 旧 RR 根与 Opening 不匹配 | Reject | `rr_prev` root cell 与 rr_old opening 根 permutation |
| C16 | Merkle direction 篡改 | Reject | `path-select` gate（`rr_new_select_1`）及同路径 dir copy permutation |
| C17 | sibling 篡改 | Reject | `path-select` gate（`rr_new_select_1`）及同路径 sibling copy |
| C18 | `GR_next ≠ GR_prev` | Reject | `gr_prev`/`gr_next` root cell permutation（DirectOnly copy） |
| C19 | event epoch ≠ next_epoch | Reject | revoke epoch cell 与 `state epoch`/public epoch 的 permutation |
| C20 | epoch 不是 +1 | Reject | `epoch-plus-one` gate（实测 cell 值 0xb → 0xb） |
| C21 | Batch commitment 不一致 | Reject | `c_revoke` 与 batch slot0 输入的 permutation |
| C22 | `event_count ≠ 1` | Reject | `event-count-one` gate（实测 cell 值 0x2） |

C24 是 C13 的重复撤销命名用例，独立运行并同样拒绝。

---

## 4. 边界与策略测试（C24–C28）

| 编号 | 测试 | 结果 | 说明 |
| --- | --- | --- | --- |
| C24 | 同一 Grant 重复撤销 | Reject | 与 C13 同一旧叶非空拒绝，证明重复撤销不能通过 |
| C25 | 撤销 Parent 但不修改 Child | Pass | GR 树同时含 Parent/Child；撤销后 `gr_prev_be == gr_next_be`，Child 叶子仍在 GR 中；证明 DirectOnly 未悄悄引入 Cascade |
| C26 | 撤销 Child | Pass | Child 作为目标 Grant 被打开，issuer 绑定 child.issuer，RR 单叶更新成立 |
| C27 | 撤销槽位哈希碰撞 | Pass | 搜索得到 depth=4 下两个 `initial_slot` 相同的 id；`canonical_assignment` 分配不同槽位；目标槽为空、另一槽已有记录时电路通过。注意电路仍把 slot 当外部可信 witness，不证明 canonical layout 本身 |
| C28 | 非规范 Field 编码 | Reject | `canonical-final` gate，`gr_prev` 32B 全 `0xff` 被拒 |

C25 的语义边界：它只证明“本电路不修改 GR，因此 Child 叶子未被本电路撤销”；不证明 Child 在外部语义下永远有效，也不证明 Parent 撤销后 Child 的授权决策结果。

---

## 5. 真实 proof / verifier

| 编号 | 测试 | 结果 | 说明 |
| --- | --- | --- | --- |
| C08 | 合法 revoke witness roundtrip | Pass | `Params::new(K)` → `keygen_vk` → `keygen_pk` → `create_proof` → `verify_proof` |
| C23 | 修改 public instance 后复用 proof | Reject | 仅改 `C_next`（instance[2]），verifier 拒绝原 proof |

C08 输出（单次测量，完整同轮对比见 benchmark 文档）：

```text
C08 K=12 proof_bytes=5760 keygen_ms=2542 prove_ms=3507 verify_ms=80
```

负向 witness 未生成“可接受的 proof”；本阶段遵循 Halo2 生成 proof 不保证 witness 满足约束的事实，只用 MockProver 做负向语义断言。

---

## 6. 完整 release 套件

```text
lib unit                 26 passed
A mock                   16 passed
A proof                   2 passed
A smoke                   1 passed
B mock                   17 passed
B proof                   2 passed
C mock                   26 passed
C proof                   2 passed
fixed vectors             1 passed
grant transition          7 passed
history order             4 passed
reference model           8 passed
revoke transition         6 passed
root consistency         10 passed
--------------------------------
total                   128 passed / 0 failed
```

A/B 冻结测试与 D3-01 固定向量全部继续通过，说明 C 的独立模块没有改变既有实现。
