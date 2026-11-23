# EXP-D3-03-E — Phase 3 测试报告

**基线**：`b9a8fc7f0e66119f23877317836d70d01b174c1b`
**分支**：`exp-d3-03-e`
**测试文件**：`tests/d3_03_e_mock.rs`、`tests/d3_03_e_proof.rs`、`tests/d3_03_e_bench.rs`（ignored）
**总计**：MockProver 22/22 通过；真实 proof 2/2 通过（含四个 E 组合与 P17）；完整 release 套件 **199 passed / 0 failed / 2 ignored**。

---

## 1. 测试口径

- **MockProver 拒绝 ≠ Verifier 拒绝**。P01–P16 与额外攻击位于 MockProver 层；P17 位于真实 `create_proof`/`verify_proof` 层。两者分开记录，不把约束不可满足说成链上 verifier 已拒绝。
- 负向测试分两类：
  1. **保留原 public instance，仅改私有 witness**：用于验证中间状态链、事件顺序、重复 ID、非法 parent/revoker 等绑定；若电路仍接受，则说明 cell copy/gated 绑定没有生效。
  2. **改 public instance 或从修改后 witness 重算 instance**：用于验证最终状态承诺、event_count、batch commitment、epoch 等外部绑定；失败可能同时落在 gate 与 instance permutation。
- 每条负向测试打印 MockProver 首条失败；下表“实测主要拒绝来源”来自实测输出中的 gate 名或 permutation 位置。
- 若一条攻击同时触发多个失败，表中明确写“存在并行失败”，不把整个验证失败唯一归因到单一语义约束。

---

## 2. 正向测试（P01–P06）

| 编号 | 测试 | 结果 | 覆盖语义 |
| --- | --- | --- | --- |
| P01 | 单 Grant + padding | Pass | `active=[1,0]`、`event_count=1`、slot2=`batch_pad`；状态链第二步不修改根 |
| P02 | 单 Revoke + padding | Pass | 单撤销下 GR 不变、RR 单叶更新、padding 门成立 |
| P03 | Grant + Grant | Pass | 两次独立 Grant，第二事件从 S1 的 GR 打开 Parent |
| P04 | Grant + Revoke（核心） | Pass | 第二个事件从第一个事件刚创建的 GR 状态打开目标 Grant；不经过 host 代入 S1 |
| P05 | Revoke + Revoke | Pass | 第二次 RR opening 使用 S1 的 RR，而非 S0 |
| P06 | Parent Grant + Child Grant | Pass | 断言 `events[1].parent.id == events[0].child.id`，验证电路内父子依赖与 S1 根绑定同时成立 |

P04 是 E 阶段的研究核心：正向通过说明 Grant 输出的 `gr_out` cell 能作为 Revoke 的 `gr_in`，并由 gated equality 绑定到 `target_opening.root`。

---

## 3. 中间状态与事件绑定攻击（P07–P15）

| 编号 | 恶意情况 | 结果 | 实测主要拒绝来源 | 掩盖说明 |
| --- | --- | --- | --- | --- |
| P07 | 交换两个 Grant 的 Parent opening，试图让第二个 Parent 指向 S0 根 | Reject | `gated-eq` @ `grant parent in GR`（event0/event1 两处）；另有 `permute state` 与 `parent_select_0` permutation | 目标 gate 首先命中；并行的 permutation 源于根/路径 cell 被连带改写 |
| P08 | Revoke+Revoke 中第二个事件复用 S0 的 RR opening | Reject | `gated-eq` @ `revoke slot empty in RR`；另有 `rr_old_select_*`/`rr_new_select_*` permutation | 目标 gate 首先命中；路径 permutation 是同一攻击的连带结果 |
| P09 | Grant+Revoke 中第二个事件用 S0 的 GR opening | Reject | `gated-eq` @ `revoke target in GR`；另有 `permute state`、`target_select_0` permutation | 目标 gate 首先命中，证明第二事件确实绑定到 S1 的 GR cell |
| P10 | 交换事件顺序但复用原事件承诺 | Reject | 多处 `gated-eq`：`revoke target in GR`、`revoke commitment -> slot`、`grant commitment -> slot` | 存在并行失败；顺序变化同时破坏根绑定与 batch slot 绑定，不能唯一归因于单个 slot |
| P11 | 遗漏第二个事件但沿用原 instances | Reject | `slot-padding` gate；另有 `permute state`、control cell 与 instance row 2/6/7 permutation | 目标 gate 首先命中；instance 失配是 `event_count`/`D_E` 的连带结果 |
| P12 | 同一 slot 重复写入（同 child 写 slot 2 两次） | Reject | `child_old_select_0`、`rr_old_select_0` permutation；另有 grant words 与 Poseidon input permutation | 目标“旧叶必须为空”由 root/path permutation 表达；未观察到单独的 gate 名 |
| P13 | 重复 Grant ID / 占用槽 | Reject | `child_old_select_0`、`rr_old_select_0` permutation | 与 P12 同类；由 builder 构造自洽 S1，确保拒绝来自“slot 非空”而非偶然根失配 |
| P14 | 第二个 Child 的 issuer 不等于 Parent.subject | Reject | `gated-eq` @ `grant commitment -> slot`；`state-transition`（GR）；另有 grant words/parent/child_new permutation | 存在并行失败：改写 issuer 同时破坏 parent binding、事件承诺与输出根，不能声称只有一个门失败 |
| P15 | Revoke 的 revoker 不等于 target.issuer | Reject | `gated-eq` @ `revoke commitment -> slot`；`state-transition`（RR）；另有 Poseidon/`permute state`/`rr_new_select_0` permutation | 存在并行失败；目标 revoker=issuer 绑定经事件承诺与 RR 根共同体现 |

---

## 4. 最终承诺与策略边界（P16 + 额外用例）

| 编号 | 恶意情况 | 结果 | 实测主要拒绝来源 | 掩盖说明 |
| --- | --- | --- | --- | --- |
| P16 | 篡改 `C_next`（instance[2]） | Reject | `permute state` 与 instance row 2 permutation | 直接由公开实例复制约束拒绝 |
| 额外 | `[0,1]` 非前缀 active | Reject | `active-monotone` gate，cell 值为 0/1 | 单一目标 gate，未被其他失败掩盖 |
| 额外 | Grant+Revoke 使用旧 GR 根（与 P09 独立构造） | Reject | `gated-eq` @ `revoke target in GR`；另有 state/target permutation | 与 P09 一致；目标 gate 首先命中 |
| 额外 | Revoke+Revoke 使用旧 RR 根（与 P08 独立构造） | Reject | `gated-eq` @ `revoke slot empty in RR`；另有 RR 路径 permutation | 与 P08 一致；目标 gate 首先命中 |
| 额外 | 第二个 Revoke 的 epoch 改为 `EPOCH+5` | Reject | `gated-eq` @ `revoke commitment -> slot`；`state-transition`（RR）；另有 Poseidon 与 instance row 2 permutation | 存在并行失败；epoch 同时进入事件承诺、状态转换和 public instance |
| 额外 | 篡改 `D_E`（instance[6]）为 Grant 事件承诺 | Reject | `permute state` 与 instance row 6 permutation | 直接由 batch commitment 复制约束拒绝 |
| 额外 | Grant/Revoke 事件承诺类型可区分 | Pass | `grant_event_commitment_e(g) != revoke_event_commitment_e(r)` | 断言 9 词与 5 词编码不碰撞于同一字段值，不宣称全域无碰撞证明 |

---

## 5. 真实 proof / verifier

| 编号 | 测试 | 结果 | 说明 |
| --- | --- | --- | --- |
| E14 | E-GG roundtrip | Pass | `Params::new(K_E)` → `keygen_vk` → `keygen_pk` → `create_proof` → `verify_proof` |
| E14 | E-GR（核心）roundtrip | Pass | 同上；核心 `Grant(A) → Revoke(A)` 真实证明被 verifier 接受 |
| E14 | E-RR roundtrip | Pass | 同上 |
| E14 | E-SINGLE padding roundtrip | Pass | 同上；单事件 + padding |
| P17 | 篡改 public instance 后复用 proof | Reject | 仅改 `C_next`（instance[2]），旧 proof 被真实 verifier 拒绝 |

单次 proof 测试输出（未固定线程，用于功能验收）：

```text
E14 E-GG K=13 proof_bytes=7040 prove_ms=4178 verify_ms=75
E14 E-GR K=13 proof_bytes=7040 prove_ms=4010 verify_ms=74
E14 E-RR K=13 proof_bytes=7040 prove_ms=4095 verify_ms=82
E14 E-SINGLE K=13 proof_bytes=7040 prove_ms=4087 verify_ms=80
E14 keygen_ms=3371
```

负向 witness 未生成“可接受的 proof”。本阶段只用 MockProver 做负向语义断言；不把“不能生成证明”当作已验证事实。

---

## 6. 完整 release 套件

```text
lib unit                 31 passed
A mock                   16 passed
A proof                   2 passed
A smoke                   1 passed
B mock                   17 passed
B proof                   2 passed
C mock                   26 passed
C proof                   2 passed
D reference              42 passed
E mock                   22 passed
E proof                   2 passed
fixed vectors             1 passed
grant transition          7 passed
history order             4 passed
reference model           8 passed
revoke transition         6 passed
root consistency         10 passed
--------------------------------
total                   199 passed / 0 failed / 2 ignored
```

两个 ignored 测试分别是 C 的 K 变体基准与 E 的同环境基准，均需显式 `--ignored` 运行。A/B/C 冻结测试、D 参考模型与 D3-01 固定向量继续通过，说明 E 的独立模块没有改变既有实现。
