# EXP-D3-03-E-R1 执行报告

**任务**：Revocation Validity and ID Uniqueness Gap Closure
**基线**：`56342803d492bb8aaa4ffd44b5586947fd7d0d0c`（`exp-d3-03-e`）
**分支**：`exp-d3-03-e-r1`
**范围**：Parent 撤销有效性、Grant ID 全局唯一性、Revoke ID 全局唯一性。不修改 A/B/C/D/E 冻结实现，不扩展到三事件、递归或 Cascade。

---

## 1. Git 与交付

新增 E-R1 独立模块与测试/文档：

```text
src/transition/e_r1_circuit.rs
src/transition/e_r1_constants.rs
src/transition/e_r1_types.rs
src/transition/e_r1_types_host.rs
src/transition/e_r1_uniqueness.rs
tests/d3_03_e_r1_mock.rs
tests/d3_03_e_r1_proof.rs
tests/d3_03_e_r1_bench.rs
docs/EXP-D3-03-E-R1-{GAP-AUDIT,CONSTRUCTION-DESIGN,TEST-REPORT,BENCHMARK,SUMMARY}.md
```

`src/transition/mod.rs` 仅新增注册/re-export 与格式调整。A/B/C/D/E 电路、固定向量和参考模型零改；`src/reference/mixed_event_state.rs` 未修改。

---

## 2. ID 与槽位审计

- Grant ID：`GrantFieldsB.id: F`（Pallas Base），由类别 II `key_field` 预映射，映射本身是外部信任。
- Revoke ID：`RevokeFieldsC.grant_id: F`，与 Grant ID 同编码；电路用 copy constraint 绑定。
- E 的 GR/RR 槽位完全由 witness 指定（`parent_slot/child_slot/target_slot/revoke_slot`），不由 ID 确定；同一 ID 可写不同空槽，这是三个缺口的根因。
- D3-01 canonical slot 用 SHA-256 `D3-SLOT-v1` + 32-byte key + 排序线性探测，与 E 的 F 字段 ID + Poseidon 树不兼容，不能直接拼接。

详见 `docs/EXP-D3-03-E-R1-GAP-AUDIT.md`。

---

## 3. 构造方案

选择 **方案 A：全树扫描 + 叶子 preimage 重算**：

- 每事件输入态的 GR/RR 各提供 16 槽 preimage（空槽带 empty flag）；
- 电路内重算每个非空叶子 Poseidon 与整棵 depth-4 Merkle root，`gated-eq` 绑定到事件输入根 cell；
- ID 不等 gadget：对完整 Field ID `a,b` 提供逆元 `inv`，约束 `fl·bf·((a-b)·inv−1)=0`；
- 不选择 canonical slot（方案 B）是因为当前无 SHA-256 电路，且会引入新 slot 版本与状态迁移信任。

K 从 E 的 13 提升到 **15**（实测 K=13/14 `NotEnoughRowsAvailable`），是工程决策。

---

## 4. 电路修复

| 语义 | 实现 | 绑定 |
| --- | --- | --- |
| Parent 未撤销 | RR 全树扫描中 `revoke_id != parent.id` | `rr_in[i]`（事件 1 绑定 `RR_1`） |
| Grant ID 全局唯一 | GR 全树扫描中 `leaf_id != child.id` | `gr_in[i]` |
| Revoke ID 全局唯一 | RR 全树扫描中 `leaf_id != revoke.grant_id` | `rr_in[i]` |
| 中间根 | 第二事件输入 cell = 第一事件输出 cell | 沿用 E 的 `state-transition` |

8 个 public instances 完全保持。负向防护不依赖 host 布尔值：ID 相等时 inv=0 使约束失败。全树扫描 region 无条件创建，避免 keygen/prove 布局不一致。

---

## 5. 测试

- MockProver：**18/18 通过**，P01–P18 全部有独立测试或 proof 层测试。
- 跨槽重复 Grant（P08/P09）：由 `scan-id-neq @ grant id global unique in GR` 精确拒绝（`a=b=0x3ea, inv=0`），无其他门先行失败。
- 同 ID 跨槽重复 Revoke（P12）：由 `scan-id-neq @ revoke id global unique in RR` 精确拒绝（`a=b=0x3e9, inv=0`），无其他门先行失败。
- 已撤销 Parent（P03/P04）：由 `scan-id-neq @ parent not revoked in RR` 精确拒绝。
- 第二事件旧根（P14/P15）：分别由 RR/GR 的 opening 根绑定与全树扫描根绑定拒绝。
- P16：低 4 位截断前缀相同但完整 Field ID 不同（2001 vs 2017）时按完整 ID 判断，二者均可通过。
- 真实 proof：R1-GG/GR/RR/SINGLE 四种组合 verifier 接受；篡改 `C_next` 后旧 proof 被拒。
- 负向真实验证：跨槽重复 Grant ID 的 witness 仍生成 8160 B proof，但 verifier 拒绝（`verifier_accepted=false`）。
- 完整 release：**224 passed / 0 failed / 3 ignored**。

详见 `docs/EXP-D3-03-E-R1-TEST-REPORT.md`。

---

## 6. 性能

同轮固定单线程三采样中位数：

| 电路 | K | Proof | Keygen | Prove | Verify |
| --- | --- | --- | --- | --- | --- |
| E-GG | 13 | 7040 B | 6032 ms | 7938 ms | 137 ms |
| E-GR | 13 | 7040 B | 6227 ms | 7590 ms | 133 ms |
| E-RR | 13 | 7040 B | 6110 ms | 7758 ms | 134 ms |
| R1-GG | 15 | 8160 B | 26118 ms | 30998 ms | 456 ms |
| R1-GR | 15 | 8160 B | 25991 ms | 35016 ms | 437 ms |
| R1-RR | 15 | 8160 B | 27784 ms | 30102 ms | 421 ms |

全树扫描带来显著成本：K +2，proof size +1120 B，prove 约 4–5×。这验证了任务书的预期——语义完整性的代价是真实的优化问题，而不是免费获得。详见 `docs/EXP-D3-03-E-R1-BENCHMARK.md`。

---

## 7. 未解决问题

- 初始 S0 的 RR 撤销记录若非由事件产生，builder 无法从裸 slots 恢复其 preimage；测试中的“已撤销 Parent”均由事件 0 产生。
- `key_field` 的 SHA-256→F 映射单射性仍是外部信任；本轮证明的是映射后 Field ID 的全局唯一性。
- 仍不证明 ALLOW/DENY、完整历史、canonical slot 规范性、Bridge/checkpoint、新鲜性、Cascade、递归、三事件或跨 VK 重放。
- 未逐门统计约束数；性能数据为墙钟采样，不构成严格分布结论。
- 全树扫描成本较高；后续可研究保持 ID 唯一性语义的更省构造，但不能以牺牲语义换取性能。

---

## 8. 最终判断

**E-R1 达到本轮语义修复目标。**

- D 状态机三个语义要求：**满足**。Parent 已撤销时不能创建子授权（绑定当前 RR）；重复 Grant ID 不能换槽位绕过；Revoke 必须对应存在的 Grant 且不能重复撤销（绑定当前 RR）。
- 仍依赖外部 canonical slot 信任：**否**（本轮不依赖 slot 规则，扫描全部 16 槽）；但 `key_field` 映射仍是外部信任。
- 具备进入下一阶段条件：是——已得到“ID 全局唯一性与撤销状态的语义完整基线构造及其明确成本”，可据此研究更省的证明结构。

本轮的关键研究结论：**在有限容量状态树中，ZK 电路证明 ID 全局唯一性不能只依赖 prover 选择的单槽 Opening；全树扫描 + 叶子 preimage 重算可以严格表达 D 状态机语义，代价是 K 从 13 升到 15、proof 增大与证明时间显著上升。**
