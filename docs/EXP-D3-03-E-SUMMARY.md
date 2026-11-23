# EXP-D3-03-E 执行报告

**任务**：Sequential Mixed Transition Halo2 Prototype
**基线**：`b9a8fc7f0e66119f23877317836d70d01b174c1b`
**分支**：`exp-d3-03-e`
**范围**：最大事件数 2 的顺序混合状态转换；支持 Grant+Grant、Grant+Revoke、Revoke+Revoke、单事件 padding。核心是 `Grant(A) → Revoke(A)` 的第二事件必须从第一事件产生的中间 GR 状态打开 Grant。不改 A/B/C 冻结接口；不做 Cascade、递归、三事件、Batch Update 或完整 DENY 证明。

---

## 1. Git 与交付文件

新增文件：

```text
docs/EXP-D3-03-E-INTERFACE-AUDIT.md
docs/EXP-D3-03-E-CIRCUIT-DESIGN.md
docs/EXP-D3-03-E-TEST-REPORT.md
docs/EXP-D3-03-E-BENCHMARK.md
docs/EXP-D3-03-E-SUMMARY.md
src/transition/e_constants.rs
src/transition/e_types.rs
src/transition/e_types_host.rs
src/transition/e_circuit.rs
tests/d3_03_e_mock.rs
tests/d3_03_e_proof.rs
tests/d3_03_e_bench.rs
```

修改文件：`src/transition/mod.rs`（仅注册 E 模块与 re-export）。A/B/C 源码、固定向量、D 参考模型与历史测试均未改。提交信息：`EXP-D3-03-E: implement sequential mixed transitions`；最终 commit SHA 由执行回传记录。

---

## 2. Phase 0：接口审计结论

审计文档：`docs/EXP-D3-03-E-INTERFACE-AUDIT.md`。

- 域标签以代码冻结值为准：`D3-STATE-P-v2`、`D3-BATCH-v1`、`D3-BATCH-PAD-v1`、`D3-EVENT-v1`、`D3-GRANT-v1`、`D3-NODE-v1`、`D3-REVOKE-v1`。旧 R1 文档中的 `D3-BATCH-P-v2` / `D3-EVENT-P-v2` 属命名漂移，不改代码。
- Grant 事件承诺为 9 词 Poseidon：`D3-EVENT-v1, TYPE_GRANT=1, id, issuer, subject, prefix_f, scope, parent_key, epoch`。
- Revoke 事件承诺为 5 词 Poseidon：`D3-EVENT-v1, TYPE_REVOKE=2, grant_id, revoker, epoch`。
- A/B/C 的 `hash_words`、`assign_root_encoding`、`copy_equal` 等 helper 为私有；E 不修改冻结模块，而是新增独立电路与语义门。
- 8 个 public instance 原样保留：`C_prev, prev_epoch, C_next, next_epoch, policy_id, transition_version, D_E, event_count`。
- 停止条件未触发；不声称与 D2-A 域标签已对齐。

---

## 3. Phase 1：电路结构冻结

冻结文档：`docs/EXP-D3-03-E-CIRCUIT-DESIGN.md`。

- 固定两个事件槽，第三个 batch slot 恒为 padding；`MAX_ACTIVE_EVENTS=2`、`BATCH_SLOTS=3`。
- `active`、`is_grant`、`is_revoke` 均为 boolean gate，且 `is_grant + is_revoke = active`；`active_1·(1−active_0)=0` 禁止 `[0,1]`；`event_count=active_0+active_1`。
- 每事件维护 `(GR_in, RR_in) → (GR_out, RR_out)`；第二事件的输入 cell 是第一事件输出 cell，不重新读取 host 计算的 S1。
- 状态转移门：

```text
gr_out = is_grant  · gr_gnew + (1 − is_grant)  · gr_in
rr_out = is_revoke · rr_rnew + (1 − is_revoke) · rr_in
```

- `gated-eq` 门约束 `flag·(left−right)=0`，通过 `Region::constrain_equal` 把外部 cell 拷入同 region 的三列并启用门；不使用 Rust `Value` 比较作为安全依据。
- `K_E=13` 是工程决策，不是原始设计参数，也不是逐门精确规模推导结果。

---

## 4. Phase 2：电路实现

新增独立模块：

- `e_constants.rs`：常量与域标签函数。
- `e_types.rs`：witness 类型、off-circuit 顺序场景构造器 `build_scenario_e`、最终根重算 `final_roots_e`、事件承诺函数。
- `e_types_host.rs`：`blank_e()`，仅用于 keygen 形状。
- `e_circuit.rs`：`TransitionCircuitE` / `TransitionConfigE`，25 个 gate family、24 个 selector、30 个 advice column。
- `mod.rs` 只新增注册与 re-export。

关键实现点：

- Grant 分支：Parent/Child opening 根绑定到当前 `gr_in`；`child.parent_key=parent.id`、`child.issuer=parent.subject`；scope/resource/epoch 沿用 B 语义；child 新叶写入 GR，RR 不变。
- Revoke 分支：目标 Grant opening 绑定到当前 `gr_in`；`revoke.grant_id=target.id`、`revoke.revoker=target.issuer`；目标 `valid=1`；RR 旧槽为空，单叶写入 RR，GR 不变。
- 顺序链：事件 1 的 `gr_in/rr_in` 通过 `constrain_equal` 连接到事件 0 的 `gr_out/rr_out`；三类旧根攻击分别由 `revoke target in GR`、`grant parent in GR`、`revoke slot empty in RR` 的 `gated-eq` 拒绝。
- epoch：批次统一 `next_epoch = prev_epoch + 1`，所有 active 事件字段 copy 到同一 epoch，第二个事件不再递增。

---

## 5. Phase 3：测试

- MockProver：**22/22 通过**，覆盖 P01–P16 与 6 项额外攻击/边界用例。
- 真实 proof：**2/2 测试通过**，包含 E-GG、E-GR、E-RR、E-SINGLE 四种组合 roundtrip 与 P17 verifier 拒绝。
- 完整 release 套件：**199 passed / 0 failed / 2 ignored**。
- 详细攻击输入、目标约束、实测拒绝来源与掩盖说明见 `docs/EXP-D3-03-E-TEST-REPORT.md`。

核心结论：`Grant+Revoke` 的正向 proof 被接受；把第二事件目标 opening 换成 S0 根、把第二 Parent opening 换成 S0 根、把第二次 RR opening 换成 S0 根均被拒绝。

---

## 6. Phase 4：性能

同环境固定单线程、3 次取中位数：

| 电路 | K | Proof | Keygen | Prove | Verify |
| --- | --- | --- | --- | --- | --- |
| A | 12 | 3904 B | 795 ms | 1427 ms | 42 ms |
| B | 12 | 5696 B | 1342 ms | 1816 ms | 41 ms |
| C | 12 | 5760 B | 1331 ms | 1805 ms | 42 ms |
| E-GG | 13 | 7040 B | 3300 ms | 4106 ms | 73 ms |
| E-GR | 13 | 7040 B | 3324 ms | 4087 ms | 73 ms |
| E-RR | 13 | 7040 B | 3315 ms | 4113 ms | 74 ms |

三种 E 组合共享同一电路形状，proof size 均为 7040 B。未做 E 的 K 变体扫描、逐门约束统计或内存测量；完整环境与原始输出见 `docs/EXP-D3-03-E-BENCHMARK.md`。

---

## 7. 未解决问题与诚实边界

- 仍不是 ALLOW/DENY 证明：无请求摘要、无 D2-A `π_path`、无非存在性证明。
- 不证明完整授权历史、canonical slot 规范性、Bridge/checkpoint 可信性、执行时新鲜性。
- 类别 II SHA-256 字段映射仍是外部信任；D3↔D2-A 域标签未对齐；跨 vk 重放未解决。
- 不实现 Cascade、递归、三事件、Batch Update；本电路只证明“给定 S0 与两事件，按 Sequential 规则得到 S2”的关系。
- 不声称逐门约束数、实际使用行数、精确电路规模或端到端性能达标。
- 负向 witness 未生成“可接受的 proof”；负向语义断言只在 MockProver 层完成。

---

## 8. 最终判断

**EXP-D3-03-E 达到工程原型验收条件，但不宣称端到端授权系统可信性完成。**

本阶段把 A/B/C 的单事件语义与 D 的顺序状态机结论落进同一个 Halo2 电路，并用真实证明验证了两种事件可以通过 cell copy 与 gated equality 形成不可跳步、不可替换 S1 的状态链。最关键的研究问题——“Grant(A) 后立即 Revoke(A) 时，第二个事件是否必须打开电路内刚产生的 GR 状态”——已得到肯定答案：正向证明被接受，旧 GR 根攻击被拒。

后续若要走向授权决策证明，仍需单独研究 ALLOW/DENY 语句、外部状态锚定与新鲜性，而不是把本阶段结果外推为完整授权可信性。
