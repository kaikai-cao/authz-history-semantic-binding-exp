# EXP-D3-03-A — Halo2 电路骨架与状态承诺绑定 · 阶段总结

**基线**：`31f3765465d108c5540631be9f762af05d33770c`（R2 冻结）
**开发分支**：`exp-d3-03-a`
**范围**：仅 DirectOnly；最小状态承诺绑定电路 + 真实证明；**不实现完整授权状态机**。

---

## 1–2. Commit / 基线

- 本地 Commit SHA / Remote SHA：见最终回传（提交推送后填入）。
- 基线一致性：建分支前 HEAD = `31f3765…`，工作区干净；D2-A / D2-B / D3-01 冻结实现、固定向量、历史数据均未改。

## 3. R2 接口计数勘误（任务书第 2 节）

- `TransitionPublicInputs` 实为 **11 字段**（3 Hash32 + 4 Field + 2 u64 + 2 u32）。
- 勘误：`docs/d3_02_r2_transition_interface.md`、`results/d3_02_r2_freeze_report.md` 中"12 字段"→"11 字段"，"4 个 Hash32"→"3 个 Hash32"（并加勘误说明）。
- **未新增/删除公共输入、未改任何域标签、未改字段语义**；8 个 instance 字段及顺序原样保留。

## 4. 实际版本

rustc/cargo `1.98.1`；halo2_proofs `0.4.0`、halo2_gadgets `0.6.0`、halo2_poseidon `0.2.0`、pasta_curves `0.6.0`、ff/group `0.14`；Poseidon P128Pow5T3（width3/rate2/R_F=8/R_P=56）。未升级任何依赖版本。

## 5. 新增 / 修改文件

新增：`src/transition/{mod,constants,types,circuit}.rs`、`tests/d3_03_a_{smoke,mock,proof}.rs`、`docs/d3_03_a_circuit_notes.md`、`results/d3_03_a_{baseline_audit,perf,summary}.md`。
修改：`Cargo.toml`/`Cargo.lock`（加依赖）、`src/lib.rs`（模块注册 + 顶部范围说明）、两份 R2 文档（仅计数勘误）。

## 6. TransitionCircuit 结构

| 模块 | 职责 |
| --- | --- |
| `TransitionConfig` | advice/fixed/instance/selector + Pow5Config |
| 规范域编码 gadget | 32B→256 bool + `< p` 字典序 + 域元素重构（每根 257 行，4 独立 region） |
| 状态承诺绑定 | 电路内 Poseidon 重算 C_prev/C_next → instance 0/2 |
| Policy/Version binding | `bind-policy` / `bind-version` 常量 gate |
| Batch commitment | 固定 3 槽 + padding + 单调 active + 计数 + Poseidon 重算 |
| `TransitionCircuit` | 汇总 + 8 instance copy |

## 7. 8 个 instance 最终顺序

`0 C_prev` · `1 prev_epoch` · `2 C_next` · `3 next_epoch` · `4 policy_id` · `5 transition_version` · `6 D_E` · `7 event_count`。3 个 Hash32 不进电路。

## 8. C_prev / C_next 电路约束

```
D_STATE = domain_field("D3-STATE-P-v2")                     // fixed 常量
C_prev  = Poseidon(D_STATE, gr_prev_f, rr_prev_f, prev_epoch, policy_id)
C_next  = Poseidon(D_STATE, gr_next_f, rr_next_f, next_epoch, policy_id)
```
Poseidon `ConstantLength<5>`，结果 `constrain_instance` 到 0/2。**全部电路内重算**，`expected_instances()` 只用于测试构造 statement，`synthesize` 从不调用。

## 9. GR/RR 规范编码检查

256 bool 分解 + 模数 fixed 列 + `pref`/`less` 累加器 + `q_final: less==1` 强制 `int_BE(b)<p`；`acc` 累加器给出域元素供 Poseidon。拒绝 `b==p`（A14）、`b>p`（A15）、字节序错误（A16）。无 host 检查替代。

## 10. Policy / Version 约束

冻结 `policy_id`（R2-01 规范）与 `transition_version=1` 作为 `Expression::Constant` 嵌入 gate；公开 instance 必须相等。注册表核对 vk_hash↔policy_id 仍在网关电路外。

## 11. Batch Commitment

`D_E = Poseidon(D_BATCH, n, c1, c2, c3)`（固定 3 槽）；未用槽 = `batch_pad()` 由 padding gate 强制；`active` 布尔 + 单调 + `n=Σactive` + copy 到 instance[7]；顺序由 Poseidon 输入顺序绑定。

## 12. A01–A18 测试结果

- **A01–A16（MockProver）**：16/16 通过。A02/A03/A08–A13 通过改 instance 验证 copy 约束；A04–A07 通过改 witness 根验证 C 绑定；A14/A15 通过非规范字节验证电路内 `<p` 门；A16 验证字节序固定。
- **A17（真实 proof）**：keygen→create_proof→verify_proof roundtrip 成功。
- **A18（错误 instance）**：同一 proof 在 `instance[0]+1` 下被 verifier 拒绝。
- 层级区分：A01–A16 是 MockProver 拒绝（约束系统检测）；A18 是 Verifier 拒绝（密码学验证失败）；二者不混用。

## 13. 真实证明结果

见 `results/d3_03_a_perf.txt`：`K=12`，`proof_bytes=3904`，`keygen_ms=1490`，`prove_ms=2737`，`verify_ms=76`。seeded RNG，prover/verifier 独立构造。

> k 说明：任务书初始参数 k=13。实测发现 A 骨架（4 根 × 257 行 + 3 Poseidon，约 1100 行）在 k=13 下
> keygen/create_proof 计算过慢（>20 分钟未完成）。k=12（4096 行）已充分容纳电路，实测证明 16s 完成。
> 本阶段不以规模达标为验收条件，故采用 k=12 并如实记录；升至 13 仅一处常量改动，留待 D3-03-B/C 扩展后重测。

## 14. 约束规模（结构估算，非实测门数）

- 4 根 × 257 行：位布尔 256×4、transition 3 poly×256×4、final 1×4。
- 3 次 Poseidon（`ConstantLength<5>`）：按一手 `halo2_gadgets 0.6.0` Pow5Chip 36 行/136 约束每置换量级。
- 批次/策略/版本门约十余个。
- 实际采用 k=12（4096 行）容纳约 1100 行的 A 骨架，余量充足；**本阶段不以规模达标为验收条件**，逐门精确统计与完整语义电路规模对比留待 D3-03-E。

## 15. 未解决问题与安全边界

- 本电路**不是** ALLOW 证明（无 Grant 路径/请求摘要，需组合 D2-A π_path），**不是** DENY 证明（非存在性）。
- 不证明历史完整性、布局规范性、Bridge 签名、执行时新鲜性；这些仍是外部/网关责任。
- 类别 (II) SHA-256 摘要走链下 `field_from_bytes`，电路不碰。
- 约束数为结构估算，未做逐门精确统计与完整语义电路规模对比。
- 3 槽批次为原型固定容量；Cascade、2 grant+1 revoke 完整语义留 D3-03-B/C。

## 16. 是否进入 D3-03-B

**满足进入条件**：R2 接口计数勘误完成、8 instance 顺序固定、电路编译运行、C_prev/C_next 电路内重算、规范编码电路约束、policy/version 常量 gate、批次承诺电路重算、A01–A18 通过、真实 proof roundtrip 成功、冻结实现零改动。下一步可在 A 骨架上叠加单 Grant 创建与 Parent Binding（D3-03-B）。
