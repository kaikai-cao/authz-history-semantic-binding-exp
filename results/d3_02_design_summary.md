# EXP-D3-02 — Halo2 Authorization State Transition Proof 设计总结

仓库：`kaikai-cao/authz-history-semantic-binding-exp`
基线：`dc13e810a65558362ccf1458bed593ca015abd9e`（D3-01-R1，冻结）
分支：`exp-d3-02-design`
本轮性质：**设计阶段**。未新增电路代码，未修改 D3-01 / D1-E / D2-A / D2-B 的任何实现、
固定向量或历史实验数据。

---

## 1. Commit SHA / Remote SHA

- 基线（分支起点）：`dc13e810a65558362ccf1458bed593ca015abd9e`
- 本轮提交与远端 SHA：见最终回传与
  `git ls-remote origin refs/heads/exp-d3-02-design`；Branch 与本地 HEAD 需一致。

## 2. 新增文件清单

```
docs/d3_02_public_statement.md        公开语句、编码、威胁模型、字段删除实验
docs/d3_02_construction_comparison.md  A/B/C 三构造完整方案与成本模型
docs/d3_02_circuit_spec.md             推荐构造 A 的 11 模块约束规格
docs/d3_02_security_analysis.md        历史完整性、撤销新鲜性、ALLOW/DENY
docs/d3_02_prototype_plan.md           最小原型与 P01–P12 测试设计
docs/d3_02_related_work.md             五类定向文献/源码核查
results/d3_02_design_summary.md        本文件
```

## 3. 最终 public statement

8 个公开字段（数量与 D3-01 的 9 个同量级，语义不同）：

```
previous_state_commitment : Field   // 来自 D2-B anchor_digest，带外可信（新增，最关键）
next_grant_root           : Field   // 供冻结的 D2-A 电路直接消费
next_revoke_root          : Field
next_epoch                : u64
event_batch_commitment    : Field   // Poseidon 承诺，替换 SHA-256 digest
event_count               : u32
policy_id                 : Field   // 版本化策略标识，替换 SHA256(code)
previous_epoch            : u64     // 网关 fencing 用
```

六项关键回答：
- SHA-256 `event_batch_digest` **不直接进电路**，改为电路内可重算的 Poseidon 批次承诺；
  否则要么电路代价过高，要么重演"摘要相等 ≠ 语义合法"。
- `event_count` 密码学上可省（编码进承诺即可），操作上保留用于容量与审计。
- `previous_anchor_digest` **必须**公开（本设计即 `previous_state_commitment`）；
  `next_anchor_digest` 第一版不需要独立公开。
- `epoch` 被承诺但仍独立公开，换取网关可审计的 fencing；epoch 单调 ≠ 新鲜。
- `SHA256(policy.code())` **不足以**约束策略，改为版本化 `policy_id`，电路内硬编码规则集。
- 请求上下文/资源标识**不进入**状态转换语句；`resource` 作为 grant 字段已在 GR 叶子中绑定，
  请求级绑定由 D2-A 的 `Dq` 负责。

## 4. 三种证明构造比较结果

| 方案 | 核心 | 深度 4 / 2 事件估算 | 关键缺陷 |
| --- | --- | --- | --- |
| **A 完整重放（推荐）** | 逐事件执行 T(S,e)，重算 GR/RR | ~7k–9k 约束，~1.3k–2k 行 | 大批次需增大 k 或分片 |
| B 状态差分 | 只约束变更叶子 + 事件背书 | ~5k–7k 约束（m=2） | Merkle 多点更新**不是**历史完整性证明；隐藏撤销无法自证 |
| C 递归/分批 | 每批固定电路 + 累积器 | 单批同 A + 递归开销 **UNKNOWN** | 本仓无 in-circuit verifier；n≤3 时开销远大于收益 |

成本口径来自一手源码：`halo2_poseidon 0.2.0`（R_F=8/R_P=56, width 3）、
`halo2_gadgets 0.6.0 Pow5Chip`（36 行 + 136 约束/置换，3 约束/absorb 行）。
D2-A 冻结基准：k=12 约 2.1 s 证明 / 47 ms 验证，仅作同量级参照，**不是本设计实测**。

## 5. 推荐电路约束规格

11 模块全部给出 witness / 约束关系 / 负向测试：
Event Encoding、Grant Validity、Parent Binding、Scope、Resource、Revocation、Epoch、
GR Update、RR Update、Batch Binding、State Binding。

分类：
- `IN_CIRCUIT`：上述 8 项语义与双根更新模块（含 `valid_flag` 专用列与 `s_not_revoked` 门，
  吸取 D2-A-R1 教训）。
- `OFF_CIRCUIT`：SHA-256 摘要、规范槽位探测顺序（已在规格 §2.8 明写信任代价）。
- `EXTERNAL_TRUST`：quorum 验签、日志 inclusion/consistency、freshness、`C_prev`/`D_E` 来源。

## 6. 历史完整性与新鲜性分析

历史完整性五类攻击逐一给出构造与防护：删撤销（电路**不能**发现）、跳中间授权
（旁支叶子情形电路接受）、重放旧批次、使用旧合法状态、合法但不完整子集。
共同结论：**电路只保证相对可信 `C_prev`/`D_E` 的语义正确，不保证历史完整**。

新鲜性：证明生成后撤销、验证后撤销（TOCTOU）、checkpoint 落后、Witness Service 不可用、
quorum 未形成——电路全部无能为力。给出执行端方案：**短 TTL quorum 令牌 + 版本化 CAS**，
撤销时递增版本并使未过期令牌失效；失败一律 fail-closed。
QC 只证明认证，不证明最新性；freshness 是外部假设。

## 7. ALLOW / DENY 结论

- 本轮 π_trans 本身**不证明 ALLOW**；ALLOW 需与冻结的 D2-A 路径证明组合
  （以 `GR_next/RR_next` 为 instance）。
- **DENY 不能证明**：DENY 是非存在性语句，当前 NP 关系电路无法枚举"不存在有效路径"；
  网关在没有有效 ALLOW 时 fail-closed，**不得**把拒绝解释为"电路证明了授权不存在"。
- 因此本设计**不是完整授权决策证明**。

## 8. 相关工作核查结果

七项一手来源，均记录标题/作者/年份/链接/具体结论：
Halo（Bowe/Grigg/Hopwood 2019）、Poseidon（Grassi 等，ePrint 2019/458 / USENIX Sec 21）、
plookup（Gabizon/Williamson 2020）、Reckle Trees（Papamanthou 等，CCS 2024）、
Verdict（Tzialla 等，NDSS 2022）、Nova（Kothapalli/Setty/Tzialla，CRYPTO 2022）、
RFC 6962（Laurie/Langley/Kasper 2013）、IRAC（Xie/Song/Cai 2025，预印本）。
每项区分"论文提出 / 代码实现 / 我们采用 / 推测"，并列出它们**未覆盖**的多授权来源、
部分撤销、隐藏历史与外部最新状态绑定组合。

## 9. 最小原型选择及 P01–P12

基准：halo2 0.4 / Pallas-Vesta / Poseidon P128Pow5T3 / 深度 4 / 2 grant + 1 revoke /
DirectOnly（Cascade 为独立对照），k 初值 13。
P01/P02 正向，P03–P10/P12 负向，P11 故意设计为"电路内接受、网关外部拒绝"以暴露
历史完整性边界。每项标明 MockProver 层还是真实 proof 层；沿用 D2-A-R1 口径，
不把"prover 出 proof 但 verifier 拒绝"写成"create_proof 失败"。

## 10. 成本估算与依据

- Poseidon：L=3/L=4 叶子或节点调用 = 2 置换 = 72 行 / 278 约束；
  L=9（grant 叶子、事件承诺）= 5 置换 = 180 行 / 695 约束；
  L=5（state commitment）= 3 置换 = 108 行 / 417 约束。
- 深度 4：单 grant 事件 ≈ 900 行 / 4 400–4 500 约束；单 revoke ≈ 756 行 / 3 000–3 100 约束。
- 批次 2 grant + 1 revoke：约 1 300–2 000 行 / 7 000–9 000 约束。
- 容量（仅行预算）：k=12 → 3–4 事件（d=4）；k=16 → 60–70；k=20 → 900–1 100。
- 依据：`halo2_poseidon 0.2.0/src/p128pow5t3.rs`、`halo2_gadgets 0.6.0/src/poseidon/pow5.rs`、
  D2-A `results/experiment_report.md` §6、D3-01 `results/experiment_report.md` §6/§10.4。
  所有数字为静态约束/行估算或他仓实测参照，**不是 D3-02 实测证明性能**。

## 11. 未解决问题

1. SHA-256 批次摘要与 Poseidon 批次承诺的桥接（第一版依赖可信来源双签；Reckle-style
   digest translation 属后续）。
2. D3 `D3-` 域标签与 D2-A `D2A-label-v1` 不一致，GR/RR 根不能直接互用。
3. 规范槽位探测顺序未在电路内约束（OFF_CIRCUIT，已明写）。
4. 递归 verifier 在本栈无实现；方案 C 开销 UNKNOWN。
5. Cascade 传递闭包未进第一版主电路。
6. 历史完整性与 freshness 的外部信任无法由本电路增强；quorum 合谋、日志被攻破仍可绕过。
7. DENY 证明与非存在性语句未设计。
8. 本轮无真实证明、无性能测试、无生产 resource 模型。

## 12. Git 状态

- 本轮只新增上述 7 个文件；不修改 D3-01 冻结实现、fixed vectors、历史 results。
- 提交命令按任务书：`git add docs/d3_02_*.md results/d3_02_design_summary.md`，
  单条提交后推送 `exp-d3-02-design`，并核验本地 HEAD 与远端 SHA 一致。
- 提交后工作区应为 clean（除被 `.gitignore` 排除的 `target/` 等）。

---

## 本轮最重要的决策

**推荐构造 A（固定容量完整批次重放）作为第一版。**

相对 D3-01 的链下状态机参考实现，它真正增加的密码学保证只有一条，但足够重要：

> 给定带外可信的前状态承诺 `C_prev` 与批次承诺 `D_E`，
> 证明者**无法**为一个违反授权规则的批次（scope 越界、parent 无效、非 issuer 撤销、
> 重复撤销、epoch 回退、伪造双根）生成可通过验证的证明。

D3-01 给的是"重执行后发现错误"（falsification），Halo2 证明给的是"错误批次不存在接受证明"
（unforgeability of semantic validity）。它没有、也未被声称增加历史完整性与执行时新鲜性；
这两项继续由 D1-E/D2-B 与执行端 fencing 负责。把这一点写清楚，比多做一个电路更重要。
