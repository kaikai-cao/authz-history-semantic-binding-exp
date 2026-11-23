# EXP-D3-02-R2 — Prototype Entry Freeze Report

**基线**：`023a5d1641354dc7f7257a09cc23a28787b33b0d`（D3-02-R1）
**分支**：`exp-d3-02-r2`
**日期**：2026-11-23
**性质**：设计冻结。本轮只新增 6 个文档，不改任何冻结实现、固定向量或历史数据。
**结论**：**达到原型入口冻结条件**——D3-03 最小 Halo2 原型可以按本报告参数实现。

---

## 摘要（本轮真正解决了什么）

R1 留下三个"接口有名字但语义未冻结"的问题，R2 把它们收敛成可逐字节复现的规范：

1. **policy_id 循环定义**：根因是"摘要自然语言文档"——文档正文可能写 policy_id，形成自引用。
   R2 引入**独立结构化 CircuitSpec 工件**（禁止含 policy_id/自身哈希），单向依赖消除循环。
2. **32B→Field 映射**：澄清系统中存在**两类 32B 值**——域元素编码（GR/RR，必须严格规范、
   禁模约简）与摘要（digest，必须哈希到域）。此前两类混用会造成"约一半摘要被拒"或
   "静默模约简破坏承诺绑定"。R2 分出两条路，给出一一对应证明与字节序桥接（大端↔小端）。
3. **canonical layout / C_next**：收敛为唯一方案（外部可信布局签名 + 网关重算），
   C_next 直接采用 Poseidon 固定式，9 个接口问题逐一回答，IN/OFF/EXTERNAL 三层无模糊表述。

**新增的密码学保证**：没有。R2 不改变安全性质，它把 R1 的"有接口但可实现错"变成
"接口逐字节确定、可审计、有分层测试"。真正的能力跃迁要等 D3-03 电路实现后
（把"错误批次无接受证明"从参考实现提升为密码学约束）。

---

## 1. 最终架构

```
                          ┌─────────────────────────────────────────┐
                          │ 外部信任层（电路外，网关执行）          │
                          │  D2-B checkpoint/QC/freshness           │
                          │  → Bridge Validator（R1-01）            │
                          │  → Layout Validator（R2-03）            │
                          │  → VK Registry（R2-01/R1-03）           │
                          └──────────────┬──────────────────────────┘
                                         │ 可信锚: A_e, C_prev, layout_digest, policy_id, vk_hash
                                         ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Halo2 π_trans（D3-03 原型）                                                │
│  IN_CIRCUIT:                                                              │
│   ① C_prev/C_next 开承诺（R2-02 类别I 规范解码 + Poseidon D3-STATE-P-v2）  │
│   ② 事件语义（scope/parent/resource/revoke/epoch/valid_flag）              │
│   ③ GR/RR 双树 d=4 更新 + 给定布局下路径                                   │
│   ④ 批次承诺 D_E 重算                                                      │
│   ⑤ policy_id / transition_version 常量 gate                              │
│  OFF_CIRCUIT / EXTERNAL_TRUST: SHA-256、验签、布局规范性、id 集合、freshness│
└──────────────────────────────┬─────────────────────────────────────────────┘
                               ▼
                    GR_next/RR_next（witness 展开）
                               ▼
              D2-A π_path（ALLOW）+ 执行端 fencing（短 TTL + CAS）
```

**三层分离**：历史完整性归 D1-E 日志 + 可信批次来源；状态可信性归 D2-B/Bridge；
语义正确性归 Halo2；新鲜性归执行端 fencing。任一层不被其他层声称。

---

## 2. 编码规范（冻结，逐字节可复现）

| 编码 | 规则 | 来源 |
| --- | --- | --- |
| 长度前缀 | `enc_bytes = u64be(len) ‖ bytes`（8B 大端） | D3-01 `encoding.rs:132` |
| 整数 | `u32be` 4B，`u64be` 8B | D2-B / D3-01 一致 |
| Pallas Fp 模数 | `p = 0x4000…0001`，`NUM_BITS=255` | pasta_curves 0.6.0 `fp.rs` |
| 域元素外部形式（类别 I） | **32B 大端规范**，`int_be < p`，禁模约简；pasta 内部是 32B 小端 `Repr`，桥接用 `reverse` | R2-02 §1–§3 |
| 摘要到场（类别 II） | `field_from_bytes(label, msg) = F::from_uniform_bytes(SHA256(msg)‖SHA256(label))`，64B 小端模约简 | D3-01 `encoding.rs:97` |
| Poseidon | `P128Pow5T3`, width=3/rate=2/R_F=8/R_P=56 | halo2_poseidon 0.2.0 |
| 状态承诺 | `C = Poseidon(D3-STATE-P-v2, GR_f, RR_f, epoch, policy_id)` | R1-01 / R2-03 |
| 域标签 | D3: `D3-STATE-P-v2,D3-GRANT-v1,D3-REVOKE-v1,D3-NODE-v1,D3-SLOT-v1,D3-EVENT-v1,D3-BATCH-v1`；D2-B: `ZK-STATE-ANCHOR-01:*`；D2-A: `D2A-label-v1` | 一手源码；三套未统一 |

**字节序桥接恒等式**（Python 实测验证）：`int_be(b) == int_le(reverse(b))`，
故 `b_be` 是大端规范域编码 ⟺ `reverse(b_be)` 是小端规范表示。边界值表见 R2-02 §4.3。

---

## 3. Policy ID 规范（冻结）

```
D_circuit = SHA256( enc_bytes("D3-CIRCUIT-SPEC-v1") ‖ CanonicalEncode(CircuitSpec) )
policy_id = F::from_uniform_bytes( SHA256(CanonPolicyId) ‖ SHA256("D_POLICY") )

CanonPolicyId =
    enc_bytes("D_POLICY") ‖ u32be(version) ‖ enc_bytes(name)
  ‖ enc_bytes(parameters) ‖ enc_bytes(D_circuit)
```

- `CircuitSpec` 是**结构化工件，禁止含 policy_id / vk_hash / 自身哈希 / 时间戳**（R2-01-C1/C2），
  14 个字段见 `d3_02_r2_policy_id_spec.md` §2.3。依赖单向：policy_id → D_circuit，无环。
- DirectOnly vs Cascade：靠 `name`（`DIRECT_ONLY`/`CASCADE`）+ `strategy_flag`（1/2）+
  `circuit_label` 三处区分，任一处变化都产生不同 policy_id。
- `vk_hash` **只进注册表，不进 policy_id**（避免编译不确定性与新循环）。
- 最终归属：语义身份进 policy_id；编译指纹进 VK 注册表键；commit/构建元数据只作审计。

---

## 4. Canonical Layout 规范（冻结）

- `C_next = Poseidon(D3-STATE-P-v2, GR_next_f, RR_next_f, next_epoch, policy_id)`（直接采用固定式）。
- GR/RR 用 R2-02 类别 I 规范编码；布局规范性 = **外部可信布局签名 + 网关独立重算**；
  电路只验给定布局下路径与 slot 范围。
- `assignment_digest` 覆盖**完整 id→slot 映射** + 前后 C + 前后 epoch + nonce + expires_at（R2-03 §5）。
- 三套独立签名密钥：D2-B QC / Bridge quorum / Layout quorum，验证端分别配置。
- 删除/插入/碰撞/重插/displaced id 沿用 D3-01-R1 `try_upsert`；最坏位移全部 16 槽。
- **电路层接受非规范布局**（T09/T10），布局验证器/网关拒绝——诚实边界。

---

## 5. 最终 Public Inputs（冻结，12 字段）

```
previous_anchor_digest: Hash32   (网关用, 不进电路)
previous_state_commitment: Field (电路开承诺)
previous_epoch: u64              (单调起点, 进 C_prev)
next_state_commitment: Field     (电路开承诺, 替代 R1 的独立双根)
next_epoch: u64                  (单调终点)
policy_id: Field                 (常量 gate)
transition_version: u32          (新增, 常量 gate, 防旧证明重放)
event_batch_commitment: Field    (批次承诺)
event_count: u32                 (容量/审计)
layout_digest: Hash32            (网关用, 不进电路)
vk_hash: Hash32                  (网关用, 不进电路)
```

**8 字段进电路 instance**（6 Field + 2 u64/u32 映射），4 个 Hash32 仅网关电路外核对。
`u64/u32 → Field` 用 `F::from_u64` 单射（小整数，非 R2-02 类别 I 的 32B 编码）。
详见 `d3_02_r2_transition_interface.md` §1。

---

## 6. 私有 Witness（冻结）

前后 4 棵 SMT + GR/RR 大端字节与域元素对 + 事件批次 + Merkle 路径/中间根/parent 路径
+ 槽位与完整 assigned 快照 + policy 参数 + **字段规范解码范围检查 witness**
+ Bridge/Layout 签名材料（打包方便，不进电路）。完整结构见 `d3_02_r2_transition_interface.md` §2。

---

## 7. 证明关系（冻结，9 子关系）

R(x,w)=1 拆为：① Anchor Bridge（开承诺+规范解码）② Canonical Slot（给定布局路径）
③ Policy+Version（双常量 gate）④ Event 语义 ⑤ GR 更新 ⑥ RR 更新 ⑦ Batch 承诺
⑧ State Binding（单调+C_next）⑨ Field Encoding（规范检查+字节反转）。
每项 IN_CIRCUIT/OFF_CIRCUIT/EXTERNAL_TRUST 标注见 `d3_02_r2_transition_interface.md` §3，
网关 9 步检查清单见 §4。**无安全关键检查被悄悄移到链下**。

---

## 8. 测试矩阵（冻结）

T01–T16 覆盖正常转换（2）、编码/策略/VK/Bridge/Layout/批次/状态绑定攻击（14）。
每项含输入构造、拒绝组件、层级（MP/RP/BV/LV/VK/GV）、是否需真实证明、支持/不支持结论。
**7 处非电路拒绝点如实标注**：T06/T08/T09/T10/T13/T14 + T03/T04 的 Bridge 层。
详见 `d3_02_r2_test_matrix.md`。

---

## 9. 电路规模估计（静态粗估，未经实测）

依据一手源码 `halo2_poseidon 0.2.0`（R_F=8/R_P=56）、`halo2_gadgets 0.6.0 Pow5Chip`
（36 行/136 约束每置换）：

| 模块 | 约束量级 |
| --- | --- |
| 事件语义（≤3 事件） | ~7k–9k（沿用 D3-02 估算） |
| 前状态开承诺 C_prev（3 置换） | ~417 |
| 后状态开承诺 C_next（3 置换） | ~417 |
| GR/RR 规范解码（4 根 × 250–500） | ~1k–2k |
| policy+version 常量 gate | ~10 |
| k 目标 | 13（超限则 14，须更新 CircuitSpec） |

**合计 ~9k–12k 约束（粗估）**。对比 R1 的 7k–9k，增量主要来自 R2 新增的字段规范解码
（~1k–2k）。所有数字未经 MockProver / 真实证明校准，标记 UNKNOWN，不作容量结论。

---

## 10. 未解决的安全问题（不声称已解决）

1. **Bridge 签名者外部信任**（R1-01 B-F1）：合谋/被攻破可对伪造 (A_e, C_e) 签名，电路无法检测。
2. **布局 quorum 外部信任**（R1-02 U6）：可签非规范布局，T09/T10 电路层接受。
3. **id 集合完整性**：靠可信前快照 + changed_ids + 审计重算，非密码学证明。
4. **跨 vk 重放**（R09/T14）：verifier 层可能接受，只靠 VK 注册表拒。
5. **历史完整性**：删撤销/跳事件/重放旧批次/不完整子集，电路单独无法发现（D3-02 security §1）。
6. **执行时新鲜性**：证明生成后或网关验证后发生撤销，靠 fencing（短 TTL 令牌 + 版本 CAS），
   QC 与 Bridge TTL 都不等于最新性。
7. **DENY 不可证明**：非存在性语句，π_trans 不证明；无 ALLOW 时网关 fail-closed，
   不得解释为"电路证明授权不存在"。
8. **D3 ↔ D2-A 域标签未对齐**：D3 SHA-256 域化 vs D2-A BLAKE2b `D2A-label-v1`，
   策略统一仅网关配置层，非电路级。
9. **32B↔域元素映射的电路内实测**：§9 约束数为粗估，需 D3-03 MockProver 校准。
10. **quorum 合谋 / D1-E 日志被攻破**：外部前提，不在本设计范围。

---

## 11. 原型实现顺序（D3-03 → D3-05）

**D3-03 最小 Halo2 原型**（本轮冻结后直接开始）：
1. 搭 Pallas + Poseidon P128Pow5T3 gadget + k=13 floor planner。
2. 实现 C_prev/C_next 开承诺 + R2-02 类别 I 规范解码（先 MP 跑 T03/T04）。
3. 实现事件语义 11 模块（先 DirectOnly），MP 跑 T01/T02/T15/T16。
4. 实现双树 d=4 更新 + 给定布局路径 + 批次承诺，MP 跑 T11/T12。
5. 实现 policy_id/transition_version 常量 gate，MP 跑 T05/T14。
6. 产物：约束数清单 + MP 测试日志（不生成真实 proof）。

**D3-04 真实证明与成本测量**：对 T01/T02/T05/T11/T12/T14/T15/T16 生成真实 proof，
测量约束数、证明时间、验证时间、证明大小、内存；预注册测量口径（沿用 Sapling 项目习惯）。

**D3-05 端到端信任链**：实现 BV / LV / VK Registry / Halo2 Verifier / Gateway，
跑 T03–T10/T13 链下检查，验证"电路接受但网关拒绝"行为。

---

## 12. 原型完成的验收条件（D3-03）

1. 冻结的 12 字段接口零增删（除 §11 的版本流程）。
2. T01/T02/T11/T12/T15/T16 在 MP 层全绿；T03/T04/T05/T14 MP 层按预期拒绝。
3. T09/T10 MP 层**接受**（诚实边界）+ 布局验证器拒绝（D3-05）。
4. R2-01 policy_id 与 R2-02 编码的 Python 参考实现与 Rust 实现逐字节一致
   （可复现向量：policy_id 冻结值、Fp 边界值表）。
5. 约束数清单与 §9 估算的差异被记录并解释（超 k=13 则按 §11 流程升 k）。
6. 未修改任何冻结实现 / 固定向量 / 历史数据。
7. 明确未实现项（真实 proof、外部验证器、CircuitSpec 工件生成器）不得声称完成。

---

## 本轮边界确认

- ✅ 达到**原型入口冻结条件**：接口逐字节确定、编码可复现、测试规范明确、参数可冻结。
- ❌ 未实现完整 Halo2 电路（D3-03 任务）。
- ❌ 未改 D1-E / D2-A / D2-B / D3-01-R1 冻结实现。
- ❌ 未改 fixed vectors / 历史实验数据。
- ❌ 未声称解决历史完整性、新鲜性、DENY、外部信任、域标签对齐。
- **最重要的诚实结论**：R2 没有增加密码学保证。它把 R1 的"接口有名字但语义未冻结"
  变成"接口逐字节确定、可审计、有分层测试"。真正值得证明的关系仍是那一条：
  **给定可信前状态与批次承诺，违反授权规则的批次不存在可通过验证的证明**。
  D3-03 电路实现后，这条保证才从"参考实现重执行"提升为"密码学约束"。
