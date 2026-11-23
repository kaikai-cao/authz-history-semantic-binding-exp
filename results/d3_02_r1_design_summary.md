# EXP-D3-02-R1 — 设计修订总结：Anchor Bridge、Canonical Slot Trust Boundary & Policy Binding

**仓库**：`kaikai-cao/authz-history-semantic-binding-exp`
**基线**：`98906dd1f94f7d9922f7759989f896c418c85561`（D3-02 设计阶段）
**分支**：`exp-d3-02-r1`
**性质**：设计修订。本轮**不实现完整电路**，不修改 D3-01-R1 / D2-A / D2-B 冻结实现、fixed
vectors 或历史数据。新增 5 份设计文档 + 本总结（6 文件）。

---

## 0. 本轮要回答的关键问题

> **Halo2 证明的状态，到底如何与真实、可信、规范、符合特定授权策略的外部状态建立不可伪造的关系？**

**回答（一句话）**：通过三条**外部签名锚点**（D2-B anchor + 认证 Bridge、canonical 布局签名、
vk 注册表）把"真实/可信/规范/策略正确"的责任明确落到可审计的外部机制；Halo2 电路只在这些
锚点之间证明**事件语义正确与双根更新正确**。三者都不是电路内证明，因此必须写成信任假设；
电路新增的保证有且只有一条——**给定可信前状态/布局/策略身份，违反授权规则的批次不存在接受证明**。
这足以进入最小原型，但不构成完整授权决策证明。

**任务书 10 问 → 本文件章节映射**（便于逐条验收）：
Q1→§1、Q2→§2、Q3→§3、Q4→§4、Q5→§5、Q6→§7、Q7→§8、Q8→§9、Q9→§10、Q10→§11；
§6（证明关系）与 §12（Git 状态）为补充，回传格式 12 项见文末与最终回传。

---

## 1. 最终推荐哪种 Anchor Bridge？

**方案 A′：认证式可信 Anchor Bridge**（`d3_02_r1_anchor_bridge.md`）。

- `C_prev` 语义唯一化为 `Poseidon(D3-STATE-P-v2, GR, RR, epoch, policy_id)`（电路内可开承诺），
  修正上一轮 `C_prev = field_from_bytes(anchor_digest)` 与 `Poseidon(状态字段)` 的文档冲突。
- Bridge Service 链下完成"D2-B SHA-256 anchor A_e → C_prev"绑定：先经 D2-B 验证器确认
  checkpoint/QC/freshness，再断言 `A_e = SHA256(encode(s))`，用目标域标签算 Poseidon 承诺，
  签发**带签名**的 Bridge Statement（覆盖完整状态元组、A_e、checkpoint_hash、前驱、域标签版本、
  policy_spec_digest、epoch、TTL、nonce）。
- 电路增量成本最低（+1 Poseidon L=5 ≈ 417 约束，粗估）；SHA-256 验证留在链下。
- **方案 B（电路内 SHA-256）**不采用：约 O(10⁴) 约束静态粗估，且 32B↔域元素一致性未解；
  作为"消除 Bridge 签名信任"的长期方向。**方案 C（双承诺 Anchor）**不采用：需改 D2-B 冻结实现。
- **新增信任代价（不可声称已消除）**：Bridge 签名者必须对"用正确元组与域标签算 Poseidon"负责；
  电路无法检测其合谋。缓解为 quorum + 独立密钥 + 与 checkpoint 交叉核对 + 审计日志。

---

## 2. 是否将 canonical slot 放进电路？

**否，第一版不放完整布局规范性**（`d3_02_r1_canonical_slots.md`）。

- 采用**方案 A：外部可信布局**：可信状态服务执行 D3-01-R1 的 `canonical_assignment` 并对
  `assignment_digest`（完整 id→slot 映射 + 前后状态承诺 + epoch + nonce）签名；网关/审计者独立
  重算比对。电路继续只验证"给定槽位下的叶子写入与 d 层路径重算"。
- **方案 B（电路内完整验证）**约束量静态粗估 ≈ 5×10⁴（B-1 排序 2.4k + B-2 初始槽位 SHA-256
  ≈32k + B-3 探测 ≈16k + B-4 单射 480；B-5 删除重插需重跑），是语义电路 7k–9k 的数倍，
  第一版不可行。
- `slot` witness 与路径更新仍是 `IN_CIRCUIT`；**布局规范性是 `EXTERNAL_TRUST`**（U6）。

---

## 3. 是否值得做局部 canonicality？

**记录为未来方向，第一版不作为任何保证声称**。

- 局部 canonicality 在数学上是**归纳步骤**：若前布局规范，且局部转移正确实现 D3-01-R1 的
  displacement（一次插入可挤走任意多已有 id），则新布局规范。
- **致命前提**：必须有可信的"前布局规范"锚点。本栈无 in-circuit verifier（上一轮结论），
  无法以递归证明提供该锚点；只能通过方案 A 的外部布局签名获得——所以局部方案**不能独立消除**
  外部信任，只是把它弱化到"一次归纳步骤 + 前布局"。
- 最坏受影响槽位数 = **全部 16 个槽位**（新 id 规范序最小且探测链重叠 → 连锁 displacement）。
  因此最坏情况退化为全局重证，局部优势消失。
- 无法覆盖攻击：非规范前布局（L-A1）、遗漏 displaced id（L-A2）、隐藏碰撞（L-A3）——
  这正是 R07/R08 的攻击模型。触发条件：本栈具备 in-circuit verifier，或外部提供可信规范前布局链。

---

## 4. policy_id 如何绑定实际电路？

**四机制组合，最终安全保证由「每策略独立编译 vk + 网关 vk 注册表」承担**（`d3_02_r1_policy_binding.md`）。

- 定义：`policy_id = H(D_POLICY, policy_version, policy_name, policy_parameters, circuit_spec_digest)`，
  其中参数含 `resource_prefix_bytes=8`、`scope_bytes=8`、epoch 单调、grant/revoke 规则 git sha、
  Merkle 域标签集、深度/容量、`direct_only_flag`；`circuit_spec_digest` 取冻结电路规范 SHA-256。
- ① 电路内 gate 强制 `policy_id_public == policy_id_const`（fixed 列）——防"同 vk 改公开值"；
  ② DirectOnly/Cascade **独立编译**成两把 vk——不同策略物理隔离；
  ④ 网关注册表 `vk_hash → (policy_id, circuit_spec_digest, commit, active)`——**最终安全保证**，
  验证者唯一能独立检查的策略身份环节；③ "参数逐项进 public 并 gate"作为扩展，第一版不用
  （隐私 + 成本，其安全作用被①②④覆盖）。
- **核心诚实点**：电路中硬编码 DirectOnly ≠ `policy_id` 自动等于 DirectOnly。R06（声称 Cascade）
  由①+④挡；**R09（跨 vk 重放）在电路/verifier 层可能接受**，只能靠注册表拒绝。
- D2-A 的 `policy_tag`（`D2A-label-v1` BLAKE2b）与 D3 `policy_id`（SHA-256 域化）不是同一承诺，
  两电路 GR/RR 根不能互认——策略统一只在网关配置层，明确为未解决。

---

## 5. 最终 Public Statement

11 个公开字段（D3-02 为 8，新增 3、修订 2）：

```
previous_state_commitment : Field    // C_prev = Poseidon(D3-STATE-P-v2, GR, RR, epoch, policy_id)（修订）
previous_anchor_digest    : Hash32   // 新增：A_e，网关核对 checkpoint（不进电路）
previous_epoch            : u64      // fencing；与 Bridge epoch 一致
layout_digest             : Hash32   // 新增：assignment_digest，布局签名承诺
next_grant_root           : Field    // GR_next，供 D2-A 消费
next_revoke_root          : Field    // RR_next
next_epoch                : u64
event_batch_commitment    : Field    // D_E = Poseidon(D_BATCH, n, c_1..c_n)
event_count               : u32
policy_id                 : Field    // 修订：结构化 id（含 circuit_spec_digest）
vk_hash                   : Hash32   // 新增：验证密钥指纹，网关查注册表
```

新增三字段把上一轮隐含的外部信任**显式化为可审计公共输入**；`previous_anchor_digest`/`vk_hash`
是 Hash32 字节，**不进 Halo2 instance 列**，由网关/验证端电路外核对。完整字段表（公开/私有、
生成者、认证者、电路用途、网关检查、防重放）见 `d3_02_r1_integrated_statement.md` §1.1。

---

## 6. 完整证明关系（八子关系）

`R(x,w)=1` 拆为：① Anchor Bridge Binding（`IN_CIRCUIT` 开承诺 + `EXTERNAL_TRUST` A_e 来源）；
② Canonical Slot Validation（`IN_CIRCUIT` 给定布局路径 + `EXTERNAL_TRUST` 布局 quorum）；
③ Policy Binding（`IN_CIRCUIT` 常量 gate + `EXTERNAL_TRUST` vk 注册表）；
④ Event Semantic Validation（全 `IN_CIRCUIT`）；⑤ GR Update / ⑥ RR Update（`IN_CIRCUIT` 叶子+路径）；
⑦ Batch Commitment（`IN_CIRCUIT` 重算 + `EXTERNAL_TRUST` 来源）；⑧ State Transition Binding
（`IN_CIRCUIT` 单调+结果绑定）。**没有任何安全关键检查被悄悄移到链下而不写明代价。**

---

## 7. 相比 D3-02，新增了哪些密码学保证？

**严格说，密码学保证本身没有增加**——电路语义与双根更新约束与 D3-02 相同。本轮增加的是
**接口的可审计性与信任边界的明确化**：

1. 消除了 `C_prev` 的语义歧义（Poseidon of 完整状态元组，电路可开承诺）——使"前状态锚定"从
   不可用的摘要域化变成可用的承诺。
2. 把三处隐含信任变成**签名可验证的外部消息**：Bridge Statement（R1-01）、Canonical Layout
   Statement（R1-02）、vk 注册表条目（R1-03）。网关有明确的检查清单（集成文档 §4），
   "proof 有效 ≠ 状态正确"被操作化为 9 步检查。
3. 给出 R01–R10 的**分层测试设计**，其中 R07/R08/R09 诚实标注"电路层接受/verifier 可能接受，
   靠外部拒绝"——防止把外部信任误当成电路保证。

真正的密码学保证仍是那一条：给定可信锚点，违规批次无接受证明。本轮让它**可被正确实现与验证**。

---

## 8. 仍有哪些信任假设？

| # | 信任假设 | 责任方 |
| --- | --- | --- |
| T1 | D2-B quorum 不合谋、D1-E 日志 append-only | D1-E/D2-B |
| T2 | **Bridge 签名者**对正确状态元组+域标签算 Poseidon 负责（新增） | Bridge quorum |
| T3 | **布局服务**执行规范 canonical_assignment 并诚实签名（新增） | 布局 quorum + 审计重算 |
| T4 | **vk 注册表**治理方正确维护策略↔vk 映射（新增） | 治理方 |
| T5 | 可信批次来源对完整事件字节算 Poseidon 承诺 | 批次来源/D1-E 日志 |
| T6 | 执行端 fencing（TTL 令牌 + 版本 CAS）在工具执行前生效 | 网关/执行端 |
| T7 | D3 ↔ D2-A 域标签对齐（当前未解决，只有网关配置绑定） | 未来研究 |

QC 只证明认证，不证明最新性；freshness 是外部假设——两句原样保留。

---

## 9. 是否可以进入 Halo2 原型阶段？

**可以进入最小原型（bounded prototype），但需先冻结下列参数。** 理由：三个接口问题已给出明确
实现路径与信任边界，电路的规范输入（前状态承诺语义、布局 witness 来源、策略身份绑定）已经确定；
继续抽象设计不再增加确定性。

**成本估算（依据）**：
- Poseidon（一手 `halo2_poseidon 0.2.0` R_F=8/R_P=56、`halo2_gadgets 0.6.0` Pow5Chip
  36 行/136 约束每置换）：L=5 前状态开承诺 ≈ 3 置换 / 108 行 / 417 约束（粗估）；
  事件语义+双树更新沿用 D3-02 的 7k–9k 约束估算。
- 方案 B（未采用）SHA-256 anchor ≈ O(10⁴)、完整 canonical 布局 ≈ 5×10⁴ 约束——均为
  **静态数量级推断，未经 MockProver/实测**，明确标记粗估。
- D2-A 冻结实测（k=12 ≈2.1s 证明/47ms 验证）仅作同量级参照，**不是本设计实测**。

---

## 10. 原型阶段需要冻结哪些参数？

1. **Poseidon 参数与域标签**：P128Pow5T3 width3；`D3-STATE-P-v2`（新）、`D3-GRANT-v1`/
   `D3-REVOKE-v1`/`D3-NODE-v1`/`D3-BATCH-P-v2`/`D3-EVENT-P-v2`/`D3-SLOT-v1`（沿用）。
2. **树参数**：depth d=4（16 槽位）；max 2 grant + 1 revoke；DirectOnly 主电路 + Cascade 独立对照。
3. **k 值**：初值 13–14，以 MockProver 通过后真实证明校准。
4. **32B↔域元素映射**：D2-B 的 32B FieldBytes → Pallas field 的确定性映射与范围约束实现
   （R1-01 B-F4，当前未定，原型第一步必须冻结）。
5. **Bridge/布局签名方案**：签名算法（建议 Ed25519）、quorum 阈值与公钥集合来源、Domain 标签
   `D3-BRIDGE-P-v2` / `D3-LAYOUT-v1` 的编码（8 字节前缀）。
6. **policy_id 冻结规范**：`policy_parameters` 文本、`circuit_spec_digest` 取值、git sha、
   DirectOnly/Cascade 两把 vk 与注册表条目。
7. **测试口径**：沿用 D2-A-R1——区分 MockProver 拒绝 / prover 出 proof 但 verifier 拒绝 /
   外部验证器拒绝 / 电路接受但网关拒绝；R07/R08/R09 必须如实记录"电路层接受/可能接受"。

---

## 11. 哪些设计仍然不能声称已经安全？

- 不能声称电路验证了 SHA-256 Anchor（第一版只验 Poseidon 开承诺，SHA-256 在 Bridge 链下）。
- 不能声称消除了状态来源信任（Bridge 签名者、布局服务、vk 注册表都是新增外部信任）。
- 不能声称电路保证 canonical assignment（R07/R08 电路层接受）、不能防跨 vk 重放（R09）。
- 不能声称 D3 与 D2-A 策略在电路内统一（域标签不一致）。
- 不能声称证明覆盖完整历史或执行时新鲜性（历史完整性归日志，freshness 归 fencing）。
- 不能声称 π_trans 是完整授权决策证明：它不单独证明 ALLOW（需 D2-A）、不证明 DENY（非存在性）。
- 不能把 O(10⁴)/5×10⁴ 约束估计当实测；不能声称递归/局部 canonicality 已在本栈可用。

---

## 12. Git 状态

- 本轮只新增 6 文件：`docs/d3_02_r1_{anchor_bridge,canonical_slots,policy_binding,
  integrated_statement,related_work}.md` + `results/d3_02_r1_design_summary.md`。
- 不修改 D3-01-R1 / D2-A / D2-B 实现、原有 fixed vectors、历史 results。
- 提交后 `git diff --check` 与 `git status --short` 应干净；本地 HEAD 与远端 branch ref SHA 一致。

---

## 本轮最重要的决策

**进入最小 Halo2 原型，但把它定位为"在三条外部签名锚点之间证明事件语义正确"的电路，而不是
"自证状态真实/规范/策略正确"的电路。** 三项修订把上一轮最大的三个接口漏洞（SHA-256↔Poseidon
语义冲突、槽位规范性无主、policy_id 与电路规则可分离）逐一变成"有明确责任方 + 有签名可审计 +
有分层测试"的接口。这是对 D3-01 参考实现真正增加的工程价值；密码学保证本身没有夸大，
也没有缩水。
