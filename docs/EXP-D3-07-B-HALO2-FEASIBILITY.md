# EXP-D3-07-B-HALO2-FEASIBILITY-01 — 多 Witness 授权状态证明的 Halo2 电路化可行性评估

> 设计评估产物，**不实现新电路、不修改 public instance、不改任何冻结成果**。
> 基线：分支 `exp-d3-07-b-closure-01` @ `b26c90b11f589f3f5292c635d96d68acce714c29`。
> 工作分支：`exp-d3-07-b-halo2-feasibility-01`。唯一新增文件：`docs/EXP-D3-07-B-HALO2-FEASIBILITY.md`。
>
> **本轮成功标准**：不是论证"什么都能放进 Halo2"，而是得到一个经得起检查的答案——究竟应该证明什么、为什么值得（或不值得）证明。核心判据：能否让验证者在**不获得完整授权历史**的前提下，验证某个多 Witness 授权状态及其转换满足定义的安全规则，且成本合理。

## 证据标签（全文统一）

| 标签 | 含义 |
| --- | --- |
| `SOURCE_VERIFIED` | 直接从冻结源码/文档核对得到 |
| `RULE_DERIVED` | 从已冻结的规则/论证推导，非实测 |
| `THEORETICAL_ESTIMATE` | 理论/结构性估计，依据明确但未经实测 |
| `NOT_MEASURED` | 本轮或现有成果无真实测量数据 |
| `OPEN_QUESTION` | 尚未定义或依赖外部决断 |

---

## 1. 研究目标与问题定义

D3-07-B 已收束：P1 给出确定性模拟证据，P2 给出 Model B 协议设计，P2-SA 给出 S-A 的规则层数学论证。本阶段转入**独立的 Halo2 电路化可行性研究**，回答单一核心问题：

> 如何将多 Witness 授权状态确认与合法状态转换，转化为一个具有明确密码学语义、可由 Halo2 证明的语句？

需要判定五件事：哪些关系进电路、哪些必须链下、proof 绑定哪些状态/证据、如何与 D3-06-C/D3-07-A 衔接、最小可行证明语句及其边界与成本。

**必须避免的陷阱**（用户明确判据）：不能把 D3-07-B 的协议摘要"再哈希一次"就称为新 ZK 贡献。真正有价值的问题是——验证者能否在不拿完整授权历史的情况下，验证某多 Witness 授权状态及转换满足定义的安全规则。本评估以此判据贯穿 §5、§8、§10。

---

## 2. 冻结成果与现有电路能力

### 2.1 六个冻结成果（Phase 0 已核对可达）

| 成果 | 分支 | commit | 可达性 |
| --- | --- | --- | --- |
| D3-06-C 双事件状态链 | `exp-d3-06-c-two-event-ir-transition` | `25b581c` | `SOURCE_VERIFIED` |
| D3-07-A anchor/freshness | `exp-d3-07-a-r1-config-hardening` | `89caad7` | `SOURCE_VERIFIED` |
| D3-07-B P1 | `exp-d3-07-b-p1-r1-c1` | `2b84300` | `SOURCE_VERIFIED` |
| D3-07-B P2-SA | `exp-d3-07-b-p2-sa-r1-c1` | `67c646b` | `SOURCE_VERIFIED` |
| D3-07-B 正式安全论证 | `exp-d3-07-b-p2-security-argument-r1` | `643a10d` | `SOURCE_VERIFIED` |
| D3-07-B 收束 | `exp-d3-07-b-closure-01` | `b26c90b` | `SOURCE_VERIFIED` |

布局说明：审计目录副本（`origin` = 指定仓库）持有 D3-07-B 全链，HEAD=`b26c90b`；主仓库副本持有 D3-06-C/D3-07-A 源码与提交，HEAD=`89caad7`。单个副本不覆盖全部六个提交，跨两副本合并后六个全部可达。`source_verified`。

### 2.2 D3-06-C 现有能力（`SOURCE_VERIFIED`，来自 `25b581c`）

- **证明语句**：给定可信、跨结构一致的 S0，两事件按顺序在单一链 `S0 → S1 → S2` 上执行；两个事件均为 active（`event_count=2`），Event 0 的 GR/RR/IR 输出根 cell **直接**作为 Event 1 的输入根 cell，Event 1 不能自带新的中间根 witness。
- **8 个 public instance**（顺序冻结，见 §3）。
- **密码学原语**：Poseidon `P128Pow5T3`、`Pow5Config<F,3,2>`（rate=2）用于 state/root/index/batch hash；256-bit canonical field 分解把 `slot=low_4(id)` 与每个 Merkle 方向位绑定；Merkle `DEPTH=4`。
- **K_C=16**（`max_rows=65536`）；`MAX_EVENTS=2`；gate families source=22。
- **明确不证**：外部 S0 锚定、SHA-256 key mapping、revoker 权限、256-bit ID 映射、执行时 freshness、DENY、RG、递归。**无形式化 soundness 证明、无普遍性能优势声明。**

### 2.3 D3-07-A 现有能力（`SOURCE_VERIFIED`，来自 `89caad7`）

- **外部 anchor**：D1 风格 checkpoint envelope（`AnchorCheckpoint` + `QuorumCertificate` + `witness_set_id`），`state_root` 携带 64-hex `C_prev`，`policy_version` 携带 policy/version，`epoch` 映射 sequence，`timestamp` 映射签发时间策略。
- **执行顺序**（`combined.rs`）：`verify_anchor` → `bind_to_instances` → `verify_transition_proof`（Halo2）→ `store.commit`。proof 失败不推进本地状态。
- **Ed25519 验签在 host 侧**（`verifier.rs`）：`validate_witness_set_config` 最先执行（强制 4/3 profile、`NO_LOG`、`log_size=0`），再校验 digest/epoch/chain_id/set_id/witness_set_root、逐份 Ed25519 签名去重计数、freshness、本地 anti-rollback（highest_sequence/highest_digest）。
- **边界**：证明的是"从外部锚定且相对本地未回滚的 S0 出发执行两事件"；**不证明 S0 是全局最新状态**。

### 2.4 D3-07-B 新增的协议层性质（`RULE_DERIVED` / `SOURCE_VERIFIED`）

- 七状态、四层纪律（收到≠接受≠PoLC≠QC≠commit）、严格锁转移 `locked_round < polc_round < current_round`、签名请求不隐式抬轮。
- S-A：`PROOF_SUPPORTED` / `ACCEPTED_WITH_EXPLICIT_MODEL_ASSUMPTIONS`；旧鸽巢论证无效；锚点相对最小冲突 PoLC 归纳。
- G1（PoLC 验证清单的 `lock_key` 绑定检查未显式）、G2（持久化原语 `durable_write`/`atomic_write_two` 是外部前提）、G3（`locked_round` 单调性可推导但未机器验证）。
- P8-B 活性反例：锁定节点无合格解锁 quorum 时网络愈合也不能恢复；QC/PoLC 均不证明 globally latest。

---

## 3. 现有 public instance 与接口分析

8 个 public instance 顺序与语义（`SOURCE_VERIFIED`，`d3_06_c_circuit.rs` 第 1771–1778 行 `constrain_instance`）：

| # | instance | 语义 | D3-07-A 绑定来源 |
| --- | --- | --- | --- |
| 0 | `C_prev` | S0 状态摘要 `D3-STATE-v2`（6 words） | anchor `state_root`（64-hex field bytes） |
| 1 | `prev_epoch` | 起始 epoch | anchor `sequence`（D1 epoch） |
| 2 | `C_next` | S2 状态摘要 | 链末根，输出状态 |
| 3 | `next_epoch` | 结束 epoch | D3-06-C 内部 `prev+1` 约束 |
| 4 | `policy_id` | 策略字段 | anchor `policy_version` 中的 policy_hex |
| 5 | `transition_version` | 转换版本 | anchor `policy_version` 中的 version |
| 6 | `D_E` | `H(D3-BATCH-v1, 2, C0, C1, pad)` 事件承诺 | D3-06-C 内部计算 |
| 7 | `event_count` | 恒为 2 | anchor 绑定检查要求 ==2 |

**硬约束**：不得新增第 9 个 instance、不得改序、不得改语义（`SOURCE_VERIFIED` + 任务包冻结要求）。任何方案若需要把新的 Witness 证据承诺暴露为 public input，只能通过**复用现有 instance 的语义载体**或**链下验证后作为电路外前置条件**，不能擅自扩展 instance 集合。这是方案 B/C 的关键设计约束（`RULE_DERIVED`）。

---

## 4. A/B/C 三种候选架构

### 4.1 方案 A：只证明授权状态转换

- **电路负责**：checkpoint 字段与状态摘要绑定、前后状态摘要一致性、授权状态转换合法性、事件顺序与状态链约束。
- **链下负责**：Witness 签名验证、PoLC/QC 验证、Witness set 配置验证、持久化锁与轮次管理、Gateway freshness 与 anti-rollback。
- **分析**：这正是 D3-06-C + D3-07-A 已实现的内容（`SOURCE_VERIFIED`）。**它只是复用已有证明，不构成新贡献**——因为它没有把任何 D3-07-B 的新协议性质引入电路。若仅作为基线描述，价值=0 的增量；若作为"是否值得做"的对照，它证明的是：现有电路已覆盖状态转换，多 Witness 协议层完全在链下。(`RULE_DERIVED`)
- **判定**：作为推荐方案的"状态转换内核"是必要组成；作为独立的新研究目标**不成立**（重复 D3-06-C）。

### 4.2 方案 B：状态转换 + 多 Witness 证据摘要绑定（推荐候选）

- **电路负责**：方案 A 全部约束 + Witness 证据摘要与 checkpoint/lock_key 的绑定 + 证据摘要与被证明状态的一致性 + 必要的轮次/状态标识与转换关系。
- **链下负责**：Ed25519 签名验证、Witness 身份与唯一性检查、PoLC/QC 的 quorum 形成验证、持久化状态与网络观察、freshness。
- **核心难题**（用户指定的必答点）：链下已验证的多 Witness 证据，如何被电路语句**可靠绑定**，而不只是一个未约束的 public 摘要？
  - 证据来源是链下 verifier 的输出（一个"已验证 QC 覆盖 checkpoint C"的判定 + Q 份签名的规范编码）。
  - **承诺方式**：链下按 canonical encoding 把 `(lock_key, C_prev, C_next, round, signer_set_digest)` 序列化后取哈希 `H_evidence`，把 `H_evidence` 作为电路内的 private witness（或经现有 instance 的语义载体间接绑定）。
  - **绑定对象**：电路内约束"该 `H_evidence` 对应的 checkpoint 字段 = 被证明状态摘要的前后根 + lock_key 相关字段"，从而把"链下认定的 QC 对象"与"电路证明的状态转换对象"锁死为同一个。
  - **验证责任**：电路**不验证 Ed25519 签名本身**，只验证"链下声称已验签的这批证据确实指向本次状态转换的 checkpoint"；签名的真实性仍由链下 verifier 承担（见 §7 责任表）。这是**证据绑定**，不是**证据验签**。(`RULE_DERIVED`)
  - **诚实边界**：若链下 verifier 作恶或出错，电路无法察觉——它只是把链下判定与状态转换绑定，不重新执行判定。因此方案 B 增加的可验证性质是"**转换的对象与链下认证的对象一致**"，而非"多 Witness 协议安全"。(`RULE_DERIVED`)
- **增量价值**：中等。它把"证据-状态一致性"变成可证明关系，减少了对"Gateway 正确地把同一 checkpoint 喂给电路和链下验证器"这一实现细节的信任，但**不验证 quorum 安全性**。（`THEORETICAL_ESTIMATE`）

### 4.3 方案 C：将 PoLC/QC 验证本身纳入电路

- **研究项**：Ed25519 验签电路成本、Witness ID 去重、3-of-4 quorum 约束、同轮/同 digest/同 lock_key 一致性、PREVOTE/PRECOMMIT 关系、锁转移条件。
- **成本分析**：
  - Ed25519 验签在 Halo2/Pallas 上需要把 Ed25519（ Edwards25519，base field ≠ Pallas scalar field）的域运算模拟到 Pallas field，属于**非原生曲线**验签，开销极大（通常每次数百万级约束/大量 range check）。本仓库无现成 Ed25519 电路组件，**无实测数据**（`NOT_MEASURED`）；仅能给出"显著高于现有 Poseidon 电路"的定性判断（`THEORETICAL_ESTIMATE`）。
  - 3-of-4 quorum 约束本身逻辑简单（4 个 signer 标志求和 + 门限比较 + 唯一性），约束开销相对验签可忽略（`THEORETICAL_ESTIMATE`）。
  - 锁转移 `locked_round < polc_round < current_round` 是三个 field 的比较，D3-06-C 已有 canonical 比较原语可复用（`RULE_DERIVED`）。
- **判定**：
  - **成本是否可接受**：以 Ed25519 非原生验签为主的方案 C，成本量级远超现有 D3-06-C（K=16, 7072B prove ≈35s），且无现成组件，工程风险高（`THEORETICAL_ESTIMATE` + `NOT_MEASURED`）。
  - **是否重复验证**：若链下已验签，电路再验一遍是**重复**，除非目标是让验证者完全不信任链下 verifier。
  - **是否提升可独立检查的性质**：理论上是的——验证者可独立确认 quorum 有效性，而不信任链下 verifier。但代价是把整个 BFT 投票验证塞进电路，与用户"不把整个 BFT 协议硬塞进电路"的要求冲突。
  - **结论**：**理论可实现 ≠ 值得实现**。在没有"验证者不能信任链下 verifier"这一明确需求前，不推荐方案 C。（`RULE_DERIVED`）

### 4.4 三方案对照小结

| 维度 | A 状态转换 | B 证据摘要绑定 | C 验签入电路 |
| --- | --- | --- | --- |
| 是否新增可验证性质 | 无（重复 D3-06-C） | 证据-状态对象一致性 | quorum 有效性可独立检查 |
| 链的信任边界 | 全信任链下协议 | 部分降低（对象一致性可证） | 几乎不信任链下 verifier |
| 电路增量成本 | 0 | 小（一个 evidence 摘要哈希+绑定） | 很大（Ed25519 非原生验签） |
| 实测数据 | 有（D3-06-C） | `NOT_MEASURED` | `NOT_MEASURED` |
| 与"不硬塞 BFT"要求 | 符合 | 符合 | 冲突 |
| 推荐度 | 作为内核必要 | **推荐进一步设计** | 不推荐（当前需求下） |

---

## 5. 最小可行证明语句（推荐：方案 B 的精简版）

回答用户核心问题："给定一个外部锚定的 checkpoint 和一组多 Witness 授权状态证据，证明者能证明什么，而不需要公开完整授权历史？"

**推荐语句（MIN-PROOF-B）**：

> 给定公开的前后状态摘要 `C_prev`/`C_next`、epoch/版本与事件承诺，证明者知道一份合法的两事件转换见证（GR/RR/IR 的 opening 与状态字），以及一份经链下验证的多 Witness 证据的**规范哈希** `H_evidence`。证明：
> (i) `C_prev → C_next` 是 D3-06-C 定义的两事件合法转换（复用现有电路）；
> (ii) `H_evidence` 的规范预像所绑定的 `(lock_key, checkpoint_digest, C_prev, C_next)` 与本次被证明的状态转换对象逐字段一致。
>
> 验证者无需看到任何 Witness 投票、签名、完整授权历史或 Merkle 全树，只需 8 个 public instance + 证明即可确认上述两点。

关键限定（`RULE_DERIVED`）：
- (ii) 只证明**对象一致性**，不证明 `H_evidence` 背后的签名有效或 quorum 成立——那是链下前提。
- 不把整个 Witness 状态机搬进电路；不改 8 个 instance；`H_evidence` 作为 private witness，其"已被链下验证"是外部信任假设。
- 这**不是**"多 Witness 协议安全"的证明，而是"状态转换与其链下认证对象一致"的证明——增量明确、边界诚实。

---

## 6. Public inputs / Private witness / Constraints

### 6.1 Public inputs（冻结 8 个，不新增）

沿用 §3 表格：`C_prev, prev_epoch, C_next, next_epoch, policy_id, transition_version, D_E, event_count=2`（`SOURCE_VERIFIED`）。MIN-PROOF-B **不引入第 9 个 instance**。若需要让验证者核对 `H_evidence`，可选方案是把它并入 `D_E` 的语义（用 evidence 哈希参与 batch 承诺）或保持为链下前置——这是 `OPEN_QUESTION`，需后续决断，且必须评估是否改变现有 instance 语义（倾向不改变）。

### 6.2 Private witness

- D3-06-C 现有见证：S0 的 GR/RR/IR opening、两事件的 grant/revoke 字段、IR slot/direction 位、状态字 mux 输入、epoch/policy 中间值（`SOURCE_VERIFIED`）。
- 新增（MIN-PROOF-B）：`H_evidence`（链下证据规范哈希）及其规范预像字段 `(lock_key, checkpoint_digest, C_prev, C_next, round, signer_set_digest)`，用于电路内重算哈希并做字段一致性约束（`RULE_DERIVED`）。

### 6.3 Constraints

- **复用**：D3-06-C 全部约束（双事件根链、canonical 256-bit 分解、IR leaf 重算、state mux、slot=low_4(id)、batch 承诺、8 instance 绑定）（`SOURCE_VERIFIED`）。
- **新增**：evidence 规范哈希约束 `H_evidence = H_canonical(lock_key, digest, C_prev, C_next, round, signer_set_digest)`（Poseidon，复用现有 gadget）+ 字段相等约束把预像中的 `C_prev/C_next/lock_key` 与状态转换对应 cell constrain_equal（`RULE_DERIVED`）。
- **不引入**：Ed25519 验签约束、quorum 求和约束、锁转移不等式约束（这些留在链下，见 §7）。

---

## 7. 链上链下责任划分

| 性质 | 电路（链上） | 链下 verifier | 电路无法确认 / 仍须信任 |
| --- | --- | --- | --- |
| 两事件状态转换合法性 | ✓ 主证明 | — | 可信 S0 的来源 |
| 前后状态摘要一致性 | ✓ | — | — |
| 事件顺序/根链 | ✓ | — | — |
| checkpoint 字段↔状态摘要绑定 | ✓ | — | — |
| 证据-状态对象一致性（MIN-PROOF-B） | ✓ 仅哈希绑定 | 生成规范证据哈希 | 链下哈希由诚实 verifier 产生 |
| Ed25519 签名有效性 | ✗ | ✓ | 验证者须信任链下验签 |
| Witness 身份/唯一性 | ✗ | ✓ | 须信任配置与去重 |
| PoLC/QC quorum 形成 | ✗ | ✓ | 须信任 quorum 判定 |
| 严格锁转移/轮次纪律 | ✗ | ✓（P1/P2 规则层） | 须信任状态机实现 |
| 外部 anchor 真实性 | ✗ | ✓（D3-07-A） | 须信任外部 checkpoint 源 |
| 执行时 freshness / globally latest | ✗ | 部分（D3-07-A 时间策略） | **电路与链下都不能独立证明全局最新** |
| crash-safe 持久化 | ✗ | 部分（外部原语假设） | **G2 是外部前提，未被任何层验证** |

**结论**：即使采用 MIN-PROOF-B，验证者仍需信任链下完成签名/quorum/freshness/持久化判定。电路增加的是**状态转换与其认证对象的一致性**，不是"BFT 安全"或"全局最新"。把这些性质合并成笼统的"ZK 安全"是错误表述（`RULE_DERIVED`）。

---

## 8. 成本与性能评估

### 8.1 现有实测（`SOURCE_VERIFIED`，来自 `25b581c`/`89caad7` 成本文档）

| 项 | 数值 | 来源 |
| --- | --- | --- |
| D3-06-C K | 16（max_rows=65536） | `EXP-D3-06-C-COST-COMPARISON.md` |
| D3-06-C proof size | 7072 B | 同上 |
| D3-06-C prove | ≈35.7–43.8 s（GG/GR/RR，run-to-run 波动） | 同上 |
| D3-06-C verify | ≈518–529 ms | 同上 |
| D3-06-C Poseidon 调用 | 93 次/two-event proof | 同上 |
| E-R1 对照（K=15） | 8160 B, prove ≈20.5–20.7 s, verify ≈276–281 ms | 同上 |
| anchor verify（host） | 0.55 ms/call | `EXP-D3-07-A-COST-COMPARISON.md` |
| local state read/write | 0.17 / 4.88 ms/call | 同上 |
| Halo2 proof verify（D3-07-A 同轮） | 838.41 ms | 同上 |
| combined verification | 848.28 ms | 同上 |

注：D3-06-C verify 在两份文档中数值不同（518–529 ms vs 838 ms），原因是不同测试轮次/机器状态；两者均为真实观测，不做统一排名（`SOURCE_VERIFIED`）。C 的 prove 慢于 E-R1，**不宣称性能优势**。

### 8.2 新增成本估计

| 项 | MIN-PROOF-B 增量 | 证据标签 |
| --- | --- | --- |
| evidence 规范哈希（1 次 Poseidon，6 words） | 约等于现有单次 state hash 量级；相对 93 次调用是小增量 | `THEORETICAL_ESTIMATE` |
| 字段一致性约束（若干 constrain_equal） | 约束开销极小 | `THEORETICAL_ESTIMATE` |
| K 是否仍为 16 | 大概率不变（增量小），但需实测确认 | `OPEN_QUESTION` |
| 新增 proving/verify 时间 | 相对 ≈35 s prove / ≈0.5–0.8 s verify 预计小幅上升 | `THEORETICAL_ESTIMATE`，`NOT_MEASURED` |
| 方案 C Ed25519 验签成本 | 非原生曲线，量级远超现有电路，无组件、无实测 | `NOT_MEASURED` |
| 参数规模/内存压力 | 随 K 固定则不变；K 若升则线性影响 | `OPEN_QUESTION` |

**禁止事项遵守**：以上带 `THEORETICAL_ESTIMATE`/`NOT_MEASURED` 的数字均为定性或明确标注，不编造具体毫秒/字节；不同方案缺少可比较实现条件，不给虚假精确排名。MIN-PROOF-B 与方案 C 之间无同条件实现，故不做精确性能排序（`RULE_DERIVED`）。

---

## 9. 安全假设与不能证明的性质

**依赖的假设**（`RULE_DERIVED`）：
- 外部锚定的 checkpoint（D3-07-A）可信且相对本地未回滚；哈希抗碰撞（Poseidon 在电路内、SHA-256 在 anchor 链下）。
- 链下 verifier 诚实产生 `H_evidence`（方案 B 的核心外部信任）。
- D3-06-C 的 S0 跨结构一致、revoker 权限、ID 映射等既有假设不变。

**电路与本协议都不能证明**（`RULE_DERIVED` / `SOURCE_VERIFIED`）：
- 全局最新授权状态（globally latest）——D3-07-A 明确不证，P2 的 QC/PoLC 也不证。
- Witness quorum 安全性 / BFT soundness——S-A 是规则层人工推导，非形式化、非电路证明。
- crash-safe 持久化（G2）——外部原语前提，未被任何层验证。
- 执行时 freshness、DENY 不可证性、递归、RG——D3-06-C 既有边界。
- 完整 Witness 状态机在电路内正确执行——本方案刻意留在链下。

---

## 10. 研究价值与创新空间判断

逐一回答用户七个必答问题：

1. **D3-06-C 已证明什么**：可信 S0 上两事件顺序合法状态转换（`S0→S1→S2`），8 instance 绑定，双事件根链（`SOURCE_VERIFIED`）。
2. **D3-07-A 已补充什么**：把 `C_prev` 用外部 checkpoint/QC（host 侧 Ed25519 验签 + 时间策略 + 本地 anti-rollback）锚定，并与同一 8 instance 绑定；不证全局最新（`SOURCE_VERIFIED`）。
3. **D3-07-B 增加了什么协议层性质**：多 Witness 轮次锁定/恢复规则、PoLC/QC/quorum 的严格纪律、冲突 QC 不可共存的规则层安全论证、崩溃与 freshness 边界（`SOURCE_VERIFIED`/`RULE_DERIVED`）。
4. **下一阶段 Halo2 证明增加什么新可验证性质**：若采用 MIN-PROOF-B，新增的是"状态转换对象与链下认证对象一致"的可证明绑定；**不是** quorum 安全或全局最新（`RULE_DERIVED`）。
5. **只把链下验证结果哈希进电路是否带来新密码学保证**：带来的是**一致性保证**（对象绑定），不是**正确性保证**（签名/quorum 已由链下判定）。若连一致性都不需要（即信任 Gateway 喂给两边的是同一 checkpoint），则增量≈0，不值得做（`RULE_DERIVED`）。这是决定"值不值得"的关键分水岭。
6. **不把 Ed25519 验签纳入电路，验证者信任谁**：信任链下 verifier 的签名验证、Witness set 配置、quorum 判定、freshness 与持久化；电路只把这些判定的**对象**与状态转换绑定（`RULE_DERIVED`）。
7. **是否存在更小、更清晰、更有价值的问题**：**有**——MIN-PROOF-B（证据-状态对象一致性绑定）比"完整证明多 Witness 协议"更小、更清晰，且不把 BFT 塞进电路。它的价值取决于是否能说清"验证者确实需要独立确认对象一致性"这一需求（`RULE_DERIVED`/`OPEN_QUESTION`）。

**区分六类性质，不合并为笼统"ZK 安全"**：电路约束正确性（电路内）、链下签名验证正确性（链下）、Witness quorum 安全性（规则层人工论证）、外部 checkpoint 真实性（外部信任）、全局 freshness（外部，未解决）、真实执行与持久化安全（G2 外部前提）——各自证据等级不同，见 §7/§9（`RULE_DERIVED`）。

**创新空间诚实判断**：MIN-PROOF-B 的新意仅在"证据对象绑定"，属于组合式工程绑定，不是新原语、新证明语句或新可证性质；按用户既定的研究价值门槛（非组合式新原语/新证明语句 + 可证性质 + 最小实验），它**不太可能单独构成论文级贡献**（`RULE_DERIVED`）。方案 C 虽可独立检查 quorum，但成本与"硬塞 BFT"问题使其不优（`THEORETICAL_ESTIMATE`）。

---

## 11. 推荐方案与不推荐方案

- **推荐**：MIN-PROOF-B（方案 B 精简版），**但仅为"有条件推荐"**——前提是能明确"验证者需要独立确认认证对象与状态转换对象一致"这一真实需求。它复用 D3-06-C、不新增 instance、增量成本小、不把 BFT 塞进电路。若进入实现，先做 MockProver 层的一致性约束验证，再做小规模实测（`RULE_DERIVED`）。
- **不推荐 - 方案 A 作为独立目标**：重复 D3-06-C，零增量（`SOURCE_VERIFIED`）。
- **不推荐 - 方案 C 在当前需求下**：Ed25519 非原生验签成本高、无组件、无实测，且与"不硬塞 BFT"冲突；除非出现"验证者完全不能信任链下 verifier"的硬性需求，否则不投入（`THEORETICAL_ESTIMATE`/`NOT_MEASURED`）。
- **不推荐 - 纯"再哈希协议摘要"**：无新可验证性质，不构成 ZK 贡献（`RULE_DERIVED`）。

---

## 12. 后续是否进入电路实现的明确决策

**本轮决策：`CONDITIONAL_HOLD`——不立即进入电路实现。**

理由与门禁条件：
- 现有 D3-06-C + D3-07-A 已覆盖状态转换与外部锚定；D3-07-B 的核心贡献是协议层规则与安全论证，其天然归链下。
- MIN-PROOF-B 是唯一有增量且成本可控的候选，但其价值取决于一个尚未确认的需求（对象一致性是否值得独立证明）。在需求未确认前投入实现，风险是"做完发现无新意"（`RULE_DERIVED`）。
- 进入实现前必须确认（均为 `OPEN_QUESTION`）：
  1. 是否存在真实验证者需要独立检查"证据-状态对象一致性"，而非信任 Gateway？
  2. `H_evidence` 的暴露方式（并入 `D_E` 语义 vs 链下前置）是否改变现有 8 instance 语义？倾向不改变。
  3. MIN-PROOF-B 的 K 是否仍为 16、prove/verify 增量实测数据。
  4. 该工作是否达到用户既定研究价值门槛（非组合式贡献 + 可证性质 + 最小实验）。
- 若上述 1 与 4 得到肯定回答，则进入 MIN-PROOF-B 的 MockProver 原型；若否定，则 D3-07-B 的 Halo2 电路化研究到此为止，结论为"协议性质归链下、不新增电路"。

**最终诚实结论**：就当前证据与研究价值判据，最扎实的可验证增量是 MIN-PROOF-B 的对象一致性绑定；它值得进一步设计，但**尚不足以无条件启动电路实现**。本轮不修改任何电路、instance 或冻结成果，等待对上述门禁条件的人工决断。
