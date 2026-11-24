# EXP-D3-07-B-HALO2-FEASIBILITY-01 — 多 Witness 授权状态证明的 Halo2 电路化可行性评估

> 设计评估产物，**不实现新电路、不修改 public instance、不改任何冻结成果**。
> 初始基线：分支 `exp-d3-07-b-closure-01` @ `b26c90b11f589f3f5292c635d96d68acce714c29`。
> 初始工作分支：`exp-d3-07-b-halo2-feasibility-01`。唯一文件：`docs/EXP-D3-07-B-HALO2-FEASIBILITY.md`。
>
> **本轮成功标准**：不是论证"什么都能放进 Halo2"，而是得到一个经得起检查的答案——究竟应该证明什么、为什么值得（或不值得）证明。核心判据：能否让验证者在**不获得完整授权历史**的前提下，验证某个多 Witness 授权状态及其转换满足定义的安全规则，且成本合理。
>
> **修订记录 — D3-07-B-BINDING-CLARIFICATION-01**（工作分支 `exp-d3-07-b-binding-clarification-01`，基线 `13ed1ae37ded16489af3659dfc4c6abb4cd0b76f`）：本轮仅做文档级证明语句审查与修订，回答单一问题——**外部已验证的多 Witness 证据如何真正绑定到 Halo2 证明描述的状态转换**。保留 §2/§4 A–C 评估与 §8 成本数据原样；新增 §5.1 公开语句缺口与反例、§5.2 四种绑定架构 A/B/C/D、§5.3 原 MIN-PROOF-B 语句的越界表述、§6 两个可成立的证明语句与信任边界；重写 §10 价值判断与 §12 最终决策为 `STOP_HALO2_DIRECTION`。未改任何电路/instance/冻结成果。

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

> **§4 修订注记（BINDING-CLARIFICATION-01）**：上表与 §4.2 对方案 B 的"推荐进一步设计"是初始评估，其默认前提是把 `H_evidence` 作为 private witness 即可完成绑定。**本轮 §5.1 证明该前提不成立**：private-only 哈希绑定在密码学上无法让验证者确认外部证据来源，存在明确的证明者伪证构造。上表"证据-状态对象一致性"一列应改读为"仅在公开语句包含 evidence commitment 或采用 verifier-level 组合验证时才可能成立"。§4 的 A/B/C 结构性分析与 §8 成本数据保持不变，最终决策以 §12 为准。

---

## 5. 外部证据绑定缺口与证明语句修订（BINDING-CLARIFICATION-01）

本节回答本轮唯一问题。先精确定义当前 MIN-PROOF-B 的绑定缺口（§5.1），再比较四种绑定架构（§5.2），再列出原语句中超出证明关系的表述（§5.3）。可成立的两个证明语句见 §6。

### 5.1 当前 MIN-PROOF-B 的公开语句缺口（`RULE_DERIVED`）

**基础原则**：Halo2（及任意 zk-SNARK）证明的是公开语句 \(x\) 与私有见证 \(w\) 的关系 \(R(x,w)\)——验证者的输入只有 \(x\) 与 proof。凡未被纳入 \(x\)、也没有可验证外部锚点的值，对验证者而言就是证明者单方面提供的数据，**不能**被称为"已认证的外部证据"。

当前 MIN-PROOF-B 的结构（原 §5/§6.2）：

- \(H_{evidence}\) 是 private witness；
- 规范预像 \((lock\_key, checkpoint\_digest, C_{prev}, C_{next}, round, signer\_set\_digest)\) 也是 private witness；
- 电路重算 \(H_{evidence} = H_{canonical}(预像)\)；
- 电路把预像中的 `C_prev/C_next/lock_key` 字段与状态转换 cell `constrain_equal`；
- **现有 8 个 public instances 不含独立的 \(H_{evidence}\)（也不含 `checkpoint_digest`/`signer_set_digest`/`round`）**。

逐项回答本轮四问：

1. **证明者能否自行选择一组预像字段并计算对应哈希？能。** 电路只证明"所给哈希等于所给预像的哈希"这一内部自洽关系；预像与哈希都在 \(w\) 中，证明者可任意选取后重算，约束恒成立。
2. **验证者能否仅凭 8 个 public instances + proof 确认该哈希来自链下已验证证据？不能。** 验证者的 \(x\) 里根本没有 \(H_{evidence}\) 的锚点，无法把 \(w\) 中那个哈希与链下 verifier 的输出做任何比对。
3. **当前 MIN-PROOF-B 实际证明什么？** 只证明两件事的合取：(i) 8 instance 描述的 `C_prev→C_next` 是合法两事件转换（= D3-06-C 已有能力）；(ii) 证明者掌握某个预像，其 `C_prev/C_next/lock_key` 字段与公开 instance 相等、且其哈希被正确计算。(ii) 中真正代表"外部证据"的 `checkpoint_digest`/`signer_set_digest`/`round` 没有 public 锚点，因此 (ii) 对验证者的可确认增量≈0（详见反例）。
4. **原文档哪些表述超界？** 见 §5.3。

**明确反例 / 攻击者构造（`RULE_DERIVED`）**：

设链下 verifier 已对 checkpoint \(C\) 验证出一组合法 QC，其规范证据对象为 \(E\)，真实哈希 \(H_{honest}=H_{canonical}(E)\)，其中 \(E.signer\_set\_digest\) 编码 3 个真实签名者、\(E.checkpoint\_digest=H(C)\)。

恶意证明者 \(P\)（或恶意 Gateway）**手上没有任何有效 QC**（例如根本不存在对 \(C\) 的 3 份 PRECOMMIT）。\(P\) 这样做：

1. 取公开 \(x\) 中的 `C_prev/C_next/policy_id/epoch/version`（这些本就公开）；
2. 自造 `checkpoint_digest' = H(C')`，其中 \(C'\ne C\) 可任意选；
3. 自造 `signer_set_digest' = H(任意 3 个 Witness ID)`，这些 Witness 可能从未签过任何东西；
4. 自造 `round'` 与 `lock_key'` 中未被 instance 钉住的部分；
5. 令预像 \('=(lock\_key', checkpoint\_digest', C_{prev}, C_{next}, round', signer\_set\_digest')\)，计算 \(H_{evidence}'=H_{canonical}(预像')\)；
6. 以 \(H_{evidence}'\) 与预像 \('\) 作为 private witness 生成 proof \(\pi\)。

电路全部约束满足（哈希自洽 + \(C_{prev}/C_{next}/lock\_key\) 与公开 instance 相等），验证者 `verify(\pi, x)` 通过。验证者因此"确认"了一条声称绑定多 Witness 证据的证明，而其中的证据字段是证明者凭空捏造的。**这正是用户指出的原则：承诺只在 \(w\) 中，验证者无独立可信依据，就不能当作已认证的外部证据。** 该攻击不需要伪造签名、不需要凑 quorum、不需要 2 个诚实双签——纯由绑定缺口产生。注意它不改变状态转换本身的合法性（那仍由 D3-06-C 保证），它击穿的是"证据-状态对象一致性"这一 MIN-PROOF-B 的全部增量声称。

### 5.2 四种绑定架构比较

| 架构 | 电路 / 公开语句能约束什么 | 验证者能确认什么 | 能否绑定链下已验证证据 | 证明者能否自造伪证据预像 |
| --- | --- | --- | --- | --- |
| **A 私有哈希 + 私有预像**（当前 MIN-PROOF-B） | 哈希自洽；部分字段 = public instance | 仅状态转换（8 instance）；证据字段不可见 | **不能**（§5.1 反例） | **能** |
| **B 新增独立 public \(H_{evidence}\)** | \(x'=\)8 instance +\(H_{evidence}\)；哈希=预像哈希；字段一致 | 存在预像使哈希等于**公开的** \(H_{evidence}\) 且状态字段一致 | 能，条件：verifier 从可信源取得该 public 值 | 否（篡改 public 值则 proof 失效） |
| **C 纳入现有 \(D_E\)** | 改变 \(D_E\) 公式 | 取决于新语义 | 需改电路才能成立 | — |
| **D 链下认证信封 + proof 组合验证** | 电路仍只证状态转换；绑定由外部 verifier 完成 | 由外部 verifier 联合确认（信封 + instance + proof） | 能，但属 **verifier-level** 绑定 | 否（信封签名阻断） |

**A. 私有哈希与私有预像**：不得描述为"已完成外部证据认证"。它认证的只是证明者自洽，验证者侧零增量。结论 `REJECT_PRIVATE_ONLY_BINDING`。

**B. 增加独立 public commitment**：建立清晰公开语句，密码学增量真实——\(H_{evidence}\) 进入 \(x\) 后由 verifier 填入，证明者无法单方改动。**但**：违反冻结的 8 instance、需新增第 9 个 public input 与新电路接口，本轮禁止实际增加；且即便允许，其可证性质仍是"对象一致性"的组合式工程绑定，不是新原语或新的正确性性质。结论 `REVISE_PUBLIC_STATEMENT_REQUIRED`（仅作为未来选项，非本轮动作）。

**C. 将 evidence commitment 纳入现有 \(D_E\)**：\(D_E\) 当前准确语义是 `H(D3-BATCH-v1, 2, C0, C1, pad)`——**两事件批承诺**，不是证据承诺（`SOURCE_VERIFIED`，D3-06-C `d3_06_c_circuit.rs`）。纳入 evidence 会把它变成"事件批 + 证据"混合承诺，改变语义；D3-06-C 按固定公式内部计算 \(D_E\)，改公式即改冻结电路，D3-07-A 的 `bind_to_instances` 与历史兼容性同时受影响；需新版本标识与新电路。**字段数量相同 ≠ 语义可复用**：在不改变现有语义的前提下无法完成绑定。结论：本轮不可行。

**D. 链下认证信封 + Halo2 proof 组合验证（verifier-level binding）**：

1. 链下 verifier 验证 Ed25519 签名、Witness 身份唯一性、quorum、checkpoint（现有 D3-07-A host 侧能力）；
2. 对规范化证据对象生成认证信封，字段至少含 8 个状态字段（`C_prev, prev_epoch, C_next, next_epoch, policy_id, transition_version, D_E, event_count`）＋ `checkpoint_digest, round, signer_set_digest, chain_id, set_id`；
3. 信封由可信验证主体签名——签名主体是谁为 `OPEN_QUESTION`（选项：链下 verifier 自身 / D3-07-A anchor 签发者 / 专用认证服务）；
4. 外部 verifier 验证信封签名；
5. 外部 verifier 逐字段对照信封状态字段与 Halo2 proof 的 8 个 public instances；
6. 外部 verifier 验证 Halo2 proof；
7. 全部通过才接受。

- **信任主体**：信封签发者（签名真实性）、Halo2 soundness、verifier 对照逻辑实现、外部 checkpoint 源。
- **绑定字段与重放防护**：信封绑定具体 `C_prev/C_next` → 跨 proof 重放需 public instance 完全相同；绑定 `epoch/policy/transition_version` → 跨 epoch/policy 重放被字段对照阻断；anti-rollback 由外部 verifier 的 high-water 状态维护（D3-07-A 已有本地机制）。
- **关联在哪完成**：信封与 proof 的关联由**外部 verifier** 在步骤 5–6 完成，不是电路约束。
- **性质归属**：这是**组合验证 / verifier-level binding，不是 Halo2 电路新增的密码学保证**，必须如此称呼，不得写成 circuit-level guarantee。
- **与现有能力的关系**：D3-07-A 已实现 `verify_anchor → bind_to_instances → verify_transition_proof → commit`；D 的信封签名≈其 QC 签名、字段对照≈其 `bind_to_instances`、proof 验证≈其 Halo2 步骤。**增量≈0，属已有工程能力的重复包装**。

### 5.3 原 MIN-PROOF-B 语句中超出证明关系的表述（`RULE_DERIVED`）

| 原表述（位置） | 问题 | 修订 |
| --- | --- | --- |
| "`H_evidence` 的规范预像所绑定的 `(lock_key, checkpoint_digest, C_prev, C_next)` 与本次状态转换对象逐字段一致"（原 §5(ii)） | `checkpoint_digest` 无 public 锚点，该"一致"对验证者不可验证 | 删除该声称；只有 public instance 内的字段才对验证者可确认 |
| "只需 8 个 public instance + 证明即可确认上述两点"（原 §5 末） | (ii) 无法被确认（§5.1 反例） | 改为：只能确认 (i) 状态转换 |
| "把链下认定的 QC 对象与电路证明的状态转换对象锁死为同一个"（原 §4.2） | private-only 下没有东西把它锁到"链下认定" | 改为：仅在 public commitment 或 verifier-level 组合下才可能 |
| "可选把 \(H_{evidence}\) 并入 \(D_E\) 语义或保持链下前置"（原 §6.1） | 淡化了缺口；并入 \(D_E\) 会改冻结语义（§5.2-C） | 明确为需决策的阻断项，不得默认并入 |
| "证据-状态对象一致性 ✓ 仅哈希绑定"（原 §7 表） | 夸大；private-only 不构成 verifier 可验证的一致性 | 改为 ✗（电路）/ ✓（仅 verifier-level，见 §6.2） |
| "有条件推荐 MIN-PROOF-B"（原 §11） | 建立在 private-only 绑定成立的错误前提上 | 撤回，见 §10/§12 |

---

## 6. 两个可成立的证明语句与信任边界（BINDING-CLARIFICATION-01）

原 §6 的 public/private/constraints 分解按"private \(H_{evidence}\) 即可绑定"的错误前提组织；本轮改为按两个**逻辑闭合**的语句重述。D3-06-C 的见证与约束清单（`SOURCE_VERIFIED`）在两版中作为状态转换内核原样复用，见 §8。

### 6.1 版本一：纯 Halo2 证明语句（不新增 instance）

- **Public statement \(x\)**：冻结 8 个——`C_prev, prev_epoch, C_next, next_epoch, policy_id, transition_version, D_E, event_count=2`（§3，`SOURCE_VERIFIED`）。**没有** \(H_{evidence}\) 或任何证据字段。
- **Private witness \(w\)**：D3-06-C 现有见证（S0 的 GR/RR/IR opening、两事件 grant/revoke 字段、IR slot/direction 位、状态字 mux 输入、epoch/policy 中间值）；可含 \(H_{evidence}\) 及预像，但它们**不进入 \(x\)**（`SOURCE_VERIFIED` + `RULE_DERIVED`）。
- **Relation \(R(x,w)\)**：D3-06-C 两事件合法转换（双事件根链、canonical 256-bit 分解、IR leaf 重算、state mux、slot=low_4(id)、batch 承诺、8 instance 绑定）。若保留 evidence 约束，则附加 \(H_{evidence}=H_{canonical}(预像)\) 与预像状态字段 = public 字段——但这是 verifier-invisible 的冗余约束（`RULE_DERIVED`）。
- **Verifier 检查**：仅 `verify(\pi, x)`。
- **能确认**：从公开 `C_prev` 出发存在合法两事件转换得到公开 `C_next`，事件承诺为公开 `D_E`，epoch/policy/version 按 instance 约束推进。
- **不能确认**：任何多 Witness 协议性质——签名有效性、quorum 形成、checkpoint_digest、round、signer_set_digest、证据-状态对象一致性，因为这些都**不在 \(x\)**（§5.1 反例）。
- **结论**：版本一 = D3-06-C 原能力；把 \(H_{evidence}\) 放进 private witness **不改变验证者能确认的任何性质**。它是本轮唯一在不改冻结 instance 下可实现的语句，但没有新增可验证性质。

### 6.2 版本二：组合验证语句（verifier-level binding）

- **Halo2 proof 证明的关系**：与版本一相同的 \(R_{D3-06C}(x,w_H)\)，\(x\)=8 instance，\(w_H\)=状态转换见证；证据承诺不作为电路内可验证对象。
- **外部认证信封证明的关系**：\(E=\mathrm{Sig}_{VK_v}(\mathrm{canonical}(\,8\ \text{instance 字段}\ \cup\{checkpoint\_digest, round, signer\_set\_digest, chain\_id, set_id\}\,))\)。它断言"该规范化证据对象已被可信 verifier 按 D3-07-A 规则验证"。
- **Verifier 对两者的关联检查**（全部由**外部 verifier** 执行，非电路）：
  1. `verify_envelope_sig(E, VK_v)` —— 信任信封签发者；
  2. 对 8 个字段逐项 `E.field[i] == x[i]` —— 字段对照；
  3. `verify(\pi, x)` —— Halo2 soundness；
  4. 链下 anti-rollback/freshness（D3-07-A 本地 high-water 与时间策略）。
- **验证者需要信任的主体**：信封签发者（签名真实性）、Halo2 soundness 的密码学假设、外部 verifier 的字段对照实现、外部 checkpoint 来源。
- **最终接受条件**：\(1\land2\land3\land4\) 全部通过；任一失败即拒绝，且不推进本地状态（沿用 D3-07-A `combined.rs` 顺序纪律）。
- **不能确认**：globally latest（QC/PoLC 均不证明）、crash-safe 持久化（G2 外部前提）、BFT soundness（S-A 为规则层人工推导，非电路/非形式化）；**对象绑定由 verifier 完成，不是 Halo2 电路独立证明的性质**。

### 6.3 性质归属与信任边界（`RULE_DERIVED`）

| 性质 | 由谁支持 | 证据等级 |
| --- | --- | --- |
| 两事件状态转换合法性、前后摘要一致、事件承诺、epoch 推进 | Halo2 soundness（\(R_{D3-06C}\)） | `SOURCE_VERIFIED` 电路 + soundness 假设 |
| 信封确由可信主体签发（含"已验证 QC"断言） | 签名安全性（信封签发者密钥） | `OPEN_QUESTION`（签发主体未定） |
| Ed25519 验签、身份唯一性、quorum、锁转移纪律、freshness、持久化判定 | 链下 verifier（D3-07-A + P2 规则层） | `RULE_DERIVED` / 外部信任 |
| S0 真实性 | 外部 checkpoint 源 | 外部信任 |
| 对象一致性（信封 ↔ proof） | **外部 verifier 字段对照** | verifier-level，非电路保证 |
| globally latest / crash-safe / BFT soundness | 无任何层独立证明 | 明确不可确认 |

**必须不写错**：版本二中"对象绑定"由外部 verifier 完成，属于**组合验证 / verifier-level binding**；把它写成"Halo2 电路独立证明"即为错误表述（`RULE_DERIVED`）。

---

## 7. 链上链下责任划分

| 性质 | 电路（链上） | 链下 verifier | 电路无法确认 / 仍须信任 |
| --- | --- | --- | --- |
| 两事件状态转换合法性 | ✓ 主证明 | — | 可信 S0 的来源 |
| 前后状态摘要一致性 | ✓ | — | — |
| 事件顺序/根链 | ✓ | — | — |
| checkpoint 字段↔状态摘要绑定 | ✓ | — | — |
| 证据-状态对象一致性 | ✗（private-only 不可验证，§5.1） | ✓ 仅版本二 verifier-level 字段对照 | 组合验证，非电路保证；须信任信封签发者与对照实现 |
| Ed25519 签名有效性 | ✗ | ✓ | 验证者须信任链下验签 |
| Witness 身份/唯一性 | ✗ | ✓ | 须信任配置与去重 |
| PoLC/QC quorum 形成 | ✗ | ✓ | 须信任 quorum 判定 |
| 严格锁转移/轮次纪律 | ✗ | ✓（P1/P2 规则层） | 须信任状态机实现 |
| 外部 anchor 真实性 | ✗ | ✓（D3-07-A） | 须信任外部 checkpoint 源 |
| 执行时 freshness / globally latest | ✗ | 部分（D3-07-A 时间策略） | **电路与链下都不能独立证明全局最新** |
| crash-safe 持久化 | ✗ | 部分（外部原语假设） | **G2 是外部前提，未被任何层验证** |

**结论（BINDING-CLARIFICATION-01 修订）**：private-only MIN-PROOF-B 连"状态转换与其认证对象的一致性"都无法让验证者确认（§5.1 反例），该行已从电路能力中撤销。即使在版本二的 verifier-level 组合下，验证者仍需信任链下完成签名/quorum/freshness/持久化判定与信封签发；对象一致性由外部 verifier 对照完成，**不是电路保证**。把这些性质合并成笼统的"ZK 安全"或写成"Halo2 独立证明"是错误表述（`RULE_DERIVED`）。

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
- （BINDING-CLARIFICATION-01 修订）版本一无证据相关假设——private `H_evidence` 不构成可验证对象（§5.1）。版本二的额外假设是：认证信封由可信主体签发、外部 verifier 正确执行 8 字段对照、该主体按 D3-07-A 规则验证过签名/quorum；**这些都不是电路假设，也不被电路验证**。
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
4. **下一阶段 Halo2 证明增加什么新可验证性质（BINDING-CLARIFICATION-01 修订）**：版本一（纯 Halo2）新增 = **0**，因 private \(H_{evidence}\) 不对验证者产生可确认关系（§5.1）。版本二（组合）的"对象一致性"由外部 verifier 对照完成，不是 Halo2 电路新增的可证性质。**因此没有任何一种在不改冻结 instance 的方式下产生电路级新性质**（`RULE_DERIVED`）。
5. **只把链下验证结果哈希进电路是否带来新密码学保证**：private-only 下**不带来**（§5.1 反例：验证者无法区分真哈希与证明者自造哈希）。即便改为 public commitment（§5.2-B），带来的也只是"对象一致性"而非"正确性"——签名/quorum 仍由链下判定；且需新增 instance（本轮禁止）。若信任 Gateway 喂给两边的是同一对象，则增量≈0（`RULE_DERIVED`）。
6. **不把 Ed25519 验签纳入电路，验证者信任谁**：版本二下信任链下 verifier 的签名验证、Witness set 配置、quorum 判定、freshness、持久化，以及认证信封签发者与字段对照实现；电路只证状态转换，不绑定这些判定的对象到电路公开语句（`RULE_DERIVED`）。
7. **是否存在更小、更清晰、更有价值的问题**：经本轮审查，**原先寄望的 MIN-PROOF-B 并不成立**——它在不改 instance 时没有新的可证性质，要成立必须新增 public input（违反冻结）或退化为 verifier-level 组合（≈D3-07-A 重复）。在 D3-07-B 范围内**未找到**值得电路化的新证明关系（`RULE_DERIVED`）。

**区分六类性质，不合并为笼统"ZK 安全"**：电路约束正确性（电路内）、链下签名验证正确性（链下）、Witness quorum 安全性（规则层人工论证）、外部 checkpoint 真实性（外部信任）、全局 freshness（外部，未解决）、真实执行与持久化安全（G2 外部前提）——各自证据等级不同，见 §7/§9（`RULE_DERIVED`）。

**创新空间诚实判断（BINDING-CLARIFICATION-01 修订）**：MIN-PROOF-B 原本寄望的"证据对象绑定"经审查为**不成立**（private-only 无可验证增量）或**非电路性质**（verifier-level 组合）。它既不是新原语，也不是电路级新证明语句/新可证性质；按用户既定门槛（非组合式新原语/新证明语句 + 可证性质 + 最小实验），它**不构成论文级贡献，且当前形态连组合式增量都无法成立**（`RULE_DERIVED`）。方案 C 虽可独立检查 quorum，但成本（`NOT_MEASURED`）与"硬塞 BFT"冲突使其不优（`THEORETICAL_ESTIMATE`）。**结论：不为保留 Halo2 方向而强行制造一个 Halo2 问题**（见 §12）。

---

## 11. 推荐方案与不推荐方案（BINDING-CLARIFICATION-01 修订）

- **不推荐 - private-only MIN-PROOF-B（原"有条件推荐"已撤回）**：其绑定在密码学上不成立（§5.1 明确反例）；"状态转换对象与认证对象一致"不是验证者可确认的性质（`RULE_DERIVED`）。
- **不推荐 - 方案 A 作为独立目标**：重复 D3-06-C，零增量（`SOURCE_VERIFIED`）。
- **不作为本轮动作 - 方案 B 新增 public commitment（§5.2-B）**：能建立清晰公开语句，但违反冻结 8 instance、需新电路接口；本轮禁止。即便未来允许，其性质是组合式工程绑定，不构成论文级贡献（`RULE_DERIVED`）。
- **不推荐 - 方案 C 在当前需求下**：Ed25519 非原生验签成本高、无组件、无实测，且与"不硬塞 BFT"冲突；除非出现"验证者完全不能信任链下 verifier"的硬性需求，否则不投入（`THEORETICAL_ESTIMATE`/`NOT_MEASURED`）。
- **不推荐 - 纯"再哈希协议摘要"**：无新可验证性质，不构成 ZK 贡献（`RULE_DERIVED`）。
- **唯一逻辑闭合但非新增贡献的方案 D**：verifier-level 组合验证，增量≈D3-07-A 已有能力，仅作为"若必须做对象绑定"时的工程组合参考，**不构成进入电路实现的理由**（`RULE_DERIVED`）。

---

## 12. 最终决策（BINDING-CLARIFICATION-01）

**本轮最终决策（四选一）：`STOP_HALO2_DIRECTION`——结束 D3-07-B 的 Halo2 电路化支线，不进入任何电路实现。**

技术前提取向 `REJECT_PRIVATE_ONLY_BINDING`（§5.1 反例证明 private-only 绑定不成立），它是导出最终决策的依据之一，不是与最终决策并列的第二个选项。

### 12.1 从四个候选中选择

任务包给定四个选项，逐项裁定（仅第一行为最终决策）：

| 候选 | 裁定 | 依据 |
| --- | --- | --- |
| `REJECT_PRIVATE_ONLY_BINDING` | 技术裁定成立（非最终决策） | §5.1 给出明确反例：private \(H_{evidence}\) 与预像下，证明者可自造 `checkpoint_digest/signer_set_digest/round` 并重算哈希，验证者仅凭 8 instance + proof 无法区分真伪。private-only 绑定在密码学上不成立——这是导出下面最终决策的技术前提。 |
| `CONDITIONAL_HOLD_COMPOSITE_VERIFICATION` | 不采纳为推进理由 | 版本二组合验证逻辑可闭合，但增量≈D3-07-A 已有 `verify_anchor→bind→proof→commit`；它只是 verifier-level engineering binding，不构成"值得继续投入电路"的新理由。 |
| `REVISE_PUBLIC_STATEMENT_REQUIRED` | 记录为未来选项，非本轮动作 | 方案 B 新增 public \(H_{evidence}\) 确能建立公开语句，但违反冻结 8 instance、需新电路接口（本轮禁止），且其性质仍是组合式工程绑定。 |
| `STOP_HALO2_DIRECTION` | **采纳（本轮最终决策）** | 综合 §10：版本一无新增可验证性质；版本二≈已有组合；在冻结 instance 约束下未找到值得单独研究的电路级新证明关系（见 §12.2）。 |

### 12.2 决策依据（守住判断标准）

用户判据：*"不需要为了证明 Halo2 有用而强行制造一个 Halo2 问题。"* 逐条核对：

1. **纯 Halo2 方案是否有新增可验证性质？否。** 版本一 = D3-06-C；private evidence 约束对验证者不可见（§6.1/§5.1）。
2. **组合方案是否只是已有链下验证 + 现有电路的重复包装？是。** 版本二 = D3-07-A 的 anchor 验证/字段绑定/Halo2 proof 组合 + 一层 verifier 签名；无新电路级性质（§5.2-D）。
3. **是否存在值得单独研究的新证明关系？在 D3-07-B 范围内未找到。** 唯一能建立公开语句的方案 B 需改冻结 instance 且仍是组合式绑定（§5.2-B）。

三条全部命中 → 按既定标准**结束这条电路化支线**，保留 D3-06-C/D3-07-A 已有成果，不再为 MIN-PROOF-B 投入电路实现。

### 12.3 阶段结论与保留事项

- **保留成果**：D3-06-C 双事件状态链、D3-07-A anchor/freshness、P1/P2/P2-SA/收束/可行性评估（A/B/C 结构与成本数据）均有效，本轮零改。
- **不声称**：不声称证明任何多 Witness 协议性质、globally latest、crash-safe 或 BFT soundness；不声称已验证任何具体存储实现。
- **唯一 `OPEN_QUESTION`**：若未来出现"验证者完全不能信任链下 verifier"的硬性需求，方案 C（验签入电路）是一个**独立的新研究问题**，需重新评估 Ed25519-in-Halo2 成本与新原语价值（当前 `NOT_MEASURED`，本轮不投入）。
- **本轮范围**：只做文档级证明语句审查与修订；未新增/修改任何电路、instance、MockProver 测试、性能实验或冻结成果。

**最终诚实结论**：就当前证据与研究价值判据，private-only MIN-PROOF-B 的绑定不成立；可成立的两种语句要么无新增可验证性质（纯 Halo2），要么不是电路保证而是已有能力的 verifier-level 组合。**不存在值得进入电路实现的新证明关系，D3-07-B 的 Halo2 电路化评估到此为止。**
