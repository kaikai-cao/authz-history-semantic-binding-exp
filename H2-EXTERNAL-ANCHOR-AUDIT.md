# H2 — 外部锚定与可验证性门禁审计

日期：2026-11-24｜对应任务包 Phase 3

**核心问题：隐藏关联字段以后，验证者凭什么相信证明中的关联关系对应真实、已认证的跨组织回执？**

**H2 通过标准（任务包原文）**：必须构造一个完整验证关系，使得 (1) 隐藏字段确实受双方已认证回执约束；(2) 公开锚点来自独立、可验证的外部证据，而非证明者自行声明；(3) 验证者可验证关联却无需完整敏感字段；(4) 不把事件真实性/日志完整性/全局最新性错误归功于 ZKP。**若最终只能得到"两个私有输入相等"，H2 直接失败。**

---

## 1. 三种候选锚定结构（逐结构七要素）

### 结构 1：双方分别签名原始回执，ZKP 证明两个隐藏字段相等

记 A 回执 `r_A` 含 `cd_A`（call_digest 明文），B 回执 `r_B` 含 `cd_B`，签名 `Sig_A(r_A)`、`Sig_B(r_B)`。目标：证 `cd_A = cd_B` 而不公开 `cd_A/cd_B`。

| 要素 | 回答 |
|---|---|
| Public Inputs | `Sig_A(r_A)`、`Sig_B(r_B)`、A/B 公钥、VDS 根。但回执字段若隐藏，签名所覆盖的消息无法被验证者重建 |
| Private Witness | `cd_A`、`cd_B`、回执其余字段 |
| Authentication | 需要验 `Sig_A/Sig_B`——而验签需知道被签消息（回执）；若回执字段隐藏，只能在电路内验签或让验证者看到明文回执 |
| Binding | ZK equality：`log_g cd_A = log_h cd_B`（Chaum-Pedersen [CP93]） |
| External Anchor | 签名的回执 + VDS 注册证明 |
| Freshness | 证明系统不提供；需外部查 epoch/撤销状态（D3-10 P3） |
| Completeness | 不提供；无遗漏超出证明目标（D3-10 P2） |

**致命问题（验签循环）**：验证者要确认"签名有效"，必须能重建被签消息；回执字段一旦隐藏，验签无法在 verifier-level 完成。若把验签放进电路（Ed25519-in-circuit），D3-07-B 标记 `NOT_MEASURED` 且本轮禁止原型。若让验证者看到明文回执 → `call_digest` 已可见 → 隐藏它再做 ZKP 是多余。**结构 1 不成立。**

### 结构 2：双方分别签名承诺，ZKP 证明承诺打开值相等

A 对 `Com(cd_A; ρ_A)` 签名，B 对 `Com(cd_B; ρ_B)` 签名；ZKP 证两承诺打开到同一 `cd`。

| 要素 | 回答 |
|---|---|
| Public Inputs | `Com_A`、`Com_B`、`Sig_A(Com_A)`、`Sig_B(Com_B)`、A/B 公钥 |
| Private Witness | `cd`、`ρ_A`、`ρ_B`（打开随机数） |
| Authentication | 验证者对公开承诺 `Com_A/Com_B` 验签——**可行**，公开对象即被签消息，无循环 |
| Binding | ZK equality of committed values（Chaum-Pedersen / Pedersen 承诺同构；`PRIMARY-EXCERPT`） |
| External Anchor | 双方对承诺的签名（可加 VDS 注册承诺） |
| Freshness | 证明系统不提供；外部 epoch/撤销 |
| Completeness | 不提供 |

**关键评估**：结构 2 是三者中唯一密码学上能避开验签循环的——它让验证者验"对承诺的签名"（公开对象），ZKP 只证"打开值相等"（隐藏）。但它有**两个硬前提**：
1. **必须修改 SCITT 回执格式**：SCITT -02 签的是含 `call_digest` **明文**的回执（§6.7 CDDL key 29，`Content MUST NOT be included` 但 digest 在回执里），并不签"对 call_digest 的承诺"。要采用结构 2，需新增"承诺字段 + 对该承诺签名"——这不是"复用现有 SCITT 锚点"，而是设计一套新的回执格式。
2. **谓词证明仍需值承诺**：若审计者要证"金额 ≤ 阈值"，仅有 `Com(cd)` 不够——`cd` 是请求摘要，不是金额本身；要对金额做 range proof 需工具方额外对金额值承诺，SCITT 无此字段。

因此结构 2 -validation 只覆盖"相等关联"，不覆盖 H1-C 的"合规谓词证明"。两者结合需更大改动。

### 结构 3：双方将回执提交 VDS/TLog，ZKP 证明隐藏关联字段对应已锚定记录

A、B 各自把回执（含 cd 明文）提交到透明日志，VDS 根公开；ZKP 证"隐藏的 cd 等于某已锚定回执的 cd 字段"。

| 要素 | 回答 |
|---|---|
| Public Inputs | VDS 根、inclusion proof、承诺 `Com(cd)` |
| Private Witness | `cd`、回执字段、Merkle 路径 |
| Authentication | 验证 inclusion proof + VDS 一致性（SCITT §9）；回执签名在链下已由 VDS 保证 |
| Binding | ZKP 证 `Com(cd)` 打开值 = 已锚定回执的 `call_digest` 字段 |
| External Anchor | **VDS（独立透明日志）**——这是最强的外部锚点（append-only + non-equivocation） |
| Freshness | epoch/撤销仍需外部 |
| Completeness | 不提供（"leaves no trace"） |

**关键评估**：结构 3 锚定最强。但存在一个根本张力——`call_digest` 明文**已在 VDS 中**（SCITT 回执把它作为字段注册）。若审计者能取回该回执做 inclusion proof，它就直接看到了 `call_digest` 明文；ZKP 隐藏它再证"等于 VDS 里的那个"没有隐私收益。若用 epoch roots（只露 digests）隐藏单条回执，审计者又拿不到"单条回执的 inclusion proof"来锚定。**隐私与可锚定性在此互斥。**

---

## 2. 三个反例测试（证明系统本身能否阻断？）

### H2-A：证明者自造两组私有数据，证相等，却无任何外部签名回执

- **攻击**：证明者选随机 `cd'`，生成两个承诺 `Com(cd')`，用 Chaum-Pedersen 证两承诺打开相等，输出 proof。
- **证明系统能否阻断**：**不能**。equality proof 只证"这两个公开承诺打开到同一值"，不证"该值来自真实回执"。
  - 原始文献证据：ePrint 2016/771 原文——证明者若能自造公开输入 X，"this proof is not sound anymore"；Chaum-Pedersen 的 soundness 前提是公开值 `y=g^α, ỹ=h^α` 已固定、证明者不能选。
  - 本项目先例：D3-07-B §5.1——private-only 下证明者自造 `checkpoint_digest/signer_set_digest/round` 重算哈希，验证者无法区分（见 `H1` 同目录 README 引用）。
- **所需外部机制**：公开输入必须是**双方已签名的承诺（结构2）或 VDS 锚定的承诺（结构3）**，使证明者无法自造公开对象。签名/VDS 提供"公开对象不可自造"，ZK 提供"隐藏值相等"——两者缺一不可。
- **判定**：`NOT_BLOCKED_BY_PROOF`；`BLOCKED_WITH_ASSUMPTION`（依赖外部签名/VDS 锚定）。

### H2-B：证明者将真实回执的关联字段替换成另一条调用的字段

- **攻击**：证明者持有回执 r1（cd=低熵支付额 100）与 r2（cd=另一值），对外声称 r1 是本次待审调用，但用 r2 的 cd 生成相等证明。
- **证明系统能否阻断**：**部分**。若公开输入是已签名承诺，替换字段意味着证明必须打开到该承诺——证明者无法为不同 `cd` 伪造打开（承诺绑定性）。但证明者可以**合法使用另一条真实回执 r2 的签名承诺**——它有权访问 r2。此时 ZK 证明有效，但"这两条承诺对应你声称的那次调用"仍需外部上下文确认。
- **所需外部机制**：需要把承诺与"待审调用的身份/上下文"绑定（如 txn 唯一、时间戳、VDS 中的业务上下文）——这又需要暴露部分上下文，削弱隐藏。
- **判定**：`BLOCKED_WITH_ASSUMPTION`（承诺绑定阻断篡改，但不阻断"用另一条真实但错误的回执"；后者是外部语境问题）。

### H2-C：证明者提交已过期或被撤销的合法历史回执

- **攻击**：证明者用过去某次合规调用的回执/承诺生成证明，在当前验证时使用。
- **证明系统能否阻断**：**不能**。静态证明无时间维度；proof 一旦生成，其有效性不随时间改变（除非 public input 含时间并绑定当前状态，但那需要验证者注入新鲜状态）。
- **所需外部机制**：验证时查当前 epoch / 撤销列表（D3-10 P3 的 freshness 外部依赖）；SCITT 有 assurance 状态 suspended/withdrawn（§9.2）但要验证者主动取当前状态。
- **判定**：`NOT_BLOCKED_BY_PROOF`；`BLOCKED_WITH_ASSUMPTION`（依赖外部 freshness 服务）。

---

## 3. H2 逐项判定汇总

| 通过标准 | 结果 | 证据 |
|---|---|---|
| (1) 隐藏字段受双方已认证回执约束 | **仅结构2/3 满足**（签承诺/VDS 锚定），但需改 SCITT 格式或牺牲隐私 | SCITT §6.7 签明文字段；结构2/3 分析 |
| (2) 公开锚点来自独立外部证据 | 结构3 满足（VDS）；结构2 满足（双方签名承诺）；但都要求新格式 | VDS 原文；ePrint 2016/771 自造不 sound |
| (3) 验证关联无需完整敏感字段 | 结构2 满足；但审计者合规谓词仍需值承诺（SCITT 无） | H1-C 分析 |
| (4) 不误归功于 ZKP | **满足**（本审计明确 E1/E2/freshness 全外包） | H2-A/B/C 判定 |
| "若只能得到两个私有输入相等则失败" | **命中失败条件**：去掉外部签名/VDS，结构退化为 equality proof = 两个私有输入相等 | Chaum-Pedersen 已知原语；H2-A |

## 4. H2 结论

# `H2_FAIL`（外部锚定门禁不通过）

- ZK equality proof 是 **1993 年已知原语**（Chaum-Pedersen [CP93]），本身不提供"字段来自真实回执"的约束。
- 三个反例一致显示：证明系统单独对 H2-A/H2-C `NOT_BLOCKED`，必须靠外部签名/VDS/freshness；H2-B 靠承诺绑定 + 外部语境。
- 唯一能让隐藏字段受已认证约束的结构（签承诺 + VDS 锚定）要求**修改 SCITT 回执格式**（SCITT 签明文字段，不签承诺），且存在"隐藏则无法验签、验签则需看明文"的循环；freshness/completeness 仍全部外包。
- **严格按通过标准**：去掉外部锚定后，剩余就是"两个私有输入相等"——**命中 H2 直接失败条件**。
- 因此 **H2 不通过**。方向 A 两门禁均未过 → `REJECT_AS_KNOWN_PROBLEM`（详见 `DECISION.md`）。
