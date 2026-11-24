# H1 — ZKP 必要性门禁审计

日期：2026-11-24｜对应任务包 Phase 2

**核心问题：公开 `call_digest` 配合访问控制，是否已经足够？**

**H1 通过标准（任务包原文）**：必须找到至少一个明确的隐私需求，使得 (1) 现有明文回执及合理访问控制无法满足；(2) 简单承诺、匿名凭证或选择性披露无法以更低成本满足；(3) ZKP 可以实现明确且可验证的额外性质。**只证明"ZKP 可以隐藏 `call_digest`"不算通过。**

---

## 1. 五方案比较

| 方案 | 能隐藏什么 | 关键机制/原文 | 局限（原文可验证） | 成本量级 |
|---|---|---|---|---|
| **A. 明文回执 + 访问控制** | 内容（No content）；Principal（pepper hash）；跨方关联字段只对被调用方转发 | SCITT §10：`No content`；`principal_link`=双方共有 token 摘要；`epoch roots` 只露 counts+digests；Data minimization | `call_digest` 低熵可猜（§10 明确）；同一部署 Principal by-design 可链接；元数据（agent_id/ts/type）仍可见（TS visibility） | 最低（哈希+签名） |
| **B. 双边签名回执** | 同 A；额外保证"双方各自验证、不照抄"（§6.7.3 Serving Party 自己算 call_digest） | SCITT §6.7.3 / §9.2 linked verification | 不隐藏摘要本身；验签需看到回执字段 | 低 |
| **C. 承诺方案** | 隐藏 `call_digest` 值，只公开承诺 `Com(cd)` | Pedersen commitment（1991）；隐藏后需证两承诺对应同值 → 落到 ZK equality（见 H2） | 单纯承诺不提供"相等可验证"；一旦要证相等就进入 ZK；且 SCITT 未签承诺（签的是含 cd 明文的回执） | 低-中 |
| **D. 匿名凭证 / 选择性披露** | 选择性披露属性、unlinkable presentation | **RFC 9901（FULL-TEXT）** SD-JWT salted hash；W3C BBS Cryptosuites（`INFERENCE`） | RFC 9901 原文："SD-JWT only conceals the value of claims that are not revealed. It does not meet the security properties for anonymous credentials"；"colluding Verifiers and Issuers can know when they have seen the same credential"；**未声明支持对隐藏值证谓词**；batch issuance 仅缓解 Verifier/Verifier 链接，"cannot work for Issuer/Verifier unlinkability" | 低-中 |
| **E. ZKP** | 隐藏 `call_digest/actor_chain/principal` 仍证关联+合规谓词 | Chaum-Pedersen [CP93] equality proof；通用 SNARK 证 Dec(P,ctx)=1 | equality proof 是已知原语（1993）；证明者能自造公开输入时不 sound（ePrint 2016/771）；需 public 锚点否则 D3-07-B 陷阱；freshness/completeness 仍外包 | 高（NOT_MEASURED） |

**首轮结论**：方案 A/B 已覆盖"内容不与审计者共享"这一核心隐私；方案 D 是成熟更简替代；方案 C 单独不够；方案 E 的增量需逐攻击检验是否真实且不可替代。

---

## 2. 三个攻击/隐私泄露场景（逐项判定）

### H1-A：审计者通过长期观察摘要关联不同组织中的同一用户或 Agent

- **攻击者**：持有同一部署一批回执的审计者 C（合法接收方）。
- **观察数据**：`principal_link`（pepper hash）、`call_digest`、`actor_chain`、`ts`、`agent_id`。
- **能推断什么**：SCITT §10 原文——同一 Principal 在同一部署内"linkable across receipts **by design**"；`txn`/`actor_chain` "correlate all hops of one transaction and reveal which operators' agents took part"。
- **访问控制为何不足**：C 被授权看这批回执做合规，就无法阻止它做跨回执关联；pepper 只在**跨部署**阻断关联，同部署内关联是设计意图（审计本就要能追责同一 Principal）。
- **更简替代**：**pepper 轮换 + epoch roots 聚合**已是 SCITT 现成机制；若确实要隐藏 Principal，BBS unlinkable presentation 或批量单次凭证是更简替代（`INFERENCE`，未独立验证规范原文）。
- **ZKP 是否必要**：**否**。同一部署内关联是审计功能而非漏洞；跨部署关联已被 pepper 阻断。ZKP 隐藏 `principal_link` 会破坏审计追责能力，且落到 H2 锚定困难。
- **判定**：`NOT_A_REQUIREMENT`（需求本身与审计目标冲突）／对跨部署关联 `BLOCKED_BY_PEPPER`（已有更简机制）。**不贡献 H1 通过。**

### H1-B：不同审计者之间交换回执，拼接出原本不应获得的执行轨迹

- **攻击者**：两个合法审计者 C1、C2（可能合谋或被强制披露）。
- **观察数据**：各自收到的回执子集。
- **能推断什么**：合并后得到更完整的 `txn`/`actor_chain` 链，看到更多 hops 与 operator 关系。
- **访问控制为何不足**：一旦回执交给 C1/C2，无法阻止它们交换；这是**分发层问题**，不是验证层密码学问题。
- **更简替代**：**epoch roots**（SCITT §10 Retention：只给 counts+digests，不给单条回执）直接消除可拼接的原文级细节；或对 C1/C2 用不同 pepper/token。RFC 9901 batch issuance 明确用于"keeping Verifiers from linking different presentations"（`FULL-TEXT`）。
- **ZKP 是否必要**：**否**。若审计者本就不该看到单条回执，正确做法是不给它（epoch roots）；若它需要看单条做逐笔合规，则 ZKP 隐藏后它无法完成合规验证（回到 H2）。
- **判定**：更简机制（epoch roots + 分发控制）充分解决；**不贡献 H1 通过。**

### H1-C：关联字段暴露调用频率、服务关系或敏感业务类型

- **攻击者**：审计者 C 或看到 VDS protected header 的观察者。
- **观察数据**：`ts`、`target`/`egress_host`（工具名/host）、`call_digest`（低熵可猜，如支付金额）、`issuer`/`agent_id`（TS visibility）。
- **能推断什么**：SCITT §10 原文承认：低熵 `call_digest` 可被重算猜测（例："a payment amount sent to a known path"）；TS 看到"agent identifier, type and key identifier"；agent_id/type 可对敏感 existence 造成暴露。
- **访问控制为何不足**：SCITT 给的是 SHOULD（ epoch roots、opaque identifiers、data minimization），不是硬保证；C 一旦持有单条回执就能看到 target/host/ts。
- **更简替代**：对 `call_digest` 加 secret salt/HMAC（类似 Principal 的 pepper 思路）即可阻断字典猜测——**无需 ZKP**；opaque identifier + epoch roots 已由 SCITT 提供。
- **ZKP 是否必要**：**部分情形是**——若需求升级为"审计者验证金额 ≤ 阈值/Principal ∈ 允许表，但不看金额和身份值"，则这是**对隐藏值的谓词证明**，RFC 9901 明确不提供、SD-JWT 无法做；这是 ZKP（或 BBS 谓词证明）真实增量所在。**但**：(a) 该谓词依赖具体字段值承诺，SCITT 回执只存摘要/pepper hash，没有可证谓词的值承诺；(b) 跨两个独立签发方（A、B）做联合谓词证明落到 H2；(c) BBS/匿名凭证对单签发方已能做此类谓词（`INFERENCE`）。
- **判定**：字典猜测部分 `BLOCKED_BY_SALT`（更简）；谓词证明部分构成**唯一候选 ZKP 增量**，但受 H2 门禁约束，且更简替代（BBS）尚未被原文排除。**这是 H1 的"薄通过点"，不足以单独构成必要性。**

---

## 3. H1 逐项判定汇总

| 判据 | 结果 | 证据 |
|---|---|---|
| (1) 明文回执+访问控制无法满足？ | **部分满足**：内容/Principal/跨部署关联已由明文设计解决；仅"谓词证明"不满足 | SCITT §10 全文 |
| (2) 更简方案无法满足？ | **否**：pepper/epoch roots/salt 解决 A/B/C 大部分；RFC 9901/BBS 是成熟更简替代 | RFC 9901 FULL-TEXT；SCITT §10 |
| (3) ZKP 有可验证额外性质？ | **仅"跨双签发方隐藏值谓词证明"是候选**，但该性质依赖 H2 锚定，且 SCITT 无值承诺可供证明 | H2 审计 + D3-11 E4 |

## 4. H1 结论

# `H1_FAIL`（ZKP 必要性门禁不通过）

- **存在真实隐私需求**（H1-C 的谓词证明场景），但 **SCITT 明文设计 + pepper/epoch roots/salt + 标准选择性披露（RFC 9901）已系统性解决 H1-A/B/C 的现实泄露**。
- ZKP 唯一不可替代的窄增量是"跨两个独立签发方的隐藏字段联合谓词证明"——但这正是 H2 要审的锚定问题，且更简替代（BBS/匿名凭证，`INFERENCE`）尚未排除。
- **严格按通过标准**：只证明"ZKP 能隐藏 call_digest"不算通过；本轮未找到"明文+访问控制+简单承诺/匿名凭证/选择性披露都无法满足、而 ZKP 能以更低成本之外的方式明确满足"的隐私需求。
- 因此 **H1 不通过**。按任务包"任一门禁未过即 REJECT"，方向 A 进入 `REJECT_AS_KNOWN_PROBLEM` 裁决（详见 `DECISION.md`）。H2 仍按任务包要求完整审计，不因 H1 失败而省略。
