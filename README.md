# D3-11：Agent Execution Evidence Binding — 跨组织 Agent 执行证据的真实性、完整性与隐私验证

日期：2026-11-24｜阶段类型：场景驱动的**只读密码学研究缺口审计**｜状态：完成，暂停等待决策

---

## 1. 本轮范围

承接 D3-10 收束（`D3-10-CLOSED`），把研究焦点从"隐藏累计计数器的 Proof Memory"转向**真实工具执行事件如何可信地诞生、关联与验证**。不写电路、不修改任何冻结仓库、不做性能实验。

固定场景（跨组织、弱信任、多工具）：

```
Principal
   |
   v
Agent A (Organization A)
   |
   +----> Tool X (Organization B)
   |          |
   |          v
   |       Execution Result
   |
   +----> Agent B (Organization C)
              |
              v
           Tool Y (Organization D)
              |
              v
         Final Result
```

本轮要回答的唯一问题：**在多工具、跨组织、弱信任环境下，现有执行证据机制究竟能保证什么、不能保证什么；是否存在一个现有框架尚未解决、可由 ZKP 或其他密码学构造获得独立保证的问题。**

历史遗漏攻击基线沿用 D3-10 的 **X2′**：Agent 实际执行 10 次工具调用、第 7 次违规，只提交 9 次并给出完全正确的证明；验证者无法仅凭证明知道第 7 次是否发生过。本轮把"遗漏"从轨迹层推进到**执行事件证据层**。

## 2. 只读输入与冻结自检

| 输入 | 用途 | 状态 |
|---|---|---|
| `D3-08-CRYPTO-GAP-AUDIT` | 排除泛化匿名委托凭证；执行绑定未覆盖 | 零改 |
| `D3-09-RESEARCH-AUDIT` | zkAgent / PoE / CVA 能力矩阵复用 | 零改 |
| `D3-10-CLOSURE.md` + 全部六份 | X2′ 基线；递归证明 ≠ 外部历史完整 | 零改 |
| `agent-exec-binding-mvp` | 单次配额 / 请求绑定工程基础 | 零改（clean） |
| `authz-history-semantic-binding-exp`（D3-06-C / D3-07-A） | 状态转换 / 外部锚定技术基线 | 零改（clean） |

审计后核验：三个冻结仓库均 `clean`；D3-08/09/10 目录 mtime 未变。

## 3. 实际核查的文献与证据等级

| 文献 | 证据等级 | 核心结论 |
|---|---|---|
| A. Agent Execution Evidence: A SCITT Profile（draft-thaha-...-**02**，November 2026，Standards Track，**Internet-Draft 非 RFC**） | `FULL-TEXT` | 跨组织执行回执 + `call_digest` 盲关联 + linked verification + PASS 语义；明列 Harness 完整性缺口 |
| B. AI Agent Execution Profile of SCITT（draft-emirdag-...-**01**，October 2026，Informational，**Internet-Draft 非 RFC**） | `FULL-TEXT` | 独立 Custodian + 签名 + 哈希链；明列"未记录操作不留缺口"与 two-party collusion 根本限制 |
| C. NovaFabric: Tamper-Evident, Replayable Evidence for Autonomous AI Agent Runs（arXiv 2609.12582） | `FULL-TEXT` | 条件可验证性；key custodian 可签假；completeness 0.652 且自报；工具响应替换未实现 |
| D. Actions with Receipts: Jointly Binding Claims, Evidence, and Execution...（arXiv 2610.00327） | `FULL-TEXT` | claim/源/执行/版本联合绑定；1280 攻击检出 1275；trusted runner/logger；观测真实性外包给外部锚点 |
| zkAgent（ePrint 2026/199，CCS 2026） | `ABSTRACT-ONLY`+缓存片段（复用 D3-09） | 证 provider 忠实推理 + 工具观察真实；不碰授权合规/轨迹隐私 |
| PoE（arXiv 2607.05397） | `FULL-TEXT`（复用 D3-09） | 签名+哈希绑定，明文 trace + 单 Gateway，不替代 TEE/zkVM |
| CVA（Frontiersin 1966725） | `FULL-TEXT`（复用 D3-09） | Groth16 单次请求/策略绑定；runtime execution binding 是 structural gap |
| SCITT Reference APIs（draft-ietf-scitt-scrapi-11） | `REFERENCE-ONLY`（从 A 引用列表提取，未单独抓全文） | 注册 API；SCITT 架构本身仍为 Internet-Draft |

所有性能数字标注 `AUTHOR-CLAIM`、**未复现**。四篇强基线均为原文逐字核对（`FULL-TEXT`），不依赖摘要。

## 4. 文档索引

| 文件 | 内容 |
|---|---|
| `README.md` | 本文件：范围、输入、文献清单、最终结论 |
| `THREAT-MODEL.md` | 七类参与方、攻击者能力分层、信任边界、六类攻击情形 |
| `FORMAL-PROPERTIES.md` | E1–E4 形式化定义（安全定义 / 公共输入 / 私有见证 / 攻击者 / 成败条件 / 信任假设） |
| `RELATED-WORK.md` | 四篇强基线 + 三篇复用文献逐篇核查、正式机制、关键原文与差异 |
| `CONSTRUCTION-COMPARISON.md` | 五类机制构造级比较 + X1–X7 攻击分析 |
| `DECISION.md` | 三条方向裁决、整阶段四选一决策、下一步门禁 |

## 5. 最终结论（摘要）

**整阶段决策：`CONDITIONAL_HOLD`。** 唯一保留候选为**方向 A：跨组织执行回执的隐私化关联**，但必须先过两道门禁（H1/H2），**不进原型、不写电路**。

三条方向：

| 方向 | 决策 | 一句话依据 |
|---|---|---|
| A. 跨组织执行回执的隐私化关联 | `CONDITIONAL_HOLD`（唯一保留） | `call_digest` 盲关联已被 SCITT 覆盖；ZK 新增仅在"隐藏关联字段 + 隐藏策略判断"，收益与 public 锚点尚未论证 |
| B. 多观察者执行证据的一致性验证 | `REJECT_AS_KNOWN_PROBLEM` | 本质是 equality-of-commitments / digest 比对，SCITT `call_digest` 已实现；ZK 增强为标准构造 |
| C. 执行证据与授权状态联合证明 | `REJECT_AS_KNOWN_PROBLEM` | D3-06-C + D3-07-A + CVA 已覆盖各组件；组合非新关系；runtime binding 已被 CVA 判为 structural gap |

**两条必须写死的边界（本轮最重要产出）：**

1. **签名有效 ≠ 事件真实。** SCITT PASS、NovaFabric、Receipts 全部明确：签名证明"指定主体签了某条记录"，不证明工具内部行为与记录一致；NovaFabric 更直白——key custodian 可签一条断言虚假的合法 capsule，下游任何验证都检不出。
2. **日志可追加 ≠ 日志无遗漏。** SCITT Profile 原文："An action that was never recorded leaves no gap"；序列缺口只能证明"产生了但未注册"，不能证明"从未发生"。NovaFabric 的 completeness 自报、未达 1.0。

**下一步门禁（须先证伪，再决定是否进原型）：**
- **H1（隐藏收益）**：验证者为何不能接受 SCITT 明文 `call_digest` 比对 + 访问控制？`call_digest` 是单向摘要、本身不泄漏请求内容；若"隐藏"只省去不可见的字段，则无新增价值。
- **H2（public 锚点）**：隐藏 `call_digest` / `actor_chain` / `principal` 后，验证者靠什么 public 锚点确认关联真实性？必须避免 D3-07-B 的 private-only 哈希自洽陷阱——锚点只能是 SCITT VDS 中已签名的承诺。

若 H1 或 H2 被证伪，方向 A 应降级 `REJECT_AS_KNOWN_PROBLEM`。本轮完成后暂停。
