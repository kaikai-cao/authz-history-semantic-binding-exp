# D3-12 决策记录：方向 A 双门禁证伪

日期：2026-11-24｜阶段类型：只读研究缺口审计｜状态：完成，暂停等待用户对方向 A 收束的决策

---

## 1. H1 逐项判定及证据

| 判据 | 判定 | 证据 |
|---|---|---|
| (1) 明文回执+访问控制无法满足目标隐私？ | **否（大部分）** | SCITT -02 §10 `FULL-TEXT`：`No content`、`principal_link`=双方共有 token 摘要（"show they recorded the same Principal without either revealing it"）、epoch roots 只露 counts+digests、pepper 跨部署轮换、Data minimization。H1-A/B/C 的现实泄露均被覆盖或缓解 |
| (2) 更简方案无法满足？ | **是（更简方案充分）** | RFC 9901 `FULL-TEXT`：salted hash 选择性披露已标准化；pepper/HMAC 阻断低熵 `call_digest` 字典猜测；epoch roots + batch issuance 缓解跨审计者拼接 |
| (3) ZKP 有明确可验证额外性质？ | **仅"跨双签发方隐藏值联合谓词证明"为窄候选**，但依赖 H2，且 SCITT 无值承诺可供谓词证明 | H1-C 分析 + D3-11 E4 |
| 附加标准："只证 ZKP 能隐藏 call_digest 不算通过" | **命中**：本轮唯一确凿增量即"隐藏摘要/关联字段"，不算通过 | SCITT §9.2 已是盲摘要比对 |

**H1 结论：`H1_FAIL`。** 真实隐私需求存在（审计者不应获得身份关联/业务类型/可猜摘要），但 SCITT 明文设计 + 标准选择性披露系统性解决；ZKP 无"明文+更简方案都够不到"的明确增量。

## 2. H2 逐项判定及证据

| 判据 | 判定 | 证据 |
|---|---|---|
| (1) 隐藏字段受双方已认证回执约束？ | **仅签承诺/VDS 结构满足**，但需改 SCITT 回执格式 | SCITT §6.7 签的是含 cd 明文的回执，不签承诺 |
| (2) 公开锚点来自独立外部证据？ | 结构3（VDS）满足，但见 (1)(3) 张力 | SCITT §9 VDS 一致性 |
| (3) 验证关联无需完整敏感字段？ | 结构2 技术上满足；但验签需看被签消息→验签循环；VDS inclusion 对含 cd 明文回执→隐藏失效 | H2 结构 1/2/3 分析 |
| (4) 不误归功于 ZKP？ | **满足**：本审计明确 E1/E2/freshness 全外包 | H2-A/B/C 判定 |
| "只能得到两个私有输入相等则失败" | **命中失败条件**：去掉外部锚定即退化为 equality proof | Chaum-Pedersen [CP93] 已知原语；ePrint 2016/771 自造公开输入不 sound；D3-07-B §5.1 本项目先例 |

**反例结果**：H2-A `NOT_BLOCKED_BY_PROOF`（需外部签名/VDS）；H2-B `BLOCKED_WITH_ASSUMPTION`（承诺绑定+外部语境）；H2-C `NOT_BLOCKED_BY_PROOF`（需外部 freshness）。

**H2 结论：`H2_FAIL`。** ZK equality proof 是 1993 已知原语，无外部锚定时不成立；唯一可锚定结构要求改 SCITT 格式或陷入"验签需看明文/隐藏则无法锚定"张力，且 freshness/completeness 全外包。

## 3. 与现有工作的差异表

| 性质 | SCITT 明文+访问控制 | RFC 9901 选择性披露 | 匿名凭证/BBS | ZKP（方向 A） |
|---|---|---|---|---|
| 跨方同调用关联 | ✅ 已实现（call_digest 盲比对） | 不适用 | 不适用 | 无新增 |
| 隐藏 Principal 且可关联 | ✅ pepper hash + token digest | 部分（合谋可链接） | ✅（`INFERENCE`） | 无新增 |
| 隐藏字段合规谓词证明 | ❌ | ❌（未声明） | ✅（`INFERENCE`，单签发方） | 窄候选，H2 未过 |
| 事件真实/无遗漏/最新 | ❌（外部基） | ❌ | ❌ | ❌（ZKP 不提供） |

**净新增**：0 个经得起强基线检验的可验证性质。

## 4. 最小候选验证关系

**不提出。** 任务包规定"仅在 H1/H2 均有通过迹象时才提出最小构造"；本轮 H1_FAIL + H2_FAIL，条件不满足。`CONSTRUCTION-AND-RELATED-WORK.md` §3 记录了"即使强行构造也不能成立"的四条理由（值承诺缺失、verifiability↔privacy 张力、freshness 外包、已知组合非新关系）。

## 5. 最终裁决

# `REJECT_AS_KNOWN_PROBLEM`

- `GO_MINIMAL_PROTOTYPE`：**否**——H1、H2 均未通过，无清晰新增性质。
- `CONDITIONAL_HOLD`：**否**——需求本身真实，但外部锚定不是"不明确"，而是经审计**不成立为 ZKP 可提供的性质**（去掉外部锚定即退化为 equality proof）。若记 HOLD 会把已证伪项伪装成待定，违背证伪审计目的。
- `REJECT_AS_KNOWN_PROBLEM`：**采纳**——(a) 关联内核已被 SCITT `call_digest`/`principal_link` 覆盖；(b) 隐私诉求被明文设计 + RFC 9901 覆盖；(c) ZKP 窄增量依赖 H2，而 equality proof 是已知原语且无锚定不成立。
- `STOP_RESEARCH_DIRECTION`：**本轮不使用**（按任务包：只审计方向 A，不裁决整个 ZKP+Agent 方向）。

## 6. 失败原因（写死，防止未来换名称重复立项）

1. **"跨组织隐私化关联"的内核是现成构造**：SCITT §10 `principal_link` 用"双方共有 token 的摘要"实现"证明同一 Principal 而不泄露"；§9.2 linked verification 实现盲摘要比对。任何以"隐藏关联字段"为卖点的 ZKP 方案，相对它只有"连摘要也隐藏"的增量，而摘要本身不是原文、隐藏后反而破坏锚定。
2. **谓词证明的窄空间被 H2 循环封死**：审计者要验签需看回执（含 cd 明文）→ 隐藏无意义；不给回执只给承诺 → 必须改 SCITT 格式（签承诺而非签含明文字段的回执）或电路内验签（D3-07-B `NOT_MEASURED`）。SCITT 回执只存摘要/pepper hash，无值承诺可供"金额≤阈值"类谓词证明。
3. **equality proof 是已知原语且无锚定不成立**：Chaum-Pedersen 1993；ePrint 2016/771 证明者可自造公开输入时不 sound；D3-07-B §5.1 本项目 private-only 反例。去掉外部签名/VDS，剩余就是"两个私有输入相等"——任务包判 H2 直接失败。
4. **freshness/completeness 全外包**：即使构造成立，过期回执（H2-C）与遗漏事件（H2-A 家族）都不由证明系统阻断——这是 D3-10 P2/P3 与 D3-11 X1–X7 的既有结论，不是本轮可新增的性质。

**结论语义**：本轮排除的是"方向 A 作为独立 ZKP 研究贡献"；不否定 Agent 执行证据的工程价值，也不否定 ZKP 在别处的作用。这是继 D3-08（泛化匿名委托）、D3-10（Proof Memory 组件组合）、D3-11（方向 B/C）之后，对方向 A 的正式证伪。**四条研究路线至此全部收束，当前研究链无 GO 候选。**

## 7. 下一阶段唯一建议

本轮**不进入原型**。若用户仍希望推进 Agent 执行证据，建议方向不在"隐私化关联"（已证伪），而在 D3-11 已标注的外部信任基问题（工具执行事件的真实采集/远程证明绑定）——但那是另一个任务包、另一轮裁决，且不是 ZKP 证明关系创新。**本轮完成后暂停。**
