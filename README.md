# D3-12：方向 A 的 H1/H2 双门禁证伪审计

日期：2026-11-24｜阶段类型：只读研究缺口审计（方向 A 的最后一次严格机会）｜状态：完成，暂停等待决策

---

## 1. 本轮唯一问题

> **跨组织 Agent 执行证据的隐私化关联，是否存在明文回执方案无法合理解决、且值得引入 ZKP 的真实需求？**

不是默认要把方向 A 做出来。通过 H1+H2 双门禁才进入原型设计；否则停止当前候选，不换组件、不换证明系统。

## 2. Phase 0 基线核验结果（全部符合，未擅自修复）

| 检查项 | 结果 |
|---|---|
| D3-11 六份交付文档完整 | ✅ 6 份齐全（README/DECISION/RELATED-WORK/FORMAL-PROPERTIES/CONSTRUCTION-COMPARISON/THREAT-MODEL） |
| D3-11 本地 HEAD = 远端 SHA | ✅ `61e9cd10b245552b485b977a173306bdf7e35497`，工作区 clean |
| D3-06-C / D3-07-A / D3-07-B / D3-10 冻结状态 | ✅ 三个 git 仓库均 0 未提交；D3-10 mtime 未变 |
| 当前工作目录未提交内容 | ✅ 无（D3-12 目录新建前不存在，远端无分支冲突） |

重点输入已读回：D3-11 `DECISION.md`（H1/H2 精确定义）、`THREAT-MODEL.md`（信任假设表）、`FORMAL-PROPERTIES.md`（E3/E4）、`CONSTRUCTION-COMPARISON.md`（机制5/X7）、D3-10 `D3-10-CLOSURE.md`（X2′）、D3-07-B `EXP-D3-07-B-HALO2-FEASIBILITY.md` §5.1（private-only 反例）、D3-07-A `EXP-D3-07-A-ANCHOR-SPEC.md`（public 锚定要求）。

## 3. 本轮证据等级

| 文献/来源 | 证据等级 | 关键用途 |
|---|---|---|
| SCITT AEE `draft-thaha-...-02` §6.7.3 / §9 / §9.2 / §10 / §11 | `FULL-TEXT` | H1 主证据：`principal_link`=digest-of-token、`call_digest` 低熵猜测、epoch roots 缓解、Omission 原文 |
| SCITT AI Agent Execution Profile `draft-emirdag-...-01` §11/§12 | `FULL-TEXT`（D3-11 核验复用） | custody/privacy/collusion 基线 |
| RFC 9901 Selective Disclosure for JWT（Standards Track, November 2025） | `FULL-TEXT`（本轮原始规范逐字核对） | H1 更简替代判定：明确不支持隐藏值谓词、合谋可链接 |
| W3C Data Integrity BBS Cryptosuites v1.0 / SD-JWT VC | `INFERENCE`（二级来源，未抓规范原文） | unlinkable presentation 更简替代（标注未独立验证） |
| Chaum & Pedersen 1993 — proof of equal discrete logs；ePrint 2016/771（weak FS / fixtures 可自造陷阱） | `PRIMARY-EXCERPT`（原始论文片段） | H2 主证据：equality proof 是已知原语 + 自造公开输入不 sound |
| D3-07-B `EXP-D3-07-B-HALO2-FEASIBILITY.md` §5.1 `STOP_HALO2_DIRECTION` | `FULL-TEXT`（本项目冻结文档） | H2 反例先例：private-only 自造字段重算哈希不可验证 |
| D3-08 / D3-09 匿名凭证、执行证据审计 | `FULL-TEXT`（复用） | 更简替代与覆盖边界 |
| 所有性能数字 | `AUTHOR-CLAIM` | 未复现 |

## 4. 文档索引

| 文件 | 内容 |
|---|---|
| `README.md` | 本文件：范围、Phase 0 核验、证据等级、最终结论 |
| `SCENARIO-AND-THREAT-MODEL.md` | Phase 1：Org A/B/C 最小场景、各方知悉/可见/可操作边界、现实隐私威胁 |
| `H1-NECESSITY-AUDIT.md` | Phase 2：五方案比较 + H1-A/B/C 三攻击；H1 逐项判定 |
| `H2-EXTERNAL-ANCHOR-AUDIT.md` | Phase 3：三锚定结构七要素 + H2-A/B/C 三反例；H2 逐项判定 |
| `CONSTRUCTION-AND-RELATED-WORK.md` | Phase 4-5：强基线对照、证据证伪、最小候选（如成立） |
| `DECISION.md` | Phase 6：H1/H2 判定、差异表、最终裁决、失败原因 |

## 5. 最终结论（摘要）

# 裁决：`REJECT_AS_KNOWN_PROBLEM`

**方向 A 的两道门禁均未通过。** 这是本轮最重要、也必须诚实接受的结论。

- **H1（ZKP 必要性）：不通过。** 存在一个真实隐私需求（审计者验证合规但不应获得身份关联/业务类型/可猜的摘要），但 SCITT -02 的明文设计已用 `principal_link`=digest-of-token、"No content"、epoch roots、pepper、data minimization **系统性缓解**；选择性披露 RFC 9901 是更低成本的现成替代。ZKP 相对明文方案的可验证增量归结为"隐藏一个本就不是原文的摘要"或"隐藏后反而破坏 H2 锚定"，**不满足 H1 通过标准**（"只证明 ZKP 能隐藏 call_digest 不算通过"）。

- **H2（外部锚定）：不通过。** ZK equality proof 是 Chaum-Pedersen 1993 已知原语；ePrint 2016/771 与 D3-07-B §5.1 共同证明：当证明者能自造公开输入/私有预像时，"两隐藏字段相等"不成立为对外部证据的可验证约束。三种候选结构中，只有"双方签承诺 + VDS 锚定"能让隐藏字段受已认证承诺约束，但它要求**修改 SCITT 回执格式**（SCITT 签的是含 `call_digest` 明文的回执，不签承诺），且 freshness/completeness 仍全部外包。按通过标准"不把事件真实性/日志完整性/全局最新性归功于 ZKP""若最终只能得到两个私有输入相等则 H2 失败"——H2 不通过。

**关键反例（写死以防未来改名重立项）**：
1. SCITT §10 `principal_link` 已实现"隐藏的跨方关联"——"跨组织隐私化关联"内核是现成构造。
2. SD-JWT（RFC 9901）更简且已标准化，但未声明支持隐藏值谓词——正说明"谓词证明"可能是 ZKP 的空间；然而该空间要成立，必须跨两个独立签发方锚定，落到 H2 的循环。
3. H2 循环：验证者需看到已签回执才能验签 → 看到回执即看到 `call_digest` 明文 → 隐藏它再做 ZKP 是多余；若不给出回执只给承诺 → 必须改 SCITT 格式或电路内验签（NOT_MEASURED），不再是"复用现有 SCITT 锚点"。

本轮不进原型、不写电路、不改任何冻结仓库。完成后暂停，等待用户对方向 A 收束的决策。
