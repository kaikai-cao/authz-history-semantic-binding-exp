# DECISION.md — D3-17-01 最终裁决

日期：2026-11-25
任务：C1「模型承诺跨周期续接」ZK 必要性审计（D3-16 优先候选 1 的深度反例审计）
裁决：**NARROW**（保留窄化候选，不进原型）

---

## 一页摘要

原 C1 定义过宽，已缩窄为 `R_eq(C₁,C₂)`：在权重隐藏、更新方不可信、承诺 ID 跨周期变化时，证明两个承诺打开到同一隐藏权重 W。

**结论**：一般问题**已被解决**——Pedersen 类代数承诺的跨承诺 witness 等值由 CP_link（LegoSNARK, CCS 2019）覆盖；FlashProve **同 ID 内**的 anchor↔leaf link proof 已在做同一个 `R_eq` 关系且是 ZK 的。真正的剩余缺口是**跨 ID** 场景：FlashProve 官方逐字写明 *"Between two IDs there is no proof ... A renewal looks exactly like a switch to another model."*；容量到期强制换 ID，而 ZK 定理明确 *"a second commitment → nothing"*。

但缺口**不足以支撑 CONDITIONAL-GO**：① 用户材料没有给出"不可信更新方与承诺方分离"的真实部署实例；② CP_link 的 Pedersen  Algebraic 前提不适配 FlashProve 的 BLAKE2b Merkle + RS 编码承诺，"套通用 SNARK"的可行性/成本无原文证据；③ 存在降低该场景密度的非 ZK 设计（预置 leaf tables、公开权重重算、可信 vouching party）。

按任务包裁决定义：一般问题已解决但 FlashProve 类隐藏、非同构承诺存在可验证的工程缺口 → **NARROW**。不宣布论文题目，不进原型，不写电路。

---

## 1. 七项必答问题结论表（摘要）

| 问题 | 结论 |
|---|---|
| 1 不可信更新方现实性 | 合理威胁模型，**缺真实部署证据** |
| 2 权重隐藏必要性 | 是（FlashProve 核心，232 GB 不现实） |
| 3 签名+日志为何不足 | RFC 9943 §9.2 明文：只证声明产生，不证内容 |
| 4 CP-Link 是否解决 | **一般情形已解**；不适配 FlashProve 非代数承诺；引用需纠错 |
| 5 是否需特定跨承诺证明 | 跨 ID 需要；但 link proof 的 query-bound 结构冲突 + ZK 定理不覆盖第二承诺 |
| 6 成本是否可接受 | **无证据**；不得把理论可表达性当可行性 |
| 7 更简单设计能否消除 | 有三种非 ZK 路径可显著降低场景密度 |

详见 `COUNTEREXAMPLES.md`。

---

## 2. 三类反例结论

- **场景 A（可信发行者）**：签名 + 透明日志满足普通版本谱系。**ZK 不必要**——这是对原 C1 最直接的证伪。
- **场景 B（恶意更新方 + 权重隐藏 + 跨 ID）**：非 ZK 不能识别 `C₂↔W₂` 却签 `same_model` 的虚假声明；`R_eq` 能解决，但保留四项信任假设（见 COUNTEREXAMPLES.md）。
- **场景 C（正常更新）**：`R_eq` ≠ `R_update`；相同权重 ≠ 功能等价。Kaizen/VFT/zkLLMPoT 均属 R_update 或其子集，不可替代 R_eq。

---

## 3. 为什么不是 STOP / CONDITIONAL-GO

**不是 STOP**：
- 跨 ID、权重隐藏下的 `R_eq` 并未被现有工作直接解决。CP_link 要求 Pedersen 型承诺验证（LegoSNARK §4.1），FlashProve 是 BLAKE2b Merkle + RS 编码，结构不兼容；FlashProve 自己的 link proof 仅同 ID 有效。任务包 STOP 条件"已有跨承诺证明已足以解决"**未命中**。
- 签名 + 日志在场景 B 明确不足（RFC 9943 §9.2）。
- 因此不能整体关闭；按"STOP 只关闭本候选"的口径也不合适——窄缺口是真实且可回溯的。

**不是 CONDITIONAL-GO（六门槛缺 1、6）**：
1. ❌ 真实应用场景：`R_eq` 跨 ID 的**真实部署实例**缺证（只有 FlashProve 一个未维护 artifact 的自述限制，且无更新方与承诺方分离的部署记录）。
2. ✅ 不可信更新方威胁模型：合理且可形式化。
3. ✅ 权重隐藏必要：是。
4. ✅ 非 ZK 不能满足：在 narrowed 威胁模型内成立。
5. ✅ Kaizen/VFT/CP-Link 未直接解决该具体问题：成立。
6. ❌ 可信可行性分析 + 可复现实验计划：缺。通用 SNARK 要把 BLAKE2b + 距离测试 + 全模型线性 claim 放进电路，全规模需 330 GB RAM / 232 GB 权重；**没有**任何原文给出成本可行性或比通用 SNARK 更高效的构造。任务包明确要求：若只能"把一般 SNARK 套到 FlashProve 上"且成本无竞争力 → 应停止该窄方向。

**因此 NARROW**：窄缺口保留为候选，但不满足进入原型的门槛。

---

## 4. 解除 NARROW 的最小外部条件（三条必须同时满足）

1. **真实场景证据**：给出一个实际部署，其中"承诺方 ≠ 更新方"或"更新方不可信"是可查事实，且权重必须隐藏、ID 必须更换。仅有 FlashProve artifact 自述不够。
2. **构造可行性**：给出针对 FlashProve 类**非代数**承诺的跨 ID R_eq 构造，且有明确 soundness/ZK 论证；或证明通用 SNARK 在该规模下有可测、可接受的成本。单纯引用 CP_link 不算（Pedersen 前提不成立）。
3. **强基线对照**：在同一威胁模型下比较"预置 leaf tables + 可信 vouching party 轮换"基线，说明 ZK 的不可替代增益，而非仅隐藏字段。

任一条件不满足 → 关闭窄方向，不再改名重立。

---

## 5. 引用纠错（必须记录）

用户任务包中把以下两个链接当作 **CP-Link**：
- `https://eprint.iacr.org/2024/1209`
- `https://link.springer.com/article/10.1007/s10207-026-01209-1`

经原文核验，两者指向同一篇 ***"Collaborative CP-NIZKs: Modular, Composable Proofs for Distributed Secrets"***（Alghazwi et al.；2024 预印本 / 2026-03-03 IJIS 期刊版），研究**分布式 witness 的 collaborative commit-and-prove NIZK**，其中使用 CPlink 作为构件，**不是**"两个承诺不同密钥同一向量"的原始定义。

真正的 `CP_link` 出自 **LegoSNARK（Campanelli, Fiore, Querol, CCS 2019, ePrint 2019/142）§4.1 "CP-SNARK for Pedersen Verification"**，原文要求 `Com.VerCommit = Ped.VerCommit`。该 PDF 直取受拦截，本轮以 **[原文片段]** 标注，未冒充全文逐字核对。

此纠错直接改变裁决：若按用户原引文误判为"CP-Link 解决一切"，会错误 STOP；若无视 CP_link 已解决一般情形，会错误 CONDITIONAL-GO。

---

## 6. 六项验收情况

| 验收项 | 状态 |
|---|---|
| 每个核心结论可回溯原始资料 | ✅ `SOURCES.md` 逐项分级（原文/原文片段/二手/UNVERIFIED） |
| 区分身份认证、历史完整性、关系正确性、隐私 | ✅ `THREAT-MODEL.md` §1 四列表 |
| 不把作者声明当数学证明 | ✅ A2/A4 均标注为作者自述；theorem 仅对 Lean verifier |
| 不把通用 SNARK 可表达性当实际可行性 | ✅ Q6 明确无证据 |
| 正面比较 CP-Link 与 Kaizen | ✅ `RELATED-WORK.md` §2/§5 + Q4 |
| 不以寻找空白为唯一目标 | ✅ 场景 A 明确裁定 ZK 不必要；给出非 ZK 路径 |
| 不进原型、不改冻结仓库 | ✅ 见 §7 自检 |

---

## 7. 范围自检与提交

- Phase 0：D3-16 HEAD = `cdf469169311aee711186a7e5af19267b74f7e38`，分支 `exp-d3-16-01-research-space-reset`，clean；5 个冻结仓库 HEAD 复核未变且干净。
- Phase 1–4：六份文档齐全（DECISION / THREAT-MODEL / NON-ZK-BASELINES / RELATED-WORK / COUNTEREXAMPLES / SOURCES）。
- 未修改 D3-13/14/15/16、MVP、Orchard、Halo2 或任何冻结工程；未写电路、未启动原型。
- 提交分支：`exp-d3-17-01-c1-zk-necessity-audit`（orphan 单根），精确 add 六文档，推送后回读远端 SHA 核验（SHA 见最终汇报）。

---

## 8. 下一步建议（不自动启动）

1. **不启动 R_eq 原型**。按 §4 三条最小条件先做证据收集；无真实部署证据即关闭窄方向。
2. 若用户希望继续 ZK 工程线，转向 D3-16 的**优先 2 / A1（Halo2 分阶段内存剖面）**——那是测量研究，无本轮的"关系必要性"风险。
3. C2（承诺来源锚定）按 D3-16 判定与本轮同构：若"签名策略必须隐藏"无真实场景 → 并入或排除，不单独立项。
