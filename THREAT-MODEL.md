# THREAT-MODEL.md — 参与方、攻击者、信任假设与安全目标

日期：2026-11-25。任务：C1「模型承诺跨周期续接」ZK 必要性审计。

---

## 1. 四类性质必须分开（不得合并为"可信模型"）

| 性质 | 精确定义 | 谁能满足 |
|---|---|---|
| **身份认证** | 发布者身份经签名/OIDC 可验证，声明未被事后篡改 | 签名 + 透明日志（RFC 9943 §9.2：只证明"由某 Issuer 产生"） |
| **历史完整性** | 声明序列不可回改、可重放、可审计 | 透明日志 / append-only log |
| **关系正确性** | 两个承诺 C₁、C₂ 是否打开到同一隐藏权重 W | 需要专门关系证明 R_eq；签名不能提供 |
| **隐私** | 验证者不获知 W，也不必重新下载 W | ZK 或 masking；与关系正确性正交 |

D3-15 的结论在本轮延续：**证明"结果相对某承诺正确"≠证明"承诺本身真实/未换"**。本轮聚焦后者中的窄问题——两个承诺之间的同一性。

---

## 2. 参与方

| 角色 | 能力 | 诚实假设 |
|---|---|---|
| **Model Provider / Committer** | 持有 W；运行 `cp_commit`/`cp_prove`；可选择承诺任意（含退化）模型；写配置文件（策略、scales、layout） | **不可信**：可选 W′≠W、可声称 C₂ 对应 W₁ 而实际对应 W₂ |
| **Verifier / Client** | 持有从可信方获得的 C_id 与三份配置文件；自建 request；运行 `cp_verify` | 诚实但资源有限；不下载 232 GB 权重 |
| **Vouching Party（可信锚）** | 独立发布/背书 C_id | **可信**；FlashProve README 明示 ID 必须从该方获得 |
| **Transparency Log / Bulletin Board** | append-only，提供 inclusion proof；可监测异常签名事件 | 完整性可信，内容真实性不保证（RFC 9943 §9.2） |
| **Updater（本轮引入）** | 在续接时发布 C₂ 并签署"same model as C₁"声明 | **不可信**（这是窄问题的前提） |

---

## 3. 攻击者能力分层（必须区分，不得合并）

- **ATK-SIGN（签名层）**：篡改已签声明、回放旧声明、换 Issuer 身份。→ 被签名 + 日志阻断。
- **ATK-PROVIDER（模型层）**：Provider 自己选 W′ 并承诺，对外声称是已接受的 W。→ FlashProve 原文明确不防：*"The provider chooses the model. A yes does not say whose weights they are ..."*
- **ATK-RENEW（续接层，窄问题核心）**：旧 C₁ 已被接受；Provider 发布新 C₂（实际打开到 W₂），签声明 `same_model(C₁,C₂)`；日志完整记录该签名。→ 签名+日志**无法识别**虚假声明，因为签名只绑定声明文本，不绑定 C₂ 的底层权重。
- **ATK-BUDGET（容量层）**：利用"新承诺 = 新 ID、无链接"把模型降级/切换伪装成正常续接。→ 官方已承认：*"A renewal looks exactly like a switch to another model."*
- **ATK-NO-MISSING（外部事实层）**：真实世界更新未被记录、数据源造假。→ 与本轮无关；属 D3-15 H6/H7、D3-13 H4 同类，仍开放。

---

## 4. 信任假设清单（原文核对）

FlashProve 要求验证者信任而**任何调用都不检查**的内容（A3 原文）：
1. commitment ID（必须来自可信方，不来自被验证服务器）；
2. 期望的 acceptance policy 及其数值；
3. tokenizer 与 chat template；
4. `cp_verify` 本身。

FlashProve 对新承诺的条件（A5 原文，*"conditions that no program checks"*）：
- 新承诺用自己的、独立抽取的 seed 与 counters；
- 保持同一配置（含 scales）；权重事先固定；counter 从不复制/恢复。

**关键**：这些是"程序不检查"的设计条件。它们**保证**的是"若按设计做，两次承诺的是同一 W"这一**实现层事实**，但**不向验证者提供可验证的密码学证据**。这正是窄问题的位置。

---

## 5. 安全目标（形式化）

给定已被接受的旧承诺 C₁ 与新承诺 C₂，公开输入 `(C₁, C₂)`：

**R_eq(C₁, C₂)**：∃ W, r₁, r₂ 使 `Open(C₁, W, r₁) = 1 ∧ Open(C₂, W, r₂) = 1`，且 W 对验证者隐藏。

- **Soundness**：若 C₁、C₂ 打开到不同权重，任何（恶意）prover 使 verify 接受的概率可忽略。
- **Zero-Knowledge**：verify 除"相同/不同"外不泄露 W 与 opening 随机性。
- **Succinctness**：验证者不下载 W（原生需求，FlashProve route 4 为 232 GB）。

**必须区分的另一个关系（不要与 R_eq 混淆）**：

**R_update(C_old, C_new, policy)**：∃ W_old, W_new, Δ, data, r_old, r_new 使
`Open(C_old, W_old, r_old) = 1 ∧ Open(C_new, W_new, r_new) = 1 ∧ W_new = F_policy(W_old, data, Δ)`，
其中 F_policy 为允许的变换（梯度下降 / LoRA / 量化 / 剪枝 / 格式转换），须显式列出输入、允许变换、误差界与验证边界。

- Kaizen / VFT / zkLLMPoT 属 R_update 或其子集（见 RELATED-WORK.md），**不是 R_eq**。
- **相同权重 ≠ 模型功能等价**：同一 W 在不同配置/layout/scale 下可产生不同输出；不同 W 也可能功能等价。R_eq 只承诺底层权重向量相同，不承诺行为相同。FlashProve 自己的 `WITHIN LIMITS` 也只保证 checked tokens 满足策略。

---

## 6. 与本轮裁决直接相关的两条硬边界

1. **R_eq 的关系本身不新**：FlashProve 同 ID 内 leaf table 的 link proof 已在做 `∃W: Open(anchor,W,r₁) ∧ Open(leaf,W,r₂)`，且 Lean 证明 perfect HVZK（A7）。缺的不是关系，是**跨 ID 的可验证链接**与**在该链接上重述 soundness/ZK 定理**。
2. **续接的触发条件与 link proof 的资源条件冲突**：续接因 leaf table 的 688,127-batch 上限触发；而 link proof 每次要打开 anchor 的列（A5），anchor query bound 限制 leaf 数量。当"需要续接"时，旧承诺的开放性预算恰已接近耗尽——这是能否复用现有 link proof 机制的**结构性障碍**，不是简单工程参数。
