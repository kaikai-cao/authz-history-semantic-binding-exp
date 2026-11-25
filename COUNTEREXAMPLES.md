# COUNTEREXAMPLES.md — 三个场景、关系定义与七问审计

日期：2026-11-25。目标：验证窄问题，而不是替原 C1 找理由。

---

## 场景 A：传统密码学已经足够

**设定**：模型发行者可信。发行者签署
`Statement = (old_commitment=C₁, new_commitment=C₂, same_model, version, timestamp)`，
写入透明日志；验证者查 inclusion proof + 身份。

**可验证证据**：
- RFC 9943 §9.2：*"registering a Statement only proves it was produced by an Issuer."*
- sigstore/model-transparency：签名 + DSSE/in-toto + 文件清单哈希 + OIDC + append-only log。

**判断**：
- ✅ 普通版本管理（V1/V2/V3 记录、谁发布、防事后篡改、版本声明关系）全部满足。
- ❌ 但只能证明"某 Issuer 声称 C₂ 与 C₁ 同模型"，不能证明该声称的底层权重为真。

**裁定**：**该类需求不需要 ZK。** 原 C1 若按"普通版本谱系"定义，应在此停止。

---

## 场景 B：签名与日志不足（窄问题核心）

**攻击者能力**：恶意更新方持有 W₁、W₂，能签任意声明，能操作日志写入（但不破坏日志 append-only 完整性）。

**历史**：
1. 验证者已从可信锚接受 C₁，对应 W₁；
2. 更新方发布 C₂，底层实际打开到 W₂ ≠ W₁；
3. 更新方签 `same_model(C₁, C₂)` 并写入透明日志；
4. 日志完整记录该签名声明。

**验证者能否识别虚假声明**：
- 用签名 + 日志：❌ **不能**。RFC 9943 §9.2 明说 Issuer 可有意或无意作虚假声明；签名只绑定声明文本，不绑定 C₂ 的 opening。
- 用 FlashProve 原生机制：❌ **不能**。A4 原文：*"Between two IDs there is no proof ... you have only the provider's word."*
- 用配置比对 + 提示重放：⚠️ 只能抽样，官方明说不能由相等文件/回复推出未变（A4）。
- 用公开权重重算 ID：✅ 能，但要求公开 W 与 232 GB 下载，违背权重隐藏与简洁性。

**构造零知识证明**：
- 关系：`R_eq(C₁, C₂) = 1 ⇔ ∃ W, r₁, r₂ : Open(C₁, W, r₁) = 1 ∧ Open(C₂, W, r₂) = 1`（公开输入仅 C₁、C₂；W 隐藏）。
- 若 verify 接受，且承诺方案 binding、证明 sound，则 C₁、C₂ 打开到同一 W → 虚假声明被拒。

**ZK 解决了什么**：在**不公开 W、不下载 W** 的前提下，把"两个承诺同一权重"从"声明"升级为"可验证关系"。

**保留的信任假设（不得省略）**：
1. C₁ 本身确实对应被接受的 W₁（来源锚定仍外部，D3-15 同构问题）；
2. 承诺方案的 binding 与证明的 soundness（FlashProve 只对 Lean verifier 有定理，C++/CUDA 程序只有测试）；
3. 验证者从可信方拿到两个 C_id（README 硬要求）；
4. 新承诺的设计条件（独立 seed/counters、同配置、权重先固定）需以协议/流程约束，程序不检查。

**结论**：窄问题在场景 B 中确实存在，且非 ZK 不能满足——但**仅当**"权重隐藏 + 不可信更新方 + 跨 ID"三者同时成立。

---

## 场景 C：正常模型更新必须与"同一权重"分开

| 情况 | 正确关系 | 说明 |
|---|---|---|
| 重新承诺但权重不变 | `R_eq(C₁, C₂)` | 本轮窄问题；同 W、不同随机性 |
| 正常 fine-tuning | `R_update(C_old, C_new, F_gd)` | Kaizen 的梯度下降轨迹；F 须含数据集承诺 |
| LoRA / Adapter 更新 | `R_update(C_old, C_new, F_lora)` | VFT 的 PEFT 电路；不允许推广为"任意更新" |
| 量化 / 剪枝 / 格式转换 | `R_update(C_old, C_new, F_quant/prune)` | 需明确容差与验证边界；FlashProve 自身只证整数模型 |

**明确禁止的混淆**：
- `R_eq` ≠ `R_update`：前者是同一 W 的两个 opening，后者是 W_old → W_new 的变换。
- **相同权重 ≠ 模型功能等价**：同一 W 用不同配置/scale 可给出不同输出；不同 W 也可能功能等价。R_eq 不承诺行为相同。
- 不能给一个哈希链就声称证明了模型更新正确性（任务包明确要求）。

---

## 关系定义（正式）

公开输入：`C_old, C_new`（可选 `policy`, `epoch`, `version`）。
私有见证：`W, r_old, r_new`（更新时另加 `data, Δ`）。

```
R_eq(C_old, C_new) = 1 ⇔ ∃ W, r_old, r_new :
    Open(C_old, W, r_old) = 1 ∧ Open(C_new, W, r_new) = 1

R_update(C_old, C_new, policy) = 1 ⇔ ∃ W_old, W_new, data, Δ, r_old, r_new :
    Open(C_old, W_old, r_old) = 1 ∧ Open(C_new, W_new, r_new) = 1 ∧
    W_new = F_policy(W_old, data, Δ)
```

- `F_policy` 必须逐项列出：允许变换集合、输入格式、误差界、验证边界。
- 若研究的是"承诺续接"而非"模型更新"，只能声称为 R_eq；不得用 R_update 文献（Kaizen/VFT/zkLLMPoT）替代。

---

## 方案比较（Phase 3 要求）

| 方案 | 必须研究的性质 | 对 R_eq（跨 ID、隐藏权重） |
|---|---|---|
| 签名 + 透明日志 | Issuer 身份、声明历史 | ❌ 只证声明产生，不证内容 |
| 哈希链 | 历史完整性 | ❌ 只链声明字节 |
| Merkle/向量承诺 | 版本数据绑定 | ✅ 代数型可行（CP_link）；⚠️ 需 Pedersen 前提 |
| TEE | 硬件信任执行证明 | ⚠️ 仅当 TEE 同时持有 W 作证；信任转移 |
| Kaizen | 增量式训练正确性 | ❌ R_update，非 R_eq |
| CP-Link / CP-NIZKs | 不同承诺 witness 等值 | ✅ 一般情形已解；❌ 不适配 FlashProve 非代数承诺 |
| 通用 SNARK | 隐藏权重下的任意关系 | ✅ 理论可表达；❌ 可行性/成本无原文证据 |

---

## 七必答问题（Phase 3 §3）

**Q1 不可信更新方是否是现实需求？**
部分。FlashProve 的 provider 本就"选择模型"（A2），且续接由容量/硬件/配置变化强制（A4）；但用户材料中**没有**给出真实部署中"更新方不可信且与承诺方分离"的实例。它是合理威胁模型，不是已证实的普遍部署事实。

**Q2 模型权重隐藏是否必要？**
对 FlashProve 是核心（README 首句），且 232 GB 下载不现实。是必要约束。

**Q3 签名+日志为什么不能满足该威胁模型？**
RFC 9943 §9.2 原文：注册只证明声明由 Issuer 产生；Issuer 可作虚假声明。签名绑定的是声明文本，不是 C₂ 的 opening。

**Q4 CP-Link 是否已经解决核心问题？**
**一般情形已解决**（LegoSNARK §4.1 `Com.VerCommit = Ped.VerCommit`），但**不能直接适配** FlashProve 的 BLAKE2b Merkle + RS 编码承诺。需注意：用户给的 2024/1209 / Springer DOI 是 Collaborative CP-NIZKs（用 CPlink 作构件），不是 CP_link 原始文献。结论：既不能说"空白"，也不能说"直接解决"。

**Q5 若用 FlashProve 哈希型承诺，是否需要特定跨承诺关系证明？**
需要——如果坚持跨 ID。但存在结构性障碍：link proof 每次打开 anchor 的列，而 anchor 的 query bound 限制 leaf 数量；续接触发时旧承诺开放性预算接近耗尽；ZK 定理明确 *"a second commitment → nothing"*（A6）。这不是"加一个电路"能绕过的，需重述 soundness/ZK 定理。

**Q6 证明成本是否随模型规模增长到不可接受？**
无法给出可信的正面答案。通用 SNARK 需把 BLAKE2b + 距离测试 + 全模型线性 claim 放进电路；FlashProve 全规模 route 4 需 330 GB RAM、232 GB 权重。本轮无原型、无成本原文证据。按"不把理论可表达性当实际可行性"的验收标准，**不能声称有竞争力**。

**Q7 是否有更简单的持久承诺/轮换设计消除问题？**
有若干非 ZK 路径：① 初始 `cp_commit` 一次性预留足够 leaf tables（A5 原文要求预先决定生命周期用量）；② 公开权重 + seed 重算 ID（A4 例外）；③ 可信 vouching party 发布新 ID 并承担声明责任（场景 A）。这些不能在所有情况下消除恶意更新方问题，但显著降低"必须做跨 ID ZK 证明"的场景密度。

---

## 反例可验证性自检

- [x] 场景 A 明确裁定"不需要 ZK"，未为凑贡献保留。
- [x] 场景 B 的 false-safe 路径给出可回溯原文（RFC 9943 §9.2、FlashProve A4）。
- [x] 场景 C 区分 R_eq/R_update 与"相同权重/功能等价"。
- [x] 正面比较 CP-Link 与 Kaizen（Q4 与 RELATED-WORK §2/§5）。
- [x] 不把作者限制当数学证明；不把预印本数字当独立验证结果。
