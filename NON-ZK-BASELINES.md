# NON-ZK-BASELINES.md — 传统密码学替代方案及能力边界

日期：2026-11-25。口径：先给方案能证明什么，再给不能证明什么；不把"作者声明"当数学证明。

---

## 1. 签名 + 透明日志

**构造**：发行者对 `(old_commitment, new_commitment, same_model, version, timestamp)` 签名；写入 append-only log；验证者查 inclusion proof 与 Issuer 身份。

**能证明**：
- 该声明由某 Issuer 产生（RFC 9943 §9.2 逐字：*"registering a Statement only proves it was produced by an Issuer."*）；
- 声明未被事后篡改；日志可发现同一 Issuer 的相互矛盾声明。

**不能证明**：
- Issuer 的声明为真（同条原文：*"Issuers can make false Statements either intentionally or unintentionally"*）；
- C₂ 底层权重 = C₁ 底层权重。

**对本轮的意义**：场景 A（可信发行者）足够；场景 B（恶意更新方）**不足**。这是 RFC 9943 明文边界，不是我们的推测。

---

## 2. Sigstore 模型签名 / in-toto / Rekor

**构造**：对模型文件清单 `(file path, digest)` 签名（DSSE envelope + in-toto statement），OIDC 身份，Sigstore append-only log。

**能证明**：*"the model hasn't been tampered with after training"*（项目 README 原话）——即下载到的文件与训练后签名时的文件一致；签名者身份来自已知/可信 identity；签名事件在 log 中可发现。

**不能证明**：
- 训练过程正确、数据来源真实（属 Kaizen/VFT 范围，且 Kaizen 也只证计算）；
- 两个不同哈希/承诺 ID 对应同一权重——除非把权重文件公开让验证者逐文件重算，而这与"权重隐藏"冲突；
- RFC 9943 §9.2 的一般限制同样适用。

**与本轮关系**：这是"普通版本谱系"的成熟路线，覆盖用户列出的 V1/V2/V3 记录、发行者签名、防事后篡改、版本声明关系。**裁定：该类需求不需要 ZK。**

---

## 3. 哈希链

**能证明**：序列未被回改（若起点可信）；链接结构完整。

**不能证明**：链上每项内容相对真实世界为真；"链中 C₂ 与 C₁ 同权重"这一关系——哈希链只绑定**声明字节**，不绑定承诺打开到的 witness。

---

## 4. Merkle / 向量承诺（代数型，如 Pedersen）

**能证明**：承诺绑定某个向量；在不 threaten 隐私下可证明两个承诺打开到同一向量（CP_link，LegoSNARK §4.1，条件 `Com.VerCommit = Ped.VerCommit`）。

**不能证明**：承诺里的权重是"真实模型"；承诺方案本身来自可信来源——这与 D3-15 的 root authenticity 同构。

**关键不适配**：FlashProve 的承诺是 BLAKE2b Merkle + Reed–Solomon 编码 + OOD 掩码（A3/A5/A6），验证算法不是 Pedersen 型线性同态。`CP_link` 的前提 `Com.VerCommit = Ped.VerCommit` 不成立 → **不能直接套用**。若强行用通用 SNARK 模拟两个哈希承诺的 opening 验证，需把 BLAKE2b + 距离测试/线性 claim 全部放进电路，成本随模型规模增长，没有原文证据表明可行或有竞争力（见 Phase 3 Q6）。

---

## 5. TEE

**能证明**：在硬件信任假设下，某程序在某 enclave 内运行（I-EIB / TRACE / SPICE draft-mw-spice-inference-chain-00 均提出或引用）。

**不能证明**：
- 无硬件后门、无侧信道（依赖硬件信任）；
- 两个不同承诺同一权重——除非 TEE 内部同时持有 W 并对外作证，此时信任从"密码学"移到"硬件厂商 +  attest 流程"。

**与本轮关系**：SPICE draft 明示 ZKML + TEE 双机制（相邻草案，已过期）；I-EIB/TRACE 的细节见 D3-14 审计，均为边界内完整性，不解决跨承诺同一性。

---

## 6. 扩展承诺寿命（非密码学设计取舍）

FlashProve 自身提供两条不需 ZK 的续接路径：

1. **公开权重 + 已发布 seed**（A4 原文例外）：*"anyone who has the weight files and makes the calibration set can make that commitment again and compare the ID."* → 验证者可独立重算 C₂ 的 ID 并比较。代价：权重必须公开，违背"权重隐藏"约束，route 4 还涉及 232 GB 下载。
2. **配置比对 + 提示重放抽样**（A4 原文）：三份配置文件 byte-for-byte 比对；对保留的 prompts 在新 ID 下重放比对 token。→ 只能覆盖抽样点，官方明说 *"from equal files and replies, do not conclude that it has not [changed]."* 非完备证明。
3. **从源头避免过度续接**（A5 原文）：leaf table 数量在 `cp_commit` 一次性决定、不能后加（*"decide how many the commitment will need over its whole lifetime"*）；可通过预留足够 leaf tables 把续接需要推迟。这是**工程容量规划**，不是密码学保证，且不改变"跨 ID 无证明"的事实。

---

## 7. 基线能力汇总表

| 方案 | Issuer 身份 | 声明历史 | 版本数据绑定 | 跨承诺同权重（权重隐藏下） | 主要信任成本 |
|---|---|---|---|---|---|
| 签名 + 透明日志 | ✅ | ✅ | 声明层 ✅ | ❌ | Issuer 诚实 |
| Sigstore/in-toto | ✅ | ✅ | 文件哈希 ✅ | ❌（需公开文件重算） | OIDC + log |
| 哈希链 | ❌ | ✅ | 声明层 ✅ | ❌ | 起点可信 |
| Pedersen/CP_link | — | — | 向量 ✅ | ✅（代数承诺） | Pedersen 型承诺 + setup |
| TEE | ✅（attest） | 部分 | 运行时 ✅ | 仅当 TEE 持有并作证 | 硬件厂商 |
| 公开权重重算 ID | ✅ | ✅ | ✅ | ✅ | 权重公开（违背隐私） |
| FlashProve link proof（同 ID） | 由 C_id 锚定 | 同 ID 内 | ✅ 同权重不同随机性 | **仅同 ID**；跨 ID 无 | ID 来源可信 |

**结论**：在"权重隐藏 + 不可信更新方 + 跨 ID"三者同时成立时，所有非 ZK 基线失败。这是窄问题成立的最小条件集。
