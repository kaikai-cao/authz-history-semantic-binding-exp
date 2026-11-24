# EXP-D3-07-B-P2 — 原始文献核验（References）

> 设计审计产物。本文只记录**原始规范/正式文档**中可定位的真实条款，不引用二手博客，不编造条款编号。
> 核验日期：2026-11-24。来源 URL 均为规范原文（CometBFT 仓库 spec 源、TUF spec 源、RFC Editor）。
> 对每条给出：具体章节/条款、原文实际规定、与本设计的对应关系、不适用或不能直接借用的部分。

## 1. Tendermint / CometBFT Consensus Specification

- **来源**：CometBFT 仓库 `spec/consensus/consensus.md`（原文 Markdown）。
  <https://github.com/cometbft/cometbft/blob/main/spec/consensus/consensus.md>
  （P1 的 `PROTOCOL-MODELS.md` 另列 Tendermint 文档 <https://docs.tendermint.com/master/spec/consensus/consensus.html> 作为思想参照。）

### 1.1 PoLC 定义（章节 `Terms`）

- **原文条款**："A set of +2/3 of prevotes for a particular block or `nil` at `(H,R)` is called a _proof-of-lock-change_ or _PoLC_ for short."
  同章："_+2/3_ is short for \"more than 2/3\""。
- **实际规定**：PoLC 是同一高度同一轮次、针对某区块（或 nil）的 +2/3 prevote 集合；+2/3 表示严格超过三分之二。
- **对应关系**：本设计 `polc` 定义为同一 `(chain_id,set_id,epoch)` 下同一 `r_p`、同一 digest 的 `Q=3`(of 4) prevote 集合；4 节点下 3-of-4 对应 >2/3。PoLC 作为解锁证据的定位一致。
- **不适用**：CometBFT 的 +2/3 按投票权（voting power）计，本设计按 Witness 数计（每 Witness 等权，f=1）；不可直接借用其权重模型。

### 1.2 解锁不等式（章节 `Prevote Step (height:H,round:R)`）

- **原文条款**："First, if the validator is locked on a block since `LastLockRound` but now has a PoLC for something else at round `PoLC-Round` where `LastLockRound < PoLC-Round < R`, then it unlocks." 随后："If the validator is still locked on a block, it prevotes that."
- **实际规定**：只有出现满足 `LastLockRound < PoLC-Round < R` 的冲突 PoLC 时才解锁；否则沿用自己的锁投票。
- **对应关系**：本设计锁转移不变量 `locked_round < polc_round < current_round` 与该句逐字对应（三个量一一映射）；"仍锁则投自己锁定的 digest"对应本设计"已锁冲突 digest 且无合格 PoLC 则拒绝改签"。
- **不适用**：CometBFT 的完整 prevote 步骤还含提案有效性、nil 投票等条件，本设计只取"锁与 PoLC 的轮次关系"一条结构。

### 1.3 Precommit 与重新锁定（章节 `Precommit Step (height:H,round:R)`）

- **原文条款**："If the validator has a PoLC at `(H,R)` for a particular block `B`, it (re)locks (or changes lock to) and precommits `B` and sets `LastLockRound = R`." "Else, if the validator has a PoLC at `(H,R)` for `nil`, it unlocks and precommits `nil`." "Else, it keeps the lock unchanged and precommits `nil`."
- **实际规定**：precommit 时基于**同一轮** `(H,R)` 的 PoLC 重新锁定；无 PoLC 则保持锁不变并 precommit nil。
- **对应关系**：本设计要求 precommit 必须观察到 `(r,C)` 的**精确同轮** PoLC（R1-B8：旧轮 PoLC 不复用），且写入 `locked_round=r`，与该规则一致。
- **不适用**：本设计没有 nil 投票语义（checkpoint 候选不是区块提案），故不实现"precommit nil"分支。

### 1.4 提案携带 PoLC 提示（章节 `Proposals`）

- **原文条款**："A proposal at `(H,R)` is composed of a block and an optional latest `PoLC-Round < R` which is included iff the proposer knows of one. This hints the network to allow nodes to unlock (when safe) to ensure the liveness property."
- **实际规定**：提案可携带 `PoLC-Round < R` 提示，帮助节点在安全时解锁以保证活性。
- **对应关系**：本设计 `PROPOSAL(r, C, polc_hint?)` 携带可选 `polc_round`，对应这一"解锁提示"机制；解锁仍须节点本地验证不等式。
- **不适用**：本设计不规定 proposer 选举算法（CometBFT 为"proportional to voting power 的 round robin"）。

### 1.5 安全性与活性证明（章节 `Proof of Safety` / `Proof of Liveness`）

- **原文条款（Safety）**："Assume that at most -1/3 of the voting power of validators is byzantine. If a validator commits block `B` at round `R`, it's because it saw +2/3 of precommits at round `R`. This implies that 1/3+ of honest nodes are still locked at round `R' > R`… at most -2/3 are available to vote for anything other than `B`."
- **原文条款（Liveness）**："If 1/3+ honest validators are locked on two different blocks from different rounds, a proposers' `PoLC-Round` will eventually cause nodes locked from the earlier round to unlock… `timeoutProposalR` increments with round `R`…"
- **实际规定**：Safety 依赖"至多 -1/3 byzantine 投票权"与锁交集论证；Liveness 依赖 proposer 最终携带更晚 PoLC-Round 与递增超时。
- **对应关系**：本设计 S-A 的鸽巢/交集论证结构对应 Proof of Safety；L-A 的"解锁需更高轮 PoLC"对应 Proof of Liveness。
- **不适用（重要）**：这些证明针对 CometBFT 完整协议与投票权模型，**本设计不继承**。本设计 f=1、等权、无完整 round-change，且明确不宣称 BFT soundness。CometBFT 的活性依赖递增 timeout，本设计刻意不把 timeout 当解锁证据（R1-C1），二者机制不同。

## 2. TUF — The Update Framework Specification（v1.0.37）

- **来源**：TUF 规范原文 `tuf-spec.md`，`Text Macro: VERSION 1.0.37`，Date 2026-10-08。
  <https://github.com/theupdateframework/specification/blob/master/tuf-spec.md>
- 规范声明关键词按 RFC 2119 解释（章节 `{#scope}`："The keywords \"MUST,\" … are to be interpreted as described in [RFC 2119]"）。

### 2.1 顶层角色与阈值（章节 `{#roles-and-pki}` / `{#root}` / `{#targets}`）

- **原文条款**："There are four fundamental top-level roles in the framework: Root role, Targets role, Snapshot role, Timestamp role. There is also one optional top-level role: Mirrors role." "All roles can use one or more keys and require a threshold of signatures of the role's keys in order to trust a given metadata file."
- **原文条款（Root）**："The client-side of the framework MUST ship with trusted root keys for each configured repository. The root role's private keys MUST be kept very secure and thus should be kept offline."
- **实际规定**：信任根是配置时内置的 root keys；每个角色需达到阈值签名才被信任；离线保存高权限密钥。
- **对应关系**：本设计 `witness_set` 来自受信任配置（非网络推断）对应"MUST ship with trusted root keys"；`Q=3` 阈值签名对应"threshold of signatures"。D3-07-A-R1 强制 4 Witness/3-of-4 profile 与"阈值不可调"精神一致。
- **不适用**：TUF 的角色分工（root/targets/snapshot/timestamp）针对软件更新分发，与本设计的 Witness/Gateway 角色不同构；不可照搬。TUF 的密钥轮换流程（章节引用 `[[#key-management-and-migration]]`）本设计未实现（对应未解决的"Witness set 轮换"问题）。

### 2.2 回滚与相关攻击目标（章节 `{#goals-to-protect-against-specific-attacks}`）

- **原文条款**："**Rollback attacks.** An attacker cannot trick clients into installing software that is older than that which the client previously knew to be available." "**Fast-forward attacks.** An attacker cannot arbitrarily increase the version numbers of metadata files…" "**Indefinite freeze attacks.** An attacker cannot respond to client requests with the same, outdated metadata without the client being aware of the problem." "**Mix-and-match attacks.** An attacker cannot trick clients into using a combination of metadata that never existed together…" "**Vulnerability to key compromises.** An attacker, who is able to compromise a single key or less than a given threshold of keys, cannot compromise clients."
- **实际规定**：TUF 的防护目标明确包含回滚、快进、无限冻结、混合匹配、低于阈值的密钥泄露。
- **对应关系**：
  - Rollback ↔ 本设计/D3-07-A 的本地 high-water anti-rollback（验证顺序第 7 步）；
  - Mix-and-match ↔ 本设计按 `set_id` 隔离投票、按完整 checkpoint 字段绑定（S3），防 P10 混合；
  - Key compromise ↔ f=1、Q=3 门限，单个 Witness 泄露不破坏 QC。
- **不适用（重要）**：TUF 的 freeze/rollback 防护依赖**版本号单调**和**元数据有效期**语义；本设计的 `epoch` 单调性与 freshness 是 checkpoint 链语义，不是 TUF 元数据版本。TUF 的"客户端总能检测到无法更新"不等于本设计能保证活性（P8-B 反例）。

### 2.3 目标声明中的可用性边界（章节 `{#goals-to-protect-against-specific-attacks}` 注释）

- **原文条款**："Note: When saying the framework protects against an attack, it means the attack will be unsuccessful. It does not mean that a client will always successfully update during an attack. Fundamentally, an attacker positioned to intercept and modify a client's communication can always perform a denial of service."
- **实际规定**：TUF 明确区分"防住攻击"与"保证可用"，不承诺 DoS 下可用。
- **对应关系**：与本设计 Safety/Liveness 分离、fail-closed 不等于活性达成的纪律一致（见 SECURITY-ARGUMENT §5）。
- **不适用**：TUF 不承担本设计的共识轮次问题。

## 3. RFC 9162 — Certificate Transparency v2.0

- **来源**：RFC Editor 原文 <https://www.rfc-editor.org/rfc/rfc9162.txt>（Laurie, Messeri, Stradling, December 2021, Experimental；Obsoletes RFC 6962）。

### 3.1 CT 的定位与日志审计边界（章节 `1. Introduction`）

- **原文条款**："The logs do not themselves prevent misissuance, but they ensure that interested parties… can detect such misissuance." "The log auditing mechanisms described in this document can be circumvented by a misbehaving log that shows different, inconsistent views of itself to different clients. Therefore, it is necessary to treat each log as a trusted third party. While mechanisms are being developed to address these shortcomings and thereby avoid the need to blindly trust logs, such mechanisms are outside the scope of this document."
- **实际规定**：CT 提供检测能力而非阻止；日志审计可被"分裂视图"绕过，需把日志视为可信第三方；解决分裂视图的机制**超出本文档范围**。
- **对应关系**：与本设计"QC 不等于 globally latest""Gateway 只有局部视图""首次接入依赖外部信任"一致——CT 原文同样承认分裂视图与信任假设的边界。
- **不适用（重要）**：RFC 9162 明确把"避免盲信日志"的机制列为 out of scope，因此**不能**从 RFC 9162 直接借用到本设计所需的"检测 quorum 共同旧视图/全局最新"能力。它提供的是边界清醒的对照，而非现成机制。

### 3.2 Merkle 包含性与一致性证明（章节 `2.1.3 Merkle Inclusion Proofs` / `2.1.4 Merkle Consistency Proofs`）

- **原文条款（目录可定位）**：`2.1.3 Merkle Inclusion Proofs`、`2.1.4 Merkle Consistency Proofs`；正文 `2.1.1 Definition of the Merkle Tree` 给出 `MTH({}) = HASH()`、`MTH({d[0]}) = HASH(0x00 || d[0])`、`MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`，并注明 "this domain separation is required to give second preimage resistance"。客户端消息 `5.4 Retrieve Merkle Inclusion Proof from Log by Leaf Hash`、`5.3 Retrieve Merkle Consistency Proof between Two STHs`。
- **实际规定**：包含证明证明某条目在日志中；一致性证明证明一版日志是另一版的追加超集；叶/节点哈希域分离防二原文攻击。
- **对应关系**：本设计未实现日志包含性证明；D3-07-A 未解决项含 "RFC6962 纳入"。若未来纳入，包含性/一致性证明可用于 checkpoint 历史的追加性校验。
- **不适用**：RFC 9162 的 Merkle 树用于证书日志条目，不是授权状态 checkpoint；域标签与条目格式不同，不能直接借用其哈希编码。P2 本轮不新增任何 Merkle 电路或 instance。

### 3.3 SCT / STH（章节 `4.8 Signed Certificate Timestamp` / `4.10 Signed Tree Head`）

- **原文条款（目录可定位）**：`4.8 Signed Certificate Timestamp (SCT)`、`4.10 Signed Tree Head (STH)`；`1. Introduction`："When a chain is accepted by a log, a signed timestamp is returned, which can later be used to provide evidence to TLS clients that the chain has been submitted."
- **实际规定**：SCT 是日志接受条目的签名凭证；STH 是日志树头的签名承诺。
- **对应关系**：与 D3-07-A 的 anchor（Ed25519 QC + state_root / policy_version 绑定）在"签名凭证 + 状态承诺"的结构上相似。
- **不适用**：SCT/STH 的安全模型依赖"日志为可信第三方"与 monitor/auditor 生态；本设计没有等价的全局 monitor/auditor，不能声称具备 CT 的检测保证。

### 3.4 客户端审计角色（章节 `8. Clients`，含 `8.2 Monitor` / `8.3 Auditing`；安全考量 `11.3 Misbehaving Logs`）

- **原文条款（目录可定位）**：`8. Clients`、`8.2 Monitor`、`8.3 Auditing`、`11.3 Misbehaving Logs`；`1. Introduction`："those who have seen signed timestamps from a particular log can later demand a proof of inclusion from that log. If the log is unable to provide this… that is evidence of the incorrect operation of the log. The checking operation is asynchronous…"
- **实际规定**：检测依赖 monitor 定期拉取、审计者验证包含性/一致性；检查是异步的，不构成实时最新性保证。
- **对应关系**：说明"全局一致性检测"需要独立审计生态与异步传播，呼应本设计"QC/PoLC 不证明全局最新""首次接入依赖外部信任"。
- **不适用**：本设计没有 CT 意义上的 monitor/auditor 角色；不能把 RFC 9162 的检测能力归为本协议已有性质。

## 4. 三份文献与本设计的关系总表

| 文献 | 可借用 | 不可直接借用 |
| --- | --- | --- |
| CometBFT consensus spec | `LastLockRound < PoLC-Round < R` 解锁结构；同轮 PoLC 重新锁定；提案带 PoLC 提示；Safety 交集论证结构 | 投票权模型、完整 round-change、递增 timeout 活性、slashing、安全证明 |
| TUF 1.0.37 | 配置内置信任根；阈值签名；回滚/混合匹配防护目标；安全≠可用边界 | 角色分工、元数据版本/有效期语义、密钥轮换流程、更新分发场景 |
| RFC 9162 | 分裂视图与信任边界的清醒声明；包含性/一致性证明作为未来纳入候选 | 日志可信第三方假设、monitor/auditor 生态、SCT/STH 安全模型、实时最新性 |

## 5. 核验方法说明

- CometBFT：读取仓库 `spec/consensus/consensus.md` 原文，逐字摘录 `Terms`、`Prevote Step`、`Precommit Step`、`Proposals`、`Proof of Safety`、`Proof of Liveness` 章节。
- TUF：读取 `tuf-spec.md` 原文（`VERSION 1.0.37`），摘录 `{#scope}`、`{#roles-and-pki}`、`{#root}`、`{#targets}`、`{#goals-to-protect-against-specific-attacks}` 章节；长文前 15000 字符已覆盖这些章节。客户端验证流程的具体条款编号**未在本次摘录范围内**，故本文不引用其编号（避免编造）。
- RFC 9162：读取 RFC Editor 原文，摘录目录章节编号与 `1. Introduction` 正文；`2.1.3/2.1.4/4.8/4.10/8.2/8.3/11.3` 的编号来自官方目录，正文细节未逐字展开处已注明"目录可定位"。
- 未使用二手博客；未根据记忆编造条款编号。
