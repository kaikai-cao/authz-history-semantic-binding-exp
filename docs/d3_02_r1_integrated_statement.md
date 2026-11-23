# EXP-D3-02-R1-04 — 端到端集成语句与证明关系

**基线**：`98906dd1f94f7d9922f7759989f896c418c85561`
**分支**：`exp-d3-02-r1`
**性质**：设计修订。把 R1-01（Anchor Bridge）、R1-02（Canonical Slot）、R1-03（Policy Binding）
组合为一个完整可审查接口。**本轮不实现电路。**

---

## 0. 三修订如何咬合

三项修订不是三个孤立补丁，它们共享同一条信任链：

```
D2-B anchor A_e ──Bridge(R1-01)──> C_prev ──┐
                                            ├──> π_trans ──> GR_next/RR_next ──> D2-A π_path ──> fencing ──> ALLOW
可信布局(R1-02) ──> slot witness ───────────┤
                                            │
vk 注册表(R1-03) ──> policy_id + vk_hash ───┘
```

- R1-01 决定 `C_prev` 的语义与来源（Poseidon of 完整状态元组 + 签名 Bridge）。
- R1-02 决定槽位布局谁负责（外部签名，电路只验给定布局下的路径）。
- R1-03 决定策略身份如何防混淆（电路常量 + 独立 vk + 注册表）。

三者共同回答了"Halo2 证明的状态如何与真实、可信、规范、符合特定策略的外部状态建立关系"：
**可信性来自 D2-B/Bridge 的签名链，规范性来自布局签名，策略身份来自 vk 注册表；
电路只在这些外部锚点之间证明语义正确与双根更新正确。**

---

## 1. 最终公开输入（重审 D3-02 的 8 字段）

任务书允许重审。相对 D3-02 的 8 字段，本轮**新增 3 个字段、语义修订 2 个**：

```rust
/// EXP-D3-02-R1 最终公共输入（仅设计，本轮不实现）
pub struct TransitionPublicInputs {
    // ---- 前状态：来自 R1-01 的认证 Bridge，Poseidon 承诺（语义已修订）----
    pub previous_state_commitment: Field,      // C_prev = Poseidon(D3-STATE-P-v2, GR, RR, epoch, policy_id)
    pub previous_anchor_digest: Hash32,        // 新增：A_e，网关核对 checkpoint 用（32B，非 Field）
    pub previous_epoch: u64,                   // fencing 高水位；与 Bridge epoch 一致
    // ---- 布局规范性：来自 R1-02 的可信布局签名 ----
    pub layout_digest: Hash32,                 // 新增：CanonicalLayoutStatement.assignment_digest
    // ---- 结果状态：供冻结 D2-A 电路消费 ----
    pub next_grant_root: Field,                // GR_next
    pub next_revoke_root: Field,               // RR_next
    pub next_epoch: u64,                       // epoch_next
    // ---- 批次绑定：Poseidon 承诺（语义不变）----
    pub event_batch_commitment: Field,         // D_E = Poseidon(D_BATCH, n, c_1..c_n)
    pub event_count: u32,                      // n，容量/审计
    // ---- 策略身份：来自 R1-03 ----
    pub policy_id: Field,                      // 语义已修订：结构化 policy_id（含 circuit_spec_digest）
    pub vk_hash: Hash32,                       // 新增：验证密钥指纹，网关查注册表
}
```

**字段总数 11**（D3-02 为 8）。新增的三个字段都不是安全增强电路本身，而是**把上一轮隐含的
外部信任显式化为可审计的公共输入**——网关必须把它们与可信数据比对，否则等于没有信任锚。

### 1.1 字段逐项：公开/私有、生成者、认证者、电路用途、网关检查、防重放

| 字段 | 公开/私有 | 生成者 | 认证者 | 电路如何使用 | 网关检查 | 是否防重放 |
| --- | --- | --- | --- | --- | --- | --- |
| `previous_state_commitment` | 公开 | Bridge Service（R1-01） | Bridge quorum 签名 + D2-B 验证器 | 开承诺 `C_prev == Poseidon(D_STATE,GR_prev,RR_prev,prev_epoch,policy_id)` | 与 BridgeStatement.poseidon_state_commitment 比对 | 部分：更新 epoch/anchor 使其失效 |
| `previous_anchor_digest` | 公开 | D2-B 验证器输出 | D2-B QC | 不进电路（32B 字节，电路只消费其 Poseidon 衍生物） | checkpoint 中的 anchor digest + QC 验签 + log inclusion | ✅ 旧 anchor 不等于当前 checkpoint |
| `previous_epoch` | 公开 | Bridge Statement | Bridge 签名 | 进入 `C_prev` preimage；单调链起点 | 本地 epoch 高水位（F01–F06） | ✅ 回滚检测 |
| `layout_digest` | 公开 | 布局服务（R1-02） | 布局 quorum 签名 | 作为公开承诺，网关核对（电路不验签） | 重算 `canonical_assignment` 比对 + 布局签名 | ✅ 含 nonce/epoch |
| `next_grant_root` | 公开 | 电路 witness 输出 | 电路（路径重算约束） | 与最后一步 GR 中间根 copy constraint | 与可信 checkpoint 的下一状态比对（可选）+ D2-A instance | 自身不防，靠前状态锚 |
| `next_revoke_root` | 公开 | 同上 | 电路 | 同上 | 同上 | 同上 |
| `next_epoch` | 公开 | 电路 witness | 电路（单调 + 承诺） | `epoch_prev ≤ epoch_i ≤ epoch_next` | 下一轮 anchor 输入 + fencing | 单调防回退 |
| `event_batch_commitment` | 公开 | 可信批次来源 | 批次来源对完整事件字节算 Poseidon 承诺 | `D_E == Poseidon(D_BATCH,n,c_1..c_n)` | 与 D1-E 日志 batch digest 来源比对 | ✅ 不同批次承诺不同 |
| `event_count` | 公开 | 批次来源 | 同上 | `n ≤ N_MAX` 容量检查 | 审计覆盖事件数 | 间接（进 D_E） |
| `policy_id` | 公开 | 冻结规范计算（R1-03） | vk 注册表 + 电路 fixed 常量 gate | 电路 gate `policy_id_pub == policy_id_const` | 查注册表 entry.policy_id + Bridge policy_spec_digest | ✅ 版本回滚换 id |
| `vk_hash` | 公开 | 验证端从所用 vk 计算 | vk 注册表 | 不进电路（元数据） | `registry[vk_hash]` 存在且 active，且 policy_id 匹配 | ✅ 旧 vk 标 inactive |

**关键设计点**：`previous_anchor_digest` 与 `vk_hash` 是 `Hash32`（字节），不进电路 instance；
它们由网关/验证端在电路外核对。把它们列为 public input 结构的一部分，是为了**接口完整性**
（验证者必须拿到它们），不是因为它们都进入 Halo2 instance 列。

### 1.2 与 D3-01 `StateTransitionStatement`（9 字段）的映射

| D3-01 字段 | R1 最终处理 |
| --- | --- |
| `previous_grant_root` / `previous_revoke_root` | 改为**私有 witness**，由 `C_prev` Poseidon 开承诺锁定 |
| `previous_epoch` | 保留公开 |
| `next_grant_root` / `next_revoke_root` | 保留公开 |
| `next_epoch` | 保留公开 |
| `event_batch_digest`（SHA-256） | 替换为 Poseidon `event_batch_commitment` |
| `event_count` | 保留 |
| `policy_digest`（`SHA256(code)`） | 替换为结构化 `policy_id` + `vk_hash` |
| —— | **新增** `previous_anchor_digest`、`layout_digest`（外部信任显式化） |

---

## 2. 私有 Witness（至少覆盖）

```
pub struct TransitionWitness {
    // ---- 前后状态树 ----
    pub grant_tree_prev: SparseMerkleTree,    // d=4，含 slots + assigned 映射
    pub revoke_tree_prev: SparseMerkleTree,
    pub grant_tree_next: SparseMerkleTree,
    pub revoke_tree_next: SparseMerkleTree,
    pub gr_prev: Field, pub rr_prev: Field,   // C_prev 开承诺的 preimage
    // ---- 事件批次 ----
    pub events: Vec<Event>,                    // e_1..e_n，n ≤ N_MAX（原型 2 grant + 1 revoke）
    pub event_commitments: Vec<Field>,         // c_i = Poseidon(D_EVENT, type, fields...)
    // ---- Merkle 路径与中间状态 ----
    pub gr_paths: Vec<MerklePath>,             // 每步每条事件的 d 层兄弟节点
    pub rr_paths: Vec<MerklePath>,
    pub inter_gr_roots: Vec<Field>,            // 每步中间 GR 根
    pub inter_rr_roots: Vec<Field>,
    pub parent_paths: Vec<MerklePath>,         // Parent Binding 用（打开到中间 GR）
    // ---- 布局信息（R1-02）----
    pub slots: Vec<(Hash32, usize)>,           // 本次涉及 id 的槽位（witness 提供，不证规范性）
    pub assigned_snapshot: BTreeMap<Hash32, usize>, // 完整映射快照，供网关重算 assignment_digest
    // ---- 策略（R1-03）----
    pub policy_params: PolicyParameters,       // scope/resource/epoch 参数的 witness 展开
    // ---- freshness / 一次性（外部核对）----
    pub bridge_nonce: [u8; 16],
    pub layout_nonce: [u8; 16],
}
```

**witness 生成者**：证明者（可能是不可信的状态服务）。电路对语义与双根更新做约束，
对布局规范性、anchor 来源、策略身份**不做独立证明**（由外部签名承担，见 §4）。

---

## 3. 完整证明关系 R(x, w) = 1

`x` = §1 公共输入，`w` = §2 私有 witness。拆分八个子关系，逐项标注分类：

### 3.1 Anchor Bridge Binding — `IN_CIRCUIT`（开承诺） + `EXTERNAL_TRUST`（A_e 来源）

```
IN_CIRCUIT:   C_prev == Poseidon(D3-STATE-P-v2, GR_prev, RR_prev, previous_epoch, policy_id)
EXTERNAL_TRUST:
    - previous_anchor_digest 来自 D2-B QC 认证的 checkpoint（验签 + log inclusion + freshness）
    - Bridge 签名覆盖 (A_e, C_prev, 完整状态元组, checkpoint_hash, 域标签版本, nonce, expires_at)
    - 网关核对 BridgeStatement.poseidon_state_commitment == C_prev
```
电路**不**验证 SHA-256、不验签、不验 checkpoint。丢失任何外部检查 → R01/R02 攻击成功。

### 3.2 Canonical Slot Validation — `OFF_CIRCUIT`（规范性） + `IN_CIRCUIT`（给定布局下的路径）

```
IN_CIRCUIT:   slot_i < 2^d；叶子写入 slot_i 后 d 层 node_hash 重算 → 对应中间根
OFF_CIRCUIT / EXTERNAL_TRUST:
    - 布局服务执行 canonical_assignment(ids, d) 并对 assignment_digest = layout_digest 签名
    - 网关/审计者独立重算 canonical_assignment 并比对 layout_digest
    - 电路不证明 "layout == canonical_assignment(ids)"
```
R07/R08 在电路层**接受**，在布局验证器/网关层拒绝（见 R1-02 §5.1）。

### 3.3 Policy Binding — `IN_CIRCUIT`（常量 gate） + `EXTERNAL_TRUST`（vk 注册表）

```
IN_CIRCUIT:   policy_id (public) == policy_id_const (fixed 列)   // 该电路硬编码策略
EXTERNAL_TRUST:
    - registry[vk_hash] 存在且 active
    - registry[vk_hash].policy_id == policy_id
    - registry[vk_hash].circuit_spec_digest == 冻结规范 digest
    - BridgeStatement.policy_spec_digest == policy_id
```
R06/R09 的最终拒绝点在网关注册表层（见 R1-03 §5）。

### 3.4 Event Semantic Validation — `IN_CIRCUIT`

```
∀i: type ∈ {1,2}; grant_id ≠ 0; scope_child & ~scope_parent == 0;
     前 8 字节 resource 前缀相等; parent 存在且 valid_flag=1; issuer == parent.subject;
     epoch 单调; revoker == issuer; 目标未撤销; 无重复撤销
```
沿用 D3-02 电路规格 §2.1–2.7，`valid_flag` 专用列 + `s_not_revoked` 门（D2-A-R1 教训）。

### 3.5 Grant Tree Update — `IN_CIRCUIT`

```
leaf_new = Poseidon(D_GRANT, id, issuer, subject, resource, scope, parent, epoch, valid_new)
node_l   = Poseidon(D_NODE, select(path_left[l], node_{l+1}), select(path_right[l], node_{l+1}))
node_0   == GR_next（末步）或 GR_i（中间）
```

### 3.6 Revocation Tree Update — `IN_CIRCUIT`

```
leaf_new = Poseidon(D_REVOKE, id, revoker, epoch)；同理 d 层路径 → RR_next
```

### 3.7 Batch Commitment — `IN_CIRCUIT`（重算） + `EXTERNAL_TRUST`（来源）

```
IN_CIRCUIT:   D_E == Poseidon(D_BATCH, n, c_1, ..., c_n); n ≤ N_MAX; c_i 顺序固定
EXTERNAL_TRUST: D_E 来自对完整事件字节计算 Poseidon 承诺的可信批次来源（D1-E 日志）
```

### 3.8 State Transition Binding — `IN_CIRCUIT`

```
epoch_prev ≤ epoch_1 ≤ ... ≤ epoch_n = epoch_next
GR_n == next_grant_root; RR_n == next_revoke_root
（前状态已由 3.1 开承诺绑定）
```

### 3.9 汇总表

| 子关系 | IN_CIRCUIT | OFF_CIRCUIT | EXTERNAL_TRUST |
| --- | --- | --- | --- |
| 3.1 Anchor Bridge | C_prev 开承诺 | SHA-256 计算 | A_e/checkpoint/Bridge 签名 |
| 3.2 Canonical Slot | 给定布局路径更新 | 布局规范性签名+审计 | 布局 quorum |
| 3.3 Policy | policy_id 常量 gate | —— | vk 注册表 |
| 3.4 Event 语义 | 全部规则 | —— | —— |
| 3.5/3.6 双树更新 | 叶子+路径 | —— | —— |
| 3.7 Batch | 承诺重算 | —— | 批次来源 |
| 3.8 State Binding | 单调+结果绑定 | —— | —— |

**没有**把任何安全关键检查（scope/parent/revoke/双根/开承诺/policy 常量）悄悄移到链下而不写明。

---

## 4. 网关集成检查清单（验证者必须执行，否则信任锚失效）

```
1. D2-B 验证器: verify(cp, QC, AnchorRecord, freshness) → 可信 A_e
2. Bridge 验证器: verify(SignedBridgeStatement, 配置公钥/阈值/期望域版本/非过期/nonce 未用)
3. 交叉: BridgeStatement.anchor_digest == A_e; checkpoint_hash 匹配; poseidon_state_commitment == C_prev
4. 布局验证器: verify(CanonicalLayoutStatement 签名); 独立重算 assignment_digest == layout_digest
5. vk 注册表: registry[vk_hash] active 且 policy_id 匹配且 circuit_spec_digest 是冻结值
6. Halo2: verify(vk, public_inputs, π_trans)   // 电路 gate 保证 policy_id 常量+语义+双根
7. epoch 高水位/freshness: previous_epoch/next_epoch 与本地高水位比对，provider 不可用 fail-closed
8. 结果状态: GR_next/RR_next 作为 D2-A π_path 的 instance（ALLOW 证明）
9. 执行时 fencing: 短 TTL 令牌 + 版本 CAS（D3-02 security §2.4），DENY fail-closed
```

任一步失败即拒绝。**步骤 1–5 全在电路外**；证明有效（步骤 6）不等于状态正确。

---

## 5. R01–R10 攻击测试设计

测试层级缩写：**MP** = Halo2 MockProver；**RP** = 真实 proof/verifier；**BV** = Anchor Bridge 验证器；
**GV** = 网关集成测试；**LV** = 布局验证器；**VK** = vk 注册表检查。

| 编号 | 攻击 | 预期 | 测试层级 | 关键说明 |
| --- | --- | --- | --- | --- |
| R01 | 旧 SHA-256 Anchor 搭配新 Poseidon 状态 | 拒绝 | BV + GV（步骤 1/3） | Bridge 内部 `A_e = SHA256(encode(s))` 校验失败；网关核对 anchor_digest ≠ 当前 checkpoint。电路层无法发现 |
| R02 | 新 Anchor 搭配旧 Bridge | 拒绝 | BV + GV（步骤 2/3） | BridgeStatement.anchor_digest / checkpoint_hash / nonce 与当前不符；验签或新鲜性失败 |
| R03 | 修改 Bridge 中的 GR/RR | 拒绝 | MP（开承诺失败）+ BV（验签失败）+ GV | 电路内 `C_prev == Poseidon(...GR/RR...)` 不等；Bridge 签名覆盖状态元组 |
| R04 | 修改 Bridge epoch | 拒绝 | MP（`C_prev` 不等 + 单调链起点冲突）+ BV + GV | epoch 在 C_prev preimage 与 Bridge 签名内 |
| R05 | 修改策略 ID | 拒绝 | MP（`policy_id==const` gate）+ RP（verifier 拒绝）+ BV + VK + GV | prover 可能出 proof 但 verifier 拒绝——沿用 D2-A-R1 诚实口径，不写成 create_proof 失败 |
| R06 | DirectOnly 电路声称 Cascade | 拒绝 | MP + RP + VK + GV | `vk_DO` 内 const=DO，填 CAS 值 gate 失败；注册表 vk_hash=DO 但 statement 称 CAS |
| R07 | 非规范槽位分配 | **电路层接受**；布局验证器+网关拒绝 | MP（**接受**，诚实记录）+ LV + GV | 电路不证布局规范性；这是 R1-02 的明确信任边界，绝不写成"电路拒绝" |
| R08 | 删除后以不符合规范的槽位重新插入 | **电路层接受**；布局验证器+网关拒绝 | MP（**接受**）+ LV + GV | 同上；若篡改布局使路径仍自洽，电路接受 |
| R09 | 跨策略验证密钥重放 | 拒绝 | **VK + GV**（RP 层可能接受） | 用 `vk_CAS` 验一个 DO 证明，两 vk 各自自洽 → verifier 可能接受；只靠注册表 policy_id 不符拒绝。必须诚实写"电路/verifier 层可能接受" |
| R10 | 旧 Bridge 重放 | 拒绝 | BV + GV（步骤 2/7） | 版本/域版本/issued_epoch/expires_at/nonce 任一失败；旧 Bridge 在新配置下版本不符 |

**测试报告必须区分**"MockProver 拒绝"、"prover 出 proof 但 verifier 拒绝"、"外部验证器拒绝"、
"电路层接受但网关拒绝"四类，不得混为一谈。R07/R08/R09 是本轮暴露的三处"电路层非拒绝"点，
是本设计诚实边界的核心。

---

## 6. 本集成语句不能声称的内容

- 不是完整授权决策证明：π_trans 不单独证明 ALLOW（需 D2-A），不证明 DENY（非存在性）。
- 不证明历史完整性（跳事件/删撤销/旧状态）——见 `d3_02_security_analysis.md` §1。
- 不证明执行时新鲜性——见 §2 fencing 方案，freshness 是外部假设。
- 不证明布局规范性（R07/R08）、不防止跨 vk 重放（R09，靠注册表）。
- 不验证 D2-B 的密码学前提（quorum 合谋、日志被攻破仍可绕过）。
