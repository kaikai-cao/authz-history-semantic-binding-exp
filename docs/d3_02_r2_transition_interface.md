# EXP-D3-02-R2-04 — 最终公共输入与私有 Witness 冻结接口

**基线**：`023a5d1641354dc7f7257a09cc23a28787b33b0d`
**分支**：`exp-d3-02-r2`
**性质**：设计冻结。给出可直接交给 D3-03 Halo2 原型实现的 Rust 接口。本轮不实现电路。

---

## 0. 一句话结论

> **明确选择**：采用任务书建议的 **11 字段 `TransitionPublicInputs`**，但做三处冻结澄清：
> ① `vk_hash` **不进电路 instance**，是纯验证器元数据（保留在结构中供网关查注册表）；
> ② `layout_digest` **不进电路**，供网关核对布局签名（电路只消费布局 witness 给出的 slot）；
> ③ `previous_anchor_digest` 与 `previous_state_commitment` 语义分离——前者是 D2-B SHA-256 32B
> （外部信任锚），后者是 Poseidon 域元素（电路开承诺）。
> 不新增 `previous_policy_id`（策略身份由单一 `policy_id` 绑定，前后状态同策略），
> 显式新增 `transition_version`（u32，随 CircuitSpec 冻结，防旧证明在新规范下重放）。

---

## 1. 最终 TransitionPublicInputs（冻结）

```rust
/// EXP-D3-02-R2 冻结公共输入。D3-03 原型实现不得增删字段，
/// 字段语义变更必须升 transition_version 并重算 D_circuit/policy_id。
pub struct TransitionPublicInputs {
    // ---- 前状态锚（外部信任 + 电路开承诺）----
    pub previous_anchor_digest: Hash32,        // D2-B SHA-256 A_e，32B，不进电路 instance，网关核对 checkpoint
    pub previous_state_commitment: Field,      // C_prev = Poseidon(D3-STATE-P-v2, GR_prev, RR_prev, prev_epoch, policy_id)
    pub previous_epoch: u64,                   // 单调链起点；进 C_prev preimage；fencing 高水位

    // ---- 后状态结果（供 D2-A / 网关）----
    pub next_state_commitment: Field,          // C_next = Poseidon(D3-STATE-P-v2, GR_next, RR_next, next_epoch, policy_id)
    pub next_epoch: u64,                       // epoch_next；单调约束终点

    // ---- 策略与协议版本 ----
    pub policy_id: Field,                      // R2-01 冻结定义；电路 fixed 常量 gate
    pub transition_version: u32,               // 新增：协议版本，随 CircuitSpec.spec_version 冻结

    // ---- 批次绑定 ----
    pub event_batch_commitment: Field,         // D_E = Poseidon(D_BATCH, n, c_1..c_n)，R2-02 §4.2
    pub event_count: u32,                      // n ≤ 3（原型容量）

    // ---- 外部信任锚（不进电路 instance）----
    pub layout_digest: Hash32,                 // R2-03 §5 的 assignment_digest，网关核对布局签名
    pub vk_hash: Hash32,                       // SHA256(vk_bytes)，网关查 VK 注册表
}
```

**字段总数 11**（3 Hash32 + 4 Field + 2 u64 + 2 u32；其中 8 个进电路 instance，3 个 Hash32 仅网关核对）。
> **D3-03-A 勘误**：初稿误写为"12 字段 / 4 个 Hash32"，实际结构体只有 3 个 Hash32
> （`previous_anchor_digest`/`layout_digest`/`vk_hash`），总数为 11。字段语义与顺序不变。
相对 R1 的 11 字段：
- `next_grant_root`/`next_revoke_root` → 合并为 `next_state_commitment`（因 R1-01 把 C_prev 语义
  唯一化为 Poseidon 承诺，后状态也应对称提供 C_next；GR_next/RR_next 降为私有 witness，
  由 C_next 开承诺锁定）。这是**与 R1 的差异，需明确记录**：
  - R1 §1 保留 `next_grant_root`/`next_revoke_root` 公开；
  - R2 改为 `next_state_commitment` 公开 + GR/RR 私有。理由：与 `previous_state_commitment`
    对称，网关只需比对一个承诺；且 D2-A π_path 的 instance 可从 witness 展开时再提供。
  - **风险**：若 D3-04 需要独立 GR_next/RR_next 公开值给下游，可在 w 中保留并由电路 copy 到
    `next_state_commitment`，不改变本接口（下游拿的是 witness 展开值，非独立 public）。
- 新增 `transition_version`: u32。

### 1.1 字段逐项：公开/私有、生成者、认证者、电路用途、网关检查、防重放

| 字段 | 类型 | 进电路 instance | 生成者 | 认证者 | 电路用途 | 网关检查 | 防重放 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `previous_anchor_digest` | Hash32 | ❌ | D2-B 验证器 | D2-B QC | 不用（32B 非域元素） | checkpoint 中 A_e + QC 验签 + log inclusion | ✅ 旧 anchor ≠ 当前 checkpoint |
| `previous_state_commitment` | Field | ✅ | Bridge Service | Bridge quorum 签名 | 开承诺 `C_prev == Poseidon(...)` | 与 BridgeStatement.poseidon_state_commitment 比对 | ✅ epoch/anchor 更新使其失效 |
| `previous_epoch` | u64 | ✅（映射 Fp） | Bridge Statement | Bridge 签名 | 进 C_prev preimage；单调起点 | 本地 epoch 高水位（F01–F06） | ✅ 回滚检测 |
| `next_state_commitment` | Field | ✅ | 电路 witness 输出 | 电路（Poseidon 重算约束） | 与末步双根重算 copy | 与可信 checkpoint 下一状态比对（可选） | 靠前状态锚 |
| `next_epoch` | u64 | ✅（映射 Fp） | 电路 witness | 电路（单调约束） | 单调终点；进 C_next | 下一轮 anchor + fencing | 单调防回退 |
| `policy_id` | Field | ✅ | R2-01 冻结规范 | vk 注册表 + 电路 fixed gate | gate `policy_id_pub == policy_id_const` | 查注册表 + Bridge policy_spec_digest | ✅ 版本回滚换 id |
| `transition_version` | u32 | ✅（映射 Fp） | CircuitSpec.spec_version | 电路 fixed gate + 注册表 | gate `version_pub == version_const` | 比对配置常量，旧版本拒 | ✅ 旧证明新规范下拒 |
| `event_batch_commitment` | Field | ✅ | 可信批次来源 | 批次来源 Poseidon 承诺 | `D_E == Poseidon(D_BATCH,n,c_1..c_n)` | 与 D1-E 日志 batch digest 来源比对 | ✅ 不同批次不同承诺 |
| `event_count` | u32 | ✅（映射 Fp） | 批次来源 | 同上 | `n ≤ N_MAX` 容量 | 审计覆盖事件数 | 间接（进 D_E） |
| `layout_digest` | Hash32 | ❌ | 布局服务 | Layout quorum 签名 | 不用（网关核对用） | 重算 assignment_digest 比对 + 验签 | ✅ 含 nonce/epoch |
| `vk_hash` | Hash32 | ❌ | 验证端从 vk_bytes 算 | VK 注册表 | 不用（元数据） | `registry[vk_hash]` active + policy_id 匹配 | ✅ 旧 vk 标 inactive |

**关键设计点**：3 个字段不进电路 instance（`previous_anchor_digest`、`layout_digest`、`vk_hash`
是 Hash32；它们是网关电路外核对的锚）。把它们列入结构是**接口完整性**要求（验证者必须拿到），
不是让它们进 Halo2 列。电路 instance 实际只有 8 个字段（4 Field + 2 u64 映射 + 2 u32 映射）。

### 1.2 u64/u32 → Field 的映射（冻结）

- `previous_epoch`/`next_epoch`（u64）：`F::from_u64(epoch)`，因 `2^64 < p` 单射；电路内用
  8 字节 range check + 累加约束（`epoch` 已是域元素的小数值表示，无字节序问题）。
- `event_count`/`transition_version`（u32）：`F::from_u64(v as u64)`，同理单射。
- 这些都是**小整数**，与 R2-02 类别 (I) 的 32B 规范编码无关（不需要 `< p` 的 32 字节比较）。

---

## 2. 私有 Witness（冻结清单）

```rust
pub struct TransitionWitness {
    // ---- 前后状态树（R1-01 开承诺 preimage）----
    pub grant_tree_prev: SparseMerkleTree,     // d=4，16 槽，含 assigned 映射
    pub revoke_tree_prev: SparseMerkleTree,
    pub grant_tree_next: SparseMerkleTree,
    pub revoke_tree_next: SparseMerkleTree,
    pub gr_prev_be: [u8; 32], pub rr_prev_be: [u8; 32],   // R2-02 类别(I) 大端规范字节（公开字节的 witness 副本）
    pub gr_prev_f: Field,  pub rr_prev_f: Field,          // 解码后域元素（小端 repr 的数值）
    pub gr_next_be: [u8; 32], pub rr_next_be: [u8; 32],
    pub gr_next_f: Field,  pub rr_next_f: Field,

    // ---- 事件批次 ----
    pub events: Vec<Event>,                    // e_1..e_n，n ≤ 3（2 grant + 1 revoke）
    pub event_commitments: Vec<Field>,         // c_i = Poseidon(D_EVENT, type, fields...)

    // ---- Merkle 路径与中间状态 ----
    pub gr_paths: Vec<MerklePath>,             // 每步每条事件的 d 层兄弟节点
    pub rr_paths: Vec<MerklePath>,
    pub inter_gr_roots: Vec<Field>,            // 每步中间 GR 根
    pub inter_rr_roots: Vec<Field>,
    pub parent_paths: Vec<MerklePath>,         // Parent Binding 用

    // ---- 布局信息（R1-02 / R2-03）----
    pub slots: Vec<(Hash32, usize)>,           // 本次涉及 id 的槽位（电路只验给定布局下路径）
    pub assigned_snapshot: BTreeMap<Hash32, usize>, // 完整映射快照，供网关重算 assignment_digest

    // ---- 策略（R2-01）----
    pub policy_params: PolicyParameters,       // scope/resource/epoch 参数 witness 展开

    // ---- 范围检查 witness（R2-02 类别(I) 解码）----
    pub field_range_witness: FieldRangeWitness, // 32B < p 比较的字节分解 + 高位条件

    // ---- 外部认证材料（不进电路，网关用）----
    pub bridge_statement: SignedBridgeStatement,   // R1-01 §3.2
    pub layout_statement: SignedCanonicalLayoutStatement, // R1-02 §2.1
    pub layout_nonce: [u8; 16],
}
```

**witness 生成者**：证明者（可能是不可信状态服务）。电路对语义、双根更新、承诺开承诺、
规范编码做约束；对布局规范性、anchor 来源、策略身份**不做独立证明**（外部签名承担）。
`bridge_statement`/`layout_statement` 放在 witness 结构里是为实现打包方便——它们**不进入电路**，
由网关在电路外验证（§4）。

---

## 3. 完整证明关系 R(x, w) = 1

`x` = §1 公共输入，`w` = §2 私有 witness。拆为 9 个子关系，逐项标注实现层级。

### 3.1 Anchor Bridge Binding — `IN_CIRCUIT`（开承诺）+ `EXTERNAL_TRUST`（A_e 来源）

```
IN_CIRCUIT:
    C_prev == Poseidon(D3-STATE-P-v2, gr_prev_f, rr_prev_f, previous_epoch, policy_id)
    DecodeField_I(gr_prev_be) == gr_prev_f ; DecodeField_I(rr_prev_be) == rr_prev_f   // R2-02 §4.1
EXTERNAL_TRUST:
    previous_anchor_digest 来自 D2-B QC 认证的 checkpoint
    Bridge 签名覆盖 (A_e, C_prev, 完整状态元组, checkpoint_hash, 域标签版本, nonce, expires_at)
    网关核对 BridgeStatement.poseidon_state_commitment == C_prev
```
电路**不**验 SHA-256、不验签、不验 checkpoint（R1-01 §3.1）。

### 3.2 Canonical Slot Validation — `IN_CIRCUIT`（给定布局路径）+ `EXTERNAL_TRUST`（规范性）

```
IN_CIRCUIT:   slot_i < 16；叶子写入 slot_i 后 d=4 层 node_hash 重算 → 对应中间根
EXTERNAL_TRUST:
    布局服务 canonical_assignment 签名；网关独立重算 assignment_digest == layout_digest
    电路不证明 layout == canonical_assignment(ids)
```
R07/R08 电路层接受、布局验证器/网关拒绝（R1-02 §5.1）。

### 3.3 Policy + Version Binding — `IN_CIRCUIT`（常量 gate）+ `EXTERNAL_TRUST`（注册表）

```
IN_CIRCUIT:
    policy_id (public) == policy_id_const (fixed 列)
    transition_version (public) == transition_version_const (fixed 列)
EXTERNAL_TRUST:
    registry[vk_hash] active；registry[vk_hash].policy_id == policy_id
    registry[vk_hash].circuit_spec_digest == 冻结 D_circuit
    BridgeStatement.policy_spec_digest == policy_id
```
R06/R09 最终拒绝点在网关注册表（R1-03 §5）。

### 3.4 Event Semantic Validation — `IN_CIRCUIT`

```
∀i: type ∈ {1,2}; grant_id ≠ 0; scope_child & ~scope_parent == 0;
     前 8 字节 resource 前缀相等; parent 存在且 valid_flag=1; issuer == parent.subject;
     epoch 单调; revoker == issuer; 目标未撤销; 无重复撤销
```
沿用 D3-02 `circuit_spec.md` §2.1–2.7，`valid_flag` 专用列 + `s_not_revoked` 门（D2-A-R1 教训）。

### 3.5 GR Update — `IN_CIRCUIT`

```
leaf_new = Poseidon(D_GRANT, id, issuer, subject, resource, scope, parent, epoch, valid_new)
node_l   = Poseidon(D_NODE, select(path_left[l], node_{l+1}), select(path_right[l], node_{l+1}))
node_0   == GR_i（中间）或 GR_next（末步）
```

### 3.6 RR Update — `IN_CIRCUIT`

```
leaf_new = Poseidon(D_REVOKE, id, revoker, epoch)；同理 d=4 路径 → RR_next
```

### 3.7 Batch Commitment — `IN_CIRCUIT`（重算）+ `EXTERNAL_TRUST`（来源）

```
IN_CIRCUIT:   D_E == Poseidon(D_BATCH, n, c_1, ..., c_n); n ≤ 3; c_i 顺序固定
EXTERNAL_TRUST: D_E 来自可信批次来源（D1-E 日志），对完整事件字节算 Poseidon
```

### 3.8 State Transition Binding — `IN_CIRCUIT`

```
previous_epoch ≤ epoch_1 ≤ ... ≤ epoch_n = next_epoch
C_next == Poseidon(D3-STATE-P-v2, gr_next_f, rr_next_f, next_epoch, policy_id)
（前状态已由 3.1 开承诺绑定）
```

### 3.9 Field Encoding Correctness — `IN_CIRCUIT`

```
对 gr_prev_be / rr_prev_be / gr_next_be / rr_next_be 各:
    int_be(b) < p（R2-02 §5 规范范围检查）
    be[k] == le[31-k] for k=0..31（字节序反转 copy）
```

### 3.10 汇总表

| 子关系 | IN_CIRCUIT | OFF_CIRCUIT | EXTERNAL_TRUST |
| --- | --- | --- | --- |
| 3.1 Anchor Bridge | C_prev 开承诺 + 规范解码 | SHA-256 计算 | A_e/checkpoint/Bridge 签名 |
| 3.2 Canonical Slot | 给定布局路径更新 + slot 范围 | 布局规范性重算+摘要 | Layout quorum |
| 3.3 Policy/Version | 双常量 gate | —— | vk 注册表 |
| 3.4 Event 语义 | 全部规则 | —— | —— |
| 3.5/3.6 双树更新 | 叶子+路径 | —— | —— |
| 3.7 Batch | Poseidon 承诺重算 | —— | 批次来源 |
| 3.8 State Binding | 单调 + C_next | —— | —— |
| 3.9 Field Encoding | 规范检查+字节反转 | —— | —— |

**没有**把任何安全关键检查（scope/parent/revoke/双根/开承诺/policy 常量/规范编码）
悄悄移到链下而不写明。

---

## 4. 网关集成检查清单（冻结，验证者必须执行）

```
1. D2-B 验证器: verify(cp, QC, AnchorRecord, freshness) → 可信 A_e
2. Bridge 验证器: verify(SignedBridgeStatement, 配置公钥/阈值/期望域版本/非过期/nonce 未用)
3. 交叉: BridgeStatement.anchor_digest == A_e; checkpoint_hash 匹配; poseidon_state_commitment == C_prev
4. 布局验证器: verify(SignedCanonicalLayoutStatement 签名); 独立重算 assignment_digest == layout_digest
5. VK 注册表: registry[vk_hash] active 且 policy_id 匹配且 D_circuit 是冻结值 且 transition_version 匹配
6. Halo2: verify(vk, 8 个 instance 字段, π_trans)   // 电路 gate 保证常量+语义+双根+规范编码
7. epoch 高水位/freshness: previous/next epoch 与本地高水位比对，provider 不可用 fail-closed
8. 结果状态: 从 witness 展开 GR_next/RR_next 作为 D2-A π_path 的 instance（ALLOW 证明）
9. 执行时 fencing: 短 TTL 令牌 + 版本 CAS（D3-02 security §2.4），DENY fail-closed
```

任一步失败即拒绝。**步骤 1–5、7、9 全在电路外**；证明有效（步骤 6）≠ 状态正确 ≠ 授权有效。

---

## 5. 字段删除/新增实验（为什么是这 11 个）

| 字段 | 删除后果 | 结论 |
| --- | --- | --- |
| `previous_anchor_digest` | 网关无法核对 Bridge 是否绑定当前可信 checkpoint → R01/R02 | 必须保留（网关用） |
| `previous_state_commitment` | 电路无法开承诺锁定前状态 → 证明者可自选 GR/RR | 必须保留（电路） |
| `previous_epoch` | 单调链无起点；C_prev 少一输入 | 必须保留 |
| `next_state_commitment` | 后状态无承诺；GR/RR 私有值无法被公开锁定 | 必须保留（电路） |
| `next_epoch` | 单调链无终点 | 必须保留 |
| `policy_id` | 策略混淆 R05/R06/R09 | 必须保留 |
| `transition_version` | 旧证明可在新规范下重放 | 必须保留（新增） |
| `event_batch_commitment` | 批次可替换 | 必须保留 |
| `event_count` | 容量/审计缺失（虽进 D_E 可间接覆盖，但显式更清晰） | 保留 |
| `layout_digest` | 网关无法核对布局签名 → R09/T09 | 必须保留（网关用） |
| `vk_hash` | 网关无法查注册表 → R09 跨 vk 重放 | 必须保留（网关用） |
| `previous_grant_root`/`previous_revoke_root`（D3-01 原字段） | 已被 C_prev 开承诺替代，公开反而暴露状态 | 降为私有 witness（R2 变更） |
| `previous_policy_id`（候选） | 前后同策略（单策略电路），冗余；策略升级靠新 vk+新 proof 链 | 不新增 |

---

## 6. 本接口不能声称的内容

- 不是完整授权决策证明：π_trans 不单独证明 ALLOW（需 D2-A），不证明 DENY（非存在性）。
- 不证明历史完整性（跳事件/删撤销/旧批次/不完整子集）——见 `d3_02_security_analysis.md` §1。
- 不证明执行时新鲜性——fencing 是外部假设（security §2.4）。
- 不证明布局规范性（T09/T10）、不防跨 vk 重放（R09 靠注册表）。
- 3 个 Hash32 字段不进电路 instance——它们是网关核对锚，不是 Halo2 公开输入列。
- `next_state_commitment` 替换 R1 的独立双根公开字段是本轮接口变更，D3-04 若需独立双根须走 witness 展开路径。
