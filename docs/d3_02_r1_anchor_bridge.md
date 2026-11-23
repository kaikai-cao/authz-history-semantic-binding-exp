# EXP-D3-02-R1-01 — Anchor Bridge：SHA-256 Anchor ↔ Poseidon 状态承诺

**基线**：`98906dd1f94f7d9922f7759989f896c418c85561`（D3-02 设计阶段）
**分支**：`exp-d3-02-r1`
**性质**：设计修订。本轮不实现电路，不修改 D2-B / D3-01 冻结实现。

---

## 0. 问题陈述与一句话结论

D2-B 的权威状态锚是 **SHA-256**：

```
A_e = SHA256( D_A ‖ u32be(version) ‖ u64be(epoch) ‖ u32be(policy_version)
              ‖ len4(GR_bytes) ‖ len4(RR_bytes) ‖ len4(prev_anchor_digest) )
```

D3-02 电路拟用的状态承诺是 **Poseidon**：

```
C_prev = Poseidon( D_STATE, GR_prev, RR_prev, epoch_prev, policy_id )
```

二者不是同一个承诺：算法不同（SHA-256 vs Poseidon）、输入表示不同（32B 原始字节 vs 域元素）、
域标签不同（`ZK-STATE-ANCHOR-01:D_A` vs `D3-STATE-*`）。**若直接把上一轮的
`previous_state_commitment` 理解为"`field_from_bytes(anchor_digest)`"，电路就无法从它
开承诺出 `(GR_prev, RR_prev, epoch_prev, policy_id)` 供后续步骤使用；若理解为
"Poseidon(状态字段)"，则验证者没有一个可信来源告诉它这个 Poseidon 值对应哪个 SHA-256
anchor。这是同一字段在两份设计文档里被赋予了两种互斥语义。`d3_02_public_statement.md` §4
写的是前者（anchor digest 域化），`d3_02_circuit_spec.md` §2.11 写的是后者（Poseidon of fields）。
本轮修正这个不一致。**

> **结论（明确选择）**：采用**方案 A′：认证式可信 Anchor Bridge**。
> 把 `C_prev` 唯一地定义为 `Poseidon(D3-STATE-P-v2, GR, RR, epoch, policy_id)`（电路内可重算、
> 可开承诺），并引入一个**签名认证的 Bridge Statement**，链下完成"经 D2-B 验证器验证的
> SHA-256 Anchor A_e ↔ C_prev"的绑定。SHA-256 继续用于外部可信锚定，Poseidon 用于电路内
> 开承诺，Bridge 是二者之间**唯一**的带版本与 freshness 的认证映射。方案 B（电路内 SHA-256）
> 作为"消除 Bridge 签名信任"的长期方向记录，第一版不采用；方案 C（双承诺 Anchor）需要
> 改 D2-B 冻结实现，本轮禁止。

必须诚实说明：**方案 A′ 新增了一个外部信任点——Bridge 签名者必须对"用正确状态元组与
正确域标签计算 Poseidon"负责**。电路无法增强这个假设；它只是把"语义正确"与"这个被认证的
Poseidon 承诺"焊接在一起。

---

## 1. 一手编码事实（R1 修订的锚点）

以下全部来自本轮读取的一手源码，R1 设计不得与之冲突：

| 项 | 一手事实 | 来源 |
| --- | --- | --- |
| Anchor 摘要 | `A_e = SHA256(domain("D_A") ‖ u32be(version) ‖ u64be(epoch) ‖ u32be(policy_version) ‖ bytes_with_len(GR) ‖ bytes_with_len(RR) ‖ bytes_with_len(prev))` | `zk-state-anchor-exp/src/anchor.rs:39-48` |
| 长度前缀 | `bytes_with_len` 用 **4 字节**大端 `u32be(len)` | `zk-state-anchor-exp/src/encoding.rs:121-126` |
| 域标签 | `domain(tag) = str_with_len("ZK-STATE-ANCHOR-01:" ‖ tag)`，同样 4 字节前缀 | `zk-state-anchor-exp/src/encoding.rs:132-135` |
| GR/RR 表示 | `FieldBytes` 32B（Pallas base 域元素的规范字节编码） | `zk-state-anchor-exp/src/encoding.rs` `FieldBytes` |
| checkpoint | `checkpoint_hash = SHA256(encode_d1e_checkpoint(cp))`，cp 含 `state_root/log_root/policy_version/witness_set_root`，D1-E 长度前缀编码 | `zk-state-anchor-exp/src/checkpoint.rs:70` |
| QC 验签 | `TrustedWitnessSet::from_trusted_config(entries, threshold, expected_root)`；验证器复检阈值/ID/公钥唯一性 | `zk-state-anchor-exp/src/witness_set.rs`、`verifier.rs` |
| freshness | 结构化判定 `latest.epoch == cp.epoch && latest.checkpoint_hash == checkpoint_hash(cp)`；provider 不可用 fail-closed | `zk-state-anchor-exp/src/freshness.rs:34-60`、`verifier.rs:328-346` |
| 域→域元素 | D3-01 `field_from_bytes(label,bytes)` = `F::from_uniform_bytes(SHA256(bytes)‖SHA256(label))`（64B） | `authz-history-semantic-binding-exp/src/encoding.rs:97-102` |
| Poseidon | `P128Pow5T3` width 3 / rate 2 / R_F=8 / R_P=56；D3 标签 `D3-GRANT-v1` 等 | `halo2_poseidon 0.2.0`、`src/encoding.rs:19-25` |

**关键推论**：32B 的 SHA-256 摘要不能直接作为 Pallas base field（≈254 bit）的规范域元素也不适合
直接进 Poseidon 的 message（模数边界），所以"anchor digest 域化"和"状态字段 Poseidon 承诺"
在电路内是两种不同操作，不可互相替代。这正是必须显式桥接的原因。

---

## 2. 三种桥接方案

记可信验证者的输入：`cp`（D2-B checkpoint）、`QC`（3-of-4 quorum 签名）、`A_e`（anchor digest）、
`AnchorRecord_e`（含完整状态元组）。记电路状态元组 `s = (GR, RR, epoch, policy_id)`。

### 2.1 方案 A：可信 Anchor Bridge（外部验证 Anchor 后认证 Poseidon 承诺）

**机制**：一个独立的 **Bridge Service**（或 quorum）执行：

```
1. 用 D2-B 验证器验证 (cp, QC, AnchorRecord_e, freshness) → 得到可信 A_e 与状态元组 s
2. 断言 A_e == SHA256(encode(s 的 D2-B 表示))             // 链下 SHA-256，廉价
3. C_e  = Poseidon(D3-STATE-P-v2, GR_f, RR_f, epoch, policy_id)   // 链下 Poseidon
4. 签发 BridgeStatement（§3），覆盖 A_e、checkpoint_hash、s、C_e、域标签、版本、freshness、nonce
```

电路只消费 `C_prev = C_e` 并在电路内从私有 `(GR,RR,epoch,policy_id)` 重算 Poseidon 开承诺。

**逐项分析**：

1. **验证者信任谁**：信任 (a) D2-B 验证器对 `cp/QC/freshness` 的判定（既有信任，不新增）；
   (b) **新增**：Bridge 签名者对"步骤 2/3 正确"的签名。二者缺一不可，必须**都验证**。
2. **状态字段能否替换**：不能。BridgeStatement 的签名覆盖完整状态元组与 `A_e`、域标签、版本；
   电路内 `C_prev` 重算覆盖 `GR/RR/epoch/policy_id`。任一层篡改都会破坏签名或开承诺。
3. **旧 Anchor 配新 Poseidon / 混搭**：不能。Bridge Service 内部步骤 2 强制
   `A_e = SHA256(encode(s))`，且签名覆盖二者；验证端再核对 `checkpoint_hash` 与当前 checkpoint。
   混搭要么在 Bridge 内部校验失败（不出签名），要么在验证端 checkpoint 比对失败。
4. **双重签名/双重承诺/版本回滚**：
   - 双重签名：同一状态同时有 D2-B QC 和 Bridge 签名。二者必须都验；Bridge 签名密钥须**独立**于
     D2-B witness 密钥（最小权限、责任分离），否则一个密钥泄露同时伪造两层。
   - 双重承诺：`A_e`（SHA-256，外部权威）与 `C_e`（Poseidon，电路输入）是两个承诺，但**只有 Bridge
     是它们之间的映射**。文档与 API 必须写明"电路只消费 Poseidon，外部只消费 SHA-256"。
   - 版本回滚：`BridgeStatement.bridge_version`、`policy_version`、`epoch`、`checkpoint_hash`、`nonce`
     全部入签名；验证者用**配置常量**指定期望 `bridge_version`/域标签，不采信 Bridge 自报值。
5. **支持 D2-B checkpoint/QC/freshness**：是。BridgeStatement 携带 `checkpoint_hash`，验证端用
   D2-B freshness provider 做 epoch+hash 结构化判定（F01–F06），用 `TrustedWitnessSet` 验 QC
   （C01–C12）。Bridge **叠加在**这些机制之上，不替代它们。
6. **电路约束/复杂度**：最低。电路内只需一次 Poseidon L=5（`C_prev` 开承诺）：约 3 置换 /
   108 行 / 417 约束（`halo2_gadgets 0.6.0` 一手口径）。Bridge 验签在链下。
7. **新增信任代价**：Bridge 签名者若被攻破或合谋，可对伪造的 `(A_e, C_e)` 签名，电路会接受
   错误 `C_prev`。**电路无法检测**。缓解：Bridge quorum + 独立密钥 + 审计日志 + 与 D2-B
   checkpoint 交叉核对。

### 2.2 方案 B：电路内 SHA-256 验证 Anchor

**机制**：电路内取私有 `(version, epoch, policy_version, GR_bytes, RR_bytes, prev)`，重算
`A_e' = SHA256(...)`（与 D2-B 编码逐字节一致），约束 `A_e' == A_e_public`；同时用同一组
GR/RR/epoch/policy 的域元素形式算 `C_prev = Poseidon(...)`。

**逐项分析**：

1. **验证者信任谁**：只信任 `A_e_public`（来自 checkpoint）这一份外部数据，以及 SHA-256/Poseidon
   的抗碰撞性。**不需要 Bridge 签名者**——这是它相对 A 的核心优势。
2. **状态字段能否替换**：不能，且是密码学保证而非签名信任。电路把 SHA-256 的字节输入与
   Poseidon 的域元素输入做 copy constraint，确保两个承诺由**同一组**状态字段驱动。
3. **旧 Anchor 配新 Poseidon**：不能，同上，单组 witness 同时喂给两个哈希。
4. **双重签名/双承诺/回滚**：没有 Bridge 签名层，消除双重签名责任混淆；`prev`、`epoch`、
   `version` 都在 SHA-256 preimage 内，回滚会导致 `A_e'` 不等。
5. **支持 D2-B 机制**：`cp/QC/freshness` 仍在电路外由 D2-B 验证器验证（本轮不把它搬进电路）；
   本方案只是把"A_e 对应哪个状态元组"从 Bridge 签名信任改为电路内 SHA-256 计算。
6. **电路约束/复杂度**：**显著高**。D2-B anchor 的 preimage 长度约
   `len(domain) + 4 + 8 + 4 + (4+32) + (4+32) + (4+32) ≈ 154` 字节，需约 3 个 512-bit SHA-256
   压缩块（含 padding 与长度域）。Halo2 中 SHA-256 需把 32-bit 字拆成字节/比特做加法进位与
   8-bit lookup 布尔函数，**数量为每块数千约束量级**。保守静态估计：仅 anchor 验证
   ≈ `O(10^4)` 约束，远高于整个 A 构造的 7k–9k。此外需处理"32B FieldBytes ↔ 域元素"的
   一致性（D2-B 的 GR 是规范域元素字节，电路内需证明其 < 模数并映射到域元素），这部分
   约束也未计入。**本估算为静态数量级推断，未经实测，标记为粗估/UNKNOWN，不作为容量结论。**
7. **信任代价**：无 Bridge 签名信任；代价是电路规模、证明时间与 k 值大幅上升，且第一版原型
   （k=13–14、2 grant+1 revoke）可能直接不可行。

### 2.3 方案 C：双承诺 Anchor（Anchor 同时维护 SHA-256 与 Poseidon）

**机制**：修改 D2-B，在 `AuthzStateAnchor` 中同时写入 `A_sha = SHA256(...)` 与
`A_pos = Poseidon(D_STATE, GR, RR, epoch, policy)`，由 quorum 一起签名，checkpoint 同时承诺两者。

**逐项分析**：

1. **验证者信任谁**：信任 D2-B quorum（已有信任），**不需要独立 Bridge 签名者**。看起来最优雅。
2. **状态字段能否替换**：D2-B 的 `policy_version: u32` 与 D3-02 的 `policy_id: Field` 不是同一
   编码；GR/RR 在 D2-B 是 32B FieldBytes，Poseidon 需域元素。必须新增一套"D2-B 字段 → Poseidon
   字段"的确定性映射并让 quorum 也对其签名，否则双承诺可各自对应不同状态。
3. **旧 Anchor 配新 Poseidon**：需要 self-consistency 检查同时覆盖两个承诺；若实现者只验一个，
   混搭成功。这是新引入的实现风险面。
4. **双重签名/双承诺/回滚**：双承诺本身就是"双重承诺"，必须用同一份状态元组生成并一起验签；
   否则出现"两个权威承诺"的歧义。本轮无法验证 D2-B 是否会正确实现。
5. **支持 D2-B 机制**：需要修改冻结的 D2-B 验证器、checkpoint 编码、quorum 签名格式、QC 验证与
   freshness provider——**全部动到冻结实现**，本轮明确禁止。
6. **电路约束/复杂度**：电路侧同方案 A（只需 Poseidon 开承诺），但**外部改造成本最高**：
   D2-B 全部测试（C01–C12/F01–F06/T01–T20）、固定向量与交叉语言 probe 都要重做。
7. **信任代价**：不新增 Bridge 签名者，但引入"双承诺一致性"的新实现信任，且需要 D2-B 升级
   与所有验证者升级。作为**后续演进方向**记录，本轮不选。

### 2.4 三方案对照表

| 维度 | A′ 认证式 Bridge（推荐） | B 电路内 SHA-256 | C 双承诺 Anchor |
| --- | --- | --- | --- |
| 验证者信任谁 | D2-B 验证器 + **Bridge 签名者** | D2-B 验证器 + SHA-256/Poseidon 抗碰撞 | D2-B quorum（升级后） |
| 状态字段替换 | 签名 + 电路双重绑定 | 电路 copy constraint（密码学） | 双承诺一致性检查 |
| 旧 Anchor 混搭新 Poseidon | Bridge 内部 SHA-256 校验 + checkpoint 比对 | 单组 witness 同时喂两哈希 | 需双承诺 self-consistency |
| 双签名/双承诺/回滚 | 有双签名，需独立密钥 + 版本绑定 | 无 Bridge 层 | 有双承诺，需一致性与版本 |
| 兼容 D2-B checkpoint/QC/freshness | 是（叠加其上层） | 是（外部仍由 D2-B 验证） | 需改全部 D2-B 冻结实现 |
| 电路约束增量 | 低（+1 Poseidon L=5 ≈ 417 约束） | 高（≈ O(10⁴) 约束，粗估） | 低（同 A） |
| 外部改造成本 | 中（新增 Bridge Service + 验证器检查） | 低（不改 D2-B） | 高（D2-B 全栈升级） |
| 主要信任代价 | **Bridge 签名者诚实** | 无（但电路规模） | 双承诺一致性实现 |
| 第一版选择 | ✅ | ❌（长期方向） | ❌（改冻结实现） |

---

## 3. 推荐的 A′ 完整设计

### 3.1 数据流（任务书指定链，逐节点落地）

```
D2-B Anchor A_e (SHA-256, 32B)
    │  checkpoint cp + 3-of-4 QC + freshness provider
    ▼
Anchor Validator (D2-B 既有验证器，逐字段验证)
    │  验证: QC 阈值/expected_root/ID 唯一 → checkpoint_hash → log inclusion
    │        → state_root≠log_root → prev_anchor == 可信前驱 → freshness(epoch+hash)
    ▼
Canonical State Tuple  s = (version, epoch, policy_version, GR_bytes, RR_bytes, prev)
    │  断言 A_e == SHA256(D2-B encode(s))    ← 链下 SHA-256，廉价
    ▼
Poseidon State Commitment  C_e = Poseidon(D3-STATE-P-v2, GR_f, RR_f, epoch, policy_id)
    │  GR_f/RR_f 为 s 中 32B 域元素映射到 Pallas base field；policy_id 由 §R1-03 定义
    ▼
Authenticated Bridge Statement  BS_e = ( 字段见 §3.2 ) + Sig_bridge(H(encode(BS_e)))
    │  验证端用 D2-B 结果核对 A_e/checkpoint_hash；验 Bridge 签名；核对版本/域标签/freshness
    ▼
Halo2 Transition Proof  π_trans : public C_prev = C_e, 电路内开承诺 → 逐事件语义 → GR_next/RR_next
```

### 3.2 Bridge Statement 结构（新协议消息，不修改 D2-B）

```
pub struct AnchorBridgeStatement {
    // ---- 协议与版本（验证者用配置常量核对，不采信自报期望值）----
    pub bridge_version: u32,            // Bridge 规范版本，例 1
    pub poseidon_domain_version: u32,   // 目标 Poseidon 域标签版本，例 2（D3-STATE-P-v2）
    pub policy_spec_digest: Field,      // §R1-03 的 policy_id，绑定电路规则与 circuit_spec_digest
    // ---- 被桥接的 Anchor（D2-B 权威值）----
    pub anchor_digest: Hash32,          // A_e，SHA-256
    pub checkpoint_hash: Hash32,        // D2-B checkpoint_hash，含 log_root/QC 绑定
    pub prev_anchor_digest: Hash32,     // 前驱关系，验证端与可信前驱比对
    // ---- 完整状态元组（解码自 AnchorRecord，签名覆盖全部字段）----
    pub protocol_version: u32,
    pub epoch: u64,
    pub policy_version: u32,            // D2-B 原生 u32，与 policy_id 对应关系见 §R1-03
    pub grant_root: FieldBytes32,       // 32B 域元素编码
    pub revoke_root: FieldBytes32,
    // ---- 桥接产物 ----
    pub poseidon_state_commitment: Field, // C_e = Poseidon(D3-STATE-P-v2, GR_f, RR_f, epoch, policy_id)
    // ---- freshness 与防重放 ----
    pub issued_epoch: u64,              // Bridge 签发时的可信 epoch
    pub expires_at: u64,                // 短 TTL（秒级），与执行端 fencing 对齐
    pub nonce: [u8; 16],                // 一次性，网关维护已用集合
}
pub struct SignedBridgeStatement {
    pub statement: AnchorBridgeStatement,
    pub signatures: Vec<BridgeSig>,     // quorum 签名，阈值与密钥集合由验证端配置
}
```

**签名 preimage 编码**：`SHA256( enc_bytes("D3-BRIDGE-P-v2") ‖ enc_bytes(canonical_encode(statement)) )`，
复用 D3-01 的 8 字节大端长度前缀（`enc_bytes`），域标签固定为 `D3-BRIDGE-P-v2`，
与 D2-B 的 4 字节前缀体系隔离，避免跨协议编码混淆。`canonical_encode` 按字段声明顺序、定长编码，
不定长字段（如 nonce）前置长度。

### 3.3 逐条满足任务书的六个关键要求

| 要求 | 落地机制 |
| --- | --- |
| Bridge 绑定完整状态元组 | 签名覆盖 `protocol_version/epoch/policy_version/GR/RR/prev` 全部字段；电路内 `C_prev` 开承诺从同一元组重算（copy constraint） |
| Bridge 绑定 anchor epoch、policy version、前驱关系 | `epoch`、`policy_version`、`prev_anchor_digest`、`anchor_digest`、`checkpoint_hash` 全部入签名；验证端用可信前驱与当前 checkpoint 交叉核对 |
| Bridge 有认证机制，不是普通状态服务返回值 | `SignedBridgeStatement` 带 quorum 签名；验证端按配置的公钥集合与阈值验签；**不接受未签名的裸 Poseidon 值** |
| Bridge 绑定目标 Poseidon 域标签与版本 | `poseidon_domain_version` 入签名，且 `C_e` 计算固定用 `D3-STATE-P-v2`；验证端用配置常量核对域标签版本，电路内域标签为 fixed 列常量（不来自 witness） |
| 验证端确认 Bridge 对应当前可信 Anchor | 验证端先用 D2-B 验证器确认 `anchor_digest`/`checkpoint_hash` 是当前可信 checkpoint（freshness epoch+hash 判定），再验 Bridge 签名；任一失败即拒绝 |
| 旧 Bridge 不得在新版本下被重放 | `bridge_version`/`poseidon_domain_version`/`policy_spec_digest` 与验证端**配置常量**比对；`issued_epoch`/`expires_at`/`nonce` 做新鲜性与一次性检查；旧版本 Bridge 在新配置下版本不符即拒 |

### 3.4 Bridge 信任边界与失败模式（诚实清单）

- **B-F1 Bridge 签名者合谋/被攻破**：可对伪造 `(A_e, C_e)` 签名。电路无法检测。缓解：quorum 阈值 +
  独立密钥 + 与 D2-B checkpoint 交叉核对 + 审计日志；**仍是外部信任，不可声称已消除**。
- **B-F2 D2-B 验证被跳过**：若网关只验 Bridge 签名而不验 D2-B checkpoint/QC/freshness，则 Bridge
  可对任意伪造 anchor 签名。**两者必须都验**，网关集成测试 R01/R02 覆盖。
- **B-F3 域标签/版本配置错误**：验证端若采信 Bridge 自报版本而非配置常量，可重放旧域版本。
  必须硬编码期望值；R05/R10 覆盖。
- **B-F4 32B↔域元素映射歧义**：D2-B 的 GR/RR 是规范域元素字节，须证明其 < 模数；映射函数须在
  Bridge 与电路内一致。**本轮只定义接口，映射的电路内约束属于原型阶段待冻结参数**（见设计总结 Q9）。
- **B-F5 freshness 仍是外部假设**：Bridge 的 `expires_at` 只限制 Bridge 消息寿命，不保证工具执行时
  授权仍有效；执行时 fencing 仍由 D3-02 安全分析 §2.4 的令牌+CAS 负责。

---

## 4. 与上一轮文档的差异（本轮修订点）

1. `previous_state_commitment` 的语义**唯一化**为 `C_prev = Poseidon(D3-STATE-P-v2, GR, RR, epoch,
   policy_id)`，修正 `d3_02_public_statement.md` §4（anchor digest 域化）与
   `d3_02_circuit_spec.md` §2.11（Poseidon of fields）的冲突。
2. 明确新增 `previous_anchor_digest`（公开，来自 Bridge Statement 的 `anchor_digest`），供网关核对
   checkpoint；上一轮把它与 `C_prev` 混为一个字段。集成语句见 `d3_02_r1_integrated_statement.md`。
3. 把"`D_E` 可信来源需对 Poseidon 承诺签名"与"Bridge 签名"区分为**两个独立签名对象**：
   Bridge 绑定前状态，批次来源绑定事件批次，二者不可合并。
4. D3-02 §8 未决问题 1（anchor 是否含 log_root/checkpoint_hash）在本轮明确：`checkpoint_hash`
   入 Bridge Statement，由 D2-B 验证器核对 log_root；不塞进电路。

---

## 5. 本方案不能声称的内容

- **不能**声称"电路验证了 SHA-256 Anchor"——第一版电路只验证 Poseidon 开承诺，SHA-256 验证在
  Bridge Service 链下完成。
- **不能**声称"消除了状态来源信任"——Bridge 签名者是新增信任点。
- **不能**声称"解决了历史完整性与新鲜性"——见 `d3_02_r1_integrated_statement.md` §4 与
  `d3_02_security_analysis.md`。
- **不能**把方案 B 的 `O(10⁴)` 约束估计当作实测；它只是基于 SHA-256 块数与 Halo2 字节分解的
  数量级推断，标记为粗估/UNKNOWN。
