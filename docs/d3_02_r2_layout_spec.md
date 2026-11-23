# EXP-D3-02-R2-03 — Canonical Layout 与 C_next 冻结规范

**基线**：`023a5d1641354dc7f7257a09cc23a28787b33b0d`
**分支**：`exp-d3-02-r2`
**性质**：设计冻结。收敛 R1-02 的布局接口为唯一方案。不实现电路。

---

## 0. 一句话结论

> **明确选择**：`C_next` **直接采用**任务书固定式
> `Poseidon(D3-STATE-P-v2, GR_next, RR_next, epoch_next, policy_id)`；
> GR_next/RR_next 严格用 R2-02 类别 (I) 规范 Field 编码（域元素）；
> 布局规范性采用 **R1-02 方案 A：外部可信布局签名 + 网关独立重算**，
> 电路只验证"给定布局下树更新正确"。布局签名密钥与 Bridge 签名密钥**独立**。

任务书 9 个问题在 §1–§9 逐一回答；IN_CIRCUIT / OFF_CIRCUIT / EXTERNAL_TRUST 划分在 §10。

---

## 1. C_next 是否直接采用上式？

**是，冻结为**：

```
C_next = Poseidon(D3-STATE-P-v2, GR_next_f, RR_next_f, epoch_next, policy_id)
```

- `D3-STATE-P-v2` 是域标签常量（R1-01 引入），在电路中是 **fixed 列常量**，不来自 witness。
- `epoch_next: u64` 需映射为单个 Fp 元素：因 `2^64 < p`，用 `F::from_u64(epoch_next)` 单射，
  电路内用 64-bit 分解 + range check 约束（`epoch` 是 u64，8 字节 < 32 字节，无越界问题）。
- `policy_id: F` 来自 R2-01 冻结定义，是电路固定常量。
- 输入共 5 个域元素，Poseidon width=3/rate=2 → 需 3 次置换（吸收 5 元素 + 输出），
  约 108 行 / 417 约束（一手 `halo2_gadgets 0.6.0 Pow5Chip` 口径）。

**与 C_prev 对称**：`C_prev = Poseidon(D3-STATE-P-v2, GR_prev_f, RR_prev_f, epoch_prev, policy_id)`，
域标签与参数完全一致，只有 GR/RR/epoch 不同。这保证前后承诺同构，便于网关比对。

---

## 2. GR/RR 是否严格使用 R2-02 的规范 Field 编码？

**是**。冻结规则：

- `GR_next_f = DecodeField_I(GR_next_be)`，`RR_next_f = DecodeField_I(RR_next_be)`，
  其中 `*_be` 是 32B 大端规范字节（R2-02 §3/§4.1）。
- 电路 witness 提供 `*_be`（公开字节，与 Bridge/布局声明 copy constraint）与
  `*_le`（域元素表示），并约束 `int_be(*_be) < p` + 逐字节反转相等（R2-02 §4.1）。
- **禁止**用 `from_uniform_bytes` 处理 GR/RR（会静默模约简，破坏 R1-01 承诺绑定）。
- 布局服务的 `assignment_digest` 编码中，状态承诺字段用 `C_prev`/`C_next` 的**域元素字节**，
  不是 GR/RR 原始字节——避免布局摘要重复承诺状态字段（R1-02 §2.1）。

---

## 3. 完整 ID 集合从哪里取得？

**来源链（冻结）**：

```
完整 ID 集合 = 当前授权状态中所有有效 grant 的 id
             = { id | leaf.valid_flag = 1 }  （D3-01 grant tree 的语义）
```

- 由**可信布局服务**从其维护的当前 Grant Tree 快照导出（`assigned_snapshot: BTreeMap<Hash32, usize>` 的键集合）。
- 布局服务对 `assignment_digest` 签名时，承诺的是**完整映射** `canonical_assignment(ids, d)`，
  因此 id 集合被完整覆盖（R1-02 §2.1）。
- **注意信任边界**：电路不验证"id 集合完整"——它只验证给定 id 集合下的树更新。
  id 集合的完整性属 `EXTERNAL_TRUST`（布局服务 quorum + 审计者独立重算）。

---

## 4. 如何确认完整 ID 集合对应当前授权状态？

三层检查（缺一不可）：

1. **状态承诺交叉核对**：布局服务的 `CanonicalLayoutStatement` 携带
   `previous_state_commitment = C_prev` 与 `next_state_commitment = C_next`；
   网关核对 `C_prev == BridgeStatement.poseidon_state_commitment`（R1-01 §3.3）。
   若 id 集合对应的 GR/RR 重算出不同的 `C_prev`，此步失败。
2. **布局验证器独立重算**：验证器从布局声明的 `changed_ids` + 可信前布局快照重算
   `canonical_assignment(ids, d)`，与 `assignment_digest` 比对（R1-02 §2.2）。
3. **审计者链下 falsification**：审计者用完整 GR Tree 叶子快照独立重算整棵布局，
   与签名的 `assignment_digest` 比对——这是链下检测，不赋予电路层保证。

**不能声称**：电路证明"id 集合完整"或"id 集合对应当前状态"——都不成立。
这些是外部信任，靠 (1)(2)(3) 的检查链维持。

---

## 5. assignment_digest 确定性编码（逐字节冻结）

```
assignment_digest = SHA256(
    enc_bytes("D3-LAYOUT-v1")                          // 8B 大端长度前缀 + 域标签
  ‖ u32be(layout_version)                              // 冻结 1
  ‖ u8be(tree_depth)                                   // 冻结 4
  ‖ enc_bytes( C_prev_field_bytes_be )                 // R2-02 类别(I) 编码的 32B
  ‖ enc_bytes( C_next_field_bytes_be )
  ‖ u64be(previous_epoch)
  ‖ u64be(next_epoch)
  ‖ enc_bytes( concat(
        sorted( id_be ‖ u32be(slot) for (id,slot) in canonical_assignment(ids,d) )
     ) )                                               // 完整映射，按 id 32B 字节序排序
  ‖ enc_bytes(nonce)                                   // 16B
  ‖ u64be(expires_at)
)
```

- `enc_bytes` = D3-01 8B 大端长度前缀（`encoding.rs:132`）。
- `sort` 按 `id` 的 32B 字节序（与 D3-01 `BTreeSet<Hash32>` 的 `Ord` 一致）。
- `slot` 用 u32be(4B)（槽号 0..15，与 `grant_tree.rs` 的 `usize` 规范序一致）。
- **完整映射**进摘要，不只是 changed 部分——确保签名覆盖整棵布局（R1-02 §2.1）。
- 域标签 `D3-LAYOUT-v1` 与 D3-01 其他标签（`D3-GRANT-v1` 等）分离，避免跨协议混淆。

---

## 6. 布局服务如何证明签名覆盖完整布局？

- `CanonicalLayoutStatement`（R1-02 §2.1）的字段：`layout_version, tree_depth,
  previous_state_commitment, next_state_commitment, previous_epoch, next_epoch,
  changed_ids, assigned_slots, assignment_digest, nonce, expires_at`。
- 签名 preimage：`SHA256(enc_bytes("D3-LAYOUT-SIG-v1") ‖ enc_bytes(canonical_encode(statement)))`，
  按字段声明顺序、定长编码，`assignment_digest` 作为字段被签名覆盖。
- 由于 `assignment_digest` 本身承诺了**完整 id→slot 映射 + 前后状态承诺 + epoch + nonce**，
  签名覆盖 `assignment_digest` == 覆盖完整布局。
- 验证端用**配置的**公钥集合与阈值验签，不采信自报；与 Bridge 验签密钥**独立**（§9）。

---

## 7. 网关如何独立重算 canonical assignment？

网关（或独立布局验证器）执行：

```
1. 从可信前布局快照取 ids_prev + assigned_prev（或直接用签名声明的前布局）
2. 应用 changed_ids（新增/删除/更新）得到 ids_next
3. 执行 canonical_assignment(ids_next, d=4)（R1-02 §1 的算法）：
   - ids 按 32B 规范序排序
   - 每个 id: start = low64be(field_from_bytes("D3-SLOT-v1", id)) & 15
   - 从 start 起环形线性探测首个空槽
   - 满树 -> TREE_CAPACITY_EXHAUSTED -> 拒绝
4. 用 §5 公式重算 assignment_digest' = SHA256(...)
5. 比对 assignment_digest' == layout_digest（statement 字段）；不符 -> 拒绝 (T09)
6. 额外核对 C_prev/C_next 与 Bridge statement 一致（§4.1）
```

**成本**：网关重算是链下、无密码学证明的确定性计算（SHA-256 + 排序 + 探测），
对 16 槽位极廉价。但它依赖"ids_next 来自可信前快照 + changed_ids 完整"——
若 changed_ids 被篡改，网关重算的是错误集合，只能靠 Bridge/事件批次交叉核对发现。
这是 `EXTERNAL_TRUST` 的一部分，如实记录。

---

## 8. 删除、插入、碰撞、重插时如何处理 displaced ID？

严格沿用 D3-01-R1 `try_upsert`（`grant_tree.rs:243-300`）语义：

| 场景 | 处理 | 对布局摘要的影响 |
| --- | --- | --- |
| 删除 id | 释放其槽位；其余 id 的规范槽位**可能改变**（因规范序重排） | 受影响 id 进 `changed_ids`，其新槽位进 `assigned_slots` |
| 插入新 id | 计算 `start`，环形探测首个空槽；若抢占已占槽触发 displaced | 新 id + 所有 displaced id 进 changed/assigned |
| 槽位碰撞（start 相同） | 线性探测保证不同 id 落到不同空槽；单射由 `BTreeMap` 维护 | 探测链上 id 的槽位进 assigned |
| 删除后重插同一 id | `try_upsert` 用新旧 `canonical_assignment` 比较，displaced id 被**复制到新规范槽位**（不重哈希叶子），只重算 dirty 路径 | 重插触发的完整位移集合进 changed/assigned |
| 满树 | 返回 `TREE_CAPACITY_EXHAUSTED`，布局服务拒签 | 无 digest |

- **最坏情况**：一次插入可位移全部 16 个槽位（R1-02 §4.3），实际影响集合由布局服务在
  `changed_ids`/`assigned_slots` 中完整列出；网关重算发现遗漏即拒绝。
- **电路视角**：电路只验证给定 `assigned_slots` 下的 Merkle 路径重算，**不验证位移规则本身**
  （R1-02 §5）。非规范重插（T10）在电路层接受、布局验证器层拒绝。

---

## 9. 布局签名与 Bridge 签名是否使用独立密钥？

**是，强制独立**。冻结规则：

| 签名域 | 密钥集合 | 职责 | 理由 |
| --- | --- | --- | --- |
| D2-B checkpoint QC | D2-B `TrustedWitnessSet`（配置） | 认证 anchor 与 checkpoint | 冻结既有 |
| Bridge Statement | Bridge quorum（**独立**公钥集合/阈值） | 认证 SHA-256 anchor ↔ Poseidon 承诺映射 | R1-01 §2.4 双签名需独立密钥 |
| Canonical Layout | Layout quorum（**再独立**公钥集合/阈值） | 认证 id→slot 规范布局 | 职责分离：布局撒谎不应能伪造 anchor 映射，反之亦然 |

- 三套公钥集合由验证端**分别配置**，不得共享密钥材料。
- 若某实现为简化共用密钥，等于把三个信任点合并为一个——一处泄露全线崩溃；
  本规范禁止，网关集成测试 T06/T09 覆盖密钥/注册表映射检查。
- Bridge 与 Layout 都是 quorum 签名（阈值 k-of-n），配置由治理方维护，不在电路内证明。

---

## 10. IN_CIRCUIT / OFF_CIRCUIT / EXTERNAL_TRUST 明确划分

| 内容 | 层级 | 谁做 / 怎么做 |
| --- | --- | --- |
| 给定 slot 下叶子写入 + d 层 Merkle 路径重算 → GR/RR 根 | **IN_CIRCUIT** | Halo2：叶子 Poseidon + 路径 node_hash（R1-02 §5） |
| `slot < 2^d` 范围检查 | **IN_CIRCUIT** | Halo2：4-bit range check |
| `C_prev`/`C_next` = Poseidon(D3-STATE-P-v2, GR, RR, epoch, policy_id) | **IN_CIRCUIT** | Halo2：3 次置换；GR/RR 走 R2-02 类别(I) 解码约束 |
| `int_be(GR/RR) < p` 规范检查 + 字节序反转 copy | **IN_CIRCUIT** | Halo2：R2-02 §5（~500–1000 约束） |
| `canonical_assignment(ids,d) == 给定布局` | **OFF_CIRCUIT**（不进电路） | 网关/布局验证器独立重算（§7） |
| `assignment_digest` 重算与比对 | **OFF_CIRCUIT** | 布局验证器（链下 SHA-256，廉价） |
| 布局签名验签（阈值/公钥/过期/nonce） | **EXTERNAL_TRUST**（链下验证器） | Layout quorum + 验证端配置 |
| id 集合完整性（changed_ids 无遗漏） | **EXTERNAL_TRUST** | 布局服务 quorum + Bridge/事件批次交叉核对 + 审计重算 |
| displaced id 位移规则正确执行 | **EXTERNAL_TRUST** | 布局服务 + 网关重算（电路不约束位移规则） |

**杜绝模糊表述**：文档不再出现"布局已验证"这类无主语说法。每处的验证者、验证方法、
失败后果均在上表明确。电路层唯一能拒绝的是"给定布局下 Merkle 根算错"或"字节非规范"，
**不是**"布局非规范"（T09/T10 电路层接受）。

---

## 11. 本规范不能声称的内容

- **不能**声称"电路保证 canonical assignment"——不保证，布局规范性在电路外（R1-02 §6）。
- **不能**声称"局部 canonicality 已解决"——只有归纳框架，无 in-circuit verifier 锚点（R1-02 §4）。
- **不能**声称"id 集合完整性已被密码学证明"——它是外部信任，靠交叉核对维持。
- **不能**声称 `C_next` 直接等于 D2-B anchor——D2-B 用 SHA-256，这里用 Poseidon，
  二者经 R1-01 Bridge 绑定，不是同一承诺。
- **不能**忽略 displaced id 最坏情况（全部 16 槽）——这使局部方案退化为全局，是布局服务必须完整列集合的原因。
