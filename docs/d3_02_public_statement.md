# EXP-D3-02-01 — 公开证明语句设计

**基线**：`dc13e810a65558362ccf1458bed593ca015abd9e`（D3-01-R1，已冻结）
**分支**：`exp-d3-02-design`
**定位**：设计文档。本轮不新增电路代码，不修改 D3-01 的任何实现、固定向量或实验数据。

---

## 0. 一句话结论

公开输入应当绑定**一个由外部可信源认证的前状态承诺**、**电路可高效重算的批次承诺**、
**结果状态的 GR/RR 根**，以及**策略版本与 epoch  fencing 字段**；不应当把 D3-01 的
SHA-256 `event_batch_digest` 直接搬进电路，也不应当把请求上下文塞进状态转换语句。

关键区分（本轮所有设计都围绕它）：

| 性质 | 谁负责 | 电路是否证明 |
| --- | --- | --- |
| 授权事件**语义正确**（scope/parent/revoke/策略） | Halo2 电路 | **是** |
| GR/RR 状态承诺的**正确更新** | Halo2 电路 | **是** |
| 事件历史的**完整性**（无跳过/截断/重放） | D1-E 日志 + D2-B 锚定 + 可信批次来源 | **否** |
| 证明使用时的**新鲜性** | 网关 fencing + D2-B freshness | **否** |
| 最终 ALLOW / DENY 决策 | 网关组合策略 + fail-closed | **否** |

把上表任何一行下放到"链下但可信"都可以让电路变小，但必须写出信任代价（§5、§6）。

---

## 1. 要证明的关系（先于字段定义）

设：

- `S = (GR, RR, epoch, policy_id)` 为授权状态；
- `C_prev = H_state(GR_prev, RR_prev, epoch_prev, policy_id)` 为前状态承诺，其值来自 D2-B 的
  `anchor_digest` 经域化后的_field_元素，由验证者**带外**从可信 checkpoint 获得；
- `E = (e_1, ..., e_n)` 为私有事件批次 witness；
- `D_E = H_batch(commit(e_1), ..., commit(e_n); n)` 为批次承诺；
- `T` 为 D3-01 已冻结的状态转移规则（含 DirectOnly / Cascade 两个显式策略）。

则电路证明的语句是：

```
公共输入:  C_prev, GR_next, RR_next, epoch_prev, epoch_next, D_E, n, policy_id
私有 witness: GR_prev, RR_prev, E=(e_1..e_n), 每步中间状态与 Merkle 路径

证明:
  (1) C_prev == H_state(GR_prev, RR_prev, epoch_prev, policy_id)       // 前状态锚定
  (2) D_E   == H_batch(commit(e_1)..commit(e_n); n)                    // 批次绑定
  (3) ∀i: e_i 格式合法且相对 S_{i-1} 满足 T 的全部规则                  // 语义
  (4) (GR_n, RR_n) == T*(GR_prev, RR_prev, E)                          // 状态更新
  (5) GR_n == GR_next ∧ RR_n == RR_next ∧ epoch_prev ≤ epoch_next      // 结果绑定 + 单调
```

**注意 (1) 和 (2) 是"开承诺"，不是"证明历史完整"**。验证者信任 `C_prev` 的来源，就等于
信任 `C_prev` 对应的前状态；验证者信任 `D_E` 的来源，就等于信任 `E` 的字节完整性。
电路把这两份信任与语义正确性**焊接**在一起，但不替代它们。

---

## 2. 推荐 public statement（与 D3-01 的 9 字段对照）

```rust
/// EXP-D3-02 推荐公共输入（仅设计，本轮不实现）
pub struct TransitionPublicInputs {
    // ---- 外部可信前状态：来自 D2-B anchor_digest 的域化值 ----
    pub previous_state_commitment: Field, // C_prev，必须公开，必须带外可信
    // ---- 结果状态：供冻结的 D2-A 路径电路直接消费 ----
    pub next_grant_root: Field,           // GR_next
    pub next_revoke_root: Field,          // RR_next
    pub next_epoch: u64,                  // epoch_next
    // ---- 批次绑定：电路内可重算的 Poseidon 承诺 ----
    pub event_batch_commitment: Field,    // D_E，不是 D3-01 的 SHA-256 digest
    pub event_count: u32,                 // n，操作上公开
    // ---- 策略与新鲜度 ----
    pub policy_id: Field,                 // 版本化策略标识，不是 policy.code() 的哈希
    pub previous_epoch: u64,              // epoch_prev，fencing 用
}
```

字段数仍为 **8**，与 D3-01 的 9 个公开输入同量级；变化在语义，不在数量。

与 D3-01 `StateTransitionStatement` 的映射：

| D3-01 字段 | D3-02 处理 | 理由 |
| --- | --- | --- |
| `previous_grant_root` / `previous_revoke_root` | 改为私有 witness，由 `previous_state_commitment` 开承诺 | 与 D2-B 的单一 `anchor_digest` 对接，避免"混搭"前状态 |
| `previous_epoch` | 保留公开 | 网关 fencing 需要比较本地高水位 |
| `next_grant_root` / `next_revoke_root` | 保留公开 | D2-A 电路以 GR/RR 为公共输入，保持可组合 |
| `next_epoch` | 保留公开 | 下一轮 anchor 的输入，且网关需要 |
| `event_batch_digest`（SHA-256） | **替换**为 Poseidon `event_batch_commitment` | SHA-256 在电路内代价过高；见 §3.1 |
| `event_count` | 保留公开 | 限制电路规模、审计覆盖事件数；见 §3.2 |
| `policy_digest` | **替换**为 `policy_id` | 名称哈希不足；见 §3.5 |

`previous_state_commitment` 与 `next_state_commitment` 的处理见 §3.3。

---

## 3. 字段逐项分析（回答任务书六个提问）

### 3.1 `event_batch_digest` 是否应该作为公共输入？

**结论：不要直接使用 D3-01 的 SHA-256 digest；改为电路内 Poseidon 批次承诺。**

理由：

1. D3-01 的 `D_E = SHA256("D3-BATCH-v1" ‖ u64(n) ‖ SHA256(e_1) ‖ ... ‖ SHA256(e_n))`。
   在 Halo2 中计算 SHA-256 需要按 512-bit 分块做消息扩展与 64 轮压缩；即使只有 2 个事件，
   事件摘要 + 批次摘要也至少跨多个压缩块，约束数远超本原型的 Poseidon 路径成本。
2. 更重要的是，**摘要相等不等于语义正确**（D3-01 已用 `digest_alone_is_not_semantic_proof`
   证明过）。把它放进 public input 的作用只是"绑定字节"，这个作用由 Poseidon 承诺同样能完成。
3. 外部日志（D1-E）仍可保留 SHA-256 digest 供人审计；需要让可信批次来源同时对
   Poseidon 承诺签名，或在未来用 Reckle Trees 式 digest-translation 证明桥接两者（见
   `d3_02_related_work.md`）。**这是本方案新增的信任点，必须明写**：
   > 信任"批次来源对正确的事件字节计算了 Poseidon 承诺"。

威胁后果：若把 SHA-256 digest 作为公共输入而不在电路内重算，证明者可以提交任意语义非法的
事件批次并声称它对应那个 digest —— 这正是 D3-01 已经钉死的漏洞。若真在电路内算 SHA-256，
则容量和证明时间会大幅上升，第一版不采用。

编码建议：`D_E = Poseidon(D_BATCH, n, c_1, ..., c_k)`，其中 `c_i` 是事件承诺
`Poseidon(D_EVENT, type, field_1..field_m)`。因为 Poseidon 原生宽度受限，长输入按
`halo2_poseidon::ConstantLength<L>` 的 sponge 规则分块，块数 `k = ceil(L/2)`。

### 3.2 `event_count` 是否有必要公开？

**结论：密码学上可省，操作上保留。**

- 若 `D_E` 的 preimage 第一位就是 `n`（推荐编码），则 `n` 已被承诺，删除它不会引入
  截断攻击；验证者信任 `D_E` 来源即可。
- 但保留 `n` 有三个实际价值：
  1. 网关可据此判断本次证明覆盖的事件规模，防止证明者用一个"小电路证明"冒充大批次；
  2. 电路固定容量 `N_MAX`，`n` 是 public 的容量上界检查输入，便于生成固定 `k` 的参数；
  3. 审计日志可读。
- 删除实验见 §6-E2：攻击者在 `D_E` 不含 `n` 时把 `(e_1,e_2)` 换成 `(e_2,e_1)` 之外还能
  尝试尾部截断；若可信来源对 `D_E` 的 preimage 不含 `n`，截断后的新承诺与旧承诺不同，
  仍会被验证者拒绝。因此**这不是安全必需字段，而是可用性/审计字段**。

### 3.3 是否需要 `previous_anchor_digest` / `next_anchor_digest`？

**`previous_anchor_digest`：必须，且是本方案最重要的新增字段。**

D3-01 的原语句公开了 `previous_grant_root` 与 `previous_revoke_root`，但**谁来认证这两个根**
没有约束。D2-B 的 `AuthzStateAnchor` 已经给出 `anchor_digest = SHA256(GR ‖ RR ‖ epoch ‖ policy ‖ prev_anchor)`，
并由 3-of-4 quorum checkpoint 认证。直接公开这个 digest 的域化值 `C_prev`，可以让：

- 验证者只需信任一个带外值（checkpoint 中的 anchor），而不是分别信任两个根；
- 电路强制 `C_prev` 打开到唯一的 `(GR_prev, RR_prev, epoch_prev, policy_id)`，
  杜绝"根来自不同时刻状态"的混搭攻击（§6-E1）。

**`next_anchor_digest`：第一版不需要独立公开。**

`GR_next`、`RR_next`、`epoch_next`、`policy_id` 都已公开，电路也约束了它们；下一轮证明的
`C_prev` 自然会承接这些值。额外公开 `C_next` 只是把同样的信息再哈希一次，不增加安全性。
若将来做 C 路线（递归/链式）且希望验证者只存一个字段，可把 `C_next` 作为 public output 导出；
那是接口优化，不是安全增强。删除 `GR_next`/`RR_next` 而只保留 `C_next` 也是可行的替代方案，
但会破坏与冻结的 D2-A 电路（它以 GR/RR 为 instance）的直接组合，因此第一版不采用。

### 3.4 `epoch` 是否需要独立公开，还是可以被状态承诺绑定？

**结论：密码学上被承诺即可，但 First version 仍然公开 `previous_epoch` 与 `next_epoch`。**

- `epoch_prev` 已在 `C_prev` 的 preimage 中，`epoch_next` 应写入 `C_next`。若完全私有，
  验证者无法用本地 epoch 高水位做 fencing（D2-B 的 F01–F06 正是这类检查），
  新鲜性会 100% 外包给 checkpoint provider。
- 公开它们是**刻意的冗余**：电路同时约束 `H_state(...epoch_prev...) == C_prev`，
  所以公开值不是可自由选择的旁路输入，而是对可信锚点的可审计展开。

**关键边界：epoch 单调 ≠ 新鲜。** 电路证明 `epoch_prev ≤ epoch_next`，但无法知道
`epoch_next` 是否是"当前时刻"的 epoch。证明生成后发生撤销，或网关验证后才撤销，
都不改变这个证明的有效性。见 `d3_02_security_analysis.md` §2。

### 3.5 `policy_digest` 是否足以约束实际使用的策略？

**结论：不足。替换为版本化 `policy_id`。**

D3-01 的 `policy_digest = SHA256(policy.code())`，其中 `code()` 只有 `"DIRECT_ONLY"` 或
`"CASCADE"` 两个字符串。它没有绑定：

- 策略版本与实现 commit（规则代码改了但 code 不变，digest 不变）；
- 实验模型的参数，例如 `RESOURCE_PREFIX_BYTES = 8`、scope 位掩码语义、epoch 单调规则；
- 叶子承诺的域标签（`D3-GRANT-v1` 等）。

推荐 `policy_id` 由一个冻结规范标识组成，例如
`D3-POLICY-v2 | DIRECT_ONLY | prefix_bytes=8 | commit=<git sha>` 经域化哈希得到。
电路对策略选择用**硬编码常量**实现（第一版只做 DirectOnly，Cascade 作为独立对照电路），
`policy_id` 作为 public input 的作用是让验证者确认"我期望的策略"与"电路实际执行的策略"
一致，而不是让证明者自由选择规则。

若保留 `SHA256(code)` 而电路只实现 DirectOnly，攻击者可以声称 Cascade 证明；验证者无法区分。
这是 §6-E4 的负向测试。

### 3.6 是否应该把请求上下文或资源标识绑定进状态转换证明？

**结论：不绑定请求上下文；资源标识作为 grant 字段已在 GR 叶子中绑定。**

- 状态转换语句回答的是"`S_prev` 经批次 `E` 到 `S_next` 是否合法"。请求上下文
  （agent、action、args、time、request nonce、网关会话）属于**随后的一次授权决策**，
  应由 D2-A 那类路径证明的 `Dq` 请求摘要绑定（D2-A 已冻结，其 `request_digest` 含 9 个词）。
- 把请求上下文塞进状态转换证明的代价：
  1. 每个请求都要重新生成状态转换证明，破坏批次证明的复用；
  2. 请求随机数进入 public input，泄露给所有验证者；
  3. 状态转换与单次决策耦合，无法回答"这个状态在时刻 t 是否通用有效"。
- `resource` 是 `GrantEvent` 的字段，已通过 `grant_leaf` 进入 GR，并由电路约束
  子资源前 8 字节包含于父资源。这是**授权规则的一部分**，与请求上下文不是一回事。

组合方式（网关侧，非电路）：

```
可信 checkpoint ──> C_prev ─┐
                            ├─> 状态转换证明 π_trans ──> (GR_next, RR_next, epoch_next)
可信批次来源   ──> D_E ─────┘                                   │
                                                                v
                                       D2-A 路径证明 π_path(instance=GR_next,RR_next,Dq)
                                                                │
                                                                v
                                        freshness / fencing / fail-closed ──> ALLOW
```

---

## 4. 编码规范

所有哈希输入采用 D3-01 已冻结的 8 字节大端长度前缀（`enc_bytes`）与域标签约定，避免
D1-E 早期 4/8 字节前缀不一致的重演。本轮**不修改**这些实现，只规定新增字段的编码：

| 值 | 编码 | 说明 |
| --- | --- | --- |
| `C_prev` | `field_from_bytes("D3-STATE-COMMIT-v2", anchor_digest_bytes)` | anchor_digest 为 32B SHA-256；用两个 256-bit 输出拼 64B 后 `FromUniformBytes` 入域，避免 32B > 域模数边界 |
| `policy_id` | `field_from_bytes("D3-POLICY-v2", policy_spec_bytes)` | 规范文本冻结在仓库文档，变更必须换 id |
| `D_E` | `Poseidon(D_BATCH, n, c_1, ..., c_k)`，域标签 `D3-BATCH-P-v2` | `c_i = Poseidon(D_EVENT, type, fields...)`，域标签 `D3-EVENT-P-v2` |
| `epoch` | `u64` → 8 字节大端，电路内按字节分解做范围与比较约束 | 与 D3-01 一致 |
| `event_count` | `u32` → 4 字节大端 | 与 D3-01 一致 |
| Merkle 叶子/节点 | 完全复用 D3-01 的 `grant_leaf`(9 词) / `revoke_leaf`(4 词) / `node_hash`(3 词) 与 `D3-` 域标签 | 保证与冻结向量同语义；D2-A 标签对齐仍是未解决问题 |

**关于 SHA-256 到域元素的映射**：D3-01 的 `field_from_bytes` 用两段 SHA-256 拼成 64 字节，
其中第二段是**标签自身的哈希**，因此不同标签得到不同域元素。本设计沿用该口径，
不引入新映射函数，便于与固定向量交叉核对。

---

## 5. 威胁模型与责任边界

### 5.1 攻击者能力

- 控制状态服务与证明者：可以自由选择私有 witness、伪造根、跳过/重排/重放事件、
  选择策略、选择批次边界。
- 控制部分事件内容（scope / issuer / resource / parent / epoch）以图提权。
- 可以拿到任何已公开的证明与公共输入，并尝试在不同上下文重放。
- **不能**伪造 SHA-256 / Poseidon 碰撞；**不能**改写带外可信 checkpoint 中的 `C_prev`
  与 `D_E`（这依赖 D1-E/D2-B 的 quorum 与日志假设，本轮不重新证明）。

### 5.2 四类责任的严格分离

1. **历史语义正确性**：电路约束 `T(S_{i-1}, e_i)` 全部规则。若电路漏约束某规则（例如
   D2-A-R1 修过的 `revoked=0`），证明者可在合法根下生成"合法"证明。必须用负向测试逐个钉死。
2. **状态承诺正确性**：电路约束双树叶子承诺与 Merkle 路径更新。它保证 `GR_next` 是
   `E` 作用于 `GR_prev` 的结果，但不保证 `GR_prev` 是"真实的当前状态"。
3. **历史完整性**：由外部日志认证 + 可信批次来源保证。电路只验证"这批事件的承诺等于
   你给我的 `D_E`"，**不验证"`E` 是授权服务真实历史的连续片段"**。若可信来源被攻破，
   合法但删过撤销事件的批次仍可获证。
4. **新鲜性**：由网关在**工具执行前**做 fencing / 原子检查提交。电路对时间一无所知；
   `epoch_next` 只是被证明的状态版本号。

### 5.3 网关必须执行的最小检查（电路外）

- 从 D2-B 验证器取得可信 `C_prev`，并用它与 statement 的 `previous_state_commitment` 比对；
- 从可信批次来源取得 `D_E` / `n` / `policy_id`，与 statement 比对；
- 用本地 epoch 高水位或 freshness provider 拒绝 `epoch_next` 落后 / provider 不可用；
- 用 `GR_next`/`RR_next` 作为 D2-A 路径证明的 instance；
- 无论路径证明成功与否，DENY 一律 fail-closed（见 `d3_02_security_analysis.md` §3）。

---

## 6. 字段删除 / 添加实验

每个实验的判据都是"能否在**公共输入仍通过外部检查**的前提下产生接受证明"。

| 编号 | 变更 | 攻击构造 | 后果 | 结论 |
| --- | --- | --- | --- | --- |
| E1 | 删 `previous_state_commitment`，回到公开两个前根 | 证明者从旧 checkpoint 取 `GR_prev`，从另一时刻取 `RR_prev`，拼成"混搭"前状态；两个根单独看都真实 | 可证明一个从未存在过的状态转移 | **必须保留** `C_prev`，承诺把四元组锁成一个原子值 |
| E2 | 删 `event_count`，且 `D_E` preimage 不含 `n` | 可信来源只承诺有序事件哈希序列；证明者提交尾部截断批次并重算承诺 | 若来源也被诱导对截断批次签名则通过；来源诚实则因承诺不等被拒 | 非密码学必需；保留用于容量/审计 |
| E3 | 删 `event_batch_commitment` | 证明者提交语义非法事件（scope 越界、重复撤销），不绑定任何批次 | 电路只证明"存在某个合法批次"，与真实历史无关 | **必须保留** |
| E4 | `policy_digest = SHA256(code)` 而不是版本化 `policy_id` | 电路只实现 DirectOnly；证明者声称 `CASCADE` 并公开对应 digest | 验证者无法区分规则集，策略混淆 | **必须替换**为 `policy_id` |
| E5 | 删 `previous_epoch` / `next_epoch` 公开值 | 网关无本地高水位可比；只能信任 provider | 旧 epoch 的状态转换被当作当前有效状态 | 承诺内仍锁 epoch，但 fencing 能力丧失；**操作上必须保留** |
| E6 | 删 `next_grant_root` / `next_revoke_root`，只留 `C_next` | 下游 D2-A 电路无法直接消费结果根 | 不是安全漏洞，是组合性退化 | 第一版保留；递归版可改为只留 `C_next` |
| E7 | 删 `GR_next`/`RR_next` 与 `C_next` 的一致性约束 | 证明者公开一组根，电路内部算另一组 | 结果与证明脱钩 | **必须约束**，两个字段缺一不可 |
| E8 | **添加** request context 到 public input | 每个请求需重证；随机数公开；Dq 与状态语义耦合 | 隐私与可组合性下降，不增加状态语义保证 | **不添加** |
| E9 | 把 SHA-256 digest 作为 public input 但电路不重算 | 证明者用任意事件批次配一个真实 digest | 语义与字节脱钩（D3-01 已证） | **禁止** |
| E10 | 把 `D_E` 改为仅承诺 grant 事件、不承诺 revoke | 证明者删除撤销事件仍能获得合法批次承诺 | 撤销被隐藏，历史完整性失效 | 承诺必须覆盖**两类**事件与顺序 |

---

## 7. 与冻结实现的关系

- 本设计**不修改** `src/lib.rs::StateTransitionStatement`、固定向量、`verify_transition_statement`
  或任何 D3-01 规则代码。D3-02 的语句是**新协议接口**，只在文档中定义。
- D3-01 的三条路径 A/B/C 与新语句的关系：A/B 提供状态转移语义的独立交叉验证，
  C 提供不共享 helper 的参考判定；它们是电路设计的**规范来源**，不是电路实现本身。
- D3-01 的已知未解决项（域标签与 D2-A 不一致、外部历史认证缺失）在本设计中分别以
  "保持 `D3-` 标签并延后对齐"和"`C_prev`/`D_E` 外部可信来源"承接，**没有被声称解决**。

---

## 8. 本字段集的未决问题

1. `C_prev` 使用的 anchor digest 是否需要包含 `log_root`/`checkpoint_hash`（D2-B 有三承诺模型）？
   本设计只取状态相关部分；若网关需要同时验证日志包含性，应另加 D2-B 验证器输出，
   不塞进本电路。
2. Poseidon 批次承诺与 D1-E SHA-256 digest 的桥接尚未实现；第一版依赖可信来源双签。
3. `policy_id` 的规范文本与 git commit 绑定需要一套版本管理流程，本轮只定义字段语义。
4. 若未来改为公开 `C_next` 而非 `GR_next`/`RR_next`，需重新评估与 D2-A 的组合方式。
