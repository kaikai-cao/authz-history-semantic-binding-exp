# EXP-D3-05 Phase 3 — Halo2 Relation Design (No Circuit Implemented)

## 1. 三棵树的认证关系：每个 opening 的四字段

对每次更新，每棵树至少要建立一个"旧叶 opening → 旧根"和一个"新叶 → 新根"的认证关系。每个 opening 明确四个字段：

| 字段 | 含义 | 约束来源 |
| --- | --- | --- |
| `root` | 被认证的原始根 | 绑定到当前事件输入根 cell（GR/RR 已有；IR 新增） |
| `key` | 目标完整 ID（`F` 元素） | 必须等于事件 ID cell，不是截断值 |
| `slot` | 目标叶子位置 | **必须约束 `slot = low_t(key)`**，不允许 witness 自由指定 |
| `leaf` | 目标叶子的完整内容 | 必须由 preimage 在电路内重算哈希得到，且 `leaf.full_id = key` |

### 1.1 GR opening（Parent / target）

- 旧叶：`poseidon::<9>([d_grant, id, issuer, subject, prefix, scope, parent_key, epoch, 1])`
- 约束：`leaf.id == key`；`slot == low_t(key)`（当前 E-R1 由 witness 指定 slot，**这是本阶段识别的缺口**）
- 新叶（Grant）：写入 `child` 的 9 字段，绑定 `child.id == e_G.id`
- 新根：从新叶 + sibling path 重算 depth-4 root，绑定到输出根 cell

### 1.2 RR opening（Parent 未撤销 / 目标未撤销）

- 旧叶：`poseidon::<4>([d_revoke, grant_id, revoker, epoch])`，空槽为 0
- 撤销有效性不能靠单个 opening 证明"不存在"——E-R1 靠全树扫描所有非空叶的 `revoke_id != parent.id`
- IR 方案下若要用 `IR(parent)=ACTIVE` 替代，必须同时约束 RR 中确无 `grant_id=parent` 的记录（否则 N06）
- 新叶（Revoke）：写入 `revoke.leaf()`，绑定 `grant_id == e_R.grant_id`

### 1.3 IR opening（新增）

- 旧叶：`poseidon::<3>([d_index, full_id, state_code])`，`Empty` 编码为 `(0,0,0)`
- 约束：`leaf.full_id == key`（成员）或目标槽为 `Empty`（非成员）；`slot == low_t(key)`
- 三态合法值：`state_code ∈ {0,1,2}`，需 boolean/range 约束（至少两 bit 分解）
- 新叶（Grant/Revoke）：写 `full_id=事件ID, state=ACTIVE/REVOKED`
- 新根：从新叶 + sibling path 重算，绑定到 IR 输出根 cell

### 1.4 `slot = low_t(id)` 与完整 ID 绑定

- `low_t(id) = id.to_repr()[0] & (cap-1)`（D3-04-R1 的 `slot_of`）：电路内需对 `id` 的域表示低 `t` 位做分解，约束 `slot` 等于该分解值
- 不能只验证 Merkle 路径重算根：攻击者可提供任意 slot 的 opening 使根一致，但那是别的 ID 的叶子（N07/N08）
- 截断键碰撞：不同完整 ID 落同槽时必须拒绝；电路需约束 `leaf.full_id == key` 或槽为空

## 2. 同事件绑定约束图

```
                 Event e  (type, id, epoch, commitment)
                /        |        \
               /         |         \
              v          v          v
        GR update    RR update   IR update
        (root_in→out)(root_in→out)(root_in→out)
              |          |          |
              +---- field equality ---+
              |  id / type / epoch / event_commitment
              v
        C_prev → C_next (D3-STATE-v2 state commitment)
```

必须存在的显式相等约束（不是共享 Rust witness 就够了）：

1. `id_GR == id_RR == id_IR == e.id`（Grant 时 `id=e_G.id`；Revoke 时 `id=e_R.grant_id`）
2. `type_GR == type_RR == type_IR == e.type`；Grant flag 门控 GR 写 + IR→ACTIVE，Revoke flag 门控 RR 写 + IR→REVOKED
3. `epoch_GR == epoch_RR == epoch_IR == epoch_next`
4. `event_commitment_GR == event_commitment_RR == event_commitment_IR == e.commitment`
5. 三条根连接：`GR_in[1] == GR_out[0]`、`RR_in[1] == RR_out[0]`、`IR_in[1] == IR_out[0]`（事件 1 读事件 0 输出）
6. 失败原子性：所有前置条件 flag 的合取 `pre_ok` 同时门控三支路的写操作，`pre_ok=0` 时三棵树输出根 == 输入根

**关键声明**：三棵树 root 被同一个 `C` 承诺，不代表它们表达同一事件；必须靠以上 1–6 的字段相等与 flag 门控，才能防止"GR 合法更新 + 另一 ID 的 IR 更新"拼接（N01/N02）。

## 3. 状态承诺接口与 D3-STATE-v2

### 3.1 接口选择

沿用 D3-04 推荐的**接口 B**：索引根并入 `C_prev/C_next`，不新增 public instance 数量。

旧（v1，E-R1 冻结）：

\[
C=H(D_{state}, GR, RR, epoch, policy) \quad (5\ words)
\]

新（v2）：

\[
C_{v2}=H(D_{state}^{v2}, GR, RR, IR, epoch, policy) \quad (6\ words)
\]

- `IR` 放在 `GR/RR` **之后**、`epoch` 之前；理由：保持前 3 个词与 v1 对齐便于审计，新增词插入在状态词尾部
- 6 words 在 rate=2 下仍是 `ceil(6/2)=3` permutations，承诺哈希成本不增加
- 新域标签 `D_state^{v2}`（如 `"D3-STATE-v2"`）确保 v1/v2 承诺不可混用

### 3.2 v1/v2 兼容与 verifier registry

- **旧 Anchor 必须拒绝**：v2 电路用新 `d_state` 域常量，若 verifier 收到 v1 的 `C_prev`（用旧域计算）将无法通过 v2 承诺约束，天然拒绝；反过来 v1 verifier 也不接受 v2 承诺
- `transition_version` instance（第 6 个 public value）作为版本标识：v1 填旧值、v2 填新值；verifier registry 按此值选择对应 vk
- **8 个 public instance 数量保持不变**：`C_prev, epoch_prev, C_next, epoch_next, policy, transition_version, D_E, event_count` 语义不变，仅 `C_*` 的内部哈希输入增加 1 词、`transition_version` 取值新增 v2
- 若安全审计认为必须显式承载 IR root 以便 verifier 直接检查，则可能需要第 9 个 instance；本设计**不主动增加**，但记录该选项作为退路

### 3.3 新旧版本混淆防护

- 域分离：`D_state^{v2}` 与 `D_state^{v1}` 不同 → 跨版本承诺值不同
- 版本 instance：`transition_version` 显式区分 → vk 选择明确
- 状态锚定协议：genesis/checkpoint 必须同时记录版本字段，禁止把 v2 的 `C` 当作 v1 的锚点复用
- 重放：与 E-R1 现状一致，跨证明新鲜性仍依赖外部 nonce/上下文，本设计不解决

## 4. 需要新增的约束族（设计级，未实现）

| 约束族 | 用途 | 相对 E-R1 增量 |
| --- | --- | --- |
| `ir-leaf-hash` | IR 三态叶重算 | 新（3-word Poseidon） |
| `ir-state-range` | state_code ∈ {0,1,2} 与空槽编码 | 新 |
| `ir-slot-low-t` | `slot = low_t(id)` 位分解 | 新 |
| `ir-full-id-eq` | `leaf.full_id == key` | 新 |
| `ir-root-recompute` | IR depth-4 根重建 | 新 |
| `cross-id-eq` | 三支路 ID/type/epoch/commitment 相等 | 新 |
| `three-root-chain` | 三棵树事件间根连接 | E-R1 已有两条（GR/RR），新增 IR 一条 |
| `pre-ok-gate` | 失败原子性门控 | 新（或复用 E-R1 flag 结构） |

## 5. 尚未闭合的设计点（阻断项，不在本阶段解决）

1. **RR 全树扫描能否被 IR 替代**：E-R1 用 RR 全扫描证 Parent 未撤销；若改用 `IR(parent)=ACTIVE`，必须证明 IR 与 RR 一致的电路关系（§1.2），否则 N06。这是"能否降成本"的核心，当前**没有**无需扫描的证明路径
2. **IR 截断键碰撞的电路处理**：D3-04-R1 host 用 `KeyCollision` 拒绝，电路需等价约束；深度 t=4 时 16 槽，碰撞概率不低，处理成本未测
3. **revoker 权限**：IR 不携带 issuer，R4 仍需 GR 叶子或外部 policy
4. **G1/G2 双重检查成本**：若保留 GR 全扫描 + IR opening，成本可能高于 E-R1（Phase 5 分析）
5. **不声称**：本设计只是约束结构描述，未写成 Halo2 代码、未测 K/prove/verify、未证 cost 低于 E-R1
