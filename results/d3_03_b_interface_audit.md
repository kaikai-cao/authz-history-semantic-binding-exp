# EXP-D3-03-B — B1 冻结接口审计

**基线**：`cae2ec722c1beac7b7b5e366dffbe6338466f6ba`（D3-03-A，已验收冻结）
**分支**：`exp-d3-03-b`
**性质**：接口审计 + 最小版本化 B 接口补充。不改 D2-A / D2-B / D3-01 / D3-03-A 任何冻结实现、固定向量或 R2 Field 编码定义。
**一手来源**：本仓 `src/{grant_tree,policy,event,encoding}.rs`、`docs/d3_02_r2_*`、`docs/d3_03_a_circuit_notes.md`、`src/transition/*`；D2-A 仓 `D:\Research\agent-authz-halo2-exp@51d0fa24` 的 `src/{poseidon_hash,model}.rs`。

---

## 0. 结论先行

1. **三系统互不兼容**：D2-A、D3-01、D3-03-A 的 Grant 叶子编码、内部节点哈希、域标签来源、字段→域映射、scope 宽度、resource 语义**均不一致**。任务书"不能直接假设相同"的警告成立。B 阶段**不得**把三者当作同一承诺。
2. **B 阶段统一采用 D3-01 语义口径 + 电路可约束变体**：域标签走 D3-01 `domain_field`（SHA-256→域，类别 II 口径，编译期 fixed 常量）；语义规则（issuer=subject、scope 子集、resource 前缀、epoch 单调、valid）逐条对齐 `policy.rs::check_grant_rules`；**不复用 D2-A 的任何编码**。
3. **R2-02 类别(II) 不进电路是硬约束**：D3-01 的 `key_field = field_from_bytes` 是 SHA-256→域（类别 II），在电路内重算需 O(10⁴)/字段。B 电路把 Grant 字段当作**已映射的域元素 witness**参与 Poseidon 叶子承诺与语义检查，**不重算 SHA-256**；其正确性属 `EXTERNAL_TRUST`。
4. **resource 前缀需要版本化补充 B-INT-01**：D3-01 的前 8 字节前缀语义作用于 32B Hash32，映射到域元素后不可反推。B 电路用"前 8 字节打包域元素 `resource_prefix_f`"进叶子承诺并用域相等检查前缀，这是对 D3-01 叶子 resource 字段的 B 专用变更，明确记录、不声称与 D3-01 冻结根兼容。
5. 状态承诺 `C_prev/C_next` 与 8 个 instance 顺序**完全沿用 A 阶段**，B 不改任何 instance、域标签或 R2 编码定义。新旧 Grant Root 通过 Equality copy 绑定到 A 阶段已有的 4 个域元素根 cell，从而进入 `C_prev/C_next`。

---

## 1. 必答问题逐项回答

### B1-Q1 Parent Grant 叶子编码

**D3-01 冻结实现**（`grant_tree.rs:137-160`，权威）：
```
grant_leaf(grant, valid) = poseidon::<9>([
    domain_field("D3-GRANT-v1"),   // D3-01 DOMAIN_GRANT，SHA-256→域（类别 II）
    key_field(grant_id),           // field_from_bytes("D3-KEY-v1", id32)
    key_field(issuer),             // field_from_bytes("D3-KEY-v1", issuer32)
    key_field(subject),            // field_from_bytes("D3-KEY-v1", subject32)
    key_field(resource),           // field_from_bytes("D3-KEY-v1", resource32)
    F::from_u128(scope),           // u64 bitmask
    parent_f,                      // Some(p) -> grant_field_key(p)=field_from_bytes("D3-GRANT-KEY", p32); None -> 0
    F::from_u128(epoch),           // u64
    valid_f,                       // 1 = 有效
])
```
注意隐藏细节：id/issuer/subject/resource 用标签 `D3-KEY-v1`，而 parent 用**另一个标签** `D3-GRANT-KEY`（`event.rs:83-85`）。二者不可混用。

**B 电路实现变体**（B-INT-01，见 §3）：
```
GRANT_LEAF_B = Poseidon(D_GRANT_B, id_f, issuer_f, subject_f,
                        resource_prefix_f, scope_f, parent_f, epoch_f, valid_f)  // ConstantLength<9>
```
9 个词位置与 D3-01 一一对应；`resource_prefix_f` 替代 `key_field(resource)`（B-INT-01）；字段映射为域元素 witness（电路不重算 SHA-256）。

### B1-Q2 Child Grant 叶子编码

与 Parent 同式，`valid_f = 1`（新建 Grant 必为有效），`parent_f = child 的 parent_grant_id 域元素`。Child 的 `parent_f` 必须在电路内等于被打开 Parent 的 `id_f`（B3 的 parent_grant_id 绑定）。

### B1-Q3 Grant Tree 节点哈希与域分离标签

| 系统 | 节点哈希 | 域标签生成 | 值 |
| --- | --- | --- | --- |
| D2-A | `poseidon::<3>([d_node, L, R])` | BLAKE2b-256(personal="D2A-label-v1") 前16B 大端 u128 → `F::from_u128` | `d_node = label_to_field("D_NODE")` |
| D3-01 | `poseidon::<3>([domain_field("D3-NODE-v1"), L, R])` | `field_from_bytes("D3-FIELD-v1", label)` = `F::from_uniform_bytes(SHA256(label)‖SHA256("D3-FIELD-v1"))` | `D3-NODE-v1` |
| D3-03-B | 采用 D3-01：`Poseidon(D_NODE_B, L, R)` | D3-01 `domain_field` 口径，`Expression::Constant` fixed 常量（非 witness） | `D3-NODE-v1` |

**结论**：D2-A 与 D3 的域标签值**完全不同**（不同哈希族 + 不同 personal/标签），即使同名字 "D_NODE" 也不相等。B 电路只使用 D3-01 口径。

### B1-Q4 Parent Opening 路径结构

- 深度 `d = 4`（16 槽），每层 witness = `(sibling_l: F, dir_l: {0,1})`。
- 方向语义（本 B 接口冻结）：`dir_l = 0` ⇒ 当前节点为左孩子（`left=node, right=sibling`）；`dir_l = 1` ⇒ 当前节点为右孩子（`left=sibling, right=node`）。
- 自底向上：`node_{l+1} = Poseidon(D_NODE_B, left_l, right_l)`，`node_0 = grant_leaf_parent`。
- `dir_l` 由 bool 门约束（`dir·(dir−1)=0`），并进入左右选择表达式——**方向位受电路约束，不是 host 预计算根**。
- 顶层 `node_4` 通过 Equality copy 绑定到 A 阶段 `gr_prev_be` 解码出的域元素 cell（`roots[0]`）。

### B1-Q5 Child 插入位置与旧叶子值

- Child 槽位 `child_slot` 由外部可信 `canonical_assignment` 给出（R2-03：`EXTERNAL_TRUST`），电路只验证"给定槽位下旧叶子、新叶子与根更新正确"，**不验证槽位是唯一规范结果**。
- 插入证明：同一组 `child_path` siblings，用 `leaf_old = 0`（空槽）重算得 `root_prev'`，用 `leaf_new = GRANT_LEAF_B(child)` 重算得 `root_next`。
- 电路约束：`root_prev' == gr_prev_f`（Eq copy 到 A 的 `roots[0]`），`root_next == gr_next_f`（Eq copy 到 A 的 `roots[2]`）。
- 旧叶子为 0 即证明该槽位此前无有效 Grant（唯一性 B09）；若槽位被占则 `leaf_old ≠ 0` 与 witness 声明的 0 冲突 → 拒绝。

### B1-Q6 新旧 Grant Root 计算关系

```
GR_prev = MerkleOpen(parent_leaf, parent_path)      // 路径重算，Eq → gr_prev_f → C_prev
        = MerkleOpen(leaf_old=0,  child_path)       // child 槽位此前为空
GR_next = MerkleOpen(GRANT_LEAF_B(child), child_path) // Eq → gr_next_f → C_next
C_prev  = Poseidon(D3-STATE-P-v2, gr_prev_f, rr_prev_f, prev_epoch, policy_id)   // A 阶段原样
C_next  = Poseidon(D3-STATE-P-v2, gr_next_f, rr_next_f, next_epoch, policy_id)   // A 阶段原样
```
RR 根本阶段不变（撤销不实现），`rr_prev_f = rr_next_f` 沿用 A 的 witness。GR 根**不是** host 直接赋值：它是电路内 Merkle 重算结果，与 A 的 32B 规范编码域元素 Equality 绑定。

### B1-Q7 Scope 与 Resource 的电路表示

**Scope**（对齐 `policy.rs::scope_is_subset`，`child & !parent == 0`）：
- `scope_child`/`scope_parent`：u64，域元素 witness `F::from(scope)`（与 D3-01 叶子一致）。
- 电路内各分解为 64 个 bool（逐位 + 重构等式 `Σ bit_i·2^i == scope_f`）。
- 逐位门 `c_bit · (1 − p_bit) = 0`（仅当 parent 位为 1 时 child 位才能为 1）。
- 边界：最大合法子集（child=parent）通过；最小非法超集（child 多一个 parent 为 0 的位）拒绝。

**Resource**（对齐 `policy.rs::resource_is_subset`，前 8 字节前缀相等；B-INT-01）：
- `resource_prefix_f = Σ_{i=0}^{7} byte_i · 256^{7−i}`，`byte_i` 为 8-bit range-checked 字节 witness。
- 电路检查 `resource_prefix_child == resource_prefix_parent`（域相等），且 `resource_prefix_f` 直接进入 `GRANT_LEAF_B`（改前缀字节即改叶子 → 改根 → 拒绝）。
- 边界：前缀恰好等于 Parent 通过；第 8 字节（索引 7）刚好超出拒绝；第 9 字节（索引 8）差异**不检查**（D3-01 实验模型语义，非漏洞）。

### B1-Q8 三系统兼容性与不兼容性

| 维度 | D2-A (`agent-authz-halo2-exp`) | D3-01 (本仓) | D3-03-B (本阶段) | 兼容? |
| --- | --- | --- | --- | --- |
| 域标签生成 | BLAKE2b personal + u128 | SHA-256×2 → `from_uniform_bytes` | 同 D3-01（fixed 常量） | ❌ D2-A vs 其他 |
| Grant 叶子 9 词语义 | `[tag,id,iss,sub,res,scope,valid_from,valid_until,parent]` | `[tag,id,iss,sub,res,scope,parent,epoch,valid]` | 同 D3-01 结构（resource 改 prefix） | ❌ 语义位置不同 |
| 字段→域 | 字符串 label→BLAKE2b→u128 | 32B Hash32→SHA256→域（类别 II） | 域元素 witness（不重算 SHA256） | ❌ 映射口径不同 |
| scope | u8 / 3-bit | u64 bitmask | u64 bitmask / 64-bit 分解 | D3-01=B ✅；D2-A ❌ |
| resource | label→域（整体） | 32B 前 8 字节前缀 | 前 8 字节打包域元素 | D3-01≈B（B-INT-01）；D2-A ❌ |
| 节点哈希 | `poseidon(D_NODE,L,R)` BLAKE2b 标签 | `poseidon(D3-NODE-v1,L,R)` | 同 D3-01 | ❌ D2-A vs 其他 |
| 树槽位 | 固定 index | canonical_assignment(id集合) | 外部可信给定槽位 | ⚠️ B 不约束规范性 |
| valid 约束 | 专用列 + 门（R1 修复） | valid_flag 字段 | `valid_f` bool 门 + 进叶子 | ✅ 沿用教训 |

**明确决策**：B 阶段是 D3 实验线的延续，**只对齐 D3-01 语义**，与 D2-A 在电路层不兼容是已知设计事实（R2-01 §4、D3-01 README 已记录"D3↔D2-A 域标签未对齐"）。跨系统统一不在本阶段范围。

---

## 2. 冻结接口足够性判定

任务书要求："若冻结接口不足以唯一确定，先提出最小、版本化 B 接口补充，写入文档，不得直接修改冻结规范。"

**判定：R2 冻结接口 + D3-01 冻结代码已唯一确定 Parent/Child 叶子编码、节点哈希、域标签、路径结构、根更新关系、scope/resource/epoch 语义的唯一问题在两处**：
1. D3-01 `key_field`（类别 II）与"类别 II 不进电路"冲突 → 字段必须以域元素 witness 进入电路，SHA256 正确性外部信任。
2. D3-01 resource 前缀作用于 32B 字节，映射到域后不可反推 → 需要 B 专用的"前缀打包域元素"表示。

两处都必须版本化补充，**不修改任何冻结文档/代码**。补充如下。

---

## 3. 版本化 B 接口补充（B-INT-01 ~ B-INT-05）

> 这些是本阶段新增的、B 专用的电路接口约定。它们不改写 R2 / D3-01 / A 的任何冻结内容；若有朝一日与冻结规范统一，需另起阶段并升 `transition_version`。

- **B-INT-01（字段→域与 resource 前缀）**：Grant 的 id/issuer/subject/parent 字段以 `F` witness 进入 `GRANT_LEAF_B`，电路不重算 SHA-256（类别 II 外部信任）；resource 以 `resource_prefix_f = Σ byte_i·256^{7−i}`（i=0..7）进入叶子第 5 词，替代 D3-01 的 `key_field(resource_full)`。电路内前缀相等 = 域相等；完整 32B resource 与 SHA256 绑定属链下。**因此 B 的 GR 根与 D3-01 固定向量根不相同，不声称兼容。**
- **B-INT-02（域标签 fixed 常量）**：`D_GRANT_B = domain_field("D3-GRANT-v1")`、`D_NODE_B = domain_field("D3-NODE-v1")`、`D_EVENT_B = domain_field("D3-EVENT-v1")` 作为 `Expression::Constant` 嵌入门（编译期计算，非 witness），与 D3-01 口径一致。
- **B-INT-03（路径方向）**：`dir=0` 当前节点在左、`dir=1` 在右；每层 bool 门 + 左右选择表达式；4 层。
- **B-INT-04（root 绑定）**：新增电路内 Merkle 根 cell 与 A 阶段 4 根 gadget 输出的域元素 cell 做 Equality copy（实现为 Halo2 0.4 `Region::constrain_equal`）；保留 A 的全部 `< p` 规范编码检查与 C_prev/C_next 重算。
- **B-INT-05（Batch 绑定）**：Child Grant 的事件摘要 `c_child = Poseidon(D_EVENT_B, TYPE_GRANT, child 字段...)` 在电路内重算并 Equality copy 到 A 阶段 `event_commitments[0]`（`event_count` 固定为 1，单 Grant 事件）；改 child 字段或 batch slot 均被拒（B12）。

---

## 4. 本审计的诚实边界

- 不声称 B 电路与 D2-A / D3-01 的 Merkle 根字节兼容——三系统编码不同（§1-Q8）。
- 不声称电路验证了 SHA-256 字段映射（类别 II）——字段域元素由外部可信来源提供。
- 不声称槽位 `child_slot` 的规范布局由电路证明——它是外部可信 witness（R2-03）。
- 不实现 Revoke / Cascade / 多事件 / 递归；epoch 新鲜度仍属外部。
- 本审计是_code-level_源码核对，非独立第三方审计；D2-A 一手源码来自本地冻结仓库 `51d0fa24`。
