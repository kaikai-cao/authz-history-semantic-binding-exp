# EXP-D3-02-R1-02 — Canonical Slot 的信任边界

**基线**：`98906dd1f94f7d9922f7759989f896c418c85561`
**分支**：`exp-d3-02-r1`
**性质**：设计修订。本轮不实现电路，不修改 D3-01-R1 冻结的 `grant_tree.rs`。

---

## 0. 问题陈述与一句话结论

D3-01-R1 把槽位分配固化为 id 集合的**纯函数**（消除插入序依赖）：

```
canonical_assignment(ids, depth):
    capacity = 1 << depth
    1. 将 ids 按 32B 规范字节序排序                       // BTreeSet<Hash32>
    2. 对每个 id（按规范序）:
         start = initial_slot(id, depth)
               = low64be( field_from_bytes("D3-SLOT-v1", id[32B]) ) & (capacity - 1)
         slot  = 从 start 起环形线性探测的第一个空槽
         占用 slot，写入 assigned[id] = slot
    3. 若任一 id 找不到空槽 -> TREE_CAPACITY_EXHAUSTED
```

D3-02 电路（§2.8）只验证"给定 witness 提供的 `slot` 下的 Merkle 路径重算"，**不验证槽位分配规则
本身**。这产生两个必须分开的保证：

| 保证 | 内容 | 电路是否提供 |
| --- | --- | --- |
| **布局更新正确性** | 在给定 `id → slot` 布局下，叶子写入与 d 层路径重算得到声称的根 | ✅ 提供（叶子承诺 + 路径） |
| **布局规范性** | 该布局等于 `canonical_assignment(当前 id 集合, depth)` 的唯一输出 | ❌ 不提供 |

> **结论（明确选择）**：第一版采用**方案 A：外部可信布局**——由可信状态服务执行
> `canonical_assignment` 并对完整布局摘要签名，电路继续只验证给定布局下的树更新。
> 不采用方案 B（电路内完整验证布局）：其约束量在 d=4/16 槽位下为 `O(10^4)–O(10^5)`，
> 比整个事件语义电路大一个数量级以上。任务书要求的**第三种方案（局部 canonicality）**
> 在数学上可行，但**必须**以"前布局已被证明规范"为归纳锚点；本栈无 in-circuit verifier，
> 无法提供该锚点，因此第一版只记录为未来方向，不作为独立保证。R07/R08 按选定信任模型
> 处理：电路层**接受**非规范布局，网关/布局验证器**拒绝**——两层结果必须如实记录，
> 不得声称电路拒绝。

---

## 1. 一手事实与规范化要求

来源：`authz-history-semantic-binding-exp/src/grant_tree.rs:78-134`、`src/encoding.rs:97-102`。

1. **规范排序键**是 id 的 32 字节本身（`Hash32` 实现 `Ord`），不是域元素、不是槽位号。
2. **初始槽位** 用独立域标签 `D3-SLOT-v1`（与叶子键 `D3-KEY-v1` 分离），输入是**完整 32B id**，
   取 `field_from_bytes` 结果 `to_repr()` 的**前 8 字节**拼大端 u64，再取低 `depth` 位。
3. **探测**是环形线性探测：`slot = (start + offset) & (capacity - 1)`，`offset = 0..capacity`，
   取第一个 `!occupied[slot]`。
4. **单射**由 `assigned: BTreeMap<Hash32, usize>` 维护；满树返回类型化错误
   `TREE_CAPACITY_EXHAUSTED`。
5. **删除/重插**：`try_upsert` 用新旧 `canonical_assignment` 比较，被 displaced 的 id 会被
   **复制到新规范槽位**（不重新哈希叶子），只重算 dirty 槽位的路径（`grant_tree.rs:243-300`）。
   这意味着一次插入可能改变**多个**已有 id 的槽位——这是局部方案最坏情况分析的关键。

---

## 2. 方案 A：外部可信布局（推荐）

### 2.1 机制

可信状态服务（与 R1-01 的 Bridge Service 可为同一 quorum，但**建议独立密钥**以职责分离）
执行 `canonical_assignment`，对以下结构签名：

```
pub struct CanonicalLayoutStatement {
    pub layout_version: u32,             // 布局规范版本，例 1（D3-SLOT-v1 + 排序 + 探测规则）
    pub tree_depth: u8,                  // d = 4，绑定容量 16
    pub previous_state_commitment: Field,// R1-01 的 C_prev
    pub next_state_commitment: Field,    // 下一轮 C_next（或 GR_next/RR_next 的组合承诺）
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub changed_ids: Vec<Hash32>,        // 本次新增/删除/更新的 id
    pub assigned_slots: Vec<(Hash32, usize)>, // 本次受影响 id 的新槽位（可含 displaced id）
    pub assignment_digest: Hash32,       // 完整 id→slot 映射的承诺，见下
    pub nonce: [u8; 16],
    pub expires_at: u64,
}
```

**`assignment_digest` 编码**（规范、可复核，不复用叶子哈希）：

```
assignment_digest = SHA256(
    enc_bytes("D3-LAYOUT-v1")
  ‖ u32be(layout_version) ‖ u8be(tree_depth)
  ‖ enc_bytes( C_prev_field_bytes ) ‖ enc_bytes( C_next_field_bytes )
  ‖ u64be(prev_epoch) ‖ u64be(next_epoch)
  ‖ enc_bytes( concat( sorted(id ‖ u32be(slot)) for all (id,slot) in canonical_assignment ) )
  ‖ enc_bytes(nonce) ‖ u64be(expires_at)
)
```

其中 `sort` 按 id 的 32B 字节序，`enc_bytes` 用 D3-01 的 8 字节大端长度前缀。
**完整映射**（不只是 changed 部分）进 digest，确保签名覆盖整棵布局。

### 2.2 签名、承诺、版本、新鲜性

| 维度 | 设计 |
| --- | --- |
| 签名 | quorum 签名（阈值 k-of-n），公钥集合与阈值由验证端**配置**，不采信自报；与 D2-B witness 密钥建议分离 |
| 承诺 | `assignment_digest` 绑定完整 `id→slot` 映射 + 前后状态承诺 + epoch + nonce |
| 版本 | `layout_version`/`tree_depth` 与验证端配置常量比对；规则变更必须换版本 |
| 新鲜性 | `expires_at` 短 TTL + `nonce` 一次性 + `previous_state_commitment` 与 R1-01 Bridge 的 `C_prev` 交叉核对 |
| 与电路接口 | 电路仅消费 witness 给出的 `slot`；布局签名在电路外验证，验证器输出"布局可信"布尔值给网关 |

### 2.3 信任代价（必须明写）

- 可信状态服务若**签名了非规范布局**，电路仍会给出接受证明（电路只验证该布局下树重算正确）。
- 这是 `d3_02_security_analysis.md` U6 的具体化：**电路不证布局规范性，只证布局更新正确性**。
- 缓解：布局服务 quorum + 审计者独立重算 `canonical_assignment` 并比对 `assignment_digest` +
  网关拒绝未通过布局验证的证明。**审计者重算**是链下 falsification，不赋予电路层保证。

---

## 3. 方案 B：电路内验证布局（不采用，给出实际约束估算）

本节回应任务书"不能仅写约 16 个比较门"的要求。列出电路内完整验证
`canonical_assignment(ids, d=4)` 所需的**实际比较关系**，并逐项估算。

记当前 id 数上限为 `M`（原型容量 d=4 → 16 槽位，`M ≤ 16`），每个 id 的初始槽计算为 `S_i`。
witness 提供 `slot_i`、`S_i`、每步 `occupied[16]` 位数组、排序后的 id 序列。

### 3.1 模块 B-1：id 规范字节序排序

- **约束**：按规范序给出的 id 序列满足 `id_1 < id_2 < ... < id_M`（32 字节 big-endian 字典序）。
- **比较关系**：每对相邻 id 需 32 个字节的相等/大小比较。按高位优先，规范化为：
  `eq_j = ∏_{b=0}^{31}(1 - xor(id_a[b], id_b[b]))` 的布尔链；大小比较需
  `lt = Σ_b ( (1-lt_prefix) · (1-eq_prefix_b) · (id_a[b] < id_b[b]) )`，其中 `id_a[b] < id_b[b]`
  用 8-bit 查找表实现（`id_a[b] + (255 - id_b[b]) < 255` 的进位位）。
- **门数**：每对相邻约 `32 × (1 xor + 1 eq-accum + 1 8-bit lookup + 2 布尔) ≈ 5` 个约束行，
  共 `(M-1) × 32 × 5 = 15 × 32 × 5 = 2 400` 行/约束量级（M=16）。若用排序网络强制排列，
  比较器数 `O(M log²M)`，更大；本估算取"witness 已排序，仅验证"的最小值。

### 3.2 模块 B-2：初始槽位计算 S_i

- **约束**：`S_i = low64be( field_from_bytes("D3-SLOT-v1", id_i[32B]) ) & 15`。
- **电路实现**：`field_from_bytes` 内部是 `SHA256(id)`（32B 单块压缩）与
  `SHA256("D3-SLOT-v1")`（常量，可放 fixed 列），拼 64B 后 `from_uniform_bytes` 模约减。
  电路内必须重算 `SHA256(id_i)` 并做位分解取前 8 字节低 4 位。
- **门数**：单个 512-bit SHA-256 压缩在 Halo2（8-bit lookup 优化）约 `1.5k–3k` 约束/块
  （保守静态估计，未经实测）。`from_uniform_bytes` 的 512→255 位模约减需额外非原生运算
  （本栈无 gadget，属 BLOCKED 子问题；若只取 64B 中的前 8 字节，仍需完整计算哈希输出）。
  取 `≈ 2 000` 约束/id × 16 ids = `≈ 32 000` 约束。**这是方案 B 的最大障碍。**

### 3.3 模块 B-3：线性探测"首个空槽"

- **约束**：对每个 id（按规范序插入），`assigned_slot_i` 是从 `S_i` 起第一个空槽：
  - (a) 对所有 `offset = 0..(assigned_slot_i - S_i - 1 mod 16)`：该槽在此之前已被占用；
  - (b) `assigned_slot_i` 在该时刻为空。
- **比较关系**：维护插入时刻的 `occupied_t[16]` 位数组（每步 witness）。"槽 j 是否被占用"
  等价于"存在已插入 id 的 assigned_slot = j"，需对已插入 id 做相等比较；更高效的做法是让
  `occupied_t[j]` 为 witness 位并用"每一步恰好翻转一个位 + 该位对应本步 id 的槽"约束一致性，
  但仍需 `occupied_t[j] = OR_{a≤t}(slot_a == j)` 的查找论证。
- **门数**：最坏 `M × capacity = 16 × 16 = 256` 次探测检查；每次检查需确认槽占用状态
  （16 个 id 的槽相等比较 → 16 次 4-bit 不等判定 ≈ 16 个约束），即
  `256 × 16 ≈ 4 096` 个相等比较，每个 4-bit ≈ 4 个约束 → `≈ 1.6 × 10^4` 约束量级。
  加上环形索引 `mod 16` 的位运算，**保守上界按最坏探测链全长计，
  取 `≈ 1.6 × 10^4` 约束**。

### 3.4 模块 B-4：单射（id → slot 一一对应）

- **约束**：`assigned_slot_i` 两两不等。
- **比较关系**：`C(M,2) = 120` 对，每对 4-bit 槽号不等判定（可用 `∏_b (1 - eq_bit)` 的逆，
  或 range + 全差积非零约束）。约 `120 × 4 = 480` 约束。**这部分相对便宜。**

### 3.5 模块 B-5：删除与重插后的规范布局

- **约束**：`slot_i^{new} = canonical_assignment(ids^{new}, d)[id_i]`——即删除/新增后 displaced
  id 搬到新规范槽位，与 D3-01-R1 `try_upsert` 一致。
- **电路实现**：等价于对 `ids^{new}` **完整重跑** B-1..B-4；无法只改局部（这正是 §4 局部方案的难点）。
- **门数**：同 B-1..B-4 之和。

### 3.6 方案 B 总估算（明确为静态粗估）

| 模块 | 约束量级（d=4, M=16） |
| --- | --- |
| B-1 规范排序验证 | ≈ 2 400 |
| B-2 初始槽位（SHA-256 × 16） | ≈ 32 000（含未解决的模约减） |
| B-3 探测首个空槽（最坏） | ≈ 16 000 |
| B-4 单射 | ≈ 480 |
| B-5 删除/重插（重跑） | ≈ 与 B-1..B-4 同量级（若每步都验证） |
| **合计（单次布局，不含 B-5 重复）** | **≈ 5 × 10^4 约束** |

对比：整个事件语义 + 双树更新电路（D3-02 构造 A）≈ 7k–9k 约束。
**方案 B 单是初始槽位的 SHA-256 就比整个语义电路贵数倍，第一版不可行。**
所有数字为基于一手编码结构的静态数量级推断，**未经 MockProver/实测**，标记为粗估。

---

## 4. 第三种方案：局部 canonicality 证明（重点分析）

### 4.1 定义与直觉

不重证整棵树的槽位布局，只证明**本次修改涉及的 id 与受影响槽位**符合局部规范性：

```
局部规范转移:  (L_prev, changed_ids) -> L_next
   L_next 在 changed_ids 涉及的槽位上等于 canonical_assignment(ids_next, d) 的输出
   其余槽位保持 L_prev 的值
```

直觉：一次只改 ≤3 个 id，为什么要把 16 个 id 的 SHA-256 初始槽都重算一遍？

### 4.2 可行性与必要条件

局部 canonicality **不是独立命题**，它是**归纳步骤**：

> 若 `L_prev = canonical_assignment(ids_prev, d)`（归纳假设），
> 且局部转移规则正确实现 D3-01-R1 `try_upsert` 的 displacement 逻辑，
> 则 `L_next = canonical_assignment(ids_next, d)`。

因此它成立**必须**同时满足：

1. **归纳锚点**：`L_prev` 已被证明规范（要么外部签名认证完整布局——回到方案 A；要么递归证明前一步——本栈无 in-circuit verifier）。
2. **转移完整性**：局部转移覆盖了所有 displaced id。D3-01-R1 中一次插入可挤走任意多个已有 id（`grant_tree.rs:270-286`），局部证明必须把它们全部列出并约束其新槽位。
3. **探测链无隐藏碰撞**：未被 changed 触及的 id，其槽位仍是"从其 S_i 起第一个空槽"——这需要前布局规范（回到 1）。

**结论**：没有可信归纳锚点时，局部 canonicality 无法自证 `L_next` 全局规范。
它只能把"信任整棵布局"弱化为"信任一次归纳步骤 + 信任前布局"。本栈无递归 verifier，
前布局只能通过外部签名获得——所以局部方案的锚点仍然是方案 A 的信任，**不能独立消除它**。

### 4.3 适用条件、证明范围、最坏情况

| 维度 | 结论 |
| --- | --- |
| 适用条件 | (i) 存在可信的规范前布局（外部签名或递归证明）；(ii) 电路能约束 changed + displaced 集合的槽位；(iii) 布局版本/深度固定 |
| 证明范围 | changed_ids（原型 ≤3）+ 由 displacement 触及的 id + 这些 id 探测链上的槽位 |
| 最坏受影响槽位数 | **全部 M 个槽位**。构造：新 id 的规范序最小且 `S_new` 与所有已有 id 的探测链重叠，新 id 抢占首槽并触发连锁位移；D3-01-R1 的 `try_upsert` 会把 displaced id 逐个搬到新规范槽，最坏重排整条链（M=16）。因此局部方案在最坏情况下退化为全局重证 |
| 与全局 canonical assignment 关系 | 局部 = 全局的归纳一步；全局 = 从 genesis 规范布局出发的局部序列。缺归纳锚点则局部无意义 |

### 4.4 无法覆盖的攻击（局部方案单独的盲区）

- **L-A1 非规范前布局**：证明者在一个非规范 `L_prev` 上做局部规范转移，得到"局部正确但全局非规范"
  的 `L_next`。若前布局锚点不可信，攻击成功。**这正是 R07/R08 的攻击模型。**
- **L-A2 遗漏 displaced id**：新 id 挤走多个已有 id，局部证明只列出部分 displaced id；未列出的
  id 留在非规范槽位，但电路若只检查 changed 集合就发现不了。
- **L-A3 隐藏碰撞**：某未 changed id 的 `S_i` 与实际占用冲突，但在前布局中已被"洗白"；局部检查
  看不到，因为只验证本步变更。

三者共同说明：**局部 canonicality 不是独立的信任消除机制**，它依赖方案 A 的布局签名或未来
递归证明提供的归纳锚点。

---

## 5. 最终选择（明确，不罗列）

1. **第一版：方案 A（外部可信布局签名）**。理由：方案 B 约束量 ≈ `5×10^4`（粗估），是语义电路
   数倍；局部方案缺归纳锚点，本栈无递归 verifier。方案 A 把布局规范性显式交给可信状态服务
    quorum + 审计重算，电路保持只证"给定布局下更新正确"。
2. **电路内分工**：`slot`  witness 与 Merkle 路径更新保持 `IN_CIRCUIT`（D3-02 §2.8 不变）；
   布局规范性为 `EXTERNAL_TRUST`（由布局验证器输出布尔给网关）。
3. **接口新增**：集成语句增加 `layout_digest`（= `assignment_digest`）作为公开字段，供网关核对
   布局签名（见 `d3_02_r1_integrated_statement.md`）。
4. **局部 canonicality**：记录为**未来方向**，触发条件 = 本栈具备 in-circuit verifier 或外部
   提供可信规范前布局链。本轮**不作为任何保证声称**。

### 5.1 R07 / R08 的测试层级归属（诚实记录两层）

| 测试 | 攻击 | 电路层（MockProver/真实 proof） | 布局验证器层 | 网关集成层 |
| --- | --- | --- | --- | --- |
| R07 | 非规范槽位分配 | **接受**（电路不检查布局规则，只验证给定布局下树重算） | **拒绝**（`assignment_digest` 与重算不符 / 无有效布局签名） | **拒绝** |
| R08 | 删除后非规范重插 | **接受**（同上，displacement 布局仍能满足路径重算） | **拒绝** | **拒绝** |

**必须**在测试报告中写明"电路层接受"，不得写成"电路拒绝非规范布局"。这与上一轮 P11
（电路内接受、网关外拒绝）的诚实口径一致。电路层唯一能拒绝的是"给定布局下 Merkle 根算错"
（P08/P09），不是"布局非规范"。

---

## 6. 本方案不能声称的内容

- **不能**声称"电路保证 canonical assignment"——它不保证，布局规范性在电路外。
- **不能**声称"局部 canonicality 已解决"——只有归纳框架，无归纳锚点实现。
- **不能**把 `≈5×10^4` 约束当实测——是静态粗估，未经 MockProver/真实证明校准。
- **不能**声称方案 A 消除了"状态服务撒谎布局"——只是把责任明确给 quorum 与审计重算（U6）。
