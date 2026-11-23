# EXP-D3-02-03 — Halo2 电路约束规格（推荐构造 A）

**状态**：规格文档，本轮不实现电路。
**基线规则**：D3-01-R1 已冻结的 `policy.rs` / `grant_tree.rs` / `revoke_tree.rs`。
**技术栈**：`halo2_proofs 0.4.0`、`halo2_gadgets 0.6.0`、`halo2_poseidon 0.2.0`、
Pallas base field（电路域）/ Vesta（承诺），Poseidon `P128Pow5T3`，与 D2-A 同族。
**第一版参数**：树深 `d = 4`（16 槽位）、最多 2 个 grant 事件 + 1 个 revoke 事件、
`DirectOnly` 单一策略，`Cascade` 为独立对照电路（不混入基础电路）。

---

## 0. 列布局与区域（指导编码的骨架）

| 类别 | 列 | 用途 |
| --- | --- | --- |
| advice | `event[q]`（q=0..8） | 当前事件展开字段：type、id、issuer、subject、resource、scope(bytes)、parent、epoch(bytes) |
| advice | `valid_flag` | 当前 grant 是否有效（D2-A-R1 教训：**必须**有专用列与门，不能只在 witness 赋值） |
| advice | `leaf_preimage[9]` | grant 叶子承诺的 9 个 preimage 词 |
| advice | `path_left[d]` / `path_right[d]` | 每层兄弟节点（GR 与 RR 各一组） |
| advice | `inter_root_gr[d+1]` / `inter_root_rr[d+1]` | 路径重算的中间根 |
| advice | `batch_acc` | 批次承诺累积器 |
| fixed | `domain_*` | 域标签对应的域元素（与 off-circuit 同源） |
| selector | `s_event_grant` / `s_event_revoke` | 事件类型互斥 |
| selector | `s_parent_present` | parent 存在性（根授权 vs 子授权） |
| selector | `s_byte8` / `s_scope_check` / `s_resource_check` / `s_epoch_check` | 细粒度规则门 |
| selector | `s_gr_path` / `s_rr_path` | 路径重算启用 |
| selector | `s_not_revoked` | 专用撤销状态门（对应 P05） |

`k` 初值 13–14（行数预算见 `d3_02_construction_comparison.md` §2.3），
以 `MockProver` 通过后再用真实 proof 校准。

---

## 1. 十一模块总表（强制分类）

分类含义：

- `IN_CIRCUIT`：必须由 Halo2 门/查找约束，漏掉即为可伪造证明。
- `OFF_CIRCUIT`：可在链下执行，但必须写明信任假设与攻击代价。
- `EXTERNAL_TRUST`：依赖 D1-E / D2-B 一类外部机制，电路不验证其密码学前提。

| 模块 | 分类 | 一句话关系 | 主要负向测试 |
| --- | --- | --- | --- |
| Event Encoding | IN_CIRCUIT | type ∈ {1,2}，域标签固定，事件承诺可重算 | P10 |
| Grant Validity | IN_CIRCUIT | grant_id 唯一，字段格式合法 | P01/P04（反向） |
| Parent Binding | IN_CIRCUIT | parent 存在且有效，issuer == parent.subject | P04/P05 |
| Scope | IN_CIRCUIT | `scope_child & ~scope_parent == 0` | P03 |
| Resource | IN_CIRCUIT | 前 8 字节前缀包含 | P03 扩展 |
| Revocation | IN_CIRCUIT | 目标存在、未撤销、revoker == issuer | P05/P06/P07 |
| Epoch | IN_CIRCUIT（单调） + EXTERNAL_TRUST（新鲜度） | `epoch_i >= last_epoch`，与 C_prev/D_E 一致 | P12 |
| GR Update | IN_CIRCUIT | 叶子承诺 + d 层 node_hash 得到 GR_next | P08 |
| RR Update | IN_CIRCUIT | revoke 叶子 + d 层 node_hash 得到 RR_next | P09 |
| Batch Binding | IN_CIRCUIT（承诺重算） + EXTERNAL_TRUST（承诺来源） | `D_E = Poseidon(D_BATCH, n, c_1..c_n)` | P10 |
| State Binding | IN_CIRCUIT（开承诺） + EXTERNAL_TRUST（C_prev 来源） | `C_prev` 打开到唯一 (GR_prev,RR_prev,epoch_prev,policy_id) | P11 |

**明确禁止**：为了让电路更小而把 Grant Validity / Parent Binding / Scope / Resource /
Revocation / GR Update / RR Update / State Binding 中任何一项移到 OFF_CIRCUIT 却不在文档中
写明信任代价。D2-A-R1 正是因为把 `revoked` 状态留在 witness 层而被用户发现；本规格从一开始
就用专用列与门约束它。

---

## 2. 逐模块规格

### 2.1 Event Encoding — `IN_CIRCUIT`

- **witness**：`event[0] = type ∈ {1,2}`；grant 时 `event[1..8]`；revoke 时字段少。
- **约束**：
  1. type 为 1 或 2：`(type - 1)(type - 2) = 0`；
  2. `s_event_grant + s_event_revoke = 1`，且与 type 一致；
  3. 域标签取自 fixed 列常量，禁止 witness 提供；
  4. `c_i = Poseidon(D_EVENT, type, fields...)`，使用 `ConstantLength<9>`（grant）或
     `ConstantLength<5>`（revoke）；长度差通过 capacity 元素区分，防止跨类型混用；
  5. 所有 u64 字段按 8 字节分解并做 8-bit range check（查找表）。
- **负向测试 P10**：保持 `D_E` 与 roots 不变，把事件字段改写 → 承诺不等 → 拒绝。

### 2.2 Grant Validity — `IN_CIRCUIT`

- **witness**：`grant_id, issuer, subject, resource, scope, parent, epoch`。
- **约束**：
  1. `grant_id ≠ 0`（零 id 保留）；
  2. 唯一性：用 `slot_of(grant_id)` 打开的槽位值必须是空叶子（0）；若非空则拒绝。
     D3-01 的规范槽位函数依赖"当前 id 集合"，电路内改为：给定旧树中该 id 的路径与
     兄弟节点，证明旧叶子值为 0 且路径根为 `GR_prev`；
  3. `scope` 的 8 个字节逐个 range check（每字节 ≤ 255）；
  4. 叶子承诺 `grant_leaf` 的 9 个 preimage 词与事件字段一一相等（copy constraint）。
- **负向测试**：P01 正向通过；重复 grant 场景（D3-05）拒绝，错误语义 `DUPLICATE_GRANT`。

### 2.3 Parent Binding — `IN_CIRCUIT`

- **witness**：parent 的 9 个 preimage 词 + 其在**当前 GR** 中的深度 d 路径；
  `s_parent_present` 标志。
- **约束**：
  1. `s_parent_present = 0` → 允许根授权，但要求 `parent = 0`（三种编码统一）；
  2. `s_parent_present = 1` → parent 叶子承诺等于 `Poseidon(D_GRANT, parent_field...)`，
     且其路径根为当前中间 GR（不是 `GR_prev` 也不是 `GR_next`，是**处理到第 i-1 步时**的根）；
  3. parent 的 `valid_flag == 1`（**专用列** + `s_not_revoked` 门，禁止仅靠 witness 赋值）；
  4. `issuer_child == subject_parent`；
  5. `epoch_child >= epoch_parent`。
- **负向测试 P04**（parent 不存在：路径根对不上或叶子为 0）、**P05**（parent 已撤销：
  `valid_flag=0` 触发门失败）。

### 2.4 Scope — `IN_CIRCUIT`

- **witness**：`scope_child[8]`、`scope_parent[8]` 字节数组。
- **约束**：逐字节 `child_b & !parent_b == 0`，可用 8-bit 查找表实现；合计 8 组字节门。
  等价于 D3-01 的 `child & !parent == 0` 与参考模型的 `(child | parent) == parent`。
- **负向测试 P03**：子授权把某一位从 0 改成 1 → 至少一字节位与失败 → 拒绝。

### 2.5 Resource — `IN_CIRCUIT`

- **witness**：`resource_child[32]`、`resource_parent[32]`（以 32 字节表示，域元素另算）。
- **约束**：前 `RESOURCE_PREFIX_BYTES = 8` 个字节逐字节相等；其余 24 字节**不约束**（与
  D3-01 模型一致，不得扩大为全 32 字节相等）。
- **负向测试**：改第 8 字节（0-based 索引 7）→ 拒绝；改第 9 字节 → 仍接受（这是实验模型
  的语义，不是漏洞）。

### 2.6 Revocation — `IN_CIRCUIT`

- **witness**：目标 grant 叶子 9 词 + GR 路径 + RR 旧叶子与路径 + `revoker`。
- **约束**：
  1. 目标叶子存在：`valid` 字段所在叶子承诺打开到 `GR_{i-1}`，且 `id` 匹配；
  2. `valid == 1`，由 `s_not_revoked` 门强制（D2-A-R1 教训）；
  3. `revoker == issuer`（从打开的 grant 叶子取 issuer）；
  4. RR 中目标 id 的叶子为 0（未撤销过），否则 `ALREADY_REVOKED`；
  5. 策略为 `DirectOnly` 时只把该叶子的 `valid` 置 0 并写一条 RR 叶子；
     `Cascade` 由独立电路处理，后代集合以 witness 给出，并逐条用 parent 链证明传递闭包；
  6. 撤销后 `GR_i` 与 `RR_i` 必须重新计算（见 2.8/2.9）。
- **负向测试 P06**（非 issuer 撤销）、**P07**（重复撤销）、**P05**（撤销已撤销 parent 的子）。

### 2.7 Epoch — `IN_CIRCUIT`（单调） + `EXTERNAL_TRUST`（新鲜度）

- **witness**：`epoch_prev, epoch_1..epoch_n, epoch_next` 的字节分解。
- **约束**：
  1. `epoch_prev <= epoch_1 <= ... <= epoch_n = epoch_next`；
  2. `epoch_prev` 与 `C_prev` 的 preimage 一致；
  3. `epoch_next` 公开且与最后一步一致；
  4. 与 `policy_id` 一起进入 `state_commitment`。
- **明确不约束**：`epoch_next` 是否"当前"。这是 freshness，见 `d3_02_security_analysis.md` §2。
- **负向测试 P12**：把 `epoch_next` 改小（或事件 epoch 回退）→ 拒绝。

### 2.8 GR Update — `IN_CIRCUIT`

- **witness**：新叶子 9 词、每层兄弟节点 `path_left/right`。
- **约束**：
  1. `leaf_new = Poseidon(D_GRANT, id, issuer, subject, resource, scope, parent, epoch, valid_new)`，
     `valid_new` 为 0/1，由 boolean 门约束；
  2. 对 `l = d-1..0`：
     `node_l = Poseidon(D_NODE, select(path_left[l], node_{l+1}), select(path_right[l], node_{l+1}))`；
  3. 最终 `node_0 == GR_next`（grant 事件）或 `GR_i` 中间根（批次未结束）；
  4. 规范槽位：第一版固定 `d=4` 且 witness 给出 `slot` 索引，约束 `slot < 2^d`；
     槽位冲突的规范序探测在链下由 D3-01 的 `canonical_assignment` 计算后作为 witness 输入，
     **其正确性在电路内通过叶子承诺 + 路径一致性间接验证，不直接约束探测顺序**。
     这是一个明确的信任边界：电路证明"这棵树按给出的槽位布局重算正确"，
     不证明"槽位布局是 D3-01 规则下的唯一结果"。若要约束后者需额外约 `2^d` 个比较门，
     第一版不做。
- **负向测试 P08**：伪造 `GR_next`（改一个兄弟节点或叶子）→ 路径重算不等 → 拒绝。

### 2.9 RR Update — `IN_CIRCUIT`

- **witness**：`revoke_leaf` 4 词、RR 路径。
- **约束**：与 GR 同理；`leaf_new = Poseidon(D_REVOKE, id, revoker, epoch)`，
  路径根为 `RR_next`。`DirectOnly` 下一个 revoke 事件只写一条 RR 叶子。
- **负向测试 P09**：伪造 `RR_next` 或改 `revoker` → 拒绝。

### 2.10 Batch Binding — `IN_CIRCUIT`（承诺重算） + `EXTERNAL_TRUST`（承诺来源）

- **witness**：全部 `c_i`、`n`。
- **约束**：`D_E == Poseidon(D_BATCH, n, c_1, ..., c_n)`，n 作为公开输入且 `n <= N_MAX`；
  `c_i` 顺序固定，不得重排。
- **信任边界**：验证者必须带外取得可信 `D_E`。电路不验证 `E` 是否是授权服务的完整历史。
- **负向测试 P10**：改任一事件或交换两个事件顺序 → 承诺不等 → 拒绝。

### 2.11 State Binding — `IN_CIRCUIT`（开承诺） + `EXTERNAL_TRUST`（C_prev 来源）

- **witness**：`GR_prev, RR_prev, epoch_prev, policy_id`。
- **约束**：`C_prev == Poseidon(D_STATE, GR_prev, RR_prev, epoch_prev, policy_id)`；
  `policy_id` 必须是电路内固定常量（第一版 DirectOnly 版本），公开值不等则拒绝；
  `GR_prev` / `RR_prev` 同时作为第一条事件路径的起点。
- **信任边界**：`C_prev` 来自 D2-B anchor + quorum checkpoint + 网关带外核对，
  电路不验证 quorum 签名、日志包含性或新鲜度。
- **负向测试 P11**：保持其他输入不变，把 `previous_state_commitment` 换成另一个合法旧状态的
  承诺 → 若验证者仍接受该公共输入（即外部信任失效），电路会给出接受证明；
  在验证者按 D2-B 核对的场景下应被gw拒。这个测试要**如实记录两层结果**。

---

## 3. 完整性检查清单（编码前对照）

| # | 检查 | witness | 约束关系 | 负向测试 |
| --- | --- | --- | --- | --- |
| 1 | type 二值 | `event[0]` | `(t-1)(t-2)=0` | P10 |
| 2 | 域标签常量 | fixed 列 | copy + 常量检查 | P10 |
| 3 | grant_id 唯一 | 旧叶子 + 路径 | 旧叶子=0 且路径根=GR_prev | D3-05 |
| 4 | parent 存在 | parent 叶子 + 路径 | 路径根=GR_{i-1} 且叶子非空 | P04 |
| 5 | parent 有效 | `valid_flag` | `s_not_revoked · valid = 0` 反向 | P05 |
| 6 | issuer 绑定 | issuer/subject 域元素 | 相等 | D3-04 |
| 7 | scope 衰减 | 8+8 字节 | 逐字节 `c & !p = 0` | P03 |
| 8 | resource 包含 | 8+8 字节 | 逐字节相等 | P03 扩展 |
| 9 | revoke 权限 | revoker + issuer | 相等 | P06 |
| 10 | 重复撤销 | RR 旧叶子 | 旧叶子=0 | P07 |
| 11 | epoch 单调 | 字节分解 | 逐字节比较链 | P12 |
| 12 | GR 叶子 | 9 词 | Poseidon L=9 | P08 |
| 13 | RR 叶子 | 4 词 | Poseidon L=4 | P09 |
| 14 | 路径重算 | 兄弟节点 | d 层 Poseidon L=3 | P08/P09 |
| 15 | 批次承诺 | c_1..c_n, n | Poseidon L=5+ | P10 |
| 16 | 前状态承诺 | 4 词 | Poseidon L=5 | P11 |
| 17 | 结果绑定 | GR_next/RR_next | 与最后中间根相等 | P08/P09 |

---

## 4. 明确不进第一版电路的内容

| 项 | 原因 | 归类 |
| --- | --- | --- |
| SHA-256 事件摘要 / 批次摘要 | 电路代价高，Poseidon 承诺足以绑定字节 | OFF_CIRCUIT（外部来源仍算 SHA-256） |
| Ed25519 / quorum 验签 | 已有 D2-B 实现，电路内重复无意义 | EXTERNAL_TRUST |
| D1-E 日志 inclusion / consistency | 同上 | EXTERNAL_TRUST |
| 规范槽位探测顺序的完整约束 | 需要额外逐槽比较，第一版固定容量下由外部生成 witness | OFF_CIRCUIT，已在 2.8 明写 |
| Cascade 传递闭包 | 第一版只做 DirectOnly，另起对照电路 | 独立电路，不混入 |
| DENY / 不存在路径 | 需要非存在性证明，语句不同 | 不做，见安全分析 §3 |
| freshness / 执行时 fencing | 电路不知道时间 | EXTERNAL_TRUST |
| D3 ↔ D2-A 域标签统一 | D3-01 冻结且 README 记录为未解决 | 延后 |

---

## 5. 与 D2-A-R1 教训的对照

D2-A-R1 的缺陷是"撤销状态只在 witness 层给出，门没有强制 `revoked=0`"，
导致撤销后仍能构造通过的证明（当时 prover 仍出 proof，由 verifier 拒绝）。
本规格的对应防护：

- `valid_flag` 有**专用 advice 列**（§0）；
- `s_not_revoked` 是**专用 selector**，在 parent binding（2.3）和 revocation（2.6）两处启用；
- P05/P06/P07 三个负向测试必须在 MockProver 层**失败**，并在真实 proof 层由 verifier 拒绝；
- 测试报告必须区分"MockProver 拒绝"与"prover 出 proof 但 verifier 拒绝"两种情形，
  沿用 D2-A-R1 的诚实记录口径。
