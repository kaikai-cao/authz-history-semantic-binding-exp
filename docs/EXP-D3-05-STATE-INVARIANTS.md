# EXP-D3-05 Phase 1 — State Invariants for S = (GR, RR, IR)

## 1. 定义与记号

- 合法 Grant ID：`x ∈ F\{0}`（`key_field` 映射下列表字段元素；ID=0 在 D3-04-R1 中被拒绝）
- `x ∈ GR`：GR 中存在以 `id = x` 为 preimage 的叶子（E-R1/E-R2 中所有已占 GR 叶子 `valid=1`）
- `x ∈ RR`：RR 中存在以 `grant_id = x` 为 preimage 的叶子
- `IR(x) ∈ {ABSENT, ACTIVE, REVOKED}`：D3-04-R1 三态索引查询结果
- 状态 `S = (GR, RR, IR)`；初始 `S0`，事件后 `S'`

## 2. GR 与 IR 的一致性：候选关系及成立条件

任务包给出的候选关系：

\[
\begin{aligned}
IR(x)=ABSENT &\iff x\notin GR\\
IR(x)=ACTIVE &\iff x\in GR\land x\notin RR\\
IR(x)=REVOKED &\iff x\in GR\land x\in RR
\end{aligned}
\]

**逐条分析（不是直接接受）：**

1. **GR 叶子 `valid` 位的真实作用**：`GrantFieldsB::leaf(valid)` 支持 `valid=0` 的叶编码，但 E-R1/E-R2 路径中 Grant 写 `leaf(true)`、Revoke **只写 RR 不改 GR**（见 `e_r2_types.rs:204-210`）。因此在当前构造里，已占 GR 叶一律 `valid=1`，"撤销"完全由 RR 表达。候选关系用 `x∈GR`（不提 valid）在当前语义下等价于"`valid=1` 且 preimage `id=x`"；若未来引入 `valid=0` 的 GR 叶（如 D3-01 的旧 root 语义），三条候选关系必须重写并注明 valid 维度。
2. **能否用 RR 取代 GR 的 valid 语义**：不能。RR 叶子只有 `(grant_id, revoker, epoch)`，**不含** issuer/subject/scope/resource/parent，无法表达授权内容；GR 叶子才有完整授权字段。IR 更只有三态，连授权内容都没有。因此"三态索引"只能回答"这个 ID 处于什么状态"，不能替代"这个授权是什么"。
3. **RR 是否允许指向不存在的 Grant**：E-R1 电路在 Revoke 时打开 target 的 GR 叶子并要求存在，故**正常转换不会**产生孤立 RR 记录。但 E-R2 的 `InitialRrState::from_preimages` 只做 RR 内部唯一性检查，**不检查**每条 S0 RR 记录的 `grant_id` 是否在 GR 中存在。因此 S0 可以携带"RR 指向不存在 Grant"的状态；这在候选关系下会得到 `x∉GR ∧ x∈RR`，IR 应为 REVOKED 却无对应 GR 记录——候选三条关系都未覆盖此情形。
4. **初始 S0 是否满足三条关系**：未被任何电路约束。E-R2 只分别检查 GR 内部与 RR 内部的唯一性，不检查跨结构一致性。必须作为可信 genesis 前提或独立证明（见 §4）。
5. **历史数据不满足关系时的处置**：两条路——(a) 拒绝启动（要求 S0 满足不变量），(b) 迁移（先构造一致的 GR/RR/IR 再锚定）。本阶段**选 (a)** 作为默认边界，不设计迁移路径；迁移需要单独证明语义等价，超出本阶段范围。
6. **同一 ID 在 GR/RR 中多处出现**：
   - GR 内重复：E-R1 全树扫描保证新 ID 不等于任何已占叶 preimage 的 `id`；S0 由 `check_initial_gr` 检查重复 ID
   - RR 内重复：E-R1 扫描保证新 `revoke_id` 不等于任何已占 RR 叶的 `grant_id`；S0 由 `check_initial_rr_unique` 检查
   - **跨 GR/RR**：同一 `x` 可合法地同时出现在 GR 与 RR（这正是 `REVOKED` 的定义）；但"同一 `x` 在 RR 出现两次"必须拒绝
   - IR 截断键碰撞：D3-04-R1 用 `KeyCollision` 显式拒绝不同完整 ID 落入同一槽；电路化时必须保留此拒绝（见 N08）

**结论**：候选三条关系在当前 E-R1/E-R2 语义下**可以成立**，但附带三个前提：(i) 已占 GR 叶为 `valid=1`；(ii) S0 无孤立 RR 记录（需额外检查，当前 E-R2 未做）；(iii) 三态查找本身依赖完整 `full_id` 匹配而非仅截断槽。三者缺一，候选关系即不成立。

## 3. IR 的状态转换关系

定义允许与禁止的转换：

| 转换 | 允许 | 执行器前置条件 |
| --- | --- | --- |
| `ABSENT → ACTIVE` | ✓ Grant | `new_id ∉ GR`（D3-04-R1: `get(new)=ABSENT`） |
| `ACTIVE → REVOKED` | ✓ Revoke | `get(target)=ACTIVE` |
| `ACTIVE → ACTIVE` | ✗ | 重复 Grant：D3-04-R1 返回 `GrantTargetActive` |
| `REVOKED → ACTIVE` | ✗ | 已撤销 ID 永久不可复用：`GrantTargetRevoked` |
| `REVOKED → REVOKED` | ✗ | 重复撤销：`RevokeTargetRevoked` |
| `ABSENT → REVOKED` | ✗ | 撤销不存在授权：`RevokeTargetAbsent` |

逐项明确：

- **Grant ID 全局唯一**：是。E-R1 全树扫描闭合；IR 方案下由 `IR(new)=ABSENT` 前置条件闭合。两者都必须针对完整 `F` 字段 ID，不是截断槽。
- **Revoke 目标必须当前 ACTIVE**：是。E-R1 检查 target GR 存在 + RR 无记录；IR 方案下由 `IR(target)=ACTIVE` 闭合。
- **已撤销 ID 永久不能用**：是。与参考模型一致（`mixed_event_state.rs` 的 `DuplicateGrant` 含已撤销 ID）。这是归纳不变量的一部分，不是临时约定。
- **Parent 必须 ACTIVE**：是。E-R1 扫描 RR 证 `parent ∉ RR` 且打开 GR 证存在；IR 方案下需 `IR(parent)=ACTIVE`，并要求与 GR/RR 的 Parent 检查是同一事件绑定（Phase 3）。
- **第二事件读取第一事件更新后的状态**：是。E-R1 通过 cell equality 把事件 1 的输入根接到事件 0 的输出根；IR 方案必须用同一 cell 连接 `IR_prev(事件1) = IR_next(事件0)`，不能重新从 S0 构造。

## 4. 初始状态 S0 的可信边界

| 问题 | 回答 |
| --- | --- |
| 谁生成 GR/RR/IR 初始状态 | D3-04-R1 的 `seed()` 是可信 S0 初始化接口；E-R2 的 `InitialRrState::from_preimages` 由 builder 接收完整 preimage。两者都是**外部注入**，不是电路证明产生 |
| 如何保证三者初始一致 | 当前**没有保证**。E-R2 只分别检查 GR/RR 内部唯一性，R1 只检查 IR 内部转换；跨结构一致性（§2 三条关系 + 无孤立 RR）从未被验证 |
| IR root 与 GR/RR 不一致时验证器如何处理 | 当前 E-R1 电路的 8 instance 中**根本没有 IR root**，verifier 无从感知 IR。接口 B（D3-04）把 IR 并入 `C_prev/C_next` 后，verifier 只能绑定一个承诺值，**仍不证明**承诺内部的语义一致——需要 genesis 证明或可信锚定 |
| 初始一致性来源 | 采用 E-R2 方案 A 思路：**可信 genesis + host 前置检查**（拒绝重复 ID/槽、拒绝 hash-only RR、拒绝 ID=0、拒绝 IR 截断键碰撞）。不声称电路独立验证任意 S0 |
| 后续转换能否继承不变量 | 能：若 S0 满足 §2/§3 不变量，且每个事件的转换约束保持不变量（Phase 2），则归纳可得 S' 满足不变量。但**基例 S0 仍需外部信任**，每一步转换合法不意味着未经验证的 S0 正确 |

**必须区分**：初始状态正确性（base case，外部信任）与状态转换正确性（inductive step，电路约束）。本阶段所有"IR 与 GR/RR 一致"的结论都以前者为前提。

## 5. 缺失信息清单（不能凭空补字段）

- RR 叶子无"对应 GR 槽位"字段，只有 `grant_id`：`x∈RR` 与 `x∈GR` 的关联只能靠 ID 相等，无法直接 opening 到 GR 的同一槽
- IR 叶子无授权内容字段：`IR(x)=ACTIVE` 不能证明 scope/resource/parent 等授权条件，这些仍在 GR 叶子或外部 policy
- E-R2 的 `check_initial_rr_unique` 只查 RR 内部重复，不查"RR 记录是否都有对应 GR"——若要覆盖孤立 RR，须新增初始检查或明确列为可信前提
- `event_id` 当前不是 E-R1 的独立字段（事件 commitment 由 type/字段/epoch 组成）；是否引入独立 `event_id` 需要 Phase 2/3 分析，不能随意加 instance

## 6. 本阶段不变量结论

在 S0 满足 GR/RR/IR 三者一致（含无孤立 RR）且转换保持不变量的前提下，`S=(GR,RR,IR)` 的三态语义与 E-R1 现有语义兼容；但三者的**一致性本身**目前只有 host 前置检查与可信锚定，**没有 Halo2 证明**。Phase 2–3 要设计的是如何让归纳步（转换）在电路中保持这些关系，而不是声称基例已被证明。
