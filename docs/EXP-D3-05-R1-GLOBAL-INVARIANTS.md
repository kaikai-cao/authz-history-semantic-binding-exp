# EXP-D3-05-R1 Phase 1 — 全局状态不变量的严格定义

## 1. 集合与映射

记合法 ID 域为 `L = F \ {0}`（`key_field` 单射为外部信任前提）。对状态 `S = (GR, RR, IR)` 定义：

\[
G(S)=\{x\in L:\text{GR 中存在完整 ID 为 }x\text{ 的已占叶}\},
\]

\[
R(S)=\{x\in L:\text{RR 中存在 grant_id 为 }x\text{ 的已占叶}\},
\]

\[
I(S):L\to\{ABSENT,ACTIVE,REVOKED\}.
\]

本轮把 GR 的 `valid` 位固定为：已占 GR 叶一律 `valid=1`。若未来允许 `valid=0` 叶，`G(S)` 的定义必须改写，本轮所有结论随之失效。

## 2. 三态一致性：必须加强任务书的三条式子

任务书给出：

\[
x\notin G \iff IR(x)=ABSENT \tag{C1}
\]

\[
x\in G\land x\notin R \iff IR(x)=ACTIVE \tag{C2}
\]

\[
x\in G\land x\in R \iff IR(x)=REVOKED \tag{C3}
\]

**不能直接接受为完备划分**：若存在孤立 RR 记录，即 `x∉G` 但 `x∈R`，则 (C1) 给出 `IR(x)=ABSENT`，(C2)(C3) 均不适用，三条式子全部满足却不合法。因此必须补：

\[
R(S)\subseteq G(S). \tag{C0}
\]

并把三态定义收紧为互斥完备的三分支：

\[
IR(x)=ABSENT \iff x\notin G \land x\notin R,
\]

\[
IR(x)=ACTIVE \iff x\in G \land x\notin R,
\]

\[
IR(x)=REVOKED \iff x\in G \land x\in R.
\]

在 (C0) 下这等价于 (C1)+(C2)+(C3)，但 (C0) 不能省。**这是本轮第一个必须显式写出的前提修正。**

## 3. 额外检查项（逐题回答）

| 检查项 | 结论 | 依据 / 当前状态 |
| --- | --- | --- |
| GR 是否可能有重复 ID | 转换中不应有；S0 需检查 | E-R1 `scan-id-neq` 在 Grant 时拒绝新 ID 等于任一已占叶 ID；E-R2 `check_initial_gr` 检查 S0 重复 ID。IR 方案下由 `IR(id)=ABSENT` + 局部 GR 空槽 opening 继承，但需完整 ID 绑定 |
| RR 是否可能有孤立撤销记录 | **可能** | E-R1 正常 Revoke 会先打开目标 GR 叶，故转换不产生孤立 RR；但 E-R2 S0 只查 RR 内部唯一性，不查 `grant_id∈G`。必须列为 S0 前置检查或可信前提 |
| RR 是否可能对同一 ID 多条记录 | S0 需检查；转换中由 `IR(target)=ACTIVE` 拒绝 | E-R2 `check_initial_rr_unique` 检查重复 `grant_id`；E-R1 RR 扫描 `revoke id global unique in RR` 拒绝新记录重复 |
| IR 是否可能有多个相同完整 ID | 不应有；需槽位规则保证 | `slot=low_t(id)` 唯一映射 + `leaf.full_id==id`；重复 ID 会落同槽，第二次写同一叶而非新增，需状态前置拒绝 |
| IR 槽位碰撞是否拒绝而非误判 ABSENT | 必须拒绝 | D3-04-R1 `get()` 在 `leaf.full_id≠id` 时返回 `ABSENT`，但 `apply_grant` 另有 `KeyCollision` 前置检查；若电路只实现 `get()` 语义而不实现碰撞拒绝，I06/I12 成立 |
| GR `valid` 位是否与撤销状态独立 | 是 | `GrantFieldsB::leaf(valid)` 支持 0，但 E-R1/E-R2 已占叶全为 `leaf(true)`；Revoke 不改 GR。IR 的 `ACTIVE/REVOKED` 对应 `(x∈G, x∉R)/(x∈G, x∈R)`，与 `valid` 位无直接电路关系 |
| S0 一致性由谁建立、验证、锚定 | 外部可信锚定 + 一次性 host 前置检查 | E-R2 方案 A + D3-04-R1 `seed()`；当前缺少跨结构一致性与孤立 RR 检查，本轮将其列为必须显式补上的 S0 边界，而不是声称电路已验证 |

## 4. 三个必须区分的概念

1. **完整 ID 集合一致性**：`G/R` 中是否同一完整 `F` 元素、是否重复、是否孤立 RR。这是集合论性质。
2. **每个 ID 的状态一致性**：`I(x)` 是否等于由 `(x∈G, x∈R)` 唯一决定的三态。这是映射性质。
3. **三棵树的 Merkle 根真实性**：给定根是否真由这些叶与路径算出，且 opening 是否绑定到正确完整 ID 和槽位。这是认证结构性质。

**三者互不推出**：

- 根真实但叶 ID 被替换：集合一致性可假（N07）。
- 集合一致但 IR 叶写错状态：状态一致性可假（I03/I09）。
- IR 状态“看起来对”但 S0 有孤立 RR：集合一致性已假，后续转换无法修复（I02）。

因此“IR opening 重算根正确”不能替代 (C0)–(C3)。

## 5. 本阶段结论

三态一致性可以被严格定义，但必须：

- 补上 (C0)，否则三分支不完备；
- 明确 S0 已满足 (C0)–(C3) 且无 GR/RR 重复 ID、无 IR 槽位碰撞；
- 明确 IR 完整 ID 绑定与 `slot=low_t(id)` 是认证要求，不是仅 host 查询约定；
- 明确 `key_field` 单射、S0 锚定为外部信任。

在这些前提下，不变量本身是自洽的。下一阶段证明 Grant/Revoke 是否保持它。
