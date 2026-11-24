# EXP-D3-04 — Final Summary: Authenticated ID-State Index Design

## 1. Git 与基线

- 仓库：`kaikai-cao/authz-history-semantic-binding-exp`
- 基线：`2bd9624a56849ee75b1a4b2dc965029582b2c660`（`exp-d3-03-e-r3`）
- 工作分支：`exp-d3-04`
- Phase 0 核验：HEAD=基线、工作区 clean、远端 R3 一致
- 冻结边界：E-R1/E-R2/R3 电路、A/B/C/D/E、8 public instances、事件数上限 2 均未改；本轮**未写任何 Halo2 电路**

## 2. 本轮定位

承接 E-R3 结论（第 2 类：理论可行但成本收益不明确），本轮**不写新电路**，先把候选 C 真正设计清楚，避免"host 层思路成立、接入电路才发现结构不成立"。核心问题：能否用一个经过密码学认证的 ID 状态索引替代 E-R1 全树扫描（344/505 permutations），同时保持授权语义。

## 3. Phase 0：修正 R3 三处口径（不改电路，仅文档）

1. **候选 C 性质**：R3 的"4 步 vs 16 槽"明确为 `BTreeSet` 排序集合二分搜索比较次数，非密码学索引树 opening 成本；四份 R3 文档已更正。
2. **public instance 口径**：R3 "必须新增 public instance" 过强，改为"可新增实例 **或** 把索引根并入 `C_prev/C_next`"。
3. **统计来源**：R3 元数据表中 gate families=28 / degree=3 标注为源码静态分析，其余五项为运行时探针 `CircuitMeta` 输出。

## 4. Phase 1：统一 ID 状态索引语义

定义 `I : F → {ABSENT, ACTIVE, REVOKED}`（完整 F 字段 ID 键）：

| 操作 | 前置 | 后置 | 拒绝（对齐参考模型） |
| --- | --- | --- | --- |
| Grant | new=ABSENT 且 parent=ACTIVE | new=ACTIVE | DuplicateGrant / ParentNotFound / ParentNotValid |
| Revoke | target=ACTIVE | target=REVOKED | GrantNotFound / AlreadyRevoked |

- 重复 Grant/Revoke 归约为状态转换前置条件，无需独立全树重复扫描；REVOKED 不能再 Grant（与参考模型保留 GR 记录一致）。
- **一致性分层**（核心难点）：转换一致性由同一 event flag 门控索引与 GR/RR 双更新（内建，不需逐 ID 审计）；S0 初始一致性沿用 E-R2 方案 A 可信锚定。逐 ID 事后审计会退回全扫描，明确排除。

## 5. Phase 2：可认证结构比较

| 候选 | 完整 ID | non-membership | 插入更新 | 最坏 | 结论 |
| --- | --- | --- | --- | --- | --- |
| S1 Sparse Merkle | 深度~254 不实用，需截断 | O(t) opening | O(t) 单叶 | 桶大小/t | 截断键碰撞未解 |
| S2 Ordered Index | 天然有序 | O(log n)+相邻性 | 最坏 O(n) 移动 | n | 相邻性证明复杂 |

**关键**：完整 254-bit ID 直接做 SMT 路径不可行（深度~254，远超 E-R1 的 16 叶+15 节点）；截断键引入碰撞，须显式处理。"O(log n)" 是 opening 深度，不是总成本。

## 6. Phase 3：状态承诺接口

- **接口 A**：新增 2 个 public 值承载 `IR_prev/IR_next`（8→10），破坏 8 值冻结字面约束。
- **接口 B**（推荐研究）：`IR` 并入 `C_prev/C_next` 输入（5→6 words），**8 个 public 值数量不变**，需新域分离版本 `D3-STATE-v2` + verifier/锚定同步。关键：rate=2 下 5 words 与 6 words 都是 3 permutations，**承诺哈希成本不增加**。
- 两接口都只解决"IR 如何被 verifier 看到"，不解决"IR 是否可信"；一致性约束与初始锚定仍必需。

## 7. Phase 4：真正的密码学 host 实验（非 BTreeSet）

`tests/d3_04_index_state.rs` 实现 Poseidon Sparse Merkle ID 索引（root/opening/verify_path/set/get，三态编码，截断键碰撞显式拒绝），**9/9 通过**：

| 场景 | 结果 |
| --- | --- |
| 空索引 root 确定性 | ✓ |
| 非空初始索引 + opening 重算 root | ✓ path_len=4 |
| Grant ABSENT→ACTIVE、重复检测 | ✓ |
| Parent 撤销 / 有效区分 | ✓ |
| Revoke ACTIVE→REVOKED、重复 Revoke 检测 | ✓ |
| 两事件顺序更新（root 逐次变化、event1 见 event0 状态） | ✓ |
| 不存在 ID 空叶 non-membership opening | ✓ |
| ID 键碰撞显式拒绝 | ✓ ids=(1,17) slot=1 |
| 索引 root 与状态不一致可检测 | ✓ |

与 E-R3 `BTreeSet` 的本质区别：本实验有真实 Poseidon Merkle 承诺与 opening 验证关系，验证了密码学结构与更新关系；但**仍是 host 模型，未接 Halo2、未测 proving cost**。

## 8. 验收检查

- `cargo fmt --check`：通过
- `cargo test --release`：**253 passed / 0 failed / 3 ignored**（E-R3 为 244；D3-04 新增 9 个 host 结构测试）
- `git diff --check`：通过
- 修改范围：4 份 R3 文档口径修正 + 4 份 D3-04 新文档 + 1 个 D3-04 测试文件；无源码电路改动

## 9. 最终决策（三选一）

**结论落入第 1 类与第 2 类之间，明确记录为：找到可认证、可更新的索引结构（Sparse Merkle 三态索引在 host 层验证了 root/opening/non-membership/update 全部关系），但电路证明成本与索引-GR/RR 一致性约束尚未设计与测量，成本收益不明确。**

- 未选第 3 类（索引树不值得替换）：三态索引在逻辑与 host 密码学结构层都成立，且承诺哈希（接口 B）不增加 permutation，值得继续。
- 未直接选第 1 类（进入 Halo2 原型）：一致性同步约束、S0 锚定升级、截断键碰撞电路处理均未设计；此时写电路会重复 E-R3 警告的"结构未清就接电路"风险。

**下一步建议**：在 E-R1/E-R2/R3 继续冻结的前提下，先设计"索引三态更新与 GR/RR 状态根同步"的电路约束关系，以及接口 B 的域分离版本方案；待一致性约束清晰后再进入最小 Halo2 gadget 原型。本轮不写任何新电路的决定得到执行。
