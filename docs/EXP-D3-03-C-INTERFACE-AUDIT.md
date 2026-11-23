# EXP-D3-03-C — Phase 0 冻结接口审计

**基线**：`ecc4d06b105b047299e785e7b8e268a70a4e2cb4`（D3-03-B，已提交推送，待用户验收后作为 C 基线）
**分支**：`exp-d3-03-c`
**审计对象**：A TransitionCircuit、B Grant Circuit、D3-01 Revoke/RR、Batch/State/Field 编码实现体、测试辅助模块
**性质**：只读源码核对。所有“不存在/未实现”结论均来自全仓 `src/`、`tests/`、`docs/`、`results/` 检索，不用推测替代源码证据。

---

## 0. Phase 0 命令与结论

执行结果与要求一致：

```text
git status --short          # 空
git branch --show-current   # exp-d3-03-b → 已切到 exp-d3-03-c
git rev-parse HEAD          # ecc4d06b105b047299e785e7b8e268a70a4e2cb4
git rev-parse origin/main   # 09612dbb26422d14cc5628cb39f7ce444be159b5
git diff --check            # 干净
```

### 结论先行

1. **B 电路层没有 RR 树实现**：`TransitionWitnessB` 虽有 `rr_prev_be/rr_next_be`，但 `build_scenario` 直接写 `let rr_f = F::ZERO`，并分别编码到两个 rr root witness（`src/transition/b_types.rs:214,221,223`）；B 文档明说“RR 根本阶段不变” (`docs/d3_03_b_interface_audit.md:85`, `docs/d3_03_b_circuit_notes.md:11,82`)。
2. **D3-01 参考模型确实实现了 RR 稀疏 Merkle 树**：`revoke_leaf` 为 4 词 Poseidon (`src/revoke_tree.rs:17-24`)，`revoke_root_from_records` 用 `SparseMerkleTree` 构造 RR (`src/revoke_tree.rs:28-37`)，增量引擎在撤销时 upsert RR (`src/state.rs:199-245`)。这部分不是电路，但给出编码和空叶子语义的源码依据。
3. **空叶子确定为 `F::ZERO`**：`SparseMerkleTree` 初始化 `slots: vec![F::ZERO; capacity]` 并注释 “empty slots hold F::ZERO” (`src/grant_tree.rs:172,193`)，删除写零 (`src/grant_tree.rs:276`)；B 的空槽证明也用 leaf=0 (`src/transition/b_circuit.rs:929-938`)。
4. **RR 电路路径与 Revoke 事件编码在 B 中均不存在**：没有 `D_REVOKE`、`TYPE_REVOKE`、`RevokeFieldsB`、`revoke_leaf_b`、`RevokeOpening` 或 RR opening witness；B 只有 GR 的 `OpeningB` (`src/transition/b_types.rs:71-76,119-149`) 和 grant event commitment (`src/transition/b_types.rs:55-68`)。
5. **不存在必须停工的阻断**：D3-01 RR 与 B 电路编码不同，但可按 B-INT-01 先例做版本化 C 补充（本文 §4），不改 A/B 冻结规范。RR 空叶子、节点哈希、槽位规则均可从源码确定；旧/新 RR 同路径可通过 B 已验证的 copy 模式实现。

---

## 1. 七个审计对象的源码证据

### 1.1 A TransitionCircuit

| 项目 | 结论 | 源码位置 |
| --- | --- | --- |
| 8 instance 顺序 | 已冻结且电路内绑定 | `src/transition/types.rs:35-39`（顺序定义）、`:41-50`（结构）、`:55-66`（`as_vec`）；`src/transition/circuit.rs:533-541`（`constrain_instance` 0..7） |
| 11 字段 public inputs / 3 Hash32 锚 | 已实现 | `src/transition/types.rs:17-33,69-82` |
| C_prev/C_next | Poseidon ConstantLength<5>，电路内重算并 copy 到 instance | `src/transition/circuit.rs:179-191`（hash gadget）、`:457-481`（重算）、`:400-416`（4 根 cell）、`:533-537`（instance copy） |
| 域标签与 policy | `D_STATE=domain_field("D3-STATE-P-v2")`，`policy_id()`，`transition_version=1` | `src/transition/constants.rs:23-31,102-121` |
| epoch 单调 | **A 未实现** | A 的 9 个 gate 见 `src/transition/circuit.rs:268-355`，无 epoch 比较门；epoch 只是 advice cell，进入 Poseidon 和 instance (`src/transition/circuit.rs:418-455,535,537`) |
| B 补充 | B 实现 `next_epoch ≥ prev_epoch` | `src/transition/b_circuit.rs:630-658`（门）、`:883-916`（pair + copy） |

**C 的结论**：状态承诺公式、8 instance、规范域编码、batch gadget 可直接复用；epoch **严格 +1** 和 event epoch 绑定必须新增 C gate。

### 1.2 B Grant Circuit

| 项目 | 结论 | 源码位置 |
| --- | --- | --- |
| Grant leaf | B-INT-01 变体，9 词 Poseidon | `src/transition/b_types.rs:40-53`；电路内 9 词组装 `src/transition/b_circuit.rs:294-328`，叶子哈希 `:832-843` |
| 域标签 | `D_GRANT/D_NODE/D_EVENT` fixed 常量 | `src/transition/b_constants.rs:12-23`；电路 fixed cell `src/transition/b_circuit.rs:739-744` |
| Grant 路径 | depth=4，16 槽 | `src/transition/b_constants.rs:25-27`；`src/transition/b_types.rs:119-149` |
| 方向语义 | `dir=0` 当前节点为左，`dir=1` 为右 | `src/transition/b_types.rs:71-76,119-149`；门 `src/transition/b_circuit.rs:563-584` |
| 空叶子 | `F::ZERO` | `src/transition/b_types.rs:95,106` |
| GR 更新 | 同 `(dir,sibling)` 改单叶；root copy 到 A 根 cell | `src/transition/b_circuit.rs:918-963`；子槽旧叶=0 `:929-938` |
| batch 绑定 | `c_child` 电路内重算并 copy 到 `event_commitments[0]` | `src/transition/b_types.rs:55-68`；`src/transition/b_circuit.rs:965-981,1023-1029` |
| B 的 RR | **恒为 ZERO，未实现树** | `src/transition/b_types.rs:214,221,223` |

**C 的结论**：Grant leaf/GR opening/GR 更新可直接复用语义；RR 更新是新增。DirectOnly 要求 `GR_next = GR_prev`，但必须新增**电路内 Equality copy**，不能只在 host 判断。

### 1.3 D3-01 Revoke / RR

| 项目 | 结论 | 源码位置 |
| --- | --- | --- |
| Revoke 事件字段 | `grant_id, revoker, epoch` | `src/event.rs:24-29` |
| 事件字节编码 | `D3-EVENT-v1` + tag `0x02` + 3 字段 | `src/event.rs:53-79` |
| 撤销规则 | GrantNotFound / AlreadyRevoked / 仅 issuer 可撤销 / epoch 回归 | `src/policy.rs:151-170` |
| DirectOnly / Cascade | 参考模型已实现，Cascade 仅展开子孙 | `src/state.rs:75-87,115-138,199-245`；`src/reference_model.rs:155-187`；`src/history.rs:80-102` |
| Revoke leaf | `Poseidon::<4>(D3-REVOKE-v1, key_field(grant_id), key_field(revoker), epoch)` | `src/revoke_tree.rs:17-24`；`src/encoding.rs:20,104-110` |
| RR 树 | 参考模型真实实现；电路未实现 | `src/revoke_tree.rs:28-37`；`src/grant_tree.rs:169-342` |
| 槽位规则 | canonical assignment：取 `field_from_bytes("D3-SLOT-v1", id32)` 低位，冲突线性探测 | `src/grant_tree.rs:86-134`；`src/encoding.rs:20` |
| 深度 | 参考模型为参数（测试常用 10，固定向量 12）；B 电路固定 4 | `tests/common/mod.rs:8`；`src/bin/gen_vectors.rs:13`；`src/transition/b_constants.rs:25-27` |

### 1.4 Batch / State / Field 的“Chip”命名澄清

仓库中不存在名为 `BatchCommitmentChip`、`StateCommitmentChip`、`FieldEncodingChip` 的独立 struct。`docs/d3_03_a_circuit_notes.md:35,38` 明确说明当前实现是“同一 config 下的门 + assign 函数”，不是独立 chip struct。本报告按实际实现体审计：

| 职责别名 | 实际实现体 | 源码位置 |
| --- | --- | --- |
| BatchCommitmentChip | 3 槽 active/padding/count gate + `D_E` Poseidon 重算 | `src/transition/circuit.rs:323-355,483-531`；B 版 `src/transition/b_circuit.rs:530-562,983-1029`；padding `src/transition/constants.rs:33-38` |
| StateCommitmentChip | 4 个 32B 根 decode cell + `C_prev/C_next` Poseidon | `src/transition/circuit.rs:400-416,457-481`；host 镜像 `src/transition/types.rs:133-162` |
| FieldEncodingChip（类别 I） | `assign_root_encoding`：256 bool 分解 + `< p` 累加器 | `src/transition/circuit.rs:114-177`；门 `:269-306`；模数 `src/transition/constants.rs:40-44`；`decode_field_i` `:123-134` |
| FieldEncoding（类别 II） | `field_from_bytes` / `key_field` / `domain_field`，SHA-256→域，电路不重算 | `src/encoding.rs:92-110`；B 中属 EXTERNAL_TRUST `docs/d3_03_b_interface_audit.md:14,133` |

### 1.5 测试辅助模块

- B 有效树与 opening：`SparseTreeB::new` / `opening` / `recompute_root_b` (`src/transition/b_types.rs:94-164`)；`build_scenario` 从字段重算全部根、opening、commitment (`src/transition/b_types.rs:193-236`)。
- B 负向 witness 模式：固定 public instance，只改私有 witness；或用 `build_scenario` 重建单字段恶意但自洽的 witness (`tests/d3_03_b_mock.rs:3-10,64-71`)。
- D3-01 测试辅助：`tests/common/mod.rs:8-78` 构造 root/child/revoke/valid history；固定向量入口 `src/bin/gen_vectors.rs`。
- 真实证明范式：`tests/d3_03_b_proof.rs:20-45,47-70`，keygen/prove/verify 与 A 同口径。

---

## 2. 七个必答问题逐项回答

### Q1. B 当前是否已经实现 RR 树？

**否。** B 的电路没有 RR 树、RR leaf、RR opening 或 RR 更新；两个 RR root 在 witness 构造中恒为 `F::ZERO`，只是通过 A 的规范编码 gadget进入状态承诺。源码：`src/transition/b_types.rs:214,221,223`；`src/transition/b_circuit.rs:792-795`；文档 `docs/d3_03_b_interface_audit.md:85`。D3-01 参考模型有 RR 树，但不是电路实现。

### Q2. RR 的空叶子如何表示？

**单个域元素 `F::ZERO`。** 证据：`src/grant_tree.rs:172,193,276`；B 空槽证明 `src/transition/b_circuit.rs:929-938`。注意：空叶的内部节点不是 0，而是逐层 `Poseidon(D_NODE,0,0)`，所以空树根非零 (`src/grant_tree.rs:213-224`)。

### Q3. Revoke leaf 的字段与哈希域标签是什么？

D3-01 参考实现：

```
revoke_leaf = Poseidon::<4>([
    domain_field("D3-REVOKE-v1"),
    key_field(grant_id),      // field_from_bytes("D3-KEY-v1", id32)
    key_field(revoker),
    F::from_u128(epoch),
])
```

源码：`src/revoke_tree.rs:17-24`；`src/encoding.rs:20,104-110`。B 电路中没有对应常量或叶子函数。

### Q4. RR 的路径深度和方向编码是什么？

**参考模型**：RR 深度是参数，不是固定电路常量（测试常用 10，固定向量 12），且不物化 opening witness (`src/revoke_tree.rs:28-37`；`tests/common/mod.rs:8`；`src/bin/gen_vectors.rs:13`)。
**B 电路**：只有 GR opening，depth=4，`dir=0` 当前节点为左、`dir=1` 为右 (`src/transition/b_constants.rs:25-27`；`src/transition/b_types.rs:71-76,119-149`；门 `src/transition/b_circuit.rs:563-584`)。
**C 决策**：以版本化 C 接口把 RR 电路深度固定为 4、方向语义沿用 B-INT-03，见 §4 C-INT-02。

### Q5. 旧 RR 根、新 RR 根如何接入 A 的状态承诺？

当前接入机制：32B `rr_prev_be/rr_next_be` witness → A 规范域编码 gadget → `rprev/rnext` cell → `C_prev/C_next` 的第 3 个 Poseidon 输入 → instance[0]/[2]。证据：`src/transition/circuit.rs:400-416,457-481,533-537`；B 对应 `src/transition/b_circuit.rs:792-821,1032-1039`。
缺口：B 的 rr 值恒为 ZERO，没有 Merkle 重算约束。C 必须新增 RR opening 根与 `rprev/rnext` cell 的 Equality copy，仿照 B 对 GR 的 `copy_equal(parent_opening.root, gprev)` (`src/transition/b_circuit.rs:927,963`)。

### Q6. D3-01 的 Revoke 事件编码与当前电路是否一致？

**不一致；更准确地说，当前电路根本没有 Revoke 实现。** D3-01 有 `RevokeEvent` 3 字段、SHA-256 字节编码、4 词 Poseidon revoke leaf；B 没有 revoke 字段、常量、叶子或路径，rr root 写死 ZERO。即使新增 revoke leaf，也不能直接照搬 D3-01 的 `key_field`（类别 II SHA-256），须按 B-INT-01 先例做版本化 C 变体。

### Q7. 哪些组件可直接复用，哪些必须新增？

**可直接复用**：8 instance 顺序与 11 字段 statement；32B 规范域编码 gadget；`C_prev/C_next` Poseidon 重算；域常量/policy/version/batch_pad；batch padding/count/`D_E` gadget；B 的 Grant leaf、scope/prefix/epoch gate、4 层 GR opening 和 GR 单叶更新模式；D3-01 的 off-circuit Revoke 规则/RR 编码/空叶子/槽位规则；真实 proof 测试范式。

**必须新增**：RR 电路树与 opening；`D_REVOKE_C`/`TYPE_REVOKE` 常量；`RevokeFieldsC` witness；revoke leaf 电路内重算；旧 RR 空叶 opening + 新 RR 同路径单叶更新；`GR_next == GR_prev` 电路内 Equality copy；`next_epoch = prev_epoch + 1` 严格 gate；event epoch 与 next_epoch 绑定；revoke event commitment 与 batch slot 绑定；相应正负向 witness 构造器。

---

## 3. 停止条件逐项判定

| 停止条件 | 判定 | 理由 |
| --- | --- | --- |
| D3-01 与 B 的 RR 编码无法兼容且无版本化方案 | **不触发** | D3-01 `key_field`（类别 II）与 B 的域元素 witness 口径不同，但 B-INT-01 已建立版本化变体先例；C-INT-01 按同一方式处理 |
| RR 空叶子/槽位/节点哈希无法确定 | **不触发** | 空叶=`F::ZERO` (`src/grant_tree.rs:172,193`)、canonical slot (`src/grant_tree.rs:86-134`)、节点哈希 (`src/transition/b_types.rs:89-92`) 均有源码证据 |
| 需要改变 A 的 public instance | **不触发** | C 保持 8 instance 顺序，新增字段全部为 private witness |
| 需要修改 B 的冻结 Grant 语义 | **不触发** | C 新模块只读复用 B 的 Grant leaf 与 opening 语义 |
| 无法保证旧/新路径同一 sibling/direction | **不触发** | B 已用逐层 copy `(dir,sibling)` 实现同槽更新 (`src/transition/b_circuit.rs:951-962`)，C 可复用 |

---

## 4. 版本化 C 接口补充（C-INT-01 ~ C-INT-08）

> 以下只作为 C 阶段新增接口约定，不修改 A/B/D3-01/D2-A 冻结文档或代码。若未来统一编码，应另起阶段并升 `transition_version`。

- **C-INT-01（Revoke leaf 字段→域）**：`grant_id_f`、`revoker_f` 以已映射域元素 witness 进入电路，电路不重算类别 II SHA-256；叶子为
  `L_REVOKE_C = Poseidon::<4>(D_REVOKE_C, grant_id_f, revoker_f, epoch_f)`，
  其中 `D_REVOKE_C = domain_field("D3-REVOKE-v1")` 为 fixed 常量。语义对齐 D3-01 4 词结构，但**不声称与 D3-01 RR 固定向量字节兼容**。
- **C-INT-02（RR 树）**：RR 电路深度 `d=4`，空叶 `F::ZERO`；节点哈希沿用 `Poseidon(D_NODE, left, right)`；方向语义沿用 B-INT-03（`dir=0` 左，`dir=1` 右）。与 D3-01 参数化深度不同，属 C 版本化选择。
- **C-INT-03（槽位）**：`revoke_slot` 是外部可信 witness，电路只验证给定槽位“旧叶=0、新叶=L_REVOKE_C、同路径根更新”，不证明 canonical layout 规范性（R2-03 外部信任）。
- **C-INT-04（RR 更新）**：`RR_prev = MerkleOpen(0, path)`，`RR_next = MerkleOpen(L_REVOKE_C, path)`；逐层 copy `(dir,sibling)`，绑定 `rprev/rnext` root cell。
- **C-INT-05（GR 不变）**：`GR_next` 与 `GR_prev` 使用同一组规范域编码 cell，并在电路内 Equality copy；不接受 prover 提供且碰巧相同的两个根。
- **C-INT-06（epoch）**：`next_epoch = prev_epoch + 1`（严格等式 gate），且 revoke event epoch copy 到 `next_epoch`。
- **C-INT-07（Batch）**：`c_revoke = Poseidon::<5>(D_EVENT, TYPE_REVOKE=2, grant_id_f, revoker_f, epoch_f)`；copy 到 `event_commitments[0]`；`event_count=1`，其余槽位 padding。与 B 的 `TYPE_GRANT=1` 分开，不静默拼接。
- **C-INT-08（Public interface）**：8 instance 顺序与 A/B 完全一致；C 新增字段均为 private witness。

---

## 5. 审计边界

本审计证明的是接口来源与缺口定位，不是形式化安全证明。以下内容仍是外部信任：类别 II SHA-256 字段映射、canonical slot 分配、Bridge/checkpoint、新鲜性、外部授权事件完整性。C 完成后只能说“给定 GR/RR 根及 Opening 满足一次 DirectOnly 撤销关系”，不能说“完整 DENY 已证明”或“所有授权均无效已证明”。
