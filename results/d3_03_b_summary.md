# EXP-D3-03-B — 单 Grant 创建与 Parent Binding 结果报告

**基线**：`cae2ec722c1beac7b7b5e366dffbe6338466f6ba`（D3-03-A，用户已验收冻结）
**分支**：`exp-d3-03-b`
**技术栈**：Halo2 0.4.0 / Pallas base field / Poseidon P128Pow5T3
**范围**：仅 1 个有效 Parent Grant + 1 个新 Child Grant；不实现 Revoke、Cascade、多事件批次、递归 SNARK。

---

## 1. 基线与接口审计（B1）

- 开始前工作区干净；未改 A 的 `circuit.rs`/`types.rs`/`constants.rs`、A 固定向量、R2 编码定义以及 D2-A / D2-B / D3-01 冻结实现。
- 审计报告：`results/d3_03_b_interface_audit.md`。
- 核心结论：D2-A、D3-01、D3-03-A 的 Grant 叶子编码、节点哈希、域标签生成、字段→域映射、scope 宽度、resource 语义均不兼容。B 只对齐 D3-01 语义口径，不复用 D2-A 编码。
- 因 R2-02 规定类别 II SHA-256 映射不进电路，B 把 id/issuer/subject/parent_key 当作已映射域元素 witness，电路不重算 SHA-256，该前提属 `EXTERNAL_TRUST`。
- D3-01 的 resource 前缀作用于 32B Hash32，映射到域后不可反推；B 新增 `resource_prefix_f` 打包表示。因此 **B 的 GR 根与 D3-01 固定向量根不兼容**，不做此声称。
- 版本化补充 B-INT-01~05 仅写入本阶段文档，不修改任何冻结规范。

## 2. Grant 叶子与节点哈希定义

```
GRANT_LEAF_B = Poseidon(D_GRANT_B, id_f, issuer_f, subject_f,
                        resource_prefix_f, scope_f, parent_key_f, epoch_f, valid_f)
node_hash    = Poseidon(D_NODE_B, left, right)

D_GRANT_B = domain_field("D3-GRANT-v1")
D_NODE_B  = domain_field("D3-NODE-v1")
D_EVENT_B = domain_field("D3-EVENT-v1")
```

- 三个标签均为 `Expression::Constant` fixed 常量，非 witness。
- `resource_prefix_f = Σ_{i=0}^{7} byte_i·256^(7−i)`，只承诺并比较 D3-01 模型中的前 8 字节前缀；第 9 字节及以后不在本实验语义内。
- `id_f/issuer_f/subject_f/parent_key_f` 是外部映射域元素 witness；`scope_f/epoch_f/valid_f` 在电路内作为 u64/bool 处理并进入叶子。

## 3. Parent Opening 的电路实现

- 深度 `d=4`（16 槽），每层 witness：`dir`, `sibling`, `left`, `right`, `cur`。
- `q_path_bool` 强制 `dir·(dir−1)=0`。
- `q_path_select` 强制：
  - `left  = (1−dir)·cur + dir·sibling`
  - `right = dir·cur + (1−dir)·sibling`
- `left/right` 进入 `Poseidon(D_NODE_B, left, right)`，逐层重算，根 copy 到 A 阶段 `gr_prev` 域元素 cell。
- `q_grant_valid` 在 Parent 叶子第 9 词强制 `valid_f=1`（沿用 D2-A-R1 教训）。
- Parent 字段不是只做 membership：`id`、`subject`、`resource_prefix`、`scope`、`epoch` 均参与第 5 节的后续约束。
- B02（sibling 篡改）、B03（方向位篡改）、B04（Parent 字段篡改）均在 MockProver 层被拒。

## 4. Child Grant 的电路关系

在电路内同时成立：

| 关系 | 机制 |
| --- | --- |
| `child.parent_key = parent.id` | Equality copy |
| `child.issuer = parent.subject` | Equality copy |
| `child.valid = 1` | `q_grant_valid` |
| `child.scope ⊆ parent.scope` | 64-bit bool 分解 + `c_bit·(1−p_bit)=0` |
| `child.resource_prefix = parent.resource_prefix` | 前 8 字节打包 + 逐位相等 |
| `child.epoch ≥ parent.epoch` | 64-bit 分解 + 前缀相等/小于累加器 + 末位 `less==0` |
| `child.epoch = next_epoch` | Equality copy |
| `next_epoch ≥ prev_epoch` | 64-bit 分解 + 同一比较 gadget |
| 新 ID 不冲突 | 子槽位在旧树中的叶子固定为 ZERO |

## 5. Scope 与 Resource 约束定义

- Scope 采用 u64 bitmask，对齐 D3-01 `scope_is_subset`：`child & !parent == 0`。电路逐位拆成 64 个 bool，累加器 copy 回叶子 `scope_f`，防止分解值与承诺值脱钩。
- Resource 不采用普通整数比较。采用 D3-01 的**前 8 字节前缀相等**语义：两侧各拆为 64 个 bit，逐位 `prefix-eq` 相等约束，累加器 copy 回叶子 `resource_prefix_f`。
- 边界测试：最大合法子集（child=parent）通过；最小非法超集拒绝；前缀恰好相等通过；第 8 字节刚好超出拒绝。第 9 字节差异不在本模型检查范围内，文档已声明。

## 6. 新旧 Grant Root 关系

```
GR_prev = MerkleOpen(parent_leaf,  parent_path)        // Parent opening 重算
        = MerkleOpen(leaf_old=0,    child_path)        // 子槽位此前为空
GR_next = MerkleOpen(child_leaf,    child_open_new)    // 同槽位插入 child

C_prev  = Poseidon(D3-STATE-P-v2, GR_prev, RR_prev, prev_epoch, policy_id)
C_next  = Poseidon(D3-STATE-P-v2, GR_next, RR_next, next_epoch, policy_id)
```

- `child_open` 与 `child_open_new` 是两个独立 witness 对象；电路逐层 Equality copy 二者的 `(dir, sibling)`，保证是**同一槽位**、只换叶子。
- Parent root、child-old root 均 copy 到 `gr_prev`；child-new root copy 到 `gr_next`。`C_prev/C_next` 继续由 A 的 Poseidon gadget 在电路内重算并 copy 到 instance 0/2。
- B09 通过“旧叶子必须为 0”拒绝重复/占用槽位；B10 通过更换新路径或新根被拒。

## 7. Batch Commitment 绑定

- `c_child = Poseidon(D_EVENT_B, TYPE_GRANT, child 字段...)` 在电路内从 Child 字段重算。
- `c_child` Equality copy 到 `event_commitments[0]`；`event_count=1`，其余两个槽位固定 padding。
- A 的 batch gadget 继续重算 `D_E = Poseidon(D_BATCH, 1, c_child, pad, pad)` 并 copy 到 instance 6。
- B12 证明：改 child 字段但不改 batch 承诺会被拒；边界测试确认 padding 稳定。

## 8. 测试矩阵 B01–B14 与边界测试

`tests/d3_03_b_mock.rs`：**17 passed / 0 failed**

- B01 合法 Child Grant 接受
- B02 Parent sibling 篡改拒绝
- B03 Parent 方向位篡改拒绝
- B04 Parent 字段篡改拒绝
- B05 `issuer_child ≠ subject_parent` 拒绝
- B06 scope 越权拒绝
- B07 resource 前缀超出拒绝
- B08 child epoch 早于 parent 拒绝
- B09 旧槽位占用/重复 ID 拒绝
- B10 错误新根拒绝
- B11 公开 `C_prev` 与旧根不一致拒绝
- B12 child 字段与 batch commitment 不一致拒绝
- B13/B14 在真实 proof 测试中，不在此文件
- 5 个边界测试：最大合法 scope、最小非法 scope、前缀恰好相等、前缀刚好超出、padding 不变

`tests/d3_03_b_proof.rs`：**2 passed / 0 failed**

- B13 错误 public instance → 真实 verifier 拒绝
- B14 合法 witness → 真实 proof/verifier roundtrip 接受

完整 release 套件：**94 passed / 0 failed**（20 lib + 16 A mock + 2 A proof + 1 A smoke + 17 B mock + 2 B proof + 1 fixed vector + 7 grant transition + 4 history order + 8 reference model + 6 revoke transition + 10 root consistency）。

MockProver 拒绝与真实 Verifier 拒绝分层记录，未混用。

## 9. 真实 proof / verifier 与性能

Fresh same-run measurement（详见 `results/d3_03_b_perf.txt`）：

```
A17 (frozen A circuit, re-run) K=12 proof_bytes=3904 keygen_ms=800  prove_ms=1424 verify_ms=42
B14 (B circuit)                K=12 proof_bytes=5696 keygen_ms=1368 prove_ms=1837 verify_ms=42
```

D3-03-A 冻结记录保留不改：`proof=3904B, keygen=1490ms, prove=2737ms, verify=76ms`。跨运行绝对时间受机器负载影响，增量比较使用同轮 A17/B14。

计时口径：`keygen_vk + keygen_pk` 计入 `keygen_ms`；`verify_ms` 不计 keygen，与 A 一致。

## 10. 约束规模 / 电路行数变化

- K 仍为 12。K=12 是工程决策，不是原始设计参数；A 初始 K=13 因 keygen 超过 20 分钟降到 12。
- 未逐门统计约束数，也未插桩实际使用行数；不据源码行数外推约束数。
- 可审计的结构指标：selector family 由 A 的 9 个增至 B 的 20 个；核心源码行数 A=990 行、B=1475 行。这只是代码结构变化，不代表约束数。
- 可测指标是 proof size 从 3904B 增至 5696B，以及同轮 prove 时间上升。

## 11. 与 A 阶段的兼容性

- A 的公开接口完全不变：8 个 instance 顺序仍为
  `C_prev, prev_epoch, C_next, next_epoch, policy_id, transition_version, D_E, event_count`；11 字段 public statement 与 3 个 Hash32 网关锚沿用 A。
- B 是独立新模块 `b_constants.rs`/`b_types.rs`/`b_circuit.rs`，`mod.rs` 仅注册与 re-export；A 源码零改动。
- `GR_prev/GR_next` 复用 A 的规范域编码 gadget 与 `C_prev/C_next` Poseidon gadget；B 只把 Merkle 重算根 Equality copy 到对应 cell。
- 与 D3-01 固定向量根不兼容（B-INT-01 的版本化变更），未声称兼容；与 D2-A 在电路编码层不兼容是已知设计事实。

## 12. 尚未解决的问题

- 仍不证明 ALLOW/DENY：缺请求摘要、D2-A `π_path` 与非存在性证明。
- 类别 II SHA-256 字段映射、`child_slot` 规范布局、Bridge/VK 信任仍属外部信任。
- 不证明完整授权历史完整性；本阶段只证明给定 Parent 叶子在给定树中的 opening 与单步派生关系。
- 不实现 Revoke/Cascade/多事件/递归；epoch 新鲜度仍属外部机制。
- 无逐门约束数与精确使用行数；无第三方审计。
- D3↔D2-A 域标签未对齐；跨 vk 重放、id 集合完整性、执行时新鲜性等 R2 遗留问题未解决。

## 13. 是否具备进入 C 阶段的条件

**结论：具备进入 C（单 Revoke / 撤销语义）设计-实现阶段的条件**，但仅在以下边界内：

1. 继续冻结 A/B 的接口、叶子编码、域标签和 instance 顺序；C 必须以新模块和版本化补充实现，不改 B 已通过测试。
2. C 必须先完成与 B1 同等级的冻结接口审计，明确 Revoke 导致的 GR/RR 根变化、DirectOnly/Cascade 策略范围，以及旧 Grant 失效如何在电路内约束。
3. C 不得被表述为完整授权决策证明；ALLOW 仍需与 D2-A 组合，DENY/非存在性仍未证明。

若 C 要跨系统复用 D2-A 编码或引入新公开输入，应先另起接口冻结阶段，不在 C 实现中顺带改动。
