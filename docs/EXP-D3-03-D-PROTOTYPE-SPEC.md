# EXP-D3-03-D — Phase 5 Halo2 原型入口规格

**基线**：`be87f2ca8c3949ed0fdf70151d9fb1d0cbc267b2`
**分支**：`exp-d3-03-d-design`
**状态**：设计冻结；本阶段不实现该电路。

---

## 1. 选择构造

**推荐构造：Sequential Transition Circuit。**

理由见 `docs/EXP-D3-03-D-CONSTRUCTION-COMPARISON.md`：Sequential 直接表达有序事件、中间状态和原子失败；Batch Update 的路径共享收益在 depth=4、n≤3 下未验证，却需要额外证明更新完整性、冲突与顺序。

这不是性能结论。后续必须实测，不预先宣称 Sequential 更慢或 Batch 更省约束。

---

## 2. 固定原型范围

第一版原型建议：

- 最大 active 事件数：**2**；
- 支持组合：
  1. `Grant + Grant`
  2. `Grant + Revoke`
  3. `Revoke + Revoke`
- 单事件序列通过 padding 兼容，不作为主要目标；
- DirectOnly：Revoke 不改 GR 根；
- depth 固定 4；
- 不允许重复 Grant ID；
- 不允许重复撤销；
- 不实现 Cascade；
- 不实现递归；
- 不做完整 DENY / ALLOW 决策证明；
- 不证明 canonical slot 全局规范性；
- 不改变 A 的 8 个 public instance。

选择 2 而不是 3，是因为 2 已能验证核心状态依赖（Grant→Revoke、Parent→Child、重复拒绝），同时避免在第一版引入三槽排序和更复杂的 active 边界。

---

## 3. Public Input

保持 A 冻结的 8 个 instance 顺序：

| Index | Public instance |
| ---: | --- |
| 0 | `C_prev` |
| 1 | `prev_epoch` |
| 2 | `C_next` |
| 3 | `next_epoch` |
| 4 | `policy_id` |
| 5 | `transition_version` |
| 6 | `D_E` |
| 7 | `event_count` |

- `event_count` 可为 1 或 2；不能用 C 的 `event-count-one` 门；
- `D_E = Poseidon(D_BATCH, n, c_1, c_2, pad)`；
- 中间状态根保持私有 witness，不加入公开接口；
- 若要公开中间根，必须另起版本并重新分析兼容性。

---

## 4. 状态与事件接口草图

以下只是概念草图，字段需按仓库现有类型修订后才可编译。

```rust
enum AuthorizationEvent {
    Grant(GrantEvent),
    Revoke(RevokeEvent),
}

struct MixedTransitionInput {
    initial_state: StateCommitment,
    events: Vec<AuthorizationEvent>,
    expected_final_state: StateCommitment,
}

struct StateCommitment {
    gr_root: [u8; 32],
    rr_root: [u8; 32],
    epoch: u64,
    policy_id: Field,
}

struct GrantEvent {
    id: Field,
    issuer: Field,
    subject: Field,
    resource_prefix: [u8; 8],
    scope: u64,
    parent: Option<Field>,
    epoch: u64,
}

struct RevokeEvent {
    grant_id: Field,
    revoker: Field,
    epoch: u64,
}
```

电路概念接口：

```rust
struct MixedTransitionCircuit {
    // initial state root cells (4 roots after canonical decode)
    // two ordered event witnesses, each with type tag and active flag
    // Grant step witnesses: parent opening, old child opening, new child opening
    // Revoke step witnesses: grant opening, old RR opening, new RR opening
    // one intermediate state witness between step 1 and step 2
    // final state root cells
}
```

---

## 5. 必须新增的电路关系

### 5.1 事件分派

- `TYPE_GRANT=1`、`TYPE_REVOKE=2` 必须由 fixed/constant gate 约束；
- active 事件必须前缀连续：`[1,1]`、`[1,0]` 或 `[0,0]`；
- 非 active step 的事件字段不进入承诺，padding 槽为 `batch_pad`；
- `event_count = active_1 + active_2`。

### 5.2 Step 1

- 从 `S_0` 打开事件 1 所需树；
- Grant：复用 B 的 Parent 有效性、scope 子集、resource 前缀、epoch 约束；新增 Parent RR 无撤销记录检查；
- Revoke：复用 C 的 Grant opening、RR 空槽、Revoke leaf、GR 不变约束；
- 重算 `S_1` 四个根 cell。

### 5.3 Step 2

- `S_1.GR/RR/epoch` 根 cell 必须 copy 到 step 2 的 `GR_prev/RR_prev/prev_epoch` cell；
- 禁止把 host 计算的 `S_1` 作为无约束 witness；
- 事件 2 必须针对 `S_1` 重新生成 opening；
- 重算 `S_2` 四个根 cell。

### 5.4 最终绑定

- `C_prev = Poseidon(D_STATE, GR_0, RR_0, epoch_0, policy)`；
- `C_next = Poseidon(D_STATE, GR_2, RR_2, epoch_2, policy)`；
- `epoch_1 = epoch_2 = epoch_0 + 1`；
- `D_E = Poseidon(D_BATCH, n, c_1, c_2, pad)`；
- 8 个 instance copy 全部保持 A 顺序。

### 5.5 事件承诺

- Grant 事件承诺 9 词，Revoke 事件承诺 5 词；
- 两者归约为 field 后写入固定 batch slot；
- type、payload、顺序任一变化都必须改变 `D_E`（在哈希抗碰撞假设下）。

---

## 6. 原型测试矩阵

| 编号 | 测试 | 目标约束 / 拒绝边界 |
| --- | --- | --- |
| P01 | 合法 `Grant + Grant` | 两个 GR 单叶更新；`S_1→S_2` 根 copy |
| P02 | 合法 `Grant + Revoke` | Grant 输出 GR 被 Revoke opening 打开；RR 单叶更新 |
| P03 | 合法 `Revoke + Revoke` | 两个不同 ID 的 RR 更新；GR 始终不变 |
| P04 | 事件顺序交换攻击 | 事件承诺顺序绑定 + 第二步输入状态 copy |
| P05 | 中间状态根替换 | step2 `prev` 根与 step1 `next` 根 copy |
| P06 | 事件遗漏 | `event_count` / active gate / batch slot 绑定 |
| P07 | 事件重复 | 同一事件承诺重复写入不同 slot 的 active/order 约束 |
| P08 | 重复 Grant ID | 当前中间状态 ID 唯一性；若用 Merkle 非存在证明则其旧叶=0 |
| P09 | 非法 Parent 依赖 | Parent 不在当前 GR 或已撤销的 opening/validity 约束 |
| P10 | 非法撤销者 | `grant.issuer = revoke.revoker` copy |
| P11 | 错误最终 GR/RR | `C_next` 重算与 instance copy |
| P12 | 错误 Batch Commitment | `c_i` 电路内重算与 slot copy |
| P13 | 修改 public instance 复用 proof | 真实 verifier 拒绝，证明公开绑定有效 |
| P14 | `event_count` 非 1/2 | active count gate |
| P15 | active 非前缀 | `active-monotone` gate |
| P16 | Parent 同批次撤销后创建 Child | Parent 当前 RR 空记录检查 |
| P17 | Revoke 改 GR 根 | DirectOnly GR 根 copy |

负向用例必须记录主要拒绝来源，不能只写 `Reject`。MockProver 拒绝与真实 verifier 拒绝必须分层。

---

## 7. 原型验收边界

通过 P01–P17 只能说明：给定初始根与有序事件 witness，电路验证了最多 2 个事件的状态转换关系。它不能说明：

- 初始根来自真实完整历史；
- 事件来自真实外部请求；
- slot 规范分配正确；
- Bridge/checkpoint 可信或最新；
- 执行时没有并发覆盖；
- 已经证明 Cascade、多事件 3+、递归、ALLOW/DENY 或完整 DENY。

---

## 8. 进入原型的条件

本阶段已经具备进入 Halo2 原型阶段的设计条件：

- Phase 0 源码审计有源码依据；
- Phase 1 状态机语义已冻结；
- Phase 2 两种构造已比较；
- Phase 3 独立参考模型 42/42 测试通过；
- Phase 4 成本模型已建立；
- Phase 5 public instance、范围、接口与测试矩阵已冻结。

下一阶段若启动，应只实现本规格的 Sequential n≤2 原型，不自动扩展到 Cascade、递归或完整历史证明。
