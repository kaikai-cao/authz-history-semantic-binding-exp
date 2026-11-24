# EXP-D3-06-A Phase 1–3 — S0 输入模型、检查清单与 C_v2 接口规格

## 1. 输入模型

\[
S_0=(GR_0,RR_0,IR_0,epoch_0,policy_0).
\]

实验阶段 ID 直接使用 Pallas Base field 元素并排除零值：`ID ∈ F \ {0}`。**本轮不解决任意 256-bit 原始 ID 到 Field 的映射问题**；`key_field` 单射仍是外部信任前提。

公开 Rust 接口：

```rust
pub struct S0InputV2 {
    pub grants: Vec<(usize, GrantFieldsB)>,
    pub revokes: Vec<(usize, RevokeFieldsC)>,
    pub index: Vec<IrSlotInputV2>,   // 只登记占用槽
    pub epoch: u64,
    pub policy: F,
}

pub struct IrSlotInputV2 {
    pub slot: usize,
    pub full_id: F,
    pub state: F,                   // 1=ACTIVE, 2=REVOKED；0/其它值必须被拒绝
}
```

输入**没有缓存 root 字段**：验证器只能从上述 preimage 重算三棵树根与 `C_v2`。`S0ExpectedV2` 只承载被调用方传入的期望值，用于最后比较，不参与任何语义检查。

三种槽位规则严格分开：

- GR / RR：保留各自 witness slot；路径合法、根合法即可，**不要求等于 `low_t(id)`**；
- IR：`slot = low_t(full_id)`，异 ID 占同槽直接 `IrKeyCollision`，不做链式寻址或 bucket 扩展。

已占 GR 叶在本模型中隐式 `valid=1`（直接调用 `leaf(true)`），不存在 `valid=0` 的第二种规范。IR 的 ABSENT 只有一种规范：槽位未登记，叶哈希为 `poseidon([D_INDEX, 0, 0])`。

## 2. 检查清单与错误映射

| 检查 | 必须满足 | 错误变体 |
| --- | --- | --- |
| GR 完整 ID 唯一 | 无重复 `grant.id` | `DuplicateGrantId` |
| RR 完整 ID 唯一 | 无重复 `revoke.grant_id` | `DuplicateRevokeId` |
| 结构槽位合法 | 各槽 `< 16`，无重复占用槽 | `SlotOutOfRange` / `DuplicateSlot` |
| RR 子集关系 | `R ⊆ G`，无孤立撤销 | `OrphanRevoke` |
| IR 与 GR/RR 双向一致 | GR/RR → IR 与 IR → GR/RR 两个方向都查 | `IrMissingForGrant` / `IrStateMismatch` / `IrGhost` |
| IR 完整 ID 绑定 | 叶内存完整 `full_id`，`slot=low_t(full_id)` | `IrSlotMismatch` |
| IR 槽位碰撞 | 异 ID 占同槽 fail-closed | `IrKeyCollision` |
| 空叶规范性 | 占用叶不得写 state=0 | `IrNonCanonicalAbsent` |
| state 合法 | 占用叶 state ∈ {1,2} | `IrInvalidState` |
| 零 ID | GR/RR/IR 全入口拒绝 | `ZeroId(S0Structure)` |
| 根真实性 | 重算 GR/RR/IR 根并比对期望值 | `RootMismatch` |
| 承诺真实性 | 重算 `C_v2` 并比对期望值 | `CommitmentMismatch` |

**双向一致性不可只做一半**：

1. `GR/RR → IR`：每个 `x∈G` 必须有 IR 占用叶，期望状态由 `x∈R?` 唯一决定为 REVOKED(2) 或 ACTIVE(1)；
2. `IR → GR/RR`：每个 IR 占用叶的 `full_id` 必须存在 GR 记录，否则就是幽灵 ACTIVE/REVOKED。

只查方向 1 会放过幽灵 IR 记录；只查方向 2 会放过 GR 存在但 IR 缺失。两者都查才对应 `GLOBAL-INVARIANTS.md` 的 (C1')–(C3) + (C0)。

## 3. `C_v2` 计算与输出边界

固定实现：

```text
C_v2 = poseidon::<6>([d_state_v2(), gr_root, rr_root, ir_root,
                      F::from(epoch), policy])
d_state_v2() = domain_field("D3-STATE-v2")
```

`validate_s0_v2(input, expected)` 的成功输出 `S0ValidationV2` 只表示：

> 这组本地 preimage 内部满足跨结构不变量，且重算出的三个根与 `C_v2` 等于调用方给的期望值。

它**不表示**：

- 外部 checkpoint / 签名 / 远程状态已被认证；
- 已建立 freshness 或抗重放；
- Halo2 电路已经证明这些约束；
- `key_field` 任意 256-bit 映射安全；
- 大规模授权记录能力。

因此该验证器是 inductive base 的**本地工程接口**，不是可信锚定本身。调用方仍须自行决定 `expected` 的来源。

## 4. 进入 Halo2 原型前必须落实的三项义务

以下三项本轮不实现，但不得留给实现者自行猜测：

### 4.1 旧根与新根必须共用同一条 Merkle 更新路径

只打开输入根的某个叶、再用另一组任意 sibling 计算输出根，不能证明“只修改了该叶”。GR/RR 现有实现已有旧/新 opening 共享 sibling 与 direction 的模式；IR 必须同样满足：

- 更新前后 slot 相同；
- 每层 direction bits 相同；
- 每层 sibling 相同；
- 只有目标 leaf 由旧值变为新值；
- 更新后根绑定到输出状态承诺（`C_next` / `C_v2`）。

这是 D3-05-R1 归纳证明中“其他 ID 状态不变”的电路依据；缺此则局部 opening 不足以替代全树扫描。

### 4.2 `pre_ok` 不得成为 prover 绕过开关

`pre_ok=0` 时三棵树保持原根可以用于失败原子性，但**不能**让无效事件产出一份被当作成功授权的 ALLOW proof。对 ALLOW 证明，活动事件必须满足全部前置条件；无效事件必须使 ALLOW 电路不可满足，或走独立且明确标记为“拒绝”的结果语义。禁止“输出 no-op 根 + 验证方误认为授权成功”的中间态。

### 4.3 ID 映射与容量必须如实限定

当前实验域为 `F \ {0}`。若将来把任意 256-bit 原始 ID 映射到 Pallas Base Field，不能无条件假设全域单射；必须限制 ID 域或显式处理映射碰撞。IR 深度 4 只有 16 槽，碰撞采用 fail-closed 而非链式寻址；它适用于与 E-R1 同容量原型对照，不构成大规模授权记录能力声明。

### 4.4 成本口径补充

`EXP-D3-05-R1-COST-IMPACT.md` 的 50–106 次 IR 置换估算必须在原型阶段按 **GG / GR / RR** 三种两事件组合分别重算；不能把“一次 Grant + 一次 Revoke”直接当成所有两事件批次的最坏情况。本轮不修改该估算文件，只把重算义务登记在此。
