# EXP-D3-01 协议与状态机规范

## 1. 事件定义

`H = (e1, ..., en)`，每个事件：

- `GrantEvent = (grant_id, issuer, subject, resource, scope:u64, parent_grant_id:Option, epoch:u64)`
- `RevokeEvent = (grant_id, revoker, epoch:u64)`

事件编码（SHA-256 摘要与批次摘要的输入）：域标签 `D3-EVENT-v1` 以 8 字节大端长度前缀写入，
随后 1 字节类型标签（0x01 grant / 0x02 revoke），再按字段顺序写入；每个 Hash32 为 32 原始字节，
整数为 8 字节大端长度前缀；Option 用 1 字节标签 + 可选 32 字节。长度前缀统一 8 字节大端
（D1-E 约定），避免历史版本里 4 字节前缀的不一致问题。

批次摘要 `D_E = SHA256("D3-BATCH-v1" ‖ u64(n) ‖ digest(e1) ‖ ... ‖ digest(en))`。

## 2. 状态

`S_i = (GR_i, RR_i)`，附加辅助数据（grants 映射、revokes 映射、policy、last_epoch、count）
仅用于参考实现与交叉验证，不进入证明的公开输入。

- **GR**：稀疏 Poseidon Merkle 树，叶子 = 每个 grant 记录的承诺
  `Poseidon(D_GRANT, id, issuer, subject, resource, scope, parent, epoch, valid)`（9 词）。
- **RR**：稀疏 Poseidon Merkle 树，叶子 = 每个撤销记录的承诺
  `Poseidon(D_REVOKE, id, revoker, epoch)`（4 词）。
- 内部节点 `Poseidon(D_NODE, left, right)`。
- Poseidon 参数 P128Pow5T3，Pallas base field，与 D2-A 电路同族；域标签前缀为 `D3-`
  （**刻意区别于 D2-A 的 `D2A-label-v1`，见未解决问题**）。
- 叶子槽位由 id 的 field 编码高位决定，线性探测解决冲突，保证不同 id 不共享叶子。

## 3. 转换规则 T(S, e)

Grant 检查（顺序即错误码优先级）：

1. `epoch >= last_epoch`，否则 `EPOCH_REGRESSION`
2. `grant_id` 不存在，否则 `DUPLICATE_GRANT`
3. 若有 parent：存在 → 有效 → `issuer == parent.subject` → `epoch >= parent.epoch`
   → `scope_child & ~scope_parent == 0` → resource 前 8 字节前缀匹配

Revoke 检查：

1. `epoch >= last_epoch`
2. 目标存在、未撤销、`revoker == issuer`
3. `DirectOnly`：仅目标置 invalid + 加 RR 叶子
   `Cascade`：目标 + 全部传递后代置 invalid + 各加 RR 叶子

`S_n = T*(S_0, H)` 为完整重放；`S_i = T(S_{i-1}, e_i)` 为增量更新。

## 4. 三条路径独立性

A（`history.rs`）与 B（`state.rs`）共享 `policy.rs` 的规则谓词（规范本身），
但状态更新实现独立（A 用快照映射，B 用树支撑的引擎）。C（`reference_model.rs`）
完全不调用 A/B 的转换函数与规则 helper，用扁平表 + 线性扫描本地重写全部检查。
因此 A/B/C 一致是交叉证据，不是单一函数复用的重言式。

交叉验证量：GR/RR 根（A vs B）、`state.summary()`（A/B vs C）、valid/revoked 集合（A vs C）。

## 5. 状态转换证明接口（未来，本轮不实现）

```
StateTransitionStatement = (
  prevGR, prevRR, nextGR, nextRR,
  prevEpoch, nextEpoch, D_E, event_count, D_P
)
```

`π = Prove(S_old, E, S_new)`；`Verify(π, S_old, S_new, D_E, D_P) = 1`。

关键记录：**事件摘要 D_E ≠ 事件语义证明**。把 D_E 放进 public input 只能绑定字节，
不能证明事件格式、授权关系、撤销状态或根更新正确。未来 Halo2 电路必须真正约束这些语义。
`verify_transition_statement`（本仓）是 O(batch) 链下重执行，正是电路要消除的代价来源。

## 6. 未解决问题

1. D3 的 Poseidon 域标签与 D2-A 不同，GR/RR 根不能直接喂给现有 D2-A 电路；
   是否统一、如何统一是下一步研究问题。
2. 谁认证"完整事件历史"（防跳过/截断）：需要外部锚点（类似 D1-E checkpoint），本轮未接入。
3. 批量事件的增量证明与递归 SNARK 尚未设计。
