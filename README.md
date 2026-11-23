# EXP-D3-01 — Authorization History → GR/RR Semantic Binding

研究型实验，独立仓库。研究问题：

> 如何让验证者确认 Grant Root (GR) / Revocation Root (RR) 确实来自经过认证、
> 顺序完整、满足授权规则的事件历史，而不是状态服务任意提供的两个 Merkle Root？

**本轮不做**：Halo2 电路、零知识证明、文献大调研、修改 D1-E/D2-A/D2-B、
修改 3-of-4 quorum、真实远程服务。本仓是参考实现 + 可证伪实验。

## 三条独立计算路径

| 路径 | 模块 | 方式 |
| --- | --- | --- |
| A 完整重放 | `history.rs::replay_full` | 从 S0 逐事件重放，末尾从记录全量建两棵树 |
| B 增量更新 | `state.rs::IncrementalEngine` | 每事件只 upsert 受影响叶子，O(depth) 节点更新 |
| C 独立参考模型 | `reference_model.rs` | 扁平事件表 + 线性扫描，不调用 A/B 的转换函数或规则 helper |

交叉验证：A/B 的 GR/RR 根逐字节相等；A/B/C 的 `state.summary()`（SHA-256 over 排序后的
valid/revoked 集合）相等。C 的规则判定本地重写，因此一致不是同函数复用的重言式。

**EXP-D3-01-R1（正确性修复，D3-01 随后冻结）**：
- Merkle 槽位改为规范性映射：id 集合规范排序 + 全键域分离哈希初始槽位 + 规范序线性探测，
  相同记录集合与插入顺序无关；初始槽位冲突按 id 序消解；满树返回 `TREE_CAPACITY_EXHAUSTED`
  类型化错误。B 仍为真增量（只更新受影响路径，不整体重建）。
- D3-11 现经真实验证器 `verify_transition_statement` 拒绝伪造 grant，错误码 `NEXT_ROOT_MISMATCH`。
- benchmark 首次测量为循环内第一轮且不再被额外重跑覆盖；5 条原始样本全部保留在 `raw_runs`。
- 修复只改变 Merkle 根；事件编码、批次摘要、状态摘要不变。修复前向量/性能数据分别保留在
  `tests/vectors/fixed_vectors_before_r1.json`、`results/performance_before_r1.json`。

## 状态机规则

- Grant：`grant_id` 全局唯一；根授权无 parent；子授权 parent 必须已存在且有效；
  `issuer == parent.subject`；`epoch >= parent.epoch`；`scope_child & ~scope_parent == 0`；
  resource 前 8 字节前缀匹配。
- Revoke：目标存在且未撤销；`revoker == grant.issuer`。
- 撤销策略：`DirectOnly` 只撤销目标；`Cascade` 连带传递后代。两者根不同，独立测试。
- 事件全局 epoch 单调不减。

## 攻击矩阵（D3-01..D3-12）

见 `tests/`。所有 REJECT 都断言具体错误码（`RuleError`/`RefError`/`StatementError`）。
D3-11 = 状态树与历史不一致；D3-12 = 状态服务跳过历史事件，验证器通过批次摘要 +
完整重执行发现，且证明"摘要相等 ≠ 语义合法"。

## 证明接口（未来 Halo2，本轮不实现）

`src/lib.rs::StateTransitionStatement` 定义 9 个公开输入。`verify_transition_statement`
是链下参考验证器（O(batch) 重执行）。**事件摘要不等于事件语义证明**：把批次哈希放进
public input 不能证明事件合法，电路必须真正约束事件格式、授权关系、撤销状态和根更新。

## 命令

```
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --bin gen_vectors      # 重新生成 tests/vectors/fixed_vectors.json
cargo run --release --bin benchmark   # 生成 results/performance.json
```

## 结果

- `results/experiment_report.md`：主报告
- `results/performance.json`：N∈{16,64,256,1024} × 5 次参考实现耗时与哈希计数
- `tests/vectors/fixed_vectors.json`：事件编码、摘要、根、statement 固定向量
- `results/test_log.txt`、`results/clippy_log.txt`：验收日志

## 诚实边界

- `results/performance.json` 测的是 Rust 参考实现，**不是 Halo2 证明性能，不是 ZK 性能**。
- 哈希/root 一致不是密码学语义证明；本仓没有零知识证明。
- 测试 fixture 不是真实授权服务；resource 前缀模型是实验模型，不代表生产系统。
- 未解决：GR/RR 与 D2-A 电路根语义对齐（域标签不同）、Witness Service、真实 freshness。
