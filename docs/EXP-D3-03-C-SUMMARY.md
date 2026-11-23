# EXP-D3-03-C 执行报告

**任务**：Single Grant Revocation and State Transition Proof
**基线**：`ecc4d06b105b047299e785e7b8e268a70a4e2cb4`
**分支**：`exp-d3-03-c`
**范围**：单 Grant、单 Revoke、DirectOnly；不做 Cascade、多事件、递归、DENY/完整历史证明。

---

## 1. 基线与工作区

Phase 0 开始时确认 HEAD 为基线 SHA、工作区干净、`git diff --check` 干净；从该基线新建独立分支 `exp-d3-03-c`。A/B 冻结源码、固定向量、R2 编码定义均未修改。

## 2. Phase 0 接口审计结论

审计文档：`docs/EXP-D3-03-C-INTERFACE-AUDIT.md`，给出源码路径与行号依据。

- **RR 是否已有实现**：电路层没有。B 的 `rr_prev_be/rr_next_be` 在 witness 构造中恒为 `F::ZERO`（`src/transition/b_types.rs:214,221,223`）；D3-01 参考模型有真实 RR 稀疏树（`src/revoke_tree.rs:17-37`），但不是电路。
- **Grant leaf 编码**：B 的 9 词 Poseidon 变体，`D_GRANT + id + issuer + subject + resource_prefix + scope + parent + epoch + valid`（`src/transition/b_types.rs:40-53`）。
- **Revoke leaf 编码**：D3-01 参考为 4 词 `Poseidon(D3-REVOKE-v1, key_field(id), key_field(revoker), epoch)`（`src/revoke_tree.rs:17-24`）；C 采用版本化 C-INT-01 的域元素 witness 变体，不声称与 D3-01 RR 固定向量字节兼容。
- **空叶子定义**：`F::ZERO`（`src/grant_tree.rs:172,193,276`），内部空子树根由 `Poseidon(D_NODE,0,0)` 逐层计算，非零。
- **Merkle 路径规则**：B GR opening 为 depth=4、`dir=0` 左、`dir=1` 右（`src/transition/b_types.rs:71-76,119-149`）；RR 电路路径原本不存在，C-INT-02 固定为 depth=4 并沿用该方向语义。
- **与 D3-01 的兼容性**：语义对齐但编码不兼容；D3-01 的类别 II `key_field` 与参数化深度不能直接进 B/C 电路，已记录为版本化差异，不静默拼接。
- **停止条件**：五个必须停工条件均未触发；通过 C-INT-01~08 版本化补充解决，不改冻结规范。

## 3. 电路实现

新增独立模块：

```text
src/transition/c_constants.rs
src/transition/c_types.rs
src/transition/c_circuit.rs
src/transition/mod.rs（仅注册与 re-export）
tests/d3_03_c_mock.rs
tests/d3_03_c_proof.rs
tests/d3_03_c_bench.rs（ignored，K 变体基准）
```

核心约束关系：

- 目标 Grant 从 `GR_prev` 做 depth-4 opening，叶子在电路内重算，`valid=1` 由 `q_grant_valid` 强制；
- `grant.id = revoke.grant_id`、`grant.issuer = revoke.revoker`、`revoke.epoch = next_epoch`；
- `next_epoch ≥ prev_epoch`（64-bit gadget）+ `next_epoch - prev_epoch - 1 = 0`，排除回绕；
- RR 旧槽位用 `zero_cell` 重算得 `RR_prev`；新叶 `L_REVOKE_C` 用同一 `(dir,sibling)` 重算得 `RR_next`；
- `GR_next = GR_prev` 由显式 `copy_equal(gnext, gprev)` 约束；
- `c_revoke` 在电路内重算，copy 到 batch slot0；`event_count=1` 独立门；
- `C_prev/C_next` 与 8 个 public instance 顺序完全沿用 A。

**A/B 是否有修改**：没有。A/B 源码、固定向量、测试均未改；`mod.rs` 只新增 C 模块注册与 re-export。

## 4. 测试

- MockProver 正向：C01–C07 全过。
- MockProver 负向：C09–C22、C24 全过；各用例的实测拒绝来源见 `docs/EXP-D3-03-C-TEST-REPORT.md`。
- 边界：C25 DirectOnly Parent 撤销不改 Child 通过；C26 Child 撤销通过；C27 槽位哈希碰撞按 canonical assignment 处理通过；C28 非规范域编码拒绝。
- 真实 proof/verifier：C08 roundtrip 通过；C23 修改 `C_next` 后旧 proof 被拒。
- 完整 release 套件：**128 passed / 0 failed**。

## 5. 性能

同轮 A/B/C（完整表见 `docs/EXP-D3-03-C-BENCHMARK.md`）：

| 电路 | K | Proof | Keygen | Prove | Verify |
| --- | --- | --- | --- | --- | --- |
| A | 12 | 3904 B | 1519 ms | 2785 ms | 85 ms |
| B | 12 | 5696 B | 2601 ms | 3616 ms | 76 ms |
| C | 12 | 5760 B | 2542 ms | 3507 ms | 80 ms |

K 变体：K=11/12/13 均可生成并验证 proof；shipped K 仍为 12。未逐门统计约束数；selector/advice/行数只作结构指标。

## 6. 未解决问题

- 不是 ALLOW/DENY 证明：无请求摘要、无 D2-A `π_path`，也没有非存在性证明。
- 不证明 RR 记录来自真实完整授权历史；不证明全局 canonical slot 规范性。
- 类别 II SHA-256 字段映射、Bridge/checkpoint、外部新鲜性仍是外部信任。
- 不实现 Cascade、多事件、递归；C25 只验证 DirectOnly 不改 GR，不验证外部授权决策下 Child 永远有效。
- 未做逐门约束数、实际使用行数、内存或多次采样统计。
- D3↔D2-A 域标签仍未对齐；跨 vk 重放、执行时并发覆盖等问题未解决。

## 7. 结论

C 阶段工程目标达成：在 A 的状态承诺与 B 的 Grant 创建基础上，独立新增了一次 DirectOnly 单撤销的可验证状态转换，完成接口审计、设计冻结、电路实现、C01–C28 测试、真实 proof、同环境成本对比和诚实边界记录。下一步才适合研究多事件批次中创建/撤销混合的状态转换及其与外部状态锚定层的连接；本阶段不宣布端到端授权系统可信性完成。
