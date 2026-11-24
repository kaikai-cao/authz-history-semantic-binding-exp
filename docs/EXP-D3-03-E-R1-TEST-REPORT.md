# EXP-D3-03-E-R1 — Phase 5 测试报告

**基线**：`56342803d492bb8aaa4ffd44b5586947fd7d0d0c`
**分支**：`exp-d3-03-e-r1`
**测试文件**：`tests/d3_03_e_r1_mock.rs`、`tests/d3_03_e_r1_proof.rs`、`tests/d3_03_e_r1_bench.rs`（ignored）

---

## 1. 核心机制与测试方法

E-R1 在 E 的两事件顺序链之上新增全树扫描：

- 每个事件输入态的 GR/RR 均提供 16 槽 preimage witness（空槽带 empty flag）；
- 电路内重算每个非空叶子的 Poseidon 承诺、自底向上重算 depth-4 Merkle root，并用 `gated-eq` 绑定到当前事件输入根 cell；
- ID 不等 gadget：对两个完整 Field ID `a,b`，提供逆元 `inv`，门为
  `q_scan_neq = fl·bf·((a-b)·inv - 1) = 0`。当 `a=b` 时不存在满足的逆元；实现仍传入 `inv=0`，得到 `-1≠0`，约束失败。

**关键实现约束**：region 创建必须无条件（keygen 全空 witness 与 prove 真实 witness 必须产生相同电路布局），是否生效仅由 `scan_fl`/分支 flag 控制。这一点由真实 proof 测试验证（曾因条件创建 region 导致 verifier 拒绝，已修复）。

**测试分层**：

- 负向语义：MockProver 断言，并记录首条失败约束；
- 正向语义：MockProver accept；
- 真实证明：R1-GG/GR/RR/SINGLE roundtrip、篡改 public instance 拒绝，以及跨槽重复 Grant ID 的负向真实验证案例。

---

## 2. P01–P18 测试矩阵

| 编号 | 测试与预期 | 状态 | 关键依据 / 实际失败门 |
| --- | --- | --- | --- |
| P01 | Parent 存在且未撤销 → Pass | Pass | S0 有 A，全树扫描与 opening 均一致 |
| P02 | Parent 不存在 → Reject | Reject | `scope-subset` 与 `prefix-eq` 先行失败；随后还有 parent opening/root permutation。属于“其他门先失败”的情形，不作为 R1 新约束证据 |
| P03 | Parent 已撤销 → Reject | Reject | **`scan-id-neq` @ `parent not revoked in RR`**；`a=b=0x3e9, inv=0`，首条失败即 R1 目标门 |
| P04 | `Revoke(A) → Grant(B, Parent=A)` → Reject | Reject | **`scan-id-neq` @ `parent not revoked in RR`**，绑定第二事件的 `RR_1` 扫描 |
| P05 | `Grant(A) → Grant(B, Parent=A)` → Pass | Pass | 事件 1 从 `GR_1` 打开 B 的父记录 A |
| P06 | 新 Grant ID + 空槽 → Pass | Pass | 全树无重复，目标槽为空 |
| P07 | 重复 Grant ID + 原槽 → Reject | Reject | **`scan-id-neq` @ `grant id global unique in GR`**；另有 child-old permutation，但首条为目标门 |
| P08 | 重复 Grant ID + 不同空槽 → Reject | Reject | **`scan-id-neq` @ `grant id global unique in GR`**；`a=b=0x3ea, inv=0`，无其他门先行失败 |
| P09 | 两事件重复 Grant ID → Reject | Reject | 同 P08 的独立两事件构造，首条失败为目标门 |
| P10 | 撤销不存在的 Grant → Reject | Reject | target opening / permutation 先行失败；属于其他门先失败 |
| P11 | 正常 Revoke → Pass | Pass | 目标 Grant 存在，RR 全树无重复 |
| P12 | 同 ID 第二次 Revoke + 不同槽 → Reject | Reject | **`scan-id-neq` @ `revoke id global unique in RR`**；`a=b=0x3e9, inv=0`，无其他门先行失败 |
| P13 | 两事件重复 Revoke → Reject | Reject | **`scan-id-neq` @ `revoke id global unique in RR`**；同槽攻击同样由 ID 扫描门拒绝 |
| P14 | 第二事件使用 RR₀ → Reject | Reject | `gated-eq` @ `revoke slot empty in RR` 与 `revoke scan root binds current RR`（RR₀ 根 ≠ `RR_1` cell） |
| P15 | 第二事件使用 GR₀ → Reject | Reject | `gated-eq` @ `grant parent in GR` 与 `grant scan root binds current GR`（GR₀ 根 ≠ `GR_1` cell） |
| P16 | 修改完整 ID 但保留截断前缀 → 按真实 ID 判断 | Pass | 2001=`0x7d1`、2017=`0x7e1` 低 4 位相同但完整 F 不同；全树扫描按完整 F 比较，二者均可写入 |
| P17 | 修改最终状态根 → Reject | Reject | `permute state` / instance row 2 permutation |
| P18 | 修改 public instance 后复用旧 proof → Verifier Reject | Reject | 真实 verifier 拒绝（见第 4 节） |

**18 个 MockProver 测试全部通过**（18 passed / 0 failed）。P18 在真实 proof 层完成。

---

## 3. 每个负向测试的攻击质量记录

| 编号 | 输入状态 / 事件序列 | 攻击方式 | 目标约束 | 实际失败 gate | 其他约束先行失败？ |
| --- | --- | --- | --- | --- | --- |
| P02 | S0 GR 为空 | Grant 指向不存在的 parent slot 5 | Parent opening + scope/prefix | `scope-subset`、`prefix-eq` | 是；非 R1 新约束证据 |
| P03 | S0 有 A | Event0 `Revoke(A)`；Event1 `Grant(B, parent=A)` | Parent 未撤销 | `scan-id-neq @ parent not revoked in RR` | 否 |
| P04 | S0 有 A | 同 P03 的独立构造 | Parent 未撤销且绑定 `RR_1` | `scan-id-neq @ parent not revoked in RR` | 否 |
| P07 | S0 有 A | 两个 Grant 都写 ID=B 到 slot 2 | Grant ID 全局唯一 | `scan-id-neq @ grant id global unique in GR` | 否；另有 child-old permutation 但非首条 |
| P08 | S0 有 A | 同一 ID=B 写入不同空槽 2/3 | **跨槽 Grant ID 唯一** | `scan-id-neq @ grant id global unique in GR` | **否** |
| P09 | S0 有 A | 两事件分别写 ID=B 到 slot 2/3 | 跨事件 Grant ID 唯一 | `scan-id-neq @ grant id global unique in GR` | 否 |
| P10 | S0 GR 为空 | Revoke 一个不存在的 ID=9999 | 目标 Grant 存在 | target opening / Poseidon permutation | 是 |
| P12 | S0 有 A | Event0 `Revoke(A,slot=5)`；Event1 `Revoke(A,slot=6)` | **跨槽 Revoke ID 唯一** | `scan-id-neq @ revoke id global unique in RR` | **否** |
| P13 | S0 有 A | 两次 Revoke(A) 都写 slot 5 | 两事件重复 Revoke | `scan-id-neq @ revoke id global unique in RR` | 否 |
| P14 | S0 RR 空；Event0 写入 A@5 | Event1 提供 RR₀ 的 opening/scan，而非 `RR_1` | 第二事件输入根 | `gated-eq @ revoke slot empty in RR`；`revoke scan root binds current RR` | 两条同时失败；目标为根绑定 |
| P15 | S0 GR 有 A；Event0 写入 B@2 | Event1 提供 GR₀ 的 parent opening/scan，而非 `GR_1` | 第二事件输入根 | `gated-eq @ grant parent in GR`；`grant scan root binds current GR` | 两条同时失败；目标为根绑定 |
| P17 | S0 有 A | 篡改 `C_next` 实例 | 最终状态绑定 | instance row 2 permutation | 否 |
| P18 | 合法 GR witness | 用旧 proof 配篡改后的 public instance | Verifier 绑定 | `verify_proof` 返回 Err | 否 |

P08 与 P12 是本轮最重要的两个跨槽攻击。二者都直接命中 ID 级唯一性门，而不是 Merkle 路径、槽位占用或 commitment 的偶然失败：cell 值显示 `id_a = id_b`、`inv = 0`，门表达式求值为 `-1`。

---

## 4. 真实 proof / verifier

```text
R1 keygen_ms=26219
R14 R1-GG K=15 proof_bytes=8160 prove_ms=27156 verify_ms=441
R14 R1-GR K=15 proof_bytes=8160 prove_ms=33974 verify_ms=459
R14 R1-RR K=15 proof_bytes=8160 prove_ms=34428 verify_ms=475
R14 R1-SINGLE K=15 proof_bytes=8160 prove_ms=34647 verify_ms=498
R18 wrong instance: verifier rejected
NEG-CROSS-SLOT-DUP-GRANT proof_bytes=8160 verifier_accepted=false
```

四组合法 witness 的 proof 均被 verifier 接受；单事件 padding 通过；篡改 `C_next` 后旧 proof 被拒。

**负向真实验证案例**：对“同一 Grant ID 写入两个不同空槽”的恶意 witness，Halo2 prover **仍输出了 8160 B proof**，但 verifier 对诚实的 public instances **拒绝**（`verifier_accepted=false`）。这证明本轮不能把“无法生成 proof”当作唯一负向保障；实际安全边界来自 verifier 对约束系统的验证。

K=15 是实测最小可行值（K=13/14 `NotEnoughRowsAvailable`）。

---

## 5. 完整测试统计

```text
cargo fmt --check                         OK
cargo test --release                      224 passed / 0 failed / 3 ignored
tests/d3_03_e_r1_mock.rs                  18 passed / 0 failed
tests/d3_03_e_r1_proof.rs                  3 passed / 0 failed
tests/d3_03_e_r1_bench.rs                  ignored（显式运行见 benchmark）
```

3 个 ignored 均为历史/本轮性能基准，不影响语义测试覆盖。

---

## 6. 诚实边界

- E-R1 证明的是“给定 S0 与两事件，按当前状态 ID 集合语义得到 S2”；仍不是 ALLOW/DENY、完整历史、Bridge/freshness 证明。
- 初始 S0 的 RR 撤销记录若非由事件产生，当前 builder 无法从裸 slots 恢复其 preimage；本轮“已撤销 Parent”均由事件 0 的 Revoke 产生。这是接口限制。
- 全树扫描的 preimage 是私有 witness；电路通过重算叶子哈希与 Merkle root 绑定防止伪造，但不证明 host 映射 `key_field` 的全局单射性（外部信任）。
- P14/P15 的第二事件旧根攻击同时触发 opening 根绑定和全树扫描根绑定；报告记录两条失败门，不把其中任一条冒充唯一失败原因。
- 负向 proof 案例证明 verifier 拒绝，但本轮未把真实负向 proof 做成独立攻击库；MockProver 矩阵仍是主要负向语义证据。
