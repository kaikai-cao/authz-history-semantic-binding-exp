# EXP-D3-02-05 — 最小原型设计（本轮不实现）

**目的**：把推荐构造 A 固化为"可以直接开工"的最小测试包，先把语句和负向测试钉死，
再决定是否写电路。
**状态**：计划文档；本轮不新增 `.rs` 文件，不修改 D3-01。

---

## 1. 固定基准

| 项 | 取值 | 依据 |
| --- | --- | --- |
| 证明系统 | `halo2_proofs = 0.4.0` | D2-A 冻结栈 |
| 辅助 gadget | `halo2_gadgets = 0.6.0`（`poseidon::Pow5Chip`） | 同上 |
| 哈希 | `halo2_poseidon = 0.2.0`，`P128Pow5T3`（width 3 / rate 2 / R_F=8 / R_P=56） | 一手源码 |
| 电路域 / 承诺曲线 | Pallas base field / Vesta（Pasta cycle） | D2-A |
| 树深 | `d = 4`（16 槽位，GR/RR 各一棵） | D2-A 同深度，便于对照 |
| 事件上限 | 2 × Grant + 1 × Revoke，`N_MAX = 3` | 覆盖 root→child→revoke 全链路 |
| 策略 | 第一版 `DirectOnly`；`Cascade` 为独立对照电路，**不混入** | D3-01 冻结约定 |
| 公开输入 | 8 字段，见 `d3_02_public_statement.md` §2 | 本轮设计 |
| `k` 初值 | 13（8192 行），以 MockProver 通过后校准 | 约 2k 行预算 + 余量 |
| 随机数 | 测试用 seeded `StdRng`（D2-A 中 `OsRng` 不可用） | D2-A 经验 |

**不做**：真实 D2-A 电路改造、递归 verifier、SHA-256 in-circuit、Cascade 主电路、
生产级 proving、真实 Witness Service。

---

## 2. 测试层次规定（必须逐项标明）

沿用 D2-A-R1 的诚实口径：

- **M（MockProver 层）**：直接检查约束系统是否满足。负向用例必须在这一层给出
  `ConstraintSystemFailure` / 具体错误门名；不写 `is_err()` 了事。
- **R（真实证明层）**：`Params::new → keygen_vk → keygen_pk → create_proof → verify_proof`。
  注意 D2-A-R1 发现本机 Halo 0.4 的 prover **不做约束自检**，错误 witness 仍可能出 proof，
  由 `verify_proof` 拒绝。测试报告必须区分"M 层拒绝"与"R 层 prover 出 proof 但 verifier 拒绝"，
  不得写成"create_proof 因约束失败而报错"。
- 每个 P 编号至少跑 M 层；P01/P02/P08/P09/P11 另跑 R 层往返。

---

## 3. P01–P12 测试矩阵

| 编号 | 场景 | 构造方式 | 预期 | 层次 |
| --- | --- | --- | --- | --- |
| **P01** | 合法 Root Grant | 单事件：`grant_id=g1, parent=None, issuer=root, scope=0b1111, epoch=1`；前状态为空树 | **接受** | M + R |
| **P02** | 合法 Child Grant | `g2.parent=g1`，`issuer=g1.subject`，`scope ⊆ g1.scope`，resource 前 8 字节相同，epoch=2 | **接受** | M + R |
| **P03** | Child Scope Escalation | 同 P02 但把 `scope` 的某一 0 位改成 1（如 g1=0b0011, g2=0b0111） | **拒绝**，断言 scope 字节门失败 | M |
| **P04** | Parent 不存在 | `g2.parent = hash("missing")`，其余合法 | **拒绝**，parent 路径根不等于中间 GR | M |
| **P05** | Parent 已撤销 | `g1` 先撤销（RR 有叶子），再让 `g2.parent=g1`；`valid_flag=0` | **拒绝**，断言 `s_not_revoked` 门失败 | M |
| **P06** | 非 Issuer 撤销 | `revoke(g2, revoker=evil)`，`evil != g2.issuer` | **拒绝**，issuer 相等约束失败 | M |
| **P07** | 重复撤销 | 先 `revoke(g2, issuer)`，再对同一 id 发第二次 revoke | **拒绝**，RR 旧叶子非零 | M |
| **P08** | 伪造 GR Root | 保持 GR witness 合法，把公开 `next_grant_root` 改成另一个 32B 值 | **拒绝**，路径恢复根不等 | M + R |
| **P09** | 伪造 RR Root | 同 P08，改 `next_revoke_root` | **拒绝** | M + R |
| **P10** | 错误事件摘要 | 保留合法 `D_E`，把某事件字段（如 scope）改写后重算其余 witness | **拒绝**，批次承诺不等；另测同集合乱序导致承诺不等 | M |
| **P11** | 错误前状态 Root | 保留其他输入，把 `previous_state_commitment` 换成另一个合法旧状态的承诺 | **电路会接受**（因为仍是某个合法前状态的开承诺）；必须由网关按 D2-B 核对外部 checkpoint 后拒绝 | M + 网关外部检查 |
| **P12** | 错误 Epoch | 把 `epoch_next` 改小，或令 `e2.epoch < e1.epoch` | **拒绝**，epoch 比较链失败 | M |

### 3.1 关于 P11 的诚实说明

P11 是**故意设计成"电路内接受"**的测试。它验证的命题是：
"电路只能证明相对 `C_prev` 的转换，不能证明 `C_prev` 是当前状态。"
若把 P11 写成"电路拒绝"，等于声称本设计解决了历史完整性，这是错误结论。
正确的验收方式是：

1. MockProver 层通过（开承诺成立）；
2. 网关层：把 statement 的 `C_prev` 与从 D2-B 验证器取得的 checkpoint anchor 比对，
   不等 → 拒绝；
3. 报告两层结果，明确"电路接受 ≠ 系统接受"。

### 3.2 额外交叉测试（不计入 P01–P12，但必须跑）

- **X1 与 D3-01 固定向量对齐**：P01/P02/P05 的事件编码、批次承诺之外，
  叶子承诺与 Merkle 根必须与 `tests/vectors/fixed_vectors.json` 的
  `h3-direct`（DIRECT_ONLY）逐字节相同（域标签保持 `D3-`）。
- **X2 负向错误码语义**：复用 D3-01 的 `RuleError` 码名（SCOPE_ESCALATION 等）作为测试名，
  但断言的是**Halo2 门失败**，不是 Rust 函数返回 `Err`。
- **X3 真证明往返**：P01/P02 必须至少各一次完整 `create_proof/verify_proof`；
  记录 proof_bytes 与耗时，**标注为本机原型微基准**，不外推。

---

## 4. 实施顺序（如果下一阶段批准实现）

1. 先写 `tests/` 的 P01–P12 fixture 生成与断言骨架（纯 Rust 数据结构，不含电路），
   用 D3-01 的三路径验证 fixture 本身的合法性；
2. 实现 Poseidon chip 配置 + 域标签 fixed 列，跑 X1 与 off-circuit 一致性；
3. 实现 GR/RR 路径门（2.8/2.9），跑 P08/P09；
4. 实现规则门（2.2–2.7），跑 P01–P07/P10/P12；
5. 实现 `C_prev` 开承诺（2.11），跑 P11 两层断言；
6. 最后接真实证明往返 X3，并记录"prover 出 proof 但 verifier 拒绝"的实际行为。

这个顺序保证：**先有可证伪的负向测试，再有电路**，避免"为了做电路而做电路"。

---

## 5. 原型选择理由（为什么不选 B / C 作第一版）

- B 的"未修改区域不变"无法用 Merkle 路径单独证明，需打开全部叶子或换承诺原语；
  在状态服务可被攻破的模型下会把历史完整性重新外包。
- C 需要统一的递归 verifier 与 curve cycle 工程，本仓没有任何实现；原型 n≤3 时
  递归开销远大于收益。
- A 能在最小规模下**逐条**把 D3-01 的语义规则变成"无接受证明"，直接回答本轮研究问题。
- 这不否认 B/C 的空间：多授权来源、部分撤销、隐藏历史与外部最新状态绑定的组合，
  现有工作并未覆盖（见 `d3_02_related_work.md`）。
