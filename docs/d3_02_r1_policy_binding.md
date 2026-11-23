# EXP-D3-02-R1-03 — policy_id 与实际电路规则的绑定

**基线**：`98906dd1f94f7d9922f7759989f896c418c85561`
**分支**：`exp-d3-02-r1`
**性质**：设计修订。本轮不实现电路，不修改 D2-A / D3-01 冻结实现。

---

## 0. 问题陈述与一句话结论

D3-02 把 D3-01 的 `policy_digest = SHA256(policy.code())` 换成版本化 `policy_id`，
并计划"电路内硬编码 DirectOnly 规则"。但存在一个**绑定缺口**：

> **电路中硬编码 DirectOnly 规则，不代表公开输入里的 `policy_id` 自动等于 DirectOnly。**

若证明者把 `policy_id` 公开输入填成"CASCADE 策略的值"，而电路实际执行 DirectOnly 规则，
验证者看到的就是一个"声称 Cascade、实际 DirectOnly"的证明。若网关不核对 `policy_id` 与
验证密钥（verifying key, vk）的对应关系，这种策略混淆无法被发现。更糟的是，若同一个 vk
能验证多个 `policy_id`（电路不约束 `policy_id` 为常量），则策略选择完全由证明者决定。

> **结论（明确选择）**：采用**组合绑定，但最终安全保证由「每策略独立编译电路 + 验证密钥注册表」承担**。
> 具体：① `policy_id = H(D_POLICY, policy_version, policy_parameters, circuit_spec_digest)`
> 由冻结规范确定性生成；② 电路内把 `policy_id` 约束为**固定常量**（copy 到 fixed 列）；
> ③ DirectOnly 与 Cascade **独立编译**成两个电路、两把 vk；④ 网关维护
> `vk_hash → (policy_id, circuit_spec_digest, 源码 commit)` 注册表，只接受注册表中的 vk，
> 并核对证明所用 vk 的 `policy_id` 与 statement 公开值一致。
> 方案 ③（电路公共输入含策略参数逐项约束）作为**扩展**，第一版不把完整参数表塞进电路。
> 单一机制都不够：只有①是命名约定，只有②无法防止"用错 vk"，只有④无法防止"vk 内部规则与
> 声明的 policy 不符（若电路未锁常量）"。**四者组合才形成可审计的绑定链。**

---

## 1. 一手语义事实（绑定必须覆盖什么）

来源：`authz-history-semantic-binding-exp/src/policy.rs`、`state.rs`、`grant_tree.rs`、
`encoding.rs`，以及 D2-A `src/poseidon_hash.rs`/`public_inputs.rs`。

| 语义项 | D3-01-R1 实际实现 | 必须用 policy_id 绑定 |
| --- | --- | --- |
| 策略区分 | `Policy::DirectOnly` / `Policy::Cascade`（`policy.rs`） | ✅ 两种枚举必须不同 id |
| DirectOnly | revoke 只把目标 grant 的 `valid` 置 0 + 写一条 RR 叶子 | ✅ 规则版本 |
| Cascade | revoke 传递撤销所有后代（`state.rs` 的集合闭包） | ✅ 规则版本 |
| Scope | `scope_child & !scope_parent == 0`（`policy.rs:scope_allows`） | ✅ 语义与字节宽度 |
| Resource | 前 `RESOURCE_PREFIX_BYTES = 8` 字节相等（`policy.rs:90-95`） | ✅ 参数（=8，不是 32） |
| Epoch | 状态版本单调（`state.rs`），事件 epoch ≥ parent epoch | ✅ 单调规则 |
| Grant/Revoke 规则版本 | 冻结的 `history.rs` / `reference_model.rs` 判定逻辑 | ✅ 源码 commit |
| Merkle 域标签版本 | `D3-GRANT-v1` / `D3-REVOKE-v1` / `D3-NODE-v1` / `D3-SLOT-v1`（`encoding.rs:19-25,42`） | ✅ 域标签集版本 |
| 电路规范版本 | `d3_02_circuit_spec.md` 的 11 模块门布局 | ✅ circuit_spec_digest |
| D2-A 域标签 | `D2A-label-v1` BLAKE2b，与 D3 `D3-` SHA-256 域化**不一致** | ⚠️ 未解决，不声称统一 |

---

## 2. policy_id 的定义（确定性、可复核）

```
policy_id = H( enc_bytes("D_POLICY")
             ‖ enc_bytes(policy_version)          // u32be，例 1
             ‖ enc_bytes(policy_name)             // "DIRECT_ONLY" 或 "CASCADE"
             ‖ enc_bytes(policy_parameters)       // 规范化的参数集合，见下
             ‖ enc_bytes(circuit_spec_digest) )   // 电路规范文档的 SHA-256（32B）
```

其中 `H` 复用 D3-01 `field_from_bytes` 口径（双 SHA-256 拼 64B + `from_uniform_bytes`），
得到 Pallas base field 元素；`enc_bytes` 为 8 字节大端长度前缀。

**`policy_parameters` 的规范化编码**（顺序固定，缺一不可）：

```
policy_parameters = "scope_bytes=8;resource_prefix_bytes=8;epoch_monotonic=1;"
                  ‖ "grant_rule_ver=<git sha>;revoke_rule_ver=<git sha>;"
                  ‖ "merkle_domains=D3-GRANT-v1,D3-REVOKE-v1,D3-NODE-v1,D3-SLOT-v1;"
                  ‖ "depth=4;max_grant=2;max_revoke=1;direct_only_flag=1"
```

- DirectOnly 与 Cascade 的 `policy_name` 与 `direct_only_flag` 不同 → `policy_id` 不同。
- `circuit_spec_digest` 取 `docs/d3_02_circuit_spec.md`（本轮修订后的 `d3_02_r1_*` 集合）的
  SHA-256；任一门布局变化必须重算 id 并新建 vk。
- `git sha` 指向 D3-01-R1 冻结实现的 commit，防止"规则代码改了但 id 不变"（上一轮 E4 的漏洞）。

**D2-B 的 `policy_version: u32` 与 D3 的 `policy_id: Field` 不是同一个值**：
Bridge Statement（R1-01 §3.2）携带两者，验证端用注册表核对
`(policy_version, policy_id)` 的对应关系；电路只认 `policy_id`。这是有意的——D2-B 是链下
u32 标签，D3 是电路域元素，语义层次不同。

---

## 3. 四种绑定机制比较

| 机制 | 内容 | 验证者能检查什么 | 单独使用是否足够 | 本轮采用 |
| --- | --- | --- | --- | --- |
| 1. 电路内约束 `policy_id` 为固定常量 | fixed 列常量 `policy_id_const`，gate 强制 `policy_id_pub == policy_id_const` | 证明者不能在该 vk 下填别的策略值 | ❌ 只防"同 vk 改公开值"，不防"用错 vk" | ✅ 采用（基础层） |
| 2. 每策略独立编译电路与 vk | DirectOnly → `vk_DO`；Cascade → `vk_CAS`；各自硬编码规则 | 不同策略的证明必须来自不同 vk | ⚠️ 若网关不核对 vk↔策略，仍可用 `vk_DO` 声称 Cascade | ✅ 采用（结构层） |
| 3. 电路公共输入含策略参数并逐项约束 | 把 `resource_prefix_bytes` 等参数作为 public，电路逐项 gate | 参数泄露在 public，且增加列 | ❌ 参数公开损害隐私；完整参数表塞电路成本高 | ⚠️ 扩展，第一版不做 |
| 4. 验证密钥注册表绑定策略版本 | 网关维护 `vk_hash → (policy_id, circuit_spec_digest, commit, active)`，只接受注册 vk 且公开 `policy_id` 与表一致 | 证明所用 vk 的策略身份可审计、可撤销 | ⚠️ 若 vk 内部规则与声明不符（电路未锁常量）则无效 | ✅ **采用（最终安全保证）** |

**为什么最终安全保证是④（配合①②）**：
- ① 保证"给定 vk，公开 `policy_id` 不能乱填"；
- ② 保证"不同策略物理上是不同 vk"；
- ④ 保证"网关只接受已知 vk，且其 `policy_id` 与 statement 一致"——这是验证者**唯一能独立检查**
  的策略身份环节（验证者不读电路源码、不做 MockProver）。
- 三者缺一：缺①则④查到 vk 对应 DO 但证明公开值填 CAS，电路接受（策略混淆，R06）；
  缺②则一个 vk 想证两套规则；缺④则证明者拿 `vk_DO` 对一个声称 CAS 的 statement 验证，网关
  无法发现（R09）。
- ③ 是第一版**刻意不用**的：把参数放 public 会让 `RESOURCE_PREFIX_BYTES=8` 等模型细节暴露给
  所有验证者，且逐项约束增加列；其安全作用被①+④覆盖。

### 3.1 网关检查流程（策略绑定在验证端的落点）

```
1. 从证明元数据/随附材料取 vk_hash = SHA256(vk_bytes)
2. 查注册表: entry = registry[vk_hash]，若不存在或 !active -> 拒绝 (R09)
3. 检查 entry.policy_id == statement.policy_id，否则拒绝 (R05/R06)
4. 检查 entry.circuit_spec_digest == 当前冻结电路规范 digest，否则拒绝 (版本回滚)
5. 执行 verify(vk, public_inputs, π)：电路内 gate 已强制 policy_id_pub == 电路常量 (R05)
6. 组合 R1-01 Bridge: 核对 statement.policy_id == BridgeStatement.policy_spec_digest (R05/R09)
```

注意步骤 3 与 5 是**双重检查**：步骤 5 是电路密码学保证，步骤 3 是注册表审计保证。
任一失败即拒绝。

### 3.2 注册表治理

- 注册表由**独立于证明者**的治理方维护（与 D2-B witness set、Bridge quorum 分离）。
- 新增策略版本 = 新增 vk + 新增 policy_id + 新 entry，旧 entry 保留 `active=false` 供历史审计。
- 策略规则变更（哪怕 `code()` 字符串不变）必须换 `policy_version`、重编译 vk、重算
  `circuit_spec_digest` 与 `policy_id`，并新增 entry——杜绝上一轮 E4。
- 注册表本身是可信外部状态（与 D1-E checkpoint 同级），其完整性不在电路内证明。

---

## 4. 与 D2-A 组合时的策略绑定（未解决，明确边界）

D2-A（冻结）的 `PublicInputs` 有 `policy_tag: F`（来自 `Request.policy_version` 经
`label_to_field`，域标签 `D2A-label-v1`，BLAKE2b），而 D3-02 的 `policy_id` 是
D3 SHA-256 域化 + 结构化参数。**两者不是同一个域元素**，GR/RR 根也因域标签不同不能直接互用
（D3-02 §11 未解决项 2）。

- 网关组合 `π_trans`（D3）与 `π_path`（D2-A）时，必须确认二者使用的策略是**同一个语义策略**：
  网关核对 `policy_id`(D3) 与 `policy_tag`(D2-A) 都映射到同一个治理方登记的策略版本。
- **这不是密码学绑定**，是网关配置绑定；两个电路的域标签不一致使电路级绑定本轮无法实现。
- 明确不声称"π_trans 与 π_path 的 policy 在电路内统一"；这是后续域对齐研究项。

---

## 5. R05 / R06 / R09 的测试层级归属

| 测试 | 攻击 | 电路层（MockProver） | 真实 proof/verifier | Bridge 验证器 | 网关集成 |
| --- | --- | --- | --- | --- | --- |
| R05 | 修改策略 ID | 拒绝（`policy_id_pub == const` gate 失败） | verifier 拒绝（prover 可出 proof，verifier 拒绝——沿用 D2-A-R1 口径） | 拒绝（BridgeStatement.policy_spec_digest 与 statement 不符） | 拒绝（注册表 policy_id 不符） |
| R06 | DirectOnly 电路声称 Cascade | 拒绝（vk_DO 电路内 `policy_id_const`=DO，填 CAS 值 gate 失败） | verifier 拒绝 | 拒绝 | 拒绝（vk_hash=DO 但 statement 声称 CAS） |
| R09 | 跨策略验证密钥重放 | 用 `vk_CAS` 验 DO 证明：若公开值也改 CAS，MockProver 层不会自动发现（电路各自自洽） | verifier 可能接受（若参数恰好满足） | —— | **拒绝**（注册表 `vk_hash` 与 statement.policy_id 不匹配；或 `policy_spec_digest` 不符） |

R09 的关键诚实点：**跨 vk 重放在电路/verifier 层可能接受**，因为两把 vk 各自验证一个自洽证明。
它只能在**网关注册表层**被拒绝。测试报告必须标明这一点，不得写成"电路拒绝 R09"。

---

## 6. 本方案不能声称的内容

- **不能**声称"`policy_id` 公开值自动等于电路规则"——需要①+②+④组合才形成绑定链。
- **不能**声称"D3 与 D2-A 策略在电路内统一"——域标签不一致，只有网关配置绑定。
- **不能**声称"策略参数完全进电路"——第三版机制未采用，参数在 `policy_id` 的 preimage 里被承诺，
  但不逐项在电路内 gate。
- **不能**声称"注册表可信"——它是外部信任，与 checkpoint 同级。
- **不能**省略 `circuit_spec_digest`——若规则代码改了而 id 不变，绑定失效（E4 漏洞重现）。
