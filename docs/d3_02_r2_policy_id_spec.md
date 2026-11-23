# EXP-D3-02-R2-01 — Policy ID 与 Circuit Spec Digest 冻结规范

**基线**：`023a5d1641354dc7f7257a09cc23a28787b33b0d`（D3-02-R1）
**分支**：`exp-d3-02-r2`
**性质**：设计冻结。本轮不实现电路，不修改 D2-A / D2-B / D3-01 冻结源码。
**目标**：彻底消除 `policy_id` 与 `circuit_spec_digest` 的循环定义风险，给出逐字段可复现的编码。

---

## 0. 一句话结论

> **明确选择**：采用**方案 A′ = 独立结构化 CircuitSpec 工件摘要 + 策略参数哈希**。
> 定义独立工件 `CircuitSpec`（纯结构化数据表，**禁止**包含 `policy_id`、`vk_hash` 或任何
> 派生哈希），`D_circuit = SHA256(enc_bytes("D3-CIRCUIT-SPEC-v1") ‖ CanonicalEncode(CircuitSpec))`；
> `policy_id = field_from_bytes("D_POLICY", CanonPolicyId)`，其中 `CanonPolicyId` 是
> `(version, name, parameters, D_circuit)` 的规范拼接。哈希到域统一复用 D3-01 的
> `field_from_bytes`（双 SHA-256 拼 64B + `from_uniform_bytes`），**不在规范里引入第二种哈希到域口径**。
> `vk_hash` 作为**编译产物指纹**只进 VK 注册表，**不进** `policy_id`——避免把编译器/floor-planner
> 的不确定性写进策略身份。

循环定义的根因与消除办法在 §2；三种设计比较在 §3；哪些进 policy_id / VK 注册表 / 审计元数据在 §4。

---

## 1. 一手事实（冻结规范的锚点，全部本轮读取源码核实）

| 项 | 一手事实 | 来源 |
| --- | --- | --- |
| D2-A / D3 域 | `pasta_curves::pallas::Base`（Pallas base field Fp） | `agent-authz-halo2-exp/src/poseidon_hash.rs:11`、`authz-history-semantic-binding-exp/src/encoding.rs:13` |
| Fp 模数 | `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`，`NUM_BITS = 255`（最高位 bit 254） | `pasta_curves-0.6.0/src/fields/fp.rs:20-29,106-110,632` |
| D3 长度前缀 | `enc_bytes(buf, b) = u64be(len) ‖ b`，即 **8 字节大端**长度前缀 | `authz-history-semantic-binding-exp/src/encoding.rs:132-135` |
| D3 哈希到域 | `field_from_bytes(label, bytes) = F::from_uniform_bytes( SHA256(bytes) ‖ SHA256(label) )`，64B | `authz-history-semantic-binding-exp/src/encoding.rs:97-102` |
| `from_uniform_bytes` 语义 | 把 64B 按 **little-endian** 解释为整数再 mod p；安全性要求 `N·8 ≥ NUM_BITS + 128` → `64·8=512 ≥ 255+128=383` ✅ | `ff-0.14.0/src/lib.rs:438-461`、`pasta_curves-0.6.0/src/fields/fp.rs:799-810` |
| D2-A 标签映射 | BLAKE2b-256 前 16B 按大端 u128 → `F::from_u128`（因 `2^128 < p`，单射）；域 `D2A-label-v1` | `agent-authz-halo2-exp/src/poseidon_hash.rs:16-31` |
| D3 域标签集 | `D3-GRANT-v1` / `D3-REVOKE-v1` / `D3-NODE-v1` / `D3-FIELD-v1` / `D3-KEY-v1` / `D3-EVENT-v1` / `D3-BATCH-v1` | `authz-history-semantic-binding-exp/src/encoding.rs:19-25` |
| R1 的 policy_id 定义 | `H(enc_bytes("D_POLICY") ‖ enc_bytes(version) ‖ enc_bytes(name) ‖ enc_bytes(params) ‖ enc_bytes(circuit_spec_digest))`，H 复用 `field_from_bytes` | `docs/d3_02_r1_policy_binding.md:53-64` |

**关键推论**：`policy_id` 的哈希到域口径必须与 D3-01 完全一致（`field_from_bytes`），否则
"同一个策略在不同文档里算出不同域元素"。本轮**不改**这个口径，只冻结其输入编码与工件结构。

---

## 2. 循环定义风险与消除（本轮核心）

### 2.1 循环从哪来

R1 给出 `policy_id = H(..., circuit_spec_digest)`，其中 `circuit_spec_digest` 被描述为
"电路规范文档的 SHA-256"（`d3_02_r1_policy_binding.md:76-77`）。若按字面把**自然语言文档**
（如 `d3_02_circuit_spec.md`）作为摘要输入，会产生两类致命问题：

1. **自引用循环**：若该文档正文里写了 `policy_id` 的值、写了 `circuit_spec_digest` 的值、
   或写了"本摘要 = ..."，则 `D_circuit = SHA256(doc)` 与 `policy_id = H(..., D_circuit)` 互相依赖，
   没有不动点或有多解。**实现者会陷入"先有鸡还是先有蛋"。**
2. **非确定性**：Markdown 的换行、空格、行尾 CRLF/LF、生成时间戳、链接锚点任一变化都会改
   `D_circuit`，进而改 `policy_id`——与电路语义无关的变化却改了策略身份，注册表全部失效。

### 2.2 消除办法：CircuitSpec 必须是"纯结构化、无自引用"工件

> **冻结规则 R2-01-C1**：`CircuitSpec` 是一个**结构化数据表**（建议 Rust `struct` + 固定序列化，
> 或等价的 canonical JSON），其字段集合在 §2.3 固定。**它禁止包含**：
> - `policy_id`、`vk_hash`、`D_circuit` 本身或任何由它们派生的值；
> - 生成时间戳、git 工作区脏标记、构建机器信息、文件路径等非语义字段；
> - 自然语言描述段落（解释性文字放文档，不进摘要）。
>
> 一句话：`CircuitSpec` 只包含"**这台电路是什么**"（门、列、约束、域标签、常量、深度、容量），
> 不包含"**这个策略叫什么 / 它的 id 是多少**"。

> **冻结规则 R2-01-C2**：摘要覆盖范围严格为
> `D_circuit = SHA256( enc_bytes("D3-CIRCUIT-SPEC-v1") ‖ CanonicalEncode(CircuitSpec) )`。
> 不允许把 `policy_id`、`vk_bytes`、`D_circuit` 之外的东西塞进 preimage；
> 不允许"摘要包含自身计算结果"。校验方法：`CanonicalEncode(CircuitSpec)` 的输出中
> 不出现 32 字节子串等于 `D_circuit`（自检脚本，原型阶段实现）。

依赖方向因此是**单向无环**：

```
CircuitSpec（结构化，无 policy_id）
      │ CanonicalEncode + SHA256
      ▼
  D_circuit ──────────────┐
                          │
(version,name,params,D_circuit) ──CanonPolicyId──> field_from_bytes ──> policy_id
                          │
                          └────────────────────────> VK 注册表 metadata（审计用）
```

注意箭头方向：`policy_id` 依赖 `D_circuit`，`D_circuit` **不**依赖 `policy_id`。注册表存
`(vk_hash → (policy_id, D_circuit, commit))` 只是记录，不参与 `D_circuit` 的计算。

### 2.3 CircuitSpec 冻结字段表

| 字段 | 类型 | 编码 | 说明 | 是否语义 |
| --- | --- | --- | --- | --- |
| `spec_version` | u32 | u32be(4B) | CircuitSpec 结构版本，冻结为 `1` | ✅ |
| `circuit_label` | ASCII | enc_bytes | 固定 `"D3-STATE-TRANSITION-DIRECTONLY-v1"` 或 Cascade 对应标签 | ✅ |
| `field_tag` | ASCII | enc_bytes | 固定 `"pallas::Base"` | ✅ |
| `poseidon_tag` | ASCII | enc_bytes | 固定 `"P128Pow5T3"`（R_F=8, R_P=56, width=3, rate=2） | ✅ |
| `poseidon_domain_tags` | Vec\<ASCII\> | u32be(count) ‖ 各 enc_bytes | 固定顺序：`D3-STATE-P-v2,D3-GRANT-v1,D3-REVOKE-v1,D3-NODE-v1,D3-EVENT-v1,D3-BATCH-v1` | ✅ |
| `tree_depth` | u8 | 1B | 冻结 `4` | ✅ |
| `tree_capacity` | u32 | u32be | 冻结 `16` = 2^4 | ✅ |
| `max_grant` | u32 | u32be | 冻结 `2` | ✅ |
| `max_revoke` | u32 | u32be | 冻结 `1` | ✅ |
| `max_event_count` | u32 | u32be | 冻结 `3` | ✅ |
| `k` | u32 | u32be | Halo2 `log2(rows)`，冻结目标 `13`（可上调，见 §6） | ✅ |
| `gate_modules` | Vec\<ASCII\> | u32be(count) ‖ 各 enc_bytes | 固定顺序的 11 模块名（`d3_02_circuit_spec.md` §2.1–2.11）：`event_encoding,grant_validity,parent_binding,scope,resource,revocation,epoch,gr_update,rr_update,batch_binding,state_binding` | ✅ |
| `policy_rule_commit` | ASCII | enc_bytes | D3-01-R1 实现 commit（`dc13e810…`）十六进制字符串；绑定规则代码版本 | ✅ |
| `strategy_flag` | u8 | 1B | `1`=DirectOnly，`2`=Cascade | ✅ |

`CanonicalEncode(CircuitSpec)` = 按上表**声明顺序**逐字段拼接，无任何分隔符或填充。
长度明确（`u32be` 4B、`u8` 1B、`enc_bytes` 8B 前缀 + 内容），故单射可解析。

**版本策略**：任一字段变化 → 新 `spec_version` 或新 `circuit_label` → 新 `D_circuit` →
新 `policy_id` → 新 vk → 注册表新增 entry。**旧 entry 保留 `active=false`**。

---

## 3. 三种设计比较（必须比较，不能只写一种）

记 `D_policy_body = CanonPolicyId = enc_bytes("D_POLICY") ‖ enc_bytes(version) ‖ enc_bytes(name) ‖ enc_bytes(parameters) ‖ enc_bytes(D_circuit)`。

### 3.1 方案 A：电路规范文件摘要 + 策略参数哈希（本轮选 A′）

- 机制：`D_circuit` 来自 §2.3 结构化工件；`policy_id = field_from_bytes("D_POLICY", D_policy_body)`。
- 验证者信任谁：`policy_id` 的可信来源是**冻结的 CircuitSpec 工件 + 治理方发布的 parameters**；
  网关用注册表核对 `policy_id ↔ vk_hash ↔ D_circuit`。
- 能否被证明者替换：不能。电路 gate 强制 `policy_id_pub == policy_id_const`（R1-03 机制①），
  注册表核对（机制④）；`D_circuit` 是规范工件的纯函数，不含证明者可控输入。
- 循环/自引用：**A′ 已消除**（§2.2）；朴素 A（摘要自然语言文档）未消除。
- 确定性：**高**。结构化编码逐字节确定，编译前可算，跨平台一致。
- 编译产物漂移：`vk_hash` 可能随编译器版本/floor-planner 变化，但 `policy_id` 不受影响；
  二者由注册表显式绑定，漂移会被注册表检查发现（新 vk 必须重新注册）。
- 适用条件：治理方愿意维护结构化 CircuitSpec 工件与 parameters 表。

### 3.2 方案 B：源码 commit + 电路规范摘要

- 机制：`D_circuit = SHA256(commit_hex ‖ CanonicalEncode(CircuitSpec))`，把 git commit 直接放进摘要。
- 验证者信任：git 仓库完整性 + 该 commit 确实实现了 CircuitSpec 声明的门布局。
- 优点：规则代码版本与策略身份强绑定，杜绝 R1 E4（代码改了 id 没改）。
- 缺点（本轮不采用的原因）：
  1. **工作区脏状态不可承诺**：commit 无法表达"未提交的改动"，若实现者用脏工作区编译，
     `vk_hash` 与 `D_circuit` 声明的 commit 不符，但电路里没有 gate 能检测——只是把风险
     从"`policy_id`"转移到"commit 声明与字节码不符"。
  2. **commit 是行的不是语义的**：同一语义电路换 commit（哪怕只改注释）→ 新 `policy_id`
     → 新 vk → 注册表 churn。
  3. **依赖外部系统**：验证者要核对 commit 内容需访问 git 仓库，网关无法离线验证。
- **可迁移部分**：`policy_rule_commit` 作为 CircuitSpec 的**一个字段**（§2.3 已采用），
  但不作为摘要的独立主输入——保留其审计价值，不承担身份主锚。

### 3.3 方案 C：编译产物 / VK 摘要 + 策略注册表

- 机制：`policy_id` 直接绑定 `vk_hash` 或 `SHA256(circuit_bytes)`。
- 验证者信任：编译过程确定性 + 注册表。
- 优点：策略身份与实际运行的验证密钥物理绑定，最"实"。
- 缺点（本轮不采用的原因）：
  1. **编译不确定性**：Halo2 vk 含 floor-planner 布局、`k`、列置换等，编译器版本或
     feature flag 变化会改 `vk_hash` 而电路语义不变 → `policy_id` 漂移。
  2. **循环风险回流**：若 `policy_id` 进 public instance 且 vk 编译时又嵌入 `policy_id`
     常量（R1-03 机制①要求），则"vk 摘要 → policy_id → vk 常量 → vk 摘要"形成新循环。
  3. **原型阶段 vk 尚未稳定**：D3-03 才编译电路，冻结阶段不能把身份锚在未产生的产物上。
- **可迁移部分**：`vk_hash` 作为**注册表键**（R1-03 机制④，本轮保留），不承担策略身份定义。

### 3.4 三方案对照表

| 维度 | A′（采用） | B（commit+摘要） | C（VK 摘要） |
| --- | --- | --- | --- |
| 策略身份主锚 | 结构化 CircuitSpec + params | git commit | 编译产物 vk |
| 循环风险 | 已消除（无自引用） | 无（commit 单向） | **有**（vk↔常量回流） |
| 确定性（跨平台） | 高 | 中（依赖 commit 可达） | 低（编译器/floor-planner） |
| 编译前可算 | ✅ | ✅ | ❌ |
| 规则代码漂移检测 | 靠 `policy_rule_commit` 字段 + 注册表 | 强（commit 进摘要） | 中 |
| 网关离线可验 | ✅（工件随注册表面发布） | ❌（需 git） | 部分（需 vk_bytes） |
| `vk_hash` 的角色 | 注册表键 | 注册表键 | 身份主锚（拒绝） |
| 本轮 | ✅ | ❌（commit 降为字段） | ❌ |

---

## 4. 内容归属：policy_id / VK 注册表 / 审计元数据

| 内容 | 归属 | 理由 |
| --- | --- | --- |
| `version`、`name`、`parameters`、`D_circuit` | **进 `policy_id`** | 策略语义身份，必须进电路常量 gate 与公开 statement |
| `D_circuit` | **同时进注册表 metadata** | 供审计者核对 vk 是否由该规范编译 |
| `vk_hash = SHA256(vk_bytes)` | **只进 VK 注册表键** | 编译产物指纹；进 `policy_id` 会引入编译不确定性与循环 |
| `policy_rule_commit` | **CircuitSpec 字段 + 注册表审计元数据** | 绑代码版本，但不作为身份主锚（B 的教训） |
| 编译器版本 / feature flags / `k` 调整记录 | **审计元数据** | 影响 vk 可复现性，但不改变策略语义；记入注册表 entry 的 `build_notes` |
| `circuit_spec_digest` 的生成时间戳、文件路径 | **禁止进任何摘要** | 非语义，破坏确定性 |
| D2-B `policy_version: u32` | **注册表映射字段** | 链下标签，与 `policy_id` 的对应关系由注册表维护（R1-03 §2） |

**最终决定**：`policy_id` 只承诺**语义身份**（version/name/parameters/D_circuit）；
`vk_hash` 只做**运行密钥身份**；二者在 VK 注册表中显式绑定。这是"身份与实现分离但可审计"。

---

## 5. 冻结的 policy_id 计算（逐字段可复现）

### 5.1 具体公式

```
CanonPolicyId =
    enc_bytes("D_POLICY")                       // 8B 大端长度前缀 + ASCII
  ‖ u32be(policy_version)                       // 4B 大端，例 1
  ‖ enc_bytes(policy_name)                      // "DIRECT_ONLY" | "CASCADE"
  ‖ enc_bytes(policy_parameters)                // §5.2 规范串
  ‖ enc_bytes(D_circuit)                        // 8B 长度前缀 + 32B 摘要

policy_id = field_from_bytes("D_POLICY", CanonPolicyId)
          = F::from_uniform_bytes( SHA256(CanonPolicyId) ‖ SHA256("D_POLICY") )
```

**注意**：`enc_bytes("D_POLICY")` 出现在 preimage 里是 R1 既有口径（域标签作为第一个字段），
与 `field_from_bytes` 第二个参数也是 `"D_POLICY"` 不冲突——前者是拼接字段，后者是哈希到域的
独立域分离。二者都用同一常量字符串，保持 R1 兼容。**不要**把其中一处改成别的标签，否则
`policy_id` 与 R1 文档描述不一致。

### 5.2 policy_parameters 规范串（逐字节固定）

```
policy_parameters =
  "scope_bytes=8;"
‖ "resource_prefix_bytes=8;"
‖ "epoch_monotonic=1;"
‖ "grant_rule_ver=dc13e810a65558362ccf1458bed593ca015abd9e;"
‖ "revoke_rule_ver=dc13e810a65558362ccf1458bed593ca015abd9e;"
‖ "merkle_domains=D3-GRANT-v1,D3-REVOKE-v1,D3-NODE-v1,D3-SLOT-v1;"
‖ "depth=4;max_grant=2;max_revoke=1;strategy_flag=1"
```

- `strategy_flag=1` = DirectOnly；Cascade 为 `2`，且 `policy_name="CASCADE"`。
- `resource_prefix_bytes=8` 来自 `policy.rs:90-95` 的 `RESOURCE_PREFIX_BYTES = 8`（不是 32）。
- `D3-SLOT-v1` 在 Merkle 域标签集里（布局用），但**不在** §2.3 的
  `poseidon_domain_tags`（那是电路 Poseidon 常量列表）——两处各有其位，不重复也不遗漏。

### 5.3 DirectOnly 与 Cascade 的身份区分

| 字段 | DirectOnly | Cascade |
| --- | --- | --- |
| `policy_name` | `"DIRECT_ONLY"` | `"CASCADE"` |
| `strategy_flag` | `1` | `2` |
| `circuit_label` | `"D3-STATE-TRANSITION-DIRECTONLY-v1"` | `"D3-STATE-TRANSITION-CASCADE-v1"` |
| 电路门布局 | `gate_modules` 相同名字，内部 revoke 语义不同（只置 valid / 传递撤销） | 同左 |
| 结果 | `D_circuit` 不同 → `policy_id` 不同 → vk 不同 | 同左 |

**两道保险**：`policy_name`/`strategy_flag` 让 `policy_id` 本身就不同；`circuit_label` 让
`D_circuit` 也不同。即使一处写错，另一处仍产生不同身份，注册表核对会失败。

---

## 6. 原型阶段需要冻结的配套参数（本轮给出目标值，D3-03 实现时不得擅改）

| 参数 | 冻结值 | 备注 |
| --- | --- | --- |
| Poseidon 域标签（状态承诺） | `D3-STATE-P-v2` | R1-01 引入；电路 fixed 常量，非 witness |
| Poseidon 参数 | `P128Pow5T3`, width=3, rate=2, R_F=8, R_P=56 | 一手：`halo2_poseidon 0.2.0` |
| 树深度 / 容量 | `4` / `16` | — |
| 事件批次上限 | 2 grant + 1 revoke，`max_event_count=3` | — |
| `k` | 目标 `13`，若约束超限上调到 `14`，须更新 `CircuitSpec.k` 并重算 `D_circuit` | 已计入身份，变更有据可查 |
| `field_from_bytes` 口径 | 双 SHA-256 拼 64B + `from_uniform_bytes` | 不改，保持与 D3-01 一致 |
| 哈希到域安全裕度 | 64B ≥ 48B（`ceil((255+128)/8)`） | 满足 `ff` 要求 |

---

## 7. 负向测试（本规范对应的拒绝点）

| 测试 | 攻击 | 拒绝组件 | 层级 |
| --- | --- | --- | --- |
| N-01 | 在 CircuitSpec 工件里塞入 `policy_id` 值后再算 `D_circuit` | 自检规则 R2-01-C1 / C2（工件结构校验） | 构建期检查 |
| N-02 | 修改 `policy_parameters` 任一字节 | `policy_id` 变化 → 电路 `policy_id==const` gate 失败 + 注册表不符 | MockProver + VK 注册表 |
| N-03 | DirectOnly 工件声称 Cascade（`strategy_flag` 与 `circuit_label` 不一致） | `D_circuit` 与声明不符 → 注册表拒绝 | VK 注册表 / 网关 |
| N-04 | 用旧 `D_circuit` 但新 vk | 注册表 `D_circuit` 字段不符 | VK 注册表 / 网关 |
| N-05 | 把 `vk_hash` 塞进 `policy_id` preimage | 实现违反本规范；电路常量与注册表 `policy_id` 不符 | 构建期检查 + 网关 |

对应 R2-05 测试矩阵的 T05（改 policy_id）、T06（VK 映射错误）、T14（跨策略重放）。

---

## 8. 本规范不能声称的内容

- **不能**声称"policy_id 在电路内证明电路实现了对应规则"——电路 gate 只锁常量相等；
  "常量对应的 CircuitSpec 真的编译成这把 vk"由注册表 + 审计保证，是外部信任。
- **不能**声称 `vk_hash` 进电路——它是验证器元数据，不进 Halo2 instance。
- **不能**声称 D3 与 D2-A 的策略在电路内统一——域标签 `D3-*` (SHA-256) 与
  `D2A-label-v1` (BLAKE2b) 不一致，只有网关配置绑定（R1-03 §4）。
- **不能**把 `k`、`max_event_count` 等参数当 finalized 实现——它们是冻结目标值，
  D3-03 若因约束超限调整，必须走 §6 的版本变更流程，不得静默改。
