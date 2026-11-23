# EXP-D3-02-R1-05 — 定向文献与源码核查（三个接口问题）

**范围**：只核查与本轮三个修订直接相关的三主题，不重做上一轮 Halo2/Poseidon/Nova 基础调研。
**核查标准**：每项写清 ① 原始论文/仓库；② 实际解决什么；③ 没解决什么；④ 对本方案可迁移部分；
⑤ 我们是否真的采用。论文给标题、作者、年份、链接与具体结论，不引用搜索摘要作为唯一依据。

---

## 主题一：SHA-256 与代数哈希（Poseidon）承诺的桥接

### 1.1 Reckle Trees / Reckle+ Trees（dynamic digest translation）

- **原始来源**：Charalampos Papamanthou, Shravan Srinivasan, Nicolas Gailly,
  Ismael Hishon-Rezaizadeh, Andrus Salumets, Stjepan Golemac. *Reckle Trees: Updatable Merkle
  Batch Proofs with Applications*. ACM CCS 2024, DOI 10.1145/3658644.3670354,
  ePrint 2024/493（2024-10-09 修订）. https://eprint.iacr.org/2024/493
- **实际解决什么**（摘要一手原文）：提出基于递归论证（RECursive）+ Merkle 的向量承诺，支持
  **可更新的简洁 Merkle batch proof**；用 canonical hashing 把 batch hash 嵌入递归 Merkle 验证，
  叶子变化时证明可 O(log n) 更新。Reckle+ 的两个应用中，**dynamic digest translation** 明确
  "maintaining a proof of equivalence between Merkle digests computed with different hash
  functions, e.g., one with a SNARK-friendly Poseidon and the other with a SNARK-unfriendly Keccak"。
  Plonky2 实测更新快 10×–15×、验证快 4.78×–1485×。
- **没解决什么**：证明的是"同一批叶子集合在两个哈希下的 Merkle digest 等价"，**不**证明授权语义
  （scope/issuer/revoke 权限）、**不**绑定外部 checkpoint 最新性、**不**保证批次是完整真实历史。
  摘要未给出连接 SHA-256 与 Poseidon 的非递归轻量方案；其实现依赖递归 SNARK 基础设施（Plonky2）。
- **可迁移部分**：如果我们未来要在密码学层面（而非签名信任）证明 D2-B 的 SHA-256 anchor 与
  D3 的 Poseidon 状态承诺对应同一状态，Reckle+ 的 digest translation 是已知技术路径。
- **是否采用**：**第一版不采用**。理由：本栈（halo2 0.4）无 in-circuit verifier（上一轮 §3.2 已核），
  引入递归 SNARK 超出原型范围；第一版用 R1-01 的签名 Bridge 替代，信任代价已明写。列为长期方向。
- **四层区分**：论文提出(✅递归+digest translation) / 代码实现(Plonky2，非本栈) / 我们采用(否，仅长期方向) /
  推测(其 digest translation 能否适用于 SHA-256↔Poseidon 的**单个 anchor digest**而非整棵 Merkle
  digest，摘要未覆盖，属推测)。

### 1.2 本仓 D2-B 的一手实现（bridge 的输入端）

- **来源**：`zk-state-anchor-exp/src/anchor.rs:39-48`（`AuthzStateAnchor::digest`）、
  `src/encoding.rs:121-135`（`bytes_with_len` 4 字节前缀、`domain`）、
  `src/verifier.rs`（quorum 验签、log inclusion、freshness epoch+hash 结构化判定）。
- **实际解决**：提供可认证的 SHA-256 状态锚 `A_e` 与 checkpoint/QC/freshness 验证链。
- **没解决**：不产出 Poseidon 承诺，不提供与电路的接口——这正是 R1-01 要补的桥。
- **可迁移**：其确定性编码（4 字节前缀、`ZK-STATE-ANCHOR-01:D_A` 域标签）是 Bridge 验证
  `A_e = SHA256(encode(s))` 的唯一权威口径，Bridge 必须逐字节复现。
- **是否采用**：✅ 采用其编码与验证结果作为 Bridge 输入。**不改冻结实现**。

### 1.3 本仓 D3-01 的域映射（bridge 的输出端）

- **来源**：`authz-history-semantic-binding-exp/src/encoding.rs:97-102`（`field_from_bytes`：
  双 SHA-256 拼 64B + `FromUniformBytes` 入域）。
- **实际解决**：把任意字节（含 32B SHA-256 摘要）确定性映射到 Pallas base field，规避
  "32B > ~254bit 域模数"边界。
- **没解决**：这个映射**不是** Poseidon，不能当作电路可开承诺的状态承诺——这是上一轮
  public_statement §4 与 circuit_spec §2.11 冲突的根源。
- **是否采用**：✅ 用于 `policy_id` 与 Bridge 域标签常量；❌ **不再**用它映射 `C_prev`
  （`C_prev` 改为 Poseidon of 状态字段，见 R1-01 §0）。

---

## 主题二：Merkle Tree canonical assignment / 局部更新证明

### 2.1 本仓 D3-01-R1 的 canonical_assignment（一手源码）

- **来源**：`authz-history-semantic-binding-exp/src/grant_tree.rs:86-134`（`initial_slot` /
  `canonical_assignment`）、`:243-300`（`try_upsert` displacement）、`src/encoding.rs:42`（`D3-SLOT-v1`）。
- **实际解决**：id→slot 映射成为**id 集合的纯函数**，消除插入序依赖；增量更新只重算 dirty 槽位。
- **没解决**：不提供任何 ZK 证明；规范槽位的 SHA-256 初始计算在电路内昂贵（R1-02 §3.2 估算）。
- **可迁移**：作为 R1-02 方案 A 的"审计者独立重算"规范来源与方案 B 的约束蓝本。
- **是否采用**：✅ 采用；R1-02 §1 的全部规则来自这里。

### 2.2 Verdict / 透明字典（indexed Merkle tree 的非成员证明）

- **原始来源**：Ioanna Tzialla, Abhiram Kothapalli, Bryan Parno, Srinath Setty.
  *Transparency Dictionaries with Succinct Proofs of Correct Operation*. NDSS 2022,
  ePrint 2021/1263. https://eprint.iacr.org/2021/1263 （上一轮 §2.2 已核，本轮不重复数字）。
- **实际解决**：对不可信服务的 label→value map 读写给出可公开验证证明；indexed Merkle tree
  支持**非成员证明**（这是判断"槽位为空/首个空槽"所需的原语）。
- **没解决**：不保证我们 D3-01 的**特定** canonical 规则（D3-SLOT-v1 哈希 + 规范序环形探测）；
  不证明多授权来源委托链、部分撤销、外部最新状态绑定。
- **可迁移**：其"应用逻辑与 SNARK 解耦、客户端验证 hashchain"思想支撑我们把布局规范性外置；
  indexed Merkle 的非成员证明是未来"电路内证首个空槽"的候选原语。
- **是否采用**：部分采用其分层思想；indexed Merkle 原语**第一版不采用**（无现成 halo2 组件，
  且 R1-02 方案 B 已估算过昂贵）。

### 2.3 Reckle Trees 的 updatable batch proof（同 1.1）

- 与主题一为同一论文。其"叶子变化时 batch proof O(log n) 更新"与 R1-02 的"局部 canonicality"
  在**结构上相关**：都试图避免重证整体。但 Reckle 更新的是**证明对象本身**（依赖递归证明的
  可更新结构），不是"只检查局部槽位规范性"；后者需要归纳锚点（R1-02 §4.2），Reckle 没提供这个
  语义锚点。**不因其存在就否定局部方案或全局方案的探索。**

---

## 主题三：ZK 电路版本、策略标识与验证密钥绑定

### 3.1 zkVM 的 PROGRAM_VKEY 模式（一手工程文档）

- **原始来源**：Succinct SP1 文档（经 DNZN Research 技术页转述其机制）：
  "Verification key (PROGRAM_VKEY): A hash that commits to the exact compiled guest. Change one line
  of the guest and the key changes. The on-chain contract stores this key as an immutable and will
  only accept proofs for that program."；"SP1VerifierGateway routes to a versioned verifier contract
  that runs verify(vkey, publicValues, proofBytes)"。https://research.dnzn.dev/technology/zkvm
- **实际解决**：把"证明针对哪个程序"编码进 vkey 哈希，验证端 pin 住 vkey 即 pin 住程序身份。
- **没解决**："A valid proof says nothing about whether the program it pins is correct"——vkey 只
  承诺编译产物，不保证程序语义正确；需要独立审计源码。
- **可迁移**：直接对应 R1-03 的④（vk 注册表绑定策略版本）与"网关 pin 住 vk_hash"。
- **是否采用**：✅ 采用其 vkey-as-identity 模式；但补充"源码审计"由我们的 circuit_spec_digest +
  git sha 承担（对应其"guest 源码需独立审计"的诚实边界）。
- **可信度说明**：该页为第三方技术解读，非 Succinct 官方原文；机制描述与公开的 SP1 设计一致，
  但**本设计不把该页数字当权威**，只采用其 vkey 绑定模式（属于工程共识）。

### 3.2 电路版本化与 verifier registry（一手工程指南 + 论文实践）

- **原始来源**：
  - Chainscore Labs 工程指南：*"Treat every circuit change as a new immutable artifact with a
    versioned circuit ID; Bind the circuit hash into the verifier or public inputs"*；
    *"Route verification through a registry mapping version → verifier"*；
    *"Never silently change arithmetic constraints or gate wiring"*。
    https://chainscorelabs.com/guides/.../how-to-design-upgradeable-zk-snark-systems
  - AZT 论文（Springer, *Discover Computing*, 2026, DOI 10.1007/s44163-026-01882-0）：
    其 zkML 审计系统中 *"the verification key is published through the authority registry"*，
    模型承诺 `C` 是"Merkle root obtained by hashing the fixed-point serialisation of the approved
    parameter vector"，电路内"recomputes the parameter hashes and enforces equality with the public
    root C"，且 key rotation 在 circuit 更新/模型版本变化时触发、撤销通过 registry 标记。
- **实际解决**：电路变更即新 artifact + 版本化 id；注册表映射版本→verifier；参数承诺进 public
  并在电路内重算相等；旧 key 保留供历史审计但不接受新提交。
- **没解决**：AZT 的 `C` 承诺的是模型参数（zkML），不是授权策略规则；没有多策略共存与跨策略
  vk 重放的语义；工程指南非同行评审论文。
- **可迁移**：R1-03 的注册表设计（active/inactive、circuit_spec_digest、git sha）、
  "电路变更必换 id/vk"流程、以及"参数承诺在电路内重算相等"的三号机制（我们仅部分采用）。
- **是否采用**：✅ 注册表与版本化流程采用；⚠️ AZT 式的"完整参数承诺进电路"作为扩展保留，
  第一版不把全部策略参数逐项 gate（理由见 R1-03 §3）。

### 3.3 D2-A 冻结电路的策略标签（一手源码，暴露未解决问题）

- **来源**：`agent-authz-halo2-exp/src/poseidon_hash.rs:18-51`（`label_to_field` BLAKE2b personal
  `D2A-label-v1`）、`src/public_inputs.rs`（`policy_tag`/`epoch`/`request_digest`）、
  `src/model.rs:93`（`label_to_field(policy_version)`）。
- **实际解决**：D2-A 有自己的策略标签 `policy_tag`（域元素），与 request digest 一起作为 instance。
- **没解决**：`D2A-label-v1`（BLAKE2b）与 D3 的 `D3-*` SHA-256 域化**不是同一承诺**；
  两个电路的 GR/RR 根语义不能互认。§3.1 的 vkey 绑定只在各自电路内成立。
- **可迁移**：说明 R1-03 的绑定链必须在**网关层**把 D3 `policy_id` 与 D2-A `policy_tag` 映射到
  同一治理策略（配置绑定，非密码学绑定）。
- **是否采用**：✅ 采用其"策略标签进 instance"的形态；❌ 不声称电路级统一（明确为未解决）。

---

## 4. 综合判断（三个问题各一句）

1. **桥接**：密码学层面的 digest translation 存在（Reckle+，需递归），但本栈无递归 verifier；
   第一版用签名 Bridge（R1-01 A′），信任代价明写，长期再评估密码学桥。
2. **规范槽位**：D3-01-R1 的 canonical_assignment 是唯一规范来源，审计者可链下重算；电路内完整
   验证 ≈5×10⁴ 约束（粗估）不可行；局部 canonicality 是归纳步骤，需可信前布局锚点，本栈无法
   独立提供——第一版外部签名（R1-02 A）。
3. **策略绑定**：vkey-as-identity（SP1）+ 版本化 registry（工程指南/AZT）+ 电路内 policy_id 常量
   gate + 每策略独立 vk，四者组合；最终安全保证在网关注册表（R1-03 ④），电路与 verifier 层
   无法单独防跨 vk 重放（R09）。

**没有任何一项相关工作覆盖"D2-B 外部 anchor + D3 canonical 布局 + 多策略 vk + 隐藏历史 + 执行时
fencing"的组合**；我们采用的技术各自有来源，但组合接口是本轮新增的设计贡献，且边界诚实。
