# EXP-D3-02-06 — 定向相关工作核查

**范围**：只核查与"选哪条构造"直接相关的五类工作，不做泛化调研。
**核查标准**：每项区分四层——
① 论文实际提出了什么；② 代码仓库实际实现了什么；③ 我们打算采用什么；④ 哪些只是推测。
所有论文均给出标题、作者、年份、链接与**具体支持的结论**，不引用搜索摘要作为唯一依据。

---

## 1. Halo2 / plookup / Poseidon 实现

### 1.1 Halo（递归的理论基础）

- **文献**：Sean Bowe, Jack Grigg, Daira Hopwood. *Recursive Proof Composition without a Trusted Setup*. Cryptology ePrint Archive, Paper 2019/1021, 2019（2020-02 最后修订）。https://eprint.iacr.org/2019/1021
- **论文实际提出**：首个无需 trusted setup 的实用递归证明组合；用普通椭圆曲线 cycle 上的离散对数假设；核心贡献是把多个 IPA 验证的昂贵部分摊还（amortize）到递归电路中。
- **代码实际实现**：`zcash/halo2` 实现了 Halo2（IPA + Pasta cycle）；本仓 D2-A 使用 `halo2_proofs 0.4.0` 实际生成/验证了 Pallas 电路 proof。
- **我们采用**：Pallas base field + Vesta 承诺 + IPA，作为 C 路线的**理论可行性**依据；第一版 A 不使用递归。
- **推测部分**：halo2 book 的 `background/recursion` 章节描述 accumulation 与 deferred checks（https://zcash.github.io/halo2/background/recursion.html；本环境直连失败，仅通过镜像摘要核对，故不作为一手依据）。**本仓没有任何 in-circuit verifier 代码，不能声称递归已可用。**

### 1.2 Poseidon

- **文献**：Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, Markus Schofnegger. *Poseidon: A New Hash Function for Zero-Knowledge Proof Systems*. ePrint 2019/458（USENIX Security '21 版本）。https://eprint.iacr.org/2019/458
- **论文实际提出**：域上原生哈希；每消息位约束数比 Pedersen Hash 少最多 8×；用 Bulletproofs 实现十亿分之一规模的 Merkle membership proof，耗时 < 1 秒。
- **代码实际实现**（一手源码）：
  - `halo2_poseidon 0.2.0 / src/p128pow5t3.rs`：`P128Pow5T3` width 3 / rate 2，`R_F = 8`，`R_P = 56`。
  - `halo2_gadgets 0.6.0 / src/poseidon/pow5.rs`：每置换 36 行（4 全轮 + 28 个"双半轮"行 + 4 全轮），136 条约束/置换，每 absorb 行 3 条。
- **我们采用**：D3-01 已用该参数做 GR/RR 根；本设计沿用同一 Poseidon 与 `D3-` 域标签，成本估算直接来自上述源码，不虚构数字。
- **推测部分**：Poseidon 的安全裕度随参数与攻击进展变化；本设计只使用论文/库给定的标准参数，未做独立密码分析。

### 1.3 plookup

- **文献**：Ariel Gabizon, Zachary J. Williamson. *plookup: A simplified polynomial protocol for lookup tables*. ePrint 2020/315, 2020. https://eprint.iacr.org/2020/315
- **论文实际提出**：用 3 个辅助多项式承诺实现 lookup 检查，支持 batched range proof。
- **代码实际实现**：halo2 生态普遍提供 8-bit range check 表（`halo2_gadgets::utilities`）。
- **我们采用**：scope 字节分解、epoch u64 比较、type 二值检查都用 8-bit 查找表（见 `d3_02_circuit_spec.md` §2）。
- **推测部分**：未实测查找表对整体约束数的节省比例。

---

## 2. Merkle 多点更新证明

### 2.1 Reckle Trees

- **文献**：Charalampos Papamanthou, Shravan Srinivasan, Nicolas Gailly, Ismael Hishon-Rezaizadeh, Andrus Salumets, Stjepan Golemac. *Reckle Trees: Updatable Merkle Batch Proofs with Applications*. ACM CCS 2024, ePrint 2024/493. https://eprint.iacr.org/2024/493
- **论文实际提出**：基于递归论证的向量承诺，支持**可更新的简洁 Merkle batch proof**；用 canonical hashing 把 batch hash 嵌入递归 Merkle 验证；叶子变化时证明可按对数时间更新；Plonky2 实测更新快 10×–15×、验证快 4.78×–1485×；包含"动态摘要转换"（Poseidon ↔ Keccak Merkle 摘要等价证明）与可更新 BLS 聚合两个应用。
- **代码实际实现**：论文给出 Plonky2 实现与评估；本仓未引入该依赖。
- **我们采用**：作为**方案 B/C 的后续方向**与"SHA-256 ↔ Poseidon 摘要桥接"的已知技术路径（对应 `d3_02_public_statement.md` §3.1 的开放问题）。第一版不采用：它需要递归 SNARK 基础设施。
- **推测部分**：Reckle Trees 的 batch proof 是否能在我们的"部分撤销 + 多授权来源 + 隐藏历史"场景下保持更新优势，论文没有覆盖，属于推测。
- **明确不覆盖**：论文证明的是"批次叶子集合与 Merkle 根一致"，**不**证明授权语义（scope/issuer/revoke 权限），也不证明外部最新状态绑定。不能因为"已有 Merkle 更新证明"就判定本场景无空间。

### 2.2 Verdict / 透明字典

- **文献**：Ioanna Tzialla, Abhiram Kothapalli, Bryan Parno, Srinath Setty. *Transparency Dictionaries with Succinct Proofs of Correct Operation*. NDSS 2022, ePrint 2021/1263. https://eprint.iacr.org/2021/1263
- **论文实际提出**：Verdict 透明字典，对不可信服务的 label-value map 读与授权更新给出可公开验证证明；indexed Merkle tree（支持非成员证明）+ Phalanx folding SNARK（amortized constant-size proofs）；评估规模到百万级 label。第三方综述（Lacuna 论文页）记录约 651 字节更新证明、~3 ms 客户端验证、百万 label 下约 4 更新/秒/核——**这些数字来自第三方解读，非论文摘要，本设计不据此做估算**。
- **论文摘要明确支持的结论**：可公开验证的读/授权更新证明 + 适度证明开销；百万级 label 可扩展。
- **代码实际实现**：论文有实现与评估；本仓未使用。
- **我们采用**：其"把应用特定逻辑从 SNARK 中解耦、由客户端验证 hashchain"的思路，支持我们在 `d3_02_public_statement.md` 中把"历史完整性"外置到日志、电路只证语义的分层决定。
- **推测部分**：Verdict 的 indexed Merkle tree 能否直接承载我们的 `grant_id → 规范槽位` 映射并保留 D3-01 的插入序无关性，尚未验证。
- **明确不覆盖**：Verdict 证明 map 操作的正确性，不证明多授权来源的委托链、部分撤销或隐藏授权历史。

---

## 3. 递归 SNARK 与 Halo2 递归验证

### 3.1 Nova

- **文献**：Abhiram Kothapalli, Srinath Setty, Ioanna Tzialla. *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes*. CRYPTO 2022, ePrint 2021/370. https://eprint.iacr.org/2021/370
- **论文实际提出**：用 folding scheme 代替 SNARK 实现 IVC；递归开销为常数且主要是两个电路内标量乘；证明工作由两次 O(|F|) 多指数主导；proof 为 O(|F|) 群元素（可用 zkSNARK 压到 O(log|F|)）；无需 trusted setup 与 FFT。
- **代码实际实现**：Nova 有独立实现（非本栈）；halo2 0.4 的递归 verifier 本仓没有。
- **我们采用**：作为 C 路线"长历史增量"的已知技术方向；不实现。
- **推测部分**：能否在 Pallas/Vesta cycle 上把 Nova 式 folding 与我们的 Poseidon 状态语句组合，属未来研究。
- **明确不覆盖**：Nova 证明通用 IVC 执行，不定义授权规则，不处理外部 checkpoint 最新性。

### 3.2 Halo2 递归验证的可得性

- **结论**：理论上 Halo（§1.1）与 Nova（§3.1）都支持递归；本栈具备 curve cycle 条件（D2-A 已用 Pallas/Vesta）。**但本仓没有 in-circuit verifier 代码，也没有实测。**
- 因此 `d3_02_construction_comparison.md` §4.3 把递归开销记为 **UNKNOWN**，而不是编造数字。
- 对 `n ≤ 3` 的原型，递归开销必然大于单批 A，这是结构性判断，不需实测。

---

## 4. 隐私保护授权撤销

### 4.1 IRAC（匿名凭证中的撤销新鲜性）

- **文献**：Bin Xie, Rui Song, Xuyuan Cai. *Achieving Flexible and Secure Authentication with Strong Privacy in Decentralized Networks*. arXiv:2512.20234（2025-12-23 提交，**预印本，未经同行评审**）. https://arxiv.org/abs/2512.20234
- **论文实际提出**：issuer-hiding 且可撤销的匿名凭证 IRAC；用有序撤销列表 + 向量承诺证明"凭证哈希落在相邻两项之间"以证明未撤销；文中指出先前的非撤销见证在凭证随后被撤销后仍然有效（该具体表述来自 PDF 正文片段，摘要未逐字包含）；present 约 1 秒（作者自评）。
- **代码实际实现**：论文自评实现；本仓未采用。
- **我们采用**：只采用其**问题定义**——"非撤销证明是时间相关的，撤销后旧见证必须失效"——直接支撑 `d3_02_security_analysis.md` §2 的 freshness 分析与 fencing 方案。不采用其凭证方案。
- **推测部分**：其列表间隙证明是否能与本设计的 GR/RR 双树共存，未验证。
- **明确不覆盖**：IRAC 解决凭证持有者的 issuer 隐藏与未撤销证明，不证明授权**状态转换**语义，也不绑定外部 checkpoint 最新性。

### 4.2 本仓 D2-A 的撤销处理（一手源码）

- `agent-authz-halo2-exp / src/circuit.rs` 的 R1 修复：`not-revoked` 专用列 + selector + gate，
  使 `revoked=0` 成为电路约束而非 witness 假设；T13/T14 验证撤销路径无法产生通过验证的 proof。
- **我们采用**：直接作为本规格 §2.3/§2.6 的 `valid_flag` / `s_not_revoked` 设计依据。
- **边界**：D2-A 证明 ALLOW，不证明 DENY；本轮继承这一边界。

---

## 5. 事件日志完整性与状态转换证明

### 5.1 RFC 6962 Certificate Transparency

- **文献**：B. Laurie, A. Langley, E. Kasper. *Certificate Transparency*. RFC 6962, June 2013. https://www.rfc-editor.org/rfc/rfc6962 （已由 RFC 9162 取代）
- **标准实际定义**：二叉 Merkle Hash Tree、Merkle audit path（inclusion proof）、
  consistency proof（证明旧树是新树前缀，即 append-only）、Signed Tree Head（含 tree_size 与 sha256_root_hash）、MMD。
- **代码实际实现**：本仓 D1-E （`authorization-state-trust-exp`）已实现 RFC6962 Merkle 与
  inclusion/consistency 验证；D2-B 在其上做 checkpoint adapter 与 3-of-4 quorum QC。
- **我们采用**：把历史完整性整体交给这一层；电路只接收由此产生的 `C_prev` 与 `D_E`。
- **推测部分**：QC 与日志的组合能否抵御 quorum 合谋不属于本研究范围（D1-E 已声明）。
- **明确不覆盖**：CT 保证 append-only 与包含性，不保证条目内容语义合法，也不保证条目是"全部真实事件"。

### 5.2 本仓 D3-01（状态转换规范来源）

- `authz-history-semantic-binding-exp / src/{history,state,reference_model}.rs`：
  A 全量重放 / B 增量 / C 独立参考模型三路径；D3-11/D3-12 证明"摘要相等 ≠ 语义合法"。
- **我们采用**：全部规则、编码、域标签与固定向量作为电路的规范来源；不改冻结实现。
- **明确不覆盖**：D3-01 没有 ZKP、没有 DENY 证明、没有真实外部历史认证源（其 README 与
  `results/experiment_report.md` §8 已诚实记录）。

---

## 6. 综合判断：现有工作没有覆盖的组合

下表回答任务书要求的"不能因为某工作实现了递归或 Merkle 更新就认定本场景无空间"：

| 已有工作覆盖了 | 尚未覆盖（对本场景关键） |
| --- | --- |
| 无 trusted setup 的递归组合（Halo/Nova） | 多授权来源 + 部分撤销的委托链语义 |
| 可更新的 Merkle batch proof（Reckle/Verdict） | 隐藏授权历史时的语义正确性证明 |
| 域友好哈希与低约束 Merkle membership（Poseidon） | 外部 checkpoint 的**最新性**与执行时 fencing |
| 匿名凭证的非撤销证明（IRAC，预印本） | 状态转换语句与 ALLOW 路径证明的可组合接口 |
| append-only 日志与 consistency proof（RFC 6962） | 日志条目语义与状态根语义的一致性（D3 ↔ D2-A 域标签仍不对齐） |

因此本轮推荐 A 作为第一版，不是因为其他工作"没做过"，而是因为**它们都没有把上述组合
打包成一个可验证语句**。我们真正新增的是：在可信锚定的前后状态之间，证明
`T(S_prev, E) → S_next` 的语义正确性不可伪造；历史完整性与新鲜性继续明确外包。
