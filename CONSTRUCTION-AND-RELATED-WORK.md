# D3-12 强基线对照、文献证伪与最小候选评估

日期：2026-11-24｜对应任务包 Phase 4–5

说明：本轮只围绕 H1/H2 做文献核查，不重新泛化搜索 Agent 安全。证据等级严格分离，不把二级来源写成原文事实。

---

## 1. 强基线逐篇核查（每项回答四问：原文证什么/信任假设/是否覆盖/缺什么）

### 1.1 SCITT AEE draft -02（`FULL-TEXT`，§6.7.3/§9/§9.2/§10/§11）

- **原文证明什么**：`call_digest` = 双方对同一请求表示计算的摘要（§6.7.3），linked verification 验证两条回执"commit to the same request ... for the same Principal, transaction and Actor Chain"（§9.2）；`principal_link` = "a digest of a token both already hold"，实现"show that they recorded the same Principal **without either revealing it**"（§10）。
- **信任假设**：双方各自验证并签名（"parties each of which verified on its own"）；TS append-only；内容不入回执。
- **是否覆盖**：**覆盖了方向 A 的核心**——"双方独立签名、第三方不集中披露即可确认同一次调用关联"。`principal_link` 已实现"隐藏的 Principal 关联"。
- **缺什么**：不证 Harness 每次记录（§11 Omission）、同 host 多服务、代理改写部分、事件真实（§9.2）。**但这些都不是 H1/H2 的 ZKP 增量——它们是外部信任基问题（D3-11 已定）。**

### 1.2 SCITT AI Agent Execution Profile -01（`FULL-TEXT`，D3-11 核验复用，§11/§12）

- **原文证明什么**：独立 Custodian + 签名 + 哈希链；sequence gap 检测"产生未注册"；redaction receipt。
- **信任假设**：TS 与 Issuer 结构独立且诚实；"An action that was never recorded leaves no gap"（§11.5）；两方串谋是"fundamental limitation of any two-party evidence system"（§11.8）。
- **是否覆盖**：custody/隐私/collusion 边界已定。
- **缺什么**：未记录操作、元数据泄漏（§12：agent_id/timestamp/sequence 可见）——靠访问控制，非 ZKP。

### 1.3 RFC 9901 — Selective Disclosure for JWT（`FULL-TEXT`，本轮原始规范逐字核对）

- **原文证明什么**：salted hash 选择性披露；"SD-JWT only conceals the value of claims that are not revealed. It does not meet the security properties for anonymous credentials [CL01]. In particular, **colluding Verifiers and Issuers can know when they have seen the same credential** no matter what fields have been disclosed"；batch issuance 缓解 Verifier/Verifier 链接，"but **cannot work for Issuer/Verifier unlinkability**"。
- **信任假设**：issuer 签名可信；披露字段不含可识别信息。
- **是否覆盖**：覆盖了"选择性披露部分字段"这一更简替代；**明确未声明支持对隐藏值证明谓词**（本轮核查范围内）。
- **缺什么**：合谋可链接；无谓词证明——这构成 ZKP 可能的空间，但该空间要成立需跨双签发方锚定（H2）。

### 1.4 匿名凭证 / BBS（`INFERENCE`，二级来源，未抓规范原文）

- W3C Data Integrity BBS Cryptosuites v1.0 提供 unlinkable presentation（多次呈现不可关联）；SD-JWT VC 仍为 draft；批量单次凭证是普遍缓解。
- **证据等级诚实标注**：以上来自厂商博客/技术雷达，**未独立核对规范原文**，仅作"存在更简替代"的方向性提示，不作为本轮裁决的硬证据。
- **与方向 A 关系**：若 BBS/匿名凭证能对单签发方做谓词证明 + unlinkable，则 H1-C 的窄增量也有更简替代——但本轮未取得规范原文，故**不据此单独否证**。裁决不依赖此条。

### 1.5 Chaum & Pedersen 1993 / ePrint 2016/771 / D3-07-B §5.1（`PRIMARY-EXCERPT` + 本项目 `FULL-TEXT`）

- **Chaum-Pedersen [CP93]**：证明 `log_g x = log_h y` 的三步 sigma 协议（special soundness + special HVZK），1993 年成熟构造——**ZK equality proof 是已知原语**。
- **ePrint 2016/771**：明确证明者若能自造公开输入 X，"this proof is not sound anymore"——H2-A 的经典对应。
- **D3-07-B §5.1（本项目冻结）**：private-only 下证明者自造字段重算哈希，验证者无法区分；导出 `STOP_HALO2_DIRECTION`。
- **结论**："证两个隐藏值相等"既不是新原语，也在无外部锚定时不成立。H2 失败有原文 + 本项目双重证据。

### 1.6 D3-08 / D3-09 / D3-10（`FULL-TEXT`，复用）

- D3-08：匿名可委托凭证已覆盖委托/撤销/隐私（PKC2011、IPSJ2022）——"隐藏授权关系"非新。
- D3-09：zkAgent 证忠实执行不证合规；PoE 明文+单 Gateway；CVA runtime binding structural gap。
- D3-10：IVC+Accumulator+Range 组合满足 P1/P2/P3 但全部 `BLOCKED_WITH_ASSUMPTION`；递归证明 ≠ 外部历史完整。

---

## 2. 差异表：候选构造 vs 现有工作

| 性质 | 明文 SCITT + 访问控制 | 选择性披露 RFC 9901 | 匿名凭证/BBS | 通用 ZKP（方向 A 候选） | 新增？ |
|---|---|---|---|---|---|
| 内容不入回执 | ✅（No content） | ✅ | ✅ | ✅ | 无（已有） |
| 跨方同调用关联 | ✅（call_digest 盲比对） | 不直接适用 | 不直接适用 | ✅（证承诺相等） | 无（已有，D3-11 E3） |
| 隐藏 Principal 且可关联 | ✅（pepper hash + token digest） | 部分（合谋可链接） | ✅（unlinkable） | ✅ | 无（已有/有更简替代） |
| 隐藏字段的合规谓词证明 | ❌ | ❌（未声明） | ✅（`INFERENCE`，仅单签发方） | ✅（跨双签发方需 H2） | **唯一候选，但 H2 未过** |
| 事件真实 / 无遗漏 / 最新 | ❌（外部信任基） | ❌ | ❌ | ❌（ZKP 不提供） | 非 ZKP 目标 |
| 验证成本 | 最低 | 低 | 中 | 高（NOT_MEASURED） | ZKP 最差 |

**结论**：候选 ZKP 相对现有工作的唯一新增是"跨双独立签发方的隐藏字段合规谓词证明"，但它 (a) 依赖 H2 锚定而 H2 失败，(b) 单签发方版本已有匿名凭证更简替代（`INFERENCE`），(c) SCITT 回执无值承诺可供谓词证明。

---

## 3. 最小形式化候选评估（Phase 5，条件性）

任务包要求"仅在 H1/H2 均有通过迹象时才提出最小构造"。**本轮 H1_FAIL + H2_FAIL，条件不满足——不提出最小构造。** 但为完整记录，说明为何即使强行构造也不能成立：

若强行写"双方签承诺 + ZKP equality + VDS 锚定"的关系：
- 参与方/密钥：A、B 各有签名密钥；C 为验证者。
- 回执结构：`r = (Com(cd), Sig_party(Com(cd)), VDS_inclusion)`——**已偏离 SCITT 现有回执格式**。
- Public Inputs：`Com_A, Com_B, Sig_A, Sig_B, VDS_root, inclusion_proofs`。
- Private Witness：`cd, ρ_A, ρ_B`。
- 验证关系：`Verify(Sig_A, Com_A) ∧ Verify(Sig_B, Com_B) ∧ inclusion(VDS, Com_A) ∧ inclusion(VDS, Com_B) ∧ Open(Com_A, cd, ρ_A) ∧ Open(Com_B, cd, ρ_B) ∧ Dec(P, cd)=1`。
- **为何仍不能成立**：
  1. `Dec(P, cd)` 中 `cd` 是请求摘要，不是可证谓词的值——需额外值承诺（SCITT 无）。
  2. VDS inclusion proof 通常对已注册回执（含 cd 明文），拿 inclusion proof 即见 cd 明文——隐藏失效（verifiability ↔ privacy 张力）。
  3. freshness/completeness 仍外包，不是该关系能保证的。
  4. 该关系本质是"已知 commit-and-prove + equality proof + 标准验签 + VDS"的组合，不是新证明关系（D3-08/09/10 的多轮裁决标准）。

因此**不进入原型**。

---

## 4. 证据等级总表（本轮新增）

| 来源 | 等级 | 用途 |
|---|---|---|
| SCITT AEE -02 §6.7.3/§9/§9.2/§10/§11 | `FULL-TEXT` | H1/H2 主证据 |
| SCITT Profile -01 §11/§12 | `FULL-TEXT`（复用） | custody/privacy/collusion |
| RFC 9901 | `FULL-TEXT` | 更简替代判定 |
| Chaum-Pedersen [CP93] / ePrint 2016/771 | `PRIMARY-EXCERPT` | equality proof 已知 + 自造不 sound |
| BBS/W3C cryptosuite | `INFERENCE`（二级） | 更简替代方向提示，不作硬证据 |
| D3-07-B §5.1 / D3-08/09/10 | `FULL-TEXT`（复用） | private-only 反例 / 覆盖边界 |
| 所有性能数字 | `AUTHOR-CLAIM` | 未复现 |

## 5. 本阶段结论

两道门禁的文献证据一致指向：方向 A 的关联内核（盲摘要比对、`principal_link` token digest）已是 SCITT 现成构造；隐私泄露由明文设计的 pepper/epoch roots/data minimization 与标准选择性披露（RFC 9901）覆盖；ZKP 的窄增量依赖 H2 锚定，而 equality proof 是 1993 已知原语且无外部锚定时不成立（ePrint 2016/771 + D3-07-B §5.1）。**没有经得起强基线检验的新证明关系。**
