# RELATED-WORK.md — D3-16-01 相关工作对照

日期：2026-11-25
用途：按文献类型逐篇记录本轮核查过的最接近工作；给出原文明确贡献、作者自述限制、与候选池的重叠程度。完整 URL 与直引索引见 `SOURCES.md`。

---

## 类型分布说明

本轮核查 31 项来源（S1–S31），类型分布：
- **peer-reviewed（顶会/顶刊）**：S5 zkFuzz（S&P 2026）、S9 MegaZK（ICS'26）、S11 MicroNova（S&P 2025）、S12 Interstellar（PKC 2026）、S17 TensorZKP（USENIX Sec 2026）、S18 Celer（CRYPTO 2026）；另 EXCLUSION-MAP 中的 CVA（Frontiers 2026-09-24）。
- **arXiv preprint**：S2、S10、S13、S14、S15、S16、S19、S20、S21、S25、S26、S28、S29、S30（含已撤稿 S31 RECPIR、S6 zkCraft）。
- **IACR ePrint**：S3 zkRAG、S4 VERIF、S7 VeriRAG、S8 ZKPoG、S27 SoK VFL。
- **Internet-Draft（个人/非 RFC）**：S1 draft-zhang-ioa-usage-accounting-01。
- **implementation artifact**：S24 FlashProve（Anthropic 官方，not maintained）。
- **行业 artifact / 指南（非论文）**：S22 MCP 安全工具与博客、S23 OWASP Agentic Top 10。

---

## A 类相关（ZK 工程与一致性）

### S8–S10 · GPU 端到端加速与瓶颈（A1 最强基线）
- **原文贡献**：ZKPoG 把 witness 生成纳入 GPU 端到端加速并优化内存以适配有限显存（22.8× vs CPU / 12.7× vs GPU）；MegaZK 进一步降 GPU 内存 80.9%（37.4×/24.3×/6.1× vs CPU/GPU/ASIC）；arXiv 2611.09569 专门分析 GPU 并行度与内存管理的 trade-off，指向多 GPU/RDMA。
- **作者自述限制**：依赖 RTX 4090 / 自定义门编译器 / Plonkish+FRI / 独占 H100；*"ZKP workloads often span tens of gigabytes"*，幂次规模使内存翻倍。
- **与候选重叠**：三者都报**端到端倍数**，不做 Halo2 CPU 侧分阶段 RSS 归因。A1 的差异点（stage-level 剖面）未被覆盖；但它们构成 A1 必须对比的强基线。A3 的递归 Pareto 与之无关（不同维度）。

### S11–S12 · Folding / 递归（A3 基线）
- **原文贡献**：MicroNova（S&P 2025）folding prover 相对 Nova 开销极小、≈2.2M gas，需复用 KZG SRS 通用可信设置；Interstellar（PKC 2026）GKR 协作 folding，每层 1.59×–6.74× prover 加速、MiMC 链最高 2.93×。
- **作者自述限制**：MicroNova 依赖通用可信设置；Interstellar 是 GKR + circuit interpolation 栈，非 Halo2/Pallas。
- **与候选重叠**：两者解决"folding 方案级效率"，未回答固定内存预算下 Halo2 递归深度拐点。A3 差异成立但贡献偏测量；拥挤度高。

### S13–S16 · 电路/规格一致性（A2 基线）
- **S13 ZIVER**（ePrint 2025/2204）：*"witness-generation code is consistent with these constraints... major source of subtle and hard-to-detect bugs"*，*"without expanding the full circuit"*；仅验证 SP1 chip。**占住 witness-vs-约束格**。
- **S14 综述**（arXiv 2607.23752）：*"most target Circom"*；隔离目标检出 45.7%，完整代码库降到 19.6%；*"focuses primarily on constraint correctness"*。**指出规格本身/全代码库/非 Circom 为稀疏处**——A2 的原文依据。
- **S15**（arXiv 2605.15163）：Lean 中 bitvector/有限域等价证明，多解 19% arithmetization benchmark；限转换/不等式 tactic。
- **S16 ZK-CEC**（arXiv 2601.11173）：面向硬件 IP 的隐私保护形式验证，*"existing ZK protocols for formal verification are designed to prove statements of public formulas"*，秘密公式场景需防恶意 prover 伪造公式；验证 AES S-Box。**场景是硬件 IP，与 ZK gadget 规格不同**。
- **与候选重叠**：A2 的 spec-first 差分与 S13（witness-vs-约束）、S16（硬件 IP 秘密规格）均不同；但 S15 的形式化等价与 S14 的稀疏处说明窗口窄。**A2 最大风险是规格 oracle 从何而来**——这与 D3-15"root 真实性"同构，需在深度审计中优先证伪。

### S5–S6 · 电路 fuzz（排除项 8）
- **S5 zkFuzz**（**S&P 2026**）：TCCT 统一 under-/over-constrained，452 Circom 电路 85 bugs（59 zero-day，39 确认修复），开源。
- **S6 zkCraft**（arXiv 2602.00667）：R1CS-aware 定位 + Row-Vortex + Violation IOP + LLM 变异；**已撤稿**，管理员注明作者被未经同意添加。
- **与候选重叠**：A2 若退化成"TCCT + LLM 变异"即落入排除项 8。B/C 类无重叠。

### S17–S18 · ZK 原语与硬件加速（A 类拥挤度）
- S17 TensorZKP（USENIX Sec 2026）：首个 GPU Tensor Core 加速 ZKP，HyperPlonk + Brakedown。
- S18 Celer（CRYPTO 2026）：查询规模 >> 表规模的 lookup，25.9× vs plookup、9.4× vs LogUp。
- **与候选重叠**：均属"换硬件后端/换原语"，A1/A3 不与其正面竞争，但若候选贡献只写"更快"则被这些工作淹没。

---

## B 类相关（Agent 系统安全）

### S19–S21、S23 · 记忆污染（B2 基线，高密度）
- **S19**（arXiv 2606.04329）：四类写入通道（显式指令/系统提示驱动/压缩驱动/经验到程序）、九类结构漏洞、六类攻击 taxonomy、MPBench；*"existing prompt injection defenses fail to cover memory poisoning"*。
- **S20 Sleeper Attack**（arXiv 2605.28201）：1,896 实例、三状态目标（会话上下文/记忆/可复用技能），跨交互潜伏后由良性查询激活。
- **S21 Aegis**（arXiv 2608.21230，[二手]结构化摘要）：shipped provenance 权重 p=.80 与无防御无差异；更强权重使正确证据 recall 99.17%→0%；**bounded occupancy 仅提案未实现**；缺"相同 evidence budget 下实现 bounded occupancy"的对照。
- **S23 OWASP Agentic Top 10 2026**：ASI-06 记忆与上下文污染（行业指南，非论文）。
- **与候选重叠**：B2 直接瞄准 S21 的未实现机制与缺失对照——差异**有原文依据但窗口极窄**。FARMA（2607.05029，[二手]）伪造推理痕迹、TRACE-Memory（2608.08446，[二手]）增量准入，进一步压缩空间。B2 为备选而非优先。

### S22 · MCP 工具描述安全（B1 基线，学术稀疏）
- **原文（实为 artifacts/指南）**：alyria/nhimng/secagentlabs/shrike 等一致描述 poisoning、rug pull、shadowing、cross-server chaining；对策为 hash-pin + 每次调用重验（TOFU）、digest pinning、扫描器、re-approval。*"native MCP support: ✗ none — no re-approval on change"*；*"You cannot stop a server from lying in its description. You can make sure the lie does not have the authority to do anything."*
- **作者自述限制**：pin 机制依赖首次见到的定义可信；"扫描只是 tripwire 不是 guarantee"（S22, nhimg）。
- **与候选重叠**：B1 的差异是**密码学可验证绑定 + 跨服务器组合语义**，而非又一层 hash-pin；但 S22 全为 artifact/指南，无顶会论文支撑问题定义 → 学术新颖性证据弱，列备选。

---

## C 类相关（密码学 × AI）

### S24 FlashProve（C1/C2 基石）
- **原文（官方 artifact）**：*"FlashProve lets an AI provider prove which model answered a request, without revealing the model's weights"*；Llama 4 Maverick / H100 / 1024 token；"The protocol's soundness is proved in Lean 4"；but README 要求 *"get [the commitment ID] from a party your user trusts, never from the server being checked"*。
- **原文自述限制（known-limits.md）**：*"A yes does not say whose weights they are, that the shipped committer made the commitment, or which real model it is."*；*"A new commitment has a new ID, and no proof links the two."*；*"The C++ verifier and the CUDA prover are written to follow the same protocol and are tested against it, not themselves proved."*；*"nothing is proved for the programs."*
- **与候选重叠**：**C1/C2 的差异直接来自官方自述空白**，不靠我们推测——这是本轮最强候选依据。S24 不是同行评审论文且 not maintained，需在深度审计中核实协议细节与可引用性，但不影响"空白确实存在"这一事实。

### S25–S27 · 可验证 ML / FL（C1/C2 基线）
- **S25 ZKPROV**（arXiv 2506.20915）：HyperNova+KZG+BLS 绑定数据集-权重-回复，8B 3.3s（作者报告）；来源外包给权威签名数据集，**不覆盖权重版本**。
- **S26 SAG**（arXiv 2508.01084）：全加密 RAG + 形式化 confidentiality/integrity、抗投毒；证存储完整，不绑定外部真值。
- **S27 SoK VFL**（ePrint 2025/2292）：系统化 VC/ZKP 的"计算正确"，Sybil/串通仍开放。
- **与候选重叠**：三者都停在"计算正确/存储完整"，C1（谱系）与 C2（来源锚定）是它们未覆盖的关系；本次差异有原文支持。

### S28–S31 · PIR / 私密检索（C 类部署基线）
- **S28 P²RAG**（arXiv 2603.14778）：两方秘密共享、二分免排序、任意 top-k，比 PRAG 快 3–300×；开放：半诚实不串通假设、大 k 验证开销。
- **S29 PIR-RAG**（arXiv 2509.21325）：聚类+格 PIR 整簇取回，RAG-Ready Latency；[二手]无可靠代码。
- **S30 VeLoPIR**（arXiv 2506.12761）：TFHE 位置 PIR，11.55× 加速，代码开源。
- **S31 RECPIR**（ePrint 2025/756）：**已撤稿（2025-12-06）**，不作为基线。
- **与候选重叠**：本轮未把"PIR 响应新鲜度"单列为候选（原因：与 D3-15"root 真实"同构，且查询隐私下的 freshness 需真实数据源，落入 EXCLUSION-MAP §3 准入规则）。记录于此供后续查档。

---

## 三类拥挤度横向对照

| 类别 | 顶会/顶刊基线数（本轮核查） | 预印本/草案/artifact | 候选差异是否有原文自述空白 | 整体拥挤度 |
|---|---|---|---|---|
| A · ZK 工程 | 6（S5/S9/S11/S12/S17/S18） | 7 | A1 有（端到端倍数外无归因）；A2 有（S14 综述明说）；A3 部分 | 中—高 |
| B · Agent 安全 | 0（本轮核查范围内） | S19–S23 密集 | B1 有（无顶会问题定义）；B2 有（S21 未实现机制）但窗口窄 | 高（学术形式化稀疏） |
| C · 密码学 × AI | 0（本轮核查范围内） | S24–S30 | C1/C2 有（FlashProve 官方自述） | 低—中（C1 最低） |
