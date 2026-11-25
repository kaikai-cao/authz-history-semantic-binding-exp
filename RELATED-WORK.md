# D3-17-02 · 相关工作审计

> 每篇记录：发表状态、目标系统、实验规模、内存测量方法、优化机制、是否开源、与 A1 的重叠。
> **关键判据阶梯**（本轮统一口径，避免把「没报某指标」误判为「问题未解决」）：
>
> | 级别 | 含义 |
> |---|---|
> | L1 | 只报端到端 proving time |
> | L2 | 报阶段耗时（stage-level time） |
> | L3 | 报聚合峰值内存（overall / peak RSS / VRAM） |
> | L4 | 报阶段级内存归因（per-stage memory attribution） |
> | L5 | 提出并验证可迁移的内存优化机制 |
>
> A1 原始定义声称的空白是 L4；本轮需要判断该空白是否真实、以及是否足以支撑 L5。

---

## 1. 直接基线（与 A1 重叠最高）

### S1 · Infrastructure for Verifiable AI: Where Proof Costs Go and How Hardware Can Help

- **类型 / 状态**：arXiv preprint `2611.17042v1`，2026-11-12，16 页 / 8 图 / 5 表。深圳大学。**非同行评审**。
- **目标系统**：可验证 AI（推理 / LoRA 微调 / 训练审计 / DP 证明），四层框架（workload → proof system → kernel → hardware）。
- **实验规模**：六个 prover（zkLLM、DeepProve、VeriLoRA、VeriDP、Expander、ZKTorch），七个 kernel；7B/13B 模型，输入长度 64–2048；40 GB / 80 GB A100，含 CPU-only 单元。
- **内存测量方法**：§IV-A `"For each cell we record prover time and its breakdown, peak GPU and host memory, proof size, verifier time..."`。§IV-C 13B LoRA：`"45.0 GB by the prover's own account (56.2 GB sampled externally)"`。**采样工具、采样间隔、allocated vs reserved 区分均未披露。**
- **成本归因粒度**：§IV-A 明确把 timed region 映射到八个**时间**类别（witness generation / sumcheck / lookup / commitment / opening / hashing-encoding / data movement / other）；`"Regions that cannot be split without modifying the code are reported as mixed rather than apportioned by guesswork."`。Table IV 的内存列只有 `GPU pk (GB) / host pk (GB)` **每行一个聚合值**。
- **优化机制**：§IV-D 四项工程改动（resident service、Pippenger MSM、integer-resident witness、避免 disk swap）验证的是 proving time（29.1→29.0 s）与 wall-clock（34.8→28.5 s），**未验证内存峰值下降**；§VI 的 fixed-weight commitment reuse / data-path commitment / heterogeneous scheduling 均为 roadmap。
- **开源**：论文未给出统一 benchmark 仓库（本轮未检出）。
- **阶梯定位**：**L2 + L3**（跨系统的时间类别归因 + 聚合峰值内存），**不是 L4**。
- **与 A1 重叠**：高（同为成本归因），但**不覆盖 Halo2/Pallas**，且归因维度是时间不是内存。它直接证伪「无人做成本归因」，但不证伪「无人做 Halo2 阶段级内存归因」。
- **原文**：`https://arxiv.org/html/2611.17042v1` §III-A/III-B/IV-A/IV-B/IV-C/IV-D/VI。

### S2 · Performance Bottlenecks in Computing ZK Proofs on a GPU

- **类型 / 状态**：arXiv preprint `2611.09569v1`，2026-11-06，8 页，无 venue。
- **目标系统**：并行化 PlonK（GPU）。
- **实验规模**：V100 16 GB / A10 24 GB；约束规模 2^15–2^25；A10 在 2^24 内 <20 s，V100 <30 s；2^24 后失败（V100 观测 VRAM 20 GB）。
- **内存测量方法**：§4 `"We consider the performance based upon (1) scaling with respect to constraint-set sizes and (2) overall memory utilization."`；Figure 4 `"Memory Utilization Vs. Constraint-Set Size"`。**整体利用率，非分阶段**。
- **优化机制**：无已验证机制；§5 定性归因于 MSM bucket indexing 与 host-device transfer；§7 讨论多 GPU / RDMA。
- **开源**：未声明。
- **阶梯定位**：**L1 + L3**。
- **与 A1 重叠**：中。证明 GPU 侧「并行度 ↔ 内存」权衡已被研究，但粒度是整机 VRAM 曲线。
- **原文**：`https://arxiv.org/html/2611.09569v1` §1/§3.2/§4/§5/§7。

### S3 · ZKPoG

- **类型 / 状态**：ePrint `2025/765`，2025-04-29/30，preprint + implementation；清华 / Cysic。
- **目标系统**：Plonkish 端到端 GPU prover，含 witness generation 与自定义门自动编译器。
- **实验规模**：RTX 4090；D3-16 记录作者报告 22.8× vs CPU、12.7× vs GPU。
- **内存测量方法**：摘要 `"optimizing memory usage to accommodate large-scale circuits on affordable GPUs with limited memory"`。**本轮全文被反爬拦截，无法核对是否含阶段级内存表**。
- **优化机制**：内存适配以容纳大规模电路（细节未取得）。
- **开源**：D3-16 记为实现 artifact，未核验仓库状态。
- **阶梯定位**：至少 **L1 + L3**；L4 **未证实**（诚实处理：不声称其不存在）。
- **与 A1 重叠**：高但粒度不同；D3-16 已把它列为 A1 最强基线。
- **原文**：`https://eprint.iacr.org/2025/765`（摘要 `[原文]`，全文 `[UNVERIFIED]`）。

### S4 · MegaZK

- **类型 / 状态**：**peer-reviewed**，ICS'26，DOI `10.1145/3797905.3807842`；与 S3 同组。
- **目标系统**：GPU 端到端 ZKP，Plonkish + FRI/GPU。
- **实验规模 / 数字**：D3-16 记录 `"GPU memory usage is also reduced by 80.9%"`、37.4×/24.3×/6.1× vs CPU/GPU/ASIC（作者报告）。
- **内存测量方法**：聚合内存下降百分比；本轮未取得原文，无法判断是否有分阶段表。
- **阶梯定位**：至少 **L1 + L3**，L4 未证实。
- **与 A1 重叠**：高（同组连续工作，端到端倍数）。
- **状态**：`[二手]`，经 D3-16 已核验条目转录。

## 2. 硬件/原语侧内存与成本优化

### S5 · TensorZKP（USENIX Security 2026）
首个用 GPU Tensor Core 加速 ZKP；HyperPlonk PIOP + Brakedown PCS；端到端加速。**阶梯 L1/L3 为主**。与 A1 重叠低：硬件原语层，不提供 Halo2 CPU 阶段级 RSS。机构页（浙大 ARC）为 `[二手]`，ePrint 元数据 `[原文]`。

### S6 · Celer（CRYPTO 2026）
大规模查询 lookup argument，作者报告 Llama 场景 25.9× over plookup / 9.4× over LogUp。**阶梯 L1**（原语耗时）。与 A1 几乎不重叠。

### S7 · MORPH / Enabling AI ASICs for ZKP（DAC 2026）
- Big-T 复杂度模型显式暴露 Big-O 忽略的异构瓶颈与 layout 转换成本；统一分片 layout-stationary TPU Pippenger MSM、3/5 步 NTT 避免 on-TPU shuffle；JAX 实现，TPUv6e8 NTT 达 10× 吞吐。
- **这是本轮最接近 L5 的工作**：它验证了一个跨 kernel 可迁移的**硬件感知成本模型 + 数据布局机制**。但对象是 TPU/MSM/NTT kernel，不是 Halo2 CPU prover 的阶段级内存生命周期。
- 阶梯：**L3 + L5（kernel 层）**。与 A1 的关系是**方法论警示**：若 A1 只做 L4 剖面而无 L5 机制，贡献弱于 S7。

### S8 · LightZK（TACO 录用，CCF A）
机构新闻原文：面向 Groth16 GPU 的端到端优化；`"受存储容量约束的递归分块与数据布局优化"`、`"协同调度磁盘、主存与显存之间的数据传输及计算任务"`；2.8× 端到端，单节点完成 2^30 约束。
- **阶梯 L3 + L5（存储侧机制）**，但对象是 Groth16 GPU，非 Halo2 CPU。
- **证据限制**：论文正文 / DOI 本轮未取得，`[二手]`。不得据此声称其有/无阶段级内存归因。

### S9 · SIMD→General ZK Compiler（Journal of Cryptology）
原文片段给出 memory-bounded prover 框架、逐段求值 + 连线证明、streaming，不需要预先知道整个电路或 witness。属理论/编译器侧的内存上界，与 Halo2 实际 RSS 剖不同层。阶梯：理论 L5（结构性内存上界），非实验 L4。

### S10 · 其他 A 类近邻
MicroNova（S&P 2025）、Interstellar（PKC 2026）、ZK-CEC（arXiv 2601.11173）：递归 folding 与 circuit/spec 一致性方向，均非 prover 内存剖面。详见 D3-16 `SOURCES.md` S11/S12/S14。

## 3. 本仓库自身（F4-A）在阶梯上的位置——最关键的对照

| 能力 | F4-A 是否已有 | 证据 |
|---|---|---|
| L1 端到端时间 | **有** | D24 §5；1P −22.00% / 8P −15.27%（历史基线） |
| L2 阶段耗时归因 | **有，九阶段** | D25 §2.3/§9.4：`instance / synthesis / advice_commit / eval_setup / lookup_permute / permutation / lookup_product / quotient / opening`；20 对配对 + bootstrap CI + 未归因残差；D26 §12 在 n=1/2/4/8 上重复 |
| L3 聚合峰值内存 | **有，多指标** | D25 §2.1：`ws_peak_kernel`（单调、只作上界）、`ws_sampled_peak`（1 ms 采样）、`private_sampled_peak`、`memo_resident_bytes`（精确）、`chunk_net_peak_bytes`（分配器计数） |
| L4 阶段级内存归因 | **没有** | D25 只做「整证明窗口采样峰值 + 每 chunk 净峰值」，没有把内存归到九个阶段中的某一阶段；D26 §20 明列「峰值比 memo 多出的 2.2 MiB — 未定位 — 需要分配点级采样」 |
| L5 可迁移内存机制 | **部分有，但非内存** | D27 给出 F4-A 优化（selector 恢复链 memo 共享）的**可先验判定条件** C1 `d_s ≤ D−1`、C2 `occ ≥ 2`、C3 消费者在根；样本量 2（Orchard + 合成 Poseidon `hi`），X5 FAIL 后未移植。这是可迁移的**时间**优化判据，不是内存机制 |
| 跨电路 | **已有第二轮** | D27：Poseidon-only 第二电路，只改 degree 5→9 使链 0→3；样本量诚实写 2，ECC/Sinsemilla 为「未覆盖范围」 |
| 方法学边界 | **已写死** | D25 §2.1/§5：1 ms 采样会漏短尖峰；`ws_peak_kernel` 单调不减不可逐证明比较；`PrivateUsage` 含堆外预留；D25 §12：绑核 vs 不绑核 1.96×、rustc 1.88 vs 1.98，跨会话绝对毫秒不可比 |

**结论**：A1 原始定义中「现有工作缺分阶段归因」「最小原型 = 采样 RSS + 每阶段计时」这两条，在_orchard 本仓库_已经被 F4-A 实现大半。**A1-A 不是空白，而是已完成工作的低价值延伸。**

## 4. 阶梯汇总

| 工作 | L1 端到端时间 | L2 阶段时间 | L3 聚合峰值内存 | L4 阶段级内存归因 | L5 已验证可迁移内存机制 | 覆盖 Halo2 CPU |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| F4-A（本仓库） | ✅ | ✅ 九阶段 | ✅ 多指标 | ❌（2.2 MiB 未定位） | ⚠️ 时间机制判据，非内存 | ✅ |
| S1 arXiv 2611.17042 | ✅ | ✅ 八时间类别 | ✅ GPU/host pk | ❌ | ❌（roadmap） | ❌ |
| S2 arXiv 2611.09569 | ✅ | ❌ | ✅ 整机 VRAM | ❌ | ❌ | ❌ |
| S3 ZKPoG | ✅ | 未证实 | ✅ | 未证实 | ✅（GPU 内存适配，细节未取） | ❌ |
| S4 MegaZK | ✅ | 未证实 | ✅ 80.9% ↓ | 未证实 | ✅（GPU） | ❌ |
| S7 MORPH | ✅ | kernel 级吞吐 | ✅ layout 成本 | ❌ | ✅ kernel 数据布局 | ❌ |
| S8 LightZK | ✅ | ❌ 未证实 | ✅ 三级存储 | ❌ 未证实 | ✅ storage 调度 | ❌ |
| S9 SIMD compiler | 理论 | 理论 | 理论内存上界 | ❌ | ✅ 结构性 streaming | ❌ |

**读法**：L4 一列中，没有一篇工作被原文证实已做；但这不等于「L4 是空白」——因为 F4-A 自身已经用**整窗口采样 + chunk 净峰值**覆盖了主要归因需求，且明确记录了唯一未定位量（2.2 MiB）。真正稀缺的是 **L4 → L5 的跨越**：从剖面走到已验证、可迁移的内存机制。
