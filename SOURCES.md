# D3-17-02 · 来源索引与证据等级

> 基准日期：2026-11-25。本文件登记本轮所有引用，逐条标注**出版状态**、**原文位置**与**证据等级**。
> 证据等级：`[原文]` = 取得原文并逐字核对；`[原文片段]` = 取得原文的可回溯片段但非全文；
> `[二手]` = 仅取得机构新闻/聚合页/作者声称的转述；`[UNVERIFIED]` = 未能取得任何可回溯原文。
> Internet-Draft 一律不称为 RFC；预印本一律不称为同行评审成果。

---

## 0. 冻结基线（本轮只读，未改动）

| ID | 对象 | 精确位置 | 状态 |
|---|---|---|---|
| F0 | `zcash-orchard-engineering` | HEAD `d291c49303e9483a45713d67bc14ad18f77c2561`，分支 `main`，`status --porcelain` = 0 | `[原文]` 本地仓库 |
| F1 | 标签 `f4a-closed-2026-11-07` | annotated tag，指向 F0 同一 commit；tag message：`Freeze F4-A.3: implementation, measurements, evidence boundaries and doc closure` | `[原文]` |
| F2 | 上游 `orchard-upstream` | HEAD `616a669df8c9a59c33d47064d3ce04b25d026b2e`，`main`，clean；remote `github.com/zcash/orchard.git` | `[原文]` 本地仓库 |
| F3 | `halo2_proofs` | vendored `0.4.0`，`experiments/transaction_e2e/vendor/halo2_proofs-0.4.0/Cargo.toml`，repository 字段 `https://github.com/zcash/halo2` | `[原文]` |
| F4 | D3-16 基线 | `cdf469169311aee711186a7e5af19267b74f7e38`，分支 `exp-d3-16-01-research-space-reset`，clean | `[原文]` |
| F5 | D3-17-01 基线 | `ee7628fa72ce25eaf938bc0a949028302cb3a2ed`，clean | `[原文]` |

## 1. F4-A 原始文档与数据（本轮 Phase 0/2 的直接事实来源）

| ID | 文档 / 产物 | 位置 | 证据 |
|---|---|---|---|
| D24 | `24_f4a_implementation.md` | `docs/orchard/24_f4a_implementation.md`，§5/§8/§10 | `[原文]` |
| D25 | `25_f4a_resource_validation.md` | `docs/orchard/25_f4a_resource_validation.md`，§2/§5/§9–§14 | `[原文]` |
| D26 | `26_f4a_action_scaling_prereg.md` | `docs/orchard/26_f4a_action_scaling_prereg.md`，§3/§5/§12/§14/§18/§20 | `[原文]` |
| D27 | `27_f4a_cross_circuit_recon.md` | `docs/orchard/27_f4a_cross_circuit_recon.md`，§3–§10 | `[原文]` |
| R25 | `f4a2_audit/{mem_1p,mem_8p,stage_1p,stage_8p,drift_check_1p_unpinned}.log`, `summary.md`, `build.txt` | `results/transaction_e2e/f4a2_audit/` | `[原文]` 文件存在性核对；**本轮未重算数字**，数值引用自 D25 |
| R26 | `f4a3_scale/{mem,count}_{1p,8p}_*.log` | `results/transaction_e2e/f4a3_scale/` | `[原文]` 文件存在性核对；数值引用自 D26 |
| R27 | `f4a4_xcircuit/poseidon_{base,hi}.log` | `results/transaction_e2e/f4a4_xcircuit/` | `[原文]` 文件存在性核对；数值引用自 D27 |
| C25 | `f4a2_report.py`、`f4a_ab.py`、`f4a_scale_report.py` | `scripts/analysis/` | `[原文]` |
| C26 | `vendor/halo2_proofs-0.4.0-f4a.patch`、`-f4a2-mem.patch`、`-f4a-probe.patch` | `experiments/transaction_e2e/vendor/` | `[原文]` |

**历史基线数字（仅作背景，本轮未重测、未改写）**：
- D24 §0/§10.3：1P `−22.00%`、8P `−15.27%`；proof 与 `h` 系数指纹不变；机制为 `compress_selectors` 恢复链的只读 memo 共享。
- D25 §9.2：`ws_sampled_peak` 增量 1P `+6.09 MiB`、8P `+6.72 MiB`；`ws_peak_kernel` 1P `+0.00`（单调计数，不可逐证明比较）。
- D25 §9.3：1P `alloc_calls −8 617`、`alloc_bytes −1.603 GiB`；每 chunk memo 1P `6.125 MiB` / 8P `0.766 MiB`。
- D25 §9.4：收益 `quotient` 占 `Δprove` 1P `100.4%` / 8P `101.2%`，其余八阶段在噪声内。
- D26 §14：n=8 时 1P `194.59 → 202.91 MiB`（增量 `8.32 MiB`，memo `6.125 MiB`，**多出约 2.2 MiB 未定位**）；8P 增量 `5.47 → 6.96 MiB` 平坦。
- D26 §20：未覆盖范围明列「峰值比 memo 多出的 2.2 MiB — 未定位 — 需要分配点级采样」「8P n=8 内存 CI 未算（3 对）」。

## 2. A1 候选定义

| ID | 来源 | 位置 | 证据 |
|---|---|---|---|
| A1DEF | D3-16 `CANDIDATE-POOL.md` 的 `## A1` 段 | `D:\Research\d3-16-01-research-space-reset\CANDIDATE-POOL.md` | `[原文]` |
| A1RANK | D3-16 `RANKING.md` 中 A1 排名与下一轮审计范围 | 同上目录 | `[原文]` |

A1DEF 原文要点：研究对象为 witness 生成 / poly fill / commit / IPA 四阶段的峰值 RSS 与延迟归因；声称「现有工作全部报告端到端倍数，对哪个阶段、在什么电路结构下吃掉内存缺少可复现的分阶段归因」；定位为**工程系统贡献，不是密码学新性质**；最小原型 1 台 32 GB 机器、复用 F4-A 脚手架、约 2–3 个月。

## 3. 相关工作（原文核查）

| ID | 工作 | 类型 / 状态 | URL 与位置 | 关键可核对事实 | 等级 |
|---|---|---|---|---|---|
| S1 | **Infrastructure for Verifiable AI: Where Proof Costs Go and How Hardware Can Help**（Yihan Xia, Wenxin Xu, Taotao Wang，2026-11-12） | arXiv preprint `2611.17042v1`，16 页 / 8 图 / 5 表，非同行评审 | `https://arxiv.org/abs/2611.17042`；`https://arxiv.org/html/2611.17042v1` §III-A/III-B/IV-A/IV-B/IV-C/IV-D/VI | 四层框架；六 prover（zkLLM/DeepProve/VeriLoRA/VeriDP/Expander/ZKTorch）+ 七 kernel；§IV-A：`"For each cell we record prover time and its breakdown, peak GPU and host memory, proof size, verifier time..."`；同节：`"Regions that cannot be split without modifying the code are reported as mixed rather than apportioned by guesswork."`，八类为 **时间**类别；§IV-C Table IV 仅 `GPU pk (GB) / host pk (GB)` 聚合列；13B LoRA 自报 45.0 GB / 外部采样 56.2 GB；**无 Halo2/Pallas**；**无阶段级内存归因**；内存采样工具与间隔未披露；§IV-D 四项工程改动验证的是时间（29.1→29.0 s），不是内存 | `[原文]` |
| S2 | **Performance Bottlenecks in Computing ZK Proofs on a GPU**（Carolino, Geren, Kaufman, Nussbaum, Scott, Korth，2026-11-06） | arXiv preprint `2611.09569v1`，8 页，无 venue | `https://arxiv.org/abs/2611.09569`；`https://arxiv.org/html/2611.09569v1` §1/§3.2/§4/§5/§7 | §4：`"We consider the performance based upon (1) scaling with respect to constraint-set sizes and (2) overall memory utilization."`；Figure 4 标题 `"Memory Utilization Vs. Constraint-Set Size"`；§5 归因于 MSM bucket indexing 与 host-device transfer，但无 MSM 单独 footprint；V100/A10、2^15–2^25；**无 per-stage 内存** | `[原文]` |
| S3 | **ZKPoG: Accelerating WitGen-Incorporated End-to-End ZKP on GPU**（Li, Yu, Wang, Fan, Deng；2025-04-29/30） | ePrint `2025/765`，preprint + implementation | `https://eprint.iacr.org/2025/765`；全文 PDF 本轮反爬拦截 | 摘要原文：`"optimizing memory usage to accommodate large-scale circuits on affordable GPUs with limited memory"`；RTX 4090、Plonkish、含 witness gen 的端到端；D3-16 S8 记录作者报告 22.8× / 12.7×。**本轮未能核对是否含阶段级内存表** → 一律按「未证实有」处理，不宣称其为研究空白 | `[原文]` 摘要 / `[UNVERIFIED]` 全文内存表 |
| S4 | **MegaZK: A Memory Efficient GPU System Accelerating End-to-end ZKP** | peer-reviewed，ICS'26，DOI `10.1145/3797905.3807842` | D3-16 `SOURCES.md` S9；本轮 WebSearch 未取得原文 | D3-16 记录原句 `"GPU memory usage is also reduced by 80.9%"`；同组连续工作；仅 Plonkish + FRI / GPU | `[二手]`（经 D3-16 已核验条目转录），本轮未直取 |
| S5 | **TensorZKP: Repurposing GPU Tensor Cores for High-Performance Zero-Knowledge Proofs** | **peer-reviewed**，USENIX Security 2026；ePrint `2026/1250` | `https://eprint.iacr.org/2026/1250`；`http://arc.zju.edu.cn/2026/0707/c62503a3186172/page.htm`（机构新闻） | 首个 Tensor Core 加速 ZKP；HyperPlonk PIOP + Brakedown PCS；端到端加速 | `[原文]` 元数据 / `[二手]` 机构页 |
| S6 | **Celer: A Lookup Argument for Large-Scale Queries** | **peer-reviewed**，CRYPTO 2026；ePrint `2026/1453` | `https://eprint.iacr.org/2026/1453` | 查询规模远大于表规模；作者报告 25.9× over plookup / 9.4× over LogUp（Llama 场景） | `[原文]` 元数据（D3-16 S18） |
| S7 | **Enabling AI ASICs for Zero Knowledge Proof**（MORPH） | DAC 2026；arXiv `2604.17808v1` | `https://arxiv.org/abs/2604.17808`；`https://arxiv.org/html/2604.17808v1` | Big-T 硬件感知复杂度；统一分片的 layout-stationary TPU Pippenger MSM + 3/5 步 NTT；TPUv6e8 NTT 达 10× 吞吐；面向 MSM/NTT **kernel**，非 Halo2 CPU 阶段级 RSS | `[原文]` 摘要 |
| S8 | **LightZK: An Efficient GPU Acceleration Framework for Large-Scale Zero-Knowledge Proofs**（卢必然等） | **peer-reviewed**（TACO 录用，CCF A），2026-09-28 公告；**本轮未取得论文原文 / DOI** | `https://grid.hust.edu.cn/info/1053/3070.htm` | 机构新闻原文：`"受存储容量约束的递归分块与数据布局优化"`、`"协同调度磁盘、主存与显存之间的数据传输及计算任务"`；Groth16 GPU；2.8× 端到端；2^30 约束。**目标为 Groth16 GPU 存储管理，非 Halo2 CPU 阶段归因** | `[二手]`（机构新闻），论文正文 `[UNVERIFIED]` |
| S9 | **An Efficient ZK Compiler from SIMD Circuits to General Circuits** | Journal of Cryptology（Springer，`10.1007/s00145-024-09531-4`） | `https://link.springer.com/content/pdf/10.1007/s00145-024-09531-4.pdf` | 原文片段：`"a framework for memory bounded provers to prove the correctness of large statements"`、`"evaluate a circuit segment-by-segment... allowing streaming"`；理论/编译器侧内存上界，非 Halo2 实现测量 | `[原文片段]` |
| S10 | MicroNova（S&P 2025, ePrint 2024/2099）、Interstellar（PKC 2026, ePrint 2025/1294）、ZK-CEC（arXiv 2601.11173） | 见 D3-16 SOURCES S11/S12/S14 | 复用 D3-16 已核验条目 | A 类相邻但非 prover 内存剖面 | `[原文]`（经 D3-16） |

## 4. 引用纪律声明

- 本轮**未运行任何证明实验**，未生成新的 RSS/时间数字；文中所有测量数字均引自 F4-A 冻结文档并显式标注来源章节。
- 对 S3/S4/S8 未能取得全文者，只使用摘要/机构新闻可核对部分，并明确不得据此断言「该方向无人做过」。
- 不把论文未报告某指标等同于该问题未被解决（本任务包明令）。
- 不把 Halo2 代码结构推断直接当作实测峰值 RSS。
