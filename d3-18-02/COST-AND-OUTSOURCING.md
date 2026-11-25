# D3-18-02 Phase 1：SealCall 本地计算、加密评分与外包价值

基准日期：2026-11-25。证据等级见 SOURCES.md。所有数字来自 SealCall §4.4 `[原文]`，经本轮重新抓取 HTML 全文逐段核对。

## 1. 原文报告值（§4.4 Encrypted fidelity and computation costs）

**实验配置**（逐字）："The cost representative was fixed before inspecting quality: outer fold 0, seed 20261016, with d=256 and K=16. Experiments use an Intel Core Ultra 5 225H, 32 GB RAM, one thread, and TenSEAL 0.3.18. CKKS parameters are polynomial modulus degree 8192, coefficient-modulus bit sizes [60,40,40,60], and scale 2^40." `[原文]`

**Table 5（单一预选模型，每 scorer 一行）**——F1 为该模型 251 例 outer test fold 的 B_F1：

| Scorer | F1 | Time (s) | Packed MB | Raw MB |
|---|---|---|---|---|
| SealCall（参考集最大相似度） | 0.895 | 0.176 | 0.131 | 3.761 |
| Center | 0.845 | 0.016 | 0.235 | 0.235 |
| LR | 0.909 | 0.043 | 0.235 | 0.235 |
| RBF-SVM | 0.915 | 15.267 | 0.131 | 93.794 |

- 注意：Table 5 的 0.895/0.909/0.915 是**预选折**，不是全部外折；全部 1,252 候选的 B_F1 在 §4.2 Table 3 中为 SealCall 0.840 / LR 0.913 / RBF-SVM 0.905。**不得把 Table 5 单折值写成全体结果** `[原文]`。
- LR 输入在该折有 1,150 坐标；SealCall 参考集查询 0.331 MB、加密参考集 5.302 MB；50 次查询计时（RBF 20 次） `[原文]`。

**逐字关键段**（§4.4 尾部）："Trusted extraction, uncached BGE encoding, and projection average 1.47, 484.95, and 0.55 ms. Query-matched sums of trusted preparation and private scoring average 0.663 s, with empirical 95th percentile 1.158 s, excluding network and scheduling. Local plaintext scoring after preparation takes approximately 19 μs. These measurements quantify the processing cost of a confidential remote audit interface. The service model is motivated by access to maintained audit knowledge and operations; the encrypted scoring time measures the cost of applying a selected scorer across that boundary while protecting the query." `[原文]`

## 2. 逐项回答任务包 Phase 1 的六个问题

**① 19 μs 与 176 ms 是否比较同一评分阶段？——是（同一逻辑阶段，不同实现）。**
两者都是"给定已构造表示后，对参考集做相似度评分"这一步：0.176 s 是 Table 5 的 "private scoring cost"（加密域评分），19 μs 是 "Local plaintext scoring **after preparation**"（明文域评分）。原文用同一个 "preparation" 边界词，说明二者都在表示构造之后计时。`[原文 + 推断]`

**② 两者是否包含相同的预处理？——都不包含 trusted preparation，且原文把 preparation 单列。**
trusted preparation = extraction 1.47 ms + BGE encoding 484.95 ms + projection 0.55 ms ≈ **486.97 ms ≈ 0.487 s**（三项相加，`[推断]` 基于原文三个分项）。两个评分数字都在这之后，因此评分比值不含这 0.487 s。但注意：19 μs 是"after preparation"，0.176 s 的查询加密是否计入 preparation 原文未逐项拆分，按原文表述 preparation 在 C 侧完成，属 `[原文]` 的结构性描述，精确到"加密操作是否计入 0.176 s"为 `[UNVERIFIED]`。

**③ 是否包含网络、排队、序列化、密钥准备？——明确排除网络与调度；未测进程隔离；密钥准备未单列。**
逐字："These measurements exclude cloud network latency and do not test process isolation." 与 "excluding network and scheduling." `[原文]`。加密与 HE 运算在同一进程、server context 无密钥 `[原文]`。序列化/通信以 MB 单独报告（0.331 MB 查询、0.131 MB packed 响应），未计入时间 `[原文]`。密钥生成成本未报告 `[UNVERIFIED]`。

**④ 0.663 s 如何组成？——trusted preparation ≈0.487 s + private scoring 0.176 s ≈ 0.663 s。**

```
extraction 1.47 ms + BGE encoding 484.95 ms + projection 0.55 ms = 486.97 ms ≈ 0.487 s
0.487 s + 0.176 s = 0.663 s   ← 与原文 "average 0.663 s" 一致
```

95th percentile 1.158 s 同口径。关键含义：**端到端时间的 73% 是 BGE 编码（本地、可信域、与安全外包无关），只有 27% 是加密评分**。用户上轮"本地 19 μs vs 加密 176 ms"的比较，只对应这 27% 的子阶段。`[原文 + 算术推断]`

**⑤ 服务商维护参考数据与本地计算的实际利益交换是什么？——原文明确：交换的是"持续维护的审计知识与运营"，不是计算卸载。**
逐字："The service model is motivated by access to maintained audit knowledge and operations; the encrypted scoring time measures the cost of applying a selected scorer across that boundary while protecting the query." `[原文]`。引言更直白："providers can curate audit references, update models, and operate the scoring service. Users thereby gain access to continuously maintained safety capabilities without building a dedicated security operation." `[原文]`。§3.4 补充配置版本更新须重新验证 `[原文]`。因此本系统里**服务器并没有承担更便宜的计算**：本地明文评分反而快 9,263 倍；用户付费换取的是"别人替你维护参考集/模型/阈值并运营服务"+ 查询内容不暴露。`[原文 + 推断]`

**⑥ 若控制器获得参考明文，是否能直接放弃 CKKS？——在 SealCall 现有信任模型下可以；但这等于改变部署目标，不是修复漏洞。**
§3.3 明确 controller 可恢复参考坐标且 "present trust model permits this access within C"，保护参考资产是 "separate goal" `[原文, §3.3]`。若 C 本就被信任到可读参考明文，则加密评分的指导意义下降——此点 D3-18-01 已记为 "ZK 在本场景无明确不可替代增益"，本轮原文进一步坐实。**但不能据此说"CKKS 无用"**：若服务部署目标转为"参考数据对 C 也保密"（双边隐私），则必须换 output-restricted 协议，CKKS 本身仍只是表示层工具。`[原文 + 推断]`

## 3. 要求报告的三组数字

**（a）评分阶段耗时比（用户给的数字，本轮复核）：**

```
CKKS / 本地 = 0.176 s / 19 μs = 176000 μs / 19 μs = 9,263.16×  ≈ 9,263×
```

用户上轮"约 9,263 倍"计算**正确** `[原文数字 + 本轮算术复核]`。但必须附口径：**这是纯评分阶段的比值，不含共享的 ≈0.487 s trusted preparation，也不含网络/调度**。若按完整 query-matched 流程比较，本地路径约 0.487 s + 19 μs ≈ **0.487 s**，SealCall 端到端 **0.663 s**，比值约 **1.36×**（本轮推断：0.663/0.487），而非 9,263×。`[推断]`

**（b）不同 scorer 的准确率与耗时（Table 5，预选折 / Table 3，全折）：**

| Scorer | 预选折 F1 (T5) | 全折 B_F1 (T3) | 加密评分耗时 | 说明 |
|---|---|---|---|---|
| SealCall 参考集 | 0.895 | 0.840 | 0.176 s | 支持 trusted 最大值选择 + 参考检视，但输出可恢复坐标 |
| Center | 0.845 | 0.818 | 0.016 s | 最快加密评分 |
| LR | 0.909 | 0.913 | 0.043 s | 全折最优；比 SealCall 快约 4.1× |
| RBF-SVM | 0.915 | 0.905 | 15.267 s | 最贵（93.794 MB raw） |

结论：SealCall 自选取的参考集 scorer **既不是最准的也不是最快的**；作者明说 "LR is both more accurate and faster than the reference scorer on this representative" `[原文]`。这为"9,263× 代价换来的到底是什么"提供了直接回答——换的是**输出接口可检视参考**（trusted 最大值 + 检视），而不是评分质量或速度。`[原文 + 推断]`

**（c）外包方案实际节省的资源：**

- **计算：没有节省。** 加密评分比本地慢 9,263×（评分阶段）；加上 preparation 后端到端仍比"本地同流程"慢约 36%。服务器承担更重运算，不是把昂贵计算转移出去 `[原文 + 推断]`。
- **通信：packed 响应比 raw 小 96.5%（3.761→0.131 MB）** `[原文]`——这是真正的节省项，但节省的是**带宽/响应体积**，不是计算。
- **用户侧运维：节省。** 免于自建与持续维护审计参考集、模型、阈值校准与版本更新 `[原文, §1 / §3.4]`。
- **保密：获得查询内容对 semi-honest 服务的输入隐私** `[原文, §3.5]`。

## 4. 计算外包 vs 专业知识/模型运营外包（必须区分）

| 维度 | 计算外包 | 专业知识/模型运营外包 |
|---|---|---|
| SealCall 是否成立 | **不成立**：本地 19 μs ≪ 加密 176 ms，服务端更慢 | **成立**：provider 维护参考集/模型/校准/版本，用户零运维，查询不暴露 |
| 支持的原文 | §4.4 全部耗时 | §1 "maintain detection capabilities, curate audit references, update models"；§4.4 "service model is motivated by access to maintained audit knowledge and operations" |
| 对选题的含义 | 不能用"卸载昂贵计算"论证外包价值 | 真正价值在参考数据保密 + 运营；**这恰好把焦点推向 Phase 2 的参考数据泄露问题** |

**阶段小结**：用户上轮的重新定位（"外包价值主要是用专业服务商维护的审计参考数据，同时不暴露查询"）**已被原文证实**。因此下一步确实应审视参考数据保密边界，而不是马上接 SNARK。但 Phase 2 将显示：这个边界问题在 SealCall 自己的信任模型内是**被明确允许**的，且已有现成 output-restricted 方案；不构成新的密码学缺口。`[原文 + 推断]`
