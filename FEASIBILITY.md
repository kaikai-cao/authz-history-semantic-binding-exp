# D3-18-01 性能与工程可行性评估

目标负载：SealCall 代表配置 d=256、K=16 参考样本、poly modulus degree 8192、coefficient-modulus [60,40,40,60]、scale 2^40、Intel Core Ultra 5 225H / 32GB / 1 thread / TenSEAL 0.3.18 `[原文, S1 §4.4]`。

## 1. 已知数据（仅这些可引用）

| 项 | 数值 | 来源与等级 |
|---|---|---|
| 纯 CKKS 加密评分（目标负载） | 0.176 s / 次；F1=0.895（该 fold）；packed 0.131 MB；raw 3.761 MB | `[原文, S1 Table 5]` |
| mean F1（全基准，grouped nested） | 0.840（1,252 binary candidates） | `[原文, S1 摘要]` |
| 加密决策一致 | 760 model–layout records 全部与冻结明文决策一致 | `[原文, S1 摘要]` |
| PRISM prover vs Zhou et al. S&P2025 | 3.5× 慢 | `[摘要, S2]` |
| PRISM verifier vs 同上 | 最多 7.8× 快 | `[摘要, S2]` |
| PRISM proof size vs 同上 | 7.8× 小 | `[摘要, S2]` |
| PRISM vs Atapoor et al. CiC2024 | proof 5.5× 大 / prover 10.1× 快 / verifier 2.6× 快 | `[摘要, S2]` |
| Batch,Pack&Prove vs 先前 | proof "several orders of magnitude smaller and faster"（NN 负载） | `[摘要, S3]` |

**没有的数据**（全部 `[UNVERIFIED]`）：PRISM/BatchPack 在 d=256,K=16 点积负载上的绝对 prover 时间、verifier 时间、proof size、离线 VOLE 成本、网络传输量。PRISM 全文受阻（SOURCES.md 已记录多途径失败）。

## 2. 为什么不能直接把 PRISM 的数字套到目标负载

1. 负载不同：PRISM 摘要报告的是"linear algebra and neural network tests"，SealCall 是 256维×16参考的相似度点积 + 阈值前聚合；两者电路结构、乘法深度、NTT 次数都不同 `[原文 + 摘要]`。
2. 基准不同：3.5×/7.8× 等是**相对** Zhou et al. 或 Atapoor et al. 的倍数，不是绝对时间；且 Zhou et al.（S&P2025，最快 prover）与 Atapoor et al.（最小 proof）本身是不同优化点 `[摘要]`。
3. 机制差异：PRISM 含 offline phase + VOLE 相关性，其在线/离线拆分无法从摘要确定；高频审计每次调用是否重付离线成本未知 `[UNVERIFIED]`。
4. 环境差异：SealCall 的 0.176 s 是单机单线程 TenSEAL、无网络延迟 `[原文, S1 §4.4]`；PRISM/BatchPack 的测试硬件、实现语言、是否含网络均未从正文核实 `[UNVERIFIED]`。

**结论** `[推断]`：不能给出"CKKS + 可验证计算在目标负载下 = X 秒"的预测值。任何这样的数字都是编造。正确做法是列出必须做的实验（见 §5）。

## 3. 四种方案对比（定性，不编造数字）

| 方案 | 模型判断质量 | 恶意服务计算完整性 | 输入隐私 | 相对成本（定性 `[推断]`） |
|---|---|---|---|---|
| 1. 明文本地审计 | SealCall 基线 F1（但无外包） | N/A（无外包方） | 无外包即无暴露 | 最低；无密码学开销 |
| 2. CKKS 半诚实外包（SealCall） | F1=0.840/0.176s `[原文]` | **无** `[原文 §3.5]` | 对 semi-honest S 成立 `[原文]` | 基线（0.176 s） |
| 3. CKKS + 可验证计算（vHE，非 ZK） | 不变（模型未改） | 有（若 vHE 覆盖负载） `[摘要]` | 同 2 | 增加 prover/验证开销，量级未知；可能用 BatchPack `[摘要]` |
| 4. CKKS + 零知识可验证计算（PRISM 类） | 不变 | 有 + ZK `[摘要]` | 同 2，且可隐藏 witness | 最高；含 VOLE 离线相关性管理，高频适配性 `[UNVERIFIED]` |

**关键点** `[推断]`：从 2→3 已获得"恶意服务计算完整性"这一核心增益；3→4 的 ZK 是否必要，取决于是否有必须隐藏的 witness（如 Θ 内容对验证者保密）。SealCall §3.3 明确 controller 本就能查询参考坐标、保护参考资产是"separate goal" `[原文]`——**在本负载下 ZK 的不可替代性未被建立**。

## 4. 工程障碍清单

1. **实现可得性**：PRISM 代码仓库未从摘要/页面取得 `[UNVERIFIED]`；BatchPack 代码同样未知 `[UNVERIFIED]`。无代码则无法实测。
2. **CKKS 近似算术**：vHE for CKKS 需处理 ring Rq 运算与 range check；S4 摘要注明 range check 有勘误 `[摘要]`；近似的"正确"定义（噪声界）需明确。
3. **离线相关性管理**（若用 PRISM）：生成方、复用边界、per-session 成本、证明者-验证者绑定 `[UNVERIFIED]`。
4. **目标负载实现工作**：SealCall 用 TenSEAL，PRISM/BatchPack 用 Lattigo/OpenFHE 类库 `[摘要, S2 参考文献]`；跨库对接需要重实现或桥接，非即插即用 `[推断]`。
5. **外部信任锚**：model/reference 版本承诺需要一个独立可信发布方——SealCall 无此角色，MVP 也未覆盖 `[推断]`。

## 5. 必须做的实验（若进入最小实验，非本轮执行）

| 实验 | 目标 | 成功判据 | 失败停止条件 |
|---|---|---|---|
| E1 负载映射 | 确认 vHE/zkHE 覆盖 SealCall 的 256维×16点积+阈值前计算 | 能在目标电路上生成并验证证明 | 不支持所需 CKKS 操作 → STOP |
| E2 成本实测 | 测 prover/verifier/proof size/离线成本/网络量（同硬件） | 可量化、可复现 | prover 较 0.176 s 基线增长 >10× 且无优化路径 → STOP |
| E3 增益对照 | 方案 2/3/4 在同一负载、同一恶意服务攻击下对比 | 3/4 能检出 A 类伪造，2 不能 | 3 已足够且 4 无独立增益 → 去掉 ZK |
| E4 判断质量前置 | 在 purpose_scope/recipient 类上测证明后的审计决策 | F1 有实质提升 | F1 仍 ~0.171 → 密码学增益无实际价值，停止 |

## 6. 可行性结论 `[推断]`

- **技术可行性**：机制层面存在（三篇顶会 vHE/zkHE + SealCall），但**目标负载可行性未证**，因为关键正文/代码/绝对数字不可得。
- **价值可行性**：核心风险不是密码学，而是**模型判断质量短板**——E4 是前提性实验，若模型在授权目的判断上仍 F1≈0.171，则"证明它正确执行"的实际安全价值很低。
- **结论**：这是"有明确缺口 + 有现成机制 + 缺目标负载验证 + 缺模型质量支撑"的组合。不足以 CONDITIONAL-GO，也不足以直接 STOP（缺口真实且可回溯）。
