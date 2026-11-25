# D3-13-01-R1 — 阶段裁决

**状态**：`CONDITIONAL_HOLD`（信任边界有实质改进；H4 保持 OPEN；不进入 ZKP 原型）｜日期：2026-11-25
**性质**：实验裁决（R1 语义与口径修订），不是论文立项，不是新证明系统声明

> **R1 边界**：从 R0 commit `22cc839` 新建独立分支，仅做攻击语义修正、历史重放、执行前失败、Oracle 信任边界与指标口径修正。**不改变 D3-13 整体裁决**。D 已重新定性为 **Oracle-assisted Observer（可信实验 Oracle 辅助的观测上界）**，不再宣称"已解决 H4"。

---

## 1. 本轮解决的问题

| # | 问题 | 判定 | 证据 |
|---|---|---|---|
| 1 | 执行者自签证据能否阻断自洽虚假回执？ | **不能**（A/B 全败） | A 的 T1/T2/T4/T10、B 的 T1/T2/T3/T4/T10 均 UER=1.0；B≈A |
| 2 | 进程隔离本身是否等于信任隔离？ | **不等于** | B（独立进程）与 A 攻击结果一致 |
| 3 | 证据产生权转移到独立 DS + 密钥隔离 + 字段绑定是否有实质改进？ | **有** | C 挡住全部 Proxy 作恶：T2/T3/T5/T7/T10 PR=1.0，T4/T6 检测；T10 执行前失败伪造 PR=1.0 |
| 4 | Gateway 能否确认响应由指定 DS 签署（H1）？ | **能** | C 的 T3/T7 → ds_signature_invalid，PR=1.0 |
| 5 | Gateway 能否确认响应绑定当前授权/nonce（H2）？ | **能** | C 的 T2 执行前拒绝、T5 历史重放拒绝，PR=1.0 |
| 6 | 可信 Oracle 前提下，观测能否检测 DS 声明不一致（H5）？ | **能（仅理想条件下界）** | D 的 T8/T9 → observer_inconsistency，B 类 100/100、UER=0；T9 DR=1.0，T8 DR=N/A（无越权执行分母，虚假声明检出 100/100）。**依赖可信 Oracle 假设，非生产结论** |

---

## 2. H1–H5 逐项判定（用户指定）

| 判定 | 回答 | 成立条件 / 不成立原因 |
|---|---|---|
| **H1** 响应由指定 DS 签署？ | **成立（C/D）** | Gateway 直接固定 DS 公钥；Proxy 自签被拒（T3/T7 PR=1.0）。前提：DS 公钥可信分发 |
| **H2** 绑定当前授权请求与 nonce？ | **成立（C/D）** | 10 字段签名 + G 侧逐字段绑定 + 当前请求绑定；T2 执行前拒绝、T5 历史重放拒绝、T11 过期 Grant 拒绝 |
| **H3** 响应来自 DS 执行边界？ | **部分成立** | C 有 DS 进程 ground-truth 记录（truth_shared），可事后定位；Gateway 验签时看到的是 DS 声明，非直接观测执行 |
| **H4** DS 本身没撒谎？ | **C 不成立；D 仅在可信 Oracle 下检出；正式状态 OPEN** | C 的 T8 UER=1.0（签名有效但假声明，ASR=0）、T9 UER=1.0 DR=0；D 靠 Oracle-assisted Observer 使 T8/T9 均 B 类 100/100、UER=0（T9 DR=1.0；T8 无越权执行分母，DR=N/A，虚假声明检出 100/100）。检出依赖"Oracle 通道如实记录 DS 执行"这一未解决假设——**H4 保持 OPEN** |
| **H5** Oracle 提供真实记录前提下能否检出不一致？ | **能（理想上界，非生产条件）** | D 的 T8/T9 observer_inconsistency，B 类 100/100；前提是 `truth_shared` 未被 DS/Proxy 合谋控制 |

**必须明确的门槛（用户指定）**：
- H1/H2 成立 **不代表** H4 成立——C 的 H1/H2 全过，但 T8/T9 仍破。
- Data Service 签名 ≠ 真实世界真实性证明。
- 独立进程 ≠ 独立信任（B 反证）；**可信 Oracle 下的检出 ≠ 生产级独立观测**。
- 日志可追加 ≠ 执行事件完整（D3-11 已证）。
- 哈希绑定 ≠ 外部事实真实性（T8：哈希绑定全过但声明为假）。

---

## 3. D 的 Observer 重新定性（R1 Phase 3）

**真实结构**：Observer 从 `truth_shared` 读取 DS 进程写入的执行记录，用自己的测试密钥签名，与 DS evidence 比对。但 `truth_shared` 由 DS 进程写入，恶意 DS 仍可能控制其内容或完整性。

**R1 诚实处理**：
1. 统一命名 **D Oracle-assisted Observer**（README / THREAT-MODEL / ARCHITECTURE-COMPARISON / ATTACK-RESULTS / 本文件）。
2. `truth_shared` 明确为**实验真值通道**，不是生产级独立观测接口。
3. D 的结果只是"**拥有可信执行记录时，能检测多少不一致**"的**理想条件上界**。
4. 若 DS 能控制/伪造该通道，D 失去检测能力（对应 T9 合谋扩展的开放缺口）。
5. **不使用** "D 已解决 H4" / "Observer 已独立证明 DS 没撒谎" 等结论。
6. D-T8/T9 只写成"**在可信实验 Oracle 假设成立时，能够检测到相应虚假声明**"。

---

## 4. 证据缺口与本轮边界

| 缺口 | 状态 | 影响 |
|---|---|---|
| **H4（DS 是否撒谎）** | **OPEN（保持）** | 签名只证明"谁签的"；D 的检出依赖可信 Oracle，未解决真实观测信任基 |
| 独立观测的真实信任基 | **OPEN** | D 的 Observer 是受控模拟 + 可信 Oracle；真实 TEE/zkTLS/权威查询未实现 |
| 合谋 DS + Proxy 下 Oracle 通道完整性 | **OPEN** | T9 假设 Oracle 通道不被合谋方控制；若可控则 D 退化为 C |
| 真实外部数据源 / 非 mock 工具 | **OPEN** | 本轮 DS 是 mock；E2.2 类攻击在非 mock 工具上的复现仍未做（资产回收 Q4） |
| 过期 snapshot | **未验证** | T11 本轮只验证过期 Grant，不代表验证过期 snapshot |
| 证据生成/验证时间分别测量 | **未埋点** | 只报端到端延迟，gen/verify 拆分为 null，不虚构；不报告进程启动耗时 |
| 统计显著性 | **不声称** | 每臂 100 次验证稳定性，不换算 p 值/CI |
| Halo2 / 任何 ZK 电路 | **本轮未涉及** | 无新证明系统，Python 执行路径不含零知识证明 |
| Gateway 与 Proxy 合谋、Issuer 私钥泄露 | 排除项 | 不在本轮威胁模型内，未实现 |

---

## 5. 与冻结成果的关系

- **未修改**任何冻结仓库：`agent-exec-binding-mvp`、`D3-06-C`、`D3-07-A/B`、`D3-08`～`D3-12`，以及 R0 分支 `exp-d3-13-independent-execution-evidence`（仍指向 `22cc839`）。
- 基线只读：MVP HEAD `e327a9444ed8cea17baefbac01587b7fa77e8d39`，分支 `experiment/independent-execution-proxy`，工作区 clean。
- R1 为独立实验分支（orphan 单根），从 R0 固定 commit 继续，不改任何既有分支。

---

## 6. 下一步最值得研究的问题（非 ZKP）

**方向：把可信实验 Oracle 推进到真实独立观测信任基**（按价值排序）：
1. **执行事件可信采集**：选定 TEE / zkTLS / 权威状态查询中一个可得的独立观测源，说明它为何能看到 Proxy/DS 看不到的真实执行。
2. **远程证明绑定**：把 Observer 的"真实记录"锚定到可验证硬件/协议证明，而非模拟进程。
3. **观测者最小信任假设**：形式化"Oracle 通道不被合谋方控制"的具体条件（对应 T9 开放缺口）。
4. **证据层完整性**：把 D3-11 的"日志可追加 ≠ 无遗漏"应用到观测通道本身。

**不启动**：新 Halo2 电路、跨组织匿名凭证、递归证明、生产级 TEE 实现、"签名比对电路化"。

---

## 7. 是否具备进入 ZKP 原型阶段的条件

**不具备（CONDITIONAL_HOLD，R1 不变）**。三条硬理由：
1. 本轮真实缺口是 H4（信任边界/外部观测），不是证明关系；ZKP 无法证明外部执行真实。
2. H1/H2 与策略绑定已被普通签名解决（C 实测 PR=1.0/检测），ZKP 在这些字段无增量。
3. 唯一条件性增量是"隐藏数据下的策略合规"，但本轮无隐私场景支撑，且 D3-12 已证更简方案覆盖类似需求。

**解禁条件**（若未来满足，另立任务包）：出现明确的"验证者不接受明文、但必须确信隐藏 query/output 满足策略且来自承诺数据集"的场景，且存在公开锚点使证明不可自造。

---

## 8. 停止点与可复现清单

本轮完成后立即停止：不自行开发 Halo2、不宣布论文题目成立、不扩大到生产 TEE、不追加攻击项、不改冻结仓库或 R0 分支。等待用户独立核查源码、攻击测试与证据链。

- 仓库：`D:\Research\d3-13-independent-execution-evidence`
- R0 固定 SHA：`22cc839eb41a15ff38580ac918361ccaf5a158e2`（分支 `exp-d3-13-independent-execution-evidence`）
- R1 分支：`exp-d3-13-independent-execution-evidence-r1`
- 命令：`python -m unittest discover -s tests -v`（19 项）；`python -m src.runner`（3800 次）
- 输出：`results/attack_results.json`（3800 raw + 4 seed + 38 臂 + 10 N/A）、`results/run_log.txt`
- 提交/推送 SHA：见汇报（本文件落盘后执行）
