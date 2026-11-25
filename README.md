# D3-13-01-R1 — Independent Execution Evidence（独立执行证据来源与信任边界实验 · 语义与口径修订）

**阶段**：D3-13-01-R1｜**日期**：2026-11-25｜**性质**：已有实验修订（P0 可信度修正），**非**新研究方向
**前序**：D3-13-01 R0（commit `22cc839`）；RESEARCH-ASSET-RECOVERY-01 候选 1（授权→真实执行效果绑定）
**本轮不做**：Halo2 / Groth16 / PLONK / 递归 SNARK、生产级 TEE / 远程证明 / zkTLS、真实外部数据库、T13 及任何新攻击项、修改 R0 分支或任何冻结仓库

> **R1 唯一目标**：修正 R0 中"部分攻击未实现各自独立语义""T5 不是历史响应重放""T10 未严格模拟执行前失败""D 的 Observer 信任边界表述过强""部分指标/文档不一致"的问题，使 R0 的核心发现建立在准确、可复核的实验定义之上。**不改变 D3-13 整体裁决**（仍为 `CONDITIONAL_HOLD`）。

---

## 1. 研究问题

先解决 **"谁有资格证明执行确实发生了"**，再讨论如何用 ZKP 隐藏执行证据。

MVP 的 `IndependentExecutionProxy` 把执行主体从 Adapter 移到独立进程，但 Proxy **同时**是执行者与证据生成者（自带密钥、自带数据集、自签 evidence）。把它的输出直接放进电路只会让自洽声明更漂亮，不会让声明更真实。本轮继续用受控攻击实验回答**证据来源与信任边界**问题，不做新电路。

两个必须分开的命题（H1/H2）及扩展判定 H1–H5 见 `DECISION.md`。**H4（DS 本身有没有撒谎）在本轮仍然 OPEN**。

---

## 2. 四种对照架构（R1 术语）

| 方案 | 证据由谁产生 | 密钥归属 | 主要信任假设 |
|---|---|---|---|
| A Adapter Receipt | Adapter | Adapter | Adapter 诚实（MVP E2.2 基线） |
| B Independent Proxy | Proxy（独立进程） | Proxy **自生成**，Gateway TOFU pin 自报公钥 | Proxy 诚实 |
| C Signed Data Service | 独立 DS 进程 | DS **自生成**，Proxy 不持有；Gateway 固定 pin DS 公钥并逐字段绑定 | DS 诚实 |
| **D Oracle-assisted Observer** | C + Observer（**可信实验 Oracle 辅助**） | Observer 独立签名 | **实验 Oracle 提供真实执行记录**（理想条件下界，非生产观测） |

> **D 的准确定性（R1 核心修正）**：D 的 Observer 从 `truth_shared` 读取 DS 进程写入的执行记录。该通道是**受控模拟中的可信测试 Oracle**，不是生产级独立观测接口，也不等价于 TEE、远程证明或真实外部审计。D 的结果只表示"**在拥有可信执行记录的理想条件下，观测机制能检测多少 DS 声明与执行记录的不一致**"——是**上界**，不是已实现的解决方案。若 DS 能控制或伪造该通道，D 立即失去检测能力。**H4 未被 D 解决。**

**关键隔离事实（源码可核）**：
- C 的 DS 在**独立进程**内 `Ed25519Signer.generate()`，Gateway 的 `ds_pk` 从 DS 进程直接读取；Proxy 转发进程的签名函数里**没有任何 DS 密钥**（`_forward_proxy_process`）。
- nonce 与 request_id 由 driver（可信请求发起侧）生成并传入，不由 Proxy 决定。
- D 的 Observer 是独立进程、独立签名密钥；`truth_shared` 是 Proxy 从不接收的旁路真值通道（实验 Oracle）。

---

## 3. 攻击适用性矩阵（R1 Phase 1，N/A 显式记录）

| 攻击 | A | B | C | D |
|---|:--:|:--:|:--:|:--:|
| T1 自洽虚假 Receipt | ✅ | ✅ | N/A | N/A |
| T2 查询参数篡改 | ✅ | ✅ | ✅ | ✅ |
| T3 Proxy 自签虚假 Evidence | N/A | ✅ | ✅ | ✅ |
| T4 结果替换 | ✅ | ✅ | ✅ | ✅ |
| T5 历史响应重放 | ✅ | ✅ | ✅ | ✅ |
| T6 证据字段篡改 | N/A | ✅ | ✅ | ✅ |
| T7 伪造 DS 身份/签名 | N/A | N/A | ✅ | ✅ |
| T8 恶意 DS 合法密钥签假结果 | N/A | N/A | ✅ | ✅ |
| T9 DS + Proxy 合谋 | N/A | N/A | ✅ | ✅ |
| T10 执行失败后伪造成功 | ✅ | ✅ | ✅ | ✅ |
| T11 过期 Grant | ✅ | ✅ | ✅ | ✅ |
| T12 正常路径 | ✅ | ✅ | ✅ | ✅ |
| **适用臂数** | **7** | **9** | **11** | **11** |

N/A 不是失败，而是该架构不存在对应角色或证据字段；逐项理由写入 `results/attack_results.json::meta.na_reason` 与 `THREAT-MODEL.md` §4。C/D 中 T3 与 T7 经过同一 DS 公钥验签边界，是**同一类密钥来源验证**，不是两种独立密码学防御性质。

---

## 4. 攻击语义与指标（R1 修订要点）

- **T4**：执行**授权** Sales 查询，但返回另一条**真实存在**的 Finance 结果（不重新执行 Finance）。Ground truth 分别记录 `actual_query_result_digest` 与 `returned_output_digest`；**ASR 只数真实越权执行，结果泄露单独计** `unauthorized_result_disclosure`。
- **T5**：正式攻击前先用独立 seed request 生成一份合法历史响应并原样保存；T5 在**新的 request_id/Grant/nonce** 下原样重放旧 evidence（不改 nonce、不重签），Gateway 因当前请求绑定不匹配拒绝。seed request 不计入 N，记入 `meta.seed_requests`。
- **T10**：工具请求在**查询执行前失败**（ground truth `executed=false`），随后伪造 `status=EXECUTED`。
- **T11**：**只验证过期 Grant**，不验证过期 snapshot（本轮未实现 snapshot 过期机制）。
- **互斥分类 A/B/C/D**：A 执行前预防；B 执行后检测；C 执行后未检测且接受虚假/越权证据；D 无法判定（本轮为 0）。T12 控制组不入攻击分母。
- **指标**：ASR / PR / DR / UER / FRR + `unauthorized_result_disclosure` 计数/比例 + 端到端延迟 + 证据大小 + 进程/IPC 成本。分母定义见 `ATTACK-RESULTS.md` §2。**DR 分母为 0 记 N/A，不写 0 或 1。**

**规模**：38 臂 × N=100 = 3800 次（3400 攻击尝试 + 400 良性控制），seed=`20261125`，4 个 seed request 另计不入 N。

---

## 5. 复现命令

```bash
cd D:\Research\d3-13-independent-execution-evidence
python -m pip install -r requirements.txt

# 结构单元测试（19 项，固定 R1 攻击语义与信任边界）
python -m unittest discover -s tests -v

# 正式实验：38 臂 × 100 = 3800 次
python -m src.runner
# -> results/attack_results.json（3800 raw_samples + 汇总 + N/A + seed_requests）

# 自定义重复次数（冒烟）
D3_13_REPEATS=2 python -m src.runner
```

依赖：Python 3.13+，`cryptography>=41`（本机：Python 3.13.12 / cryptography 50）。

---

## 6. 基线与边界（冻结，全程只读）

- **基线仓库**：`kaikai-cao/agent-exec-binding-mvp`，分支 `experiment/independent-execution-proxy`，HEAD `e327a9444ed8cea17baefbac01587b7fa77e8d39`（未修改）。
- **R0**：本实验 R0 = `22cc839eb41a15ff38580ac918361ccaf5a158e2`（分支 `exp-d3-13-independent-execution-evidence`，保持不变）。本 R1 从该固定 commit 新建独立分支。
- **不外推**：单主机、mock 只读工具、进程级隔离、无真实外部数据源、无 TEE、无 Halo2；D 依赖可信实验 Oracle。结论只在受控夹具内成立。

---

## 7. 文件索引

| 文件 | 内容 |
|---|---|
| `THREAT-MODEL.md` | 角色/攻击能力/信任假设/H1–H5、T1–T12 适用性规格与 N/A 理由 |
| `ARCHITECTURE-COMPARISON.md` | A/B/C/D 信任边界与源码级隔离事实；D=Oracle-assisted |
| `ATTACK-RESULTS.md` | T1–T12 实测矩阵、指标分母、逐次计数、R0→R1 变化 |
| `ZKP-INCREMENTAL-VALUE.md` | ZKP 相对签名/承诺/访问控制/透明日志的真实增量分析 |
| `DECISION.md` | H1–H5 判定、D 的 Oracle 边界、开放问题、ZKP 门禁结论 |
| `src/` | 架构实现、指标、一致性判定、runner |
| `tests/` | 19 项单元测试（固定 R1 攻击语义） |
| `results/` | 3800 条逐次原始 JSON + 运行日志 |
