# D3-13-01 — Independent Execution Evidence（独立执行证据来源与信任边界实验）

**阶段**：D3-13-01｜**日期**：2026-11-25｜**性质**：受控攻击实验 + 构造对比，**非**新电路、**非**新证明系统
**前序**：RESEARCH-ASSET-RECOVERY-01 候选 1（授权→真实执行效果绑定）
**本轮不研究**：新 SNARK 构造、跨组织匿名凭证、递归证明、生产级 TEE、Halo2 电路

---

## 1. 研究问题（收紧后）

先解决 **"谁有资格证明执行确实发生了"**，再讨论如何用 ZKP 隐藏执行证据。

MVP 的 `IndependentExecutionProxy` 把执行主体从 Adapter 分离到独立进程，但 Proxy **同时**是执行者与证据生成者（自带签名密钥、自带数据集、自签 evidence）。把它直接送进 Halo2 只会把自洽声明证明得更漂亮，不会让声明更真实。因此本轮**不做新电路**，而是做有明确攻击目标、有对照组、有量化指标的实验。

### 两个必须分开的命题

- **H1 执行来源认证**：Gateway 能否确认结果确实由指定 Data Service 返回，而非 Proxy 自造？→ 独立签名密钥 + 请求绑定 + 新鲜性可答。
- **H2 执行语义真实性**：Data Service 声称的查询/结果是否对应它实际处理的数据与操作？→ 签名只证明"DS 作出了这个声明"，**不自动证明 DS 没撒谎**；必须明确 DS 的信任假设。

本轮进一步拆成五个判定问题 H1–H5，见 `DECISION.md`。

---

## 2. 四种对照架构

| 方案 | 证据由谁产生 | 密钥归属 | 主要信任假设 |
|---|---|---|---|
| A Adapter Receipt | Adapter | Adapter | Adapter 诚实（MVP E2.2 基线） |
| B Independent Proxy | Proxy（独立进程） | Proxy **自生成** | Proxy 诚实 |
| C Signed Data Service | 独立 DS 进程 | DS **自生成**，Proxy 不持有 | DS 诚实 + Gateway 字段绑定 |
| D Independent Observer | C + 独立 Observer | Observer 独立签名 | Observer 能独立获得真实执行记录 |

**关键隔离事实（源码可核）**：
- C 的 DS 在**独立进程**内 `Ed25519Signer.generate()`，Gateway 的 `ds_pk` 从 DS 进程直接读取；Proxy 转发进程的参数里只有队列，**没有任何 DS 密钥**（`_forward_proxy_process` 签名 + `ArchCSignedDataService.__init__`）。
- nonce 与 request_id 由 driver（可信请求发起侧）生成并传入，不由 Proxy 决定（`runner.py::_grant_for` + `ArchCSignedDataService.execute`）。
- D 的 Observer 从 DS 写入的旁路记录（`truth_shared`，Proxy 从不接收该通道）独立取证并签名。

> **D 组边界**：Observer 用独立测试进程 + 受控记录**模拟**，不宣称等价于生产级外部观测、TEE 或远程证明。

---

## 3. 攻击与指标

- **12 个攻击 T1–T12**：恶意 Adapter/Proxy/DS、各类合谋、重放、结果替换、参数篡改、身份伪造、过期授权、正常路径。逐项前提/步骤/预期见 `THREAT-MODEL.md`，实测见 `ATTACK-RESULTS.md`。
- **互斥分类 A/B/C/D**：A 执行前预防；B 执行后检测；C 执行后未检测；D 无法判定。T12 为控制组，不入攻击分母。
- **指标**：ASR / PR / DR / UER / FRR + 正常接受率 + 证据生成/验证时延 + 证据大小 + 进程与通信成本。分母定义见 `ATTACK-RESULTS.md` §2。
- **确定性**：每组 N=100，`seed=20261125`，nonce/request_id 由 run_id 确定性派生；无随机策略。

---

## 4. 复现命令

```bash
cd D:\Research\d3-13-independent-execution-evidence
python -m pip install -r requirements.txt

# 结构单元测试（11 项，固定信任边界行为）
python -m unittest discover -s tests -v

# 正式实验：4 架构 × 12 攻击 × 100 次 = 4800 次
python -m src.runner
# 输出 results/attack_results.json（逐次元数据 + 汇总）

# 自定义重复次数
D3_13_REPEATS=20 python -m src.runner
```

依赖：Python 3.13+，`cryptography>=41`（本机验证：Python 3.13.14 / cryptography 50.0.2）。

---

## 5. 基线与边界（冻结，不改动）

- **基线仓库**：`kaikai-cao/agent-exec-binding-mvp`，分支 `experiment/independent-execution-proxy`，HEAD `e327a9444ed8cea17baefbac01587b7fa77e8d39`。只读获取，本轮未修改。
- **E2.2 原始结果**：`research/e-stage-results-v0.1.md` §3.3，`UER=1.0, DR=0`；本轮 A 架构在相同夹具语义下重放该反例。
- **不适用外推**：单主机、mock 只读工具、进程级隔离、无真实外部数据源、无 TEE、无 Halo2。结论只在受控夹具内成立。

---

## 6. 文件索引

| 文件 | 内容 |
|---|---|
| `THREAT-MODEL.md` | 角色、攻击能力、信任假设、安全目标、T1–T12 逐项规格 |
| `ARCHITECTURE-COMPARISON.md` | A/B/C/D 信任边界与代码级隔离事实 |
| `ATTACK-RESULTS.md` | T1–T12 逐项实测、指标、分母、原始计数 |
| `ZKP-INCREMENTAL-VALUE.md` | ZKP 相对签名/承诺/访问控制/透明日志的真实增量分析 |
| `DECISION.md` | H1–H5 判定、开放问题、是否具备进入 ZKP 原型条件 |
| `src/` | 架构实现、指标、一致性判定、runner |
| `tests/` | 单元测试（固定信任边界行为） |
| `results/` | 逐次原始 JSON + 运行日志 |
