# D3-13-01-R1.1 — 四种架构对比与信任边界

**状态**：构造对比（R1.1 源码核对 + R1.1 实测）｜日期：2026-11-25

---

## 1. 四架构总览（R1 术语：D = Oracle-assisted Observer）

| 维度 | A Adapter Receipt | B Independent Proxy | C Signed Data Service | D Oracle-assisted Observer |
|---|---|---|---|---|
| 执行查询的进程 | 主进程（Adapter） | Proxy 子进程 | DS 子进程 | DS 子进程 |
| 数据集归属 | Adapter | **Proxy 子进程自建** | **DS 子进程自有** | DS 子进程自有 |
| 证据签名密钥 | Adapter 私钥 | **Proxy 自生成** | **DS 自生成** | DS 私钥 + Observer 私钥 |
| Gateway 验签公钥来源 | Adapter 自报（pin） | **Proxy 启动自报（TOFU）** | **直接从 DS 进程读取** | 同 C + Observer 公钥 |
| Proxy 是否持有 DS 私钥 | 不适用 | 不适用 | **否**（构造保证） | 否 |
| nonce/request_id 生成方 | Grant（Issuer） | Grant（Issuer） | **driver 可信侧** | driver 可信侧 |
| 证据字段绑定 | receipt 绑定 | 自签字段 | **10 字段签名 + G 侧逐字段绑定** | 同 C + Observer 交叉核对 |
| 独立执行 record | 无 | 无（Proxy 自报） | 有（DS 写 truth_shared） | 有 + Observer 独立签名（**读 Oracle 通道**） |
| 默认信任假设 | Adapter 诚实 | Proxy 诚实 | DS 诚实 | DS 诚实；Observer 依赖**可信实验 Oracle** |
| 适用攻击臂 | 7 | 9 | 11 | 11 |

---

## 2. 源码级隔离事实（可审查点）

用户要求重点审查"C 方案是否真正独立"。以下为逐条可核事实：

### 2.1 DS 私钥只在 DS 进程内生成

`src/architectures.py::_ds_process`：
```python
def _ds_process(req_q, resp_q, issuer_pk, truth_shared):
    ds_signer = Ed25519Signer.generate()   # DS 自己生成，不经任何外部传入
    records = copy.deepcopy(RECORDS)        # DS 自有数据集
```
父进程 `ArchCSignedDataService` **只持有** `self.ds_pk`（从 DS 进程读取的公钥），没有 `ds_signer` / `ds_private_key` 属性（单测 `test_ds_key_never_reaches_proxy` 断言）。

### 2.2 Proxy 转发进程没有任何 DS 密钥参数

`src/architectures.py::_forward_proxy_process` 签名：
```python
def _forward_proxy_process(req_q, resp_q, ds_req_q, ds_resp_q):
    proxy_signer = Ed25519Signer.generate()  # 仅 Proxy 自己的密钥（演示伪造失败）
```
参数只有四个队列，**无 DS 密钥、无数据集**。Proxy 只能通过队列把请求转给 DS、拿回 DS 签好的 evidence，自己无法生成 DS 签名。

> **若 Proxy 能控制 DS 私钥、输入或执行结果，则只是把信任问题转移位置。** 本构造排除这三点：私钥不共享、查询由 DS 独立重验 Grant（T2 执行前拒绝）、结果由 DS 在自己数据集上执行产生。
>
> **Proxy 可尝试的动作（更正 R1 的错误表述）**：恶意 Proxy 可以**尝试** T2 参数篡改、T3/T7 伪造 DS 签名、T4 结果替换、T5 历史响应重放、T6 字段篡改、T10 失败后伪造成功。C/D 通过 DS 密钥验签与请求绑定把这些动作**阻断或检出**：T2 在 DS 执行前拒（A 类），T3/T4/T5/T6/T7/T10 在 Gateway 验证阶段拒（B 类，提交后检测）；全部 UER=0（R1.1 实测）。**T8/T9 需要恶意 DS 或 DS+Proxy 合谋主体参与**，不属于 Proxy 单方面攻击。R1 文档曾误写"Proxy 能做的仅是 T4 和 T6"，已更正。

### 2.3 nonce 由可信侧生成，不由 Proxy 决定

`src/runner.py::_grant_for` 生成 `nonce = f"{SEED}-{run_id}-nonce"`（driver 侧），DS 侧强制校验 `msg["nonce"] == grant.payload["nonce"]`，Gateway 用同一 nonce 做字段绑定。Proxy 无法自选新鲜性参数。

### 2.4 D 的 Observer 通道：独立进程 ≠ 生产级独立观测（R1 核心修正）

DS 把真实执行记录写入 `truth_shared[run_id]`，Observer 进程从该通道读取并独立签名；`_forward_proxy_process` 的参数里**没有** `truth_shared`，Proxy 拿不到该通道。

> **R1 诚实定性**：`truth_shared` 是**受控模拟中的可信测试 Oracle**——我们假设它如实保存了 DS 的真实执行记录。它**不是**生产级独立观测接口，不等价于 TEE、远程证明或外部审计。D 的结果是"**给定可信执行记录时，能检测多少不一致**"的**理想上界**：若恶意 DS 能控制/伪造该通道（T8/T9 的合谋扩展），D 立即失去检测能力。**因此 H4 仍然 OPEN，D 并未解决"DS 有没有撒谎"。** 单测 `test_d_t8_t9_detected_under_trusted_oracle` 的命名与注释明确标注了 Oracle 前提。

---

## 3. B 为什么"独立但不独立"

B 的 Proxy 在独立进程运行，看似隔离，但：私钥由 Proxy 自己 `generate()`；Gateway pin 的公钥来自 Proxy 启动自报（`self.pinned_pk = self.proc.public_key()`，TOFU）；数据集由 Proxy 子进程自建；evidence 由 Proxy 自己签。因此 B 与 A 在攻击结果上一致（R1 实测两者恶意臂 UER=1.0）。这验证用户的核心判断："把 Proxy 的输出放进电路只会把自洽声明证明得更漂亮，不会让声明更真实。"

---

## 4. 成本对比（R1，N=100 均值，来自 results/attack_results.json）

| 架构 | 额外进程数 | IPC 往返/请求 | 端到端延迟（T12 正常路径） | T12 证据大小 |
|---|---|---|---|---|
| A | 0 | 0 | ~0.27 ms | ~652 B |
| B | 1 | 1 | ~0.57 ms | ~862 B |
| C | 2 | 3 | ~0.72 ms | ~601 B |
| D | 3 | 4 | ~1.08 ms | ~1141 B（DS evidence + Observer evidence） |

> R1 修正：T12 控制组此前延迟/证据大小被计为 0（分类提前 return 的副作用），现已修正为实测累计；D 的 T12 证据大小包含 Observer evidence。延迟为单机 mock 端到端墙钟时间，**不拆分**"证据生成"/"Gateway 验证"（跨进程强行拆分会引入不可靠测量点）。R0 中"首轮 ~6 ms 含进程启动"的表述**已删除**——计时点在架构启动之后，本轮未独立测量进程启动时间，故不报告。不外推为生产系统性能，也不宣称任何相对性能优势。

---

## 5. 对比结论（R1.1）

1. **进程隔离本身不带来安全性**：B ≈ A。
2. **证据产生权转移 + 密钥隔离 + 字段绑定带来实质改进**：C 挡住全部 Proxy 单方面作恶——T2/T11 执行前预防（A 类，PR=1），T3/T4/T5/T6/T7/T10 提交 Gateway 后验签/绑定检出（B 类，PR=0 但 UER=0）。R1.1 更正了"这些全是预防（PR=1）"的误述：伪造响应已提交到验证流程，属于检测而非预防。
3. **T10 签名对象修复（R1.1）**：Proxy 伪造 DS evidence 现在对真实提交的 payload 签名；密码学断言证明 Proxy 公钥可验、DS 公钥不可验，Gateway `ds_signature_invalid` 拒绝可归因于密钥来源验证，不再是无关 Bug。
4. **C 止步于 H2**：T8/T9（恶意/合谋 DS）仍通过——信任边界从"执行代理"移到"数据服务"，但没有消失；H4 保持 OPEN。
5. **D 在可信 Oracle 假设下可检出 T8/T9**（理想上界），代价是额外进程与通信；**不是**生产级独立观测，也**不等于**已解决 H4。
