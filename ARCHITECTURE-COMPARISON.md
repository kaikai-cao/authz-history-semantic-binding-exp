# D3-13-01 — 四种架构对比与信任边界

**状态**：构造对比（R1 源码核对 + R3 实测）｜日期：2026-11-25

---

## 1. 四架构总览

| 维度 | A Adapter Receipt | B Independent Proxy | C Signed Data Service | D Independent Observer |
|---|---|---|---|---|
| 执行查询的进程 | 主进程（Adapter） | Proxy 子进程 | DS 子进程 | DS 子进程 |
| 数据集归属 | Adapter | **Proxy 子进程自建** | **DS 子进程自有** | DS 子进程自有 |
| 证据签名密钥 | Adapter 私钥 | **Proxy 自生成** | **DS 自生成** | DS 私钥 + Observer 私钥 |
| Gateway 验签公钥来源 | Adapter 自报（pin） | **Proxy 启动自报（TOFU）** | **直接从 DS 进程读取** | 同 C + Observer 公钥 |
| Proxy 是否持有 DS 私钥 | 不适用 | 不适用 | **否**（构造保证） | 否 |
| nonce/request_id 生成方 | Grant（Issuer） | Grant（Issuer） | **driver 可信侧** | driver 可信侧 |
| 证据字段绑定 | 8 项 receipt 绑定（MVP） | 11 项自签字段 | **10 字段签名 + G 侧逐字段绑定** | 同 C + Observer 交叉核对 |
| 独立执行 record | 无 | 无（Proxy 自报） | 有（DS 写 truth_shared） | 有 + Observer 独立签名 |
| 默认信任假设 | Adapter 诚实 | Proxy 诚实 | DS 诚实 + 字段绑定 | DS 诚实可被 Observer 证伪 |

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
父进程 `ArchCSignedDataService` **只持有** `self.ds_pk`（公钥，`ds.public_key()` 从 DS 进程读取），没有 `ds_signer` / `ds_private_key` 属性（单元测试 `test_ds_key_never_reaches_proxy` 断言这一点）。

### 2.2 Proxy 转发进程没有任何 DS 密钥参数

`src/architectures.py::_forward_proxy_process` 签名：
```python
def _forward_proxy_process(req_q, resp_q, ds_req_q, ds_resp_q):
    proxy_signer = Ed25519Signer.generate()  # 仅 Proxy 自己的密钥（用于演示伪造失败）
```
参数只有四个队列，**无 DS 密钥、无数据集**。`ArchCSignedDataService.__init__` 里 Proxy 服务的构造：
```python
self.proxy = _ProcService("C-forward-proxy", _forward_proxy_process,
                          (self.ds_req_q, self.ds_resp_q))
```
Proxy 只能通过队列把请求转给 DS，拿回 DS 签好的 evidence，自己无法生成 DS 签名。

> **若 Proxy 能控制 DS 私钥、输入或执行结果，则只是把信任问题转移位置。** 本构造排除这三点：私钥不共享、查询由 DS 独立重验 Grant、结果由 DS 在自己数据集上执行产生。Proxy 能做的仅是 T4（替换 output）和 T6（篡改字段），而这两者都会被 Gateway 的 `result_digest` / 字段绑定检测到（实测 C 的 T4/T6 均为 B 类，检测成功）。

### 2.3 nonce 由可信侧生成，不由 Proxy 决定

`src/runner.py::_grant_for` 与 `ArchCSignedDataService.execute`：
```python
nonce = f"{SEED}-{run_id}-nonce"   # driver 生成
grant = issue_grant(issuer, ..., nonce=nonce)
result = arch.execute(attack, run_id, grant, request_id, nonce)
```
DS 侧强制校验 `msg["nonce"] == grant.payload["nonce"]`，Gateway 侧用同一 nonce 做字段绑定与一次性消费。Proxy 无法自选新鲜性参数。

### 2.4 Observer 旁路通道独立于 Proxy

DS 把真实执行记录写入 `truth_shared[run_id]`，Observer 进程从该通道读取并独立签名。`_forward_proxy_process` 的参数里**没有** `truth_shared`，Proxy 拿不到该通道。因此 D 的 Observer 证据是超出 Proxy 自我声明的独立证据。

> **D 的诚实边界**：Observer 用受控测试进程 + DS 写入的记录模拟，不宣称等价于生产级外部观测、TEE 或远程证明。若真实部署中 Observer 也只能看到 Proxy 提供的数据，则 D 退化为 B。

---

## 3. B 为什么"独立但不独立"

B 的 Proxy 在独立进程运行，看似隔离，但：
- 私钥由 Proxy 自己 `generate()`；
- Gateway pin 的公钥来自 Proxy 启动自报（`self.pinned_pk = self.proc.public_key()`）——**与 MVP 的 TOFU 一致**；
- 数据集由 Proxy 子进程自建；
- evidence 由 Proxy 自己签。

因此 B 与 A 在攻击结果上完全相同（实测两者 T1–T10 UER=1.0）。这直接验证用户的核心判断："如果现在直接把 Proxy 的输出放进 Halo2 电路，只会把它的自洽声明证明得更漂亮，并不会让声明更真实。"

---

## 4. 成本对比（100 次均值，来自 results/attack_results.json）

| 架构 | 额外进程数 | IPC 往返/请求 | 端到端延迟（正常路径，量级） | 证据大小 |
|---|---|---|---|---|
| A | 0 | 0 | ~0.25 ms | ~612 B |
| B | 1 | 1 | ~0.58 ms | ~802 B |
| C | 2 | 3 | ~0.6 ms（预热后；首轮含进程启动 ~6 ms） | ~599 B |
| D | 3 | 4 | ~0.95–1.06 ms | ~599 B（+ Observer 证据） |

> 延迟为单机 mock 进程通信的端到端墙钟时间，不拆分"证据生成"/"Gateway 验证"（跨进程强行拆分会引入不可靠测量点）。**不外推为生产系统性能**，也不宣称任何相对性能优势。

---

## 5. 对比结论

1. **进程隔离本身不带来安全性**：B ≈ A。
2. **证据产生权转移 + 密钥隔离 + 字段绑定带来实质改进**：C 挡住全部 Proxy 作恶（T1/T2/T3/T5/T7/T10 预防，T4/T6 检测）。
3. **C 止步于 H2**：T8/T9（恶意/合谋 DS）仍通过——信任边界从"执行代理"移到"数据服务"，但没有消失。
4. **D 用独立观测把 H4 从"不可达"变为"可检测"**：代价是额外进程与通信。
