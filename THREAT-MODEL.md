# D3-13-01 — 威胁模型

**状态**：受控实验威胁模型｜日期：2026-11-25｜证据等级：R0 定义 + R3 本轮实测
**配套**：`README.md`、`ATTACK-RESULTS.md`、`ARCHITECTURE-COMPARISON.md`

---

## 1. 角色与信任边界

| 角色 | 记号 | 拥有 | 是否可信（默认） |
|---|---|---|---|
| Agent / Adapter | A | 授权 Grant、发起请求 | **可恶意**（攻击主体） |
| Proxy | P | 转发请求/响应；在 B 中还自带签名密钥+数据集 | **可恶意** |
| Data Service | DS | 真实数据集 + 自生成 Ed25519 私钥 | C/D 中默认诚实，但 T8/T9 显式放开 |
| Gateway | G | Issuer 公钥、DS 公钥（可信固定）、授权校验 | 本轮假设诚实（P-G 合谋仅登记，不实现） |
| Independent Observer | O | 独立执行记录通道 + 独立签名密钥 | D 中默认诚实；模拟角色 |

**四个分离层级**（本轮核心变量）：
1. A：执行者 = 证据者 = Adapter（同进程同边界）。
2. B：执行者 = 证据者 = Proxy（**独立进程但同一信任边界**：Proxy 自生成密钥、自带数据集、自签 evidence，Gateway pin 的公钥来自 Proxy 启动自报）。
3. C：执行者 = DS（独立进程、自生成密钥、自有数据集），Proxy 仅转发；Gateway 直接持有 DS 公钥并做字段绑定。
4. D：C + Observer 旁路独立取证。

> **硬边界**：进程隔离 ≠ 信任隔离。B 有独立进程但没有独立信任，所以 B 与 A 的攻击结果应相同（本轮实测确实相同）。

---

## 2. 攻击能力分层（攻击者控制什么）

| 攻击能力 | 控制对象 | 不控制 |
|---|---|---|
| 恶意 Adapter（A） | tool call 参数、Receipt 生成（同签名密钥） | Issuer 私钥、Grant payload |
| 恶意 Proxy（B/C/D） | 转发请求参数、output、自称的 source/snapshot、自有 Proxy 密钥 | C/D 的 **DS 私钥**、DS 数据集、Gateway 固定的 DS 公钥 |
| 恶意 DS（C/D，T8/T9） | 自己的查询结果声明 + 自己的合法签名密钥 | Issuer 私钥、Gateway 对其他字段的期望值 |
| DS + Proxy 合谋（T9） | 双方协同构造自洽响应 | Issuer 私钥；D 中 Observer 的独立记录通道 |
| 重放者 | 历史响应/Grant/nonce | 新鲜 nonce 的生成（由 driver 控制） |

**明确排除项**（不在本轮攻击能力内，登记不外推）：
- Gateway 被攻破（P-G 合谋）；Issuer 私钥泄露；TEE 远程证明伪造；真实外部数据源被入侵（本轮 DS 是 mock）；跨副本/分布式 nonce 状态。

---

## 3. 安全目标（H1–H5 的操作化）

| 目标 | 操作化判定 | 本轮可否达成 |
|---|---|---|
| H1 执行来源认证 | evidence 上的 Ed25519 签名用 Gateway 固定的 DS 公钥验过 | C/D 可（PR=1 挡住 T3/T7） |
| H2 执行语义绑定 | canonical_query_digest / nonce / grant_id / request_id 绑定当前授权 | C/D 可（PR=1 挡住 T2） |
| H3 来自 DS 执行边界 | 有 DS 进程内实际执行的 ground-truth 记录 | C 可取证（truth_shared）；A/B 无独立边界 |
| H4 DS 没撒谎 | 签名声明与真实执行一致 | **C 不可**（T8 UER=1）；D 可检测（T8/T9 虚假声明 B 类 100/100、UER=0；T9 DR=1，T8 DR=N/A 因无越权执行分母） |
| H5 Observer 超出自我声明 | Observer 证据与执行者自报能不一致并被发现 | D 可（T8/T9 均 observer_inconsistency，B 类 100/100） |

**不可让步的区分**：H1/H2 成立 **不代表** H4 成立；DS 签名有效 ≠ 真实世界真实性；独立进程 ≠ 独立信任；日志可追加 ≠ 执行事件完整；哈希绑定 ≠ 外部事实真实性。

---

## 4. T1–T12 逐项规格

记：授权查询 = Sales/2026；越权查询 = Finance/2026；"自洽虚假声明" = 用合法签名密钥签一份声明授权请求、但实际执行越权查询（或签假结果）的回执。

| ID | 名称 | 攻击前提 | 攻击步骤 | 预期结果（安全目标角度） | 注入到 |
|---|---|---|---|---|---|
| T1 | 恶意执行者自洽虚假 Receipt | 执行者持有合法签名密钥 | 执行 Finance 查询，签 request_hash=Sales 的回执 | 应被阻断；A/B 实际接受（E2.2 反例） | Adapter/Proxy |
| T2 | 篡改查询参数 | 能改转发参数 | 把 Sales 改成 Finance，其余字段一致 | 应被 DS 的 grant 绑定挡住 | Proxy |
| T3 | 自签虚假 Evidence | 有自己的合法密钥 | 自造 Finance output 并用自己密钥签 | 应被 Gateway 用 DS 公钥验签挡住 | Proxy |
| T4 | 替换另一条真实查询结果 | 能改 output | 用另一真实查询结果覆盖当前 output | 应被 result_digest 绑定挡住 | Proxy |
| T5 | 重放历史响应 | 持有历史响应/Grant | 重放旧 nonce 的响应 | 应被 nonce 新鲜性挡住 | Proxy |
| T6 | 篡改 source_id/snapshot_id/query_digest | 能改证据字段 | 改这些字段（不重新用 DS 密钥签） | 应被签名字段绑定挡住 | Proxy |
| T7 | 伪造 DS 身份/签名 | 有自己的 Proxy 密钥 | 冒充 DS 签名 | 应被 DS 公钥验签挡住 | Proxy |
| T8 | 恶意 DS 合法密钥签假结果 | DS 私钥合法、DS 可撒谎 | DS 执行授权 Sales 查询，但签 Finance 结果的 digest | **签名必然有效**；C 无法挡，需 Observer | DS |
| T9 | DS+Proxy 合谋自洽响应 | DS 与 Proxy 协同 | 执行 Finance 查询，DS 签伪装成授权查询的 digest | C 无法挡；需 Observer | DS+Proxy |
| T10 | 失败伪造成功 | 能改 status/output | 请求失败但签 EXECUTED + 假 output | 应被挡住 | Proxy |
| T11 | 过期授权/snapshot | 持有过期 Grant | 用 expires_at 已过的 Grant | 应被时间窗挡住 | 任意 |
| T12 | 正常路径 | 全角色诚实 | 合法 Sales 查询、合法返回 | 应接受（FRR 控制组） | 全角色 |

**T8/T9 的解释纪律**：这两个攻击用于确认**独立签名的信任边界**，不是要求签名协议解决"恶意签名者撒谎"。若实验把它们报告成"签名验证失败"，说明实现或威胁模型有误——本轮实测 T8 在 C 下 `accepted=True`、reason=`accepted`（签名有效），符合正确解释。

---

## 5. 每次尝试的必记字段

`run_id`、`arch`、`attack`、`accepted`、`detected`、`reason`、`class`、`ground_executed`、`ground_unauthorized`、`false_evidence_accepted`、`observation`。原始 4800 条见 `results/attack_results.json::raw_samples`。
