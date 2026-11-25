# D3-13-01-R1 — 威胁模型

**状态**：受控实验威胁模型｜日期：2026-11-25｜证据等级：R0 定义 + R1 语义修订 + R1 实测
**配套**：`README.md`、`ATTACK-RESULTS.md`、`ARCHITECTURE-COMPARISON.md`

---

## 1. 角色与信任边界

| 角色 | 记号 | 拥有 | 默认是否可信 |
|---|---|---|---|
| Agent / Adapter | A | 授权 Grant、发起请求 | **可恶意**（攻击主体） |
| Proxy | P | 转发请求/响应；B 中还自带签名密钥+数据集 | **可恶意** |
| Data Service | DS | 真实数据集 + 自生成 Ed25519 私钥 | C/D 默认诚实；T8/T9 显式放开 |
| Gateway | G | Issuer 公钥、固定 pin 的 DS 公钥、授权校验 | 本轮假设诚实（P-G 合谋仅登记，不实现） |
| Oracle-assisted Observer | O | 从**可信实验 Oracle 通道**读取执行记录 + 独立签名密钥 | D 中默认诚实；**模拟角色**，非生产观测 |

**四个分离层级**（本轮核心变量）：
1. A：执行者 = 证据者 = Adapter（同进程同边界）。
2. B：执行者 = 证据者 = Proxy（**独立进程但同一信任边界**：Proxy 自生成密钥、自带数据集、自签 evidence，Gateway pin 的公钥来自 Proxy 启动自报——TOFU）。
3. C：执行者 = DS（独立进程、自生成密钥、自有数据集），Proxy 纯转发；Gateway 直接持有 DS 公钥并做逐字段绑定。
4. **D（Oracle-assisted Observer）**：C + Observer 旁路取证，但观测记录来自 `truth_shared`——**受控模拟中的可信测试 Oracle**。

> **硬边界**：进程隔离 ≠ 信任隔离（B 与 A 攻击结果相同，R1 实测证实）；可信 Oracle 下的检出 ≠ 生产级独立观测 ≠ 解决 H4。

---

## 2. 攻击能力分层（攻击者控制什么）

| 攻击能力 | 控制对象 | 不控制 |
|---|---|---|
| 恶意 Adapter（A） | tool call 参数、Receipt 生成（同签名密钥） | Issuer 私钥、Grant payload |
| 恶意 Proxy（B/C/D） | 转发参数、output、自称的 source/snapshot、自有 Proxy 密钥 | C/D 的 **DS 私钥**、DS 数据集、Gateway 固定的 DS 公钥 |
| 恶意 DS（C/D，T8/T9） | 自己的查询结果声明 + 自己的合法签名密钥 | Issuer 私钥、Gateway 对其他字段的期望值 |
| DS + Proxy 合谋（T9） | 双方协同构造自洽响应 | Issuer 私钥；D 中 Oracle 通道的完整性（本轮假设可信） |
| 重放者（T5） | 历史响应/Grant/nonce | 当前 nonce / request_id 的生成（由 driver 控制） |

**明确排除项**（登记不外推）：Gateway 被攻破（P-G 合谋）；Issuer 私钥泄露；TEE 远程证明伪造；真实外部数据源被入侵（DS 是 mock）；跨副本/分布式 nonce 状态；**DS 伪造或控制 Oracle 通道**（若发生，D 失去检测能力——这正是 D 只是上界的原因）。

---

## 3. 安全目标（H1–H5 的操作化）

| 目标 | 操作化判定 | R1 判定 |
|---|---|---|
| H1 执行来源认证 | evidence 上 Ed25519 签名用 Gateway 固定的 DS 公钥验过 | C/D 可（PR=1 挡住 T3/T7） |
| H2 执行语义绑定 | canonical_query_digest / nonce / grant_id / request_id 绑定当前授权 | C/D 可（PR=1 挡住 T2/T5） |
| H3 来自 DS 执行边界 | 有 DS 进程内实际执行的 ground-truth 记录 | C/D 可取证（`truth_shared`）；A/B 无独立边界 |
| H4 DS 没撒谎 | 签名声明与真实执行一致 | **C 不可**（T8 UER=1、T9 UER=1 DR=0）；**D 仅在可信 Oracle 下检出**（T8/T9 observer_inconsistency，B 类 100/100、UER=0；T9 DR=1，T8 DR=N/A）。**H4 正式状态仍为 OPEN** |
| H5 Oracle 前提下的不一致检测 | 在可信 Oracle 提供真实执行记录的前提下，观测机制能否检测 DS 声明与执行记录的不一致 | D 可（理想条件下界）；**不代表生产条件下成立** |

**不可让步的区分**：H1/H2 成立 **不代表** H4 成立；DS 签名有效 ≠ 真实世界真实性；独立进程 ≠ 独立信任；日志可追加 ≠ 执行事件完整；哈希绑定 ≠ 外部事实真实性；**可信 Oracle 下的检出 ≠ DS 已经无法撒谎**。

---

## 4. T1–T12 逐项规格与适用性（R1 Phase 1）

记：授权查询 = Sales/2026；越权查询 = Finance/2026；"自洽虚假声明" = 用合法密钥签一份声称授权请求的回执。N/A = 该架构无对应角色或证据字段，**不映射到其他攻击**。

| ID | 名称 | 真实注入行为（R1） | 适用性 | 预期（安全目标角度） |
|---|---|---|---|---|
| T1 | 自洽虚假 Receipt | 执行者真实执行 Finance，签 request_hash=Sales 回执 | A/B；C/D N/A | A/B 接受（E2.2 反例） |
| T2 | 查询参数篡改 | 参数从 Sales 改成 Finance 后执行 | 全架构 | A/B 接受；C/D 的 DS 对照 Grant request_hash **执行前拒绝**（ASR=0、PR=1） |
| T3 | Proxy 自签虚假 Evidence | Proxy 用**自己**私钥伪造 evidence（信任来源问题，区别于 T1 的执行/声明不一致） | B/C/D；A N/A | B TOFU 接受；C/D 固定 DS 公钥验签拒绝 |
| T4 | 结果替换 | **执行授权 Sales**，但返回另一条**真实存在**的 Finance 结果（不重跑 Finance）；truth 分记执行结果摘要与返回输出摘要 | 全架构 | A/B 接受（UER=1，ASR=0，披露=1）；C/D 因 result_digest 不匹配检出（B 类） |
| T5 | 历史响应重放 | seed request 生成合法历史响应并原样保存；T5 在**新 request_id/Grant/nonce** 下原样重放旧 evidence（不改 nonce、不重签） | 全架构 | 全部因当前请求绑定/nonce 不匹配拒绝（PR=1）；seed 不计入 N |
| T6 | 证据字段篡改 | B：Proxy 改自己签的 source/snapshot 后用自己的密钥重签（B Gateway 不绑定该字段→接受，但 truth 判为虚假）；C/D：DS 签后 Proxy 改 source_id/snapshot_id | B/C/D；A N/A | B 接受（暴露绑定缺口）；C/D 因 DS 签名无效拒绝 |
| T7 | 伪造 DS 身份/签名 | Proxy 用自己密钥签声称来自指定 DS 的 evidence | C/D；A/B N/A | C/D 因 DS 公钥验签拒绝；与 T3 同类密钥来源边界 |
| T8 | 恶意 DS 合法密钥签假结果 | DS **执行授权 Sales**，但用真实私钥签 Finance 假结果 | C/D；A/B N/A | **签名必然有效**；C 接受（UER=1、ASR=0、披露=1）；D 在 Oracle 下检出 |
| T9 | DS + Proxy 合谋 | DS 真实执行 Finance，签伪装成授权查询的 digest | C/D；A/B N/A | C 接受（ASR=1、UER=1、DR=0）；D 在 Oracle 下检出（DR=1） |
| T10 | 执行失败后伪造成功 | 工具在**查询执行前失败**（`executed=false`），随后伪造 `status=EXECUTED` | 全架构 | A/B 接受（虚假成功证据，UER=1）；C/D Proxy 无 DS 私钥，伪造证据被拒（PR=1） |
| T11 | 过期 Grant | 签名有效的 Grant，`expires_at` 已过期，执行前拒绝 | 全架构 | 全部拒绝（PR=1）。**仅验证过期 Grant，不代表验证过期 snapshot** |
| T12 | 正常路径 | 全角色诚实，合法 Sales 查询成功返回 | 全架构 | 接受（FRR 控制组，不入攻击分母） |

**N/A 汇总（10 项）**：A: T3/T6/T7/T8/T9（A 无独立 Proxy、无 DS、Receipt 无 source/snapshot/query 字段）；B: T7/T8/T9（B 无独立 DS）；C: T1、D: T1（C/D 不再用 MVP Adapter Receipt 作可信证据，Proxy 自签伪造由 T3/T7 覆盖）。

**T8/T9 解释纪律**：用于确认**独立签名的信任边界**，不是要求签名协议解决"恶意签名者撒谎"。若报告成"签名验证失败"即为实现/威胁模型错误——R1 实测 T8 在 C 下 `accepted=True`、reason=`accepted`（签名有效），符合正确解释。

---

## 5. 每次尝试的必记字段（R1 Phase 2）

`run_id`、`arch`、`attack`、`accepted`、`detected`、`reason`、`class`、`executor_role`、`executed`、`actual_query_where`、`actual_query_result_digest`、`returned_output_digest`、`unauthorized_execution`、`unauthorized_result_disclosure`、`false_evidence_accepted`、`observation`、`is_control`。

`false_evidence_accepted` 由 **Evidence 与 ground truth 的字段比对**计算（`src/consistency.py`），不按攻击编号赋值。3800 条逐次记录见 `results/attack_results.json::raw_samples`；4 条 seed request 见 `meta.seed_requests`（不计入 N）。所有 ASR/PR/DR/UER/FRR/披露率均可由 raw_samples 重算（R1 已逐臂校验零偏差）。
