# ATTACK-HISTORIES.md — D3-15-01 八个攻击历史

基准日期：2026-11-25。每例按任务包六项要求写全：攻击者能力 / 目标性质 / 现有方案能否阻止 / 需要的信任假设 / 判定（REJECT、INDETERMINATE 或 ACCEPT）/ 为什么。
判定对象：Gateway 对「Agent 请求 + 查询结果 + 证明 + root/epoch 证据」的最终决定。
**ATK-DS / ATK-DO-negligent / ATK-DO-malicious 严格分开**（见 `TRUST-AND-THREAT-MODEL.md` §3）。

---

## H1：DS 在固定数据根下返回伪造查询结果

- **设定**：DO 已认证 root `R_e`，Gateway 独立获得同一 `R_e`。DS 用合法数据，但把 query `SELECT SUM(amount) WHERE dept='Finance'` 的结果从 1,200 改成 12,000。
- **攻击者能力**：ATK-DS；控制查询结果与证明生成输入；不能签 DO 的 root。
- **目标性质**：Query Correctness。
- **现有方案能否阻止**：**能**。ZKSQL（恶意 P 下 soundness of all query answers）、PoneglyphDB（不可信 server + 查询正确性 ZK）、TruthTable（correct execution over committed database）、RogueDB（authenticated indexes）都直接针对此。
- **需要的信任假设**：承诺固定且 Gateway 拿到的是真 root（本例满足）；SNARK soundness；电路正确实现。
- **判定**：`REJECT`（证明验证失败）；若无证明则为 `INDETERMINATE`（纯签名只能证明 DS 签了结果，不证明结果正确）。
- **为什么**：这是可验证数据库的标准威胁模型，已被充分覆盖；不构成新研究缺口。

## H2：DS 返回历史上有效、但当前已过期的数据根

- **设定**：`R_{e-3}` 曾由 DO 认证；当前已到 `R_e`。DS 重放 `R_{e-3}` 及当时合法查询证明。
- **攻击者能力**：ATK-DS；持有全部旧证明与旧 root 签名。
- **目标性质**：Freshness。
- **现有方案能否阻止**：**证明层不能，外部锚层能**。查询证明对 `R_{e-3}` 完全有效（ZKSQL/PoneglyphDB/TruthTable 都如此）；AD SoK 明确 value/history binding 不保证 read 返回最新写；但 B1 提到 signed timestamped commitment + update proof 中的变更计数支持 rollback detection，B2  threat model 依赖 gossip/auditor 发现分叉。Rampertab §11.3（D3-14 引用）有 head attestation→本地锚→witness→公链四级机制可作外部锚设计参考。
- **需要的信任假设**：Gateway 必须从**独立渠道**（DO 当前 head 签名 / witness / bulletin board 带新鲜 client nonce）确定 `latest_epoch`；该渠道不经 DS；时钟 skew 与公告延迟有界。
- **判定**：若 Gateway 独立锚确认 `latest_epoch=e` → `REJECT`；若 Gateway 只能看到 DS 提供的 root → `INDETERMINATE`，**不得 ACCEPT**。
- **为什么**：`epoch = latest_epoch` 不能在电路内自断（D3-12：无外部锚时证明者可自造公开输入）。这是外部状态问题，不是查询证明问题。

## H3：DS 对两个 Gateway 展示同一 epoch 的不同数据根

- **设定**：epoch `e`，DS 给 Gateway-1 `R_e^a` 与相应证明，给 Gateway-2 `R_e^b`（均为 DO 曾签过的不同版本，或 DS 伪造的分叉头）。
- **攻击者能力**：ATK-DS；网络分区下对不同验证者给不同视图（equivocation / oscillation）。
- **目标性质**：History Binding（B1 Def.3 的 oscillation attack 场景）。
- **现有方案能否阻止**：**能检出，需一致性机制**。AD SoK 明确 history binding 防 equivocation，且「单个 client 对恶意更新的声明不可密码学验证，但同一 label / 同一 epoch 的不一致视图可以」；GlassDB 单不可信 provider 模型下只能 fork consistency，靠用户 gossip 或可信 auditor 检出；PoneglyphDB 把承诺放以太坊（不可撤销、不可变）使所有客户看到同一承诺。
- **需要的信任假设**：存在可 gossip 的客户端群 / auditor / append-only bulletin board；网络不能永久分区（B2 明确）。
- **判定**：有独立 bulletin board 且两方比对 → `REJECT`（发现分叉）；Gateway 各自孤立且只看 DS → `INDETERMINATE`，**不得 ACCEPT**。
- **为什么**：这是认证字典的标准安全定义问题（B1），已有明确模型；但必须把一致性基础设施作为独立假设列出。

## H4：DS 使用正确的数据根，但替换 Agent 授权所绑定的查询

- **设定**：Grant 只允许 `dept='Sales'`；DS 实际执行 `dept='Finance'`，返回该查询在正确 root 上的有效证明，但声称执行的是 Sales 查询。
- **攻击者能力**：ATK-DS；控制 query 文本与 query_digest 的计算输入；不能改 Grant。
- **目标性质**：Authorization Binding。
- **现有方案能否阻止**：**能，且普通签名已够**。D3-13 C 的 10 字段签名含 `canonical_query_digest`、`grant_id`、`nonce`，Gateway 逐字段绑定；R1.1 的 T1/T2 三状态与 T6 字段篡改已实测。可验证数据库层（B1–B4）本身不管 Grant，但一旦 `query_digest` 在 Gateway 侧对当前请求重算比对，替换即失败。
- **需要的信任假设**：Gateway 持有当前 Grant 与请求原文；canonical 编码一致；DS 公钥 pin 正确（D3-13 H1）。
- **判定**：`REJECT`（query_digest 不匹配）。
- **为什么**：不是密码学新性质；把已有绑定接入查询证明是工程集成。无需新电路。

## H5：DS 重放此前合法生成的证明，试图通过新的授权请求

- **设定**：证明 `π` 对 `(q, R_e, result)` 合法且曾通过；新请求带新 `request_id` / `nonce`，DS 原样提交 `π`。
- **攻击者能力**：ATK-DS；可缓存任意历史证明。
- **目标性质**：Authorization Binding + Freshness（请求级）。
- **现有方案能否阻止**：**能，普通 nonce 绑定已够**。D3-13 C 的 nonce 由 driver 生成、逐请求更新，T5 历史响应原样重放在 R1.1 被归为 B 类（提交后被绑定检出，UER=0）。non-interactive ZK 证明本身可转移，但把 `request_id/nonce` 作为公开输入写进证明语句即可绑定。
- **需要的信任假设**：nonce 不可预测且单次使用；prover 必须把 nonce 作为约束的公开输入（否则证明可重放）。
- **判定**：`REJECT`（nonce 不匹配）；若证明语句未绑定 nonce → `INDETERMINATE` 且实现有缺陷。
- **为什么**：D3-13 已实测解决；不是新贡献。

## H6：数据所有者没有将真实发生的更新写入已认证状态

- **设定**：真实世界某账户余额从 100 变为 250，但 DO 的认证数据集仍记 100；DS 对 root `R_e` 给出「余额=100」的正确查询证明。
- **攻击者能力**：**ATK-DO-negligent**（非密码学敌手：不伪造签名、不打破承诺）；可能是漏报、采集延迟、被下游系统瞒报。
- **目标性质**：Update Completeness。
- **现有方案能否阻止**：**不能，且全部明确外置**。
  - TruthTable 作者访谈：*"does not establish that the committed data was collected honestly, complete, or otherwise fit for purpose."*（非论文原文）
  - PoneglyphDB：auditor 核的是「它从 DO 读到的原始库」与链上承诺一致；若原始库本身漏记，auditor 照样通过。
  - AD SoK：read-write consistency 约束的是「已认证更新序列」内的读写一致，不约束现实事件是否都进序列；无信任源模型下只有 history binding。
  - GlassDB：证明执行正确 + append-only，不证明写入等于真实。
- **需要的信任假设**：需要一个**独立于 DO 的真实事件源**（采集系统 / 权威对手方 / TEE 采集 + 远程证明 / 多方交叉账本），即 D3-13 H4 与 D3-14 开放项同类。
- **判定**：Gateway 仅有查询证明与 DO 根 → `ACCEPT`（相对给定 root 结果正确），但**该 ACCEPT 只针对「认证状态内」命题，不能上读为现实真值**；若审计问题含「现实世界是否如此」→ 必须 `INDETERMINATE`。不得虚报现实层 ABSENT/真实。
- **为什么**：这是所有方案的共同边界，也是 STOP 条件第 3 条的直接触发点。ZK 无法生成缺失的事件。

## H7：数据所有者本身故意认证错误数据

- **设定**：DO 用自己合法密钥对虚构数据集签名并发布 `R_e`；DS 对该库给出完全正确的查询证明。
- **攻击者能力**：**ATK-DO-malicious**（合法密钥持有者自签假数据）；可合谋 DS（ATK-COLLUDE）。
- **目标性质**：Root Authenticity / 现实真实性。
- **现有方案能否阻止**：**不能**。
  - AD SoK 公开外包模型：客户用 source 公钥验证；*"updates, and possibly verification, become impossible if the trusted data source's key is lost or compromised."* DO 是根信任，不是被验证对象。
  - PoneglyphDB：auditor 由双方信任，若 auditor 与 DO 合谋或被收买，链条失守；这是信任假设，不是密码学保证。
  - TruthTable / ZKSQL / Rogue：承诺正确性与数据来源都在模型外。
  - D3-11/D3-13 同构结论：签名有效 ≠ 事件真实。
- **需要的信任假设**：若要求检出 DO 恶意，必须引入 DO 之外的独立观测 / 交叉签名 / 远程证明，并说明它为何能看到 DO 看不到的真相——这是新的信任基设计，不是查询证明增量。
- **判定**：Gateway 按现有机制会 `ACCEPT`（签名有效、证明有效）；**这对「认证状态内」命题是正确的**，但对「现实真实」是 false-safe。若 Gateway 的审计问题宣称现实真实性 → 必须 `INDETERMINATE`。
- **为什么**：STOP 条件第 3 条命中——若数据所有者必须被完全信任而工作没有降低该信任成本，不能宣称新密码学贡献。

## H8：多个数据源参与查询，但不同数据根的版本不一致

- **设定**：查询 join 源 A 的 `R^A_e` 与源 B 的 `R^B_{e-2}`；B 落后两版；或同一时刻两源对同一共享键给出不同值。
- **攻击者能力**：ATK-DS（故意挑旧根）+ 部分 ATK-DO-negligent（某源更新慢）。
- **目标性质**：Freshness + 多源 History Binding + 版本一致性。
- **现有方案能否阻止**：**部分能**。AD SoK 已形式化 multiple data sources / per-key trusted writers 下的 read-write consistency，并给出 `Read-write consistency ⇒ History-binding ⇒ Value-binding`；多源写入各自签名、update proof 带变更计数可检测 rollback。但「两个源之间业务上应当同步到同一逻辑时刻」是**策略/语义约束**，需外部声明版本映射；AD SoK 不替应用定义。PoneglyphDB 的 auditor 模型可扩到多源，但仍依赖双方信任的 auditor。
- **需要的信任假设**：每个源独立认证 + 每个源都有外部 epoch 锚 + 声明跨源版本一致性规则；若源间版本允许不同步，必须显式给出可接受 skew。
- **判定**：若策略声明要求 `epoch_A = epoch_B` 且实测不等 → `REJECT`；若策略允许 skew 且在界内 → `ACCEPT`；若无跨源版本规则 → `INDETERMINATE`，**不得 ACCEPT**。
- **为什么**：AD SoK 已给出底层定义；剩下的是应用策略，不是新密码原语。

---

## 横向结论（我方推论）

1. H1/H4/H5 在 B3（查询证明 + 独立认证根 + Grant/nonce 绑定）下已全部解决；这正是用户验收问题「B3 是否已经解决问题？」的核心部分——**在 ATK-DS 模型内是的**。
2. H2/H3 需要外部 epoch 锚与一致性机制（B4），AD SoK / GlassDB 已给出形式定义与实现路径；这是基础设施，不是 SNARK 创新。
3. H6/H7 不能由任何已有方案或 B4 解决；它们要求 DO 之外的真实事件信任基，属于 D3-13 H4 同类开放问题。
4. 因此：`ACCEPT` 只能在「认证状态内」语义下给出；宣称现实真实性会 false-safe。
