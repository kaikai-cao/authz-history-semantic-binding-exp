# CONSTRUCTION-SKETCH.md — D3-15-01 候选验证关系草案（仅形式化，不实现）

基准日期：2026-11-25。本文件是**分析用的最小化关系草案**，不是新协议、不是电路设计、不是论文贡献声明。本轮不写 Halo2、不写真实数据库实现。

## 1. 公开输入 / 私有见证（按任务包）

**公开输入 x**：
`(grant_digest, request_id, nonce, source_id, schema_hash, root, epoch, query_digest, result_digest)`

**私有见证 w**：
`(database, query, result, database_opening, source_evidence)`

说明：`source_evidence` 只作为被检查的私有对象出现；本草案不声称它能由电路内自证真实性。

## 2. 六项关系逐条分析（哪些需要进电路）

| # | 关系 |  expressed as | 是否需 SNARK | 依据 / 理由 |
|---|---|---|---|---|
| R1 | 当前 Grant 是否授权该查询 | `AuthCheck(grant_digest, query_digest, schema_hash, epoch)` | **不需要**；Gateway 侧明文/摘要比对即可 | D3-13 C 十字段签名 + 字段绑定已实测 H1/H2；授权策略通常是表查找，不是算术约束 |
| R2 | 查询符合允许字段、过滤条件、操作范围 | 同上，属于策略谓词；若策略私有且需隐藏才进电路 | **默认不需要** | 本轮无隐私场景；CVA 已把 request-bound ZK 关系做过 PoC（D3-14 文献 A） |
| R3 | 数据库承诺与认证 root 一致 | `CommitOpening(database, database_opening) → root` | **不需要证明一致性本身**；需 Gateway 用独立渠道确认 root 真实性 | A4 作者访谈：证明对承诺库正确执行，承诺正确性由 data owner 负责；AD SoK 公开外包模型用 source 公钥 |
| R4 | 返回结果等于指定查询在库上的结果 | `QueryExec(database, query) = result ∧ result_digest = H(result)` | **需要 SNARK/查询证明**（或专用 PIOP） | A2/A3/A4/A5 的核心；B3 之前解决 ATK-DS 伪造结果 |
| R5 | root 满足版本与新鲜度约束 | `epoch ∈ [min,max] ∧ root = anchor_at(epoch)` | **电路外**：`epoch=latest_epoch` 不能内部断言 | B1：value/history binding 不保证最新写；D3-12 无外部锚自造公开输入不 sound；B2 fork consistency 需 gossip |
| R6 | 证明绑定当前 request / nonce / Grant | `Verify(π, x)` 且 x 含 grant_digest/request_id/nonce | **部分需要**：把 nonce/request 作为公开输入约束即可，无需新电路结构 | D3-13 C 已用签名做同样绑定；ZK 版本只是把绑定移入证明语句 |

**结论**：六项里只有 R4 本质需要查询证明；R1/R2/R3/R5 是策略 / 认证 / 一致性检查，R6 是普通 public-input 绑定。**这直接支持 STOP 条件第 5 条**：ZK 没有不可替代增益，除非有明确的隐私必要性。

## 3. 完整验证流程（若未来实现，需按此拆分）

```
Gateway 侧（不进电路）：
  1. 从独立渠道取得 DO 公钥 pk_DO、当前 epoch 锚 anchor(e)、（可选）审计日志一致性证明
     —— 不经 DS；否则回到 D3-12 自造公开输入陷阱
  2. 验证 DO 对 root 的签名：Ver_pk_DO(root, epoch, source_id, schema_hash)
     —— 只证明「DO 签过」，不证明「数据真实」
  3. 重算 grant/request/nonce 绑定：query_digest ?= H(query from request)
     与当前 Grant 允许范围比对（R1/R2/R6 的非电路部分）
  4. 新鲜度检查：epoch ?= anchor(e).epoch 或落在策略允许 skew 内；
     检查公告板/witness 一致性（B1 history binding, B2 fork consistency）
  5. 验证查询证明：Verify(vk, x, π)   —— R4，唯一必须密码学验证的核心
  6. 输出判定：REJECT / ACCEPT（仅认证状态内） / INDETERMINATE（覆盖或新鲜度证据不足）
```

## 4. 普通密码学方案 vs ZK 方案对照

| 检查 | 普通方案（签名 / Merkle / AD） | ZK 方案 | 增量 |
|---|---|---|---|
| 查询结果正确 | 逐个记录签名 / Merkle 包含证明（受查询类型限制） | 通用查询证明（A2–A5） | 表达力与证明大小，不是新安全性质 |
| root 认证 | DO 签名 + 链上承诺（A3） | 把签名验证放进电路 | 无安全增量；D3-13 已证签名足够 |
| Grant / nonce 绑定 | D3-13 C 十字段签名，实测通过 | 作为公开输入约束 | 无增量 |
| freshness | witness / 公告板 / gossip（B1/B2） | 电路内自断 latest（**不成立**） | 负增量 |
| 历史一致性 | history binding / append-only（B1/B2） | 证明历史满足某关系 | 无增量；需外部一致性 |
| 数据内容隐私 | 不提供 | ZKSQL/PoneglyphDB 已提供 | 已覆盖，非本轮新贡献 |

## 5. 必要外部假设（缺任一项则该构造不成立）

1. **独立 epoch 锚**：Gateway 能从 DO / witness / bulletin board 获得当前 epoch，不经 DS。
2. **root 来源认证**：DO 公钥可信分发；DO 与 DS 不同信任主体。
3. **一致性基础设施**：公告板 append-only，或 auditor / gossip 能发现 equivocation；单不可信服务器只在 fork consistency 下检出（B2）。
4. **SNARK 可信设置 / 电路正确实现**：不虚构测量，不声称形式化验证过的实现。
5. **策略层跨源版本规则**（H8）：若多源，需声明允许的 epoch skew，否则返回 INDETERMINATE。
6. **DO-2/DO-3 外部信任**：数据收集诚实完整、真实更新都入账——若审计问题要求现实真实性，目前无方案可满足（H6/H7）。

## 6. 与本轮七性质边界的一致性

- 本草案**不**把 `Root Authenticity`、`History Binding`、`Freshness`、`Update Completeness` 归为 SNARK 可解；只把 Query Correctness 归为 SNARK 可解，把 Authorization Binding 归为签名/公开输入可解。
- 因此本草案是「B3 + B4 的外部锚部分」的诚实拆分，不是一个新密码学机制；写出来是为了说明：即使实现它，H6/H7 仍在信任基之外。
- 若未来用户要求进入原型，必须先答：`B3 是否已足够？`（本轮答案：在 ATK-DS 模型内足够）以及 `是否接受只针对认证状态内的 ACCEPT 语义？`。若答案是「是」，则无新研究问题；若「否」，则须先解决 DO 外部信任基，回到 D3-13 H4。
