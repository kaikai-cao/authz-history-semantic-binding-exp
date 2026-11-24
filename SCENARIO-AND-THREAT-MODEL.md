# D3-12 最小场景与威胁模型

日期：2026-11-24｜对应任务包 Phase 1

---

## 1. 固定最小场景（不再用泛化"跨组织 Agent 隐私保护"）

```
Organization A（Agent 运营方）
   Agent A --tool_call(req)--> Tool X（Organization B 工具服务方）
        |                          |
        |                     admission receipt（B 产生）
   execution receipt（A 产生）
        |                          |
        +-------- 关联字段 --------+
        |  call_digest / principal_link / actor_chain / txn
        v
Organization C（独立审计者）
   判断某次执行是否满足合规策略 P，但不获得不必要信息
```

## 2. 六个必答问题

### 2.1 A、B、C 各自知道什么？

| 参与方 | 知道/持有 |
|---|---|
| **A（Agent 运营方）** | 原始请求 `req` 与响应 `resp` 全文；Agent 凭据/密钥；`call_digest = H_canonical(req)`；自己产生的 execution receipt；Principal 的 pepper（若 Principal 为自然人）；完整 actor_chain |
| **B（工具服务方）** | 收到的请求 `req'` 与响应；自己的签名密钥；admission receipt；自己计算的 `call_digest'`（SCITT 要求 B 自己算、不照抄 A）；`caller_ref`/`caller_agent_id` |
| **C（独立审计者）** | 仅收到的回执/证明/公开锚点；A、B 的公钥与策略；VDS 一致性证明（若提供）。**不应**持有 `req/resp` 原文（SCITT §10 "No content"） |

### 2.2 谁能观察原始请求和响应？
- 仅 A 与 B（各自在 Decision Point）。SCITT §10：`response_digest` 承诺"Harness 改动/截断/隐瞒之前收到的字节"，即 A 侧 Harness 能看到并可能篡改。
- C 看不到原文——这是 SCITT 的明文设计已保证的，不是 ZKP 的功劳。

### 2.3 谁能生成、签署、删除、替换回执？
- **生成/签署**：A 在 Decision Point 签 execution receipt（`agent_sig`）；B 对每个收到的调用签 admission receipt。双方各自签名、各自验证（§9.2 "parties each of which verified on its own"）。
- **删除/替换**：回执注册进 VDS 后不可删（§10 Retention）；删除需同时控制 Issuer 与 TS（SCITT Profile §11.8 two-party collusion）。Harness 在回执产生前可"不产生"（§11 Omission：leaves no trace）。

### 2.4 C 需要验证哪些性质？
1. **关联**：A、B 的两条回执对应同一次调用（`call_digest_A = call_digest_B`，§9 linked verification）。
2. **合规**：该次调用满足策略 P（如主体在允许列表、参数符合限制、预算未超）。
3. **真实性/新鲜度边界**：回执由指定 A、B 签名、在 VDS 中、未过期/撤销（这些依赖外部信任，不是 ZKP 提供——D3-11 已定论）。

### 2.5 C 不应该获知哪些信息？
- 请求内容 `req`、响应 `resp`、工具参数值（SCITT §10 "No content" + Data minimization）。
- Principal 明文身份（用 pepper hash 表示）。
- 完整执行轨迹（只应看到与待审调用相关的回执子集）。
- 可推断业务类型/服务关系的元数据（target/egress_host/ts/frequency）——这部分 SCITT 只给"最佳实践"而非硬保证。

### 2.6 哪些信息已经通过现有 SCITT 回执公开（给 C 或 VDS）？
- 签名回执全部字段（除内容）：`target, request_digest, response_digest, ts, agent_id, seq, prev_hash, actor_chain, principal_link, txn, call_digest`（§6.7 CDDL）。
- VDS 中：Issuer、agent identifier、type、key identifier（§10 "Transparency Service visibility"）。
- **这不是"泄漏"**：这些字段本来就是为第三方验证设计的；关键是其中没有任何原文内容。

## 3. 一个现实的隐私威胁（不是笼统"保护用户隐私"）

**场景：跨组织支付审计的身份关联（具体、可验证）**

Org A 的 Agent 代表自然人 Principal P 调用 Org B 的支付工具。SCITT §10 原文承认两点：
1. `call_digest` 是请求内容的摘要；"where that content has low entropy, for example **a payment amount sent to a known path**, a party holding the receipt can confirm a guessed value by recomputing the digest."
2. 自然人 Principal 用 `SHA-256(pepper, identifier)` 表示，"The same Principal is **linkable across receipts of one deployment by design**"。

威胁：审计者 C（合法持有该部署一批回执）可 (a) 对已知路径的支付金额做字典攻击重算 `call_digest` 猜出金额；(b) 用稳定的 pepper-hash 在同一部署内跨回执关联同一 Principal 的多笔支付，推断消费习惯/业务关系。这是**真实的、可具体描述的泄露**，不是泛泛而谈。

SCITT 的现有缓解（§10）：注册 epoch roots 而非单条回执（限制谁能持有 digest）、pepper 每部署轮换（阻断跨部署关联）、principal_link 用双方共有 token 摘要（不泄露 Principal 本身）。**这些缓解都不用 ZKP**。

## 4. 与 D3-11 信任模型的衔接

本场景沿用 D3-11 的定义（E1–E4、X1–X7、七类参与方），不重新审计。关键继承：
- E1 事件真实、E2 完整无遗漏的缺口在外部信任基（TEE/远程证明/独立观察），不是 ZKP（D3-11 已定）。
- E3 `call_digest` 盲关联已实现（D3-11 已定）。
- E4 合规判定隐私化是唯一残存候选——**本轮 H1/H2 就是对 E4 的最终裁决**。

## 5. 威胁范围之外（明确不审）
- 不重新审计事件真实性（E1）与日志完整性（E2）——D3-11 已定论为外部信任基问题。
- 不审计"日志无遗漏"——承接 D3-10 X2′。
- 不引入"全局最新性"要求——D3-07-A 已明确不证明 globally latest。
