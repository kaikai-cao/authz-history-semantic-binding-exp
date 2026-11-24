# D3-11 威胁模型：参与方、攻击者能力与信任边界

日期：2026-11-24｜状态：审计产物，非实现规格

---

## 1. 固定场景

```
Principal（委托方）
   |
   v
Agent A（Organization A 运营）
   |-- tool_call --> Tool X（Organization B 运营）--> Execution Result
   |-- delegate ---> Agent B（Organization C 运营）
                          |-- tool_call --> Tool Y（Organization D 运营）--> Final Result
```

长期运行任务，工具跨四个组织，回执可信度异质（有的来自 TEE、有的纯签名、有的经第三方托管）。第三方验证方要验证任务合规，但不应依赖单一统一可信 Gateway，也不应看到完整调用轨迹。

## 2. 七类参与方（沿用 SCITT -02 术语并对齐场景）

| 参与方 | 定义 | 在本场景中 |
|---|---|---|
| **Principal** | 发起任务、最终追责的委托方 | 顶层委托者，可能不直接参与每次调用 |
| **Agent Operator** | 运营 Agent、持有 Agent Credential 签名密钥的实体 | Org A（Agent A）、Org C（Agent B）；可能各自不同 |
| **Agent Runtime / Harness** | 承载 Agent、中介其工具调用、在 Decision Point 产生回执的运行时 | Agent A/B 的 Harness；**遗漏攻击的关键位置** |
| **Tool Provider / Serving Party** | 运营工具、对每个收到的调用做 admission 并产生 admission receipt 的实体 | Org B（Tool X）、Org D（Tool Y） |
| **Evidence Custodian / Transparency Service (TS)** | 独立运营、维护 append-only VDS、签发 registration receipt 的实体 | 可为第三方托管，或与某 Operator 同实体（信任边界在此） |
| **Independent Verifier** | 持有回执、离线验证链完整性与 linked verification 的第三方 | 审计方 / 监管方 |
| **Serving Party 的 Model Provider** | 被 api-bound 的模型服务 | 可能与 Tool Provider 分属不同组织 |

## 3. 攻击者能力分层（不允许全不可信，也不允许全诚实）

按 D3-11 任务包要求，明确区分六类攻击情形，并标注每个强基线的立场：

### 3.1 单方恶意
- **恶意 Harness（X1）**：篡改、截断、隐瞒其传给 Agent 的响应；或对某些调用干脆不产生回执。SCITT -02 §6.7：`response_digest` 承诺"Harness 改动/截断/隐瞒之前收到的字节"，即 Harness 被明确视为可能篡改的一方；但"Harness 是否记录每次调用"§9.2 明说不在 PASS 范围。
- **恶意 Agent Planner**：发起越权调用、伪造参数。CVA 已把 Planner 妥协列为 out-of-scope（复用 D3-09）。
- **恶意单个 Tool Provider（X3）**：执行成功但返回伪造回执，或回执描述与内部行为不一致。SCITT -02 §9.2：`a Serving Party checked more than its admission_basis records` 不在 PASS 范围。

### 3.2 调用双方串谋（X4）
- 调用方与服务方对同一次调用对外展示不同参数；或联合删除/隐瞒执行记录。
- SCITT Profile §11.8：Issuer 与 TS 串谋是"fundamental limitation of any two-party evidence system"——**双方串谋可无检测地伪造/抑制/修改证据**。
- SCITT -02 §9.2：linked verification 只保证双方 `call_digest` 相同；若双方对 physically 同一调用各自算不同摘要并各自展示，验证者无法分辨哪个是真。

### 3.3 Harness 被攻破
- SCITT Profile §11.5：capture pipeline 被攻破可在签名前伪造或抑制 AIR；缓解靠 HSM 中签名密钥 + TS 的序列完整性校验。但"从未记录的操作不留缺口"——被攻破的 Harness 完全跳过某调用，无序列缺口可查。
- SCITT -02 §9.2：Harness completeness 是与远程证明（RATS/EAT）的组合点，**本文不定义该绑定**。

### 3.4 多个组织选择性不提供记录（X1、X2′）
- 某 Tool Provider 决定不为某些调用产生 admission receipt；或某 Agent Harness 不记录某跳。
- 现状：无密码学机制能证明"外部真实事件一个不少地进入证据链"（承接 D3-10 P2 结论）。`call_digest` 只在"双方都产生回执"时才能比对。

### 3.5 多个组织向不同验证者展示不同证据（X6）
- 同一任务，对不同 Verifier 展示不同的 receipt chain。
- SCITT 靠 append-only VDS + consistency proof + 外部见证/gossip 检测分叉；这是**分布式系统假设**，不是 SNARK 属性（承接 D3-10）。SCITT Profile §11.2 要求 TS "operationally honest"——若同一实体运营两角色，tamper-evidence 保证作废。

### 3.6 工具真实执行与签名回执不一致（X3）
- 回执断言"调用了 Tool X 参数 p"，但工具实际执行了 q。
- 四篇基线一致承认这是外部信任边界：
  - SCITT -02：`call_digest` 由 Serving Party 对自己收到的请求计算、绝不照抄对方证据（§6.7 call_digest）；但"工具内部行为与回执一致"不在任何 PASS 语义内。
  - NovaFabric：key custodian 可签一条断言虚假的合法 capsule，下游任何验证都检不出（TCB）。
  - Receipts §A.5：`Observation authenticity remains an external property supplied by an anchor such as a signed append-only log, an authenticated event source, or hardware-backed attestation`。
  - zkAgent：用 zkTLS/zkVM 证明"观察真实"，但目标是 provider 忠实执行，不碰授权合规。

## 4. 明确不假设的事（防止过度敌意或过度天真）

- **不**假设所有外部参与者不可信：SCITT -02 的 Serving Party 按注册策略做 admission，SCITT Profile 假设 TS 操作诚实、签名密钥未泄露。这些是显式信任假设，写进各性质的"所需信任假设"。
- **不**假设所有参与者诚实：Harness 明确可能篡改（response_digest 的定义前提）、Custodian 可能被攻破或串谋、Planner 可能妥协。
- **不**把"签名有效"等同于"事件真实"（E1 的边界）。
- **不**把"日志可追加/序列连续"等同于"日志无遗漏"（E2 的边界）。

## 5. 信任假设汇总（裁决时逐条对照）

| 假设 | 来自 | 若破坏 |
|---|---|---|
| TS 与 Issuer 结构独立 | SCITT Profile §11.2(a) | tamper-evidence 保证作废 |
| TS 操作诚实 | SCITT Profile §11.2(b) | 可伪造注册、分叉 VDS |
| Issuer 签名密钥未泄露（HSM） | SCITT Profile §11.2(c)/§11.3 | 可签虚假回执 |
| 签名密钥 custodian 诚实 | NovaFabric TCB | 可签断言虚假的合法 capsule，下游检不出 |
| capture hooks / proxy 忠实观察、spool/collector 不丢 | NovaFabric TCB | 遗漏不可检测 |
| verifier 独立获取可信密钥与策略 | NovaFabric TCB | 可被喂假策略 |
| runner + observation logger 执行期可信 | Receipts §A.5 | 执行期伪造不可检测 |
| 双方对同一请求表示计算 `call_digest` | SCITT -02 §6.7.3 | 跨方关联失效 |

**结论**：四项性质中，E1（事件真实）与 E2（完整无遗漏）的关键缺口都落在这张信任假设表上，而不是落在证明系统的可靠性上。这是本轮把候选问题从"ZKP 问题"重新归类为"信任边界 + 外部锚点问题"的依据。
