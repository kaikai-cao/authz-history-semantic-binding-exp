# D3-18-01 协议映射草案（仅设计，不实现）

本文件给出 SealCall × 可验证计算的绑定关系草案。**不声称已实现**，所有未取得正文的机制细节按 SOURCES.md 证据等级标注。

## 1. 拟绑定的对象

任务包要求评估以下绑定关系能否同时成立。逐项给出可绑定性判断：

| 绑定对象 | 载体 | 可绑定性 | 证据/条件 |
|---|---|---|---|
| 用户任务/上下文承诺 | trusted controller C 本地 hash 承诺（SHA-256 或 Poseidon） | 可，但需 C 侧生成 | SealCall 已有 trusted representation 层 `[原文, S1 §3.1]`；承诺本身是本候选新增 |
| 最终工具调用及参数承诺 | call digest（tool name + final args + expected state） | 可 | SealCall §3.4 记录了 final call 与 expected state `[原文]` |
| 审计模型/参考库版本承诺 | model/reference digest，需外部可信锚 | **条件可绑定**：需新增可信发布方 | SealCall 只有 versioned configuration 概念，无外部承诺锚 `[原文 + 推断]` |
| CKKS 输入密文 | c_in = Enc_pk(z_t)，z_t 为加密表示 | 可 | SealCall 每次查询 fresh randomness 加密 `[原文, S1 §3.2]` |
| 指定计算关系及参数 | F（点积/线性评分）+ 阈值 δ + 公开 circuit 描述 | 可写入 statement | SealCall 的 circuit description/dimensions/output layout 是公开的 `[原文, S1 §3.2]` |
| 输出密文 | c_out = F(c_in, Θ) | 可 | SealCall server 返回密文 `[原文]` |
| 可验证计算证明 | π = Prove(statement, witness) | **条件可绑定**：机制存在但目标负载未验证 | PRISM/BatchPack 提供通用能力 `[摘要]`；是否支持本负载 `[UNVERIFIED]` |
| nonce / 有效期 / 审计会话标识 | 进入 statement 的公开输入 | 可 | 本候选新增；SealCall 未定义 nonce `[原文+推断]` |

**statement 草案（概念式，非最终形式）** `[推断]`：
```
Public:  H(task), H(call), model_digest, c_in, c_out,
         F_id, dim, K, threshold_id, nonce, session_id, validity_window
Witness: z_t, Θ, r_in, r_out, F 的中间值
Relation: c_out = Eval_pk(F_id, c_in, Θ) 且 Θ 对 model_digest 开启成立
          且 H(call) 与 z_t 来源绑定 且 nonce/session 在有效期内
```
注：CKKS 的近似算术使"精确相等"不成立，需用噪声界/DEC 容差；这本身是 vHE for CKKS 的已知复杂点（S4 摘要提及 range check 勘误）`[摘要]`。

## 2. 攻击 A–F 逐项分析

以下判断基于可获得的证据；机制不可得处标 `[UNVERIFIED]` 并给"需什么假设"。

### A. 审计服务直接伪造一个低风险分数
- **现有机制**：不能防。SealCall §3.5 逐字：malicious server "could return a well-formed ciphertext encoding a false score" `[原文]`。
- **本候选机制**：若 π 的 statement 绑定 (c_in, model_digest, c_out) 且证明 c_out = Eval(c_in, Θ)，则伪造分数无法通过 soundness `[推断]`。
- **前提**：所用 vHE/zkHE 覆盖 SealCall 实际使用的点积与阈值前计算 `[UNVERIFIED]`。
- **应返回**：REJECT（证明验证失败）或审计系统默认拒绝放行。

### B. 审计服务替换用户提交的输入密文
- **现有机制**：SealCall 威胁模型未含输入篡改；S 只见密文，输入 c_in 由 C 加密提交 `[原文 + 推断]`。
- **本候选机制**：statement 绑定 c_in 与 H(task)/H(call)；若 S 换成别的 c_in'，除非它能伪造 C 侧承诺的对应证明，否则失败 `[推断]`。但注意：C 侧承诺若只在本地、不进入 S 的证明 statement，则 S 仍可用任意 c_in' 配一个"对该 c_in' 正确"的证明——**必须让 c_in 的来源锚（C 的签名或承诺）成为 S 证明的公开输入**，这是关键设计点 `[推断]`。
- **信任假设**：C 的输入签名/承诺可信。

### C. 审计服务使用过期或被替换的审计模型/参考库
- **现有机制**：SealCall 有 versioned configuration，但 Θ 由 C 或 cooperating data owner 加密，S 持密文；若 provider=S 自供 Θ，则 S 知道其内容且可替换 `[原文 + 推断]`。
- **本候选机制**：statement 绑定 model_digest，证明 Θ 对该 digest 开启；需外部可信注册表发布 digest `[推断]`。
- **信任假设**：可信 model registry 存在且 C 获取 digest 的渠道独立——**SealCall 无此角色，是本候选新增的外部信任基**。
- **应返回**：若 digest 不在可信列表 → INDETERMINATE / 默认拒绝。

### D. 审计服务重放其他调用的证明
- **现有机制**：SealCall §3.4 检查 stale state / replay（在执行绑定层）`[原文]`；但密码学证明本身无 nonce `[推断]`。
- **本候选机制**：nonce / session_id / validity_window 进入 statement，重放旧证明因公开输入不匹配而失败 `[推断]`。
- **前提**：C 在验证时传入当前 nonce 并检查相等。

### E. 审计证明正确，但实际放行的工具调用不是被审计的调用
- **现有机制**：SealCall §3.4 已防（call binding + expected state check）`[原文]`；MVP 也有 request/tool/schema 绑定 `[原文, 前序轮次]`。
- **本候选机制**：证明只能覆盖"被审的那次调用"，**无法阻止 C 之外的人在执行层做替换**；仍需 SealCall/MVP 的执行绑定 `[推断]`。
- **结论**：此项**不是本候选贡献**，是复用既有机制。

### F. 审计服务拒绝服务或选择性不返回证明
- **现有机制**：无 `[原文]`；本候选的证明机制也不覆盖 `[推断]`。
- **需补**：超时 + 默认拒绝放行（fail-closed）策略，属系统可用性设计，非密码学。
- **应返回**：INDETERMINATE（无证明则不放行）。

## 3. 必须明确的边界声明

> **证明服务正确执行了指定计算，不代表指定模型本身正确，也不代表它能准确理解用户的自然语言意图。**

- SealCall 自己报告 purpose_scope F1=0.171、recipient_binding F1=0.455，并明言当前表示与 scorer 不能可靠区分策略变化 `[原文, S1 §4.3/App.E]`。
- 因此即使 A–D 全部被密码学阻断，审计结论在"授权目的/接收方绑定"类别上仍可能错误——**这是模型层缺陷，vHE/zk 无能为力**。
- 结论 `[推断]`：本候选的密码学增益只覆盖"计算完整性 + 版本/输入/nonce 绑定"，不覆盖"判断准确性"。任何以"可信 Agent 安全审计"为名的整体声明都超出证据。

## 4. 与 MVP 的连接点（非新造授权系统）

- MVP 已有 request/context/tool/schema 绑定与独立执行代理签名证据 `[原文, 前序轮次]`；SealCall §3.4 有 call binding `[原文]`。
- 二者可对接：审计证明绑定 audit call digest → 执行层用 MVP 的绑定校验放行对象一致。
- **不重造授权系统**：本候选不引入新的 capability token / 授权语言 / 委托链（这些已在 D3-08~D3-17 系列中被排除或覆盖）。
