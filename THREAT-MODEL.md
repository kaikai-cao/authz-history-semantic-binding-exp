# D3-18-01 威胁模型与信任边界

证据等级标注同 SOURCES.md：每个断言后附 `[原文]` / `[摘要]` / `[推断]` / `[UNVERIFIED]`。

## 1. 参与方与信任域

以 SealCall 的三域审计模型为基线 `[原文, S1 §2.2]`，叠加本候选要引入的"可验证计算"层。

| 参与方 | 持有 | 权限 | 基线信任（SealCall） | 本候选要降低的信任 |
|---|---|---|---|---|
| 用户 / trusted controller C | 任务 u、候选调用 a_t、历史 h_<t、secret key、放行权 | 构造并加密表示、解密、决策、放行 | 完全可信 `[原文]` | 保持不变 |
| LLM Agent | 执行域，产生候选调用与上下文 | 提出待审调用 | 半可信（其行为是审计对象） | 保持不变 |
| Audit Service S（审计服务） | pk、evk、密文输入、密文参考库 Θ、`[候选]` 证明生成密钥 | 在密文上做约定计算、返回密文结果、返回证明 | ** semi-honest**：遵循约定计算但试图推断隐私 `[原文, S1 §2.1]` | **降为 malicious**：可返回格式正确但数值虚假的密文/证明 `[原文, S1 §3.5]` |
| 审计数据/参考库提供方 Θ | 维护参考样本或模型参数 | 在可信环境加密 Θ 交 C/S | 可信准备 `[原文, S1 §2.2]` | 视场景：若 Θ 由恶意 S 自供，需版本承诺 |
| passive observer | 加密参考数据、无密钥 | 观察密文、推断审计规则 | 被动 `[原文, S1 §2.1]` | 保持不变 |
| Data/Model Registry | `[候选]` 承诺公开锚 | 发布可信模型/参考库版本承诺 | SealCall 未设 `[UNVERIFIED]` | 需外部可信锚（本候选新增） |

## 2. 关键信任边界（不可混淆的三件事）

SealCall 原文与任务包共同要求严格区分以下三类性质，不得互相掩盖：

1. **审计计算正确性**（密文计算是否按约定函数 F 执行）——本候选的密码学目标。SealCall 当前**不保证**：恶意服务可返回 "well-formed ciphertext encoding a false score" `[原文, S1 §3.5]`。
2. **审计模型的判断准确性**（F/表示/阈值能否正确区分越权与安全）——**不由密码学解决**。SealCall 自己报告 purpose_scope F1=0.171、recipient_binding F1=0.455，并明言 "the current representation and scorer do not reliably distinguish these policy changes" `[原文, S1 §4.3 / App.E]`。证明服务正确执行了一个判断力很差的模型，不等于审计有效。
3. **审计结果与实际工具调用的绑定**（放行的是否就是被审的那次调用）——SealCall **已有**：§3.4 在放行前检查 result 归属该 request、call 与 expected state 仍匹配，变化触发重审，覆盖 stale state / replay / argument changes / failure handling `[原文, S1 §3.4]`。这是本候选与 MVP 的自然连接点，但**不是待填补的空白**。

**结论性边界** `[推断]`：本候选的密码学机制只能加固第 1 项；它既不能修复第 2 项的模型缺陷，也不是第 3 项的首创（SealCall 已实现）。任何声明"解决 Agent 安全审计可信问题"的表述都越过了证据。

## 3. 攻击者能力（本候选要防的恶意 S）

对照任务包 Phase 3 六类攻击，明确攻击者能力与是否落在 SealCall 现有威胁模型内：

| 攻击 | 恶意 S 能力 | SealCall 基线能否防 | 备注 |
|---|---|---|---|
| A 伪造低风险分数 | 返回格式正确、数值虚假的密文 | **不能** `[原文, S1 §3.5]` | 真缺口，作者自述需 computation-integrity mechanism |
| B 替换输入密文 | 用另一组密文冒充用户输入算分 | 未定义（威胁模型未含篡改输入） `[推断]` | 可由输入承诺 + 证明中的 statement 绑定缓解 |
| C 使用过期/被替换的模型/参考库 Θ | 换用对攻击者有利的 Θ | 部分：SealCall 有 versioned configuration，但 Θ 由 C 或 cooperating data owner 加密，S 只持密文 `[原文, S1 §3.4]`；若 S 自供 Θ 则未覆盖 `[推断]` | 需可信模型/参考库版本承诺 |
| D 重放其他调用的证明 | 复用旧密文/旧证明 | 未定义 `[推断]` | 需 nonce / 有效期 / 会话标识进入 statement |
| E 证明正确但放行非被审调用 | 审计与执行层脱钩 | **已防**：§3.4 call binding `[原文]` | 非本候选贡献 |
| F 拒绝服务/选择性不返回证明 | 不返回或延迟返回 | 密码学不可防 `[推断]` | 属可用性，需超时/默认拒绝策略 |

## 4. 验证者模型的新增约束（来自 PRISM）

- PRISM 通过 VOLE correlations 获得 ZK，"in a model with an offline phase" `[摘要, S2]`；ZK 的实现依赖 prover–verifier 之间的离线相关性。
- **指定验证者风险** `[推断，待正文核验]`：若 VOLE 相关性是 prover 与特定 verifier 之间预共享的两方材料，则第三方无法独立验证证明，这与"公开可审计"的审计服务诉求存在张力。任务包点名此风险，但 PRISM 正文 `[UNVERIFIED]`，不能断言其确为指定验证者。
- **高频审计的 offline 成本** `[推断]`：SealCall 代表配置 0.176 s/次是纯 CKKS 加密评分 `[原文, S1 §4.4]`；叠加 PRISM 后，每次调用是否都要重新生成/消耗一份 VOLE 相关性、能否跨调用复用，正文未取得，`[UNVERIFIED]`。不能把 PRISM 在 NN 负载上的相对倍数当作本负载的答案。

## 5. 信任假设清单（CONDITIONAL-GO 需逐条满足）

1. trusted controller C 与密钥隔离可信（SealCall 基线要求）`[原文]`
2. 明文准备在用户控制域完成、服务端无解密密钥 `[原文]`
3. `[新增]` 审计模型/参考库版本有外部可信承诺锚——SealCall 无此角色 `[推断]`
4. `[新增]` 若采用 PRISM：离线 VOLE 相关性的生成方、复用边界与验证者身份明确 `[UNVERIFIED]`
5. `[新增]` 计算完整性证明的 statement 必须包含输入/输出密文、模型版本、nonce、会话标识 `[推断]`
6. `[不可消除]` 审计模型的判断质量是独立前提，密码学无法补足 purpose_scope F1=0.171 的短板 `[原文 + 推断]`
