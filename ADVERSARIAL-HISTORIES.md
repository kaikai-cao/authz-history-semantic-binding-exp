# ADVERSARIAL-HISTORIES.md — D3-14-01 敌意历史对照

基准日期：2026-11-25。本文只构造历史并逐文献对照，**不提出新协议**。
ground truth 按构造给定；「各文献可给出的结论」只写原文能支撑的内容，超出处标 `NOT ADDRESSED` 或 `UNVERIFIED`。

三值语义沿用 Baek §5 REQ-2：`ABSENT` / `PRESENT` / `INDETERMINATE`；
quiescence 判定沿用 Zhu/Wang §3.5：`QUIESCENT` / `NOT_QUIESCENT` / `INDETERMINATE`。
禁止把两者混为一谈：Baek 的 PRESENT 说的是**能力可用**，Zhu/Wang 的 NOT_QUIESCENT 说的是**受保护效果仍可产生**。

---

## H1：未使用权限（用户示例）

### 时间线
- T0 = 10:00：授予 Agent 访问 Finance 的权限（有授权转换记录）。
- T1 = 10:05：撤销该权限（有撤销记录），期间**从未调用**该权限。
- T2 = 10:10：审计，问「10:00–10:10 内 Agent 是否曾经拥有访问 Finance 的能力？」

### ground truth
**PRESENT**（Baek T-1 / §4.1：*"a grant that is issued and withdrawn without use produces no action record"*；能力在 10:00–10:05 可用）。
注意：若问题改成「区间内是否产生 Finance 访问效果」，答案为「无」——那是 P1，不是 P3。

### 可见证据
- 授权转换记录、撤销记录（若系统记录授权状态而非仅调用）。
- 工具调用回执为空：`[]`。
- 授权历史 head / 状态根（Rampertab 类系统）。

### 遗漏证据
- 若系统只记录调用（SCITT 风格回执链），授权与撤销本身不产生调用回执，两段都不在证据里。
- 若授权/撤销发生在两次清单快照之间，快照也看不到（Baek §4.1 明确）。

### 攻击者能力
无主动攻击者；这是**语义误判**场景。审计者把「无调用记录」读作「无权限」，产生 false-safe。Baek §8 把此列为主要风险。

### 各文献可给出的结论
| 文献 | 结论 | 依据 |
|---|---|---|
| CVA | NOT ADDRESSED | 证明「某请求满足策略」，不回答区间可用性；§7 明确 runtime 之外留给外部信任锚 |
| PoE | NOT ADDRESSED | 验证执行轨迹合规，不重建授权可用性区间 |
| SCITT | 空回执集合；**不能**由空集合得 ABSENT | §9.2 PASS 不覆盖 Harness 是否记录每次调用 |
| Rampertab | 可从完整历史重放出 T0 授权、T1 撤销与「captured authority at any position」→ 可支持 PRESENT | §11.2；§12 要求 absence 主张覆盖全部可改变结论的记录 |
| Baek | PRESENT（且不得报 ABSENT） | T-1：*"Ground truth: usable. Acceptable: PRESENT or INDETERMINATE."* |
| Zhu/Wang | NOT ADDRESSED（无 root cut / fence 事件；且其证书不承诺 usability） | 摘要末尾排除项；§3.5 证书对象 |

### 是否存在 false-safe
**存在**。路径：调用回执为空 → 审计者报 ABSENT。Baek REQ-1/REQ-2/REQ-4 与 T-1 正是为此设置。Rampertab §12 的「inclusion proof for a granting record alone does not establish the absence of a prohibition」从反方向说明单条记录不足。

### ZK 能解决什么 / 不能解决什么
- **能**：在隐藏 delegator 与条款的前提下证明「某授权记录存在于已认证历史并满足给定谓词」（Rampertab §12 private authority profile；CVA PoC）。存在性证明对本例容易。
- **不能**：从「我证明了某段历史」推出「没有未记录的历史」。若授权/撤销走的是未覆盖路径，ZK 证明仍可接受——这正是 Baek REQ-4、Rampertab §12 全体域覆盖要求与附录 B「证明不确立 completeness」共同指出的边界。
- **结论**：本例的正确答案是 `PRESENT`，**不是**一个「区间 ABSENT 证明」的需求。它不构成新密码机制的动机。

---

## H2：撤销后的迟到效果

### 时间线
- T0：旧 root-epoch atom `a=(r,e,h_g)` 授权；主 Agent 把请求交给远端 Provider。
- T1：Provider 在 commit boundary 前接受请求，产生 in-flight carrier / channel token。
- T2：root `r` 被撤销，进入 epoch `e+1`；**仅发出 cancellation，未安装 provider fence**。
- T3：旧请求迟到提交，产生受保护效果。
- T4：审计。

### ground truth
**分两种配置，不能合并**：
- cancellation-only / cut-only：`NOT_QUIESCENT`，迟到效果**会**发生（Zhu/Wang §7.2：两个 cancellation-only 与一个 cut-only 执行都接受同一类已调度迟到效果）。
- cut + fence（含 restart、stale-process 变体）：`QUIESCENT`（同上：两例 cut-plus-fence、一 restart、一 stale-process 拒绝）。
- 若 fence 安装证据缺失或冲突：只能 `INDETERMINATE`，不得升格为 QUIESCENT（§3.5）。

### 可见证据
- 撤销/epoch 推进记录、cut 与冻结 manifest、channel token 的 SEND 与终态处置、provider frontier statement、fence 安装承诺、rebind receipt。
- Rampertab 类系统可见：intent/admission/submission identity、reserved allowance、outcome UNKNOWN、late report 记录。

### 遗漏证据
- 未注册的 provider / effect sink（Zhu/Wang A6 之外的路径）。
- 未安装或仅被「声明」安装的 fence（*"staging a new checkpoint MUST NOT be reported as an acknowledged fence"*，Rampertab §9.1）。
- 跨域 timestamp 与本地 commit 顺序的真实对应（Baek §8）。

### 攻击者能力
1. 撤销后继续以旧 atom 选择授权 witness 并提交。
2. 把 cancellation 回执包装成 sink fence。
3. 复用 pre-fence commitment 作为 post-fence 额外效果的掩护。
4. 冲突/陈旧的 frontier 证据，或用超时与多数投票逼迫判定为成功。
Zhu/Wang §3.5 逐条把上述列为敌手成功条件；并明确超时/重试/多数投票/Agent 自述停止都不能把非成功转为成功。

### 各文献可给出的结论
| 文献 | 结论 | 依据 |
|---|---|---|
| CVA | NOT ADDRESSED（请求级绑定；执行时一致性是开放问题） | §4.5 / §7：需执行时信任锚 |
| PoE | 若效果未经 Gateway 则由 A5 失败；否则可验证 deny 侧零效果；**不判定 root cut 收敛** | §4.2 A3/A5；§3 第五个保证 |
| SCITT | 可显示 Revocation Statement 与回执链；不证明远端效果被 fence | §6 / §9.2 |
| Rampertab | late report 仅记证据；APPLIED 后撤销报 too late；destination 在 commit boundary 重查 | §9.1；§11.2 不确立世界效果 |
| Baek | REQ-8/T-3：撤销前移除且 lingering session 在区间内仍可用 → PRESENT 或 INDETERMINATE；未结束则不得 ABSENT | §4.3 / REQ-8 |
| Zhu/Wang | **明确给出三值判定、形式化性质与 17 例测试**；证书仅在 bound manifest/config 内成立 | 摘要 / §3.4 / §3.5 / §7.2 |

### 是否存在 false-safe
**存在，且已有针对性防御**：把 cancellation 当作 quiescence、把 staged checkpoint 当作 acknowledged fence、把超时当作 INDETERMINATE→SUCCESS 的转换。Zhu/Wang 明确禁止；Rampertab 明确要求 commit boundary 重查与 too-late 报告。

### ZK 能解决什么 / 不能解决什么
- **能**：隐藏哪些 provider / 哪些 leaf 参与了证书（若把 ZK 作用在该证书上），并证明给定私有 witness 满足公开的组合规则。
- **不能**：产生 fence；证明未注册 effect sink 不存在；证明 manifest 本身完整。Zhu/Wang §3.4 把 "an effect path absent from the registered manifest" 明确置于定理域外。Rampertab 附录 B 的七个 ZK 证明自述 *"establish neither authority, completeness nor freshness."*
- **结论**：本例的硬部分是执行边界与 manifest 注册（外部信任基），不是证明系统。把 ZK 套在 Zhu/Wang 证书上只会隐藏字段，不改变 false-safe 的来源。

---

## H3：遗漏的跨域执行路径（coverage gap）

### 时间线
- T0：系统发布声明覆盖 Manifest `M`，列出 runtime、provider、effect sink、channel class。
- T1：期间创建一个子 Agent / 外部 Provider，其授权路径**未被 `M` 覆盖**，也未产生可关联记录。
- T2：该路径使目标权限可用（或产生受保护效果），但审计系统无对应事件。
- T3：验证者收到一份「看似完整」的证明 / 证书，所有被检查的证据都一致。

### ground truth
**能力确实可用（Baek：PRESENT）/ 旧 atom 仍有路径（Zhu/Wang：NOT_QUIESCENT 若能被发现）**。
但由于遗漏路径在证据中完全不可见，**可证明的正确输出只能是 `INDETERMINATE`**——任务包明确要求不得虚报 ABSENT。这与 Baek T-8（unrecorded path：acceptable PRESENT or INDETERMINATE）、REQ-4、REQ-12 一致。

### 可见证据
- Manifest `M`、已注册 sink 的 frontier / fence、channel token 账本、授权历史 export 与 head attestation、回执链 hash、proof 与 verifying key。
- 所有可见证据可以**内部完全一致**——这正是危险之处。

### 遗漏证据
- 未注册的 runtime / provider / 子 Agent 与其授权来源。
- 未记录路径上的授权转换与效果。
- 观察源自身的漏报（日志写入者可以省略条目）。

### 攻击者能力
控制一个或多个未纳入 Manifest 的执行端；或控制记录器以省略条目；或提供一份对「已声明域」完全正确、但域本身偏小的证明。攻击者不需要伪造签名或破解哈希。

### 各文献可给出的结论
| 文献 | 结论 | 依据 |
|---|---|---|
| CVA | NOT ADDRESSED；即使 proof 有效也不覆盖执行域之外 | §4.5 / §6 / §7 |
| PoE | A5 trace completeness 是部署假设；A3 单 Gateway；非 Gateway 事件会导致 trace-completeness failure 但系统未必察觉 | §4.2 / §4.3；§10 composition open |
| SCITT | PASS 不确立 Call Chain 每一跳存在、不确立 Harness 记录每次调用 | §9.2 |
| Rampertab | §10.1 `open` 类；*"A history that records only what passed through the decision point proves what the decision point saw and decided, not what the agent did."*；§11.2 不确立「每次调用经过决策点」 | §10.1 / §11.2 |
| Baek | INDETERMINATE（不得 ABSENT） | T-8 / T-7 / REQ-4 / §8 三类遗漏 |
| Zhu/Wang | 因 A6 前提被破坏而落在定理域外；verifier 对缺失/不透明证据返回 INDETERMINATE | §3.4 / §3.5 |

### 是否存在 false-safe
**最高风险场景**。proof/证书验证通过 ≠ 覆盖完整。七篇文献一致地把覆盖前提外置：Baek REQ-4（系统须声明可检查的 completeness property）、Rampertab §10.1（须发布覆盖表）、Zhu/Wang A6（manifest completeness 是安全前提）、PoE A5（部署假设）、SCITT §9.2（Harness completeness 需远程证明组合且本文未定义）。

### ZK 能解决什么 / 不能解决什么
- **能**：在**给定**已认证注册表 / 公开承诺的前提下，证明私有 Manifest 与注册表投影一致、且每个注册项都有兼容 leaf（集合等式 + 谓词检查，属已知技术）。这可让验证者看不到内部拓扑。
- **不能**：证明注册表本身 enumerates 了所有真实执行端；不能发现未被任何人登记的路径；不能替代外部观察 / 准入审计 / 远程证明。
- **我方推论**：即便构造出这样的 ZK 关系，P5 仍然外置，P6 也不能替代 P5（任务包硬约束）。因此 H3 是**停止条件检测器**，而不是新选题的动机。

---

## 三例横向结论（我方推论）

1. H1 的正确回答是 PRESENT；把它包装成「区间 ABSENT 证明」会直接产生 false-safe，Baek 已用 T-1 覆盖。
2. H2 的正确回答依赖 fence 是否已安装；Zhu/Wang 已给出形式化三值判定和可执行的 17 例测试，且明确禁止把 cancellation 当收敛。
3. H3 的正确回答是 INDETERMINATE；覆盖缺口在所有七篇中都是外部前提，ZK 只能证明「给定 witness 满足关系」，不能证明 witness 未漏掉真实事件。
4. 三例共同指向同一约束：**缺口在观察 / 注册 / 执行边界的信任基，不在证明关系**。与 D3-11/D3-12/D3-13 的结论同构。
