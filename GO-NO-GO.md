# GO-NO-GO.md — D3-14-01 最终裁决

基准日期：2026-11-25。任务性质：只读文献审计与安全性质对照。

---

## 裁决摘要（一页以内）

**裁决：`STOP`**

**裁决对象**：D3-14-01 候选「面向长期多代理工作流的隐私保护区间缺失证明」作为**独立 ZKP 研究选题**。本裁决不表示 Agent 授权、执行证据、撤销收敛或恢复方向整体无价值；只表示该候选在当前证据下不满足立项门槛，并命中任务包 §4 的强制停止条件。

**一行理由**：候选的核心命题已被拆成三块分别解决——区间缺失问题与三值口径由 Baek 定义（但明确无协议），有界撤销收敛由 Zhu/Wang 形式化解决，隐藏委派拓扑的 ZK 披露由 Rampertab §12 规范；剩余「把 ZK 作用于收敛证书」正是停止条件第 1 条所指的拼装，且覆盖完整性（P5）在七篇中一律外置，ZK 无法内生解决。

**关键证据（均可回溯，见 RELATED-WORK.md 引用表）**：
1. Zhu/Wang 摘要：证书 *"establishes root-relative authorization quiescence within its bound manifest and configuration, not global idleness, rollback, or business completion"*；§3.4 把未登记 effect path 置于定理域外。
2. Rampertab §12：absence / revocation 主张 *"MUST cover every record that can change the answer"*；附录 B 七个 Groth16 证明 *"establish neither authority, completeness nor freshness"*；全文 `interval absence` / `quiescence` 零命中。
3. Baek 摘要：*"It does not define a protocol, a data format, or a verification algorithm."*；REQ-4/§8 要求可检查 completeness property，且 ABSENT 不抵抗操作者伪造或漏报。
4. CVA §4.5/§7：runtime execution binding 为开放问题，需执行时信任锚；PoE §6：ZK EAC 为 open work；SCITT §9.2：PASS 不确立 Harness 记录每次调用。

**未解决但不在本选题内**：P5 的外部完整性来源（Manifest 注册真实性、执行事件真实采集、远程证明绑定、未登记端的发现）。这些是信任基 / 协议工程问题，与 D3-11/D3-12/D3-13 结论同构，且任务包已禁止在本轮新建协议或架构拼装。

**交付**：四份文档；未修改任何其他仓库；未启动下一阶段。原任务包规定「不提交、不推送」；2026-11-25 用户后续指令要求提交推送，故按独立审计目录规范提交至 orphan 分支并核验远端 SHA。

---

## 1. 七个必答问题

### Q1. 已有哪篇工作覆盖了候选性质？
分三项回答，避免把「部分覆盖」说成「完全覆盖」：
- **区间权限可用性缺失（P3）**：Baek `draft-baek-audit-absence-claims-00` 完整定义了问题、术语、三值语义、REQ-1–13 与 T-1–22 场景；但摘要明言不定义协议、数据格式或验证算法。Rampertab §11.2 可在完整历史任意位置求 captured authority，§12 规范了 absence 主张必须覆盖全部相关记录，但未定义区间级三值结论。
- **撤销后迟到效果收敛（P4）**：Zhu/Wang arXiv:2609.21284 明确定义 root-scoped quiescence，给出协议、六项安全性质证明、三值判定与 17 例 late-effect 测试 + 独立 checker（作者报告 17/17、44/44）。Baek REQ-8 与 Rampertab §9.1 只给需求 / 局部规则。
- **隐藏拓扑的第三方验证（P6）**：Rampertab §12 private authority profile 可隐藏 delegators 与 terms；SCITT §10 用 `principal_link` / pepper / epoch roots 隐藏关联；CVA 有 Groth16 私有谓词 PoC；PoE 把 ZK EAC 列为开放工作。**没有一篇把 P6 作用在区间缺失或 quiescence 证书上。**

### Q2. 哪个性质没有被现有工作明确覆盖？
严格说只有一个交集性质：**在可检查覆盖边界内，对外隐藏内部委派 / 执行载体拓扑，同时让第三方验证区间级撤销收敛结论（P4∧P6，并带 Baek 三值语义）**。
它未被明确覆盖是事实；但「未被写下」不等于「需要新密码机制」。该交集的两半分别由 F 与 D §12 给出，剩余的是一个实例化选择。

同时必须记录：**P5（所有路径均在已声明且可检查的覆盖范围内）在七篇中一律外置**，无一给出全局可检查证明。它的缺口是真实且重要的，但不属于 ZKP 证明关系创新。

### Q3. 这个性质是否可以独立形式化？
**可以写出语句，但不能在现有证据下给出比已有工作更强的独立安全定义。**
- 可形式化的部分：给定公开锚定的注册表承诺 `C_reg`、私有 Manifest `M`、私有 leaf 集合 `L`，证明 `M ≡ projection(C_reg)` 且每个注册项存在兼容 leaf，且组合规则满足 Zhu/Wang 的 verdict discipline；公开输出只含区间、root-epoch、结论三值。这是集合等式 + 谓词检查，可由标准承诺 / Merkle / SNARK 表达。
- 不能形式化的部分：`C_reg` 是否 enumerates 所有真实执行端。Zhu/Wang A6、PoE A5、SCITT §9.2、Rampertab §10.1、Baek REQ-4 都把它设为外部前提。
- 因此该性质在形式上是**已有定义的隐私化改写**，不是新的安全目标；且隐私化改写不涉及新的困难性假设或新证明关系。

### Q4. ZK 是否增加了实质安全属性，而不只是隐藏字段？
**按现有证据：否。**
- ZK 增加的是"不公开 witness"的隐私属性，不增加 soundness 强度、不产生 fence、不扩大覆盖范围。
- Rampertab 附录 B 明确其 ZK 演示 *"establish neither authority, completeness nor freshness"*；§12 明确 *"Zero knowledge limits disclosure beyond the public statement; it does not conceal the statement"*。
- Baek §8：ABSENT 在证据被伪造 / 漏报时不成立；这不会因为证明被零知识化而改变。
- D3-12 已证伪相邻的「跨组织隐私化关联」增量：SCITT `principal_link` + RFC 9901 已覆盖；equality proof 是 Chaum-Pedersen 已知原语。本候选没有给出超出该结论的可测隐私价值。
- 唯一可能的实质增益场景是「泄露委派拓扑会造成可量化商业 / 安全风险」，但本任务包要求只读审计，未提出场景、度量或对照基线；按证据不足处理。

### Q5. Completeness 是否有独立可检查的来源？
**在声明范围内有，在范围外没有；没有发现任何可称为「独立且全局可检查」的来源。**
- Zhu/Wang：A6 registry/manifest completeness + A7 exact channel accounting + stable-scan watermark，verifier 可检查**在 manifest 内**的一致性；未登记路径在定理域外。
- Rampertab：§10.1 必须发布覆盖表（enforced/recorded/open）；§11.3 头证明 / 本地锚 / 远程 witness / 公共链锚强弱递进；但 §11.2 明确不确立「每次调用都经过决策点」。
- PoE：A5 trace completeness 由 Effector-exclusive credentialing 规约，被原文标注为**部署假设，非密码学保证**。
- SCITT：§9.2 Harness completeness 需与远程证明组合，本文明确未定义该绑定。
- Baek：REQ-4 要求系统声明可检查的 completeness property；§8 明确不抵抗操作者伪造 / 漏报 / 密钥失陷 / 执行点失陷。
- 结论：completeness 的来源始终是外部观察 / 注册 / 准入机制；ZK 只能证明给定来源的一致性，不能生成来源。

### Q6. 能否建立非 ZK、签名 / Merkle、TEE / Witness 等强基线？
**能，而且强基线已经存在，并强于任何本轮可设想的 ZK 版本。**
- 签名 / Merkle 基线：Zhu/Wang 的 manifest + leaf + channel token + frontier 证书，三值判定、独立 checker、17 例测试；Rampertab 的可重放授权历史 + owner 签名 + witness + 公共链锚定；SCITT 的 Signed Statements + hash chain + Bundle。
- TEE / 远程证明基线：CVA §4.5 自己指出关闭 runtime gap 需要执行时信任锚（TEE / 远程证明 / 可验证回执）；SCITT §9.2 把 Harness completeness 指向 RATS Evidence（RFC 9334）；Baek §7 指向 RFC 9334、RFC 9162、CAEP、token status list。
- 观察 / 外部执行端基线：PoE 的 Effector-exclusive credentialing；Zhu/Wang 的 provider-local fence 与扫描。
- 由于强基线已覆盖 P4 与 P5（有界）并给出可测指标，ZK 版本必须证明「在同等完整性前提下，额外提供可测的隐私收益」；本轮没有该证据。

### Q7. 相比已有方案，能否定义可量化的增益？
**不能。**
- 已有可量化基线：Zhu/Wang 的 17/17 结果 + 44/44 语义回归拒绝；Xu(G) 的 7,513 trials × 2 平台、0/200 vs 117/200、170/170 orphaned、75/100 未解决；PoE 的 2.7 ms / 4.4% / 1.1 KB；CVA 的电路规模与验证时间。
- 本候选没有给出：隐私泄露度量（可观察输出 / 元数据 / 低熵猜测 / 链接攻击）、与选择性披露的对照、证明大小 / 时间、或任何 false-safe 率的改进量。Rampertab §12 反而要求 ZK profile 必须 *"list observable outputs and metadata, assess low-entropy guessing and linkage"* 并禁止把精确聚合称为差分隐私。
- 无增益指标即无法与强基线比较，`CONTINUE` 不成立。

---

## 2. 强制停止条件逐条判定

任务包 §4 规定「出现以下任一情况，裁决 STOP」。本次判定：

| # | 停止条件 | 是否命中 | 证据 |
|---|---|---|---|
| 1 | 只是把 Rampertab 的 ZK authority history 与 Zhu/Wang 的 quiescence certificate 拼装 | **命中** | 候选自述的"真正可能有价值的部分"=隐藏内部授权拓扑 + 第三方验证区间级撤销收敛；D §12 提供私有 authority profile，F 提供 quiescence 证书，E 提供问题口径。无第四种机制 |
| 2 | 只是给已有证书写一个 Halo2 电路 | 未直接命中 | 本轮明确禁止建电路；但若进入原型，可行路径仅剩此形式 |
| 3 | 证明仍依赖单一不可信日志源的自我声明 | 部分命中 | 依赖多运营者 Manifest，非单一日志；但 Manifest 真实性仍是自我声明 |
| 4 | 无法处理遗漏的授权路径或外部执行端 | **命中** | H3；F §3.4 明确未登记路径在定理域外；PoE A5 为部署假设；SCITT §9.2 PASS 不保证每跳存在；Baek REQ-4 要求外部声明 |
| 5 | 无法定义比现有工作更强的独立安全性质 | **命中** | P6 是隐私属性，不提高 soundness；P4 已由 F 形式化；P3 已由 E 定义。无新增安全目标 |
| 6 | 隐私收益仅是隐藏若干字段，且没有可测量的实际价值 | **命中** | 无场景 / 无度量 / 无对照；D3-12 已证伪相邻跨组织隐私关联增量 |

`CONDITIONAL_HOLD` 的三项情形（性质可能独立但外部完整性未解决、ZK 隐私价值未超选择性披露、文献高度相近需再查）客观上也都成立；但任务包把 `CONDITIONAL_HOLD` 写为「最多裁决」的上限，而 STOP 条件是「出现任一即裁决 STOP」的强制条款。**按条款优先级，命中第 1/4/5/6 条即 STOP**，不取上限。

---

## 3. `CONTINUE` 六门槛核对

| 门槛 | 结论 |
|---|---|
| 明确指出至少一项现有工作没有覆盖的性质 | 满足（P4∧P6 交集无人明确写下） |
| 给出严格的形式化安全定义 | 不满足（本轮只读审计未产出新定义；可写出的语句是已有定义的隐私化改写） |
| 列清完整性和观察信任假设 | 满足（见 ADVERSARIAL-HISTORIES H3、PROPERTY-MATRIX 行 4/11） |
| 构造现有方案无法通过的反例 | 不满足（H3 中现有方案均正确返回 INDETERMINATE，未越界报 ABSENT） |
| 说明 ZK 的不可替代增益 | 不满足（仅隐藏字段；Rampertab 附录 B 自述不确立 authority/completeness/freshness） |
| 定义强基线和可量化评价指标 | 不满足（强基线已由 F/D/B/CVA/G 给出，本候选无指标） |

六项缺四项；`CONTINUE` 明确不成立。

---

## 4. 明确不宣称的边界

- 不宣称「区间可用性证明」「Agent 授权」「跨组织隐私验证」「撤销收敛」整体不可研究；只裁决**本候选在本轮证据下**不成立。
- 不宣称 Baek 草案已解决问题——它明确没有协议 / 格式 / 算法；其价值在于把问题口径固定下来。
- 不宣称 Zhu/Wang 的证书是全局收敛——其原文限定在 bound manifest and configuration，且排除 global idleness / rollback / business completion。
- 不宣称 Rampertab 的七个 ZK 证明是可生产使用的——原文明确 `not production-qualified` 且不确立 authority / completeness / freshness。
- 不把任何 Internet-Draft 描述为 RFC 或正式 IETF 标准；C/G 为 arXiv preprint（G 的后续投稿非录用），A 为 peer-reviewed 期刊论文。

---

## 5. 保留但不立项的开放问题（超出本任务包范围）

若未来用户另立任务包，方向必须是**外部信任基 / 协议工程**，而非 ZKP 证明关系创新：
1. Manifest / 执行端注册表的真实性与完整性来源（谁有资格登记一个 effect path）。
2. 执行事件真实采集与远程证明绑定（CVA §4.5 明确需要执行时信任锚；D3-13 的 H4 仍 OPEN）。
3. 未登记路径的发现机制（Baek T-8 / REQ-11；Zhu/Wang A6 域外）。
4. 跨域时钟 / 生效顺序的可核查性（Baek REQ-13 / §8）。

这些问题与 D3-11、D3-12、D3-13 的开放项同构；按任务包约束，本轮不新建协议、不拼装架构、不启动下一阶段。

---

## 6. 交付自检

- [x] 仅在 `D:\Research\d3-14-01-private-quiescence-audit` 创建四份文档：`RELATED-WORK.md`、`PROPERTY-MATRIX.md`、`ADVERSARIAL-HISTORIES.md`、`GO-NO-GO.md`。
- [x] 原任务包要求「不提交不推送」；2026-11-25 用户后续指令改为要求提交推送，故按独立审计目录规范新建 orphan 单根分支 `exp-d3-14-01-private-quiescence-audit`，remote 指向 `kaikai-cao/authz-history-semantic-binding-exp.git`，精确 add 四份文档；推送后回读远端 SHA 核验。
- [x] 未修改 `agent-exec-binding-mvp`、`authz-history-semantic-binding-exp`、D3-13 R0/R1/R1.1 或任何 Halo2 / Orchard / Sapling 仓库。
- [x] 未新增 Halo2 电路、未编写新 Agent 执行协议、未做实验性架构拼装、未宣布选题成立。
- [x] 文献类型已区分 peer-reviewed / arXiv preprint / Internet-Draft；Internet-Draft 均未称为 RFC。
- [x] 引用给出原文章节 / 场景号 / 直引，且列明抓取入口与日期；无法逐字核对的项标注为摘要级或未验证。
- [x] 裁决只取三值之一：`STOP`。
