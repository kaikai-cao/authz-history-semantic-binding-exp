# D3-11 决策记录

日期：2026-11-24｜阶段类型：只读研究缺口审计｜状态：完成，暂停等待决策

---

## 1. 裁决对象与判据

裁决的是：**在跨组织、弱信任、多工具 Agent 执行场景下，是否存在一个现有执行证据框架尚未解决、可由 ZKP 或其他密码学构造获得独立保证的问题。**

判据（来自任务包）：
1. 找到明确的 Agent 实际安全需求；
2. 找到普通签名/日志/Gateway/TEE 无法充分解决、或其信任假设不适用于目标场景的具体性质；
3. 找到现有密码学方案没有完整解决的明确缺口；
4. 能定义清楚公开输入、私有 witness、验证关系；
5. 能设计反例/攻击实验验证是否真正新增保证；
6. 贡献不只是换证明系统重实现已有协议。

**五个禁止**：不把多组织回执+哈希链+第三方验证当创新；不把签名检查包装成 ZK；不用递归 SNARK 本身当创新；不把某论文的 Future Work 当无人解决；不用"加 ZKP 就能解决"收尾。

---

## 2. 三条方向裁决

### 方向 A：跨组织执行回执的隐私化关联 — `CONDITIONAL_HOLD`（唯一保留候选）

**候选问题**：不同组织独立签署回执，第三方只需知道两边记录对应同一次操作、且合规，不需要知道完整请求、响应、Principal 或全部 Agent 链。

**已承认的覆盖事实（`OUR-INFERENCE`，基于 A 原文）**：SCITT -02 的 `call_digest` + linked verification **已实现**"双方各自验证、不披露请求内容、盲摘要比对确认同一次调用"。即用户描述的"不集中披露建立可验证跨组织关联"——**其关联内核已是现成构造**。任何 ZKP 方案必须说明相对明文 `call_digest` 比对新增什么。

**唯一残存的候选增量（E4）**：在 SCITT 的 public 锚点（VDS 中已签名的承诺）之上，用 ZKP 证明"这两条已承诺的回执满足 `call_digest` 相等 + 身份链一致 + 合规判定 Dec=1"，而不公开 `call_digest/actor_chain/principal` 明文与策略细节。这相对 A 的明文比对新增"隐藏关联字段 + 隐藏策略判断"。

**为何不是 GO（判据 2、3、6 未过）**：
- 隐藏 `call_digest` 的收益存疑：它是单向 SHA-256 摘要，本身不泄漏请求内容；隐藏它未必增加实际隐私（门禁 H1）。
- 隐藏 `actor_chain/principal` 属于匿名凭证/ZK 集合证明的已知能力（D3-08 已裁匿名委托凭证为已知问题）。
- 公开锚点若处理不当会退化为 D3-07-B 的 private-only 哈希自洽陷阱（门禁 H2）。
- 因此贡献可能是"commit-and-prove + 匿名凭证 + SCITT 锚点"的组合，而非新证明关系。

**保留条件（两道门禁，须先证伪）**：
- **H1 隐藏收益**：论证验证者为何不能接受"SCITT 明文 `call_digest` 比对 + 元数据访问控制"。若"隐藏"只省去本就不可见的摘要字段，则无新增价值 → 降级 REJECT。
- **H2 public 锚点**：给出隐藏 `call_digest/actor_chain/principal` 后，验证者确认关联真实性所依赖的 public 锚点。必须是 SCITT VDS 中已签名的承诺或等价外部锚点；若只能靠证明者私有 witness 自洽 → 降级 REJECT。
- 两门禁均通过，才允许进入"最小证明关系定义"，仍不自动进原型。

### 方向 B：多观察者执行证据的一致性验证 — `REJECT_AS_KNOWN_PROBLEM`

**候选问题**：Agent、调用方、服务方分别观察同一事件，能否不暴露完整记录就证明记录一致、或证明存在不一致。

**裁决理由**：
- 该问题的密码学内核是 equality-of-commitments / 摘要比对，SCITT -02 的 `call_digest` 已是其实例（双方各算同一摘要、盲比对）。
- "证明不一致"即两个公开摘要不同，公开可验证，无需 ZK。
- 隐私增强版（隐藏事件内容仍证一致）是标准 commit-and-prove / linkable 构造，无新证明关系。
- 判据 3、6 未过：现有方案已完整解决内核，无明确未解缺口。

### 方向 C：执行证据与授权状态联合证明 — `REJECT_AS_KNOWN_PROBLEM`

**候选问题**：把一次执行事件、当前授权状态、前置执行结果绑定，使后续工具调用只能消费符合条件的前序结果。

**裁决理由**：
- 组件已被覆盖：状态链 = D3-06-C（双事件 IR-bound 状态转换）；外部锚定/freshness = D3-07-A；单次 request/policy 绑定 = CVA；多跳 scope 收缩 = CVA 明示 future work；撤销/委托链 = D3-08 已裁已知。
- "联合证明"是这些组件的组合，不是新证明关系（判据 6 未过）。
- CVA §4.5 已把 runtime execution binding 判为 structural gap：ZK 电路在证明时无运行时状态访问权——关闭它需要执行时 trust anchor（TEE/zkAgent），不是新电路关系。
- 与 D3-10 一致：递归连续状态转换 ≠ 外部历史完整。

---

## 3. 整阶段最终决策

# `CONDITIONAL_HOLD`

- `GO_CRYPTOGRAPHIC_PROTOTYPE`：**否**——判据 2、3、6 未过，未找到经得起 SCITT 强基线检验的新证明性质。
- `CONDITIONAL_HOLD`：**是**——方向 A 的"合规判定隐私化验证"是四篇基线均未提供的残存候选，但需先过 H1/H2 门禁。
- `REJECT_AS_KNOWN_PROBLEM`：对方向 B、C 分别成立；对整阶段不成立（因方向 A 仍有未证伪的候选）。
- `STOP_RESEARCH_DIRECTION`：否——Agent 执行证据的隐私化验证是有真实需求的领域，只是本轮未找到可立即立项的独立性质。

---

## 4. 本轮最重要的两条边界（必须保留）

1. **签名有效 ≠ 事件真实。** 四篇强基线一致：签名证明"指定主体签了某条记录"，不证明工具内部行为与记录一致。NovaFabric 原文：key custodian 可签一条断言虚假的合法 capsule，"no amount of downstream verification detects it"。关闭此缺口需外部信任基（TEE/远程证明/zkAgent 式观察绑定），不是密码学证明关系本身。

2. **日志可追加 ≠ 日志无遗漏。** SCITT Profile §11.5 原文："An action that was never recorded leaves no gap"；§9.2："does not establish that the Harness recorded every call"。序列缺口只能证明"产生了但未注册"。这是 D3-10 X2′（递归证明 ≠ 外部历史完整）在证据层的翻版。

**由此**：七个攻击 X1–X7 没有一个由纯密码学 `BLOCKED`；六个是 `BLOCKED_WITH_ASSUMPTION`，阻断能力全部来自外部信任基或分布式假设。这是"缺口在信任边界、不在证明系统"的实证。

---

## 5. 下一步建议（暂停后由用户决定）

若用户认可方向 A 值得推进，**下一步不是写电路**，而是先做一个"证伪性小检查"：
1. 取 SCITT -02 的 `call_digest` + linked verification 作为明文基线；
2. 尝试写出"隐藏 `call_digest/actor_chain/principal`、只证关联+合规"的证明关系；
3. 明确列出 public 锚点（必须来自 VDS 已签承诺）；
4. 回答 H1：这个隐藏相对明文比对究竟新增了哪种可验证性质？若答不出，方向 A 降级 REJECT。

只有当 H1/H2 都通过，才考虑进入最小原型——且届时仍需重新裁决，不自动启动。

**本轮完成后暂停**：不写 Halo2 电路、不改 MVP、不改任何冻结仓库、不做性能实验。
