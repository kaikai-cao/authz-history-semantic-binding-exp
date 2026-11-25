# D3-18-02 Phase 2：参考数据选择性查询与泄露审计

基准日期：2026-11-25。证据等级见 SOURCES.md。**本轮未执行任何查询或攻击实验**；本文件区分"数学可恢复性""协议允许的查询能力""真实实现限制"三个层次，不把理论推导写成已完成攻击。

## 1. 决定性原文（SealCall §3.3，逐字）

> "The output interface fixes what the trusted recipient learns. Returning individual similarities supports trusted maximum selection and inspection of references; **a controller able to query arbitrary basis vectors can also recover reference coordinates from these similarities. The present trust model permits this access within C. Protecting a provider's reference assets against the controller is a separate goal: it calls for an output-restricted protocol that reveals prescribed predictions or search results** (Juvekar et al., 2018; Chen et al., 2020). This provides a route to extending input confidentiality to protection of both parties' data."

`[原文, §3.3, HTML 纯文本 L410–418]`

这段同时回答了本 Phase 的核心问题：**作者自己承认**任意基向量查询可恢复参考坐标，且**明确声明当前信任模型允许 C 这样做**，并把"保护 provider 参考资产"列为独立目标与未来路线。因此这不是一个被遗漏的漏洞，而是**已声明的系统边界**。

## 2. 数学推导（本轮新增，标明为推断）

设参考向量 `p_j ∈ R^d`，查询向量 `q = e_i`（第 i 个标准基向量），则返回相似度：

```
s_j = ⟨e_i, p_j⟩ = p_j[i]
```

若允许对全部 `d` 个基向量 `e_1,...,e_d` 提交查询，则可逐坐标恢复 `p_j` 的 d 个分量，即恢复整个参考向量。`[推断]`

**次数**：恢复单个 d 维参考向量需 `d` 次查询（每次得 1 个坐标）；恢复全部 `K=16` 个 d=256 维参考向量理论上需 `K×d = 16×256 = 4096` 次单坐标查询（若一次查询可返回 K 个相似度，则 d=256 次查询即可覆盖各参考的每个坐标——SealCall 返回的是"individual similarities"，故后者更贴近本系统）`[推断]`。原文未给出此类查询次数上界，也未报告任何查询频率/格式限制 `[原文未见]`。

**数值误差影响**：§4.4 报告 packed 参考 scorer 的最大最终分数误差 `1.52×10⁻⁶`、全布局全 scorer 约 `1.19×10⁻⁵` `[原文]`。该误差量级远小于典型坐标幅值，因此**数值误差不足以阻止近似的坐标恢复**；是否足以精确重建到可用精度取决于下游用途，本轮未实验，标 `[推断]`。原文另注 "an error harmless for a well-separated score can change a decision near its threshold" `[原文, §3.3]`——误差对决策的影响与对坐标恢复的影响是两件事，不可混同。

## 3. 逐项回答任务包 Phase 2 的七个问题

| # | 问题 | 结论 | 证据等级与依据 |
|---|---|---|---|
| 1 | 原文是否确实允许控制器任意基向量查询？ | **是，且为明文陈述** | `[原文, §3.3]` "a controller able to query arbitrary basis vectors can also recover reference coordinates"；"present trust model permits this access within C" |
| 2 | 控制器是否持有生成查询密文的能力？ | **是** | `[原文, §2.2/§3.3]` controller 构造并加密表示、持 pk 与 secret key；server 只有 pk/evk、无密钥。原文明确 controller "constructs and encrypts representations" |
| 3 | 服务端是否有查询格式/频率/身份/来源限制？ | **原文未见任何此类限制** | `[原文未见]`；§3.4 的 call binding 是 **C 侧**对结果的检查（"result belongs to this request"），不是 S 侧对查询者身份/来源的认证 |
| 4 | 是否有模型版本/参考数据访问控制/查询审计？ | **版本：有流程性要求；访问控制与审计：无** | `[原文, §3.4]` representation+data+arithmetic+decision rule 组成 "one versioned configuration"，provider 更新须 "renewed validation before the controller activates"——但这是流程纪律，非密码学绑定、非可信外部锚；对 C 的参考访问控制被明确列为 "separate goal" `[原文, §3.3]` |
| 5 | 恢复参考坐标需多少次查询？ | 单向量 d 次；K×d（或按批 d 次）| `[推断]`，见 §2；原文未给次数 |
| 6 | CKKS 数值误差是否影响恢复精度？ | 不足以阻止近似恢复；精确可用精度未测 | `[推断]` + `[原文]` 误差 1.52×10⁻⁶ / 1.19×10⁻⁵ |
| 7 | 是威胁模型边界还是可触发攻击？ | **在论文模型内是已声明边界；只有在"要求参考对 C 也保密"的替代模型下才成为攻击面** | `[原文 + 推断]`。论文把对 C 的参考保护列为 separate goal 并指向现成 output-restricted 协议，说明其目标部署中 C 被信任可读参考 |

## 4. 三层区分（任务包明确要求）

- **数学上的可恢复性**：`⟨e_i,p_j⟩=p_j[i]` 成立，d 次基查询可重建参考向量。`[推断]`，且被原文以文字承认 `[原文]`
- **协议允许的查询能力**：controller 可任意构造并加密查询、无来源/频率限制、信任模型允许其读取相似度 `[原文 + 原文未见反例]`
- **真实实现是否存在限制**：**未检视 SealCall 实现（本轮禁实现/禁改代码），也未运行攻击**。原文未提任何速率限制/查询白名单/输出裁剪 `[原文未见]`。不能声称"已完成攻击实验"或"真实实现可被实际攻破"

## 5. 对本轮选题的直接含义

1. **用户上轮判断得到证实**：既然真正价值在"维护参考数据且不暴露用户查询"，那么焦点必须在参考数据的保密边界——而 Phase 1/2 显示 SealCall 的参考数据**对 controller 不保密、对 semi-honest server 保密**，这是一组**有意选择**的边界，不是待补的密码学漏洞。`[原文 + 推断]`
2. **双边隐私不是新缺口**：§3.3 自己指向 Juvekar et al. 2018（即 GAZELLE）与 Chen et al. 2020 的 output-restricted protocol；S4/S5/S6 原文证实 GAZELLE/SANNS/SOTERIA 已在 semi-honest 下同时保护两侧数据 `[原文]`。**把双边隐私 + 恶意服务完整性 + 工具调用绑定拼起来，是把三套成熟机制做系统集成**（见 RELATED-WORK-MATRIX.md 与 DECISION.md）。
3. **不能反向用它论证 ZK 必要性**：D3-18-01 已据此判定"ZK 在本场景无明确不可替代增益"；本轮原文进一步坐实——若 C 可读参考，则需要防的是"服务伪造分数"（计算完整性），而非"向验证者隐藏 Θ"。`[原文 + 推断]`

## 6. 边界声明

本 Phase 的结论**不意味着**"恢复攻击已验证"或"实现必然有此漏洞"；只意味着"数学上可恢复 + 协议允许 + 作者已声明并给出解决路线"。任何把此写成"我们发现了 SealCall 的新攻击"的表述都超出证据，明确禁止。
