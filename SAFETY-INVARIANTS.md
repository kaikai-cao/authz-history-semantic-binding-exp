# SAFETY-INVARIANTS.md

Safety 与 Liveness 在本审计中分开统计。fail-closed 拒绝只说明没有接受坏输入，不能自动证明系统能继续推进。

## 1. Safety

### S1 — 同轮不双签

同一 `lock_key`、同一轮次、同一 vote kind 下，诚实 Witness 不得为两个冲突 `checkpoint_digest` 产生有效投票。

- 检查方式：`Witness.floor()` 与 `signed_votes` 扫描；
- Byzantine 冲突签名记为 `adversarial_observations`，不计入诚实 Witness 的 S1；
- 覆盖：P4/P7/P8；
- 结果：A/B/C 的诚实 Witness 全部通过；W4 的冲突签名被单独记录。

### S2 — 已提交 checkpoint 不被冲突替代

Gateway 在同一 `lock_key` 下接受第二个冲突 digest，记为失败。

- 覆盖：P2/P3/P4/P7/P8/P9/U1；
- 结果：A/B/C 在 P1–P10 中通过；U1 因 timeout 解锁策略失败。

### S3 — QC/FC 绑定一致

被接受的 QC/FC 的所有 vote 必须绑定同一 `chain_id`、`witness_set_id`、`epoch`、`checkpoint_digest`、`parent_digest`、`transition_version`，FC 还必须绑定同一 nonce。

- 检查方式：Gateway 提交前按 `full_key` 与 nonce 过滤；
- 结果：全部场景通过；P10 的混合 set  votes 被拒。

### S4 — 旧轮签名不得重解释

任何 vote 的 `round` 进入绑定；Gateway 只接受与提交轮次完全相同的 vote。

- 覆盖：P2/P8/CK5；
- 结果：通过；旧轮签名被记录为 `old_round_vote_ignored`。

### S5 — 重启不回退已持久化签署状态

重启后 Witness 的签署 floor（最高轮次与该轮 digest）不得低于重启前。

- 覆盖：P5/P6/AL1；
- 结果：完整重启与 pending 记录丢失（signed_vote 日志仍在）均通过；AL1 中 pending 与投票日志同时丢失，S5 失败。

## 2. Liveness

### L1 — 网络恢复后可推进

在网络恢复、诚实 Witness 可通信且满足模型条件后，是否能形成新的合法 QC/FC。

- A：否，除非触发可信恢复；
- B：是，需要更高轮 PoLC 与诚实 quorum；
- C：是，但仅在租约到期且时钟可信后。

### L2 — 未完成候选不无限阻塞

- A：是，会阻塞；
- B：否，无 PoLC 不产生锁；
- C：到期前是，到期后否。

### L3 — 一个节点离线仍有 quorum

3/4 诚实节点在数学上可形成 quorum；但已有锁/损坏状态可能使其不可用。各场景按实际可用签署者单独报告，不把数值 quorum 当成可用性保证。

### L4 — 是否需要可信管理员或额外共识轮次

- A：需要可信恢复流程；
- B：不需要管理员，但需要额外轮次与 PoLC 证据；
- C：不需要管理员，但需要可信单调时钟。

## 3. 证据标签

每个结论必须属于以下之一：

1. **已由模拟器验证**：`results/p1_p10.json` 中有对应事件与 Gateway 决策；
2. **由协议规则推导**：来自状态转换定义，而不是单次模拟；
3. **仍依赖外部假设**： honest quorum、最终通信、持久化、可信时钟、配置来源等；
4. **当前无法证明**：BFT soundness、全球最新状态、生产级持久化、完整轮换协议。

## 4. 统计原则

- 不把 safety 通过写成 liveness 通过；
- 不把 fail-closed 拒绝写成协议完成了恢复；
- 不把单个调度通过写成所有调度安全；
- 不把 Tendermint/HotStuff 参照写成继承其安全证明。
