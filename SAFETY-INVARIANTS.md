# SAFETY-INVARIANTS.md（R1）

Safety 与 Liveness 在本审计中分开统计。fail-closed 拒绝只说明没有接受坏输入，不能自动证明系统能继续推进。R1 进一步把 Liveness 从作者手写改为从事件与最终状态机器推导。

## 1. Safety

### S1 — 同轮不双签

同一 `lock_key`、同一轮次、同一 vote kind 下，诚实 Witness 不得为两个冲突 `checkpoint_digest` 产生有效投票。

- 检查方式：`Witness.floor()` 与 `signed_votes` 扫描；
- Byzantine 冲突签名记为 `adversarial_observations`，不计入诚实 Witness 的 S1；
- 覆盖：P4/P7/P8、**R1-B6**（Byzantine 双签不放松诚实锁）；
- 结果：A/B/C 的诚实 Witness 全部通过；W4 的冲突签名被单独记录。

### S2 — 已提交 checkpoint 不被冲突替代

Gateway 在同一 `lock_key` 下接受第二个冲突 digest，记为失败。

- 覆盖：P2/P3/P4/P7/P8/P9/U1；
- 结果：A/B/C 在 P1–P10 中通过；U1 因 timeout 解锁策略失败。
- R1 补充：P3-B 中冲突 QC 因锁规则**不可达**，不是靠 Gateway 事后拒绝。

### S3 — QC/FC 绑定一致

被接受的 QC/FC 的所有 vote 必须绑定同一 `chain_id`、`witness_set_id`、`epoch`、`checkpoint_digest`、`parent_digest`、`transition_version`，FC 还必须绑定同一 nonce。

- 检查方式：Gateway 提交前按 `full_key` 与 nonce 过滤；
- 结果：全部场景通过；P10 混合 set votes 被拒。

### S4 — 旧轮签名不得重解释

任何 vote 的 `round` 进入绑定；Gateway 只接受与提交轮次完全相同的 vote。

- 覆盖：P2/P8/CK5、**R1-B8**（旧轮 PoLC 不能用于新轮 precommit）；
- 结果：通过；旧轮签名被记录为 `old_round_vote_ignored`。

### S5 — 重启不回退已持久化签署状态

重启后 Witness 的签署 floor（最高轮次与该轮 digest）不得低于重启前。

- 覆盖：P5/P6/AL1、**R1-B7**（locked_round/locked_digest 完整恢复）；
- 结果：完整重启与 pending 记录丢失（signed_vote 日志仍在）均通过；AL1 中 pending 与投票日志同时丢失，S5 失败。

## 2. Liveness（R1 机器推导）

R0 的 L1–L4 由场景作者手写。R1 改为 `Simulator.derive_liveness()` 从**已记录事件与最终状态**计算，`tests/test_all.py` 再独立从序列化日志重算 L1/L3/L4 交叉验证。每个指标有三种状态：

| 状态 | 记号 | 含义 |
| --- | --- | --- |
| `achieved` | A | 前置条件成立，且从证据观察到目标结果 |
| `not_achieved` | N | 前置条件成立，但证据显示目标未达成 |
| `not_applicable` | X | 前置条件不成立，**不自动计为通过** |

`author_liveness_r0` 字段保留 R0 手写值，仅供对照。

### L1 — 网络恢复后有 QC/FC 被接受

- 前置：事件中存在 `qc_accepted` / `fc_accepted`，或存在 `timeout_round_advance` / `trusted_recovery` / heal/recovery 阶段；
- 达成：存在至少一个被接受的 QC/FC；
- 未达成：尝试了恢复但无 QC/FC 被接受（如 P8-B）；
- 不适用：既无接受也无恢复尝试。

### L2 — 未完成候选不无限阻塞

- 前置：存在由 1..2 个不同 Witness 签署、且未被任何 QC/FC 接受的候选；
- 达成：仍有 QC/FC 被接受，且最终 durable locked/pending 中无未解析项；
- 未达成：无接受的进展，或存在未解析锁（P1-A、P4-A/C、P8-A/B）；
- 不适用：本调度没有未完成候选。

### L3 — 一个 Byzantine/offline 节点仍有诚实 quorum

- 前置：事件中出现 `byzantine_marked`；
- 达成：某个被接受的 QC/FC 的 signer 集合中，非 Byzantine 节点数 ≥ 3；
- 未达成：没有由 3 个诚实节点构成的被接受 QC/FC（如 P2-B 的 signers 为 W2/W3/W4，其中 W4 为 Byzantine）；
- 不适用：本调度没有 Byzantine 节点。

### L4 — 恢复不依赖管理员 / 额外轮次 / 可信时钟

- 前置：存在被接受的 QC/FC；
- 达成：事件中无 `trusted_recovery`、无 `timeout_round_advance`，且模型不是 C；
- 未达成：依赖上述任一项（Model B 的正常恢复几乎都会因 round change 记为 N）；
- 不适用：没有接受事件，无法观察依赖。

**P8-B 的 R1 结论**：两个诚实 Witness 在 cp_a@0 上锁定时，heal 后缺乏严格解锁 PoLC，`cp_c@1` 冲突 prevote 被拒，形成不了 QC。这是 `not_achieved`，不是 fail-closed 成功；R0 声称的"进入更高轮次即可恢复"被推翻。

## 3. 证据标签

每个结论必须属于以下之一：

1. **已由模拟器验证**：`results/p1_p10.json` 中有对应事件与 Gateway 决策；
2. **由协议规则推导**：来自状态转换定义，而不是单次模拟；
3. **仍依赖外部假设**：honest quorum、最终通信、持久化、可信时钟、配置来源等；
4. **当前无法证明**：BFT soundness、全球最新状态、生产级持久化、完整轮换协议。

## 4. 统计原则（R1）

- 不把 safety 通过写成 liveness 通过；
- 不把 fail-closed 拒绝写成协议完成了恢复；
- 不把 `not_applicable` 计为通过（R0 的手写布尔在此项上会失真）；
- 不把单个调度通过写成所有调度安全；
- 不把进入更高轮次写成合法解锁；
- Liveness 字段必须与可从事件重算的状态一致，测试会交叉验证；
- 不把 Tendermint/HotStuff 参照写成继承其安全证明。
