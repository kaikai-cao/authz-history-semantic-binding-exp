# ATTACK-SCENARIOS.md（R1）

所有场景的逐事件证据（全局序号、时间、发送/接收、签名时刻、持久化变化、QC/FC、Gateway 原因、Witness 快照）在 `results/p1_p10.json`。本文件给出可读摘要。R1 共 48 个场景：P1–P10 × A/B/C、U1、AL1、CK1–CK7、FRESH-B、R1-B1–B8。

## 1. P1–P10（R1 修正后的 B 模型）

| ID | 初始状态与调度 | 消息延迟 / 丢失 | 最终 Witness 状态 | Gateway 决策 | 安全不变量 | 活性阻塞 |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | W1/W2 对 cpA 已签名，但只有 2 份；W1 timeout 后尝试 cpB | B：W3 在恢复轮加入 | A/C：pending cpA 拒绝 cpB；B：两份 prevote 未形成锁，新轮 3 票形成 cpB QC | A/C 无 QC；B 接受 cpB QC | 无 S1–S5 违规 | A 永久阻塞；B 恢复；C 租约到期后恢复 |
| P2 | W1/W2/W3 签 cpA@0 prevote；W1 未看到 QC | **B：W1 的 prevote 交付 W2/W3；W2/W3 互换但不交付 W1** | B：W2/W3 各观察 3 票形成 PoLC 并 precommit；W1 只看到自身，学习 cpA commit 后冲突 prevote 被拒 | A/B/C 接受 cpA QC；B 的 signers=W2/W3/W4 | 无 S1–S5 违规；旧轮票不计入新轮 | A 的 W1 需可信恢复；B/C 全局可推进 |
| P3 | Gateway 只见 cpOld；B 中诚实节点已锁定 cpOld@0 | cpNew 只由 Byzantine W4 签出，不送达 Gateway | B：W2/W3 锁定 cpOld@0，冲突 cpNew@1 的 PoLC=False，诚实节点拒绝改签；A/C：仍可为 cpOld 签 FC | B 只接受 cpOld QC；A/C 接受旧 digest FC | 无 S1–S5 违规；B 冲突 PoLC **不可达** | B 需外部最新性证据；A/C 以旧状态继续 |
| P4 | 两个 sibling cpA/cpB，各有两方签名 | 两分区各 2 票 | A/C 双方 pending 冲突；B：cpC 新轮由 3 诚实票形成 PoLC 并恢复 | A 无 QC；B/C 接受 cpC QC | 无冲突提交 | A 阻塞；B 恢复；C 到期后恢复 |
| P5 | 三 Witness 对 cpA 形成 QC，完整重启 | 无 | 锁、committed、投票日志恢复；W1 改签 cpB 被拒 | cpA QC 有效；cpB QC 被拒 | S5 通过 | A 需可信恢复变更 digest |
| P6 | 三 Witness 形成 QC，W1/W2 丢失 pending 记录 | 无 | 从 signed_vote 日志重建 pending/locked；冲突签名被拒 | cpA QC 有效；cpB QC 被拒 | S5 通过 | 三节点仍有 quorum；A 不可自行改锁 |
| P7 | W4 Byzantine，对 cpA/cpB 同轮双签 | byz 的 cpA 发全员，cpB 只给 Gateway | 诚实 W1/W2 锁 cpA；W4 冲突记为对抗观察 | cpA QC 接受；cpB QC 被拒 | 诚实 S1 通过；Byz 冲突单列 | 1 个 Byzantine 不阻断 quorum |
| P8 | 网络分区，Witness 观察不同状态；W4 双签 | 分区定向投递；Gateway 每侧只见 2 票 | **B：W1/W2 在 cpA@0 上 precommit 并锁定（观察含 W4 的 PoLC），但 Gateway 只收到 2 票；heal 后超时不能解锁，cpC@1 冲突 prevote 被拒** | 分区 QC 均被拒；**B 的 cpC QC 不可达**；C 到期后接受；A 无 QC | 无冲突提交；S4 通过 | A 阻塞；**B 在锁定节点无解锁 quorum 时也阻塞（R0 结论被推翻）**；C 到期后恢复 |
| P9 | cpNew 已提交，Gateway 对 cpOld 发新 nonce FC | 仅 W4 为 cpOld 签 FC | 诚实 Witness 因 committed 冲突拒绝 | cpOld FC 被拒；cpNew 可继续认证 | S2/S3 通过 | 无阻塞；stale FC 无法形成 |
| P10 | set-v1 已提交 cpOld，轮换到 set-v2 请求 cpNew | 混合 set-v1/v2 的 vote 提交 Gateway | 旧锁按 witness_set_id 隔离；新 set 可独立形成 QC | 混合 QC 被拒；两个 set 分别被接受 | 无 S1–S5 违规；S3 要求同 set | 新 namespace 可推进；轮换信任未定义 |

`accept=none` 表示 Gateway 在该场景没有接受 QC/FC，不等于测试失败；Safety 与 Liveness 分开记录。
R1 的 Liveness 列见 `RESULTS.md` 第 3 节，使用 `A/N/X`（achieved / not_achieved / not_applicable）。

## 2. Model B 锁转移专项（R1-B1–R1-B8）

每个场景直接安装初始锁/PoLC 状态，然后走真实 `can_sign` → `sign_vote` → `submit_qc` 路径；`预期`、`can_sign`、`产生签名` 均来自事件记录。

| ID | 初始锁状态 | PoLC 证据 | 当前轮 / 目标轮 | 预期 | 实测 |
| --- | --- | --- | --- | --- | --- |
| R1-B1 | cp_a @ round 2 | 无 | 3 / prevote cp_b@3 | 拒绝 | 拒绝，理由含 `locked_round < polc_round < current_round` |
| R1-B2 | cp_a @ round 2 | cp_b @ round 2（同轮） | 3 / prevote cp_b@3 | 拒绝 | 拒绝，同轮 PoLC 不解锁 |
| R1-B3 | cp_a @ round 2 | cp_b @ round 3 | 4 / prevote cp_b@4 | 允许 | 允许，理由 `2 < 3 < 4`，签名产生 |
| R1-B4 | cp_a @ round 2 | cp_b @ round 4 | 4 / prevote cp_b@4 | 拒绝 | 拒绝，`polc_round == current_round` 不满足严格不等式 |
| R1-B5 | 无 | 仅 W1/W2 两票 | 0 / precommit cp@0 | 拒绝 | 不形成 PoLC，precommit 签名未产生 |
| R1-B6 | cp_a @ round 2 | Byzantine W4 双签 cp_a/cp_b@3 | 3 / prevote cp_b@3 | 拒绝 | 诚实 Witness 不因 Byzantine 双签放宽锁 |
| R1-B7 | cp_a @ round 2 | 无 | 3 / 完整重启后 prevote cp_b@3 | 拒绝 | locked_round/digest 从持久化状态恢复 |
| R1-B8 | 无 | cp @ round 1 | 2 / precommit cp@2 | 拒绝 | 精确轮次匹配，旧轮 PoLC 不复用 |

全部 8 个场景 Safety 为 `S✓`，无 `ANOMALY` 标记。

## 3. 额外边界、反例与 freshness

| ID | 目的 | 预期与实测 | 结论标签 |
| --- | --- | --- | --- |
| U1 | timeout 直接解锁的不安全策略 | 两个诚实 Witness 在已提交 cpA 后改签 cpB；配合 W4 形成第二 QC 请求；Gateway 因 S2 拒绝，但 S2 违规已发生 | 已由模拟器验证 |
| AL1 | A 模型持久化锁与投票日志同时丢失 | W1 回退到更旧可签署状态，S5 失败 | 已由模拟器验证 |
| CK1 | 签名早于租约，QC 晚于租约提交 | Gateway 拒绝 | 已由模拟器验证 |
| CK2 | 3 票到期前已存在，到期后才提交 | Gateway 按提交时刻拒绝 | 已由模拟器验证 |
| CK3 | 时钟偏差处于 epsilon 边界 | `now=expiry+epsilon` 接受；`+1` 拒绝 | 已由模拟器验证 |
| CK4 | Witness 时钟回拨 / 不可用 | 无法作安全释放决定 | 仍依赖外部假设 |
| CK5 | 旧租约签名与新轮签名混合 | 旧轮签名被排除；新轮 3 票形成 QC | 已由模拟器验证 |
| CK6 | 旧 QC 在租约过期后重放 | 被拒 | 已由模拟器验证 |
| CK7 | Gateway 时钟回拨到过期前 | 旧 QC 重新被接受；freshness 失效 | 已由模拟器验证 |
| FRESH-B | Gateway 持有 cp_old QC，诚实 Witness 锁定 cp_old，cp_new 冲突 prevote 因锁规则被拒 | 接受 cp_old QC；三层状态写入 `notes`；结论：QC 有效不等于全局最新 | 由协议规则推导 + 模拟器验证 |

## 4. 与指定攻击矩阵的对应

任务包 P1–P10 全部实现为独立确定性场景，A/B/C 各跑一遍；R1 新增 P3 可达性分析与独立 freshness 场景 FRESH-B，以及 R1-B1–B8 锁转移专项。`src/scenarios.py` 中的 `SCENARIOS` 是唯一调度来源，`tests/test_all.py` 验证数量、确定性、锁规则、P2/P3/P8 事件证据与 Liveness 一致性。场景专属说明写入 `results/p1_p10.json` 的 `notes`，不只在文档中口头描述。
