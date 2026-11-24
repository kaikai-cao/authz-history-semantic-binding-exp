# ATTACK-SCENARIOS.md

所有场景的逐事件证据（序号、时间、发送/接收、签名时刻、持久化变化、QC/FC、Gateway 原因、Witness 快照）在 `results/p1_p10.json`。本文件给出可读摘要。

## 1. P1–P10

| ID | 初始状态与调度 | 消息延迟 / 丢失 | 最终 Witness 状态 | Gateway 决策 | 安全不变量 | 活性阻塞 |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | W1/W2 对候选 cpA 已签名，但只有 2 份签名；W1 timeout 后尝试 cpB | 无网络分区；B 场景中第 3 个 W3 在恢复轮加入 | A/C：W1/W2 pending cpA，拒绝 cpB；B：无 PoLC 故无锁，进入更高轮并形成 cpB QC | A/C 无 QC；B 接受 cpB QC | 无 S1–S5 违规 | A 永久阻塞；B 恢复；C 租约到期后恢复 |
| P2 | W1/W2/W3 签 cpA；W1 未看到 QC | W2/W3 的确认延迟到 W1；Gateway 收到足够签名 | A/C：W1 锁定 cpA 但本地视图旧；B：W1 未观察 PoLC，后续被要求学习 commit | A/B/C 接受 cpA QC；cpB QC 因无有效签名/冲突被拒 | 无 S1–S5 违规；旧轮 vote 不计入新轮 | A 的 W1 需要可信恢复；B/C 全局可推进 |
| P3 | Gateway 只见旧 cpOld；Witness 已观察到 cpNew 或更高轮证据 | cpNew 不送到 Gateway | A/C：Witness 仍可为 cpOld 签 FC；B：W1 观察到更高轮 PoLC 后拒绝旧 FC | A/C 接受旧 digest FC；B 拒绝 | 无 S1–S5 违规；这是 freshness limitation | A/C 以旧状态继续；B 需要获取新状态证据 |
| P4 | 两个 sibling checkpoint cpA/cpB，各有两方签名 | 两分区各 2 票，无一方达到 3 | A/C 双方 pending 冲突；B 无 PoLC，可在新轮提出 cpC | A 无 QC；B/C 接受 cpC QC | 无冲突 checkpoint 被接受 | A 阻塞；B 立即恢复；C 到期后恢复 |
| P5 | 三 Witness 对 cpA 形成 QC，然后完整重启 | 无 | 锁、committed 与投票日志恢复；W1 改签 cpB 被拒 | 原 cpA QC 有效；cpB QC 被拒 | S5 通过 | A 需可信恢复变更 digest；B/C 可按各自规则推进 |
| P6 | 三 Witness 对 cpA 形成 QC，然后 W1/W2 丢失 pending 记录 | 无 | 从持久化 signed_vote 日志重建 pending/locked；冲突签名被拒 | 原 cpA QC 有效；cpB QC 被拒 | S5 通过 | 三节点可得 quorum；A 仍不可自行改锁 |
| P7 | W4 为 Byzantine，对 cpA/cpB 同轮签冲突 prevote/candidate | byz 的 cpA 发给全员，cpB 只给 Gateway | 诚实 W1/W2 锁 cpA；W4 冲突被记录为对抗观察 | cpA QC 接受；cpB QC 被拒 | 诚实 Witness S1 通过；Byzantine 冲突单列 | 1 个 Byzantine 不阻断 quorum |
| P8 | 网络分区，Witness 观察不同轮次；W4 双签 | 分区内定向投递；Gateway 每侧只见 2 票 | B：每侧不足 quorum；heal 后 W1/W2/W3 在更高轮形成 PoLC；A/C：两侧 pending 冲突 | 分区 QC 均被拒；B 接受 cpC QC；C 到期后接受；A 无 QC | 无冲突提交；S4 通过 | A 阻塞；B 恢复；C 到期后恢复 |
| P9 | cpNew 已提交，Gateway 对 cpOld 发新 nonce FC | 仅 W4 为 cpOld 签 FC | 诚实 Witness 因冲突锁/committed 拒绝 | cpOld FC 被拒；cpNew 可继续认证 | S2/S3 通过 | 无阻塞；stale FC 无法形成 |
| P10 | set-v1 已提交 cpOld，轮换到 set-v2 后请求 cpNew | 混合 set-v1/v2 的 vote 被提交给 Gateway | 旧 pending 按 witness_set_id 隔离；新 set 可独立形成 QC | 混合 QC 被拒；cpOld(set-v1) 与 cpNew(set-v2) 分别被接受 | 无 S1–S5 违规；S3 要求同 set | 新 namespace 可推进，但轮换信任未定义 |

`accept=none` 表示 Gateway 在该场景没有接受 QC/FC，不等于测试失败；Safety 与 Liveness 分开记录。

## 2. 额外边界与反例

| ID | 目的 | 预期与实测 | 结论标签 |
| --- | --- | --- | --- |
| U1 | timeout 直接解锁的不安全策略 | 两个诚实 Witness 在已提交 cpA 后改签 cpB；配合 W4 形成第二 QC 请求；Gateway 因 S2 拒绝，但 S2 违规已经发生 | 已由模拟器验证 |
| AL1 | A 模型持久化锁与投票日志同时丢失 | W1 回退到更旧可签署状态，S5 失败 | 已由模拟器验证 |
| CK1 | 签名早于租约，QC 晚于租约提交 | Gateway 拒绝 | 已由模拟器验证 |
| CK2 | 3 票在到期前已存在，但到期后才提交 | Gateway 按提交时刻拒绝 | 已由模拟器验证 |
| CK3 | 时钟偏差处于 epsilon 边界 | `now=expiry+epsilon` 接受；`+1` 拒绝 | 已由模拟器验证 |
| CK4 | Witness 时钟回拨 / 不可用 | 无法作安全释放决定；记为外部时钟假设 | 仍依赖外部假设 |
| CK5 | 旧租约签名与新轮签名混合 | 旧轮签名被排除；新轮 3 票形成 QC | 已由模拟器验证 |
| CK6 | 旧 QC 在租约过期后重放 | 被拒 | 已由模拟器验证 |
| CK7 | Gateway 时钟回拨到过期前 | 旧 QC 重新被接受；freshness 失效 | 已由模拟器验证 |

## 3. 与指定攻击矩阵的对应

任务包 P1–P10 全部实现为独立确定性场景；A/B/C 各跑一遍。`src/scenarios.py` 中的 `SCENARIOS` 是唯一调度来源，`tests/test_all.py` 验证数量、确定性与关键结果。场景专属说明写入 `results/p1_p10.json` 的 `notes`，不只在文档中口头描述。
