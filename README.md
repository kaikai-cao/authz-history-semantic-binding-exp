# D3-07-B-P1 — Pending Lock Recovery Protocol Audit

本目录是一个**独立、只读于冻结仓库**的协议审计与确定性模拟实验。它研究四节点、3-of-4 quorum、最多一个 Byzantine Witness 条件下，checkpoint 候选已签名但 QC 未被观察到时，pending lock 如何恢复。

本轮不实现 FC、不改 Halo2、不改 D3-06-C 或 D3-07-A，也不创建或推送 GitHub 仓库。

## 1. 固定参数

| 参数 | 值 |
| --- | --- |
| Witness 数 N | 4 |
| QC threshold | 3 |
| FC threshold | 3 |
| Byzantine 上限 f | 1 |
| 随机种子 | 20261124（实际调度为显式事件，种子仅固定实验标识） |
| Lease 长度 | 默认 100；CK 边界场景显式使用 50 |
| 时钟偏差 epsilon | 5 |
| checkpoint 字段 | chain_id, witness_set_id, epoch, checkpoint_digest, parent_digest, transition_version |

所有场景使用确定性事件序列，没有随机测试替代指定攻击场景。

## 2. 目录结构

```text
README.md
PROTOCOL-MODELS.md
ATTACK-SCENARIOS.md
SAFETY-INVARIANTS.md
RESULTS.md
src/simulator.py      状态机、投票对象、Gateway 验证、事件记录
src/scenarios.py      P1–P10 + U1/AL1/CK1–CK7 确定性调度
src/report.py         从结果 JSON 生成 RESULTS.md
tests/test_all.py     自动化验收测试
results/p1_p10.json   全部 39 个场景的完整事件与判定
results/summary.json  运行摘要
```

## 3. 复现命令

在 Windows / Git Bash 中：

```bash
cd /d/Research/d3-07-b-protocol-audit
PYTHONPATH=src python3 src/scenarios.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 src/report.py
```

`src/scenarios.py` 写出 `results/p1_p10.json` 与 `results/summary.json`；`src/report.py` 从 JSON 重新生成 `RESULTS.md`。仅依赖 Python 3 标准库。

## 4. 冻结仓库不受影响

本轮开始前记录的 HEAD：

```text
authz-history-semantic-binding-exp 89caad7
agent-authz-halo2-exp              51d0fa2
authorization-state-trust-exp      09da2a6
```

可用以下命令复核：

```bash
git -C /d/Research/authz-history-semantic-binding-exp status --short
git -C /d/Research/agent-authz-halo2-exp status --short
git -C /d/Research/authorization-state-trust-exp status --short
git -C /d/Research/authz-history-semantic-binding-exp rev-parse --short HEAD
git -C /d/Research/agent-authz-halo2-exp rev-parse --short HEAD
git -C /d/Research/authorization-state-trust-exp rev-parse --short HEAD
```

## 5. 结果摘要

- A（Permanent Lock）：安全边界最容易描述，但未完成候选可无限阻塞；P1/P4/P8 显示 Liveness 失败。AL1 显示持久化全损会破坏 S5。
- B（Tendermint-style Reference）：timeout 仅推进轮次；PoLC/lock transfer 才改变锁状态。P1–P10 诚实 Witness 未出现 S1–S5 违规，恢复依赖最终通信。
- C（Bounded Lease）：到期后可恢复可用性，但 CK1–CK7 显示安全与活性都绑定单调可信时钟；Gateway 时钟回拨可重新接受旧 QC。
- U1：把 timeout 当作解锁证明的反例，产生冲突提交，S2 失败。

**核心答案**：不用可信时钟，安全恢复可以由 quorum-evidence 的轮次切换规则支撑；活性不能无条件保证，仍需最终通信/部分同步假设。详见 `RESULTS.md`。

## 6. 边界声明

- 模拟器不是密码学实现，Vote 只是结构化绑定对象；
- 通过模拟不等于证明 BFT soundness；
- 不声称全球最新状态；
- 不声称生产级持久化；
- 不把 Tendermint/HotStuff 的规则照搬为授权状态协议；
- 所有结论按“已由模拟器验证 / 由协议规则推导 / 仍依赖外部假设 / 当前无法证明”分类。
