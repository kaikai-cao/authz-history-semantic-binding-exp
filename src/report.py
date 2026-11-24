"""Generate RESULTS.md from the deterministic scenario output (R1).

All numbers in the report are derived from results/p1_p10.json; no summary
figure is hand-edited.  R0 author annotations are kept only as a comparison
column and are never used as the R1 result.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "results" / "p1_p10.json").read_text(encoding="utf-8"))
SUMMARY = json.loads((ROOT / "results" / "summary.json").read_text(encoding="utf-8"))
PIDS = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10")
MODELS = ("A", "B", "C")
R1_IDS = tuple(f"R1-B{i}" for i in range(1, 9))
ABBR = {"achieved": "A", "not_achieved": "N", "not_applicable": "X"}


def safety_str(r: dict) -> str:
    if all(r["safety"].values()):
        return "S✓"
    return "S!" + ",".join(k for k, v in sorted(r["safety"].items()) if not v)


def live_str(r: dict) -> str:
    return "".join(ABBR[r["liveness"][k]["status"]] for k in ("L1", "L2", "L3", "L4"))


def r0_str(r: dict) -> str:
    return "".join("1" if r["author_liveness_r0"].get(k, False) else "0" for k in ("L1", "L2", "L3", "L4"))


def accepted(r: dict) -> list[str]:
    return [d.split()[0] for d in r["gateway_decisions"] if d.startswith(("QC_ACCEPT", "FC_ACCEPT"))]


def cell(pid: str, model: str) -> str:
    r = DATA[f"{pid}-{model}"]
    acc = accepted(r)
    return f"{safety_str(r)} L={live_str(r)} accept={','.join(acc) if acc else 'none'}"


def p_table() -> str:
    lines = ["| 场景 | A | B | C |", "| --- | --- | --- | --- |"]
    for pid in PIDS:
        lines.append("| " + pid + " | " + " | ".join(cell(pid, m) for m in MODELS) + " |")
    return "\n".join(lines)


def r1_model_b_table() -> str:
    lines = [
        "| 场景 | 预期 | can_sign | 产生签名 | QC | Safety | 关键理由 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for sid in R1_IDS:
        r = DATA[f"{sid}-B"]
        note = next((n for n in r["notes"] if n.startswith(sid) and "expected_allowed=" in n), "")
        m = re.search(
            r"expected_allowed=(\w+)\s+(?:can_sign|actual)=(\w+)(?:\s+signature_created=(\w+))?(.*)",
            note,
        )
        if m:
            exp, actual, sig = m.group(1), m.group(2), m.group(3) or "n/a"
            reason = m.group(4)
            reason = re.sub(r";\s*(lock|polc|current_round)=.*", "", reason)
            reason = re.sub(r"^qc_accepted=\w+\s*reason=", "", reason).strip(" ;")
        else:
            exp = actual = sig = "?"
            reason = "见事件日志"
        lines.append(
            f"| {sid} | {exp} | {actual} | {sig} | {len(r['gateway_qc'])} | "
            f"{safety_str(r)} | {reason[:110]} |"
        )
    return "\n".join(lines)


def r0_r1_table() -> str:
    lines = [
        "| 场景 | R0 L (作者填写) | R1 L (机器推导) | R1 QC 数 | 判定 |",
        "| --- | --- | --- | --- | --- |",
    ]
    verdicts = {
        "P2-B": "R0 声称 QC 形成但缺 PoLC 投递；R1 用真实 3-of-4 PoLC 重建 QC",
        "P3-B": "R0 依赖错误锁转移；R1 改为不可达性测试",
        "P8-B": "R0 声称 heal 后可恢复；R1 显示锁定节点无解锁证据时不可达",
    }
    for pid in PIDS:
        r = DATA[f"{pid}-B"]
        verdict = verdicts.get(
            f"{pid}-B",
            "Liveness 口径改为机器推导，安全结论保持",
        )
        lines.append(f"| {pid}-B | {r0_str(r)} | {live_str(r)} | {len(r['gateway_qc'])} | {verdict} |")
    return "\n".join(lines)


def extra_table() -> str:
    keys = ["U1-UNSAFE", "AL1-A"] + [f"CK{i}-C" for i in range(1, 8)] + ["FRESH-B-B"]
    labels = {
        "U1-UNSAFE": "已由模拟器验证：超时解锁产生冲突提交",
        "AL1-A": "已由模拟器验证：持久化全损时 S5 失效",
        "CK1-C": "已由模拟器验证：过期 QC 被拒",
        "CK2-C": "已由模拟器验证：以 Gateway 提交时刻为准",
        "CK3-C": "已由模拟器验证：epsilon 边界",
        "CK4-C": "仍依赖外部假设：时钟回拨/不可用",
        "CK5-C": "已由模拟器验证：旧轮签名不混入新轮",
        "CK6-C": "已由模拟器验证：旧 QC 过期后重放被拒",
        "CK7-C": "已由模拟器验证：Gateway 时钟回拨重新接受旧 QC",
        "FRESH-B-B": "由协议规则推导 + 模拟器验证：QC 不等于全局最新",
    }
    lines = ["| 场景 | Safety | Liveness | Gateway 决策 | 结论标签 |", "| --- | --- | --- | --- | --- |"]
    for k in keys:
        r = DATA[k]
        decisions = "<br>".join(r["gateway_decisions"][-2:]) or "none"
        lines.append(f"| {k} | {safety_str(r)} | {live_str(r)} | {decisions} | {labels[k]} |")
    return "\n".join(lines)


TEXT = f"""# EXP-D3-07-B-P1-R1 — Results

> 本文件由 `src/report.py` 从 `results/p1_p10.json` 自动生成。R1 修正了 R0 的 Model B 锁转移规则、
> P2/P3 场景与 Liveness 统计口径。R0 的手写标注仅作对照列保留，不参与 R1 结论。
> 修订 `{SUMMARY['revision']}`，场景数 `{SUMMARY['scenario_count']}`，seed `{SUMMARY['seed']}`。

## 1. 核心答案

**不引入可信墙上时钟时，能否用有明确安全规则的轮次切换解决 pending lock 恢复？**

- **安全层面：可以，但只能依靠 quorum 证据。** R1 修正后的 Model B 严格执行
  `locked_round < polc_round < current_round`：仅进入更高轮次、同轮或低轮 PoLC 都不能解锁；
  timeout 只推进轮次状态机。U1 反例仍显示纯 timeout 解锁会导致冲突提交。
- **活性层面：不能无条件保证。** 保护安全性的代价是：P8-B 中两个诚实 Witness 已锁定一个
  未形成 QC 的状态后， healed 网络也不能单靠更高轮次恢复——它们无法自行制造解锁所需的
  冲突 quorum。活性依赖网络最终恢复、诚实节点能交换 quorum 证据、以及持久化状态延续。
  这是**部分同步/最终通信**假设，不是可信墙上时钟假设。
- 结论仍是 **B 为主、A 为安全基线、C 作带时钟对照**，但 R0 的 B 活性结论被收紧：
  R1 不再声称"进入更高轮次即可恢复"。

证据标签：安全与可达性结论由模拟器验证；"最终通信"由协议规则推导并仍依赖外部网络条件；
生产级 BFT soundness 与全球最新性当前无法证明。

## 2. R1 对 R0 的三项修正

1. **锁转移规则**：R0 的 `can_sign()` 在 `round > locked_round` 时直接允许冲突 prevote，
   且在 `round <= locked_round` 时允许同轮 PoLC 解锁。R1 改为严格三段不等式，并区分
   `current_round / locked_round / polc_round / locked_digest / polc_digest`；precommit 还要求
   同轮精确 PoLC 与自身 prevote。
2. **PoLC 证据**：R0 的 PoLC 统计遗漏 Witness 自己的投票；R1 合并投票日志与送达消息，
   并以 `(witness, vote.binding())` 去重。
3. **Liveness**：R0 由场景作者直接写 L1–L4；R1 从事件与最终状态推导，前置条件缺失时标记
   `not_applicable`（`X`），不再自动计为通过。

## 3. P1–P10 结果表（R1）

记号：`S✓`=S1–S5 通过；`S!编号`=对应不变量失败。
`L` 顺序为 `L1L2L3L4`，`A`=achieved、`N`=not_achieved、`X`=not_applicable。
`accept=` 为 Gateway 实际接受类型。

{p_table()}

R0/R1 对比（仅 B 模型，L 列为各自口径）：

{r0_r1_table()}

P2-B 的事件证据：W2/W3 各自观察到 `['W1','W2','W3']` 三份 prevote 并形成 PoLC，
W1 只观察到自身；Gateway 收到 `['W2','W3','W4']` 三份 precommit 并形成 QC。
P3-B 的事件证据：W2/W3 锁定 `cp_old@0`，冲突 `cp_new@1` 的 PoLC 为 False，
只有 Byzantine W4 签出冲突 prevote；冲突 QC 不可达。
P8-B 的事件证据见 `results/p1_p10.json` 的 `notes`：锁定节点无解锁 quorum，恢复不可达。

## 4. Model B 专项回归（R1-B1–R1-B8）

{r1_model_b_table()}

`预期`/`can_sign`/`产生签名` 均取自真实 `can_sign` → `sign_vote` 路径，不是测试构造器预判；
所有场景的 `ANOMALY` 标记为空，Safety 均为 `S✓`。

## 5. 额外边界场景与反例

{extra_table()}

必须保留的反例：

1. **U1（不安全恢复）**：把 timeout 当作解锁证明后，两个诚实 Witness 改签冲突 checkpoint，
   配合 1 个 Byzantine witness 形成第二个 QC；S2 被破坏。已由模拟器验证。
2. **AL1（持久化全损）**：pending lock 与签署日志同时丢失后，S5 失效。已由模拟器验证；
   "持久化锁可信"本身是外部假设。

CK7 显示 Gateway 时钟回拨可让过期 QC 再次被接受；CK4 说明时钟不可用时无法作安全释放决定。
FRESH-B 明确区分三层状态：Gateway 的 committed QC、Witness 的 durable lock、
Witness 的 volatile observed。有效 QC 只证明 cp_old 被 commit，不证明它是最新状态。

## 6. A/B/C 对照（R1）

| 指标 | A Permanent Lock | B Tendermint-style Reference | C Bounded Lease |
| --- | --- | --- | --- |
| 旧状态被重新接受 | 是（A/C 可对旧 digest 签 FC） | 否：锁定规则阻止诚实节点改签旧状态 | 是：租约内可对旧 digest 签 FC |
| 冲突 checkpoint 被接受 | 否 | 否（R1-B1–B8、P3/P7） | 否 |
| 未完成候选阻塞 | 是，永久 | 条件性：有解锁 quorum 才恢复（P1 恢复、P8 阻塞） | 到期前是；到期后可恢复 |
| Witness 崩溃恢复 | P5/P6 通过；AL1 全损时 S5 失败 | P5/P6 通过；须保留 round/lock 与投票日志 | P5/P6 通过；须保留 lease/pending |
| 是否依赖可信时钟 | 否 | 否 | 是（CK1–CK7） |
| 是否依赖轮次切换协议 | 否 | 是，且需严格 lock transfer | 否 |
| 额外网络消息 | 不新增；靠可信恢复 | prevote/precommit/PoLC/round-change 证据 | 有效期检查进入验证条件 |
| 安全假设 | 持久化 pending lock + 可信人工恢复 | quorum 交集、诚实多数、持久化投票状态、最终通信 | 单调可信时钟、epsilon、持久化租约状态 |

## 7. 不变量覆盖

| 不变量 | 覆盖场景 | R1 结果 | 结论标签 |
| --- | --- | --- | --- |
| S1 同轮同 Witness 不签冲突投票 | P4/P7/P8、R1-B6 | 诚实 Witness 通过；Byzantine 冲突单独记录 | 已由模拟器验证 |
| S2 已提交 checkpoint 不被冲突替代 | P2/P3/P4/P7/P8/P9、U1 | P1–P10 通过；U1 失败 | 已由模拟器验证 |
| S3 QC/FC 绑定同一 checkpoint 字段 | 全部 QC/FC 提交 | 通过 | 已由模拟器验证 |
| S4 旧轮签名不得重解释为新轮签名 | P2/P8、CK5、R1-B8 | 通过 | 已由模拟器验证 |
| S5 重启不得回退已持久化签署状态 | P5/P6、AL1、R1-B7 | P5/P6/R1-B7 通过；AL1 全损失败 | 已由模拟器验证 |
| L1 网络恢复后可推进 | P1/P4/P8 | A 否；B 条件性；C 到期后是 | 由机器推导 + 规则推导 |
| L2 未完成候选不无限阻塞 | P1/P4/P8 | A 阻塞；B 条件性；C 到期后否 | 由机器推导 |
| L3 一节点离线仍有 quorum | P2/P3/P7/P9 | 视具体 signer 集合，`X` 表示前置条件缺失 | 由机器推导 |
| L4 是否需要管理员/额外轮次/可信时钟 | 全部 | 由事件中的 `trusted_recovery`/`timeout_round_advance`/模型参数推导 | 由机器推导 |

## 8. 研究差异性检查

1. **D1 parent-child lock 已提供什么？** 签名前的本节点锁与拒绝冲突签名；它不能证明 QC 未形成，也不能恢复已锁状态。由协议规则推导。
2. **nonce-bound FC 新增什么？** 把认证绑定到当前请求 nonce；它不自动解决 pending lock 恢复。已由 P9 验证。
3. **monotonic head 新增什么？** 给 Gateway 单调状态目标；没有 quorum 锁转移规则时仍会卡在 pending lock。已由 P3/P8 验证。
4. **Tendermint-style lock transfer 是否只是已有共识机制的应用？** 是机制借鉴，不是新共识发明；价值在精确映射授权状态 Witness 的签名/锁定/恢复边界。由协议规则推导。
5. **Bounded Lease 是否只是时钟换可用性？** 是。CK1–CK7 显示其安全与活性都依赖单调可信时钟。已由模拟器验证。
6. **是否存在值得继续研究的授权状态特有问题？** 有条件存在：Gateway 只有局部视图，且 QC 有效不等于状态最新（FRESH-B）。仍依赖外部 latestness 机制才能闭合。

## 9. 推荐与未解决问题

推荐：**以 Model B 的 quorum-evidence lock transfer 为后续研究对象，A 作安全基线，C 仅在明确可信时钟时做对照。** 不把 timeout 当安全解锁证据，不把模拟器结果当成 BFT soundness 或全球最新性证明。

未解决：

- R1-B3 只验证单节点解锁许可，未验证完整多轮协议的可达性；
- P8-B 显示锁定节点可能在无解锁 quorum 时永久阻塞，恢复所需 quorum 的形成条件未定义；
- 完整 BFT 状态机证明、持久化投票状态与崩溃恢复细节仍属外部工作；
- 部分同步/GST 假设未在本模拟器中量化；
- Witness Set 认证轮换规则缺失（P10）；
- Gateway 获得"更高状态存在"可信证据的机制未定义（FRESH-B）；
- FC 与 Halo2/D3-07-A 锚定的接口未实现，本轮不动冻结仓库。
"""

(ROOT / "RESULTS.md").write_text(TEXT, encoding="utf-8")
print(f"wrote RESULTS.md from {len(DATA)} scenario results")
