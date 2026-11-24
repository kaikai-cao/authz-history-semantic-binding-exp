"""Generate RESULTS.md from the deterministic scenario output."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "results" / "p1_p10.json").read_text(encoding="utf-8"))
PIDS = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10")
MODELS = ("A", "B", "C")


def cell(pid: str, model: str) -> str:
    r = DATA[f"{pid}-{model}"]
    safety = "S✓" if all(r["safety"].values()) else "S!" + ",".join(
        k for k, v in sorted(r["safety"].items()) if not v
    )
    live = "".join("1" if r["liveness"][k] else "0" for k in ("L1", "L2", "L3", "L4"))
    accepted = [d.split()[0] for d in r["gateway_decisions"] if d.startswith(("QC_ACCEPT", "FC_ACCEPT"))]
    ok = f"{safety} L={live} accept={','.join(accepted) if accepted else 'none'}"
    if r["notes"]:
        ok += " *note*"
    return ok


def p_table() -> str:
    lines = [
        "| 场景 | A | B | C |",
        "| --- | --- | --- | --- |",
    ]
    for pid in PIDS:
        lines.append("| " + pid + " | " + " | ".join(cell(pid, m) for m in MODELS) + " |")
    return "\n".join(lines)


def extra_table() -> str:
    keys = ["U1-UNSAFE", "AL1-A", "CK1-C", "CK2-C", "CK3-C", "CK4-C", "CK5-C", "CK6-C", "CK7-C"]
    lines = [
        "| 场景 | 安全 | Gateway 决策 | 结论标签 |",
        "| --- | --- | --- | --- |",
    ]
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
    }
    for k in keys:
        r = DATA[k]
        safety = "S✓" if all(r["safety"].values()) else "S!" + ",".join(
            x for x, v in sorted(r["safety"].items()) if not v
        )
        decisions = "<br>".join(r["gateway_decisions"][-2:]) or "none"
        lines.append(f"| {k} | {safety} | {decisions} | {labels[k]} |")
    return "\n".join(lines)


TEXT = f"""# EXP-D3-07-B-P1 — Results

## 1. 核心答案

**如果不引入可信时钟，能否用有明确安全规则的轮次切换解决 pending lock 恢复？**

- **安全层面：可以，但必须依靠 quorum 证据而不是本地超时。** 已由模拟器验证：Model B 的 PoLC/lock-transfer 规则在 P1–P10 中对诚实 Witness 没有产生 S1–S5 违规；单方 timeout 只推进轮次，不构成解锁证据（U1 反例显示纯 timeout 解锁会导致冲突提交）。
- **活性层面：不能无条件保证。** 在异步网络中，系统无法仅靠本地决定判断“没有 QC 形成”。Model B 的推进依赖网络最终恢复、诚实节点之间可交换 PoLC/precommit 证据，以及持久化状态延续。这是**部分同步/最终通信**假设，不是可信墙上时钟假设；但也不是无假设的异步活性。
- 因此推荐路线是 **B 为主、A 为安全基线、C 仅作带时钟对照实验**，不把 D1 parent-child lock 直接升级为“签名后永久锁定 head”。

证据标签：安全结论由模拟器验证；活性中的“最终通信”由协议规则推导，仍依赖外部网络条件；生产级 BFT soundness 与全球最新性当前无法证明。

## 2. P1–P10 结果表

记号：`S✓`=S1–S5 通过；`S!编号`=对应不变量失败；`L=L1L2L3L4`，1=该场景满足，0=不满足。`accept=` 为 Gateway 实际接受类型。`*note*` 表示存在场景专属说明，见 `results/p1_p10.json` 的 `notes`。

{p_table()}

A/B/C 在 P1–P10 中均未出现 S1–S5 违规；安全性结论不因 fail-closed 拒绝而自动成立，Liveness 单列统计。

## 3. A/B/C 对照

| 指标 | A Permanent Lock | B Tendermint-style Reference | C Bounded Lease |
| --- | --- | --- | --- |
| 旧状态被重新接受 | 是（P3：FC 可对旧 digest 成功） | 否（P3：更高轮 PoLC 阻止旧 FC） | 是（P3：租约内仍可对旧 digest 成功） |
| 冲突 checkpoint 被接受 | 否（P4/P7/P8） | 否（P4/P7/P8） | 否（P4/P7/P8） |
| 未完成候选阻塞 | 是（P1/P4/P8：永久阻塞） | 否：有 honest quorum 时经更高轮推进 | 到期前是；到期后可恢复（P1/P4/P8） |
| Witness 崩溃恢复 | P5/P6 通过；AL1 全损时 S5 失败 | P5/P6 通过；需保留 round/lock 与投票日志 | P5/P6 通过；需保留 lease/pending 与投票日志 |
| 是否依赖可信时钟 | 否 | 否 | 是（CK1–CK7） |
| 是否依赖轮次切换协议 | 否 | 是 | 否 |
| 额外网络消息 | 不新增；靠可信恢复 | prevote/precommit/round-change/PoLC 证据 | 不新增轮次消息；有效期检查进入验证条件 |
| 安全假设 | 持久化 pending lock + 可信人工恢复 | quorum 交集、诚实多数、持久化投票状态、最终通信 | 单调可信时钟、epsilon、持久化租约状态 |
| 结论标签 | 由协议规则推导 + 模拟器验证 | 由协议规则推导 + 模拟器验证 | 由模拟器验证；时钟假设仍依赖外部 |

P10 显示 `set-v1`/`set-v2` 是不同 binding namespace：混合签名 QC 被拒，但当前模拟器**没有**定义经认证的轮换规则，因此“两个 set 分别提交冲突 digest”不是 S2 违规，而是明确的未解决问题。

## 4. 额外边界场景与反例

{extra_table()}

两个必须保留的反例：

1. **U1（不安全恢复）**：把 timeout 当作解锁证明后，W1/W2 改签冲突 checkpoint，配合 1 个 Byzantine witness 形成第二个 QC；Gateway 因 S2 拒绝冲突提交，但“两个诚实节点先后签署冲突状态”的安全边界已经被破坏。已由模拟器验证。
2. **AL1（持久化全损）**：pending lock 与已签投票日志同时丢失后，Witness 可回退到更旧的可签署状态，S5 失效。已由模拟器验证；这说明“持久化锁可信”本身是外部假设。

CK7 显示 Gateway 本地时钟回拨可让过期 QC 再次被接受，因此 Bounded Lease 的 freshness 完全依赖单调可信时钟；CK4 说明时钟不可用时无法作安全释放决定。

## 5. 不变量覆盖

| 不变量 | 覆盖场景 | 结果 | 结论标签 |
| --- | --- | --- | --- |
| S1 同轮同 Witness 不签冲突投票 | P4/P7/P8 | 诚实 Witness 通过；Byzantine 冲突被单独记录 | 已由模拟器验证 |
| S2 已提交 checkpoint 不被冲突替代 | P2/P3/P4/P7/P8/P9/U1 | A/B/C 通过；U1 失败 | 已由模拟器验证 |
| S3 QC/FC 绑定同一 checkpoint 字段 | 全部 QC/FC 提交 | 通过 | 已由模拟器验证 |
| S4 旧轮签名不得重解释为新轮签名 | P2/P8/CK5 | 通过 | 已由模拟器验证 |
| S5 重启不得回退已持久化签署状态 | P5/P6/AL1 | P5/P6 通过；AL1 全损失败 | 已由模拟器验证 |
| L1 网络恢复后可推进 | P1/P4/P8 | A 否；B 是；C 到期后是 | 由协议规则推导 + 模拟器验证 |
| L2 未完成候选不无限阻塞 | P1/P4/P8 | A 是阻塞；B/C 在各自条件下否 | 已由模拟器验证 |
| L3 一节点离线仍有 quorum | P1/P4/P8 | 条件性满足，见各场景 notes | 已由模拟器验证 |
| L4 是否需要可信管理员 | 全部 | A 是；B 否；C 否但需可信时钟 | 由协议规则推导 |

## 6. 研究差异性检查

1. **D1 parent-child lock 已提供什么？** 签名前的本节点锁与拒绝冲突签名；它防止本地双签，但不能证明 QC 未形成，也不能恢复已锁状态。已由协议规则推导。
2. **nonce-bound FC 新增什么？** 把认证绑定到当前请求 nonce，阻止旧 checkpoint 直接当作本次新鲜响应；它不自动解决 pending lock 恢复。已由 P9 验证。
3. **monotonic head 新增什么？** 给 Gateway 一个单调状态目标，减少旧状态回退；但没有 quorum 锁转移规则时仍会卡在 pending lock。已由 P3/P4 推导与验证。
4. **Tendermint-style lock transfer 是否只是已有共识机制的应用？** 是机制借鉴，不是新共识发明；研究价值不在“提出 BFT”，而在精确映射授权状态 Witness 的签名/锁定/恢复边界，并对照 D1 已有限制。已由协议规则推导。
5. **Bounded Lease 是否只是时钟换可用性？** 是。CK1–CK7 显示其安全与活性都依赖单调可信时钟；它适合做对照，不适合无时钟假设下的主方案。已由模拟器验证。
6. **是否存在值得继续研究的授权状态特有问题？** 有条件存在：Gateway 只持有外部锚定的局部视图，而 Witness 可能已观察到更高状态；P3 中 A/C 对旧 digest 签 FC 显示“QC 有效 ≠ 当前状态新鲜”。这是与授权状态锚定结合的具体问题，不是通用 BFT 结论。仍依赖外部 latestness 机制才能闭合。

## 7. 推荐与未解决问题

推荐：**以 Model B 的 quorum-evidence lock transfer 为后续研究对象，Model A 作为安全基线，Model C 仅在明确可信时钟的场景做对照。** 不把 timeout 当作安全解锁证据，不把本模拟器结果当成 BFT soundness 或全球最新性证明。

未解决：

- 完整 BFT 状态机的证明、持久化投票状态与崩溃恢复细节仍属外部工作；
- 部分同步/GST 假设的网络条件未在本模拟器中量化；
- Witness Set 认证的轮换规则缺失（P10）；
- Gateway 如何获得“更高状态存在”的可信证据仍未定义（P3）；
- FC 与 Halo2/D3-07-A 锚定的具体接口未实现，本轮不动冻结仓库；
- 生产级持久化、时钟源和 Byzantine 行为边界不在本轮证明范围。
"""

(ROOT / "RESULTS.md").write_text(TEXT, encoding="utf-8")
print("wrote RESULTS.md")
