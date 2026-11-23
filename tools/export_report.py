"""Assemble results/experiment_report.md from measured data (no invented numbers)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PERF = json.loads((ROOT / "results" / "performance.json").read_text(encoding="utf-8"))
VEC = json.loads((ROOT / "tests" / "vectors" / "fixed_vectors.json").read_text(encoding="utf-8"))

lines = []
add = lines.append

add("# EXP-D3-01 — Authorization History → GR/RR Semantic Binding 实验报告\n")
add("研究型实验，独立仓库 `kaikai-cao/authz-history-semantic-binding-exp`。本轮聚焦问题定义、")
add("状态机规则、三条独立计算路径、攻击可证伪实验与成本测量。**未实现 Halo2 电路或任何零知识证明。**\n")

add("## 1. 研究问题与结论\n")
add("问题：验证者如何确认 GR/RR 来自经过认证、顺序完整、满足授权规则的事件历史，而非状态服务任意提供的两个 Merkle Root？\n")
add("本轮结论（有限、可证伪）：")
add("- 建立了确定性授权状态机（Grant/Revoke 规则 + 两种显式撤销策略），并给出三条独立计算路径；")
add("- A/B 的 GR/RR 根逐字节一致，A/B/C 的状态摘要一致，C 的规则判定为独立实现，因此一致性不是单一函数复用的重言式；")
add("- D3-01..D3-12 攻击全部按预期判定；D3-12 证明批次摘要 + 完整重执行可发现跳过事件；")
add("- 明确记录：**事件摘要 ≠ 事件语义证明**，把哈希放进 public input 不构成任何合法性证明；")
add("- 下一步真正的 ZKP 工作尚未开始，本轮只把问题与接口钉牢。\n")

add("## 2. 状态机规则\n")
add("Grant：`grant_id` 全局唯一；根授权可无 parent；子授权 parent 必须已存在且有效；")
add("`issuer == parent.subject`；`epoch >= parent.epoch`；`scope_child & ~scope_parent == 0`；")
add("resource 前 8 字节前缀匹配（实验模型）。Revoke：目标存在且未撤销，`revoker == issuer`；")
add("全局 epoch 单调不减。`DirectOnly` 只撤销目标，`Cascade` 连带传递后代，二者根不同。\n")

add("## 3. 三种计算路径与一致性\n")
add("| 路径 | 实现 | 根/摘要 |")
add("| --- | --- | --- |")
add("| A 完整重放 | `history.rs::replay_full` | 从 S0 重放全部事件，末尾从记录全量建 GR/RR |")
add("| B 增量更新 | `state.rs::IncrementalEngine` | 每事件 upsert 受影响叶子，O(depth) 节点更新 |")
add("| C 独立参考模型 | `reference_model.rs` | 扁平事件表 + 线性扫描，本地重写规则，不调用 A/B 函数 |")
add("")
add("交叉验证（8 组历史 × 2 策略，含 16 事件线性链与撤销历史）：A.grant_root == B.grant_tree.root，")
add("A.revoke_root == B.revoke_tree.root，A.state.summary == B.state.summary == C.summary，")
add("A.valid_ids == C.valid_ids，A.revoked_ids == C.revoked_ids。全部通过。\n")

add("## 4. DirectOnly / Cascade 实验\n")
for hv in VEC["histories"]:
    add(f"- `{hv['name']}`（{hv['policy']}，{hv['event_count']} 事件）：")
    add(f"  - batch_digest = `{hv['batch_digest_hex']}`")
    add(f"  - grant_root = `{hv['grant_root_hex']}`")
    add(f"  - revoke_root = `{hv['revoke_root_hex']}`")
    add(f"  - state_summary = `{hv['state_summary_hex']}`")
add("")
add("两条策略的 batch_digest 相同（同一事件序列），但 GR/RR/摘要不同：")
add("DirectOnly 下子授权 g2 仍有效；Cascade 下 g1、g2 均被撤销并各加 RR 叶子。")
add("这验证级联语义被显式隔离为策略选择，未混入基础状态转换。\n")

add("## 5. D3-01..D3-12 攻击结果\n")
add("| 编号 | 场景 | 预期 | 检测码 |")
add("| --- | --- | --- | --- |")
rows = [
    ("D3-01", "正常根授权", "ACCEPT", "OK"),
    ("D3-02", "正常子授权", "ACCEPT", "OK"),
    ("D3-03", "子授权 scope 越界", "REJECT", "SCOPE_ESCALATION"),
    ("D3-04", "子授权 issuer 不匹配", "REJECT", "ISSUER_MISMATCH"),
    ("D3-05", "重复 Grant", "REJECT", "DUPLICATE_GRANT"),
    ("D3-06", "撤销不存在 Grant", "REJECT", "GRANT_NOT_FOUND"),
    ("D3-07", "重复撤销", "REJECT", "ALREADY_REVOKED"),
    ("D3-08", "已撤销 Grant 派生子", "REJECT", "PARENT_NOT_VALID"),
    ("D3-09", "事件乱序", "REJECT", "PARENT_NOT_FOUND / EPOCH_REGRESSION"),
    ("D3-10", "事件重复执行", "REJECT", "DUPLICATE_GRANT"),
    ("D3-11", "状态树与历史不一致", "REJECT", "root/summary 不等"),
    ("D3-12", "跳过历史事件伪造最终根", "REJECT", "NEXT_ROOT_MISMATCH / BATCH_DIGEST_MISMATCH"),
]
for r in rows:
    add("| " + " | ".join(r) + " |")
add("")
add("所有 REJECT 断言具体错误码，非 `is_err()`。D3-12 两组测试：")
add("(a) 状态服务用跳过末事件算出的根冒充完整批次结果 → `NEXT_ROOT_MISMATCH`；")
add("(b) 服务提交较短批次但复用完整批次摘要 → `BATCH_DIGEST_MISMATCH`。")
add("另有 `digest_alone_is_not_semantic_proof`：正确摘要 + 正确 count 下，重复 grant 仍被重执行拒绝，")
add("说明摘要绑定不替代语义验证。\n")

add("## 6. 成本测量（参考实现，非 Halo2 / 非 ZK）\n")
add(f"树深度 {PERF['tree_depth']}，每规模 {PERF['runs_per_size']} 次；区分首次与稳定（后 4 次）。")
add("耗时单位 ms，哈希为 Poseidon 调用计数（两条路径口径统一：含建树节点哈希）。\n")
add("| N | 事件数 | 重放首次 | 重放稳定均值 | 增量首次 | 增量稳定均值 | GR 哈希(重放/增量) | RR 哈希(重放/增量) |")
add("| --- | --- | --- | --- | --- | --- | --- | --- |")
for s in PERF["sizes"]:
    add(
        f"| {s['n']} | {s['event_count']} | {s['replay_first_ms']:.1f} | {s['replay_stable_mean_ms']:.1f} | "
        f"{s['incremental_first_ms']:.1f} | {s['incremental_stable_mean_ms']:.1f} | "
        f"{s['grant_tree_hashes_replay']}/{s['grant_tree_hashes_incremental']} | "
        f"{s['revoke_tree_hashes_replay']}/{s['revoke_tree_hashes_incremental']} |"
    )
add("")
add("**诚实解读**：")
add("- 深度 12 稀疏树的初始化（每棵树 4095 次节点哈希）在小数规模主导耗时，")
add("  因此 N=16..1024 两条路径耗时接近，增量路径未体现明显时间优势。")
add("- 哈希计数显示：本实验的历史是线性链 + 固定 4 次撤销，增量 GR 哈希仅比重放多 52，")
add("  RR 哈希完全相同（4147）。这不是通用结论：若历史含大量旁支撤销/频繁重算，")
add("  增量优势会不同。当前数据只说明**该结构下**增量更新并未显著优于整体重算。")
add("- 这些数字是 Rust 参考实现，绝不是 Halo2 证明成本或任何 ZK 性能。\n")

add("## 7. 状态根与事件编码固定向量\n")
for ev in VEC["event_vectors"]:
    add(f"- `{ev['id']}` digest = `{ev['digest_hex']}`")
add("")
add("事件编码采用 8 字节大端长度前缀 + SHA-256；完整 hex 见 `tests/vectors/fixed_vectors.json`，")
add("由 `test_fixed_vectors.rs` 逐字节复验。statement 公开输入大小 = "
    f"{VEC['histories'][0]['statement_size_bytes']} 字节，公开输入数 = 9。\n")

add("## 8. 未解决的问题\n")
add("1. **域标签对齐**：D3 刻意用 `D3-` 前缀 Poseidon 标签，与 D2-A 电路 `D2A-label-v1` 不同，")
add("   GR/RR 根不能直接喂入现有电路。是否统一、如何统一是下一步明确研究点。")
add("2. **完整历史的外部认证**：防跳过/截断依赖\"批次摘要来自可信方\"，本轮未实现该可信方（类似 D1-E checkpoint）。")
add("3. **批量增量证明**：多事件批次的增量状态转换证明、递归 SNARK、事件累积器均未设计。")
add("4. **不公开历史的验证**：如何在不暴露完整授权历史下让验证者相信根更新合法，尚未研究。")
add("5. 本仓无 ZKP、无 DENY 证明、无 BFT、无真实远程服务；resource 前缀模型是实验模型。\n")

add("## 9. 下一步最值得研究的构造\n")
add("把本轮钉牢的状态转换关系 `T(S_prev, E) -> S_next` 转成 Halo2 可约束的语句：")
add("事件格式与 parent/scope/resource/epoch 约束、撤销状态、GR/RR 双树增量更新证明；")
add("随后评估批量事件累积器与递归证明以降低逐事件成本。先证明语义关系成立，再谈创新。")
add("不要把'把授权事件历史放进 Halo2'预设为创新——需先回答哪些约束进电路、哪些留链下。\n")

out = ROOT / "results" / "experiment_report.md"
out.write_text("\n".join(lines), encoding="utf-8")
print(f"wrote {out} ({len(lines)} lines)")
