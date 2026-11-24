# EXP-D3-07-B-P2-SA — Model B Safety 核心论证独立数学审计

> 独立数学审计，只回答一个问题：在 `N=4, Q=3, f≤1` 下，当前 P2 状态机是否足以推出两个冲突 checkpoint 不可能同时形成有效 QC？
> 基线分支 `exp-d3-07-b-p2-design` @ `b18a0c6`。
> 本轮不修改任何现有文档、不改协议规则、不实现代码、不进 P3。
>
> **最终结论：`PROOF_SUPPORTED`（带关键前提与一处规格歧义标注）。** 原 S-A 的鸽巢表述不成立；改用"最早冲突事件归纳"后论证成立，但成立依赖当前规则中几条常被忽略的绑定条件（PoLC 必须绑定 chain_id/set_id/epoch、round 进入签名体、PRECOMMIT 要求同轮精确 PoLC、honest 遵守 S1）。这是规则层推导，不是机器检查的形式化证明。

---

## 1. 审计对象与固定假设

### 1.1 被审计的性质 S-A

> 两个冲突 checkpoint（同一 `lock_key=(chain_id,set_id,epoch)`、不同 `digest`）不会同时获得有效 QC。

### 1.2 审计范围（逐条对应任务包 §3）

| 编号 | 规则 | 原文位置 |
| --- | --- | --- |
| R-QC | QC = 3 份不同 Witness 对同一 round、同一完整 C 的 PRECOMMIT | STATE-MACHINE §2.5；PROTOCOL §3.2 |
| R-PoLC | PoLC = 3 份不同 Witness 对同一 round、同一 digest 的 PREVOTE；按 `(witness,binding)` 去重 | STATE-MACHINE §2.3 |
| R-LOCK | 解锁冲突 digest 的充要条件：`locked_round < polc_round < current_round`，PoLC 绑定同一 `(chain_id,set_id,epoch)` 且目标为冲突 digest | STATE-MACHINE §3.1/§3.2 |
| R-PREVOTE | prevote 冲突 digest 必须走 R-LOCK 解锁路径；同轮同 Witness 不得对两个冲突 digest prevote（S1） | STATE-MACHINE §2.2(a)(b)(c2)、§1 |
| R-PRECOMMIT | precommit 必须：本轮已对同一 C prevote、观察到 `(r,C)` 精确 PoLC（`r_p==r`）、若已锁冲突 digest 则满足 R-LOCK；动作先写 `durable_lock=(r,C.digest)` | STATE-MACHINE §2.4(a)–(d) 及动作 |
| R-ROUND | `current_round` 只由显式 `ROUND_ADVANCE` 单调推进，签名不隐式抬轮 | STATE-MACHINE §2.1；S6 |

### 1.3 固定假设（任务包 §3.7）

`N=4`、`Q=3`、`f≤1`、`witness_set` 固定；签名不可伪造；摘要抗碰撞；honest Witness 遵守上述规则；参与 quorum 的签名按 Witness 身份计票（非按权重）。

### 1.4 关键定义（消除歧义）

- **冲突**：`lock_key` 相同而 `digest` 不同。两个不同 `epoch` 或不同 `set_id` 的 checkpoint **不是**冲突，S-A 不适用。
- **有效 QC**：满足 R-QC 且 Gateway 验证顺序全部通过的 QC（SECURITY-ARGUMENT §4）。本审计只检验"能否形成两套签名集合"，Gateway 的 freshness/Halo2 步骤不在范围内（它们在 R-QC 之后独立拒绝，只会更严格）。
- **诚实 PRECOMMIT**：honest Witness 按 R-PRECOMMIT 产生的 PRECOMMIT；因此它必然满足 (b)(c)(d) 且已写锁。

---

## 2. Quorum 交集计算（任务包 A）

设 `S1, S2 ⊆ W`，`|S1|=|S2|=3`，`|W|=4`。

**(1) 最小交集**：

```
|S1 ∩ S2| = |S1| + |S2| − |S1 ∪ S2| ≥ 3 + 3 − 4 = 2
```

两个 3-of-4 quorum 的最小交集为 **2 个 Witness**。

**(2) 交集中的诚实 Witness 下界**：`f≤1`，交集中最多 1 个 Byzantine，故

```
|诚实 ∩ (S1 ∩ S2)| ≥ 2 − 1 = 1
```

交集中**至少 1 个诚实 Witness**，不是 2 个。

**(3) 原 S-A 表述判定**：原论证（SECURITY-ARGUMENT §2 S-A）写"至少 2 个 Witness 必须为两个冲突 digest 都签了 precommit（鸽巢原理）……f=1 下最多 1 个 Byzantine 双签，无法凑出第二个含 ≥2 honest 双签者的 QC"。

- "至少 2 个 Witness 双签"：成立（交集 ≥2）。
- 由此隐含"第二个 QC 需要 ≥2 honest 双签者"：**不成立**。交集只保证 ≥1 个诚实 Witness，可能恰好 1 honest + 1 Byzantine。原论证把"交集 ≥2 个成员"误当成"交集 ≥2 个诚实成员"（任务包明确禁止的混淆）。
- 更重要的是：即使只有 1 个诚实 Witness 双签，S1 也只禁止**同一轮次**双签；跨轮次双签是 R-LOCK 允许的合法行为。所以单纯的交集 + S1 **不足以**推出冲突 QC 不可能。原 S-A 论证路线应判定为**无效**，不能靠修补措辞保留。

**结论**：原鸽巢论证不成立；这不是协议不安全，而是论证选错了不变量。正确路线见 §3。

---

## 3. 最早冲突事件归纳论证（任务包 B）

### 3.1 为什么必须先证明"冲突 PoLC 不可能"

按 R-PRECOMMIT(c)，每个诚实的 PRECOMMIT 都必须观察到 `(r,C)` 的**精确同轮 PoLC**。因此：

```
QC(D, r') 成立 ⟹ 存在 (r', D) 的 PoLC
```

于是"冲突 QC 不可能"可归约为"冲突 PoLC 不可能"：若不存在针对冲突 digest 的 PoLC，则冲突 digest 的诚实 PRECOMMIT 无法产生，QC 门限 3 无法由诚实 Witness 凑齐（Byzantine 最多 1 票）。

**回答任务包 B 的首问：是，必须先证明冲突 PoLC 不可能（或等价地证明其无法达到 3 票），才能推出冲突 QC 不可能。** 直接对 QC 签名集合做鸽巢是走不通的。

### 3.2 归纳设置

反设存在两个冲突 QC：`QC(C, r0)` 与 `QC(C', r1')`，`C.digest ≠ C'.digest`、同 `lock_key`。不妨设 `r0 ≤ r1'`（否则交换记号）。

由于 `QC(C,r0)` 成立，存在 `S_pc = {W : W 对 (r0,C) 签 PRECOMMIT}`，`|S_pc| ≥ 3`。由 `f≤1`，`S_pc` 中至少 2 个 honest，且由 R-PRECOMMIT 动作，这些 honest 在签名前已写 `durable_lock=(r0, C.digest)`，即**已锁定 C，locked_round = r0**。

定义"冲突 PoLC"：针对某个 `D ≠ C.digest`、同 `lock_key` 的 PoLC。反设存在至少一个冲突 PoLC；取其中**轮次最早**者，记其轮次为 `r1`：

```
r1 = min{ ρ : 存在针对 D≠C.digest 的 PoLC at round ρ }
```

### 3.3 步骤 1：r0 处有 ≥2 honest 锁定 C（成立）

核对 R-PRECOMMIT：QC 的每个签名是有效 PRECOMMIT → 签名者 honest 时已满足 (c) 精确 PoLC 并已写 `durable_lock=(r0,C.digest)`。`|S_pc|≥3, f≤1` → 至少 2 honest 锁定 C at `locked_round=r0`。

**成立**，但依赖：PRECOMMIT 的"先写锁再返回签名"顺序（STATE-MACHINE §2.4 动作、§3.5）。若实现把写锁放到签名之后，此步失效（见 §8 缺口 G2）。

### 3.4 步骤 2：最早的冲突 PoLC at r1 与 r0 的关系

冲突 PoLC 可能出现在 `r1 < r0`、`r1 = r0`、`r1 > r0`。用户给定路线的步骤 4–7 隐含假设 `r1 > r0`（因为要比较"在 r0 已锁定"的 Witness 是否在 r1 改签）。**这是路线的关键分支点，必须分情况**：

- **情况 A：`r1 < r0`。** 冲突 PoLC 早于 C 的 QC。此时"在 r0 已锁定 C 的 honest Witness"尚未锁定（它们锁定发生在 r0），步骤 4 的前提不成立。但这不构成对 S-A 的威胁：S-A 关心的是**同时存在**两个冲突 QC；若 C 已在 r0 commit，则任何冲突 QC 必须出现在 `r' > r0`（同轮 r'=r0 见 §3.6）。`r1<r0` 的冲突 PoLC 最多导致 r0 之前的冲突 commit，与 `QC(C,r0)` 并存时，取较早的 QC 重做归纳即可（见 §3.7）。所以可**不失一般性地归结到情况 C**。
- **情况 B：`r1 = r0`。** 同轮冲突 PoLC，见 §3.6，由 S1 排除。
- **情况 C：`r1 > r0`。** 主归纳，见 §3.5。

**判定**：用户路线在 `r1 > r0` 的分支成立；`r1 ≤ r0` 需要补充分支（情况 A 的归纳重选、情况 B 的 S1 排除），不能直接跳过。这是原路线的**缺失分支**，不是证明错误。

### 3.5 步骤 3–7：r1 > r0 主归纳

`r1` 处存在针对 `D ≠ C.digest` 的 PoLC，即集合 `S_prev = {W : W 对 (r1,D) 签 PREVOTE}`，`|S_prev| ≥ 3`。

**(3) 交集**：`|S_prev ∩ S_pc| ≥ 3+3−4 = 2`（成立）。

**(4) 交集中 ≥1 honest**：`f≤1` → ≥1 honest Witness `Wh ∈ S_prev ∩ S_pc`（成立）。`Wh` 在 r0 已锁定 C（`locked_round=r0, locked_digest=C.digest`），且在 r1 为冲突 `D` 签了 PREVOTE。

**(5) `Wh` 解锁所需的中间 PoLC**：`Wh` honest 且遵守 R-PREVOTE(c2)，它在 r1 为冲突 digest `D` prevote 的前提是走 R-LOCK：

```
locked_round(r0) < polc_round < current_round(r1)
```

且该 PoLC 绑定同一 `(chain_id,set_id,epoch)`、目标为冲突 digest。因此存在一个针对某 `D* ≠ C.digest`、同 `lock_key` 的 PoLC，轮次 `polc_round` 满足

```
r0 < polc_round < r1
```

**逐步核对**：
- `current_round = r1`：由 R-PREVOTE(a)，prevote 请求轮次必须等于 `current_round`；`Wh` 在 r1 prevote，故其 `current_round=r1`。
- `locked_round = r0`：由步骤 1，`Wh` 在 r0 precommit 后锁定 C。需假设 r0 与 r1 之间 `Wh` 未合法改锁到别的冲突 digest；即便改锁，`locked_round` 只会**单调增大**，仍 ≥ r0，不等式 `locked_round < polc_round < r1` 给出的中间 PoLC 轮次仍 `< r1`，不影响矛盾（见 §3.8）。
- `D* 与 C 冲突`：R-LOCK 要求 PoLC 目标为"冲突 digest"，即相对于 `Wh` 的锁目标不同。若 `Wh` 仍锁 C，则 `D*≠C.digest`。若 `Wh` 中途改锁到 `D2`，则 `D*≠D2`；此时 `Wh` 需要**两次**解锁，第一次（从 C 解锁）已经需要一个 `r0 < polc'_round < r1` 的冲突 PoLC——矛盾同样成立。

**(6) 矛盾**：`polc_round` 满足 `r0 < polc_round < r1`，且针对 `D*≠C.digest`、同 `lock_key` —— 这是一个轮次**严格小于 r1** 的冲突 PoLC，与 `r1` 是冲突 PoLC 的最小轮次矛盾。∎

**判定**：步骤 (3)(4)(5)(6) 在当前规则下逐条成立。前提 (5) 依赖"honest Witness 改签冲突 digest 必须先有满足严格不等式的 PoLC"这条规则确实存在（R-LOCK / STATE-MACHINE §2.2c2、§3.1），已核对无误。

### 3.6 同轮情况（任务包 B 必答）

**是否存在同轮冲突 PoLC？** 同轮 `r` 若同时存在针对 `C` 和 `C'`（冲突）的两个 PoLC，则各需 3 份 PREVOTE：

```
|S_prev(C,r) ∩ S_prev(C',r)| ≥ 3+3−4 = 2
```

交集中 ≥1 honest Witness，它在同一轮 `r` 对两个冲突 digest 都签了 PREVOTE，违反 **S1**（STATE-MACHINE §1 不变量 + §2.2(b) 拒绝条件"同轮已对本 lock_key 的另一 digest 签过 PREVOTE"）。

**由哪条规则排除**：S1（同轮同 Witness 不双签），配合 `f≤1` 保证交集含 honest。同名轮的两个冲突 QC 同理被 S1 在 PREVOTE 层就排除（R-PRECOMMIT(b) 要求本轮对同一 C prevote，冲突 QC 会要求同轮对两 digest prevote）。

**判定**：同轮冲突 PoLC / QC 由 S1 排除，成立。

### 3.7 情况 A 的补归纳（r1 < r0）

若最早的冲突 PoLC 早于 `QC(C,r0)`：S-A 要排除的是"两个冲突 QC 并存"。取两个冲突 QC 中轮次**较早**的那个作为新的锚点 `C0`，把 `C` 换成 `C0` 重做 §3.5 的归纳：较晚的 QC 要求一个"晚于较早 QC 轮次"的冲突 PoLC，而该 PoLC 又要求更早的冲突 PoLC，递归下降到最小冲突 PoLC，由 §3.5 矛盾。**结论与锚点选择无关。** 故此分支不影响 S-A。

### 3.8 跨轮多次转移（任务包 B 必答）

**跨轮次解锁是否允许经过中间 digest 多次转移？** 允许。R-LOCK 只要求"PoLC 目标与当前锁目标冲突"，并未限定必须一步到位到最终 `D`。可以 `C → D2 → D3 → … → D`。

**证明是否仍成立？** 成立。每次转移都触发一次 R-LOCK：

```
locked_round_i < polc_round_i < current_round_i
```

`locked_round` 单调不减，故 `polc_round_i` 均严格位于上一锁轮次与转移发生轮次之间。第一次从 C 解锁的 PoLC 轮次 `polc_round_1` 满足 `r0 < polc_round_1 < r1`（因为最终要在 r1 prevote，所有转移都在 r1 之前完成）。这仍与 `r1` 最小性矛盾。多次转移**不会**绕过归纳，反而每一步都生成一个更小的冲突 PoLC 轮次。

### 3.9 任务包 B 必答汇总

| 问题 | 回答 |
| --- | --- |
| 需先证冲突 PoLC 不可能？ | 是。R-PRECOMMIT(c) 使冲突 QC 蕴含冲突 PoLC |
| 存在同轮冲突 PoLC？ | honest 遵守规则时不存在 |
| 同轮由哪条排除？ | S1（§1 不变量 + §2.2(b)），配合 f≤1 的交集 honest 下界 |
| 跨轮可经中间 digest 多次转移？ | 允许；每步都需 R-LOCK PoLC |
| 证明仍成立？ | 成立；多次转移只生成更多更小的冲突 PoLC 轮次 |

---

## 4. 从 PoLC 推导 QC（任务包 C）

**C1 — QC 中每份诚实 PRECOMMIT 对应同轮同 digest PoLC**：成立。R-PRECOMMIT(c) 明确要求 `r_p == r`（精确同轮、旧轮不可复用，R1-B8 已在 P1 验证），且 R-PRECOMMIT(b) 要求本轮已对同一 C prevote。

**C2 — PoLC 形成与 PRECOMMIT 签名绑定无缺口**：基本成立，但有一处**规格显式化缺口**（不推翻证明）：

- STATE-MACHINE §2.3 的 PoLC 形成条件写"同一 `(chain_id,set_id,epoch)` 下，对同一 round、同一 digest 的 PREVOTE"，这覆盖了跨 epoch/set 混合（§3.2 亦明确"跨 epoch/set 的 PoLC 无效"）。✓
- 但 §2.3 的"验证外部 PoLC（用于解锁）"列表写的是"逐份验签；检查 Q 份互不重复、同一 `r_p` 同一 digest、round 在签名体内；检查 `r_p` 与当前锁/轮次满足 §3"——其中**没有显式列出"检查 PoLC 的 `(chain_id,set_id,epoch)` 等于本地锁的 lock_key"**。它只在 §3.2 以文字形式要求。实现者若只读 §2.3 的验证清单，可能漏掉 lock_key 检查，从而接受跨 epoch 的 PoLC 用于解锁。**建议将 lock_key 相等检查写入 §2.3 的验证清单**（本轮不改原文，仅记录）。

**C3 — Byzantine 不能绕过**：成立。

- 跨轮：PREVOTE/PRECOMMIT 的 `round` 进入签名体（PROTOCOL §3.1、P1 的 S4），旧轮签名不能在新轮重解释；R-PRECOMMIT(c) 只接受同轮 PoLC。
- 跨 epoch/set：如上，§3.2 + §2.3 的 lock_key 约束（含 G1 缺口）；QC 侧 §2.5 要求 `set_id` 与当前 witness_set 一致。
- 混合 digest：PoLC 要求"同一 digest"；QC 要求"同一完整 C 字段"（S3）。
- 去重：§2.3 按 `(witness,binding)` 去重，Byzantine 无法用重复消息凑数（R1-B5 已验证）。

---

## 5. 反例搜索（任务包 D）

### 5.1 搜索方法

对 `W={W1,W2,W3,W4}`、`f=1`（不妨设 W4 Byzantine）、两个冲突 digest `A/B`、轮次 `r∈{0,1,2,3}`，按 R-ROUND/R-PREVOTE/R-POLC/R-PRECOMMIT/R-LOCK 逐步枚举可签名事件，尝试产生 `QC(A,r)` 与 `QC(B,r')` 并存。只列关键阻断路径，非穷尽状态空间。

### 5.2 尝试与阻断

**尝试 1：同轮双 QC（`r=r'=0`）**。要 `QC(A,0)` 与 `QC(B,0)`，需在 r=0 形成 `PoLC(A,0)` 与 `PoLC(B,0)`。两集合交 ≥2、含 ≥1 honest → 该 honest 同轮对 A/B 双 prevote → S1 拒绝。**阻断**。

**尝试 2：跨轮，W4 双签**。设 `QC(A,0)` 由 `{W1,W2,W4}` 形成（W1,W2 honest 锁 A at r0；W3 honest 未参与、未锁；W4 byz）。要在 r1>0 形成 `QC(B,r1)`，需 `PoLC(B,r1)`（3 prevote）。可用 prevote 者：W4（byz，任意签）+ W3（未锁 A，可自由 prevote B）= 2 票；W1/W2 锁 A，改签 B 需 `0 < polc_round < r1` 的冲突 PoLC(B,·)——但那正是我们想形成的第一个 PoLC(B)，循环无起点。**阻断**（即 §3.5 矛盾的具体化）。

**尝试 3：让 W3 先形成 PoLC(B,1)**。只有 W3+W4=2 票，不足 3；W1/W2 不能加入（无解锁 PoLC）。**阻断**。

**尝试 4：W4 在不同轮对 B 签多次并伪装不同身份**。按身份计票 + `(witness,binding)` 去重（§2.3）+ 签名不可伪造，W4 始终只算 1 票。**阻断**。

**尝试 5：用跨 epoch 的 PoLC(B) 解锁**。§3.2 禁止跨 epoch/set；若实现漏检查则落入 G1——但那是违反当前规格的实现，不构成"符合当前状态机"的反例。**阻断（规格内）**。

**尝试 6：先 commit B at r0、再 commit A at r1**。对称于尝试 2，取较早 QC 为锚点即可。**阻断**。

### 5.3 搜索结论

在枚举的 6 类路径中未找到符合当前状态机的反例；阻断机制一致地是"**锁定 honest Witness 的 ≥2 票使任何冲突 PoLC 最多只能拿到 2 票（< Q=3）**"。这是对 §3 归纳的具体印证。

**边界声明**：这是有限枚举 + 规则推导，**不是形式化穷尽证明**。枚举只覆盖 4 轮、单 Byzantine、两 digest；更多轮次或三 digest 未穷举，但 §3 的归纳论证不依赖轮次数，逻辑上覆盖这些情况。

---

## 6. 与 CometBFT 原始规范的差异（任务包 §5）

### 6.1 已逐字核对的原文（来源：`spec/consensus/consensus.md`）

- **Terms**："+2/3 is short for 'more than 2/3'"；"A set of +2/3 of prevotes for a particular block or `nil` at `(H,R)` is called a _proof-of-lock-change_ or _PoLC_"。
- **Prevote Step (height:H,round:R)**："First, if the validator is locked on a block since `LastLockRound` but now has a PoLC for something else at round `PoLC-Round` where `LastLockRound < PoLC-Round < R`, then it unlocks."；"If the validator is still locked on a block, it prevotes that."
- **Precommit Step (height:H,round:R)**："If the validator has a PoLC at `(H,R)` for a particular block `B`, it (re)locks (or changes lock to) and precommits `B` and sets `LastLockRound = R`."；"Else, it keeps the lock unchanged and precommits `nil`."
- **Proof of Safety**（全文）："Assume that at most -1/3 of the voting power of validators is byzantine. If a validator commits block `B` at round `R`, it's because it saw +2/3 of precommits at round `R`. This implies that 1/3+ of honest nodes are still locked at round `R' > R`. These locked validators will remain locked until they see a PoLC at `R' > R`, but this won't happen because 1/3+ are locked and honest, so at most -2/3 are available to vote for anything other than `B`."

### 6.2 关键条件继承核对

| CometBFT 证明依赖 | P2 状态机是否具备 | 说明 |
| --- | --- | --- |
| 至多 -1/3 byzantine 投票权 | 部分：`f≤1`、`N=4` → 1/4 < 1/3 ✓ | 但 P2 按 Witness **计数**等权，CometBFT 按**投票权**；权重模型未继承 |
| commit 需要 +2/3 precommits | 是：`Q=3` of 4 = 3/4 > 2/3 ✓ | 更强，但计数而非权重 |
| 1/3+ honest 仍 locked at `R'>R` | 是：≥2 honest 锁 C（2/4=1/2 > 1/3）✓ | 依赖 PRECOMMIT 先写锁（§2.4 动作） |
| locked validators 保持 locked 直到见 PoLC | 是：R-LOCK，`locked_round<polc_round<current_round` ✓ | 逐字对应 Prevote Step 不等式 |
| 可用票 < 2/3 故无法形成冲突 PoLC | 是：4−2=2 < 3=Q ✓ | §3.5 的核心计数 |

### 6.3 缺失 / 未继承的条件

1. **`nil` 投票语义**：CometBFT Precommit Step 有"precommits `nil`"分支（无 PoLC 时保持锁并投空票）；P2 没有 nil vote，PRECOMMIT 只针对具体 C。差异影响活性与状态推进，**不影响 S-A 的冲突 QC 论证**（无 nil 意味着更少的合法改签路径）。
2. **投票权模型**：CometBFT 按质押权重，P2 按等权 Witness 计数。若未来引入异质权重，`Q=3` 的 3/4 与 f=1 的 1/4 关系不再直接成立，论证需重做。
3. **proposer 选举、PoLC-Round 提示、递增 timeout、证据传播、validator set 轮换、equivocation slashing**：CometBFT 均有；P2 只借用锁转移一条结构（PROTOCOL §5、P1 已声明），这些全部未实现。
4. **任何这些条件都不是"继承 CometBFT 安全保证"的依据**：P2 的安全结论来自 §3 在自身规则上的独立推导，不是从 CometBFT 的证明搬运。CometBFT 原文只作为不等式结构的来源核对。

---

## 7. 最终结论

**判定：`PROOF_SUPPORTED`。**

在 §1.3 固定假设下，当前 P2 状态机足以推出 S-A。成立的论证是 §3 的"最早冲突 PoLC 归纳"，核心计数为：一个 QC 使 ≥2 honest Witness 锁定 C → 任何冲突 PoLC 最多剩 2 票（`W4` + 至多 1 个未锁 honest）< `Q=3` → 冲突 PoLC 无法形成 → 冲突 QC 无法形成。原 S-A 的鸽巢表述（"≥2 honest 双签"）**不成立、已作废**，但不能据此得出协议不安全。

**这不是形式化证明**：是规则层数学推导 + 有限反例枚举，未经机器证明辅助；结论强度限于"在明确假设下、按当前书面规则可推出"。

### 7.1 成立所依赖的前提（逐条标注当前 P2 是否已定义）

| 前提 | P2 是否已定义 | 位置 |
| --- | --- | --- |
| `Q=3` of `N=4`、`f≤1`、按身份计票 | 已定义 | §1.3 / PROTOCOL §1 |
| `round` 进入签名体、旧轮不可重解释 | 已定义 | PROTOCOL §3.1 / S4 |
| PoLC 绑定同一 `(chain_id,set_id,epoch)` | 已定义（文字）但验证清单未显式 | §3.2 / §2.3 — 见缺口 G1 |
| PRECOMMIT 要求同轮精确 PoLC | 已定义 | §2.4(c) |
| PRECOMMIT 先写锁再返回签名 | 已定义 | §2.4 动作 / §3.5 — 见缺口 G2 |
| honest 遵守 S1（同轮不双签） | 已定义（规则），honest 守规是假设 | §1 / §2.2(b) |
| 重启不静默丢锁 | 已定义但依赖持久化外部假设 | S5 / CRASH-ANALYSIS §0 |

### 7.2 规格缺口（不推翻结论，但需在未来实现前显式化）

- **G1**：§2.3 "验证外部 PoLC"清单未显式检查 PoLC 的 `lock_key` 等于本地锁的 `lock_key`（只在 §3.2 文字要求）。补入清单即可；否则跨 epoch PoLC 可能被误用于解锁。
- **G2**：写 `durable_lock` 与返回 PRECOMMIT 签名的原子性由 §3.5 以"需求原语"形式要求，但未指定存储实现；若在两者之间崩溃并丢锁，步骤 3.3 的"已锁定"失效（对应 AL1）。这是外部持久化假设，不是规则缺口。
- **G3**：`locked_round` 单调性在 §3.8 推理中被使用，但 STATE-MACHINE §1 的不变量只写明 `locked_round ≤ current_round`，未显式写"改锁时 `locked_round` 非递减"（R-LOCK 的严格不等式隐含了它，但建议显式列出）。

---

## 8. 未解决的最小问题集合

1. **原 S-A 应在 P2 原文中改写**：用 §3 归纳替换 §2 鸽巢表述；本轮按任务包要求不修改原文，仅交付本审计文档。
2. **G1/G3 的规则显式化**：不等价于协议改动，但应在 STATE-MACHINE 的验证清单/不变量中补写。
3. **异质投票权**：若 witness_set 引入权重，`Q=3` 与 `f=1` 的计数关系需重证。
4. **BFT soundness 与 crash-safe 持久化**：本结论不覆盖；仍属外部工作。
5. **有限枚举 ≠ 形式化**：§3 归纳是可信的数学论证，但若要"形式化证明"级别，需在证明助手中建模并有状态的机器检查——本轮未做，不声称。

**停止条件**：本轮完成，暂停等待人工验收；不修改 P2 原文、不进 P3、不实现协议代码。
