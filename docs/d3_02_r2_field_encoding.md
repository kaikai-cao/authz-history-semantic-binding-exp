# EXP-D3-02-R2-02 — 32B ↔ Pallas Field 映射冻结规范

**基线**：`023a5d1641354dc7f7257a09cc23a28787b33b0d`
**分支**：`exp-d3-02-r2`
**性质**：设计冻结。本轮最重要密码学接口。不实现电路，不改冻结源码。

---

## 0. 一句话结论与关键澄清

> **明确选择**：系统中存在**两类语义完全不同的 32 字节值**，必须分开处理，绝不能用同一函数：
>
> | 类别 | 例子 | 本质 | 映射方式 |
> | --- | --- | --- | --- |
> | **(I) 域元素的规范编码** | D2-B 的 `grant_root`/`revoke_root`（来自 D2-A Poseidon 输出） | 已经是一个 Fp 元素，只是以 32B 表示 | **方案 A′：严格规范编码 + 字节序桥接**，非规范输入直接拒绝，**禁止模约简** |
> | **(II) 摘要/哈希输出** | SHA-256 anchor digest、事件摘要、32B 随机数 | 是均匀 256-bit 串，**未必** < p | **方案 B′：哈希到域** `from_uniform_bytes`（64B 输入，模约简） |
>
> 任务书把这两类都叫"32B 到 Pallas Field 的映射"，但**只有 (I) 需要一一对应**；
> (II) 若用规范编码会约一半概率被拒（p/2²⁵⁶ ≈ 0.5），若静默模约简则破坏一一对应——
> 正确做法是把 (II) 当作"哈希到域"而非"编码解码"。本轮冻结的关键贡献就是**分开这两条路**。

对 (I) 采用方案 A′：`DecodeField_I(b) = Fp::from_repr(reverse_be_to_le(b))`，
前置检查 `int_be(b) < p`，非规范返回 `NonCanonicalField`；`EncodeField_I(x) = reverse_le_to_be(x.to_repr())`。
**禁止静默模约简**：绝不用 `from_uniform_bytes` / `from_u512` 处理 (I)。

---

## 1. 一手事实（逐条源码核实）

### 1.1 Pallas base field 模数与规范表示

来源：`pasta_curves-0.6.0/src/fields/fp.rs`

```
p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
  = 28948022309329048855892746252171976963363056481941560715954676764349967630337
bit_length(p) = 255                // 最高位在 bit 254
NUM_BITS = 255                     // fp.rs:632
p_be_hex   = 40000000000000000000000000000000224698fc094cf91b992d30ed00000001  (32B 大端)
p_le_hex   = 01000000ed302d991bf94c09fc98462200000000000000000000000000000040  (32B 小端)
p - 1 (BE) = 40000000000000000000000000000000224698fc094cf91b992d30ed00000000
```

- `pasta_curves` 的 `type Repr = [u8; 32]` 是 **little-endian**（`fp.rs:622,675-686`）：
  `from_repr` 用 `u64::from_le_bytes(repr[0..8])…`，然后检查 `< MODULUS`，否则 `CtOption::None`；
  `to_repr` 用 `to_le_bytes()` 输出。
- `Fp` 内部是 Montgomery form，`R = 2^256`（`fp.rs:27-29`）。

### 1.2 D2-B 的 FieldBytes 是**大端**规范编码

来源：`zk-state-anchor-exp/src/encoding.rs:11-56`

```
PALLAS_BASE_MODULUS_HEX = "40000000000000000000000000000000224698fc094cf91b992d30ed00000001"  // 大端
FieldBytes::from_u64(v):  b[24..32] = v.to_be_bytes()          // 值放末尾 = 大端
FieldBytes::is_canonical: self.0.as_slice() < modulus_be.as_slice()   // 大端字节比较
FieldBytes::from_bytes(b): 若非规范 -> Err(NonCanonicalField)
```

⚠️ **源码注释措辞有误**：`encoding.rs:11` 写"Pallas **标量**域（D2-A 中 GR/RR 所属域）"，
但给出的模数 `4000…0001` 实际是 **Pallas base field**（Fp），D2-A 也确实用 `pallas::Base`
（`poseidon_hash.rs:11`）。**模数值正确、注释"标量域"三字错误**。本轮不改冻结源码，
仅在文档中记录：GR/RR 属于 **Fp（Pallas base field）**。

### 1.3 D3-01 哈希到域口径

来源：`authz-history-semantic-binding-exp/src/encoding.rs:97-102`

```
field_from_bytes(label, bytes) = F::from_uniform_bytes( SHA256(bytes) ‖ SHA256(label) )   // 64B
```

`ff-0.14.0/src/lib.rs:438-461` 明确规定 `from_uniform_bytes` = "little endian 整数 mod p"，
安全条件 `N·8 ≥ NUM_BITS + 128`（64B·8 = 512 ≥ 383 ✅）。

### 1.4 字节序桥接恒等式（Python 实测验证）

对任意 32B 大端串 `b_be`：
```
int_be(b_be) == int_le(reverse(b_be))
```
因此
```
b_be 是大端规范域编码 (< p)  ⟺  reverse(b_be) 是小端规范表示 (< p)
```
本轮用 Python 对 7 个边界样本逐一验证该等价性成立（零 / 一 / p-1 / p / p+1 / 2^255 / 2^256-1）。

---

## 2. 三种方案比较（任务书要求，不预设 A 正确）

### 2.1 方案 A：32B 严格规范域编码

- 机制：`b` 必须满足 `int_be(b) < p`，否则拒绝；`Fp::from_repr(reverse(b))`。
- 一一对应：✅（见 §3 证明）。
- 拒绝非规范：✅（`from_repr` 内建 `< p` 检查 + 前置显式检查双保险）。
- 能否直接约束：部分。电路内需约束"32B < p"（25 字节比较 + 高位条件），
  且需约束字节序反转（或让 witness 直接提供小端表示并 copy 到大端公开字节）。
  **约束量中等，非原生**（见 §5）。
- 适用：**类别 (I)**（已是域元素的编码）。

### 2.2 方案 B：32B 哈希到域

- 机制：`Fp::from_uniform_bytes(pad_to_64(b))`，模约简。
- 一一对应：❌。多个 32B 串可映射到同一域元素（模 p 碰撞）；且 32B 输入只给 256-bit
  熵，`from_uniform_bytes` 要求 64B 输入才满足偏差界——需填充到 64B，引入额外规则。
- 拒绝非规范：❌（模约简吞掉非规范）。
- 能否直接约束：需电路内 SHA-256（若输入来自任意 32B）+ `from_uniform_bytes` 模约简，
  **昂贵**（同 R1-01 方案 B 的 O(10⁴) 问题）。
- 适用：**类别 (II)** 摘要，且必须扩到 64B 输入。

### 2.3 方案 C：拆成多个小域元素

- 机制：把 32B 拆成 e.g. 4 个 8B 块，各 `Fp::from_u64_le`（因 8B < p，天然规范），
  承诺 `Poseidon(chunk_0..chunk_3)` 而非单域元素。
- 一一对应：✅（4×8B 拼接唯一还原 32B）。
- 约束开销：承诺输入从 1 个域元素变 4 个 → Poseidon rate=2 需 2 次置换（原 1 次），
  每次 36 行/136 约束 → 多 ~136 约束/承诺；但**改变状态承诺结构**，牵动 R1-01 Anchor Bridge、
  `C_prev` 公式、D2-A 接口，**溢出本轮范围**。
- 重构唯一性：✅，但与现有 D3-01 Poseidon 树根（单域元素）不一致。
- 适用：未来若必须把 SHA-256 digest 直接塞进承诺；本轮不采用。

### 2.4 对照表

| 维度 | A（严格规范） | B（哈希到域） | C（拆块） |
| --- | --- | --- | --- |
| 一一对应 | ✅ | ❌ | ✅ |
| 拒绝非规范 | ✅ | ❌ | ✅ |
| 静默模约简 | 禁止 | 本身就是 | 无 |
| 电路可约束 | 中（比较+序转换） | 高（SHA-256+模约简） | 中（多一次置换） |
| 改动现有承诺结构 | 否 | 否 | **是**（溢出范围） |
| 适用类别 | **(I) 域元素编码** | **(II) 摘要** | 未来备选 |
| 本轮 | ✅ 用于 GR/RR | ✅ 用于 digest | ❌ |

---

## 3. 方案 A′ 一一对应证明（禁止静默模约简的可证明依据）

定义两个函数（大端为外部规范形式，小端为 pasta 内部 repr）：

```
EncodeField_I(x: Fp) -> [u8;32] = reverse_le_to_be( x.to_repr() )
DecodeField_I(b: [u8;32]) -> Result<Fp, NonCanonicalField>:
    if int_be(b) >= p:  return Err(NonCanonicalField)     // 显式拒绝，禁止模约简
    let le = reverse_be_to_le(b)
    return Fp::from_repr(le).ok_or(NonCanonicalField)      // 双保险：内部再检 < p
```

**双射证明**：
1. `to_repr : Fp → {le ∈ [u8;32] : int_le(le) < p}` 是双射（`pasta_curves` 保证：每个域元素有唯一
   < p 的 32B 小端表示，且 `from_repr(to_repr(x)) = x`）。
2. `reverse` 是 `[u8;32]` 上的双射，且由 §1.4 恒等式，
   `int_le(le) < p ⟺ int_be(reverse(le)) < p`。
3. 故 `EncodeField_I = reverse ∘ to_repr` 是 `Fp → {b_be : int_be(b_be) < p}` 的双射。
4. `DecodeField_I` 先检查 `int_be(b) < p`（锁定定义域），再 `from_repr(reverse(b))`，
   正是 `EncodeField_I` 的逆。
5. 因此 `DecodeField_I(EncodeField_I(x)) = x` 对所有 x，`EncodeField_I(DecodeField_I(b)) = b`
   对所有规范 b。**不存在多种字节表示对应同一域元素**（在规范定义域内），
   也不存在静默模约简（非规范输入被拒而非映射）。

---

## 4. 冻结的编码规则（逐场景）

### 4.1 类别 (I)：GR/RR 根

```
Bridge Service（链下）:
    gr_f = DecodeField_I(anchor.grant_root.0)      // D2-B 大端 FieldBytes → Fp
    rr_f = DecodeField_I(anchor.revoke_root.0)
    若 Err(NonCanonicalField) -> Bridge 拒绝签发（该 anchor 无效）
    C_prev = Poseidon(D3-STATE-P-v2, gr_f, rr_f, epoch, policy_id)

Halo2 电路（witness）:
    grant_root_be: [u8; 32]     // 公开字节（来自 BridgeStatement，经 copy constraint）
    grant_root_le: Fp           // witness 直接提供小端"数值"的域表示
    约束:
      (a) int_be(grant_root_be) < p                       // 规范范围检查（§5）
      (b) decode_le_bytes(grant_root_be) == grant_root_le  // 逐字节：be[k] ↔ le[31-k]
      (c) C_prev == Poseidon(D3-STATE-P-v2, grant_root_le, revoke_root_le, epoch, policy_id)
```

### 4.2 类别 (II)：SHA-256 摘要（anchor digest / 事件摘要 / policy 哈希）

```
field_from_bytes(label, digest_32B) = F::from_uniform_bytes( SHA256(digest_32B) ‖ SHA256(label) )
```

**注意**：这里不是把 32B 当域元素编码，而是把 32B 当**消息**再哈希一次到 64B 后模约简。
- anchor digest 进 BridgeStatement 时保持 32B 原始字节（`Hash32`），**不转域元素**；
  只有需要域元素时才用 `field_from_bytes`。
- `policy_id` 用 §R2-01 的 `field_from_bytes("D_POLICY", CanonPolicyId)`——输入是变长拼接串，
  先 SHA-256 得 32B，再拼 `SHA256(label)` 得 64B，模约简（合规）。

### 4.3 边界值表（Python 实测，作为负向测试向量）

| 输入（大端 32B） | `int_be < p` | `DecodeField_I` | 说明 |
| --- | --- | --- | --- |
| `0000…00` | ✅ | `Fp(0)` | 零值 |
| `0000…01` | ✅ | `Fp(1)` | D2-B `from_u64(1)` |
| `4000…0000`（p-1） | ✅ | `Fp(p-1)` | **最大规范值** |
| `4000…0001`（p） | ❌ | `Err` | **模数本身，必须拒绝** |
| `4000…0002`（p+1） | ❌ | `Err` | 越界 |
| `8000…00`（2^255） | ❌ | `Err` | 高位越界 |
| `ffff…ff`（2^256-1） | ❌ | `Err` | 全 1 |

### 4.4 Bridge 与电路必须使用同一规则（冻结）

- 两边都把**大端**作为外部规范形式（与 D2-B `FieldBytes` 一致），小端只作内部 repr。
- 两边都实施 `int_be < p` 显式拒绝；电路侧额外做字节 ↔ 域元素的 copy constraint（§4.1b）。
- **禁止**任何一边用 `from_uniform_bytes` 处理类别 (I)——那是类别 (II) 的函数。
- 顺序固定：Bridge 先解码 GR/RR（失败即拒），再算 Poseidon，再签 BridgeStatement。

---

## 5. 电路内约束成本（静态估算，未经实测）

类别 (I) 单个根（GR 或 RR）的规范解码约束：

| 子步骤 | 实现 | 约束量级 |
| --- | --- | --- |
| `int_be(b) < p` | 32 字节 range check（8-bit lookup）+ 与 p 的 32 字节字典序比较 | ≈ 32×(1 lookup + 若干布尔) + 高位条件 ≈ `O(10²)`，取 ~200–400 |
| 字节序反转 copy | `be[k] == le[31-k]` 的 32 个等式的位分解 | ~32–64 |
| 与 Poseidon 输入衔接 | `grant_root_le` 直接作为 Poseidon 输入，无额外约束 | 0 |
| **单根合计** | | **≈ 250–500 约束（粗估）** |
| **GR+RR 双根** | | **≈ 500–1000 约束（粗估）** |

对比：整个语义电路 ~7k–9k 约束。类别 (I) 解码约占 5–12%，可接受。
类别 (II) 若在电路内做（本设计不做，放链下 Bridge）需 SHA-256 ≈ O(10⁴)，再次印证
"类别 (II) 不进电路"的合理性。

**所有数字为静态数量级推断，未经 MockProver / 真实证明校准，标记为粗估/UNKNOWN。**

---

## 6. 负向测试构造

| 测试 | 构造 | 预期拒绝组件 | 层级 |
| --- | --- | --- | --- |
| T03 | BridgeStatement.grant_root 大端字节 = `p`（`4000…0001`） | Bridge：`DecodeField_I` 返 `NonCanonicalField`，拒签 | Bridge Validator + 网关 |
| T03b | 电路 witness 直接喂非规范 `grant_root_be`（=p）给约束 4.1a | MockProver：规范范围检查失败 | MockProver |
| T04 | RR = `2^255`（`8000…00`） | 同上（Bridge + MockProver） | Bridge + MockProver |
| T04b | 字节序反转错：`be[k]` 与 `le[k]`（未反转）强行 copy | MockProver：copy constraint 失败 | MockProver |
| N-II | 把类别 (II) digest 误当类别 (I) 用 `DecodeField_I` | 约一半 digest ≥ p → Bridge 拒签；暴露"用错函数" | 构建期检查 + 集成测试 |

对应 R2-05 测试矩阵 T03 / T04。

---

## 7. 本规范不能声称的内容

- **不能**声称"电路验证 SHA-256 摘要的规范编码"——类别 (II) 全在链下 Bridge 处理，电路不碰。
- **不能**声称字节序换算"零成本"——它有 ~250–500 约束/根的实测待校准成本（§5）。
- **不能**把 `from_uniform_bytes` 用在 GR/RR 上——那会静默模约简，破坏 R1-01 承诺绑定。
- **不能**声称 D2-B 注释"标量域"正确——已记录为措辞错误，实际是 Fp。
- **不能**在未实测前把 §5 约束数当容量结论。
