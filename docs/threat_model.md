# EXP-D3-01 威胁模型

## 攻击者能力

- 控制状态服务：可任意提供 GR/RR、跳过事件、重排事件、伪造根。
- 控制部分事件内容（scope/issuer/resource/parent/epoch）以图提权。
- 但不能伪造 SHA-256 / Poseidon 碰撞，不能改写被外部认证的批次摘要（本轮用固定向量模拟）。

## 覆盖的攻击（D3-01..D3-12）

| 攻击 | 检测机制 | 错误码 |
| --- | --- | --- |
| 子授权 scope 越界 | 位掩码子集检查 | `SCOPE_ESCALATION` |
| 子授权 issuer 不匹配 | issuer==parent.subject | `ISSUER_MISMATCH` |
| 重复 grant | 全局唯一 | `DUPLICATE_GRANT` |
| 撤销不存在的 grant | 存在性检查 | `GRANT_NOT_FOUND` |
| 重复撤销 | 未撤销检查 | `ALREADY_REVOKED` |
| 已撤销 grant 派生子 | parent 有效检查 | `PARENT_NOT_VALID` |
| 事件乱序 | parent 存在 + epoch 单调 | `PARENT_NOT_FOUND`/`EPOCH_REGRESSION` |
| 事件重复执行 | 重放时唯一性 | `DUPLICATE_GRANT` |
| 状态树与历史不一致 | 根/集合不一致 | root/summary 不等 |
| 跳过历史事件 | 批次摘要 + 完整重执行 | `NEXT_ROOT_MISMATCH`/`BATCH_DIGEST_MISMATCH` |

## 明确不覆盖

- 没有 ZKP：验证者本轮仍 O(batch) 重执行，不是零知识状态转换证明。
- 没有真实外部历史认证源：防跳过依赖"批次摘要来自可信方"的假设，本轮未实现该可信方。
- 不证明 DENY（不存在有效路径）；不验证 Ed25519 签名者身份；不实现 BFT 共识。
- 哈希/root 一致是确定性检查，不是密码学语义证明。
- 测试 fixture 不是真实授权服务；resource 前缀模型是实验模型。
- 未实现 Halo2 内部 SHA-256/Poseidon 约束。

## 策略边界

`DirectOnly` 与 `Cascade` 是两条独立策略，根不同。第一版不默认级联：任何级联语义必须
显式选择 `Cascade`，不得混入基础转换逻辑。
