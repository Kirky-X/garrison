# ADR-0001: Argon2id 密码哈希策略

- 状态：Accepted

- 日期：2026-09-21

- 关联代码：`src/account/credential/password.rs`（`Argon2Hasher` / `BcryptHasher`）

- 关联配置：`password_hasher` 配置节（见 `docs/CONFIGURATION.md`）

## Context

Garrison 作为身份认证框架，密码哈希是安全底线。可选方案对比：

| 维度 | Argon2id | bcrypt | scrypt | PBKDF2 |
|------|----------|--------|--------|--------|
| GPU/ASIC 抗性 | 强（内存硬度） | 中（可控内存但上限低） | 强 | 弱（纯 CPU 迭代） |
| 侧信道（时间/缓存） | 低（Argon2id 混合数据独立与块独立访问） | 低 | 中 | 低 |
| OWASP Password Storage Cheat Sheet 现行建议 | **首选** | 可接受（work factor ≥10） | 可接受 | 仅 FIPS 合规场景 |
| Rust 生态 | `argon2` crate（RustCrypto，PHC 格式） | `bcrypt` crate | 成熟 | 成熟 |

需要同时支持：历史密码迁移（已存 bcrypt 哈希的存量系统）、内存受限环境（19 MiB × 并发请求数的内存预算）。

## Decision

1. **默认算法 Argon2id**，默认参数 **m=19456 KiB（19 MiB）/ t=2 / p=1**——OWASP 建议的最低安全配置（以 2024+ 硬件为参照的第二推荐档：m=19 MiB, t=2, p=1）。

2. **锁定测试钉住默认值**：`src/account/credential/tests.rs` 断言 `Argon2Hasher::default()` 参数与 PHC 输出前缀 `$argon2id$v=19$m=19456,t=2,p=1`——默认策略的无声漂移会被 CI 阻断。

3. **可配置但有下限**：`password_hasher` 配置节暴露 `argon2_m_cost/t_cost/p_cost`，`validate_core` 校验 m_cost ≥ 19456（低于下限需显式风险接受字段），防止业务方为吞吐无意弱化参数。

4. **verify 路径参数自 PHC 字符串解析**：`Argon2::default()` 仅作构造，实际成本参数从 `$argon2id$m=...,t=...,p=1` 哈希串读取——历史哈希（不同参数）无需迁移即可验证，参数升级采用"新密码/重登录时重哈希"的自然演进。

5. **bcrypt 兼容保留**（默认 cost=12，可配置且校验 10≤cost≤15）：仅用于存量 bcrypt 哈希验证；新哈希一律 Argon2id。

## Consequences

**正面：**

- 默认配置即 OWASP 建议值，开箱安全。

- 参数演进不破坏存量密码（PHC 自描述）。

- 默认值漂移有测试锚点，配置弱化有校验门禁。

**负面 / 代价：**

- 19 MiB × 并发数的内存占用：高并发登录场景需评估内存预算（经 `spawn_blocking` 下沉，不阻塞 async reactor，但内存仍按并发峰值占用）。

- 配置化带来校验分支复杂度（下限 + 风险接受标记）。

**后续跟进：**

- 参数升级（如 m=47104 档）作为 minor 版本的默认变更需在 CHANGELOG 显著标注（verify 兼容，仅影响新哈希）。

- 若未来需要 FIPS 合规场景，评估 PBKDF2 hasher 作为可选 `PasswordHasher` 实现（trait 已抽象，成本可控）。
