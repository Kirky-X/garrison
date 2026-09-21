# ADR-0002: CSPRNG 统一策略（getrandom::fill 直读 OS 熵源）

- 状态：Accepted

- 日期：2026-09-21

- 关联代码：`src/web/csrf.rs`、`src/oauth2_server/authorize.rs`、`src/oauth2_server/token.rs`、`src/account/credential/backup_code.rs`、`src/listener/audit_chain.rs`

- 关联依赖：`getrandom 0.4`（optional，由使用方 feature 传递启用）

## Context

身份框架的随机数用途全部为**安全敏感**：CSRF token、OAuth2 授权码、refresh token、备份码、审计链盐。随机数弱化（用户态 PRBG 种子不足、缓冲复用）会直接导致 token 可预测。

Rust 生态的随机数版本割裂是现实约束：`rand 0.10` 移除了 `OsRng` 结构体（rand_core 0.10 改由 getrandom 提供系统熵）；`rsa 0.9` 基于 rand_core 0.6 的 trait（其自带 `rsa::rand_core::OsRng`）；项目中曾同时存在 rand 0.8/0.9 风格调用。

## Decision

1. **安全随机路径统一使用 `getrandom::fill(&mut bytes)`**——每次直接触发系统调用读 OS CSPRNG（getrandom(2) / BCryptGenRandom / SecRandomCopyBytes），**不引入用户态 DRBG 缓冲**，杜绝种子质量与状态泄露类缺陷。

2. **`rand` crate 仅限非安全用途**（如测试数据生成），不得出现在 token/密钥/盐生成路径。

3. **`rsa::rand_core::OsRng` 边界**：rsa 0.9 的 keygen/签名内部基于 rand_core 0.6 trait，使用其 re-export 的 OsRng 是版本兼容的**唯一例外**（见 `src/protocol/sso/oidc.rs`、`src/protocol/sso/saml.rs`），其本质仍是 OS 熵源，立场一致。

4. **禁止降级模式**：禁止 `rand::thread_rng()`、`SmallRng`、时间戳/UUID 拼接等伪随机方案进入安全路径；code review 与后续 Semgrep 规则可基于此约束。

## Consequences

**正面：**

- 单一安全随机原语，审计面小（grep `getrandom::fill` 即可枚举全部安全随机点）。

- 无用户态缓冲 → 无状态泄露/回卷风险；无 rand 版本耦合。

**负面 / 代价：**

- 每次系统调用的开销（微秒级）——token 生成非热路径（相对哈希计算），可接受。

- rsa 路径保留 rand_core 0.6 兼容例外，需在升级 rsa crate 时复核。

**后续跟进：**

- 新增安全随机调用点必须使用 `getrandom::fill`；ADR-0003 的常量时间比较同理构成"密码学卫生三原则"。
