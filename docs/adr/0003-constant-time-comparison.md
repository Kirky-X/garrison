# ADR-0003: 常量时间比较统一原语（secure-ct-eq）

- 状态：Accepted

- 日期：2026-09-21

- 关联代码：`src/secure/ct_eq.rs`（公共原语）、`Cargo.toml`（`secure-ct-eq` feature）

- 关联依赖：`subtle 2.6`（`ConstantTimeEq`）

## Context

密钥/凭证比较若使用 `==`（提前返回的短路比较），存在**定时侧信道**（CWE-208）：攻击者通过测量比较耗时逐字节猜测正确值。受影响面包括 HMAC 校验、digest response、API Key secret、审计链校验等"比较密钥级数据"的路径。

项目早期各模块各自复制 subtle 调用，存在实现漂移风险（某处误用 `==` 不易发现）。

## Decision

1. **统一公共原语**：`secure::ct_eq::constant_time_eq(a: &[u8], b: &[u8]) -> bool`（基于 `subtle::ConstantTimeEq`），由 `secure-ct-eq` feature 导出。

2. **所有需要常量时间比较的 feature 依赖该 feature**，禁止各模块复制本地实现（消除第二实现）；`audit-log`、`oauth2-server` 等已按此声明依赖。

3. **适用路径清单**（新增比较路径须对照补充）：
   - OAuth2 `code_verifier` ↔ `code_challenge`（S256 摘要比较为哈希值比较，verifier 匹配路径）
   - HTTP Digest `response` 字段校验
   - API Key `key_secret` 哈希比对（CWE-208 + CWE-916 组合防御）
   - 审计链哈希校验（`audit-log`）
   - SimpleTokenStyle HMAC 签名校验（`secure-simple-token`）

4. **不适用说明**：密码哈希 verify（Argon2/bcrypt）由库内部保证常数时间行为，不走本原语；非敏感数据（如配置字符串）比较无需常量时间（避免误用导致的性能焦虑）。

## Consequences

**正面：**

- 单点实现 + 类型级约束（subtle 的 `Choice` 类型防误转 bool 提前返回）。

- 适用路径可枚举、可测试（`tests/constant_time_eq.rs` 回归）。

**负面 / 代价：**

- `secure-ct-eq` 成为多个安全 feature 的公共依赖（feature 传播面 +1）。

- 常量时间语义依赖 `subtle` 的平台实现正确性（RustCrypto 维护，信任假设同 ADR-0002 的原语信任）。

**后续跟进：**

- 新代码 review 清单项：任何"比较密钥/token/摘要"的代码必须走 `ct_eq`；可考虑在后续变更中增加 clippy 自定义 lint 或 Semgrep 规则检测敏感路径的裸 `==`。
