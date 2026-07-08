//! 账号安全引擎模块（v0.6.0 新增，吸收 keycloak 安全能力）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 本模块吸收 Keycloak 安全能力，提升 Bulwark 原生账号安全能力。
//! 与 `secure/` 模块（密码学原语）互补：`secure/` 提供 TOTP/签名/Basic/Digest
//! 等底层原语，`account/` 提供账号生命周期安全能力。
//!
//! # 子模块
//!
//! | 子模块 | Feature | 说明 |
//! |--------|---------|------|
//! | `credential` | `account-credential` | 统一凭证模型 SPI（Credential trait + PasswordCredential + TotpCredential） |
//! | `policy` | `account-policy` | 密码策略套件（12+ PasswordPolicyRule） |
//! | `lockout` | `account-lockout` | 用户级双态账号锁定（temporary + permanent） |
//! | `authflow` | `account-authflow` | AuthenticationFlow DSL（全认证流程编排） |
//!
//! # 与现有模块的关系
//!
//! - `secure/`：保留 totp/sign/httpbasic/httpdigest/confusable 子模块（密码学原语）
//! - `secure/password/`：v0.6.0 删除，迁移到 `account/credential/password.rs`
//! - `stp/`：不变，authflow DSL 在 SessionLogic/MfaLogic 之上编排
//! - `strategy/firewall/`：BruteForceStrategy 保留，UserLockoutStrategy 组合到 Firewall 执行链

/// 凭证模型 SPI 子模块（`account-credential` feature）。
///
/// 提供 `Credential` trait + `CredentialModel` + `CredentialRepository` 统一凭证抽象，
/// 含 `PasswordCredential`（吸收 secure/password/）和 `TotpCredential`（复用 secure/totp/）。
#[cfg(feature = "account-credential")]
pub mod credential;

/// 密码策略套件子模块（`account-policy` feature）。
///
/// 提供 `PasswordPolicyRule` trait + `PasswordPolicyEngine` + 12+ 规则实现
/// （长度/复杂度/历史/黑名单/用户名相似/常见密码/过期/字典/重复字符/序列/邮箱/正则）。
#[cfg(feature = "account-policy")]
pub mod policy;

/// 用户级双态账号锁定子模块（`account-lockout` feature）。
///
/// 提供 `UserLockoutStrategy` 实现 `BulwarkFirewallStrategy` trait，
/// 支持 temporary + permanent 双态锁定，与 `BruteForceStrategy`（IP 级）组合使用。
#[cfg(feature = "account-lockout")]
pub mod lockout;

/// AuthenticationFlow DSL 子模块（`account-authflow` feature）。
///
/// 提供声明式认证流程编排：`AuthenticationFlow` + `AuthStep` + `AuthExecutor`，
/// 覆盖登录 + MFA + 社交登录 + SSO 全认证流程。
#[cfg(feature = "account-authflow")]
pub mod authflow;

/// 账号安全能力 Prometheus 指标子模块（`metrics-prometheus` feature）。
///
/// 提供 `AccountMetrics`：4 个指标覆盖凭证验证 / 策略校验 / 锁定触发 / 认证流程执行。
/// 未启用 `metrics-prometheus` 时 `AccountMetrics` 为 `()` unit type 别名。
pub mod metrics;

#[cfg(test)]
mod tests {
    /// 验证 account 模块在启用 account-credential feature 时可编译。
    #[cfg(feature = "account-credential")]
    #[test]
    fn credential_module_compiles() {
        // 模块存在性检查：引用子模块路径确保编译期链接
        let _ = std::any::TypeId::of::<crate::account::credential::CredentialModel>();
    }

    /// 验证 account 模块在启用 account-policy feature 时可编译。
    #[cfg(feature = "account-policy")]
    #[test]
    fn policy_module_compiles() {
        let _ = std::any::TypeId::of::<crate::account::policy::PasswordPolicyEngine>();
    }

    /// 验证 account 模块在启用 account-lockout feature 时可编译。
    #[cfg(feature = "account-lockout")]
    #[test]
    fn lockout_module_compiles() {
        let _ = std::any::TypeId::of::<crate::account::lockout::UserLockoutConfig>();
    }

    /// 验证 account 模块在启用 account-authflow feature 时可编译。
    #[cfg(feature = "account-authflow")]
    #[test]
    fn authflow_module_compiles() {
        let _ = std::any::TypeId::of::<crate::account::authflow::AuthenticationFlow>();
    }
}
