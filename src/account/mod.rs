// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 账号安全引擎模块（吸收 Keycloak 安全能力）：与 `secure/`（密码学原语：TOTP/签名/Basic/Digest）
//! 互补，提供账号生命周期安全能力。
//!
//! 子模块与 feature：`credential`（`account-credential`，统一凭证 SPI）、`policy`（`account-policy`，
//! 12+ 密码规则）、`lockout`（`account-lockout`，用户级双态锁定）、`authflow`（`account-authflow`，
//! 认证流程 DSL）、`password_reset`（`account-password-reset`，ActionToken 一次性消费/防枚举/防竞态）。
//!
//! 模块关系：`stp/` 的 SessionLogic/MfaLogic 之上由 authflow DSL 编排；`strategy/firewall/` 保留
//! IP 级 `BruteForceStrategy`，用户级 `UserLockoutStrategy` 组合进 Firewall 执行链。

/// 凭证模型 SPI 子模块（`account-credential` feature）：`Credential` trait + `CredentialModel` +
/// `CredentialRepository`，含 `PasswordCredential` 与 `TotpCredential` 实现。
#[cfg(feature = "account-credential")]
pub mod credential;

/// 密码策略套件子模块（`account-policy` feature）：`PasswordPolicyRule` trait + `PasswordPolicyEngine`
/// + 12+ 规则（长度/复杂度/历史/黑名单/用户名相似/常见密码/过期/字典/重复字符/序列/邮箱/正则）。
#[cfg(feature = "account-policy")]
pub mod policy;

/// 用户级双态账号锁定子模块（`account-lockout` feature）：`UserLockoutStrategy` 实现
/// `GarrisonFirewallStrategy`（temporary + permanent），与 IP 级 `BruteForceStrategy` 组合使用。
#[cfg(feature = "account-lockout")]
pub mod lockout;

/// AuthenticationFlow DSL 子模块（`account-authflow` feature）：`AuthenticationFlow` + `AuthStep` +
/// `AuthExecutor`，覆盖登录 + MFA + 社交登录 + SSO 全认证流程。
#[cfg(feature = "account-authflow")]
pub mod authflow;

/// 找回密码/可恢复流程子模块（`account-password-reset` feature）：ActionToken 签发/校验（自包含 JWT）、
/// jti 一次性消费登记（`set_if_absent` 原子语义）、两段式防竞态、防枚举 dummy token 与 restricted 会话约束。
#[cfg(feature = "account-password-reset")]
pub mod password_reset;

/// 账号安全 Prometheus 指标子模块（`metrics-prometheus` feature）：`AccountMetrics` 4 个指标覆盖
/// 凭证验证 / 策略校验 / 锁定触发 / 认证流程执行；未启用 feature 时为 `()` unit type 别名。
pub mod metrics;

/// 封禁库子模块：`DisableEntry` struct + `DisableRepository` trait（持 `Arc<dyn GarrisonDao>` 委托实现，
/// 非 feature-gated）。
pub mod disable;

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

    /// 验证 account 模块在启用 account-password-reset feature 时可编译。
    #[cfg(feature = "account-password-reset")]
    #[test]
    fn password_reset_module_compiles() {
        let _ = std::any::TypeId::of::<crate::account::password_reset::ActionTokenService>();
    }
}
