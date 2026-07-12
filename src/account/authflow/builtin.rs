//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 内置 AuthenticationFlow。
//! 通过 `inventory::submit!` 编译期注册 4 个内置认证流程，
//! [`FlowRegistry::from_inventory`](super::registry::FlowRegistry::from_inventory) 自动收集。
//!
//! # 内置流程
//!
//! | 名称 | 步骤 | 用途 |
//! |:---|:---|:---|
//! | `default-password-flow` | Login(password) → Conditional(HasCredential(totp), Mfa(totp), None) | 密码登录 + 可选 MFA |
//! | `default-mfa-flow` | Login(password) → Mfa(totp) | 密码登录 + 强制 TOTP |
//! | `default-social-flow` | SocialProvider(wechat) → Conditional(HasCredential(totp), Mfa(totp), None) | 微信社交登录 + 可选 MFA |
//! | `default-sso-flow` | SsoServer(default) → Conditional(HasCredential(totp), Mfa(totp), None) | SSO 登录 + 可选 MFA |

use super::builder::FlowBuilder;
use super::registry::FlowRegistration;
use super::{AuthCondition, AuthStep};

// ============================================================================
// 内置 flow 构造函数
// ============================================================================

/// 构造 `default-password-flow`：密码登录 + 可选 TOTP MFA。
///
/// 步骤：Login(password) → Conditional(HasCredential(totp), Mfa(totp), None)
///
/// 用户已注册 TOTP 凭证时执行 MFA，否则跳过。
fn default_password_flow() -> super::AuthenticationFlow {
    FlowBuilder::new("default-password-flow")
        .login("password")
        .conditional(
            AuthCondition::HasCredential("totp".to_string()),
            AuthStep::Mfa {
                credential_type: Some("totp".to_string()),
            },
            None,
        )
        .build()
}

/// 构造 `default-mfa-flow`：密码登录 + 强制 TOTP MFA。
///
/// 步骤：Login(password) → Mfa(totp)
fn default_mfa_flow() -> super::AuthenticationFlow {
    FlowBuilder::new("default-mfa-flow")
        .login("password")
        .mfa(Some("totp"))
        .build()
}

/// 构造 `default-social-flow`：微信社交登录 + 可选 TOTP MFA。
///
/// 步骤：SocialProvider(wechat) → Conditional(HasCredential(totp), Mfa(totp), None)
fn default_social_flow() -> super::AuthenticationFlow {
    FlowBuilder::new("default-social-flow")
        .social("wechat")
        .conditional(
            AuthCondition::HasCredential("totp".to_string()),
            AuthStep::Mfa {
                credential_type: Some("totp".to_string()),
            },
            None,
        )
        .build()
}

/// 构造 `default-sso-flow`：SSO 登录 + 可选 TOTP MFA。
///
/// 步骤：SsoServer(default) → Conditional(HasCredential(totp), Mfa(totp), None)
fn default_sso_flow() -> super::AuthenticationFlow {
    FlowBuilder::new("default-sso-flow")
        .sso("default")
        .conditional(
            AuthCondition::HasCredential("totp".to_string()),
            AuthStep::Mfa {
                credential_type: Some("totp".to_string()),
            },
            None,
        )
        .build()
}

// ============================================================================
// inventory 编译期注册（R-auth-flow-dsl-012）
// ============================================================================

inventory::submit! {
    FlowRegistration {
        name: "default-password-flow",
        flow: default_password_flow,
    }
}

inventory::submit! {
    FlowRegistration {
        name: "default-mfa-flow",
        flow: default_mfa_flow,
    }
}

inventory::submit! {
    FlowRegistration {
        name: "default-social-flow",
        flow: default_social_flow,
    }
}

inventory::submit! {
    FlowRegistration {
        name: "default-sso-flow",
        flow: default_sso_flow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::authflow::FlowRegistry;

    /// `default-password-flow` 可从 Registry 查询且结构正确
    /// （Login + Conditional，R-auth-flow-dsl-012）。
    #[test]
    fn default_password_flow_registered() {
        let registry = FlowRegistry::from_inventory();
        let flow = registry
            .get("default-password-flow")
            .expect("default-password-flow 应已注册");
        assert_eq!(flow.name, "default-password-flow");
        assert_eq!(flow.steps.len(), 2);
        assert!(matches!(flow.steps[0], AuthStep::Login { .. }));
        assert!(matches!(flow.steps[1], AuthStep::Conditional { .. }));
        // Conditional 的 if_step 为 Mfa { Some("totp") }，else_step 为 None
        match &flow.steps[1] {
            AuthStep::Conditional {
                condition,
                if_step,
                else_step,
            } => {
                assert!(matches!(
                    condition,
                    AuthCondition::HasCredential(ref s) if s == "totp"
                ));
                assert!(matches!(
                    if_step.as_ref(),
                    AuthStep::Mfa { credential_type: Some(ref ct) } if ct == "totp"
                ));
                assert!(else_step.is_none());
            },
            _ => panic!("第二个步骤应为 Conditional"),
        }
    }

    /// `default-mfa-flow` 可从 Registry 查询且结构正确
    /// （Login + Mfa，R-auth-flow-dsl-012）。
    #[test]
    fn default_mfa_flow_registered() {
        let registry = FlowRegistry::from_inventory();
        let flow = registry
            .get("default-mfa-flow")
            .expect("default-mfa-flow 应已注册");
        assert_eq!(flow.name, "default-mfa-flow");
        assert_eq!(flow.steps.len(), 2);
        assert!(matches!(
            &flow.steps[0],
            AuthStep::Login { credential_type } if credential_type == "password"
        ));
        assert!(matches!(
            &flow.steps[1],
            AuthStep::Mfa { credential_type: Some(ref ct) } if ct == "totp"
        ));
    }

    /// `default-social-flow` 可从 Registry 查询且结构正确
    /// （SocialProvider + Conditional，R-auth-flow-dsl-012）。
    #[test]
    fn default_social_flow_registered() {
        let registry = FlowRegistry::from_inventory();
        let flow = registry
            .get("default-social-flow")
            .expect("default-social-flow 应已注册");
        assert_eq!(flow.name, "default-social-flow");
        assert_eq!(flow.steps.len(), 2);
        assert!(matches!(
            &flow.steps[0],
            AuthStep::SocialProvider { provider } if provider == "wechat"
        ));
        assert!(matches!(flow.steps[1], AuthStep::Conditional { .. }));
    }

    /// `default-sso-flow` 可从 Registry 查询且结构正确
    /// （SsoServer + Conditional，R-auth-flow-dsl-012）。
    #[test]
    fn default_sso_flow_registered() {
        let registry = FlowRegistry::from_inventory();
        let flow = registry
            .get("default-sso-flow")
            .expect("default-sso-flow 应已注册");
        assert_eq!(flow.name, "default-sso-flow");
        assert_eq!(flow.steps.len(), 2);
        assert!(matches!(
            &flow.steps[0],
            AuthStep::SsoServer { server_id } if server_id == "default"
        ));
        assert!(matches!(flow.steps[1], AuthStep::Conditional { .. }));
    }
}
