//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! FlowBuilder 流式构建 DSL。
//! 提供链式 API 构建 [`AuthenticationFlow`]，每个方法返回 `Self`（除 [`FlowBuilder::build`]）。
//!
//! # 示例
//!
//! ```ignore
//! use garrison::account::authflow::builder::FlowBuilder;
//! use garrison::account::authflow::{AuthenticationFlow, AuthCondition, AuthStep};
//!
//! let flow: AuthenticationFlow = FlowBuilder::new("default-password-flow")
//!     .login("password")
//!     .conditional(
//!         AuthCondition::HasCredential("totp".to_string()),
//!         AuthStep::Mfa { credential_type: Some("totp".to_string()) },
//!         None,
//!     )
//!     .build();
//! assert_eq!(flow.steps.len(), 2);
//! ```

use super::{AuthCondition, AuthStep, AuthenticationFlow};

/// 认证流程流式构建器。
///
/// 通过链式调用追加 [`AuthStep`]，最终 [`build`](Self::build) 生成 [`AuthenticationFlow`]。
///
/// # 默认值
///
/// - `allow_skip` 默认 `false`，需显式调用 [`allow_skip`](Self::allow_skip) 开启。
///
/// # 示例
///
/// ```
/// use garrison::account::authflow::builder::FlowBuilder;
/// use garrison::account::authflow::AuthenticationFlow;
///
/// let flow: AuthenticationFlow = FlowBuilder::new("test")
///     .login("password")
///     .build();
/// assert_eq!(flow.name, "test");
/// assert_eq!(flow.steps.len(), 1);
/// assert!(!flow.allow_skip);
/// ```
#[derive(Debug)]
pub struct FlowBuilder {
    /// 流程名称。
    name: String,
    /// 有序步骤列表。
    steps: Vec<AuthStep>,
    /// 是否允许步骤跳过。
    allow_skip: bool,
}

impl FlowBuilder {
    /// 创建构建器，指定流程名称。
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            steps: Vec::new(),
            allow_skip: false,
        }
    }

    /// 追加 [`AuthStep::Login`] 步骤（密码登录）。
    pub fn login(mut self, credential_type: &str) -> Self {
        self.steps.push(AuthStep::Login {
            credential_type: credential_type.to_string(),
        });
        self
    }

    /// 追加 [`AuthStep::Mfa`] 步骤（MFA 校验）。
    ///
    /// `credential_type` 为 `None` 时由执行器自动选择，`Some("totp")` 指定 TOTP。
    pub fn mfa(mut self, credential_type: Option<&str>) -> Self {
        self.steps.push(AuthStep::Mfa {
            credential_type: credential_type.map(|s| s.to_string()),
        });
        self
    }

    /// 追加 [`AuthStep::SocialProvider`] 步骤（社交登录）。
    pub fn social(mut self, provider: &str) -> Self {
        self.steps.push(AuthStep::SocialProvider {
            provider: provider.to_string(),
        });
        self
    }

    /// 追加 [`AuthStep::SsoServer`] 步骤（SSO 登录）。
    pub fn sso(mut self, server_id: &str) -> Self {
        self.steps.push(AuthStep::SsoServer {
            server_id: server_id.to_string(),
        });
        self
    }

    /// 追加 [`AuthStep::Conditional`] 步骤（条件分支）。
    ///
    /// 内部将 `if_step`/`else_step` 包装为 `Box<AuthStep>`。
    pub fn conditional(
        mut self,
        condition: AuthCondition,
        if_step: AuthStep,
        else_step: Option<AuthStep>,
    ) -> Self {
        self.steps.push(AuthStep::Conditional {
            condition,
            if_step: Box::new(if_step),
            else_step: else_step.map(Box::new),
        });
        self
    }

    /// 追加 [`AuthStep::SubFlow`] 步骤（子流程引用）。
    pub fn sub_flow(mut self, flow_name: &str) -> Self {
        self.steps.push(AuthStep::SubFlow {
            flow_name: flow_name.to_string(),
        });
        self
    }

    /// 设置 `allow_skip = true`，允许步骤跳过。
    pub fn allow_skip(mut self) -> Self {
        self.allow_skip = true;
        self
    }

    /// 构造 [`AuthenticationFlow`]，消耗构建器。
    pub fn build(self) -> AuthenticationFlow {
        AuthenticationFlow {
            name: self.name,
            steps: self.steps,
            allow_skip: self.allow_skip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 空 flow：仅指定名称，steps 为空，allow_skip 默认 false（R-auth-flow-dsl-006）。
    #[test]
    fn empty_flow() {
        let flow = FlowBuilder::new("empty").build();
        assert_eq!(flow.name, "empty");
        assert!(flow.steps.is_empty());
        assert!(!flow.allow_skip);
    }

    /// 单步 flow：一个 Login 步骤（R-auth-flow-dsl-006）。
    #[test]
    fn single_step_flow() {
        let flow = FlowBuilder::new("single").login("password").build();
        assert_eq!(flow.steps.len(), 1);
        assert!(matches!(
            &flow.steps[0],
            AuthStep::Login { credential_type } if credential_type == "password"
        ));
    }

    /// 多步 flow：login + mfa + social + sso（R-auth-flow-dsl-006）。
    #[test]
    fn multi_step_flow() {
        let flow = FlowBuilder::new("multi")
            .login("password")
            .mfa(Some("totp"))
            .social("wechat")
            .sso("keycloak")
            .build();
        assert_eq!(flow.steps.len(), 4);
        assert!(matches!(flow.steps[0], AuthStep::Login { .. }));
        assert!(matches!(
            &flow.steps[1],
            AuthStep::Mfa { credential_type } if credential_type.as_deref() == Some("totp")
        ));
        assert!(matches!(
            &flow.steps[2],
            AuthStep::SocialProvider { provider } if provider == "wechat"
        ));
        assert!(matches!(
            &flow.steps[3],
            AuthStep::SsoServer { server_id } if server_id == "keycloak"
        ));
    }

    /// conditional flow：条件分支含 Box 包装（R-auth-flow-dsl-006）。
    #[test]
    fn conditional_flow() {
        let flow = FlowBuilder::new("cond")
            .login("password")
            .conditional(
                AuthCondition::HasCredential("totp".to_string()),
                AuthStep::Mfa {
                    credential_type: Some("totp".to_string()),
                },
                None,
            )
            .build();
        assert_eq!(flow.steps.len(), 2);
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
                assert!(matches!(if_step.as_ref(), AuthStep::Mfa { .. }));
                assert!(else_step.is_none());
            },
            _ => panic!("第二个步骤应为 Conditional"),
        }
    }

    /// sub_flow flow：子流程引用步骤（R-auth-flow-dsl-006）。
    #[test]
    fn sub_flow_step() {
        let flow = FlowBuilder::new("parent")
            .login("password")
            .sub_flow("child-flow")
            .build();
        assert_eq!(flow.steps.len(), 2);
        assert!(matches!(
            &flow.steps[1],
            AuthStep::SubFlow { flow_name } if flow_name == "child-flow"
        ));
    }

    /// allow_skip：显式开启后 build 返回的 flow allow_skip == true（R-auth-flow-dsl-006）。
    #[test]
    fn allow_skip_flag() {
        let flow = FlowBuilder::new("skippable")
            .login("password")
            .allow_skip()
            .build();
        assert!(flow.allow_skip);

        // 未调用 allow_skip 时默认 false
        let flow_default = FlowBuilder::new("not-skippable").login("password").build();
        assert!(!flow_default.allow_skip);
    }

    /// mfa(None) 构造 Mfa { credential_type: None }（R-auth-flow-dsl-006 补充）。
    #[test]
    fn mfa_none_variant() {
        let flow = FlowBuilder::new("mfa-none").mfa(None).build();
        assert_eq!(flow.steps.len(), 1);
        assert!(matches!(
            &flow.steps[0],
            AuthStep::Mfa { credential_type } if credential_type.is_none()
        ));
    }
}
