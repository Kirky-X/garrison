//! AuthenticationFlow DSL 子模块（v0.6.0 新增，吸收 keycloak AuthenticationFlow）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供声明式认证流程编排，覆盖登录 + MFA + 社交登录 + SSO 全认证流程。
//! 详见 spec `auth-flow-dsl`。
//!
//! # 核心类型（T013）
//!
//! - [`AuthStep`](crate::account::authflow::AuthStep)：认证步骤 enum（7 变体：Login/Mfa/SocialProvider/SsoServer/RequiredAction/Conditional/SubFlow）
//! - [`AuthCondition`](crate::account::authflow::AuthCondition)：条件分支 enum（4 变体：HasCredential/IsLocked/IpWhitelisted/Custom）
//! - [`AuthenticationFlow`](crate::account::authflow::AuthenticationFlow)：认证流程定义（name + steps + allow_skip）
//! - [`AuthContext`](crate::account::authflow::AuthContext)：执行上下文（input + user_id + tenant_id + ip + completed_steps + extras）
//! - [`AuthResult`](crate::account::authflow::AuthResult)：执行结果 enum（4 变体：Success/Failed/Pending/ChallengeRequired)
//!
//! # 子模块
//!
//! - [`builder`](crate::account::authflow::builder): FlowBuilder 流式构建 DSL（T014）
//! - [`registry`](crate::account::authflow::registry): FlowRegistry inventory 注册（T015）
//! - [`executor`](crate::account::authflow::executor): AuthExecutor 执行器（T016/T017）
//! - [`builtin`](crate::account::authflow::builtin): 内置 AuthenticationFlow（T018）

pub mod builder;
pub mod builtin;
pub mod executor;
pub mod registry;

use std::collections::HashMap;

/// 认证步骤 enum，定义流程中的 7 种步骤类型（依据 spec auth-flow-dsl R-auth-flow-dsl-001）。
///
/// 使用 enum 而非 trait object（决策 D3），保证可序列化与编译期穷尽匹配。
#[derive(Debug, Clone)]
pub enum AuthStep {
    /// 密码登录，调用 `Credential::verify`。
    Login {
        /// 凭证类型（如 "password"）。
        credential_type: String,
    },
    /// MFA 校验，调用 `MfaLogic::check_safe` 或 `Credential::verify` for TOTP。
    Mfa {
        /// 凭证类型（None 表示由执行器自动选择，Some("totp") 指定 TOTP）。
        credential_type: Option<String>,
    },
    /// 社交登录，调用 `SocialProvider::authorize`。
    SocialProvider {
        /// Provider 名称（如 "wechat"/"alipay"/"keycloak"）。
        provider: String,
    },
    /// SSO 登录，调用 `SsoServer::issue_ticket`。
    SsoServer {
        /// SSO 服务器标识。
        server_id: String,
    },
    /// 必需动作（v0.6 仅占位，v0.6.5 实现）。
    RequiredAction {
        /// 动作标识。
        action: String,
    },
    /// 条件分支，根据 `condition` 评估结果执行 `if_step` 或 `else_step`。
    Conditional {
        /// 条件判断。
        condition: AuthCondition,
        /// 条件为真时执行的步骤。
        if_step: Box<AuthStep>,
        /// 条件为假时执行的步骤（None 表示跳过）。
        else_step: Option<Box<AuthStep>>,
    },
    /// 子流程引用，从 `FlowRegistry` 查询并递归执行。
    SubFlow {
        /// 引用的流程名称。
        flow_name: String,
    },
}

/// 认证条件 enum，用于 `AuthStep::Conditional` 的条件判断
/// （依据 spec auth-flow-dsl R-auth-flow-dsl-002）。
#[derive(Debug, Clone)]
pub enum AuthCondition {
    /// 用户已注册特定凭证类型（参数为 credential_type）。
    HasCredential(String),
    /// 用户处于锁定状态。
    IsLocked,
    /// 请求来源 IP 在白名单。
    IpWhitelisted,
    /// 自定义条件（闭包不可序列化，仅运行期注册，v0.6.5 实现）。
    Custom(String),
}

/// 认证流程定义（依据 spec auth-flow-dsl R-auth-flow-dsl-003）。
///
/// 含有序步骤列表，由 `FlowBuilder` 构造，`AuthExecutor` 执行。
#[derive(Debug, Clone)]
pub struct AuthenticationFlow {
    /// 流程名称（唯一标识，用于 `FlowRegistry` 查询与 `SubFlow` 引用）。
    pub name: String,
    /// 有序步骤列表（按顺序执行）。
    pub steps: Vec<AuthStep>,
    /// 是否允许步骤跳过（false 时每步必须通过，true 时允许跳过失败步骤）。
    pub allow_skip: bool,
}

/// 执行上下文，携带认证过程的状态与输入（依据 spec auth-flow-dsl R-auth-flow-dsl-004）。
///
/// 作为 `AuthExecutor::execute` 的可变引用参数，执行过程中更新 `completed_steps`。
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// 用户输入（密码/TOTP code/社交 authorization_code 等）。
    pub input: String,
    /// 用户 ID（社交登录首步可能无 user_id）。
    pub user_id: Option<String>,
    /// 租户 ID。
    pub tenant_id: Option<String>,
    /// 请求来源 IP。
    pub ip: String,
    /// 已完成步骤索引列表。
    pub completed_steps: Vec<usize>,
    /// 扩展数据（社交登录 state/redirect_uri 等）。
    pub extras: HashMap<String, String>,
}

/// 认证执行结果（依据 spec auth-flow-dsl R-auth-flow-dsl-005）。
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// 认证成功。
    Success {
        /// 登录 ID（用户标识）。
        login_id: String,
        /// 会话 token。
        token: String,
    },
    /// 认证失败。
    Failed {
        /// 失败原因。
        reason: String,
        /// 失败步骤索引。
        step: usize,
    },
    /// 等待用户输入（多步认证中间状态）。
    Pending {
        /// 已完成步骤索引。
        completed_step: usize,
        /// 下一步骤索引。
        next_step: usize,
        /// 挑战信息（提示用户输入下一步所需的凭证）。
        challenge: String,
    },
    /// 需要挑战（如验证码/二次验证）。
    ChallengeRequired {
        /// 挑战类型（如 "captcha"/"otp"）。
        challenge_type: String,
        /// 挑战消息。
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 AuthStep::Login 构造与字段访问（R-auth-flow-dsl-001）。
    #[test]
    fn auth_step_login_construction() {
        let step = AuthStep::Login {
            credential_type: "password".to_string(),
        };
        match step {
            AuthStep::Login { credential_type } => {
                assert_eq!(credential_type, "password");
            },
            _ => panic!("应为 Login 变体"),
        }
    }

    /// 验证 AuthStep::Conditional 构造含 Box<AuthStep>（R-auth-flow-dsl-001）。
    #[test]
    fn auth_step_conditional_construction() {
        let step = AuthStep::Conditional {
            condition: AuthCondition::HasCredential("totp".to_string()),
            if_step: Box::new(AuthStep::Mfa {
                credential_type: Some("totp".to_string()),
            }),
            else_step: None,
        };
        match step {
            AuthStep::Conditional {
                condition,
                if_step,
                else_step,
            } => {
                assert!(matches!(
                    condition,
                    AuthCondition::HasCredential(ref s) if s == "totp"
                ));
                assert!(matches!(*if_step, AuthStep::Mfa { .. }));
                assert!(else_step.is_none());
            },
            _ => panic!("应为 Conditional 变体"),
        }
    }

    /// 验证 AuthStep match 穷尽匹配（7 变体，R-auth-flow-dsl-001）。
    #[test]
    fn auth_step_exhaustive_match() {
        let steps = vec![
            AuthStep::Login {
                credential_type: "p".to_string(),
            },
            AuthStep::Mfa {
                credential_type: None,
            },
            AuthStep::SocialProvider {
                provider: "w".to_string(),
            },
            AuthStep::SsoServer {
                server_id: "s".to_string(),
            },
            AuthStep::RequiredAction {
                action: "a".to_string(),
            },
            AuthStep::Conditional {
                condition: AuthCondition::IsLocked,
                if_step: Box::new(AuthStep::Login {
                    credential_type: "p".to_string(),
                }),
                else_step: None,
            },
            AuthStep::SubFlow {
                flow_name: "f".to_string(),
            },
        ];
        for step in &steps {
            let _ = match step {
                AuthStep::Login { .. } => "login",
                AuthStep::Mfa { .. } => "mfa",
                AuthStep::SocialProvider { .. } => "social",
                AuthStep::SsoServer { .. } => "sso",
                AuthStep::RequiredAction { .. } => "action",
                AuthStep::Conditional { .. } => "conditional",
                AuthStep::SubFlow { .. } => "subflow",
            };
        }
        assert_eq!(steps.len(), 7);
    }

    /// 验证 AuthCondition 4 个变体构造（R-auth-flow-dsl-002）。
    #[test]
    fn auth_condition_variants() {
        let conditions = vec![
            AuthCondition::HasCredential("totp".to_string()),
            AuthCondition::IsLocked,
            AuthCondition::IpWhitelisted,
            AuthCondition::Custom("my_check".to_string()),
        ];
        let mut has_cred = false;
        let mut is_locked = false;
        let mut ip_whitelist = false;
        let mut custom = false;
        for c in &conditions {
            match c {
                AuthCondition::HasCredential(s) => {
                    assert_eq!(s, "totp");
                    has_cred = true;
                },
                AuthCondition::IsLocked => is_locked = true,
                AuthCondition::IpWhitelisted => ip_whitelist = true,
                AuthCondition::Custom(s) => {
                    assert_eq!(s, "my_check");
                    custom = true;
                },
            }
        }
        assert!(has_cred && is_locked && ip_whitelist && custom);
    }

    /// 验证 AuthenticationFlow 构造与字段访问（R-auth-flow-dsl-003）。
    #[test]
    fn authentication_flow_construction() {
        let flow = AuthenticationFlow {
            name: "test-flow".to_string(),
            steps: vec![AuthStep::Login {
                credential_type: "password".to_string(),
            }],
            allow_skip: false,
        };
        assert_eq!(flow.name, "test-flow");
        assert_eq!(flow.steps.len(), 1);
        assert!(!flow.allow_skip);
    }

    /// 验证 AuthContext 构造与字段访问（R-auth-flow-dsl-004）。
    #[test]
    fn auth_context_construction() {
        let ctx = AuthContext {
            input: "password123".to_string(),
            user_id: Some("user1".to_string()),
            tenant_id: None,
            ip: "192.168.1.1".to_string(),
            completed_steps: vec![],
            extras: HashMap::new(),
        };
        assert_eq!(ctx.input, "password123");
        assert_eq!(ctx.user_id.as_deref(), Some("user1"));
        assert!(ctx.tenant_id.is_none());
        assert_eq!(ctx.ip, "192.168.1.1");
        assert!(ctx.completed_steps.is_empty());
        assert!(ctx.extras.is_empty());
    }

    /// 验证 AuthResult 4 个变体 match 匹配（R-auth-flow-dsl-005）。
    #[test]
    fn auth_result_variants_match() {
        let results = vec![
            AuthResult::Success {
                login_id: "user1".to_string(),
                token: "token123".to_string(),
            },
            AuthResult::Failed {
                reason: "bad password".to_string(),
                step: 0,
            },
            AuthResult::Pending {
                completed_step: 0,
                next_step: 1,
                challenge: "enter totp".to_string(),
            },
            AuthResult::ChallengeRequired {
                challenge_type: "captcha".to_string(),
                message: "please solve captcha".to_string(),
            },
        ];
        let mut success = false;
        let mut failed = false;
        let mut pending = false;
        let mut challenge = false;
        for r in &results {
            match r {
                AuthResult::Success { login_id, token } => {
                    assert_eq!(login_id, "user1");
                    assert_eq!(token, "token123");
                    success = true;
                },
                AuthResult::Failed { reason, step } => {
                    assert_eq!(reason, "bad password");
                    assert_eq!(*step, 0);
                    failed = true;
                },
                AuthResult::Pending {
                    completed_step,
                    next_step,
                    challenge: ch,
                } => {
                    assert_eq!(*completed_step, 0);
                    assert_eq!(*next_step, 1);
                    assert_eq!(ch, "enter totp");
                    pending = true;
                },
                AuthResult::ChallengeRequired {
                    challenge_type,
                    message,
                } => {
                    assert_eq!(challenge_type, "captcha");
                    assert_eq!(message, "please solve captcha");
                    challenge = true;
                },
            }
        }
        assert!(success && failed && pending && challenge);
    }

    /// 验证 AuthenticationFlow 默认 allow_skip=false 的惯例
    /// （未显式设置时为 false）。
    #[test]
    fn authentication_flow_allow_skip_default_false() {
        let flow = AuthenticationFlow {
            name: "default".to_string(),
            steps: vec![],
            allow_skip: false,
        };
        assert!(!flow.allow_skip, "默认 allow_skip 应为 false");
    }
}
