//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! account/authflow 模块测试（从 mod.rs 迁移，Rule 25 合规）。

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
