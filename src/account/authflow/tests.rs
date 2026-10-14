// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! account/authflow 模块测试。

use super::*;

/// 验证 AuthStep::Login 构造与字段访问。
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

/// 验证 AuthStep::Conditional 构造含 Box<AuthStep>。
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

/// 验证 AuthStep match 穷尽匹配（7 变体）。
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

/// 验证 AuthCondition 4 个变体构造。
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

/// 验证 AuthenticationFlow 构造与字段访问。
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

/// 验证 AuthContext 构造与字段访问。
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

/// 验证 AuthResult 4 个变体 match 匹配。
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

/// 验证 `allow_skip` 默认链路：`AuthenticationFlow` 无 `Default` 实现（仅 derive Debug/Clone），
/// 字面量构造必须显式给出 `allow_skip`，实际默认来源是 [`FlowBuilder`]（初始 false，仅显式调用
/// `.allow_skip()` 才置 true）；本测试验证未调用时为 false、显式开启后为 true。
#[test]
fn authentication_flow_allow_skip_default_false() {
    let flow = FlowBuilder::new("default").build();
    assert!(
        !flow.allow_skip,
        "FlowBuilder 默认（未显式开启）allow_skip 应为 false"
    );

    // 对照组：显式开启后为 true（确认断言不是恒假）
    let skipped = FlowBuilder::new("default").allow_skip().build();
    assert!(skipped.allow_skip, "显式调用 .allow_skip() 后应为 true");
}

/// AuthContext 手动 Debug 对 input 脱敏。
#[test]
fn auth_context_debug_redacts_input() {
    let ctx = AuthContext {
        input: "super-secret-password".to_string(),
        user_id: Some("alice".to_string()),
        tenant_id: None,
        ip: "127.0.0.1".to_string(),
        completed_steps: vec![0],
        extras: HashMap::new(),
    };
    let debug = format!("{ctx:?}");
    assert!(
        debug.contains("<redacted>"),
        "Debug 输出应含 <redacted>，实际: {debug}"
    );
    assert!(
        !debug.contains("super-secret-password"),
        "Debug 输出不得包含明文凭证，实际: {debug}"
    );
    // 具名字段访问不受影响
    assert_eq!(ctx.input, "super-secret-password");
}

/// AuthResult::Success 手动 Debug 对 token 掩码。
#[test]
fn auth_result_success_debug_masks_token() {
    let result = AuthResult::Success {
        login_id: "alice".to_string(),
        token: "raw-session-token-value-12345".to_string(),
    };
    let debug = format!("{result:?}");
    assert!(
        !debug.contains("raw-session-token-value-12345"),
        "Debug 输出不得包含明文 token，实际: {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "Debug 输出应含 <redacted> 掩码，实际: {debug}"
    );
    // 短 token 全掩码，不泄露任何片段
    let short = AuthResult::Success {
        login_id: "bob".to_string(),
        token: "abc".to_string(),
    };
    let debug = format!("{short:?}");
    assert!(
        !debug.contains("abc\"") && debug.contains("<redacted>"),
        "短 token 应全掩码，实际: {debug}"
    );
}

/// AuthResult 其余变体的手动 Debug 分支：Failed / Pending / ChallengeRequired 均带 variant 标签。
#[test]
fn auth_result_debug_covers_failed_pending_and_challenge_variants() {
    let failed = AuthResult::Failed {
        reason: "invalid_credentials".to_string(),
        step: 2,
    };
    let debug = format!("{failed:?}");
    assert!(
        debug.contains("variant: \"Failed\"")
            && debug.contains("invalid_credentials")
            && debug.contains("step: 2"),
        "Failed Debug 应含 variant 标签、reason 与 step，实际: {debug}"
    );

    let pending = AuthResult::Pending {
        completed_step: 1,
        next_step: 2,
        challenge: "请输入 TOTP".to_string(),
    };
    let debug = format!("{pending:?}");
    assert!(
        debug.contains("variant: \"Pending\"")
            && debug.contains("completed_step: 1")
            && debug.contains("next_step: 2")
            && debug.contains("请输入 TOTP"),
        "Pending Debug 应含 variant 标签与三步进度，实际: {debug}"
    );

    let challenge = AuthResult::ChallengeRequired {
        challenge_type: "captcha".to_string(),
        message: "请完成验证码".to_string(),
    };
    let debug = format!("{challenge:?}");
    assert!(
        debug.contains("variant: \"ChallengeRequired\"")
            && debug.contains("captcha")
            && debug.contains("请完成验证码"),
        "ChallengeRequired Debug 应含 variant 标签与挑战信息，实际: {debug}"
    );
}

/// IpWhitelist::is_empty 与空/非空 CIDR 列表一致。
#[test]
fn ip_whitelist_is_empty_tracks_cidr_list() {
    let empty = IpWhitelist::parse(&[]).expect("空列表应可解析");
    assert!(empty.is_empty(), "空 CIDR 列表应判定为空");

    let one = IpWhitelist::parse(&["10.0.0.0/8".to_string()]).expect("合法 CIDR 应可解析");
    assert!(!one.is_empty(), "非空 CIDR 列表不得判定为空");
}
