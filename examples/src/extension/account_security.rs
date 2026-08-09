//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 账号安全引擎示例：演示密码策略 / 账号锁定 / 认证流程 DSL。
//!
//! 对应模块：`src/account/`（各 `account-*` feature 开启时可用）。
//!
//! 流程：
//! 1. PasswordPolicyEngine：注册规则 + 校验密码
//! 2. UserLockoutConfig：配置锁定策略
//! 3. FlowBuilder：声明式认证流程编排
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin account_security --features "account-policy,account-lockout,account-authflow,cache-memory"
//! ```

use garrison::error::GarrisonResult;

// ============================================================================
// 1. 密码策略引擎（account-policy）
// ============================================================================

#[cfg(feature = "account-policy")]
fn demo_password_policy() {
    use garrison::account::policy::rules::{BlacklistRule, LengthRule, NotCommonPasswordRule};
    use garrison::account::policy::{
        ErrorMode, PasswordPolicyEngine, PasswordPolicyRule, PolicyContext,
    };

    println!("[1] 密码策略引擎 (PasswordPolicyEngine):");

    // 注册规则
    let rules: Vec<Box<dyn PasswordPolicyRule>> = vec![
        Box::new(LengthRule::new(8, 128)),
        Box::new(BlacklistRule::new(vec![
            "admin123".to_string(),
            "password".to_string(),
        ])),
        Box::new(NotCommonPasswordRule::new(vec![
            "123456".to_string(),
            "qwerty".to_string(),
        ])),
    ];

    let engine = PasswordPolicyEngine::new(rules, ErrorMode::AllErrors);

    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: None,
        username: Some("alice".to_string()),
        email: None,
        password_history: vec![],
    };

    // 强密码 — 通过
    let strong = "S3cur3&P@ss!";
    match engine.validate(&ctx, strong) {
        Ok(()) => println!("    '{}' → 通过 ✓", strong),
        Err(errors) => println!("    '{}' → 失败: {:?}", strong, errors),
    }

    // 弱密码 — 过短
    let weak = "short";
    match engine.validate(&ctx, weak) {
        Ok(()) => println!("    '{}' → 通过", weak),
        Err(errors) => {
            println!("    '{}' → 失败 ({} 条规则不满足):", weak, errors.len());
            for e in &errors {
                println!("      - [{}]: {}", e.rule_name, e.message);
            }
        },
    }

    // 黑名单密码
    let blacklisted = "admin123";
    match engine.validate(&ctx, blacklisted) {
        Ok(()) => println!("    '{}' → 通过", blacklisted),
        Err(errors) => {
            println!("    '{}' → 失败:", blacklisted);
            for e in &errors {
                println!("      - [{}]: {}", e.rule_name, e.message);
            }
        },
    }
    println!();
}

#[cfg(not(feature = "account-policy"))]
fn demo_password_policy() {
    println!("[1] 密码策略引擎示例跳过（需启用 account-policy feature）\n");
}

// ============================================================================
// 2. 账号锁定配置（account-lockout）
// ============================================================================

#[cfg(feature = "account-lockout")]
fn demo_account_lockout() {
    use garrison::account::lockout::{UserLockoutConfig, WaitStrategy};

    println!("[2] 账号锁定配置 (UserLockoutConfig):");

    let config = UserLockoutConfig {
        max_failure_factor: 5,     // 5 次失败触发锁定
        permanent_lockout: true,   // 启用永久锁定
        max_temporary_lockouts: 3, // 3 次临时锁定后升级为永久锁定
        wait_strategy: WaitStrategy::Multiple {
            base_seconds: 60, // 基础等待 60 秒
            multiplier: 2,    // 每次翻倍：60s → 120s → 240s
        },
        failure_window_seconds: 1800, // 30 分钟窗口内累计失败
    };

    println!("    失败阈值: {} 次", config.max_failure_factor);
    println!("    永久锁定: {}", config.permanent_lockout);
    println!("    临时锁定上限: {} 次", config.max_temporary_lockouts);
    println!("    等待策略: Multiple {{ base: 60s, multiplier: 2 }}");
    println!("    失败窗口: {}s\n", config.failure_window_seconds);
}

#[cfg(not(feature = "account-lockout"))]
fn demo_account_lockout() {
    println!("[2] 账号锁定配置示例跳过（需启用 account-lockout feature）\n");
}

// ============================================================================
// 3. 认证流程 DSL（account-authflow）
// ============================================================================

#[cfg(feature = "account-authflow")]
fn demo_auth_flow() {
    use garrison::account::authflow::builder::FlowBuilder;
    use garrison::account::authflow::{AuthCondition, AuthStep};

    println!("[3] 认证流程 DSL (FlowBuilder):");

    // 构建标准密码 + MFA 流程
    let flow = FlowBuilder::new("password-mfa-flow")
        .login("password")
        .conditional(
            AuthCondition::HasCredential("totp".to_string()),
            AuthStep::Mfa {
                credential_type: Some("totp".to_string()),
            },
            None, // 无 TOTP 则跳过
        )
        .build();

    println!("    流程名称: {}", flow.name);
    println!("    步骤数: {}", flow.steps.len());
    println!("    允许跳过: {}", flow.allow_skip);
    for (i, step) in flow.steps.iter().enumerate() {
        println!("    [{}] {:?}", i, step);
    }

    // 构建社交登录流程
    let social_flow = FlowBuilder::new("social-login-flow")
        .social("wechat")
        .conditional(
            AuthCondition::HasCredential("password".to_string()),
            AuthStep::Login {
                credential_type: "password".to_string(),
            },
            None,
        )
        .allow_skip()
        .build();

    println!("\n    社交登录流程: {}", social_flow.name);
    println!("    步骤数: {}", social_flow.steps.len());
    println!("    允许跳过: {}", social_flow.allow_skip);
    for (i, step) in social_flow.steps.iter().enumerate() {
        println!("    [{}] {:?}", i, step);
    }
    println!();
}

#[cfg(not(feature = "account-authflow"))]
fn demo_auth_flow() {
    println!("[3] 认证流程 DSL 示例跳过（需启用 account-authflow feature）\n");
}

/// 运行账号安全引擎示例。
///
/// 演示密码策略校验、账号锁定配置、认证流程编排。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 账号安全引擎示例 ===\n");

    demo_password_policy();
    demo_account_lockout();
    demo_auth_flow();

    println!("=== 示例执行完成 ===");
    Ok(())
}
