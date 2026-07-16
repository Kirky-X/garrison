//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `PasswordPolicyEngine` 单元测试。
//!
//! 测试自父模块迁移（规则 25：mod.rs 接口隔离）。

use super::*;

// ------------------------------------------------------------------------
// Mock 规则（用于引擎测试）
// ------------------------------------------------------------------------

/// 始终通过的规则。
struct AlwaysPassRule;
impl PasswordPolicyRule for AlwaysPassRule {
    fn name(&self) -> &'static str {
        "always_pass"
    }
    fn validate(&self, _ctx: &PolicyContext, _password: &str) -> Result<(), PolicyError> {
        Ok(())
    }
}

/// 始终失败的规则（message 可定制，用于区分多个失败规则）。
struct AlwaysFailRule {
    msg: &'static str,
}
impl PasswordPolicyRule for AlwaysFailRule {
    fn name(&self) -> &'static str {
        "always_fail"
    }
    fn validate(&self, _ctx: &PolicyContext, _password: &str) -> Result<(), PolicyError> {
        Err(PolicyError::new("always_fail", self.msg))
    }
}

// ------------------------------------------------------------------------
// R-001: PasswordPolicyRule trait 对象安全测试
// ------------------------------------------------------------------------

/// R-001: `PasswordPolicyRule` trait 可作 `Box<dyn PasswordPolicyRule>` 使用（对象安全）。
#[test]
fn password_policy_rule_is_object_safe() {
    fn _assert_object_safe(_rule: Box<dyn PasswordPolicyRule>) {}
    let rule: Box<dyn PasswordPolicyRule> = Box::new(AlwaysPassRule);
    _assert_object_safe(rule);
}

/// R-001: `Vec<Box<dyn PasswordPolicyRule>>` 可构造（引擎 rules 字段类型验证）。
#[test]
fn password_policy_rule_vec_of_boxed_dyn() {
    let rules: Vec<Box<dyn PasswordPolicyRule>> = vec![
        Box::new(AlwaysPassRule),
        Box::new(AlwaysFailRule { msg: "fail1" }),
    ];
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].name(), "always_pass");
    assert_eq!(rules[1].name(), "always_fail");
}

// ------------------------------------------------------------------------
// R-002: PolicyContext 构造测试
// ------------------------------------------------------------------------

/// R-002: `PolicyContext` 5 字段构造（类型与 design.md §3.2 一致）。
#[test]
fn policy_context_constructs_with_5_fields() {
    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: Some("tenant-001".to_string()),
        username: Some("alice".to_string()),
        email: Some("alice@example.com".to_string()),
        password_history: vec!["hash1".to_string(), "hash2".to_string()],
    };
    assert_eq!(ctx.user_id, "alice");
    assert_eq!(ctx.tenant_id, Some("tenant-001".to_string()));
    assert_eq!(ctx.username, Some("alice".to_string()));
    assert_eq!(ctx.email, Some("alice@example.com".to_string()));
    assert_eq!(ctx.password_history.len(), 2);
}

/// R-002: `PolicyContext` 可选字段为 `None` 时构造正常。
#[test]
fn policy_context_optional_fields_none() {
    let ctx = PolicyContext {
        user_id: "bob".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: Vec::new(),
    };
    assert!(ctx.tenant_id.is_none());
    assert!(ctx.username.is_none());
    assert!(ctx.email.is_none());
    assert!(ctx.password_history.is_empty());
}

// ------------------------------------------------------------------------
// R-003: PasswordPolicyEngine 测试
// ------------------------------------------------------------------------

/// R-003: 空规则集 + 任意密码 → `Ok(())`。
#[test]
fn engine_empty_rules_returns_ok() {
    let engine = PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError);
    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: Vec::new(),
    };
    assert!(engine.validate(&ctx, "any").is_ok());
}

/// R-003: 全部规则通过 → `Ok(())`。
#[test]
fn engine_all_pass_returns_ok() {
    let engine = PasswordPolicyEngine::new(
        vec![Box::new(AlwaysPassRule), Box::new(AlwaysPassRule)],
        ErrorMode::AllErrors,
    );
    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: Vec::new(),
    };
    assert!(engine.validate(&ctx, "password").is_ok());
}

/// R-003: `FirstError` 模式 — 首条失败即返回单元素 Vec 并短路。
#[test]
fn engine_first_error_mode_short_circuits() {
    // 第一条失败，第二条也失败；FirstError 应只返回第一条错误
    let engine = PasswordPolicyEngine::new(
        vec![
            Box::new(AlwaysFailRule { msg: "fail1" }),
            Box::new(AlwaysFailRule { msg: "fail2" }),
        ],
        ErrorMode::FirstError,
    );
    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: Vec::new(),
    };
    let result = engine.validate(&ctx, "password");
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1, "FirstError 模式应只返回 1 个错误");
    assert_eq!(errors[0].message, "fail1", "应短路在第一条失败规则");
}

/// R-003: `AllErrors` 模式 — 收集全部失败规则错误。
#[test]
fn engine_all_errors_mode_collects_all() {
    // 第一条通过，第二、三条失败；AllErrors 应返回 2 个错误
    let engine = PasswordPolicyEngine::new(
        vec![
            Box::new(AlwaysPassRule),
            Box::new(AlwaysFailRule { msg: "fail1" }),
            Box::new(AlwaysFailRule { msg: "fail2" }),
        ],
        ErrorMode::AllErrors,
    );
    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: Vec::new(),
    };
    let result = engine.validate(&ctx, "password");
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 2, "AllErrors 模式应收集全部 2 个失败");
    assert_eq!(errors[0].message, "fail1");
    assert_eq!(errors[1].message, "fail2");
}

/// R-003: `FirstError` 模式 — 首条通过、第二条失败时返回第二条错误。
#[test]
fn engine_first_error_mode_skips_passing_rules() {
    let engine = PasswordPolicyEngine::new(
        vec![
            Box::new(AlwaysPassRule),
            Box::new(AlwaysFailRule { msg: "fail1" }),
        ],
        ErrorMode::FirstError,
    );
    let ctx = PolicyContext {
        user_id: "alice".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: Vec::new(),
    };
    let result = engine.validate(&ctx, "password");
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].message, "fail1");
}
