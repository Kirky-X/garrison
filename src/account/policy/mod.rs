//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 密码策略套件子模块（吸收 keycloak PasswordPolicyRule）。
//! 提供可插拔密码策略规则 + 统一引擎执行，支持企业合规场景。
//! 详见 spec `password-policy`。
//!
//! # 核心类型
//!
//! - `PasswordPolicyRule` trait：规则抽象（同步纯函数，`name` + `validate`）
//! - `PolicyContext`：策略校验上下文（user_id/tenant_id/username/email/password_history）
//! - `PasswordPolicyEngine`：规则引擎（FirstError/AllErrors 两种模式）
//! - `PolicyError`：规则校验错误（rule_name + message）
//!
//! # 设计
//!
//! - 规则为同步纯函数（无 IO/await），可在任意上下文调用
//! - 引擎按 `ErrorMode` 执行：`FirstError` 短路，`AllErrors` 收集全部
//! - 规则参数由构造器注入（v0.6.5 支持 `BulwarkConfig` 加载）

mod error;
pub mod rules;

pub use error::PolicyError;
#[cfg(feature = "metrics-prometheus")]
use std::sync::Arc;

// ============================================================================
// PasswordPolicyRule trait
// ============================================================================

/// 密码策略规则 trait。
///
/// 每条规则为同步纯函数（非 async），校验密码是否符合规则。
/// 无 `#[async_trait]`（规则校验不执行 IO/await）。
///
/// # 对象安全
///
/// trait 仅含同步方法，对象安全，可作 `Box<dyn PasswordPolicyRule>` /
/// `Vec<Box<dyn PasswordPolicyRule>>` 使用。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::policy::{PasswordPolicyRule, PolicyContext, PolicyError};
///
/// struct AlwaysPassRule;
/// impl PasswordPolicyRule for AlwaysPassRule {
///     fn name(&self) -> &'static str { "always_pass" }
///     fn validate(&self, _ctx: &PolicyContext, _password: &str) -> Result<(), PolicyError> {
///         Ok(())
///     }
/// }
/// ```
pub trait PasswordPolicyRule: Send + Sync {
    /// 返回规则名称（编译期常量，如 `"length"` / `"complexity"`）。
    fn name(&self) -> &'static str;

    /// 校验密码是否符合规则。
    ///
    /// # 参数
    /// - `ctx`: 策略上下文（含 user_id/username/password_history 等）
    /// - `password`: 待校验密码
    ///
    /// # 返回
    /// - `Ok(())`: 密码符合规则
    /// - `Err(PolicyError)`: 密码不符合规则（`rule_name` 应与 `name()` 一致）
    fn validate(&self, ctx: &PolicyContext, password: &str) -> Result<(), PolicyError>;
}

// ============================================================================
// PolicyContext
// ============================================================================

/// 策略校验上下文。
///
/// 5 字段 schema（pre-1.0 锁定，与 design.md §3.2 严格一致）。
/// 提供规则校验所需的用户上下文信息。
///
/// # 字段说明
///
/// | 字段 | 类型 | 说明 |
/// |:---|:---|:---|
/// | `user_id` | `String` | 用户 ID |
/// | `tenant_id` | `Option<String>` | 租户 ID（可选） |
/// | `username` | `Option<String>` | 用户名（用于相似度检测） |
/// | `email` | `Option<String>` | 邮箱（用于邮箱检测） |
/// | `password_history` | `Vec<String>` | 密码历史（存 hash，非明文） |
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// 用户 ID。
    pub user_id: String,
    /// 租户 ID（可选，多租户场景使用）。
    pub tenant_id: Option<String>,
    /// 用户名（可选，用于 `NotUsernameRule` 相似度检测）。
    pub username: Option<String>,
    /// 邮箱（可选，用于 `NotEmailRule` 检测）。
    pub email: Option<String>,
    /// 密码历史（hash 列表，非明文，用于 `HistoryRule` 检测）。
    pub password_history: Vec<String>,
}

// ============================================================================
// ErrorMode + PasswordPolicyEngine
// ============================================================================

/// 引擎错误返回模式。
///
/// - `FirstError`: 首条规则失败即返回 `Err(vec![error])` 并短路
/// - `AllErrors`: 执行所有规则，收集全部错误返回 `Err(errors)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorMode {
    /// 首条失败即返回并短路（不执行后续规则）。
    FirstError,
    /// 执行所有规则，收集全部错误。
    AllErrors,
}

/// 密码策略引擎。
///
/// 持有规则列表 + 错误模式，按 `mode` 执行规则校验。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::policy::{ErrorMode, PasswordPolicyEngine, PolicyContext};
/// // T008/T009 实现具体规则后注入
/// let engine = PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError);
/// let ctx = PolicyContext {
///     user_id: "alice".into(),
///     tenant_id: None,
///     username: None,
///     email: None,
///     password_history: Vec::new(),
/// };
/// assert!(engine.validate(&ctx, "password").is_ok()); // 空规则集 → Ok
/// ```
pub struct PasswordPolicyEngine {
    /// 规则列表（按注册顺序执行）。
    rules: Vec<Box<dyn PasswordPolicyRule>>,
    /// 错误返回模式。
    mode: ErrorMode,
    /// 账号安全指标（可选，注入后每条规则校验后调用 `observe_policy_validate`）。
    #[cfg(feature = "metrics-prometheus")]
    metrics: Option<Arc<crate::account::metrics::AccountMetrics>>,
}

impl PasswordPolicyEngine {
    /// 创建密码策略引擎。
    ///
    /// # 参数
    /// - `rules`: 规则列表（按顺序执行）
    /// - `mode`: 错误返回模式
    pub fn new(rules: Vec<Box<dyn PasswordPolicyRule>>, mode: ErrorMode) -> Self {
        Self {
            rules,
            mode,
            #[cfg(feature = "metrics-prometheus")]
            metrics: None,
        }
    }

    /// 注入账号安全指标（builder 模式，需启用 `metrics-prometheus` feature）。
    ///
    /// 注入后 `validate` 对每条规则计时，调用 `observe_policy_validate(rule.name(), duration)`。
    /// 未注入时校验逻辑不变，仅不记录指标。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::account::metrics::AccountMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 校验密码是否符合所有规则。
    ///
    /// # 参数
    /// - `ctx`: 策略上下文
    /// - `password`: 待校验密码
    ///
    /// # 返回
    /// - `Ok(())`: 所有规则通过（或空规则集）
    /// - `Err(Vec<PolicyError>)`: 规则失败
    ///   - `FirstError` 模式：`Vec` 含 1 个元素（首条失败规则）
    ///   - `AllErrors` 模式：`Vec` 含所有失败规则的错误
    pub fn validate(&self, ctx: &PolicyContext, password: &str) -> Result<(), Vec<PolicyError>> {
        let mut errors = Vec::new();
        for rule in &self.rules {
            #[cfg(feature = "metrics-prometheus")]
            let start = std::time::Instant::now();
            let result = rule.validate(ctx, password);
            #[cfg(feature = "metrics-prometheus")]
            if let Some(metrics) = &self.metrics {
                metrics.observe_policy_validate(rule.name(), start.elapsed());
            }
            match result {
                Ok(()) => {},
                Err(e) => match self.mode {
                    ErrorMode::FirstError => return Err(vec![e]),
                    ErrorMode::AllErrors => errors.push(e),
                },
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
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
}
