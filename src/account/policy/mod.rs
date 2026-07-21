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
//! - 规则参数由构造器注入（v0.6.5 支持 `GarrisonConfig` 加载）

pub mod engine;
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
/// use garrison::account::policy::{PasswordPolicyRule, PolicyContext, PolicyError};
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
/// use garrison::account::policy::{ErrorMode, PasswordPolicyEngine, PolicyContext};
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

#[cfg(test)]
mod tests;
