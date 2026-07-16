//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! [`PasswordPolicyEngine`] 实现。
//!
//! 引擎按 [`ErrorMode`] 执行规则校验，支持 `FirstError`（短路）/ `AllErrors`（收集）两种模式。
//! 实现自父模块迁移（规则 25：mod.rs 接口隔离）。

#[cfg(feature = "metrics-prometheus")]
use std::sync::Arc;

use super::{ErrorMode, PasswordPolicyEngine, PasswordPolicyRule, PolicyContext, PolicyError};

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
