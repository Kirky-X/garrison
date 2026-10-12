// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! [`PasswordPolicyEngine`] 实现：按 [`ErrorMode`] 执行规则校验，`FirstError` 短路、`AllErrors` 收集。

#[cfg(feature = "metrics-prometheus")]
use std::sync::Arc;

use super::{ErrorMode, PasswordPolicyEngine, PasswordPolicyRule, PolicyContext, PolicyError};

impl PasswordPolicyEngine {
    /// 创建密码策略引擎：`rules` 按顺序执行，`mode` 控制错误返回模式。
    pub fn new(rules: Vec<Box<dyn PasswordPolicyRule>>, mode: ErrorMode) -> Self {
        Self {
            rules,
            mode,
            #[cfg(feature = "metrics-prometheus")]
            metrics: None,
        }
    }

    /// 注入指标（builder，需 `metrics-prometheus` feature）：注入后 `validate` 对每条规则计时并
    /// 调用 `observe_policy_validate(rule.name(), duration)`；未注入时校验逻辑不变，仅不记录指标。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::account::metrics::AccountMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 校验密码是否符合所有规则。
    ///
    /// `FirstError` 模式返回首个失败规则的错误（`Vec` 单元素），`AllErrors` 收集全部失败；
    /// 规则集为空视为通过。
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
