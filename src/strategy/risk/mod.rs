// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 风险自适应认证决策层（`risk-adaptive-auth` feature 门控）。
//!
//! 把既有异常检测信号聚合为结构化 [`RiskAssessment`]，经策略评分与动作映射后
//! 在登录流程内同步处置；未注入引擎时行为与基线一致。

mod action;
mod model;
mod policy;

pub use action::{DefaultRiskActionResolver, RiskAction, RiskActionResolver};
pub use model::{RiskAssessment, RiskContext, RiskLevel, RiskReason, RiskSignal};
pub use policy::{RiskPolicy, RiskThresholds, RiskWeights, ThresholdRiskPolicy};

use std::sync::Arc;

/// 风险引擎：聚合策略评分与动作映射；策略失败 fail-open 为 `NotifyOnly`。
pub struct RiskEngine {
    policy: Arc<dyn RiskPolicy>,
    resolver: Arc<dyn RiskActionResolver>,
    /// 二次验证强制因子（默认 `otp`）。
    pub step_up_factor: String,
    /// 临时锁定时长（秒，默认 300）。
    pub lock_ttl_secs: u64,
}

impl RiskEngine {
    /// 用默认 resolver 构造引擎。
    pub fn new(policy: Arc<dyn RiskPolicy>) -> Self {
        Self::with_resolver(policy, Arc::new(DefaultRiskActionResolver))
    }

    /// 自定义 resolver 构造引擎（下游显式启用 `RequireReauthentication` 等动作）。
    pub fn with_resolver(
        policy: Arc<dyn RiskPolicy>,
        resolver: Arc<dyn RiskActionResolver>,
    ) -> Self {
        Self {
            policy,
            resolver,
            step_up_factor: "otp".to_string(),
            lock_ttl_secs: 300,
        }
    }

    /// 评估风险并映射动作；策略失败时 fail-open 为 `NotifyOnly` 并 warn，不返回错误、不 panic。
    pub async fn evaluate(&self, ctx: &RiskContext) -> RiskAction {
        match self.assess(ctx).await {
            Some(assessment) => self.resolver.resolve(&assessment),
            None => RiskAction::NotifyOnly,
        }
    }

    /// 返回结构化评估；策略失败时 warn 并返回 `None`（fail-open）。
    pub async fn assess(&self, ctx: &RiskContext) -> Option<RiskAssessment> {
        match self.policy.assess(ctx).await {
            Ok(assessment) => Some(assessment),
            Err(e) => {
                tracing::warn!(error = %e, "{}", crate::i18n::translate_detail(
                    "logs-riskpolicy-assess-failed-fail-open-to-notifyonly", &[]
                ));
                None
            },
        }
    }

    /// 用本引擎的 resolver 把评估映射为动作（供需同时拿到评估与动作的调用方使用）。
    pub fn resolve(&self, assessment: &RiskAssessment) -> RiskAction {
        self.resolver.resolve(assessment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{GarrisonError, GarrisonResult};
    use async_trait::async_trait;

    struct FailingPolicy;
    #[async_trait]
    impl RiskPolicy for FailingPolicy {
        async fn assess(&self, _ctx: &RiskContext) -> GarrisonResult<RiskAssessment> {
            Err(GarrisonError::Config("forced-policy-failure".to_string()))
        }
    }

    #[tokio::test]
    async fn engine_evaluate_fails_open_on_policy_error() {
        let engine = RiskEngine::new(Arc::new(FailingPolicy));
        let ctx = RiskContext {
            login_id: "user".to_string(),
            device_id: "dev".to_string(),
            ip: None,
            events: Vec::new(),
            recent_failure_count: 0,
        };
        let action = engine.evaluate(&ctx).await;
        assert_eq!(action, RiskAction::NotifyOnly);
    }

    #[tokio::test]
    async fn engine_evaluate_maps_normal_assessment() {
        let engine = RiskEngine::new(Arc::new(ThresholdRiskPolicy::owasp_baseline()));
        let ctx = RiskContext {
            login_id: "user".to_string(),
            device_id: "dev".to_string(),
            ip: None,
            events: Vec::new(),
            recent_failure_count: 0,
        };
        assert_eq!(engine.evaluate(&ctx).await, RiskAction::Allow);
    }
}
