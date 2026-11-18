// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 风险处置动作与默认映射（`risk-adaptive-auth` feature 门控）。

use super::model::{RiskAssessment, RiskLevel};

/// 风险处置动作：按评估等级映射的四种可执行处置 + 放行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskAction {
    /// 放行（Low）。
    Allow,
    /// 仅广播告警，不改变登录结果（Medium / 策略失败 fail-open）。
    NotifyOnly,
    /// 要求二次验证：写 MFA 强制因子（High）。
    RequireSecondFactor,
    /// 要求重新认证：踢出当前会话（默认映射不含，须下游 resolver 显式启用）。
    RequireReauthentication,
    /// 临时锁定：`ttl_secs` 秒后自动解除（Critical）。
    TemporaryLock {
        /// 锁定时长（秒）。
        ttl_secs: u64,
    },
}

/// 可插拔动作解析器（下游可自定义等级→动作映射）。
pub trait RiskActionResolver: Send + Sync {
    /// 把评估结果映射为处置动作。
    fn resolve(&self, assessment: &RiskAssessment) -> RiskAction;
}

/// 默认保守映射：Low→Allow / Medium→NotifyOnly / High→RequireSecondFactor /
/// Critical→TemporaryLock{300}；RequireReauthentication 不进默认映射（对合法用户打扰最大）。
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRiskActionResolver;

impl RiskActionResolver for DefaultRiskActionResolver {
    fn resolve(&self, assessment: &RiskAssessment) -> RiskAction {
        match assessment.level {
            RiskLevel::Low => RiskAction::Allow,
            RiskLevel::Medium => RiskAction::NotifyOnly,
            RiskLevel::High => RiskAction::RequireSecondFactor,
            RiskLevel::Critical => RiskAction::TemporaryLock { ttl_secs: 300 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::risk::RiskReason;

    fn assessment(level: RiskLevel) -> RiskAssessment {
        RiskAssessment {
            level,
            score: 0,
            reasons: Vec::<RiskReason>::new(),
        }
    }

    #[test]
    fn default_resolver_maps_four_levels() {
        let resolver = DefaultRiskActionResolver;
        assert_eq!(
            resolver.resolve(&assessment(RiskLevel::Low)),
            RiskAction::Allow
        );
        assert_eq!(
            resolver.resolve(&assessment(RiskLevel::Medium)),
            RiskAction::NotifyOnly
        );
        assert_eq!(
            resolver.resolve(&assessment(RiskLevel::High)),
            RiskAction::RequireSecondFactor
        );
        assert_eq!(
            resolver.resolve(&assessment(RiskLevel::Critical)),
            RiskAction::TemporaryLock { ttl_secs: 300 }
        );
    }

    #[test]
    fn reauthentication_is_not_in_default_mapping() {
        let resolver = DefaultRiskActionResolver;
        for level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            assert_ne!(
                resolver.resolve(&assessment(level)),
                RiskAction::RequireReauthentication,
                "默认映射不得自动重新认证"
            );
        }
    }
}
