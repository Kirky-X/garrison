// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 风险评分策略（`risk-adaptive-auth` feature 门控）。
//!
//! `RiskPolicy` 为下游可实现的 async trait；默认 `ThresholdRiskPolicy` 为确定性加权阈值评分，
//! 无随机性、无网络调用。构造后权重/阈值不可变，调整须重建实例。

use super::model::{RiskAssessment, RiskContext, RiskLevel, RiskReason, RiskSignal};
use crate::error::GarrisonResult;
use crate::strategy::alert::SecurityAlertEvent;
use async_trait::async_trait;

/// 可插拔风险评分策略（下游可实现自有模型评分）。
#[async_trait]
pub trait RiskPolicy: Send + Sync {
    /// 根据上下文评估风险，返回结构化结果。
    async fn assess(&self, ctx: &RiskContext) -> GarrisonResult<RiskAssessment>;
}

/// 各信号权重（构造后不可变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskWeights {
    /// IP 变化信号权重。
    pub ip_changed: u32,
    /// 设备变化信号权重。
    pub device_changed: u32,
    /// 地理跳跃信号权重。
    pub geo_jump: u32,
    /// 快速连续登录信号权重。
    pub rapid_successive_login: u32,
    /// 会话劫持疑似信号权重。
    pub session_hijack_suspected: u32,
    /// 登录失败突发信号权重。
    pub login_failure_burst: u32,
}

/// 分级阈值下限（构造后不可变）：score ≥ 对应值即进入该级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskThresholds {
    /// 进入 Medium 的分数下限。
    pub medium: u32,
    /// 进入 High 的分数下限。
    pub high: u32,
    /// 进入 Critical 的分数下限。
    pub critical: u32,
}

/// 确定性加权阈值策略：信号加权求和 → 按阈值分级。
#[derive(Debug, Clone, Copy)]
pub struct ThresholdRiskPolicy {
    weights: RiskWeights,
    thresholds: RiskThresholds,
    /// 触发 `LoginFailureBurst` 的失败次数下限（0 = 不合成该信号）。
    failure_burst_min: u32,
}

impl ThresholdRiskPolicy {
    /// 自定义权重/阈值构造（构造后不可变）。
    pub fn new(weights: RiskWeights, thresholds: RiskThresholds, failure_burst_min: u32) -> Self {
        Self {
            weights,
            thresholds,
            failure_burst_min,
        }
    }

    /// OWASP 保守基线：GeoJump / SessionHijack 高权重，单 IP 变化低权重。
    pub fn owasp_baseline() -> Self {
        Self {
            weights: RiskWeights {
                ip_changed: 10,
                device_changed: 15,
                geo_jump: 35,
                rapid_successive_login: 30,
                session_hijack_suspected: 40,
                login_failure_burst: 20,
            },
            thresholds: RiskThresholds {
                medium: 25,
                high: 60,
                critical: 100,
            },
            failure_burst_min: 5,
        }
    }

    fn weight_of(&self, signal: &RiskSignal) -> u32 {
        match signal {
            RiskSignal::IpChanged => self.weights.ip_changed,
            RiskSignal::DeviceChanged => self.weights.device_changed,
            RiskSignal::GeoJump => self.weights.geo_jump,
            RiskSignal::RapidSuccessiveLogin => self.weights.rapid_successive_login,
            RiskSignal::SessionHijackSuspected => self.weights.session_hijack_suspected,
            RiskSignal::LoginFailureBurst => self.weights.login_failure_burst,
        }
    }

    fn level_of(&self, score: u32) -> RiskLevel {
        if score >= self.thresholds.critical {
            RiskLevel::Critical
        } else if score >= self.thresholds.high {
            RiskLevel::High
        } else if score >= self.thresholds.medium {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

#[async_trait]
impl RiskPolicy for ThresholdRiskPolicy {
    async fn assess(&self, ctx: &RiskContext) -> GarrisonResult<RiskAssessment> {
        let mut signals: Vec<RiskSignal> = Vec::new();
        for event in &ctx.events {
            match event {
                SecurityAlertEvent::AnomalyLogin { anomaly_type, .. } => {
                    signals.push(RiskSignal::from(anomaly_type));
                },
                SecurityAlertEvent::NewDeviceLogin { .. } => {
                    signals.push(RiskSignal::DeviceChanged);
                },
                _ => {},
            }
        }
        if self.failure_burst_min > 0 && ctx.recent_failure_count >= self.failure_burst_min {
            signals.push(RiskSignal::LoginFailureBurst);
        }

        let mut score = 0u32;
        let mut reasons = Vec::with_capacity(signals.len());
        for signal in signals {
            score = score.saturating_add(self.weight_of(&signal));
            reasons.push(RiskReason {
                signal,
                detail: "risk-signal-observed".to_string(),
            });
        }
        Ok(RiskAssessment {
            level: self.level_of(score),
            score,
            reasons,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::alert::AnomalyType;

    fn ctx_with(anomalies: &[AnomalyType], failures: u32) -> RiskContext {
        let events = anomalies
            .iter()
            .map(|a| SecurityAlertEvent::AnomalyLogin {
                login_id: "user".to_string(),
                anomaly_type: a.clone(),
                detail: "detail".to_string(),
                trace_id: "trace".to_string(),
            })
            .collect();
        RiskContext {
            login_id: "user".to_string(),
            device_id: "dev".to_string(),
            ip: None,
            events,
            recent_failure_count: failures,
        }
    }

    #[tokio::test]
    async fn empty_events_assess_low() {
        let result = ThresholdRiskPolicy::owasp_baseline()
            .assess(&ctx_with(&[], 0))
            .await
            .unwrap();
        assert_eq!(result.level, RiskLevel::Low);
        assert_eq!(result.score, 0);
        assert!(result.reasons.is_empty());
    }

    #[tokio::test]
    async fn single_ip_changed_is_low() {
        let result = ThresholdRiskPolicy::owasp_baseline()
            .assess(&ctx_with(&[AnomalyType::IpChanged], 0))
            .await
            .unwrap();
        assert!(matches!(result.level, RiskLevel::Low | RiskLevel::Medium));
    }

    #[tokio::test]
    async fn geojump_plus_rapid_login_reaches_high() {
        let result = ThresholdRiskPolicy::owasp_baseline()
            .assess(&ctx_with(
                &[AnomalyType::GeoJump, AnomalyType::RapidSuccessiveLogin],
                0,
            ))
            .await
            .unwrap();
        assert_eq!(result.level, RiskLevel::High);
    }

    #[tokio::test]
    async fn five_signals_reach_critical() {
        let result = ThresholdRiskPolicy::owasp_baseline()
            .assess(&ctx_with(
                &[
                    AnomalyType::IpChanged,
                    AnomalyType::DeviceChanged,
                    AnomalyType::GeoJump,
                    AnomalyType::RapidSuccessiveLogin,
                    AnomalyType::SessionHijackSuspected,
                ],
                0,
            ))
            .await
            .unwrap();
        assert_eq!(result.level, RiskLevel::Critical);
    }

    #[tokio::test]
    async fn assessment_is_deterministic() {
        let policy = ThresholdRiskPolicy::owasp_baseline();
        let ctx = ctx_with(&[AnomalyType::GeoJump], 5);
        let a = policy.assess(&ctx).await.unwrap();
        let b = policy.assess(&ctx).await.unwrap();
        assert_eq!(a.level, b.level);
        assert_eq!(a.score, b.score);
        assert_eq!(
            a.reasons.iter().map(|r| &r.signal).collect::<Vec<_>>(),
            b.reasons.iter().map(|r| &r.signal).collect::<Vec<_>>()
        );
    }
}
