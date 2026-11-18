// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 风险模型：风险等级、信号、原因、评估结果与评估上下文（`risk-adaptive-auth` feature 门控）。

use crate::strategy::alert::{AnomalyType, SecurityAlertEvent};
use serde::{Deserialize, Serialize};

/// 风险等级：四级有序，便于阈值比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    /// 无风险信号。
    Low,
    /// 需关注但不处置。
    Medium,
    /// 需二次验证。
    High,
    /// 需临时锁定。
    Critical,
}

/// 风险信号：五类既有异常信号 + 登录失败突发（由失败计数派生）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskSignal {
    /// IP 地址变化。
    IpChanged,
    /// 设备指纹变化。
    DeviceChanged,
    /// 地理位置跳跃。
    GeoJump,
    /// 快速连续登录。
    RapidSuccessiveLogin,
    /// 会话劫持疑似。
    SessionHijackSuspected,
    /// 窗口内登录失败突发。
    LoginFailureBurst,
}

impl From<&AnomalyType> for RiskSignal {
    fn from(anomaly: &AnomalyType) -> Self {
        match anomaly {
            AnomalyType::IpChanged => Self::IpChanged,
            AnomalyType::DeviceChanged => Self::DeviceChanged,
            AnomalyType::GeoJump => Self::GeoJump,
            AnomalyType::RapidSuccessiveLogin => Self::RapidSuccessiveLogin,
            AnomalyType::SessionHijackSuspected => Self::SessionHijackSuspected,
        }
    }
}

/// 单条风险原因：`detail` 不含 token 全文与 IP 全文（掩码纪律同审计事件）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReason {
    /// 触发的信号。
    pub signal: RiskSignal,
    /// 掩码后的详情（不含 token/IP 全文）。
    pub detail: String,
}

/// 结构化风险评估结果（可解释、可序列化进审计/后续 HTTP 拒绝载荷）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// 风险等级。
    pub level: RiskLevel,
    /// 加权得分。
    pub score: u32,
    /// 评分依据（可解释原因列表）。
    pub reasons: Vec<RiskReason>,
}

/// 评估上下文：既有检测器事件 + 登录失败窗口计数。
pub struct RiskContext {
    /// 登录主体标识。
    pub login_id: String,
    /// 设备标识。
    pub device_id: String,
    /// 脱敏后的登录 IP（可选）。
    pub ip: Option<String>,
    /// 检测器输出的告警事件列表。
    pub events: Vec<SecurityAlertEvent>,
    /// 窗口内登录失败次数（account-lockout 未启用时为 0）。
    pub recent_failure_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_type_converts_to_risk_signal_losslessly() {
        let cases: [(AnomalyType, RiskSignal); 5] = [
            (AnomalyType::IpChanged, RiskSignal::IpChanged),
            (AnomalyType::DeviceChanged, RiskSignal::DeviceChanged),
            (AnomalyType::GeoJump, RiskSignal::GeoJump),
            (
                AnomalyType::RapidSuccessiveLogin,
                RiskSignal::RapidSuccessiveLogin,
            ),
            (
                AnomalyType::SessionHijackSuspected,
                RiskSignal::SessionHijackSuspected,
            ),
        ];
        for (anomaly, expected) in cases {
            let signal = RiskSignal::from(&anomaly);
            assert_eq!(signal, expected);
            assert_eq!(
                serde_json::to_string(&signal).unwrap(),
                format!("\"{}\"", signal_name(&signal))
            );
        }
    }

    fn signal_name(signal: &RiskSignal) -> &'static str {
        match signal {
            RiskSignal::IpChanged => "IpChanged",
            RiskSignal::DeviceChanged => "DeviceChanged",
            RiskSignal::GeoJump => "GeoJump",
            RiskSignal::RapidSuccessiveLogin => "RapidSuccessiveLogin",
            RiskSignal::SessionHijackSuspected => "SessionHijackSuspected",
            RiskSignal::LoginFailureBurst => "LoginFailureBurst",
        }
    }

    #[test]
    fn risk_assessment_serde_roundtrip_preserves_fields() {
        let assessment = RiskAssessment {
            level: RiskLevel::High,
            score: 75,
            reasons: vec![RiskReason {
                signal: RiskSignal::GeoJump,
                detail: "geo-jump-detected".to_string(),
            }],
        };
        let json = serde_json::to_string(&assessment).unwrap();
        let back: RiskAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.level, RiskLevel::High);
        assert_eq!(back.score, 75);
        assert_eq!(back.reasons.len(), 1);
        assert_eq!(back.reasons[0].signal, RiskSignal::GeoJump);
        assert_eq!(back.reasons[0].detail, "geo-jump-detected");
    }
}
