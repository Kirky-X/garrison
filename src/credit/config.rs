//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量配置。
//!
//! 提供 `CreditConfig`（主配置）与 `CreditAlertConfig`（告警配置）。

use serde::{Deserialize, Serialize};

use super::cycle::CreditCycle;
use super::schedule::CreditSchedule;

/// Credit 计量配置。
///
/// 控制 credit 计量引擎的行为：配额上限、周期模式、资源权重、告警阈值。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditConfig {
    /// 每租户每月 credit 配额（0 = 不限制）。
    pub credit_limit: u64,
    /// 配额周期模式。
    pub cycle: CreditCycle,
    /// 资源权重表。
    pub schedule: CreditSchedule,
    /// 多级告警阈值（百分比，如 [80, 90, 100]），必须升序排列。
    pub alert_thresholds: Vec<u8>,
    /// 是否启用 SQL 流水持久化（false = 仅 KV 热数据）。
    pub persist_history: bool,
}

impl Default for CreditConfig {
    fn default() -> Self {
        Self {
            credit_limit: 10_000,
            cycle: CreditCycle::Fixed { day_of_month: 1 },
            schedule: CreditSchedule::default(),
            alert_thresholds: vec![80, 90, 100],
            persist_history: false,
        }
    }
}

impl CreditConfig {
    /// 校验配置合法性。
    ///
    /// # 校验规则
    /// - `alert_thresholds` 非空
    /// - 每个值 ∈ [0, 100]（百分比语义）
    /// - 严格升序排列
    ///
    /// # 错误
    /// - 违反以上任一规则时返回描述性错误消息。
    pub fn validate(&self) -> Result<(), String> {
        if self.alert_thresholds.is_empty() {
            return Err("alert_thresholds 不能为空".to_string());
        }
        for (i, &t) in self.alert_thresholds.iter().enumerate() {
            if t > 100 {
                return Err(format!("alert_thresholds[{}] = {} 超出范围 [0, 100]", i, t));
            }
            if i > 0 && t <= self.alert_thresholds[i - 1] {
                return Err(format!(
                    "alert_thresholds 必须严格升序: [{}] = {} <= [{}] = {}",
                    i,
                    t,
                    i - 1,
                    self.alert_thresholds[i - 1]
                ));
            }
        }
        Ok(())
    }
}

/// Credit 告警配置。
///
/// 独立于 `CreditConfig`，允许复用告警策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditAlertConfig {
    /// 多级告警阈值（百分比，如 [80, 90, 100]），必须升序排列。
    pub thresholds: Vec<u8>,
    /// 同一阈值的最小触发间隔（秒），避免重复广播。
    pub cooldown_seconds: u64,
}

impl Default for CreditAlertConfig {
    fn default() -> Self {
        Self {
            thresholds: vec![80, 90, 100],
            cooldown_seconds: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CreditConfig::default() 各字段取默认值。
    #[test]
    fn test_credit_config_default_values() {
        let config = CreditConfig::default();
        assert_eq!(config.credit_limit, 10_000);
        assert_eq!(config.cycle, CreditCycle::Fixed { day_of_month: 1 });
        assert_eq!(config.schedule.default_weight(), 1);
        assert_eq!(config.alert_thresholds, vec![80, 90, 100]);
        assert!(!config.persist_history);
    }

    /// validate() 对合法配置返回 Ok（含边界值 0 与 100）。
    #[test]
    fn test_validate_ok_with_boundary_values() {
        let config = CreditConfig {
            alert_thresholds: vec![0, 50, 100],
            ..CreditConfig::default()
        };
        assert!(config.validate().is_ok(), "0 与 100 均在合法范围");
    }

    /// validate() 对空 alert_thresholds 返回 Err。
    #[test]
    fn test_validate_empty_thresholds_err() {
        let config = CreditConfig {
            alert_thresholds: vec![],
            ..CreditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("不能为空"), "实际错误: {}", err);
    }

    /// validate() 对超过 100 的阈值返回 Err（>100 边界）。
    #[test]
    fn test_validate_threshold_over_100_err() {
        let config = CreditConfig {
            alert_thresholds: vec![50, 101],
            ..CreditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("超出范围") && err.contains("101"),
            "实际错误: {}",
            err
        );
    }

    /// validate() 对相等阈值（非严格升序）返回 Err。
    #[test]
    fn test_validate_equal_thresholds_err() {
        let config = CreditConfig {
            alert_thresholds: vec![80, 80],
            ..CreditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("严格升序"), "实际错误: {}", err);
    }

    /// validate() 对降序阈值返回 Err。
    #[test]
    fn test_validate_descending_thresholds_err() {
        let config = CreditConfig {
            alert_thresholds: vec![90, 80],
            ..CreditConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("严格升序"), "实际错误: {}", err);
    }

    /// validate() 对默认阈值 [80, 90, 100] 返回 Ok。
    #[test]
    fn test_validate_default_config_ok() {
        assert!(CreditConfig::default().validate().is_ok());
    }

    /// CreditConfig serde 往返（TOML）保持字段一致。
    #[test]
    fn test_credit_config_serde_roundtrip() {
        let mut schedule = CreditSchedule::with_default(2);
        schedule.insert("sms", 5);
        let config = CreditConfig {
            credit_limit: u64::MAX,
            cycle: CreditCycle::Rolling { days: 7 },
            schedule,
            alert_thresholds: vec![10, 20],
            persist_history: true,
        };
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: CreditConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.credit_limit, u64::MAX);
        assert_eq!(deserialized.cycle, CreditCycle::Rolling { days: 7 });
        assert_eq!(deserialized.schedule.weight_for("sms"), 5);
        assert_eq!(deserialized.alert_thresholds, vec![10, 20]);
        assert!(deserialized.persist_history);
    }

    /// CreditAlertConfig::default() 各字段取默认值。
    #[test]
    fn test_credit_alert_config_default_values() {
        let alert = CreditAlertConfig::default();
        assert_eq!(alert.thresholds, vec![80, 90, 100]);
        assert_eq!(alert.cooldown_seconds, 3600);
    }

    /// CreditAlertConfig serde 往返（TOML）保持字段一致。
    #[test]
    fn test_credit_alert_config_serde_roundtrip() {
        let alert = CreditAlertConfig {
            thresholds: vec![50],
            cooldown_seconds: 0,
        };
        let serialized = toml::to_string(&alert).unwrap();
        let deserialized: CreditAlertConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.thresholds, vec![50]);
        assert_eq!(deserialized.cooldown_seconds, 0);
    }

    /// CreditConfig 的 Debug 输出包含类型名。
    #[test]
    fn test_credit_config_debug() {
        let debug = format!("{:?}", CreditConfig::default());
        assert!(debug.contains("CreditConfig"), "实际: {}", debug);
    }

    /// CreditAlertConfig 的 Debug 输出包含类型名。
    #[test]
    fn test_credit_alert_config_debug() {
        let debug = format!("{:?}", CreditAlertConfig::default());
        assert!(debug.contains("CreditAlertConfig"), "实际: {}", debug);
    }
}
