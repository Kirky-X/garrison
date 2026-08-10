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
