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
