//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量错误类型。
//!
//! 提供 `CreditError` 枚举与 `CreditResult` 类型别名。

use std::fmt;

/// Credit 计量错误类型。
#[derive(Debug)]
pub enum CreditError {
    /// Credit 不足（配额耗尽）。
    Insufficient {
        /// 租户 ID。
        tenant_id: i64,
        /// 请求的 credit 数。
        requested: u64,
        /// 剩余 credit 数。
        remaining: u64,
    },
    /// 配置无效。
    ConfigInvalid(String),
    /// DAO 层错误。
    Dao(String),
    /// 周期已过期（内部状态，触发重置后清除）。
    CycleExpired,
}

impl fmt::Display for CreditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreditError::Insufficient {
                tenant_id,
                requested,
                remaining,
            } => write!(
                f,
                "credit-insufficient::tenant:{}::requested:{}::remaining:{}",
                tenant_id, requested, remaining
            ),
            CreditError::ConfigInvalid(msg) => write!(f, "credit-config-invalid::{}", msg),
            CreditError::Dao(msg) => write!(f, "credit-dao::{}", msg),
            CreditError::CycleExpired => write!(f, "credit-cycle-expired"),
        }
    }
}

impl std::error::Error for CreditError {}

/// Credit 计量 Result 类型别名。
pub type CreditResult<T> = Result<T, CreditError>;

/// Credit 消费结果。
#[derive(Debug, Clone)]
pub struct CreditConsumeResult {
    /// 是否允许消费（未超限）。
    pub allowed: bool,
    /// 本次消费消耗的 credit 数（cost * weight）。
    pub consumed_credits: u64,
    /// 当前周期已消费总量。
    pub total_consumed: u64,
    /// 当前周期剩余 credit。
    pub remaining: u64,
    /// 当前周期使用率百分比。
    pub usage_percent: f64,
    /// 触发的告警阈值列表（空 = 无告警）。
    pub alerts_triggered: Vec<u8>,
    /// 当前周期重置时间（Unix 时间戳）。
    pub cycle_reset_at: i64,
}

/// Credit 使用情况查询结果。
#[derive(Debug, Clone)]
pub struct CreditUsage {
    /// 租户 ID。
    pub tenant_id: i64,
    /// 当前周期已消费总量。
    pub consumed: u64,
    /// 当前周期 credit 配额。
    pub limit: u64,
    /// 剩余 credit。
    pub remaining: u64,
    /// 使用率百分比。
    pub usage_percent: f64,
    /// 当前周期起始时间（Unix 时间戳）。
    pub cycle_start: i64,
    /// 当前周期重置时间（Unix 时间戳）。
    pub cycle_reset_at: i64,
    /// 周期模式。
    pub cycle: super::cycle::CreditCycle,
}

/// Credit 消费流水记录（SQL 冷数据）。
#[derive(Debug, Clone)]
pub struct CreditConsumptionRecord {
    /// 租户 ID。
    pub tenant_id: i64,
    /// 消费的资源类型。
    pub resource: String,
    /// 原始 cost（调用次数）。
    pub cost: u64,
    /// 实际消耗 credit（cost * weight）。
    pub credits: u64,
    /// 消费后当前周期累计 consumed。
    pub total_consumed: u64,
    /// 当前周期起始（Unix 时间戳）。
    pub cycle_start: i64,
    /// 消费时间（Unix 时间戳）。
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CreditError::Insufficient Display 包含关键字段。
    #[test]
    fn test_credit_error_display() {
        let err = CreditError::Insufficient {
            tenant_id: 42,
            requested: 100,
            remaining: 50,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("credit-insufficient"));
        assert!(msg.contains("42"));
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    /// CreditError::Dao Display 包含错误信息。
    #[test]
    fn test_credit_dao_error_display() {
        let err = CreditError::Dao("test-error".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("credit-dao"));
        assert!(msg.contains("test-error"));
    }

    /// CreditError::ConfigInvalid Display。
    #[test]
    fn test_credit_config_invalid_display() {
        let err = CreditError::ConfigInvalid("bad limit".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("credit-config-invalid"));
        assert!(msg.contains("bad limit"));
    }
}
