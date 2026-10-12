// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Credit 计量模块（`credit-metering` feature）：`CreditMeter` 为计量引擎（按 tenant 维度，
//! tenant_id 来源为 `context::tenant`），`CreditCycle` 决定配额周期，`CreditSchedule`
//! 提供资源权重，`ActivityWriteThrottle` 默认启用做活跃度写路径节流，
//! `CreditMeteringListener` 为可选事件监听器（Login 自动扣减，CreditConsumed /
//! CreditAlert 事件可被 `listener::audit` 审计）。
//!
//! 消费语义与已知限制：`consume_credit` 的 credits = cost × weight 经 `checked_mul`
//! 计算，溢出返回错误（不静默回绕），被拒绝的请求不消耗配额（并发交错超限时回滚
//! 本次扣减）；`CreditMeterStorage::incr_consumed` 在 `GarrisonDao` 无 `INCRBY`
//! 语义下按 credits 循环单步 incr，整体非原子且为 N 次串行 DAO 往返（详见
//! `credit::storage`）；persist_history 默认经 `ActivityWriteThrottle` 节流聚合
//! （同 key 窗口内仅首次快照落库、进程退出不持久化），逐笔对账用
//! `CreditMeter::without_activity_throttle` 关闭（详见 `credit::throttle`）。

/// Credit 配额周期模型。
pub mod cycle;

/// Credit 消费权重表。
pub mod schedule;

/// Credit 计量配置。
pub mod config;

/// Credit 计量错误类型与结果类型。
pub mod error;

/// Credit KV 热数据存储层。
pub mod storage;

/// 高频活跃度写路径节流聚合器。
pub mod throttle;

/// Credit 计量引擎。
pub mod meter;

/// Credit 计量 Prometheus 指标。
pub mod metrics;

/// Credit 计量监听器（可选自动扣减）。
#[cfg(feature = "listener")]
pub mod listener;

// Re-export 核心类型
pub use config::{CreditAlertConfig, CreditConfig};
pub use cycle::CreditCycle;
pub use error::{
    CreditConsumeResult, CreditConsumptionRecord, CreditError, CreditResult, CreditUsage,
};
pub use meter::CreditMeter;
pub use metrics::CreditMetrics;
pub use schedule::CreditSchedule;
pub use storage::CreditMeterStorage;
pub use throttle::ActivityWriteThrottle;

#[cfg(feature = "listener")]
pub use listener::CreditMeteringListener;
