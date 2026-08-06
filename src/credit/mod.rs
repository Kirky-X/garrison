//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量模块（`credit-metering` feature）。
//!
//! 提供 team-level credit 消费计量能力：
//! - `CreditMeter`：核心计量引擎（consume / query / reset API）
//! - `CreditCycle`：配额周期模型（Fixed 自然月 / Rolling 滚动窗口）
//! - `CreditSchedule`：resource → credit_weight 映射
//! - `CreditConfig` / `CreditAlertConfig`：配置
//! - `CreditMeteringListener`：可选事件监听器（Login 自动扣减）
//!
//! # 与现有模块的关系
//!
//! - `limiteron::quota`：per-user 限流配额（独立，不交互）
//! - `listener::audit`：审计日志（CreditConsumed / CreditAlert 事件可被审计监听器捕获）
//! - `context::tenant`：tenant_id 来源（CreditMeter 按 tenant 维度计量）

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

#[cfg(feature = "listener")]
pub use listener::CreditMeteringListener;
