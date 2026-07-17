//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HealthReport` 实现块。
//!
//! 从 `registry.rs` 拆分而出（规则 25：单一职责）。

use super::{HealthReport, HealthStatus};

impl HealthReport {
    /// 创建空报告（无检查项），整体状态为 Healthy。
    pub fn empty() -> Self {
        Self {
            overall: HealthStatus::Healthy,
            checks: Vec::new(),
        }
    }
}
