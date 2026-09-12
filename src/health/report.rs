//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HealthReport` 实现块。
//!
//! 从 `registry.rs` 拆分而出（规则 25：单一职责）。

use super::{HealthReport, HealthStatus};

impl HealthReport {
    /// 创建空报告（无检查项），整体状态为 Healthy。
    ///
    /// # 语义说明
    ///
    /// 「空 registry → Healthy」是**有意为之**的语义：readiness 反映的是
    /// 「已注册依赖项的就绪状态」，未注册任何检查项时无可失败对象，视为
    /// Healthy（进程自身存活即可对外服务）。调用方若需要「无检查项即不就绪」
    /// 的严格语义，应在注册至少一个关键依赖检查后再暴露 readiness 端点。
    pub fn empty() -> Self {
        Self {
            overall: HealthStatus::Healthy,
            checks: Vec::new(),
        }
    }
}
