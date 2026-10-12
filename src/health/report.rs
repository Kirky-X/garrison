// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `HealthReport` 实现块。

use super::{HealthReport, HealthStatus};

impl HealthReport {
    /// 创建空报告（无检查项），整体状态为 Healthy。
    ///
    /// 「空 registry → Healthy」是有意语义：readiness 反映已注册依赖项的就绪状态，
    /// 未注册检查项时无可失败对象；调用方若需要「无检查项即不就绪」的语义，应在注册
    /// 至少一个关键依赖检查后再暴露 readiness 端点。
    pub fn empty() -> Self {
        Self {
            overall: HealthStatus::Healthy,
            checks: Vec::new(),
        }
    }
}
