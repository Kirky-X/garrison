// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 风险自适应认证决策层（`risk-adaptive-auth` feature 门控）。
//!
//! 把既有异常检测信号聚合为结构化 [`RiskAssessment`]，经策略评分与动作映射后
//! 在登录流程内同步处置；未注入引擎时行为与基线一致。

mod model;

pub use model::{RiskAssessment, RiskContext, RiskLevel, RiskReason, RiskSignal};
