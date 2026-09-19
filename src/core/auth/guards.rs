// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `SwitchToGuard` 内置实现：`DenyAllSwitchToGuard`。
//!
//! 本文件仅承载 impl 块，struct 声明与 trait 定义保留在 `mod.rs`（mod.rs 接口隔离约定）。

use async_trait::async_trait;

use super::{DenyAllSwitchToGuard, SwitchToGuard};
use crate::error::{GarrisonError, GarrisonResult};

#[async_trait]
impl SwitchToGuard for DenyAllSwitchToGuard {
    async fn check(&self, _original: &str, _target: &str) -> GarrisonResult<()> {
        Err(GarrisonError::NotPermission(
            "core-switch-to-denied::".to_string(),
        ))
    }
}
