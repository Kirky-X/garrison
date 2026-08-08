//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SwitchToGuard` 内置实现：`DenyAllSwitchToGuard`。
//!
//! 本文件仅承载 impl 块，struct 声明与 trait 定义保留在 `mod.rs`（规则 25 mod.rs 接口隔离）。

use async_trait::async_trait;

use super::{DenyAllSwitchToGuard, SwitchToGuard};
use crate::error::{GarrisonError, GarrisonResult};

#[async_trait]
impl SwitchToGuard for DenyAllSwitchToGuard {
    async fn check(&self, _original: &str, _target: &str) -> GarrisonResult<()> {
        Err(GarrisonError::NotPermission(
            "switch_to 被拒绝：未配置 SwitchToGuard，默认 deny-all".to_string(),
        ))
    }
}
