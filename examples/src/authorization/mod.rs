//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 授权 / 权限 / 策略示例模块。

#[cfg(feature = "abac")]
pub mod abac_policy;
pub mod permission_check;
#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod strategy_firewall;
#[cfg(feature = "cache-memory")]
pub mod strategy_registry;
pub mod token_styles;
