//! 授权 / 权限 / 策略示例模块。

pub mod permission_check;
#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod strategy_firewall;
#[cfg(feature = "cache-memory")]
pub mod strategy_registry;
pub mod token_styles;
