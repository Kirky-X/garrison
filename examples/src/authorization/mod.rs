//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 授权 / 权限 / 策略示例模块。

#[cfg(feature = "abac")]
pub mod abac_policy;
#[cfg(all(
    feature = "firewall-bruteforce",
    feature = "firewall-ratelimit",
    feature = "firewall-ddos",
    feature = "cache-memory"
))]
pub mod firewall_defense;
pub mod permission_check;
#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod strategy_firewall;
#[cfg(all(
    feature = "cache-memory",
    any(
        feature = "firewall-bruteforce",
        feature = "firewall-ratelimit",
        feature = "firewall-ddos",
        feature = "oauth2-server",
    )
))]
pub mod strategy_registry;
pub mod token_styles;
