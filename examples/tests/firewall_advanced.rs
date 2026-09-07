//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! firewall_advanced 示例测试（firewall-anomalous + firewall-geoip + firewall-waf + cache-memory + web-axum feature）。
//!
//! 验证 run() 完整执行（内部演示异地登录检测/GeoIP 拦截/WAF 校验）。

#![cfg(all(
    feature = "firewall-anomalous",
    feature = "firewall-geoip",
    feature = "firewall-waf",
    feature = "cache-memory",
    feature = "web-axum"
))]

use garrison_examples::authorization::firewall_advanced;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    firewall_advanced::run().await.unwrap();
}
