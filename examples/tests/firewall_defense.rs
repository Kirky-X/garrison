//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 防火墙防护示例集成测试。

#![cfg(all(
    feature = "firewall-bruteforce",
    feature = "firewall-ratelimit",
    feature = "firewall-ddos",
    feature = "cache-memory"
))]

#[tokio::test(flavor = "multi_thread")]
async fn firewall_defense_runs_successfully() {
    garrison_examples::authorization::firewall_defense::run()
        .await
        .expect("firewall_defense 示例应成功执行");
}
