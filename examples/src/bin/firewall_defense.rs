//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 防火墙防护完整流程示例二进制入口。
//!
//! ```sh
//! cargo run -p garrison-examples --bin firewall_defense --features "firewall-bruteforce firewall-ratelimit firewall-ddos cache-memory"
//! ```

#[tokio::main]
async fn main() {
    garrison_examples::authorization::firewall_defense::run()
        .await
        .expect("firewall_defense 示例执行失败");
}
