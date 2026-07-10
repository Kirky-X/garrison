//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

#[tokio::main]
async fn main() {
    bulwark_examples::authorization::strategy_firewall::run()
        .await
        .unwrap();
}
