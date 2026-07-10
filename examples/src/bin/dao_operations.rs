//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::dao_operations::run()
        .await
        .unwrap();
}
