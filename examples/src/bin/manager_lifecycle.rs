//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

#[tokio::main]
async fn main() {
    garrison_examples::extension::manager_lifecycle::run()
        .await
        .unwrap();
}
