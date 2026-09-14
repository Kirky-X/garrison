//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

#[tokio::main]
async fn main() {
    garrison_examples::apikey::apikey_namespace::run()
        .await
        .unwrap();
}
