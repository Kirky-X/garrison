//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! cache_redis binary 入口。

#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::cache_redis::run()
        .await
        .unwrap();
}
