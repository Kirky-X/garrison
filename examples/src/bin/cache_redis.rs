//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! cache_redis binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::infrastructure::cache_redis::run()
        .await
        .unwrap();
}
