// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! cache_redis binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::infrastructure::cache_redis::run()
        .await
        .unwrap();
}
