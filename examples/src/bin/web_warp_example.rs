// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! web_warp_example binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::web::web_warp_example::run()
        .await
        .unwrap();
}
