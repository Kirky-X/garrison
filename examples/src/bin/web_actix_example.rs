// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! web_actix_example binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::web::web_actix_example::run()
        .await
        .unwrap();
}
