// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! grpc_interceptor binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::web::grpc_interceptor::run()
        .await
        .unwrap();
}
