//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! grpc_interceptor binary 入口。

#[tokio::main]
async fn main() {
    bulwark_examples::web::grpc_interceptor::run()
        .await
        .unwrap();
}
