// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 授权服务器完整流程示例二进制入口。
//!
//! ```sh
//! cargo run -p garrison-examples --bin oauth2_server_flow --features "oauth2-server cache-memory"
//! ```

#[tokio::main]
async fn main() {
    garrison_examples::oauth2::oauth2_server_flow::run()
        .await
        .expect("oauth2_server_flow 示例执行失败");
}
