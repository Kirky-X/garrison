//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 授权服务器示例集成测试。

#![cfg(all(feature = "oauth2-server", feature = "cache-memory"))]

#[tokio::test(flavor = "multi_thread")]
async fn oauth2_server_flow_runs_successfully() {
    garrison_examples::oauth2::oauth2_server_flow::run()
        .await
        .expect("oauth2_server_flow 示例应成功执行");
}
