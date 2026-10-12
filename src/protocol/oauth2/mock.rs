// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 协议层测试 mock（仅 `cfg(test)` 编译）：`make_client` 创建指向 wiremock MockServer 的客户端，供 `tests` 复用。

use crate::protocol::oauth2::OAuth2Client;
use wiremock::MockServer;

/// 创建测试用 OAuth2Client，指向 mock server。
pub async fn make_client(server: &MockServer) -> OAuth2Client {
    let base = server.uri();
    OAuth2Client::new(
        "test-client-id",
        "test-client-secret",
        "https://example.com/callback",
        format!("{}/auth", base),
        format!("{}/token", base),
    )
    .expect("failed to create OAuth2Client")
}
