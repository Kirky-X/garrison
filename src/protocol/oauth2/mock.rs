//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `make_client` 辅助函数（创建指向 wiremock MockServer 的 OAuth2Client），
//! 供 `protocol::oauth2::tests` 集成测试复用。

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
    .expect("创建 OAuth2Client 失败")
}
