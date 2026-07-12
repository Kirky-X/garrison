//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! oauth2_pkce 示例测试（protocol-oauth2 feature）。
//!
//! 验证 run() 完整执行：PKCE S256 challenge 生成 + RFC 7636 测试向量 + 授权 URL 构造。

#![cfg(feature = "protocol-oauth2")]

use bulwark_examples::oauth2::oauth2_pkce;

#[tokio::test]
async fn test_run_completes() {
    oauth2_pkce::run().await.unwrap();
}
