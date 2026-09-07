//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! social_alipay 示例测试（social-alipay feature）。
//!
//! 验证 run() 完整执行（占位 RSA 密钥构造失败为预期行为，无外部网络依赖）。

#![cfg(feature = "social-alipay")]

use garrison_examples::oauth2::social_alipay;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    social_alipay::run().await.unwrap();
}
