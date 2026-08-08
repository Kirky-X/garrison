//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 安全中间件示例集成测试。

#![cfg(all(
    feature = "web-waf",
    feature = "web-cors",
    feature = "web-csrf",
    feature = "web-axum"
))]

#[tokio::test]
async fn web_security_runs_successfully() {
    garrison_examples::web::web_security::run()
        .await
        .expect("web_security 示例应成功执行");
}
