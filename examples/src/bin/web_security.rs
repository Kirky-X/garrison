//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 安全中间件完整流程示例二进制入口。
//!
//! ```sh
//! cargo run -p garrison-examples --bin web_security --features "web-waf web-cors web-csrf web-axum"
//! ```

#[tokio::main]
async fn main() {
    garrison_examples::web::web_security::run()
        .await
        .expect("web_security 示例执行失败");
}
