//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 一键启动 BulwarkAuthServer 双端口服务。
//!
//! 用于 E2E / 性能 / 渗透测试的真实进程部署，对应 `infrastructure::auth_server::serve()`。
//!
//! # 运行方式
//!
//! ```sh
//! EXAMPLE_INTERNAL_API_KEY=test \
//! cargo run -p bulwark-examples --bin auth_server_serve --features full
//! ```
//!
//! # 环境变量
//!
//! - `EXAMPLE_INTERNAL_API_KEY`（必填）：内网 API Key，缺失时 fail-closed 退出码 1
//! - `BULWARK_EXTERNAL_PORT`（默认 8080）：外网端口
//! - `BULWARK_INTERNAL_PORT`（默认 8081）：内网端口
//! - `BULWARK_RATE_LIMIT`（默认 100）：每 IP 限速阈值（req/s）

#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::auth_server::serve()
        .await
        .expect("auth_server_serve 启动失败");
}
