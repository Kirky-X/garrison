//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查完整流程示例二进制入口。
//!
//! ```sh
//! cargo run -p garrison-examples --bin health_check --features "cache-memory db-sqlite"
//! ```

#[tokio::main]
async fn main() {
    garrison_examples::infrastructure::health_check::run()
        .await
        .expect("health_check 示例执行失败");
}
