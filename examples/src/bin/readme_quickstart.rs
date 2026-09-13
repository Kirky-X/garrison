//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! README 快速开始示例 bin（对应 examples/src/web/readme_quickstart.rs）。
//!
//! 运行：`cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"`

#[tokio::main]
async fn main() {
    garrison_examples::web::readme_quickstart::run()
        .await
        .unwrap();
}
