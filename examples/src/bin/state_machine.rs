// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 状态机生命周期完整流程示例二进制入口。
//!
//! ```sh
//! cargo run -p garrison-examples --bin state_machine --features full
//! ```

#[tokio::main]
async fn main() {
    garrison_examples::extension::state_machine::run()
        .await
        .expect("state_machine 示例执行失败");
}
