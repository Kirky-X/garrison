//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! web_warp_example binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::web::web_warp_example::run()
        .await
        .unwrap();
}
