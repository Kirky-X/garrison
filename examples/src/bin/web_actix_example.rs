//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! web_actix_example binary 入口。

#[tokio::main]
async fn main() {
    garrison_examples::web::web_actix_example::run()
        .await
        .unwrap();
}
