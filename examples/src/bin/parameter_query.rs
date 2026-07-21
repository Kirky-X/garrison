//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

#[tokio::main]
async fn main() {
    garrison_examples::infrastructure::parameter_query::run()
        .await
        .unwrap();
}
