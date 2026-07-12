//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

#[tokio::main]
async fn main() {
    bulwark_examples::sign::sign_protocol::run().await.unwrap();
}
