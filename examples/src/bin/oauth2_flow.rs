// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

#[tokio::main]
async fn main() {
    garrison_examples::oauth2::oauth2_flow::run().await.unwrap();
}
