#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::alone_cache::run()
        .await
        .unwrap();
}
