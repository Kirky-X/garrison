#[tokio::main]
async fn main() {
    bulwark_examples::config_loader::run().await.unwrap();
}
