#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::config_loader::run()
        .await
        .unwrap();
}
