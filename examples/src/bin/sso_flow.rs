#[tokio::main]
async fn main() {
    bulwark_examples::sso_flow::run().await.unwrap();
}
