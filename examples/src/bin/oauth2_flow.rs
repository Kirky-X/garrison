#[tokio::main]
async fn main() {
    bulwark_examples::oauth2_flow::run().await.unwrap();
}
