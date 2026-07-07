#[tokio::main]
async fn main() {
    bulwark_examples::oauth2::oauth2_flow::run().await.unwrap();
}
