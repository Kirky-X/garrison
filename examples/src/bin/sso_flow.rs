#[tokio::main]
async fn main() {
    bulwark_examples::oauth2::sso_flow::run().await.unwrap();
}
