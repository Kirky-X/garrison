#[tokio::main]
async fn main() {
    bulwark_examples::sso_server::run().await.unwrap();
}
