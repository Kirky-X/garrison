#[tokio::main]
async fn main() {
    bulwark_examples::oauth2::sso_server::run().await.unwrap();
}
