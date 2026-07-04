#[tokio::main]
async fn main() {
    bulwark_examples::oauth2_pkce::run().await.unwrap();
}
