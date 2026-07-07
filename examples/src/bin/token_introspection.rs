#[tokio::main]
async fn main() {
    bulwark_examples::oauth2::token_introspection::run()
        .await
        .unwrap();
}
