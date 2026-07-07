#[tokio::main]
async fn main() {
    bulwark_examples::oauth2::scope_handler::run()
        .await
        .unwrap();
}
