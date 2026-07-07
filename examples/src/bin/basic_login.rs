#[tokio::main]
async fn main() {
    bulwark_examples::authentication::basic_login::run()
        .await
        .unwrap();
}
