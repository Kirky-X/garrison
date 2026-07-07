#[tokio::main]
async fn main() {
    bulwark_examples::authentication::password_login::run()
        .await
        .unwrap();
}
