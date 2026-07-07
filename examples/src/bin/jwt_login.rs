#[tokio::main]
async fn main() {
    bulwark_examples::authentication::jwt_login::run()
        .await
        .unwrap();
}
