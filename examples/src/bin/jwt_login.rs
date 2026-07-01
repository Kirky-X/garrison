#[tokio::main]
async fn main() {
    bulwark_examples::jwt_login::run().await.unwrap();
}
