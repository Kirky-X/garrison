#[tokio::main]
async fn main() {
    bulwark_examples::password_login::run().await.unwrap();
}
