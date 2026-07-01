#[tokio::main]
async fn main() {
    bulwark_examples::sign_protocol::run().await.unwrap();
}
