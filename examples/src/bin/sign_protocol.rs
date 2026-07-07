#[tokio::main]
async fn main() {
    bulwark_examples::sign::sign_protocol::run().await.unwrap();
}
