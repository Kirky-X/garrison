#[tokio::main]
async fn main() {
    bulwark_examples::permission_check::run().await.unwrap();
}
