#[tokio::main]
async fn main() {
    bulwark_examples::manager_lifecycle::run().await.unwrap();
}
