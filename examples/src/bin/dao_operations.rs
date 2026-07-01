#[tokio::main]
async fn main() {
    bulwark_examples::dao_operations::run().await.unwrap();
}
