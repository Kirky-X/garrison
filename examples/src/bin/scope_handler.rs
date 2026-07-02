#[tokio::main]
async fn main() {
    bulwark_examples::scope_handler::run().await.unwrap();
}
