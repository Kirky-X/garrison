#[tokio::main]
async fn main() {
    bulwark_examples::token_introspection::run().await.unwrap();
}
