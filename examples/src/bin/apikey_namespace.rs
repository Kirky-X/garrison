#[tokio::main]
async fn main() {
    bulwark_examples::apikey_namespace::run().await.unwrap();
}
