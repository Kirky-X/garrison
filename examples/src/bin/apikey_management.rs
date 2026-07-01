#[tokio::main]
async fn main() {
    bulwark_examples::apikey_management::run().await.unwrap();
}
