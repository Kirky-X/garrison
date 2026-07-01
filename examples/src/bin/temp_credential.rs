#[tokio::main]
async fn main() {
    bulwark_examples::temp_credential::run().await.unwrap();
}
