#[tokio::main]
async fn main() {
    bulwark_examples::apikey::apikey_management::run()
        .await
        .unwrap();
}
