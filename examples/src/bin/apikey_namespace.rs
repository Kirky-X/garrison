#[tokio::main]
async fn main() {
    bulwark_examples::apikey::apikey_namespace::run()
        .await
        .unwrap();
}
