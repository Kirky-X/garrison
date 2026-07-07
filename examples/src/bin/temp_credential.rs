#[tokio::main]
async fn main() {
    bulwark_examples::sign::temp_credential::run()
        .await
        .unwrap();
}
