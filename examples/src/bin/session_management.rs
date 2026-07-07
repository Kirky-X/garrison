#[tokio::main]
async fn main() {
    bulwark_examples::extension::session_management::run()
        .await
        .unwrap();
}
