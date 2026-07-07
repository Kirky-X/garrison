#[tokio::main]
async fn main() {
    bulwark_examples::extension::manager_lifecycle::run()
        .await
        .unwrap();
}
