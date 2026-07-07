#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::dao_operations::run()
        .await
        .unwrap();
}
