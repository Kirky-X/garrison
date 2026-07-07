#[tokio::main]
async fn main() {
    bulwark_examples::authorization::strategy_registry::run()
        .await
        .unwrap();
}
