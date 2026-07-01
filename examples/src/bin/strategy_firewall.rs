#[tokio::main]
async fn main() {
    bulwark_examples::strategy_firewall::run().await.unwrap();
}
