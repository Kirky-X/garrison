#[tokio::main]
async fn main() {
    bulwark_examples::authorization::strategy_firewall::run()
        .await
        .unwrap();
}
