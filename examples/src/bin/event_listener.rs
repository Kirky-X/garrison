#[tokio::main]
async fn main() {
    bulwark_examples::event_listener::run().await.unwrap();
}
