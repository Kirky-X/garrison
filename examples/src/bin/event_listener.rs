#[tokio::main]
async fn main() {
    bulwark_examples::extension::event_listener::run()
        .await
        .unwrap();
}
