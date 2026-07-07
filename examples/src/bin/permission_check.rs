#[tokio::main]
async fn main() {
    bulwark_examples::authorization::permission_check::run()
        .await
        .unwrap();
}
