#[tokio::main]
async fn main() {
    bulwark_examples::authentication::jwt_modes::run()
        .await
        .unwrap();
}
