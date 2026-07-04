#[tokio::main]
async fn main() {
    bulwark_examples::jwt_modes::run().await.unwrap();
}
