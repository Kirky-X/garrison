#[tokio::main]
async fn main() {
    bulwark_examples::web::axum_integration::run()
        .await
        .unwrap();
}
