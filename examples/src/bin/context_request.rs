#[tokio::main]
async fn main() {
    bulwark_examples::web::context_request::run().await.unwrap();
}
