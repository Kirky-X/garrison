#[tokio::main]
async fn main() {
    bulwark_examples::infrastructure::parameter_query::run()
        .await
        .unwrap();
}
