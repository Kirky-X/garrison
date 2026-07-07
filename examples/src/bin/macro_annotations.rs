#[tokio::main]
async fn main() {
    bulwark_examples::extension::macro_annotations::run()
        .await
        .unwrap();
}
