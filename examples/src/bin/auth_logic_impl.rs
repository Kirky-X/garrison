#[tokio::main]
async fn main() {
    bulwark_examples::extension::auth_logic_impl::run()
        .await
        .unwrap();
}
