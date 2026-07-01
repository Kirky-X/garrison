#[tokio::main]
async fn main() {
    bulwark_examples::auth_logic_impl::run().await.unwrap();
}
