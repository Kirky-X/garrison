//! cache_redis binary 入口。

#[tokio::main]
async fn main() {
    bulwark_examples::cache_redis::run().await.unwrap();
}
