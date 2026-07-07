//! web_actix_example binary 入口。

#[tokio::main]
async fn main() {
    bulwark_examples::web::web_actix_example::run()
        .await
        .unwrap();
}
