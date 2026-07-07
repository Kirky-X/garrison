//! grpc_interceptor binary 入口。

#[tokio::main]
async fn main() {
    bulwark_examples::web::grpc_interceptor::run()
        .await
        .unwrap();
}
