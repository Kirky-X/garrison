//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! web_actix_example 示例测试（web-actix feature）。
//!
//! 验证 BulwarkMiddleware + LoggingInterceptor 的鉴权行为：
//! - 公开路径无需 token → 200
//! - 受保护路径无 token → 401
//! - 受保护路径有 token → 200
//! - CheckRole 路径有匹配角色 → 200
//! - CheckPermission 路径有匹配权限 → 200
//!
//! 使用 `#[serial_test::serial]` 串行化，因为 `setup()` 修改全局 `BulwarkManager` 单例。

#![cfg(feature = "web-actix")]

use bulwark_examples::web::web_actix_example;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_middleware_protection() {
    let (config, token) = web_actix_example::setup().await;
    let middleware = web_actix_example::create_middleware(config.clone());

    use actix_web::http::StatusCode;
    use actix_web::{test, web, App};

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .wrap(middleware)
            .route("/api/protected", web::get().to(|| async { "ok" }))
            .route("/api/admin", web::get().to(|| async { "ok" }))
            .route("/api/data", web::get().to(|| async { "ok" }))
            .route("/public", web::get().to(|| async { "ok" })),
    )
    .await;

    // 公开路径 - 无需 token → 200
    let req = test::TestRequest::get().uri("/public").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 受保护路径 - 无 token → 401
    let req = test::TestRequest::get().uri("/api/protected").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 受保护路径 - 有 token → 200
    let req = test::TestRequest::get()
        .uri("/api/protected")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // CheckRole 路径 - 有 token 且持有 admin 角色 → 200
    let req = test::TestRequest::get()
        .uri("/api/admin")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // CheckPermission 路径 - 有 token 且持有 data:read 权限 → 200
    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
