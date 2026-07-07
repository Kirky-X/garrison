//! Web 框架集成示例模块（axum / actix / warp / grpc）。

#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod axum_integration;
#[cfg(feature = "web-axum")]
pub mod context_request;
#[cfg(feature = "grpc")]
pub mod grpc_interceptor;
#[cfg(feature = "web-actix")]
pub mod web_actix_example;
#[cfg(feature = "web-warp")]
pub mod web_warp_example;
