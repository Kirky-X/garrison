//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 基础设施示例模块（cache / config / dao / i18n / observability）。

#[cfg(feature = "alone-cache")]
pub mod alone_cache;
#[cfg(feature = "auth-server")]
pub mod auth_server;
#[cfg(feature = "backend-remote")]
pub mod backend_remote;
#[cfg(feature = "cache-redis")]
pub mod cache_redis;
pub mod config_loader;
#[cfg(feature = "cache-memory")]
pub mod dao_operations;
pub mod exception_handling;
pub mod i18n_usage;
pub mod json_template;
#[cfg(all(feature = "metrics-prometheus", feature = "observability-otlp"))]
pub mod observability_setup;
#[cfg(feature = "parameter-query")]
pub mod parameter_query;
