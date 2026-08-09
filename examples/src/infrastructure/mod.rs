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
#[cfg(all(feature = "credit-metering", feature = "cache-memory"))]
pub mod credit_metering;
#[cfg(feature = "cache-memory")]
pub mod dao_operations;
pub mod exception_handling;
#[cfg(all(feature = "cache-memory", feature = "db-sqlite"))]
pub mod health_check;
pub mod i18n_usage;
pub mod json_template;
#[cfg(all(feature = "metrics-prometheus", feature = "otlp"))]
pub mod observability_setup;
#[cfg(feature = "parameter-query")]
pub mod parameter_query;
#[cfg(feature = "sms-rate-limit")]
pub mod sms_rate_limit;
#[cfg(feature = "three-tier-cache")]
pub mod three_tier_cache;
