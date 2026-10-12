// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 旧集成测试树迁移模块。
//!
//! 逐字移植保留各域集成测试（注解矩阵 / 注解宏全矩阵 / axum middleware / JWT 模式 /
//! keycloak RP 全流程 / 密码登录 / 插件监听器 / 策略注册表 / refresh token / 租户隔离），
//! 测试体与断言语义零改动（可强化不可弱化），原各文件的内部 `#![cfg(...)]` 转挂到本
//! 文件各 `mod` 声明。

#[cfg(feature = "web-axum")]
pub mod annotation;

#[cfg(feature = "annotation-macros")]
pub mod annotation_macros;

#[cfg(feature = "web-axum")]
pub mod axum;

#[cfg(all(feature = "protocol-jwt", feature = "cache-memory"))]
pub mod jwt_modes;

#[cfg(all(
    feature = "keycloak-oidc",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
pub mod keycloak_oidc;

#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
pub mod login_password;

#[cfg(feature = "listener")]
pub mod plugin_listener;

#[cfg(feature = "protocol-jwt")]
pub mod refresh_token;

#[cfg(feature = "cache-memory")]
pub mod strategy_registry;

#[cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
pub mod tenant_isolation;
