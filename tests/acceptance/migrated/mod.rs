//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 旧集成测试树迁移模块（Phase 4 T041，迁自 `tests/integration/`）。
//!
//! 迁移方式：**逐字移植**（内部 `#![cfg(...)]` 属性转挂到本文件各 `mod` 声明，
//! 测试体与断言语义零改动——迁移规则「可强化不可弱化」，保底总覆盖）。
//! 覆盖：router 注解矩阵 / 注解宏全矩阵（strict+loose、and/or、access/client/temp
//! token、MFA、ABAC）/ 密码登录（hasher 矩阵 + 缺装配失败路径）/ 插件与监听器
//! 事件 / 策略注册表外部实现与热替换 / JWT 四种模式 / keycloak RP 全流程 /
//! 租户隔离 E2E（audit + 决策溯源）。

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
