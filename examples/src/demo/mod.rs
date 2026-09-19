// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 综合演示示例模块。

#[cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "core-advanced",
    feature = "keycloak-oidc",
    feature = "social-wechat",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
pub mod v0_5_0_demo;
