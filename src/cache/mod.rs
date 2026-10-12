// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 缓存模块，启用 `three-tier-cache` feature 时编译。
//!
//! [`UserCacheService`]：L1（oxcache 进程内缓存，per-entry TTL 默认 30s）命中即止；
//! L2（DAO 持久化缓存，TTL 默认 300s）命中回填 L1；L3（PermissionStrategy 回调）命中回填 L1 + L2。
//!
//! [`UserCacheService`]: crate::cache::three_tier::UserCacheService

/// 三层缓存服务（L1 oxcache + L2 DAO + L3 interface）。
pub mod three_tier;

/// DAO 缓存后端（oxcache `CacheBackend` 适配器）：ChainCache 组链的 L2 持久层。
pub(crate) mod dao_backend;

pub use three_tier::UserCacheService;
