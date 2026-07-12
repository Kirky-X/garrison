//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 缓存模块，提供三层缓存架构（L1 moka + L2 DAO + L3 interface）。
//!
//! 启用 `three-tier-cache` feature 时编译。提供 [`UserCacheService`]，
//! 用于权限/角色/用户信息的加速查询。
//!
//! # 三层缓存架构
//!
//! - **L1（moka 内存缓存）**：进程内 LRU + TTL 缓存，TTL 较短（默认 30s），命中时不查询 L2/L3
//! - **L2（DAO 持久化缓存）**：通过 `BulwarkDao` set/get，TTL 较长（默认 300s），命中时回填 L1
//! - **L3（interface 回调）**：通过 `BulwarkPermissionStrategy` 的 `get_permission_list` /
//!   `get_role_list` / `get_user_info` 获取原始数据，命中时回填 L1 + L2
//!
//! [`UserCacheService`]: crate::cache::three_tier::UserCacheService

/// 三层缓存服务（L1 moka + L2 DAO + L3 interface）。
pub mod three_tier;

pub use three_tier::UserCacheService;
