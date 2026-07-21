//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! limiteron 适配器模块。
//!
//! 提供 4 个适配器，将 `GarrisonDao` 桥接到 limiteron 的 `Storage` / `QuotaStorage` /
//! `BanStorage` / `DistributedLimiter` trait，使 garrison 的限速/封禁策略可以
//! 委托 limiteron 的统一抽象。
//!
//! # 适配器清单
//!
//! | 适配器 | 实现 trait | 用途 |
//! |--------|-----------|------|
//! | [`GarrisonDaoStorage`](crate::limiteron::GarrisonDaoStorage) | `Storage` | KV get/set/delete |
//! | [`GarrisonDaoQuotaStorage`](crate::limiteron::GarrisonDaoQuotaStorage) | `QuotaStorage` | 原子配额消费（SMS 限速） |
//! | [`GarrisonDaoDistributedLimiter`](crate::limiteron::GarrisonDaoDistributedLimiter) | `DistributedLimiter` | 原子计数 + TTL（滑动窗口） |
//! | [`GarrisonDaoBanStorage`](crate::limiteron::GarrisonDaoBanStorage) | `BanStorage` | 封禁记录管理（暴力破解防护） |
//!
//! # 已知限制
//!
//! - `GarrisonDao::incr` 默认实现非原子（get→parse→+1→update），`MockDao` 重写为进程内原子
//! - `QuotaStorage::consume` 通过循环 `dao.incr` 实现，cost > 1 时非原子
//! - `BanStorage::list_bans` / `cleanup_expired_bans` 无法实现（GarrisonDao 无 iter API），返回空/0

pub mod ban;
pub mod distributed;
pub mod errors;
pub mod quota;
pub mod storage;

pub use ban::GarrisonDaoBanStorage;
pub use distributed::GarrisonDaoDistributedLimiter;
pub use quota::GarrisonDaoQuotaStorage;
pub use storage::GarrisonDaoStorage;
