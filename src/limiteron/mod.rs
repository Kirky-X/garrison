//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! limiteron 适配器模块。
//!
//! 提供 4 个适配器，将 `BulwarkDao` 桥接到 limiteron 的 `Storage` / `QuotaStorage` /
//! `BanStorage` / `DistributedLimiter` trait，使 bulwark 的限速/封禁策略可以
//! 委托 limiteron 的统一抽象。
//!
//! # 适配器清单
//!
//! | 适配器 | 实现 trait | 用途 |
//! |--------|-----------|------|
//! | [`BulwarkDaoStorage`](crate::limiteron::BulwarkDaoStorage) | `Storage` | KV get/set/delete |
//! | [`BulwarkDaoQuotaStorage`](crate::limiteron::BulwarkDaoQuotaStorage) | `QuotaStorage` | 原子配额消费（SMS 限速） |
//! | [`BulwarkDaoDistributedLimiter`](crate::limiteron::BulwarkDaoDistributedLimiter) | `DistributedLimiter` | 原子计数 + TTL（滑动窗口） |
//! | [`BulwarkDaoBanStorage`](crate::limiteron::BulwarkDaoBanStorage) | `BanStorage` | 封禁记录管理（暴力破解防护） |
//!
//! # 已知限制
//!
//! - `BulwarkDao::incr` 默认实现非原子（get→parse→+1→update），`MockDao` 重写为进程内原子
//! - `QuotaStorage::consume` 通过循环 `dao.incr` 实现，cost > 1 时非原子
//! - `BanStorage::list_bans` / `cleanup_expired_bans` 无法实现（BulwarkDao 无 iter API），返回空/0

pub mod ban;
pub mod distributed;
pub mod errors;
pub mod quota;
pub mod storage;

pub use ban::BulwarkDaoBanStorage;
pub use distributed::BulwarkDaoDistributedLimiter;
pub use quota::BulwarkDaoQuotaStorage;
pub use storage::BulwarkDaoStorage;
