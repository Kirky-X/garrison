// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! limiteron 适配器模块。
//!
//! 提供 3 个基础适配器，将 `GarrisonDao` 桥接到 limiteron 的 `Storage` / `BanStorage` /
//! `DistributedLimiter` trait，使 garrison 的限速/封禁策略可以委托 limiteron 的统一抽象；
//! 并通过 [`LimiterRuntime`](crate::limiteron::LimiterRuntime) 支持按配置在 DAO 后端与独立 Redis 限流后端之间切换。
//!
//! # 适配器清单
//!
//! | 适配器 | 实现 trait | 用途 |
//! |--------|-----------|------|
//! | [`GarrisonDaoStorage`](crate::limiteron::GarrisonDaoStorage) | `Storage` | KV get/set/delete |
//! | [`GarrisonDaoDistributedLimiter`](crate::limiteron::GarrisonDaoDistributedLimiter) | `DistributedLimiter` | 原子计数 + TTL（滑动窗口） |
//! | `GarrisonDaoBanStorage`（`firewall-ddos` feature 门控） | `BanStorage` | 封禁记录管理（暴力破解防护） |
//! | [`LimiterBackend`](crate::limiteron::LimiterBackend) | `DistributedLimiter` + 扩展 | 限流执行面（DAO / Redis 可切换） |
//! | `RedisLimiterBackend`（`rate-limit-redis` feature 门控） | `LimiterBackend` + `Storage` | 独立 Redis 限流运行时 |
//!
//! # 已知限制
//!
//! - `GarrisonDao::incr` 默认实现非原子（get→parse→+1→update），`MockDao` 重写为进程内原子
//! - `BanStorage::list_bans` / `cleanup_expired_bans` 无法实现（GarrisonDao 无 iter API），
//! 返回空/0，且调用时以 `tracing::warn` 留痕——调用方不得依赖其做封禁审计/枚举/清理
//! （返回值是假阴性，非真实状态）
//! - [`LimiterBackend::reset_prefix`](crate::limiteron::LimiterBackend::reset_prefix) 为测试/运维辅助：DAO 后端经 `keys()`（可能全表扫描），
//! Redis 后端经 `SCAN`；生产热路径不得调用

pub mod backend;
#[cfg(feature = "firewall-ddos")]
pub mod ban;
#[cfg(feature = "backend-remote")]
pub mod circuit;
pub mod distributed;
pub mod errors;
#[cfg(feature = "backend-remote")]
pub mod fallback;
#[cfg(feature = "rate-limit-redis")]
pub mod redis;
pub mod storage;

pub use backend::{LimiterBackend, LimiterRuntime};
#[cfg(feature = "firewall-ddos")]
pub use ban::GarrisonDaoBanStorage;
#[cfg(feature = "backend-remote")]
pub use circuit::CircuitBreakerWrapper;
pub use distributed::GarrisonDaoDistributedLimiter;
#[cfg(feature = "backend-remote")]
pub use fallback::{FallbackDecision, FallbackPolicy};
#[cfg(feature = "rate-limit-redis")]
pub use redis::RedisLimiterBackend;
pub use storage::GarrisonDaoStorage;
