//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 锁定状态存储抽象。
//! 本文件为 DAO 存储抽象的具体实现占位（如 Redis/SQL 适配）。
//! v0.6.0 的 [`UserLockoutStrategy`](crate::account::lockout::UserLockoutStrategy) 直接通过
//! [`BulwarkDao`](crate::dao::BulwarkDao) 持久化 [`LockoutState`](crate::account::lockout::LockoutState)，
//! 未来版本可在此文件实现专用的锁定状态存储后端（如 Redis TTL 自动过期、
//! SQL 持久化、跨数据中心同步）。
//!
//! # 与 `UserLockoutStrategy` 的关系
//!
//! `UserLockoutStrategy` 当前使用 `BulwarkDao` 通用抽象
//! （`lockout:{user_id}` key，TTL=0 永久存储），本文件预留给需要专用
//! 存储后端的场景（如分布式锁定、Redis 自动过期解锁）。
//!
//! # v0.6.5+ 实现范围
//!
//! - Redis 后端：利用 Redis TTL 自动过期解锁（替代 `locked_until` 轮询）
//! - SQL 后端：持久化锁定状态到关系数据库（支持审计查询）
//! - 分布式锁定：跨数据中心同步锁定状态（多活场景）
