//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! 封禁库模块，提供账号封禁/解封/查询能力。
//! # 核心类型
//!
//! - [`DisableEntry`](crate::account::disable::DisableEntry)：封禁条目 struct（5 字段，JSON 持久化）
//! - [`DisableRepository`](crate::account::disable::DisableRepository)：封禁库 trait（5 方法）
//!
//! # 实现层
//!
//! 将实现 `DefaultDisableRepository`，持有 `Arc<dyn GarrisonDao>` 委托实现。
//!
//! # 过期语义（统一约定）
//!
//! 封禁存在两套过期：DAO key 的存储 TTL（`disable` 的 `duration_secs`，写入时取
//! `max(duration_secs, until 剩余秒数)` 兜底）与条目 `until` 的逻辑过期。
//! 三个查询方法（`is_disable` / `get_disable_time` / `get_disable_level`）对
//! **逻辑已过期**的条目行为一致：一律视为未封禁（false / None / None），
//! 即使 DAO key 因 TTL=0 仍驻留。诊断错误信息（key 冲突等）会包含原始
//! `service` / `login_id` 以便定位问题，属有意设计。

pub mod repository;

pub use repository::{DefaultDisableRepository, DisableEntry, DisableRepository};
