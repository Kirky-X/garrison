// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 封禁库：账号封禁/解封/查询。[`DisableEntry`](crate::account::disable::DisableEntry) 为封禁条目
//! （5 字段，JSON 持久化），[`DisableRepository`](crate::account::disable::DisableRepository) trait 由
//! `DefaultDisableRepository` 持 `Arc<dyn GarrisonDao>` 委托实现。
//!
//! 过期语义：DAO key 存储 TTL（`duration_secs`，写入取 `max(duration_secs, until 剩余秒数)` 兜底）
//! 与 `until` 逻辑过期并存；`is_disable` / `get_disable_time` / `get_disable_level` 对逻辑已过期条目
//! 一律视为未封禁（false / None / None），即使 key 因 TTL=0 仍驻留。诊断错误信息含原始
//! `service` / `login_id` 属有意设计。

pub mod repository;

pub use repository::{DefaultDisableRepository, DisableEntry, DisableRepository};
