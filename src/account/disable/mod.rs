//! 封禁库模块，提供账号封禁/解封/查询能力。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! # 核心类型（T015）
//!
//! - [`DisableEntry`](crate::account::disable::DisableEntry)：封禁条目 struct（5 字段，JSON 持久化）
//! - [`DisableRepository`](crate::account::disable::DisableRepository)：封禁库 trait（5 方法）
//!
//! # 实现层（T016-T018）
//!
//! T016-T018 将实现 `DefaultDisableRepository`，持有 `Arc<dyn BulwarkDao>` 委托实现。

pub mod repository;

pub use repository::{DefaultDisableRepository, DisableEntry, DisableRepository};
