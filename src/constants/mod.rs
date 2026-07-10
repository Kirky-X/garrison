//! 常量模块，提供框架共享的枚举与常量定义。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

/// DAO key 前缀枚举模块。
pub mod dao_keys;

/// 事件 reason 枚举模块。
pub mod events;

pub use dao_keys::DaoKeyPrefix;
pub use events::EventReason;
