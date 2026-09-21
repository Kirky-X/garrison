// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 数据合规能力（`data-erasure` feature）。
//!
//! 提供 GDPR / 个保法语境下的**数据主体权利（删除权 / erasure）**框架侧编排：
//! 按主体（login_id）擦除框架管辖内可定位的存储键，并产出擦除报告，
//! 明示哪些残留数据归属业务方处置。数据清单与责任边界详见
//! `docs/DATA_COMPLIANCE.md`。
//!
//! # 设计约束
//!
//! - **会话擦除委托而非复制**：会话/token 删除的并发正确性（per-login 锁 +
//!   内存索引清理）由 `StpLogic::logout_by_login_id` / `kickout` 承载，
//!   本服务通过闭包委托执行，不复制该语义。
//! - **键构造单点复用**：直接引用生产路径的键前缀常量（`DaoKeyPrefix`）与
//!   会话键构造函数（`session::account_key`），不复制格式字符串。
//! - **删除幂等**：所有 `dao.delete` 调用对不存在的键安全。

pub mod erasure;

pub use erasure::{DataErasureService, ErasureReport};
