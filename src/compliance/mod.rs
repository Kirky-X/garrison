// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 数据合规能力（`data-erasure` feature）：GDPR / 个保法语境下数据主体删除权（erasure）的框架侧编排——按 login_id 擦除框架管辖内可定位存储键并产出报告，明示残留归属业务方（数据清单与责任边界见 `docs/DATA_COMPLIANCE.md`）。
//!
//! 设计约束：会话/token 删除经闭包委托 `StpLogic::logout_by_login_id` / `kickout`（不复制其 per-login 锁与内存索引清理语义）；键构造复用生产常量（`DaoKeyPrefix`、`session::account_key`）不复制格式字符串；所有 `dao.delete` 对不存在的键幂等安全。

pub mod erasure;

pub use erasure::{DataErasureService, ErasureReport};
