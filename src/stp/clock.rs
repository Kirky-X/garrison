//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SystemClock / MockClock 实现：可注入时钟抽象。
//!
//! `Clock` trait 与 `SystemClock` / `MockClock` 结构体定义位于 `super::mod`，
//! 本文件仅承载 impl 块（mod.rs 接口隔离，Rule 25）。
use super::{Clock, MockClock, SystemClock};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::sync::Arc;

impl SystemClock {
    /// 创建系统时钟实例。
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        chrono::Utc::now()
    }
}

impl MockClock {
    /// 创建 MockClock，初始时间为 `time`。
    pub fn new(time: DateTime<Utc>) -> Self {
        Self {
            time: Arc::new(RwLock::new(time)),
        }
    }

    /// 设置当前时间。
    pub fn set_time(&self, time: DateTime<Utc>) {
        *self.time.write() = time;
    }

    /// 推进时间（正数向前，负数向后）。
    pub fn advance(&self, duration: chrono::Duration) {
        let mut w = self.time.write();
        *w += duration;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.time.read()
    }
}
