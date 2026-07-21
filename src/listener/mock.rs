//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 监听器层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `OkListener` / `ErrListener` 两个 GarrisonListener mock（通过 `inventory` 编译期注册），
//! 供 `listener::tests` 事件广播与监听器管理测试复用。

use super::{GarrisonEvent, GarrisonListener, GarrisonListenerEntry};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 计数器，记录 on_event 被调用次数。
pub static EVENT_CALLS: AtomicUsize = AtomicUsize::new(0);

/// 成功监听器，on_event 返回 Ok(())。
pub struct OkListener;

#[async_trait]
impl GarrisonListener for OkListener {
    async fn on_event(&self, _event: &GarrisonEvent) -> GarrisonResult<()> {
        EVENT_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// 失败监听器，on_event 返回 Err。
pub struct ErrListener;

#[async_trait]
impl GarrisonListener for ErrListener {
    async fn on_event(&self, _event: &GarrisonEvent) -> GarrisonResult<()> {
        Err(GarrisonError::Internal(
            "listener-on-event-failed".to_string(),
        ))
    }
}

pub fn ok_listener_factory() -> Arc<dyn GarrisonListener> {
    Arc::new(OkListener)
}

pub fn err_listener_factory() -> Arc<dyn GarrisonListener> {
    Arc::new(ErrListener)
}

// 注册测试监听器到 inventory
inventory::submit! {
    GarrisonListenerEntry { factory: ok_listener_factory }
}
inventory::submit! {
    GarrisonListenerEntry { factory: err_listener_factory }
}

/// 重置计数器。
pub fn reset_counters() {
    EVENT_CALLS.store(0, Ordering::SeqCst);
}
