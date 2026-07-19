//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AlertListenerManager 实现块（从 mod.rs 迁移）。

use super::*;

impl AlertListenerManager {
    /// 创建空的告警监听器管理器。
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 运行时追加告警监听器。
    pub fn add_listener(&self, listener: Arc<dyn AlertListener>) {
        self.listeners.write().push(listener);
    }

    /// 返回已注册的告警监听器数量。
    pub fn count(&self) -> usize {
        self.listeners.read().len()
    }

    /// 广播告警事件到所有已注册监听器。
    ///
    /// 异步遍历所有监听器的 `on_alert` 方法，单个监听器失败仅记录 `tracing::warn!`，
    /// 不中断广播。
    pub async fn broadcast_alert(&self, event: &SecurityAlertEvent) {
        let listeners = self.listeners.read().clone();
        for listener in &listeners {
            if let Err(e) = listener.on_alert(event).await {
                tracing::warn!("alert listener on_alert failed: {}", e);
            }
        }
    }
}

impl Default for AlertListenerManager {
    fn default() -> Self {
        Self::new()
    }
}
