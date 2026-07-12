//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkListenerManager 实现块（从 mod.rs 迁移）。

use super::*;

impl BulwarkListenerManager {
    /// 创建监听器管理器并收集所有已注册监听器。
    pub fn new() -> Self {
        use std::iter::Iterator;
        let listeners: Vec<Arc<dyn BulwarkListener>> = inventory::iter::<BulwarkListenerEntry>()
            .map(|entry| (entry.factory)())
            .collect();
        for l in &listeners {
            tracing::info!(
                "已加载监听器: {}",
                std::any::type_name::<Arc<dyn BulwarkListener>>()
            );
            let _ = l; // 避免 unused 警告
        }
        Self {
            listeners: Arc::new(RwLock::new(listeners)),
        }
    }

    /// 运行时注册监听器。
    ///
    /// 补充 `inventory` 编译期注册机制的不足：`AuditLogListener` 等需要运行时参数
    /// （如 `DbPool`）的监听器无法通过无参工厂函数注册，需通过此方法在初始化后追加。
    pub fn register(&self, listener: Arc<dyn BulwarkListener>) {
        self.listeners.write().push(listener);
    }

    /// 返回已注册监听器数量。
    pub fn count(&self) -> usize {
        self.listeners.read().len()
    }

    /// 广播事件到所有已注册监听器。
    ///
    /// 异步遍历所有监听器的 `on_event` 方法，单个监听器失败仅记录 `tracing::warn!`，
    /// 不中断广播，最终返回 `Ok(())`。
    ///
    /// v0.5.0 改为 async：`on_event` 改为 async 后，broadcast 需 `.await`。
    pub async fn broadcast(&self, event: &BulwarkEvent) {
        let listeners = self.listeners.read().clone();
        for listener in &listeners {
            if let Err(e) = listener.on_event(event).await {
                tracing::warn!("监听器 on_event 失败: {}", e);
            }
        }
    }
}

impl Default for BulwarkListenerManager {
    fn default() -> Self {
        Self::new()
    }
}
