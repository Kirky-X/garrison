//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonListenerManager 实现块（从 mod.rs 迁移）。

use super::*;

impl GarrisonListenerManager {
    /// 创建监听器管理器并收集所有已注册监听器。
    pub fn new() -> Self {
        use std::iter::Iterator;
        let listeners: Vec<Arc<dyn GarrisonListener>> = inventory::iter::<GarrisonListenerEntry>()
            .map(|entry| (entry.factory)())
            .collect();
        // ocr #5348：`type_name::<Arc<dyn GarrisonListener>>()` 对所有条目恒为同一字符串，
        // 无任何 per-listener 信息，原逐条循环属死代码；改为输出监听器数量。
        tracing::info!("listener loaded: {} listener(s) registered", listeners.len());
        Self {
            listeners: Arc::new(RwLock::new(listeners)),
        }
    }

    /// 运行时注册监听器。
    ///
    /// 补充 `inventory` 编译期注册机制的不足：`AuditLogListener` 等需要运行时参数
    /// （如 `DbPool`）的监听器无法通过无参工厂函数注册，需通过此方法在初始化后追加。
    pub fn register(&self, listener: Arc<dyn GarrisonListener>) {
        self.listeners.write().push(listener);
    }

    /// 返回已注册监听器数量。
    pub fn count(&self) -> usize {
        self.listeners.read().len()
    }

    /// 广播事件到所有已注册监听器。
    ///
    /// 异步遍历所有监听器的 `on_event` 方法：
    /// - 单个监听器返回 `Err` 仅记录 `tracing::warn!`，不中断广播，最终返回 `Ok(())`；
    /// - 单个监听器 **panic** 同样被 `catch_unwind` 捕获并降级为 `tracing::warn!`
    ///   （ocr #2620：panic 不得传播出 `broadcast`，违背监听器隔离承诺），
    ///   后续监听器继续收到事件。
    ///
    /// panic 捕获在当前 task 内完成（非 spawn），`task_local` 上下文（如 `TENANT`）
    /// 对监听器仍然可见。
    ///
    /// v0.5.0 改为 async：`on_event` 改为 async 后，broadcast 需 `.await`。
    pub async fn broadcast(&self, event: &GarrisonEvent) {
        use futures::FutureExt;
        use std::panic::AssertUnwindSafe;

        let listeners = self.listeners.read().clone();
        for listener in &listeners {
            // AssertUnwindSafe：dyn GarrisonListener 不承诺 UnwindSafe，
            // 此处仅隔离 panic 不重入监听器，跨 catch_unwind 使用是安全的
            match AssertUnwindSafe(listener.on_event(event)).catch_unwind().await {
                Ok(Ok(())) => {},
                Ok(Err(e)) => tracing::warn!("listener on_event failed: {}", e),
                Err(panic_payload) => {
                    let msg = panic_payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    tracing::warn!("listener on_event panicked: {}", msg);
                },
            }
        }
    }
}

impl Default for GarrisonListenerManager {
    fn default() -> Self {
        Self::new()
    }
}
