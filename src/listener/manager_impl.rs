// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonListenerManager 实现块（从 mod.rs 迁移）。

use super::*;

impl GarrisonListenerManager {
    /// 创建监听器管理器并收集所有已注册监听器。
    pub fn new() -> Self {
        use std::iter::Iterator;
        let listeners: Vec<Arc<dyn GarrisonListener>> = inventory::iter::<GarrisonListenerEntry>()
            .map(|entry| (entry.factory)())
            .collect();
        // `type_name::<Arc<dyn GarrisonListener>>()` 对所有条目恒为同一字符串，
        // 无任何 per-listener 信息，原逐条循环属死代码；改为输出监听器数量。
        tracing::info!(
            "listener loaded: {} listener(s) registered",
            listeners.len()
        );
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
    ///   （panic 不得传播出 `broadcast`，违背监听器隔离承诺），
    ///   后续监听器继续收到事件。
    ///
    /// 单事件派发循环体（Immediately / OnCommit 两档共用）。
    ///
    /// 依序调用所有监听器的 `on_event`：
    /// - 返回 `true`：所有监听器均成功（全部 `Ok`）；
    /// - 返回 `false`：任一监听器返回 `Err` 或 **panic**（`catch_unwind` 捕获并
    ///   降级为 `tracing::warn!`），不中断，后续监听器继续收到事件。
    ///
    /// panic 捕获在当前 task 内完成（非 spawn），`task_local` 上下文（如 `TENANT`）
    /// 对监听器仍然可见。
    ///
    /// `on_event` 为 async，需 `.await`。
    pub(crate) async fn dispatch_one(&self, event: &GarrisonEvent) -> bool {
        use futures::FutureExt;
        use std::panic::AssertUnwindSafe;

        let listeners = self.listeners.read().clone();
        let mut dispatched = true;
        for listener in &listeners {
            // AssertUnwindSafe：dyn GarrisonListener 不承诺 UnwindSafe，
            // 此处仅隔离 panic 不重入监听器，跨 catch_unwind 使用是安全的
            match AssertUnwindSafe(listener.on_event(event))
                .catch_unwind()
                .await
            {
                Ok(Ok(())) => {},
                Ok(Err(e)) => {
                    tracing::warn!("listener on_event failed: {}", e);
                    dispatched = false;
                },
                Err(panic_payload) => {
                    let msg = panic_payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    tracing::warn!("listener on_event panicked: {}", msg);
                    dispatched = false;
                },
            }
        }
        dispatched
    }

    /// 广播事件到所有已注册监听器（Immediately 档）。
    ///
    /// 事件产生即派发，不与数据库事务绑定；单个监听器失败仅记录
    /// `tracing::warn!`，不中断、不返回计数。与 OnCommit 档
    /// （`broadcast_after_commit`）共用同一监听器集合与隔离承诺。
    ///
    /// `on_event` 为 async，broadcast 需 `.await`。
    pub async fn broadcast(&self, event: &GarrisonEvent) {
        let _ = self.dispatch_one(event).await;
    }

    /// 派发事件批次（OnCommit 档）：数据库事务 commit 成功后由
    /// `GarrisonEventTx` 调用。
    ///
    /// 按 FIFO 顺序逐个派发；与 Immediately 档共用 `dispatch_one` 的隔离承诺
    /// （单个监听器 `Err`/panic 不中断，后续监听器与后续事件继续处理）。
    /// 返回 [`DispatchOutcome`]：存在 `Err`/panic 的事件计入 `failed`
    /// （审计链缺口显性化，panic 同样计入），且
    /// `dispatched + failed == events.len()`。
    pub async fn broadcast_after_commit(&self, events: &[GarrisonEvent]) -> DispatchOutcome {
        let mut outcome = DispatchOutcome::default();
        for event in events {
            if self.dispatch_one(event).await {
                outcome.dispatched += 1;
            } else {
                outcome.failed += 1;
            }
        }
        outcome
    }
}

impl Default for GarrisonListenerManager {
    fn default() -> Self {
        Self::new()
    }
}
