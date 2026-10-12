// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonListenerManager 实现块（broadcast / dispatch_one 等）。

use super::*;

impl GarrisonListenerManager {
    /// 创建监听器管理器并收集所有已注册监听器。
    pub fn new() -> Self {
        use std::iter::Iterator;
        let listeners: Vec<Arc<dyn GarrisonListener>> = inventory::iter::<GarrisonListenerEntry>()
            .map(|entry| (entry.factory)())
            .collect();
        // 逐条日志对所有监听器恒为同一字符串（无 per-listener 信息），故只输出数量
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

    /// 单事件派发循环体（Immediately / OnCommit 两档共用）。
    ///
    /// 返回 `true` 表示所有监听器均成功（全部 `Ok`）；监听器 `Err` 或 panic 均被
    /// `catch_unwind` 捕获并降级为 `tracing::warn!`，不中断、不传播，后续监听器
    /// 继续收到事件。panic 捕获在当前 task 内完成（非 spawn），`task_local` 上下文
    /// （如 `TENANT`）对监听器仍然可见。
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
    /// 事件产生即派发，不与数据库事务绑定；单个监听器失败仅 `tracing::warn!`，
    /// 不中断、不返回计数。与 OnCommit 档（`broadcast_after_commit`）共用同一
    /// 监听器集合与隔离承诺。
    pub async fn broadcast(&self, event: &GarrisonEvent) {
        let _ = self.dispatch_one(event).await;
    }

    /// 派发事件批次（OnCommit 档）：数据库事务 commit 成功后由 `GarrisonEventTx`
    /// 按 FIFO 顺序调用。
    ///
    /// 返回 [`DispatchOutcome`]：`Err`/panic 事件计入 `failed`（审计链缺口显性化），
    /// `dispatched + failed == events.len()`；隔离承诺同 Immediately 档。
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
