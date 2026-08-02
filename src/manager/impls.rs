//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonManager` 的实现块（含 `Drop` impl）。
//!
//! 本文件从 `mod.rs` 迁移而来，遵循 mod-crate-hardening（规则 25）：
//! `mod.rs` 仅保留 trait 定义、pub struct/enum、pub type alias、pub use、mod 声明。
//!
//! 初始化职责已迁移至 [`crate::manager::builder`]（`GarrisonManager::builder()`），
//! 本文件仅保留单例状态读取与测试重置相关方法。

use crate::account::disable::DisableRepository;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::GarrisonLogicDefault;
use crate::strategy::Strategy;
use arc_swap::ArcSwapOption;
use parking_lot::RwLock;
use std::sync::Arc;

use super::{GarrisonManager, GARRISON_MANAGER};

impl GarrisonManager {
    /// 创建空的管理器实例（仅用于 GARRISON_MANAGER 单例初始化）。
    pub(super) fn new() -> Self {
        Self {
            logic: ArcSwapOption::empty(),
            strategy: ArcSwapOption::empty(),
            cleanup_task_handle: RwLock::new(None),
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_handle: RwLock::new(None),
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_shutdown_tx: RwLock::new(None),
        }
    }

    /// 获取全局 `GarrisonLogicDefault` 引用。
    ///
    /// # 返回
    /// 已初始化时返回 `Arc<GarrisonLogicDefault>`。
    ///
    /// # 错误
    /// - 若未初始化，返回 `GarrisonError::Session("GarrisonManager 未初始化")`。
    pub fn logic() -> GarrisonResult<Arc<GarrisonLogicDefault>> {
        GARRISON_MANAGER
            .logic
            .load_full()
            .ok_or_else(|| GarrisonError::Session("manager-not-init".to_string()))
    }

    /// 获取全局 `Strategy` 注册表引用。
    ///
    /// 返回 `Arc<RwLock<Strategy>>`，业务方可通过 `strategy.write().register_*()`
    /// 运行时替换策略，替换后立即生效（下次调用使用新策略）。
    ///
    /// # 返回
    /// 已初始化时返回 `Arc<RwLock<Strategy>>`。
    ///
    /// # 错误
    /// - 若未初始化，返回 `GarrisonError::Session("GarrisonManager 未初始化")`。
    pub fn strategy() -> GarrisonResult<Arc<RwLock<Strategy>>> {
        GARRISON_MANAGER
            .strategy
            .load_full()
            .ok_or_else(|| GarrisonError::Session("manager-not-init".to_string()))
    }

    /// 获取全局 `DisableRepository` 引用（v0.6.5 T020）。
    ///
    /// `builder().build()` 时自动创建 `DefaultDisableRepository` 并注入到 `GarrisonLogicDefault`，
    /// 此方法从 logic 中读取封禁库实例，供业务方调用 `disable` / `untie_disable` /
    /// `is_disable` / `get_disable_time` / `get_disable_level`。
    ///
    /// # 返回
    /// - `Some(Arc<dyn DisableRepository>)`: 已初始化且 disable_repository 已注册。
    /// - `None`: 未初始化或未注册（向后兼容场景）。
    ///
    /// # 示例
    /// ```ignore
    /// use garrison::prelude::*;
    ///
    /// if let Some(repo) = GarrisonManager::disable_repository() {
    ///     repo.disable("user-1", "default", None, 0, 0).await.unwrap();
    /// }
    /// ```
    pub fn disable_repository() -> Option<Arc<dyn DisableRepository>> {
        Self::logic()
            .ok()
            .and_then(|logic| logic.disable_repository.clone())
    }

    /// 替换全局 `Strategy` 注册表。
    ///
    /// 用于运行时或测试时整体替换 Strategy 实例（如注入预配置的自定义策略集合）。
    /// 替换后立即生效，旧 Strategy 被 drop。
    ///
    /// # 参数
    /// - `strategy`: 新的 `Arc<RwLock<Strategy>>` 实例。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    pub fn with_strategy(strategy: Arc<RwLock<Strategy>>) -> GarrisonResult<()> {
        GARRISON_MANAGER.strategy.store(Some(strategy));
        Ok(())
    }

    /// 检查管理器是否已初始化。
    ///
    /// # 返回
    /// - `true`: 已通过 `builder().build()` 初始化且全局单例持有 `GarrisonLogicDefault`。
    /// - `false`: 未初始化或已 `reset_for_test`。
    pub fn is_initialized() -> bool {
        GARRISON_MANAGER.logic.load().is_some()
    }

    /// 重置管理器（仅供测试用，业务代码不应调用）。
    ///
    /// 清空全局 `GarrisonLogicDefault` 与 `Strategy` 引用，
    /// 使后续 `GarrisonUtil::login(id)` 等返回未初始化错误。
    #[cfg(any(test, feature = "testing"))]
    pub fn reset_for_test() {
        // T030: abort cleanup task 避免测试间残留后台线程
        if let Some(handle) = GARRISON_MANAGER.cleanup_task_handle.write().take() {
            handle.abort();
        }
        // T023: abort anomalous analyzer task + 清空 shutdown_tx
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if let Some(handle) = GARRISON_MANAGER.anomalous_analyzer_handle.write().take() {
                handle.abort();
            }
            GARRISON_MANAGER
                .anomalous_analyzer_shutdown_tx
                .write()
                .take();
        }
        GARRISON_MANAGER.logic.store(None);
        GARRISON_MANAGER.strategy.store(None);
    }
}

impl Drop for GarrisonManager {
    fn drop(&mut self) {
        // T030: manager drop 时 abort cleanup task，避免后台线程残留
        if let Some(handle) = self.cleanup_task_handle.write().take() {
            handle.abort();
        }
        // T023: abort anomalous analyzer task + 清空 shutdown_tx
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if let Some(handle) = self.anomalous_analyzer_handle.write().take() {
                handle.abort();
            }
            self.anomalous_analyzer_shutdown_tx.write().take();
        }
    }
}
