// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonManager` 的实现块（含 `Drop` impl）。
//!
//! 初始化职责在 [`crate::manager::builder`]（经 `GarrisonManager::builder()`），
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

    /// 获取全局 `GarrisonLogicDefault` 引用；未初始化返回 `GarrisonError::Session`。
    pub fn logic() -> GarrisonResult<Arc<GarrisonLogicDefault>> {
        GARRISON_MANAGER
            .logic
            .load_full()
            .ok_or_else(|| GarrisonError::Session("manager-not-init".to_string()))
    }

    /// 获取全局 `Strategy` 注册表引用（未初始化返回 `GarrisonError::Session`）。
    ///
    /// 返回 `Arc<RwLock<Strategy>>`，业务方可通过 `strategy.write().register_*()`
    /// 运行时替换策略，替换后立即生效（下次调用使用新策略）。
    pub fn strategy() -> GarrisonResult<Arc<RwLock<Strategy>>> {
        GARRISON_MANAGER
            .strategy
            .load_full()
            .ok_or_else(|| GarrisonError::Session("manager-not-init".to_string()))
    }

    /// 获取全局 `DisableRepository` 引用（未初始化返回 `None`）。
    ///
    /// `builder().build()` 时自动创建 `DefaultDisableRepository` 并注入到 `GarrisonLogicDefault`，
    /// 此方法从 logic 中读取封禁库实例，供业务方调用 `disable` / `untie_disable` /
    /// `is_disable` / `get_disable_time` / `get_disable_level`。
    ///
    /// # 示例
    /// ```ignore
    /// use garrison::prelude::*;
    ///
    /// if let Some(repo) = GarrisonManager::disable_repository() {
    /// repo.disable("user-1", "default", None, 0, 0).await.unwrap();
    /// }
    /// ```
    pub fn disable_repository() -> Option<Arc<dyn DisableRepository>> {
        Self::logic()
            .ok()
            .map(|logic| logic.disable_repository.clone())
    }

    /// 替换全局 `Strategy` 注册表。
    ///
    /// 用于运行时或测试时整体替换 Strategy 实例（如注入预配置的自定义策略集合）。
    /// 替换后立即生效，旧 Strategy 被 drop。
    pub fn with_strategy(strategy: Arc<RwLock<Strategy>>) -> GarrisonResult<()> {
        GARRISON_MANAGER.strategy.store(Some(strategy));
        Ok(())
    }

    /// 检查管理器是否已初始化（已 `builder().build()` 且单例持有 logic 与 strategy；
    /// 未初始化或已 `reset_for_test` 返回 false）。
    pub fn is_initialized() -> bool {
        GARRISON_MANAGER.logic.load().is_some() && GARRISON_MANAGER.strategy.load().is_some()
    }

    /// 重置管理器（仅供测试用，业务代码不应调用）：清空全局 `GarrisonLogicDefault` 与
    /// `Strategy` 引用，使后续 `GarrisonUtil::login(id)` 等返回未初始化错误。
    #[cfg(any(test, feature = "testing"))]
    pub fn reset_for_test() {
        // abort cleanup task 避免测试间残留后台线程
        if let Some(handle) = GARRISON_MANAGER.cleanup_task_handle.write().take() {
            handle.abort();
        }
        // abort anomalous analyzer task + 清空 shutdown_tx
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
        // manager drop 时 abort cleanup task，避免后台线程残留
        if let Some(handle) = self.cleanup_task_handle.write().take() {
            handle.abort();
        }
        // abort anomalous analyzer task + 清空 shutdown_tx
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if let Some(handle) = self.anomalous_analyzer_handle.write().take() {
                handle.abort();
            }
            self.anomalous_analyzer_shutdown_tx.write().take();
        }
    }
}
