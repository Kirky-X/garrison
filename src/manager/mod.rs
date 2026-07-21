//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 管理器模块，提供全局管理器单例与编译期工厂注册。
//!
//! 对应 `SaManager`，
//! 统筹 DAO、配置、策略等组件的全局生命周期。
//!
//! ## 设计
//!
//! - `GarrisonManager` 持有 `Arc<GarrisonLogicDefault>` 全局单例（基于 `parking_lot::RwLock` 支持重复 init）
//! - `GarrisonLogicFactory` trait 通过 `inventory::submit!` 编译期注册
//! - 业务方调用 `GarrisonManager::init(dao, config, interface)` 注入依赖
//! - `GarrisonUtil::login(id)` 等静态方法委托到 `GARRISON_MANAGER` 单例
//!
//! ## 初始化流程
//!
//! ```ignore
//! use std::sync::Arc;
//! use garrison::prelude::*;
//!
//! // 1. 准备依赖
//! let dao: Arc<dyn GarrisonDao> = /* oxcache 或 dbnexus 实现 */;
//! let config = Arc::new(GarrisonConfig::default_config());
//! let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);
//!
//! // 2. 初始化全局管理器
//! GarrisonManager::init(dao, config, interface).unwrap();
//!
//! // 3. 使用静态 API（task_local 上下文由 middleware 设置）
//! let token = GarrisonUtil::login_simple("1001").await.unwrap();
//! ```

use crate::stp::GarrisonLogicDefault;
use crate::strategy::Strategy;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::sync::Arc;
#[cfg(feature = "anomalous-detector-dual")]
use tokio::sync::watch;
use tokio::task::JoinHandle;

// 显式 Manager API
// 启用 manager-explicit feature 后提供不依赖全局单例的 Manager struct。
#[cfg(feature = "manager-explicit")]
pub mod explicit;

// 工厂子系统（GarrisonLogicFactoryContext / GarrisonLogicFactoryEntry / garrison_logic_factory_default）。
pub mod factory;
// GarrisonManager 实现块（含 Drop impl）与 factory selector 辅助函数。
pub mod impls;

// Re-export factory 公共 API（保持原 mod.rs 路径兼容，如 crate::manager::GarrisonLogicFactoryEntry）。
pub use factory::*;

/// 全局管理器，统筹 `GarrisonLogicDefault` 的生命周期。
///
/// 对应 `SaManager`，
/// 持有全局 `Arc<GarrisonLogicDefault>` 引用，提供静态方法入口。
///
/// # 初始化
///
/// 业务方启动时调用 `GarrisonManager::init(dao, config, interface)` 注入依赖。
/// 未初始化时调用 `GarrisonUtil::login(id)` 等返回 `GarrisonError::Session`。
pub struct GarrisonManager {
    /// 全局 `GarrisonLogicDefault` 引用（RwLock 支持测试时重复 init 与 reset）。
    logic: RwLock<Option<Arc<GarrisonLogicDefault>>>,
    /// 全局 Strategy 注册表引用。
    ///
    /// 外层 `RwLock` 管理 Option（初始化/重置），内层 `Arc<RwLock<Strategy>>`
    /// 允许运行时通过 `strategy.write().register_*()` 替换策略。
    strategy: RwLock<Option<Arc<RwLock<Strategy>>>>,
    /// 后台 cleanup task 的 JoinHandle（T030）。
    ///
    /// `init` 时若 `config.token_map_cleanup_interval_secs > 0` 则启动 task 并保存 handle。
    /// `reset_for_test` / `Drop` 时 abort task，避免后台线程在测试间或程序退出后残留。
    cleanup_task_handle: RwLock<Option<JoinHandle<()>>>,
    /// 异常登录分析器 task 的 JoinHandle（anomalous-detector-dual feature）。
    ///
    /// `init` 时若 `anomalous-detector-dual` feature 启用则启动 analyzer task 并保存 handle。
    /// `reset_for_test` / `Drop` 时 abort task，避免后台线程在测试间或程序退出后残留。
    #[cfg(feature = "anomalous-detector-dual")]
    anomalous_analyzer_handle: RwLock<Option<JoinHandle<()>>>,
    /// 异常登录分析器 shutdown 信号发送端（anomalous-detector-dual feature）。
    ///
    /// 保存 `shutdown_tx` 使其生命周期与 `GarrisonManager` 一致，
    /// 避免 `shutdown_rx` 因 sender drop 而误触发停止。
    /// `reset_for_test` / `Drop` 时 take 清空，触发 `shutdown_rx.changed()` 返回 Err 通知 task 退出。
    #[cfg(feature = "anomalous-detector-dual")]
    anomalous_analyzer_shutdown_tx: RwLock<Option<watch::Sender<bool>>>,
}

/// 全局管理器单例。
///
/// 通过 `once_cell::sync::Lazy` 实现懒加载，
/// 首次访问时调用 `GarrisonManager::new()`。
pub static GARRISON_MANAGER: Lazy<GarrisonManager> = Lazy::new(GarrisonManager::new);

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
