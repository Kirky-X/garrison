//! 管理器模块，提供全局管理器单例。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaManager`，
//! 统筹 DAO、配置、策略等组件的全局生命周期。

use crate::error::BulwarkResult;
use once_cell::sync::Lazy;

/// 全局管理器，负责统筹各组件生命周期。
///
/// [借鉴 Sa-Token] 对应 `SaManager`，
/// 持有 DAO、配置、策略等组件的全局引用。
pub struct BulwarkManager {
    /// 占位字段，实际持有各组件句柄。
    _inner: (),
}

impl BulwarkManager {
    /// 创建新的管理器实例。
    fn new() -> Self {
        Self { _inner: () }
    }

    /// 初始化管理器，注册各组件。
    pub fn init(&self) -> BulwarkResult<()> {
        todo!()
    }

    /// 获取全局配置。
    pub fn config(&self) -> BulwarkResult<&crate::config::BulwarkConfig> {
        todo!()
    }

    /// 获取全局 DAO。
    pub fn dao(&self) -> BulwarkResult<&dyn crate::dao::BulwarkDao> {
        todo!()
    }
}

/// 全局管理器单例。
///
/// 通过 `once_cell::sync::Lazy` 实现懒加载，
/// 首次访问时调用 `BulwarkManager::new()`。
pub static BULWARK_MANAGER: Lazy<BulwarkManager> = Lazy::new(BulwarkManager::new);
