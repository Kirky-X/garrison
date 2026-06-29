//! 权限校验模块，定义权限 / 角色校验抽象。
//!
//! [借鉴 Sa-Token] 权限认证核心逻辑，对应 Sa-Token 的 `StpLogic.checkPermission / checkRole` 方法。

use crate::error::BulwarkResult;

/// 权限校验 trait，定义权限与角色检查抽象。
///
/// 实现方需提供具体的权限 / 角色数据查询逻辑。
pub trait PermissionChecker {
    /// 校验是否拥有指定权限。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    fn has_permission(&self, permission: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 校验是否拥有指定角色。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    fn has_role(&self, role: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 批量校验权限（全部满足）。
    ///
    /// # 参数
    /// - `permissions`: 权限标识列表。
    fn check_and_permission(&self, permissions: &[&str]) -> BulwarkResult<()> {
        todo!()
    }

    /// 批量校验权限（任一满足）。
    ///
    /// # 参数
    /// - `permissions`: 权限标识列表。
    fn check_or_permission(&self, permissions: &[&str]) -> BulwarkResult<()> {
        todo!()
    }
}
