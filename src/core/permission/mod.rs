//! 权限校验模块，定义权限 / 角色校验抽象。
//!
//! [借鉴 Sa-Token] 权限认证核心逻辑，对应 Sa-Token 的 `StpLogic.checkPermission / checkRole` 方法。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// 权限校验 trait，定义权限与角色检查抽象。
///
/// 实现方需提供具体的权限 / 角色数据查询逻辑。
pub trait PermissionChecker {
    /// 校验是否拥有指定权限。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    fn has_permission(&self, _permission: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 校验是否拥有指定角色。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    fn has_role(&self, _role: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 批量校验权限（全部满足）。
    ///
    /// # 参数
    /// - `permissions`: 权限标识列表。
    fn check_and_permission(&self, _permissions: &[&str]) -> BulwarkResult<()> {
        todo!()
    }

    /// 批量校验权限（任一满足）。
    ///
    /// # 参数
    /// - `permissions`: 权限标识列表。
    fn check_or_permission(&self, _permissions: &[&str]) -> BulwarkResult<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 占位实现结构体，仅用于触发 trait 默认方法的 todo!() panic。
    struct DummyPermissionChecker;

    impl PermissionChecker for DummyPermissionChecker {}

    /// 验证 `PermissionChecker::has_permission` 默认实现调用 `todo!()` 必 panic。
    /// Rust `todo!()` panic 消息为 "not yet implemented: ..."。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn permission_checker_has_permission_panics_with_todo() {
        let checker = DummyPermissionChecker;
        let _ = checker.has_permission("user:read");
    }

    /// 验证 `PermissionChecker::has_role` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn permission_checker_has_role_panics_with_todo() {
        let checker = DummyPermissionChecker;
        let _ = checker.has_role("admin");
    }

    /// 验证 `PermissionChecker::check_and_permission` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn permission_checker_check_and_permission_panics_with_todo() {
        let checker = DummyPermissionChecker;
        let _ = checker.check_and_permission(&["user:read", "user:write"]);
    }

    /// 验证 `PermissionChecker::check_or_permission` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn permission_checker_check_or_permission_panics_with_todo() {
        let checker = DummyPermissionChecker;
        let _ = checker.check_or_permission(&["user:read", "user:write"]);
    }
}
