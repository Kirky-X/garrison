//! 监听器模块，提供事件监听抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenListener`，
//! 提供登录、登出、权限校验等事件的通知回调。
//!
//! 此模块仅在启用 `listener` 特性时编译。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// 监听器 trait，定义框架事件回调。
///
/// [借鉴 Sa-Token] 对应 `SaTokenListener`，
/// 实现方可订阅登录、登出、权限校验等事件。
pub trait BulwarkListener: Send + Sync {
    /// 登录事件回调。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: 生成的 Token。
    fn on_login(&self, _login_id: i64, _token: &str) -> BulwarkResult<()> {
        todo!()
    }

    /// 登出事件回调。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    fn on_logout(&self, _login_id: i64) -> BulwarkResult<()> {
        todo!()
    }

    /// 权限校验事件回调。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `permission`: 被校验的权限。
    /// - `pass`: 是否通过。
    fn on_check_permission(
        &self,
        _login_id: i64,
        _permission: &str,
        _pass: bool,
    ) -> BulwarkResult<()> {
        todo!()
    }

    /// 角色校验事件回调。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `role`: 被校验的角色。
    /// - `pass`: 是否通过。
    fn on_check_role(&self, _login_id: i64, _role: &str, _pass: bool) -> BulwarkResult<()> {
        todo!()
    }
}
