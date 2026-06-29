//! Stp 模块，提供核心逻辑与工具入口。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `StpLogic` / `StpInterface` / `StpUtil` 三件套，
//! Bulwark 中统一使用 `Bulwark*` 前缀。

use crate::error::BulwarkResult;

/// 核心逻辑 trait，定义登录认证的完整行为契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic`，是框架最核心的抽象。
/// 实现方需集成认证、权限、会话等能力。
pub trait BulwarkLogic {
    /// 执行登录。
    ///
    /// # 参数
    /// - `id`: 登录主体标识。
    fn login(&self, id: i64) -> BulwarkResult<String> {
        todo!()
    }

    /// 执行登出。
    fn logout(&self) -> BulwarkResult<()> {
        todo!()
    }

    /// 检查登录状态。
    fn check_login(&self) -> BulwarkResult<()> {
        todo!()
    }

    /// 校验权限。
    ///
    /// # 参数
    /// - `permission`: 权限标识。
    fn check_permission(&self, permission: &str) -> BulwarkResult<()> {
        todo!()
    }

    /// 校验角色。
    ///
    /// # 参数
    /// - `role`: 角色标识。
    fn check_role(&self, role: &str) -> BulwarkResult<()> {
        todo!()
    }
}

/// 接口 trait，定义获取权限 / 角色数据的回调。
///
/// [借鉴 Sa-Token] 对应 `StpInterface`，由业务方实现以提供权限数据。
pub trait BulwarkInterface {
    /// 获取指定主体的权限列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        todo!()
    }

    /// 获取指定主体的角色列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        todo!()
    }
}

/// 工具结构体，提供静态方法入口。
///
/// [借鉴 Sa-Token] 对应 `StpUtil`，是面向使用者的便捷入口。
/// 内部委托给全局注册的 `BulwarkLogic` 实现。
pub struct BulwarkUtil;

impl BulwarkUtil {
    /// 执行登录。
    ///
    /// # 参数
    /// - `id`: 登录主体标识。
    pub fn login(id: i64) -> BulwarkResult<String> {
        todo!()
    }

    /// 执行登出。
    pub fn logout() -> BulwarkResult<()> {
        todo!()
    }

    /// 检查登录状态。
    pub fn check_login() -> BulwarkResult<()> {
        todo!()
    }
}
