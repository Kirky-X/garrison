//! 认证逻辑模块，定义登录 / 登出核心抽象。
//!
//! [借鉴 Sa-Token] 登录认证核心逻辑，对应 Sa-Token 的 `StpLogic.login / logout` 方法。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// 认证逻辑 trait，定义登录 / 登出 / 会话检查抽象。
///
/// 实现方需提供具体的登录态管理与 Token 生成逻辑。
pub trait AuthLogic {
    /// 执行登录操作，返回生成的 Token。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（如用户 ID）。
    fn login(&self, _id: i64) -> BulwarkResult<String> {
        todo!()
    }

    /// 执行登出操作，清除当前会话。
    fn logout(&self) -> BulwarkResult<()> {
        todo!()
    }

    /// 检查当前请求是否已登录。
    fn is_login(&self) -> BulwarkResult<bool> {
        todo!()
    }

    /// 获取当前登录主体标识。
    fn get_login_id(&self) -> BulwarkResult<Option<i64>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 占位实现结构体，仅用于触发 trait 默认方法的 todo!() panic。
    struct DummyAuthLogic;

    impl AuthLogic for DummyAuthLogic {}

    /// 验证 `AuthLogic::login` 默认实现调用 `todo!()` 必 panic。
    /// Rust `todo!()` panic 消息为 "not yet implemented: ..."。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn auth_logic_login_panics_with_todo() {
        let logic = DummyAuthLogic;
        let _ = logic.login(1001);
    }

    /// 验证 `AuthLogic::logout` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn auth_logic_logout_panics_with_todo() {
        let logic = DummyAuthLogic;
        let _ = logic.logout();
    }

    /// 验证 `AuthLogic::is_login` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn auth_logic_is_login_panics_with_todo() {
        let logic = DummyAuthLogic;
        let _ = logic.is_login();
    }

    /// 验证 `AuthLogic::get_login_id` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn auth_logic_get_login_id_panics_with_todo() {
        let logic = DummyAuthLogic;
        let _ = logic.get_login_id();
    }
}
