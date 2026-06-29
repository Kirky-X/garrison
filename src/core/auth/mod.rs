//! 认证逻辑模块，定义登录 / 登出核心抽象。
//!
//! [借鉴 Sa-Token] 登录认证核心逻辑，对应 Sa-Token 的 `StpLogic.login / logout` 方法。

use crate::error::BulwarkResult;

/// 认证逻辑 trait，定义登录 / 登出 / 会话检查抽象。
///
/// 实现方需提供具体的登录态管理与 Token 生成逻辑。
pub trait AuthLogic {
    /// 执行登录操作，返回生成的 Token。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（如用户 ID）。
    fn login(&self, id: i64) -> BulwarkResult<String> {
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
