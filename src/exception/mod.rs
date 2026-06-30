//! 异常模块，定义框架异常类型。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的异常体系，
//! 提供细化异常类型与统一错误枚举。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

/// 重导出 `crate::error::BulwarkError`，便于从异常模块统一访问。
pub use crate::error::BulwarkError;

/// 未登录异常，表示请求缺少有效登录态。
///
/// [借鉴 Sa-Token] 对应 `NotLoginException`。
#[derive(Debug, Clone)]
pub struct NotLoginException {
    /// 异常消息。
    pub message: String,

    /// 关联的登录类型（如 account / wechat 等）。
    pub login_type: String,
}

impl NotLoginException {
    /// 创建新的未登录异常。
    ///
    /// # 参数
    /// - `message`: 异常消息。
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            login_type: String::new(),
        }
    }

    /// 设置登录类型并返回 self（builder 模式）。
    ///
    /// # 参数
    /// - `login_type`: 登录类型。
    pub fn with_login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = login_type.into();
        self
    }
}

impl std::fmt::Display for NotLoginException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "未登录: {}", self.message)
    }
}

impl std::error::Error for NotLoginException {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 `NotLoginException::new` 创建实例并设置默认 login_type 为空字符串。
    #[test]
    fn new_creates_exception_with_empty_login_type() {
        let ex = NotLoginException::new("请先登录");
        assert_eq!(ex.message, "请先登录");
        assert_eq!(ex.login_type, "");
    }

    /// 验证 `NotLoginException::new` 接受 String 与 &str 等可转换类型。
    #[test]
    fn new_accepts_string() {
        let msg = String::from("会话已过期");
        let ex = NotLoginException::new(msg);
        assert_eq!(ex.message, "会话已过期");
    }

    /// 验证 `with_login_type` 设置 login_type 并返回 self（builder 模式）。
    #[test]
    fn with_login_type_sets_login_type() {
        let ex = NotLoginException::new("未登录").with_login_type("account");
        assert_eq!(ex.login_type, "account");
        assert_eq!(ex.message, "未登录");
    }

    /// 验证 `with_login_type` 接受 String 类型。
    #[test]
    fn with_login_type_accepts_string() {
        let lt = String::from("wechat");
        let ex = NotLoginException::new("未登录").with_login_type(lt);
        assert_eq!(ex.login_type, "wechat");
    }

    /// 验证 `Display` 实现输出 "未登录: {message}" 格式。
    #[test]
    fn display_formats_correctly() {
        let ex = NotLoginException::new("token 已过期");
        assert_eq!(format!("{}", ex), "未登录: token 已过期");
    }

    /// 验证 `NotLoginException` 实现 `std::error::Error` trait。
    #[test]
    fn implements_std_error() {
        fn assert_error<T: std::error::Error>(_: &T) {}
        let ex = NotLoginException::new("test");
        assert_error(&ex);
    }

    /// 验证 builder 链式调用：new + with_login_type。
    #[test]
    fn builder_chain_works() {
        let ex = NotLoginException::new("未登录").with_login_type("oauth2");
        assert_eq!(ex.message, "未登录");
        assert_eq!(ex.login_type, "oauth2");
    }
}
