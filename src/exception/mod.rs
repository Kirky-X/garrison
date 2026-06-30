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
