//! 异常模块，定义框架异常类型。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的异常体系，
//! 提供细化异常类型与统一错误枚举。

use std::collections::HashMap;

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

/// 携带上下文的业务可恢复异常（0.2.0 新增）。
///
/// 与 `BulwarkError` enum 解耦，提供更丰富的异常上下文（token / login_id / extras）。
/// 业务方可通过 `BulwarkException::new(code, msg).with_token(t).build()` 链式构造，
/// 并通过 `Into<BulwarkError>` 转换为 `BulwarkError::Exception` 上抛。
///
/// [借鉴 Sa-Token] 对应 Sa-TokenException 的"携带上下文"语义。
#[derive(Debug, Clone)]
pub struct BulwarkException {
    /// 业务错误码（如 -1 表示未登录，依据 spec exception-system）。
    pub code: i32,

    /// 异常消息。
    pub message: String,

    /// 登录类型（如 1 表示账号登录，依据 spec exception-system）。
    pub login_type: i32,

    /// 关联的 token（可能为 `None`）。
    pub token_value: Option<String>,

    /// 关联的登录主体（可能为 `None`）。
    pub login_id: Option<i64>,

    /// 额外键值对上下文。
    pub extras: HashMap<String, String>,
}

impl BulwarkException {
    /// 创建基础异常实例（Builder 入口，依据 spec exception-system Requirement: Builder 模式构造）。
    ///
    /// # 参数
    /// - `code`: 业务错误码。
    /// - `message`: 异常消息。
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            login_type: 0,
            token_value: None,
            login_id: None,
            extras: HashMap::new(),
        }
    }
}

impl From<BulwarkException> for BulwarkError {
    /// 将 `BulwarkException` 转换为 `BulwarkError::Exception` 变体（依据 spec exception-system Requirement: BulwarkError 集成）。
    fn from(ex: BulwarkException) -> Self {
        BulwarkError::Exception(ex)
    }
}

impl std::fmt::Display for BulwarkException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "业务异常[{}]: {}", self.code, self.message)
    }
}

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

    // ========================================================================
    // BulwarkException 测试（依据 spec exception-system）
    // ========================================================================

    /// 验证 `BulwarkException::new` 创建实例并设置可选字段为默认值（依据 spec Scenario: 未设置的可选字段默认为 None）。
    #[test]
    fn bulwark_exception_new_creates_with_defaults() {
        let ex = BulwarkException::new(-1, "请先登录");
        assert_eq!(ex.code, -1);
        assert_eq!(ex.message, "请先登录");
        assert_eq!(ex.login_type, 0);
        assert_eq!(ex.token_value, None);
        assert_eq!(ex.login_id, None);
        assert!(ex.extras.is_empty());
    }

    /// 验证 `BulwarkException::new` 接受 String 类型消息。
    #[test]
    fn bulwark_exception_new_accepts_string() {
        let msg = String::from("会话已过期");
        let ex = BulwarkException::new(-1, msg);
        assert_eq!(ex.message, "会话已过期");
    }

    /// 验证 `BulwarkException` 派生 `Clone`（依据 spec Scenario: BulwarkException 派生 Debug 与 Clone）。
    #[test]
    fn bulwark_exception_clone_preserves_fields() {
        let mut ex = BulwarkException::new(-1, "请先登录");
        ex.token_value = Some("T1".to_string());
        ex.login_id = Some(1001);
        let cloned = ex.clone();
        assert_eq!(cloned.code, -1);
        assert_eq!(cloned.message, "请先登录");
        assert_eq!(cloned.token_value, Some("T1".to_string()));
        assert_eq!(cloned.login_id, Some(1001));
    }

    /// 验证 `BulwarkException` 派生 `Debug`（依据 spec Scenario: BulwarkException 派生 Debug 与 Clone）。
    #[test]
    fn bulwark_exception_debug_format_works() {
        let ex = BulwarkException::new(-1, "请先登录");
        let debug = format!("{:?}", ex);
        assert!(debug.contains("BulwarkException"));
        assert!(debug.contains("-1"));
        assert!(debug.contains("请先登录"));
    }

    /// 验证 `BulwarkException` 的 `Display` 输出格式。
    #[test]
    fn bulwark_exception_display_format() {
        let ex = BulwarkException::new(-1, "请先登录");
        assert_eq!(format!("{}", ex), "业务异常[-1]: 请先登录");
    }

    /// 验证 `BulwarkException` 通过 `From` 转换为 `BulwarkError::Exception`（依据 spec Scenario: BulwarkException 转换为 BulwarkError）。
    #[test]
    fn bulwark_exception_into_bulwark_error() {
        let ex = BulwarkException::new(-1, "请先登录");
        let err: BulwarkError = ex.into();
        assert!(matches!(err, BulwarkError::Exception(_)));
        if let BulwarkError::Exception(e) = err {
            assert_eq!(e.code, -1);
            assert_eq!(e.message, "请先登录");
        }
    }

    /// 验证既有 `BulwarkError` 变体不受 `Exception` 新增影响（依据 spec Scenario: 既有 BulwarkError 变体不受影响）。
    #[test]
    fn existing_bulwark_error_variants_unaffected() {
        let err = BulwarkError::NotLogin("请先登录".to_string());
        assert_eq!(err.to_string(), "未登录: 请先登录");
        // 确保新增 Exception 变体不破坏既有 match
        let errors: [BulwarkError; 2] = [
            BulwarkError::NotLogin("a".into()),
            BulwarkError::Exception(BulwarkException::new(-1, "b")),
        ];
        assert_eq!(errors.len(), 2);
    }
}
