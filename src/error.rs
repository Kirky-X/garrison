//! 错误类型定义模块。
//!
//! [借鉴 Sa-Token] Sa-TokenException 异常体系，提供框架统一的错误类型与 Result 别名。

use crate::exception::BulwarkException;
use thiserror::Error;

/// Bulwark 框架统一错误类型。
///
/// 涵盖登录、权限、Token、DAO、配置等各层错误场景。
///
/// # Display 行为
///
/// - 未启用 `i18n` feature：硬编码中文（与 0.2.x 行为一致）
/// - 启用 `i18n` feature：依据线程本地 locale 切换中英文（详见 [`crate::i18n`]）
#[derive(Debug, Error)]
pub enum BulwarkError {
    /// 未登录异常（对应 Sa-Token NotLoginException）。
    NotLogin(String),

    /// 无权限异常（对应 Sa-Token NotPermissionException）。
    NotPermission(String),

    /// 无角色异常（对应 Sa-Token NotRoleException）。
    NotRole(String),

    /// Token 无效异常。
    InvalidToken(String),

    /// Token 已过期异常。
    ExpiredToken(String),

    /// DAO 层错误。
    Dao(String),

    /// 配置错误。
    Config(String),

    /// 内部错误。
    Internal(String),

    /// 会话错误（对应会话创建/查询/过期/续期等场景）。
    Session(String),

    /// 注解错误（对应注解校验失败、组合冲突等场景）。
    Annotation(String),

    /// 上下文错误（对应 BulwarkContext / Request / Response / Storage 异常）。
    Context(String),

    /// 业务异常（携带上下文的可恢复异常，0.2.0 新增，依据 spec exception-system）。
    Exception(BulwarkException),

    /// OAuth2 协议错误（0.2.0 新增，依据 spec protocol-oauth2）。
    OAuth2(String),

    /// 网络错误（0.2.0 新增，依据 spec protocol-oauth2）。
    Network(String),

    /// 参数无效错误（0.2.0 新增，依据 spec protocol-oauth2）。
    InvalidParam(String),

    /// 功能未实现（0.2.0 新增，依据 spec core-auth-api：default 实现返回此错误）。
    NotImplemented(String),
}

// ============================================================================
// Display 实现：依据 i18n feature 切换硬编码中文 / fluent-rs 多语言
// ============================================================================

/// 启用 `i18n` feature 时：委托 `i18n::translate_error` 依据当前 locale 翻译。
#[cfg(feature = "i18n")]
impl std::fmt::Display for BulwarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::translate_error(self))
    }
}

/// 未启用 `i18n` feature 时：硬编码中文（与 0.2.x 行为一致，向后兼容）。
#[cfg(not(feature = "i18n"))]
impl std::fmt::Display for BulwarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulwarkError::NotLogin(s) => write!(f, "未登录: {}", s),
            BulwarkError::NotPermission(s) => write!(f, "无权限: {}", s),
            BulwarkError::NotRole(s) => write!(f, "无角色: {}", s),
            BulwarkError::InvalidToken(s) => write!(f, "Token 无效: {}", s),
            BulwarkError::ExpiredToken(s) => write!(f, "Token 已过期: {}", s),
            BulwarkError::Dao(s) => write!(f, "DAO 错误: {}", s),
            BulwarkError::Config(s) => write!(f, "配置错误: {}", s),
            BulwarkError::Internal(s) => write!(f, "内部错误: {}", s),
            BulwarkError::Session(s) => write!(f, "会话错误: {}", s),
            BulwarkError::Annotation(s) => write!(f, "注解错误: {}", s),
            BulwarkError::Context(s) => write!(f, "上下文错误: {}", s),
            BulwarkError::OAuth2(s) => write!(f, "OAuth2 错误: {}", s),
            BulwarkError::Network(s) => write!(f, "网络错误: {}", s),
            BulwarkError::InvalidParam(s) => write!(f, "参数无效: {}", s),
            BulwarkError::NotImplemented(s) => write!(f, "未实现: {}", s),
            BulwarkError::Exception(ex) => write!(f, "业务异常[{}]: {}", ex.code, ex.message),
        }
    }
}

/// Bulwark 框架统一 Result 类型别名。
pub type BulwarkResult<T> = Result<T, BulwarkError>;

// ============================================================================
// response_parts：框架无关的响应分片（0.3.0 新增，依据 spec web-adapters）
// ============================================================================

impl BulwarkError {
    /// 返回 HTTP 响应分片 `(status_code, error_code, message, exception_code)`。
    ///
    /// 框架无关方法，axum / actix-web / warp 适配器均复用此方法以保证三框架行为一致性
    /// （依据 spec web-adapters Requirement: 适配器行为一致性）。
    ///
    /// # 返回
    /// - `status_code`: HTTP 状态码（401/403/500/502/400/501）。
    /// - `error_code`: 结构化错误码字符串（如 `"NOT_LOGIN"`）。
    /// - `message`: 通用错误消息（不泄漏内部细节）。
    /// - `exception_code`: 仅 `Exception` 变体返回 `Some(code)`，其他变体返回 `None`。
    ///
    /// # 安全性
    ///
    /// 返回的 `message` 仅暴露通用描述（如 "未登录"），完整错误通过 `tracing::error!` 记录。
    pub fn response_parts(&self) -> (u16, &'static str, &'static str, Option<i32>) {
        match &self {
            BulwarkError::NotLogin(_) => (401, "NOT_LOGIN", "未登录", None),
            BulwarkError::InvalidToken(_) => (401, "INVALID_TOKEN", "Token 无效", None),
            BulwarkError::ExpiredToken(_) => (401, "EXPIRED_TOKEN", "Token 已过期", None),
            BulwarkError::NotPermission(_) => (403, "NOT_PERMISSION", "无权限", None),
            BulwarkError::NotRole(_) => (403, "NOT_ROLE", "无角色", None),
            BulwarkError::Dao(_) => (500, "DAO_ERROR", "数据访问错误", None),
            BulwarkError::Config(_) => (500, "CONFIG_ERROR", "配置错误", None),
            BulwarkError::Internal(_) => (500, "INTERNAL_ERROR", "内部错误", None),
            BulwarkError::Session(_) => (500, "SESSION_ERROR", "会话错误", None),
            BulwarkError::Annotation(_) => (500, "ANNOTATION_ERROR", "注解错误", None),
            BulwarkError::Context(_) => (500, "CONTEXT_ERROR", "上下文错误", None),
            BulwarkError::OAuth2(_) => (500, "OAUTH2_ERROR", "OAuth2 错误", None),
            BulwarkError::Network(_) => (502, "NETWORK_ERROR", "网络错误", None),
            BulwarkError::InvalidParam(_) => (400, "INVALID_PARAM", "参数无效", None),
            BulwarkError::NotImplemented(_) => (501, "NOT_IMPLEMENTED", "未实现", None),
            // Exception 依据 BulwarkException.code 字段映射状态码
            // code = -1 → 未登录 → 401；code = -2 → 无权限 → 403；其他 → 500
            BulwarkError::Exception(ex) => {
                let (status, error_code, message) = match ex.code {
                    -1 => (401, "NOT_LOGIN", "未登录"),
                    -2 => (403, "NOT_PERMISSION", "无权限"),
                    _ => (500, "EXCEPTION", "业务异常"),
                };
                (status, error_code, message, Some(ex.code))
            },
        }
    }

    /// 构造 JSON 响应体（框架无关）。
    ///
    /// 返回 `serde_json::Value`，由各框架适配器自行序列化为响应 body。
    /// `Exception` 变体额外包含 `code` 字段。
    pub fn to_json_body(&self) -> serde_json::Value {
        let (_, error_code, message, ex_code) = self.response_parts();
        let mut body = serde_json::json!({
            "error_code": error_code,
            "message": message,
        });
        if let Some(code) = ex_code {
            body["code"] = serde_json::json!(code);
        }
        body
    }
}

// ============================================================================
// IntoResponse 实现（cfg feature = "web-axum"）
// ============================================================================

/// 实现 `IntoResponse` 以便 extractor 的 `Rejection = BulwarkError` 可直接作为 axum 响应返回。
///
/// 状态码映射：
/// - `NotLogin` / `InvalidToken` / `ExpiredToken` → 401 Unauthorized
/// - `NotPermission` / `NotRole` → 403 Forbidden
/// - 其他 → 500 Internal Server Error
///
/// # 安全性
///
/// 响应体仅暴露结构化错误码 + 通用消息（不泄漏内部错误细节）；
/// 完整错误通过 `tracing::error!` 记录到日志（依据 codebase-hardening Task 0.4）。
#[cfg(feature = "web-axum")]
impl axum::response::IntoResponse for BulwarkError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        // 完整错误记录到日志（不返回给客户端）
        tracing::error!(error = ?self, "bulwark rejection");

        // 0.3.0：复用 response_parts() 保证三框架行为一致（依据 spec web-adapters）
        let (status_code, _, _, _) = self.response_parts();
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::Json(self.to_json_body());
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 Session 变体的 Display 输出包含原始消息。
    #[test]
    fn session_variant_display_includes_message() {
        let err = BulwarkError::Session("会话已过期".to_string());
        assert_eq!(err.to_string(), "会话错误: 会话已过期");
    }

    /// 验证 Annotation 变体的 Display 输出包含原始消息。
    #[test]
    fn annotation_variant_display_includes_message() {
        let err = BulwarkError::Annotation("注解校验失败".to_string());
        assert_eq!(err.to_string(), "注解错误: 注解校验失败");
    }

    /// 验证 Context 变体的 Display 输出包含原始消息。
    #[test]
    fn context_variant_display_includes_message() {
        let err = BulwarkError::Context("上下文缺失".to_string());
        assert_eq!(err.to_string(), "上下文错误: 上下文缺失");
    }

    /// 验证新增变体可通过 BulwarkResult 传播。
    #[test]
    fn new_variants_propagate_via_result() {
        fn fallible() -> BulwarkResult<()> {
            Err(BulwarkError::Session("测试".to_string()))
        }
        let result = fallible();
        assert!(matches!(result, Err(BulwarkError::Session(_))));
    }

    /// 验证新增变体与已有变体共存于同一枚举。
    #[test]
    fn new_variants_coexist_with_existing() {
        let errors = [
            BulwarkError::NotLogin("a".to_string()),
            BulwarkError::Session("b".to_string()),
            BulwarkError::Annotation("c".to_string()),
            BulwarkError::Context("d".to_string()),
        ];
        assert_eq!(errors.len(), 4);
    }

    // ========================================================================
    // BulwarkResult 类型别名与 IntoResponse 实现测试
    // ========================================================================

    /// 验证 `BulwarkResult` 类型别名可用于返回 Ok 值。
    ///
    /// 覆盖 `pub type BulwarkResult<T> = Result<T, BulwarkError>;` 的使用。
    #[test]
    fn bulwark_result_ok_carries_value() {
        fn ok_fn() -> BulwarkResult<i32> {
            Ok(42)
        }
        assert_eq!(ok_fn().unwrap(), 42);
    }

    /// 验证 `BulwarkResult` 类型别名可用于返回 Err 值，且 `?` 可透传错误。
    ///
    /// 覆盖 `pub type BulwarkResult<T> = Result<T, BulwarkError>;` 在错误传播路径中的使用。
    #[test]
    fn bulwark_result_err_propagates_via_question_mark() {
        fn inner() -> BulwarkResult<()> {
            Err(BulwarkError::Dao("db down".to_string()))
        }
        fn outer() -> BulwarkResult<()> {
            inner()?;
            Ok(())
        }
        assert!(matches!(outer(), Err(BulwarkError::Dao(_))));
    }

    /// 验证 Dao 变体的 Display 输出包含原始消息。
    #[test]
    fn dao_variant_display_includes_message() {
        let err = BulwarkError::Dao("连接失败".to_string());
        assert_eq!(err.to_string(), "DAO 错误: 连接失败");
    }

    /// 验证 Config 变体的 Display 输出包含原始消息。
    #[test]
    fn config_variant_display_includes_message() {
        let err = BulwarkError::Config("配置非法".to_string());
        assert_eq!(err.to_string(), "配置错误: 配置非法");
    }

    /// 验证 InvalidToken 变体的 Display 输出包含原始消息。
    #[test]
    fn invalid_token_variant_display_includes_message() {
        let err = BulwarkError::InvalidToken("格式错误".to_string());
        assert_eq!(err.to_string(), "Token 无效: 格式错误");
    }

    /// 验证 ExpiredToken 变体的 Display 输出包含原始消息。
    #[test]
    fn expired_token_variant_display_includes_message() {
        let err = BulwarkError::ExpiredToken("已过期".to_string());
        assert_eq!(err.to_string(), "Token 已过期: 已过期");
    }

    /// 验证 NotPermission 变体的 Display 输出包含原始消息。
    #[test]
    fn not_permission_variant_display_includes_message() {
        let err = BulwarkError::NotPermission("无权限".to_string());
        assert_eq!(err.to_string(), "无权限: 无权限");
    }

    /// 验证 NotRole 变体的 Display 输出包含原始消息。
    #[test]
    fn not_role_variant_display_includes_message() {
        let err = BulwarkError::NotRole("无角色".to_string());
        assert_eq!(err.to_string(), "无角色: 无角色");
    }

    /// 验证 NotLogin 变体的 Display 输出包含原始消息。
    #[test]
    fn not_login_variant_display_includes_message() {
        let err = BulwarkError::NotLogin("请先登录".to_string());
        assert_eq!(err.to_string(), "未登录: 请先登录");
    }

    /// 验证 Internal 变体的 Display 输出包含原始消息。
    #[test]
    fn internal_variant_display_includes_message() {
        let err = BulwarkError::Internal("内部错误".to_string());
        assert_eq!(err.to_string(), "内部错误: 内部错误");
    }

    // ========================================================================
    // IntoResponse 实现测试（cfg feature = "web-axum"）
    // ========================================================================

    /// 验证 Dao 错误映射为 500 Internal Server Error。
    ///
    /// 覆盖 `IntoResponse for BulwarkError` 的 `_ =>` 分支（Dao 变体）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn dao_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Dao("db down".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 验证 Config 错误映射为 500 Internal Server Error。
    ///
    /// 覆盖 `IntoResponse for BulwarkError` 的 `_ =>` 分支（Config 变体）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn config_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Config("invalid".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 验证 Annotation 错误映射为 500 Internal Server Error。
    ///
    /// 覆盖 `IntoResponse for BulwarkError` 的 `_ =>` 分支（Annotation 变体）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn annotation_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Annotation("conflict".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 验证 Context 错误映射为 500 Internal Server Error。
    ///
    /// 覆盖 `IntoResponse for BulwarkError` 的 `_ =>` 分支（Context 变体）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn context_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Context("missing".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ========================================================================
    // 鉴权错误状态码映射测试（依据 codebase-hardening Task 3.1-3.5）
    // ========================================================================

    /// 验证 NotLogin 错误映射为 401 Unauthorized（依据 codebase-hardening Task 3.1）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn not_login_error_returns_401() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::NotLogin("请先登录".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// 验证 NotPermission 错误映射为 403 Forbidden（依据 codebase-hardening Task 3.2）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn not_permission_error_returns_403() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::NotPermission("无权限".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// 验证 InvalidToken 错误映射为 401 Unauthorized（依据 codebase-hardening Task 3.3）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn invalid_token_returns_401() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::InvalidToken("格式错误".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// 验证 ExpiredToken 错误映射为 401 Unauthorized（依据 codebase-hardening Task 3.4）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn expired_token_returns_401() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::ExpiredToken("已过期".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// 验证 NotRole 错误映射为 403 Forbidden（依据 codebase-hardening Task 3.5）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn not_role_returns_403() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::NotRole("无角色".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ========================================================================
    // Exception 变体测试（依据 spec exception-system Requirement: IntoResponse 实现）
    // ========================================================================

    /// 验证 Exception 变体的 Display 输出（委托给 BulwarkException::Display）。
    #[test]
    fn exception_variant_display_includes_code_and_message() {
        use crate::exception::BulwarkException;
        let err = BulwarkError::Exception(BulwarkException::new(-1, "请先登录"));
        assert_eq!(err.to_string(), "业务异常[-1]: 请先登录");
    }

    /// 验证 code=-1 的 Exception 映射为 401 Unauthorized（依据 spec Scenario: 未登录异常返回 401 JSON）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn exception_not_login_returns_401() {
        use crate::exception::BulwarkException;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Exception(BulwarkException::new(-1, "请先登录"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// 验证 code=-2 的 Exception 映射为 403 Forbidden（依据 spec Scenario: 无权限异常返回 403 JSON）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn exception_not_permission_returns_403() {
        use crate::exception::BulwarkException;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Exception(BulwarkException::new(-2, "无权限"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// 验证其他 code 的 Exception 映射为 500 Internal Server Error（依据 spec Scenario: 其他异常返回 500 JSON）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn exception_other_code_returns_500() {
        use crate::exception::BulwarkException;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Exception(BulwarkException::new(500, "业务异常"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ========================================================================
    // 补充测试：覆盖剩余 IntoResponse 分支 + Display 变体（0.2.1 覆盖率提升）
    // ========================================================================

    /// 验证 Internal 错误映射为 500 Internal Server Error。
    #[cfg(feature = "web-axum")]
    #[test]
    fn internal_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Internal("内部错误".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 验证 Session 错误映射为 500 Internal Server Error。
    #[cfg(feature = "web-axum")]
    #[test]
    fn session_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Session("会话过期".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 验证 OAuth2 错误映射为 500 Internal Server Error。
    #[cfg(feature = "web-axum")]
    #[test]
    fn oauth2_error_returns_500() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::OAuth2("授权失败".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// 验证 Network 错误映射为 502 Bad Gateway。
    #[cfg(feature = "web-axum")]
    #[test]
    fn network_error_returns_502() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::Network("连接超时".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    /// 验证 InvalidParam 错误映射为 400 Bad Request。
    #[cfg(feature = "web-axum")]
    #[test]
    fn invalid_param_returns_400() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::InvalidParam("参数缺失".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// 验证 NotImplemented 错误映射为 501 Not Implemented。
    #[cfg(feature = "web-axum")]
    #[test]
    fn not_implemented_returns_501() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::NotImplemented("功能未实现".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// 验证 OAuth2 变体的 Display 输出包含原始消息。
    #[test]
    fn oauth2_variant_display_includes_message() {
        let err = BulwarkError::OAuth2("授权码无效".to_string());
        assert_eq!(err.to_string(), "OAuth2 错误: 授权码无效");
    }

    /// 验证 Network 变体的 Display 输出包含原始消息。
    #[test]
    fn network_variant_display_includes_message() {
        let err = BulwarkError::Network("DNS 解析失败".to_string());
        assert_eq!(err.to_string(), "网络错误: DNS 解析失败");
    }

    /// 验证 InvalidParam 变体的 Display 输出包含原始消息。
    #[test]
    fn invalid_param_variant_display_includes_message() {
        let err = BulwarkError::InvalidParam("client_id 为空".to_string());
        assert_eq!(err.to_string(), "参数无效: client_id 为空");
    }

    /// 验证 NotImplemented 变体的 Display 输出包含原始消息。
    #[test]
    fn not_implemented_variant_display_includes_message() {
        let err = BulwarkError::NotImplemented("refresh_token 未实现".to_string());
        assert_eq!(err.to_string(), "未实现: refresh_token 未实现");
    }

    // ========================================================================
    // 覆盖率补充：to_json_body / response_parts / Exception 变体
    // ========================================================================

    /// 验证 `to_json_body` 对普通错误变体返回包含 error_code 和 message 的 JSON。
    ///
    /// 覆盖行 163-164（to_json_body 中的 json! 宏构造）。
    #[test]
    fn to_json_body_returns_error_code_and_message() {
        let err = BulwarkError::NotLogin("token missing".to_string());
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "NOT_LOGIN");
        assert_eq!(body["message"], "未登录");
        // 普通错误变体不应包含 code 字段
        assert!(body.get("code").is_none(), "普通错误变体不应包含 code 字段");
    }

    /// 验证 `to_json_body` 对 Exception 变体额外包含 code 字段。
    ///
    /// 覆盖行 166-168（Exception 变体的 code 字段写入）。
    #[test]
    fn to_json_body_includes_code_for_exception_variant() {
        let err = BulwarkError::Exception(crate::exception::BulwarkException {
            code: 1001,
            message: "自定义业务异常".to_string(),
            login_type: 1,
            token_value: None,
            login_id: None,
            extras: std::collections::HashMap::new(),
        });
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "EXCEPTION");
        assert_eq!(body["code"], 1001);
    }

    /// 验证 `response_parts` 对各变体返回正确的 HTTP 状态码和错误码。
    #[test]
    fn response_parts_returns_correct_status_and_code() {
        // NotLogin → 401
        let (status, code, _, _) = BulwarkError::NotLogin("".to_string()).response_parts();
        assert_eq!(status, 401);
        assert_eq!(code, "NOT_LOGIN");

        // NotPermission → 403
        let (status, code, _, _) = BulwarkError::NotPermission("".to_string()).response_parts();
        assert_eq!(status, 403);
        assert_eq!(code, "NOT_PERMISSION");

        // Dao → 500
        let (status, code, _, _) = BulwarkError::Dao("".to_string()).response_parts();
        assert_eq!(status, 500);
        assert_eq!(code, "DAO_ERROR");

        // NotImplemented → 501
        let (status, code, _, _) = BulwarkError::NotImplemented("".to_string()).response_parts();
        assert_eq!(status, 501);
        assert_eq!(code, "NOT_IMPLEMENTED");
    }
}
