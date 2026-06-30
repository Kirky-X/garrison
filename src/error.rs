//! 错误类型定义模块。
//!
//! [借鉴 Sa-Token] Sa-TokenException 异常体系，提供框架统一的错误类型与 Result 别名。

use thiserror::Error;

/// Bulwark 框架统一错误类型。
///
/// 涵盖登录、权限、Token、DAO、配置等各层错误场景。
#[derive(Debug, Error)]
pub enum BulwarkError {
    /// 未登录异常（对应 Sa-Token NotLoginException）。
    #[error("未登录: {0}")]
    NotLogin(String),

    /// 无权限异常（对应 Sa-Token NotPermissionException）。
    #[error("无权限: {0}")]
    NotPermission(String),

    /// 无角色异常（对应 Sa-Token NotRoleException）。
    #[error("无角色: {0}")]
    NotRole(String),

    /// Token 无效异常。
    #[error("Token 无效: {0}")]
    InvalidToken(String),

    /// Token 已过期异常。
    #[error("Token 已过期: {0}")]
    ExpiredToken(String),

    /// DAO 层错误。
    #[error("DAO 错误: {0}")]
    Dao(String),

    /// 配置错误。
    #[error("配置错误: {0}")]
    Config(String),

    /// 内部错误。
    #[error("内部错误: {0}")]
    Internal(String),

    /// 会话错误（对应会话创建/查询/过期/续期等场景）。
    #[error("会话错误: {0}")]
    Session(String),

    /// 注解错误（对应注解校验失败、组合冲突等场景）。
    #[error("注解错误: {0}")]
    Annotation(String),

    /// 上下文错误（对应 BulwarkContext / Request / Response / Storage 异常）。
    #[error("上下文错误: {0}")]
    Context(String),
}

/// Bulwark 框架统一 Result 类型别名。
pub type BulwarkResult<T> = Result<T, BulwarkError>;

// ============================================================================
// IntoResponse 实现（cfg feature = "web-axum"）
// ============================================================================

/// 实现 `IntoResponse` 以便 extractor 的 `Rejection = BulwarkError` 可直接作为 axum 响应返回。
///
/// 状态码映射：
/// - `NotLogin` / `InvalidToken` / `ExpiredToken` → 401 Unauthorized
/// - `NotPermission` / `NotRole` → 403 Forbidden
/// - 其他 → 500 Internal Server Error
#[cfg(feature = "web-axum")]
impl axum::response::IntoResponse for BulwarkError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        #[allow(unused_imports)]
        use axum::response::IntoResponse as _;

        let status = match &self {
            BulwarkError::NotLogin(_)
            | BulwarkError::InvalidToken(_)
            | BulwarkError::ExpiredToken(_) => StatusCode::UNAUTHORIZED,
            BulwarkError::NotPermission(_) | BulwarkError::NotRole(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = axum::Json(serde_json::json!({ "error": self.to_string() }));
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
}
