//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

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

    /// 防火墙拦截（0.5.0 新增，依据 spec firewall R-firewall-001 ~ R-firewall-005）。
    ///
    /// 携带 strategy 名与原因，便于 audit-log 订阅。
    FirewallBlocked(String),

    /// 账号被封禁异常（0.6.1 新增，依据 spec error-exceptions R-error-001）。
    ///
    /// 对应 PRD §3.1.6 DisableServiceException / FRD §3.4 BW-ERR-010。
    /// `service` 记录被封禁的服务名（如 "default" / "oidc"），
    /// `until` 为 `Some(time)` 表示定时解封，`None` 表示永久封禁。
    /// 不泄露 user_id / tenant_id 等敏感信息。
    DisableService {
        /// 被封禁的服务名（如 "default" / "oidc"）。
        service: String,
        /// 定时解封时间；`None` 表示永久封禁。
        until: Option<chrono::DateTime<chrono::Utc>>,
    },

    /// 未完成二次认证异常（0.6.1 新增，依据 spec error-exceptions R-error-002）。
    ///
    /// 对应 PRD §3.1.6 NotSafeException / FRD §5.4.1。
    /// `reason` 说明未完成的具体认证（如 "MFA_TOTP_REQUIRED" / "WEBAUTHN_REQUIRED"）。
    NotSafe {
        /// 未完成认证的原因标识。
        reason: String,
    },

    /// 非法状态转换（0.6.1 新增，依据 spec error-exceptions R-error-003）。
    ///
    /// 供 E-005 状态机使用，`from` / `to` 为状态枚举的 Debug 输出。
    /// HTTP status = 500（内部状态错误，非用户错误）。
    InvalidStateTransition {
        /// 源状态（`format!("{:?}", state)` Debug 输出）。
        from: String,
        /// 目标状态。
        to: String,
    },
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
            BulwarkError::FirewallBlocked(s) => write!(f, "防火墙拦截: {}", s),
            BulwarkError::DisableService { service, until } => {
                write!(f, "账号已被封禁：service={}, until={:?}", service, until)
            },
            BulwarkError::NotSafe { reason } => write!(f, "未完成二次认证：{}", reason),
            BulwarkError::InvalidStateTransition { from, to } => {
                write!(f, "非法状态转换：{} -> {}", from, to)
            },
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
    // ========================================================================
    // BW-ERR 错误码常量（0.6.1 新增，依据 spec error-exceptions R-error-004 / FRD §3.4）
    // ========================================================================
    // 与 response_parts() 返回的字符串 error_code（如 "DISABLE_SERVICE"）解耦：
    // - response_parts().1 → 面向 HTTP 响应体（Sa-Token 既有惯例）
    // - BW_ERR_XXX 常量 → 面向 audit-log / 监控埋点 / FRD §3.4 数值追溯

    /// BW-ERR-009：并发登录冲突（FRD §3.4）。
    ///
    /// 超出设备并发上限时抛出，HTTP 409 Conflict。
    pub const BW_ERR_009: u32 = 409001;

    /// BW-ERR-010：账号被封禁（FRD §3.4）。
    ///
    /// 对应 `BulwarkError::DisableService`，HTTP 403 Forbidden。
    pub const BW_ERR_010: u32 = 403003;

    /// BW-ERR-011：多账号体系冲突（FRD §3.4）。
    ///
    /// 同一 login_id 在不同 account_type 下冲突，HTTP 401 Unauthorized。
    pub const BW_ERR_011: u32 = 401004;

    /// BW-ERR-012：第三方登录失败（FRD §3.4）。
    ///
    /// 对应 `BulwarkError::NotSafe`（第三方登录回退），HTTP 400 Bad Request。
    pub const BW_ERR_012: u32 = 400001;

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
            BulwarkError::FirewallBlocked(_) => (403, "FIREWALL_BLOCKED", "防火墙拦截", None),
            // 0.6.1 新增变体（依据 spec error-exceptions R-error-001~003）
            BulwarkError::DisableService { .. } => (403, "DISABLE_SERVICE", "账号已被封禁", None),
            BulwarkError::NotSafe { .. } => (400, "NOT_SAFE", "未完成二次认证", None),
            BulwarkError::InvalidStateTransition { .. } => {
                (500, "INVALID_STATE_TRANSITION", "非法状态转换", None)
            },
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
        let (status_code, error_code, _, _) = self.response_parts();
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let json_value = self.to_json_body();

        // 防御性截断：限制响应体大小为 4KB（依据 spec R-error-002）
        // 当前架构下 message 是固定字符串，body 永远 < 4KB；
        // 此截断保护未来架构变化（如 message 字段包含可变内容时）不会导致响应体过大。
        const MAX_BODY_SIZE: usize = 4096;
        let body_str = serde_json::to_string(&json_value).unwrap_or_else(|_| {
            r#"{"error_code":"INTERNAL_ERROR","message":"序列化失败"}"#.to_string()
        });

        if body_str.len() <= MAX_BODY_SIZE {
            (status, axum::Json(json_value)).into_response()
        } else {
            // 截断后构造简化版 JSON，保证合法（依据 spec R-error-002 验收标准 2）
            let truncated = serde_json::json!({
                "error_code": error_code,
                "message": "<truncated>",
            });
            (status, axum::Json(truncated)).into_response()
        }
    }
}

// ============================================================================
// miette::Diagnostic 实现（cfg feature = "miette"，依据 spec error R-error-001 M5）
// ============================================================================
//
// 富错误渲染层：保留 `thiserror::Error` derive（错误定义 + source 链），
// miette 仅作为 `Diagnostic` trait 实现，提供 `code` / `severity` / `labels` 富上下文。
// 默认关闭，启用方式：`--features miette`。
//
// [借鉴 miette] miette 推荐使用 dotted kebab-case 形式作为错误代码（如 `bulwark.not_login`），
// 与 `response_parts()` 返回的 UPPER_SNAKE_CASE error_code（如 `NOT_LOGIN`）解耦：
// - `response_parts().error_code` → 面向 HTTP 响应体（与 Sa-Token 既有惯例一致）
// - `Diagnostic::code()` → 面向开发者诊断终端（miette 渲染惯例）
#[cfg(feature = "miette")]
impl miette::Diagnostic for BulwarkError {
    /// 返回稳定的错误代码标识符（dotted kebab-case，miette 渲染惯例）。
    ///
    /// 形如 `bulwark.not_login` / `bulwark.config` / `bulwark.firewall_blocked`。
    /// 与 `response_parts().1` 返回的 UPPER_SNAKE_CASE error_code 解耦：
    /// - `response_parts` 的 error_code → 面向 HTTP 响应体（与 Sa-Token 既有惯例一致）
    /// - `Diagnostic::code()` → 面向开发者诊断终端（miette 渲染惯例）
    fn code(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        let code_str: &'static str = match self {
            BulwarkError::NotLogin(_) => "bulwark.not_login",
            BulwarkError::NotPermission(_) => "bulwark.not_permission",
            BulwarkError::NotRole(_) => "bulwark.not_role",
            BulwarkError::InvalidToken(_) => "bulwark.invalid_token",
            BulwarkError::ExpiredToken(_) => "bulwark.expired_token",
            BulwarkError::Dao(_) => "bulwark.dao",
            BulwarkError::Config(_) => "bulwark.config",
            BulwarkError::Internal(_) => "bulwark.internal",
            BulwarkError::Session(_) => "bulwark.session",
            BulwarkError::Annotation(_) => "bulwark.annotation",
            BulwarkError::Context(_) => "bulwark.context",
            BulwarkError::Exception(_) => "bulwark.exception",
            BulwarkError::OAuth2(_) => "bulwark.oauth2",
            BulwarkError::Network(_) => "bulwark.network",
            BulwarkError::InvalidParam(_) => "bulwark.invalid_param",
            BulwarkError::NotImplemented(_) => "bulwark.not_implemented",
            BulwarkError::FirewallBlocked(_) => "bulwark.firewall_blocked",
            BulwarkError::DisableService { .. } => "bulwark.disable_service",
            BulwarkError::NotSafe { .. } => "bulwark.not_safe",
            BulwarkError::InvalidStateTransition { .. } => "bulwark.invalid_state_transition",
        };
        Some(Box::new(code_str))
    }

    /// 返回错误严重级别。
    ///
    /// 当前所有变体均返回 `Severity::Error`（无 Warning/Advice 级别）。
    /// 设计依据：BulwarkError 表示框架级错误，需触发调用方错误处理路径。
    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Error)
    }

    /// 返回源码 span 标签（用于 IDE/CLI 高亮定位）。
    ///
    /// `BulwarkError` 变体仅携带 `String` 消息或 `BulwarkException` 结构体（无源码位置信息），
    /// 返回 `None`。未来若引入带 span 的错误变体（如注解解析失败），可在此分支返回 label。
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        None
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

    // ========================================================================
    // 响应体大小限制测试（依据 spec R-error-002）
    // ========================================================================

    /// 验证响应体大小被限制在 4KB 以内（依据 spec R-error-002）。
    ///
    /// 构造超长 error message 的 BulwarkError，断言 response body <= 4096 字节且仍是合法 JSON。
    /// 防御性测试：当前架构下 message 字段是固定字符串（不泄露变体 String 内容），
    /// body 永远 < 4KB；此测试保护未来架构变化不会导致响应体过大。
    #[cfg(feature = "web-axum")]
    #[tokio::test]
    async fn error_response_body_limited_to_4kb() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt;

        // 构造超长 error message（10KB）
        let long_msg = "x".repeat(10 * 1024);
        let err = BulwarkError::InvalidParam(long_msg);
        let response = err.into_response();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collect")
            .to_bytes();
        assert!(
            bytes.len() <= 4096,
            "响应体应 <= 4KB，实际: {} 字节",
            bytes.len()
        );
        // 截断后仍应是合法 JSON
        let body_json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("响应体应是合法 JSON");
        assert!(
            body_json.get("error_code").is_some(),
            "响应体应包含 error_code 字段"
        );
        assert!(
            body_json.get("message").is_some(),
            "响应体应包含 message 字段"
        );
    }

    // ========================================================================
    // miette::Diagnostic 测试（cfg feature = "miette"，依据 spec error R-error-001 M5）
    // ========================================================================

    /// 验证 `Diagnostic::code()` 返回稳定的 dotted kebab-case 错误代码。
    ///
    /// 覆盖多个变体：NotLogin / NotPermission / FirewallBlocked / NotImplemented / Exception。
    /// 选择带复合单词的变体（FirewallBlocked / NotImplemented）以验证 snake_case 转换正确性。
    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_code_returns_stable_identifier() {
        use miette::Diagnostic;

        let cases: [(BulwarkError, &str); 5] = [
            (BulwarkError::NotLogin("x".to_string()), "bulwark.not_login"),
            (
                BulwarkError::NotPermission("x".to_string()),
                "bulwark.not_permission",
            ),
            (
                BulwarkError::FirewallBlocked("x".to_string()),
                "bulwark.firewall_blocked",
            ),
            (
                BulwarkError::NotImplemented("x".to_string()),
                "bulwark.not_implemented",
            ),
            (
                BulwarkError::Exception(crate::exception::BulwarkException::new(500, "x")),
                "bulwark.exception",
            ),
        ];
        for (err, expected) in cases {
            let code = err.code().expect("code() 应返回 Some(Box<dyn Display>)");
            assert_eq!(
                code.to_string(),
                expected,
                "code() 应返回 dotted kebab-case 形式"
            );
        }
    }

    /// 验证所有变体的 `severity()` 返回 `Severity::Error`。
    ///
    /// 覆盖全部 17 个变体，确保无 Warning/Advice 漏网。
    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_severity_returns_error_for_all_variants() {
        use miette::{Diagnostic, Severity};

        let errors = [
            BulwarkError::NotLogin(String::new()),
            BulwarkError::NotPermission(String::new()),
            BulwarkError::NotRole(String::new()),
            BulwarkError::InvalidToken(String::new()),
            BulwarkError::ExpiredToken(String::new()),
            BulwarkError::Dao(String::new()),
            BulwarkError::Config(String::new()),
            BulwarkError::Internal(String::new()),
            BulwarkError::Session(String::new()),
            BulwarkError::Annotation(String::new()),
            BulwarkError::Context(String::new()),
            BulwarkError::Exception(crate::exception::BulwarkException::new(500, "")),
            BulwarkError::OAuth2(String::new()),
            BulwarkError::Network(String::new()),
            BulwarkError::InvalidParam(String::new()),
            BulwarkError::NotImplemented(String::new()),
            BulwarkError::FirewallBlocked(String::new()),
            BulwarkError::DisableService {
                service: String::new(),
                until: None,
            },
            BulwarkError::NotSafe {
                reason: String::new(),
            },
            BulwarkError::InvalidStateTransition {
                from: String::new(),
                to: String::new(),
            },
        ];
        for err in errors {
            let sev = err.severity().expect("severity() 应返回 Some");
            assert_eq!(sev, Severity::Error, "{:?} severity 应为 Error", err);
        }
    }

    /// 验证 String 携带型变体的 `labels()` 返回 `None`（无源码位置信息）。
    ///
    /// `BulwarkError` 的 String 变体仅携带消息字符串，不携带源码 span。
    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_labels_returns_none_for_string_variants() {
        use miette::Diagnostic;

        let cases: [BulwarkError; 5] = [
            BulwarkError::NotLogin("x".to_string()),
            BulwarkError::Dao("x".to_string()),
            BulwarkError::Config("x".to_string()),
            BulwarkError::OAuth2("x".to_string()),
            BulwarkError::FirewallBlocked("x".to_string()),
        ];
        for err in cases {
            assert!(err.labels().is_none(), "{:?} 的 labels() 应返回 None", err);
        }
    }

    /// 验证 `miette::Report::new(error)` 可构造，且 Debug 渲染输出包含错误代码。
    ///
    /// 验收 spec R-error-001 的"source chain 渲染"要求：miette::Report 接受任何
    /// `Diagnostic + Send + Sync + 'static`，BulwarkError 通过 thiserror::Error derive
    /// 满足 `std::error::Error`，本测试验证集成可达。
    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_can_be_rendered_with_miette_handler() {
        let err = BulwarkError::NotLogin("test message".to_string());
        let report = miette::Report::new(err);
        let rendered = format!("{:?}", report);
        assert!(
            rendered.contains("bulwark.not_login"),
            "miette::Report 的 Debug 渲染应包含错误代码 bulwark.not_login，实际: {}",
            rendered
        );
    }

    // ========================================================================
    // 覆盖率补充：FirewallBlocked 变体（依据 spec firewall R-firewall-001）
    // ========================================================================

    /// 验证 FirewallBlocked 变体的 Display 输出包含原始消息。
    ///
    /// 覆盖 Display impl 的 FirewallBlocked 分支（i18n 启用时走 fallback_display）。
    #[test]
    fn firewall_blocked_variant_display_includes_message() {
        let err = BulwarkError::FirewallBlocked("IP 1.2.3.4 被拦截".to_string());
        assert_eq!(err.to_string(), "防火墙拦截: IP 1.2.3.4 被拦截");
    }

    /// 验证 FirewallBlocked 变体的 response_parts 返回 403 + FIREWALL_BLOCKED。
    ///
    /// 覆盖 response_parts 的 FirewallBlocked 分支（行 149）。
    #[test]
    fn firewall_blocked_response_parts_returns_403() {
        let (status, error_code, message, ex_code) =
            BulwarkError::FirewallBlocked("bruteforce".to_string()).response_parts();
        assert_eq!(status, 403, "FirewallBlocked 应映射为 403 Forbidden");
        assert_eq!(error_code, "FIREWALL_BLOCKED");
        assert_eq!(message, "防火墙拦截");
        assert!(ex_code.is_none(), "FirewallBlocked 不携带 exception code");
    }

    /// 验证 FirewallBlocked 变体的 to_json_body 返回正确 JSON（无 code 字段）。
    #[test]
    fn firewall_blocked_to_json_body_returns_correct_json() {
        let err = BulwarkError::FirewallBlocked("ratelimit".to_string());
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "FIREWALL_BLOCKED");
        assert_eq!(body["message"], "防火墙拦截");
        assert!(
            body.get("code").is_none(),
            "FirewallBlocked 不应包含 code 字段"
        );
    }

    /// 验证 FirewallBlocked 错误映射为 403 Forbidden（web-axum feature）。
    #[cfg(feature = "web-axum")]
    #[test]
    fn firewall_blocked_error_returns_403() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = BulwarkError::FirewallBlocked("ddos".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ========================================================================
    // DisableService / NotSafe / InvalidStateTransition 变体测试
    // （0.6.1 新增，依据 spec error-exceptions R-error-001~003）
    // ========================================================================

    /// 验证 DisableService 变体的 Display 输出包含 service 与 until。
    ///
    /// 覆盖 spec R-error-001：Display 输出 `"账号已被封禁：service={service}, until={until:?}"`。
    #[test]
    fn disable_service_display_includes_service_and_until() {
        let err = BulwarkError::DisableService {
            service: "default".to_string(),
            until: None,
        };
        assert_eq!(err.to_string(), "账号已被封禁：service=default, until=None");

        // 带 until 的 Display
        let until = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err_with_until = BulwarkError::DisableService {
            service: "oidc".to_string(),
            until: Some(until),
        };
        let display = err_with_until.to_string();
        assert!(
            display.contains("service=oidc"),
            "Display 应包含 service=oidc，实际: {}",
            display
        );
        assert!(
            display.contains("2026-12-31T23:59:59Z"),
            "Display 应包含 until 时间，实际: {}",
            display
        );
    }

    /// 验证 DisableService 变体的 response_parts 返回 403 + DISABLE_SERVICE。
    ///
    /// 覆盖 spec R-error-001：HTTP status = 403，error_code 字符串 = "DISABLE_SERVICE"。
    #[test]
    fn disable_service_response_parts_returns_403() {
        let err = BulwarkError::DisableService {
            service: "default".to_string(),
            until: None,
        };
        let (status, error_code, message, ex_code) = err.response_parts();
        assert_eq!(status, 403, "DisableService 应映射为 403 Forbidden");
        assert_eq!(error_code, "DISABLE_SERVICE");
        assert_eq!(message, "账号已被封禁");
        assert!(ex_code.is_none(), "DisableService 不携带 exception code");
    }

    /// 验证 DisableService 变体不泄露敏感信息（service 字段不暴露到响应体）。
    ///
    /// 覆盖 spec R-error-001 约束：to_json_body 的 message 字段为通用描述，不含 service 值。
    #[test]
    fn disable_service_to_json_body_does_not_leak_service() {
        let err = BulwarkError::DisableService {
            service: "sensitive-service-name".to_string(),
            until: None,
        };
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "DISABLE_SERVICE");
        assert_eq!(body["message"], "账号已被封禁");
        // message 不应包含 service 字段值
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("sensitive-service-name"),
            "响应体 message 不应泄露 service 字段值"
        );
    }

    /// 验证 NotSafe 变体的 Display 输出包含 reason。
    ///
    /// 覆盖 spec R-error-002：Display 输出 `"未完成二次认证：{reason}"`。
    #[test]
    fn not_safe_display_includes_reason() {
        let err = BulwarkError::NotSafe {
            reason: "MFA_TOTP_REQUIRED".to_string(),
        };
        assert_eq!(err.to_string(), "未完成二次认证：MFA_TOTP_REQUIRED");
    }

    /// 验证 NotSafe 变体的 response_parts 返回 400 + NOT_SAFE。
    ///
    /// 覆盖 spec R-error-002：HTTP status = 400，error_code = "NOT_SAFE"。
    #[test]
    fn not_safe_response_parts_returns_400() {
        let err = BulwarkError::NotSafe {
            reason: "WEBAUTHN_REQUIRED".to_string(),
        };
        let (status, error_code, message, ex_code) = err.response_parts();
        assert_eq!(status, 400, "NotSafe 应映射为 400 Bad Request");
        assert_eq!(error_code, "NOT_SAFE");
        assert_eq!(message, "未完成二次认证");
        assert!(ex_code.is_none(), "NotSafe 不携带 exception code");
    }

    /// 验证 NotSafe 变体不泄露敏感信息（reason 字段不暴露到响应体）。
    #[test]
    fn not_safe_to_json_body_does_not_leak_reason() {
        let err = BulwarkError::NotSafe {
            reason: "internal-mfa-secret-leak".to_string(),
        };
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "NOT_SAFE");
        assert_eq!(body["message"], "未完成二次认证");
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("internal-mfa-secret-leak"),
            "响应体 message 不应泄露 reason 字段值"
        );
    }

    /// 验证 InvalidStateTransition 变体的 Display 输出包含 from 与 to。
    ///
    /// 覆盖 spec R-error-003：Display 输出 `"非法状态转换：{from} -> {to}"`。
    #[test]
    fn invalid_state_transition_display_includes_from_and_to() {
        let err = BulwarkError::InvalidStateTransition {
            from: "Expired".to_string(),
            to: "Active".to_string(),
        };
        assert_eq!(err.to_string(), "非法状态转换：Expired -> Active");
    }

    /// 验证 InvalidStateTransition 变体的 response_parts 返回 500。
    ///
    /// 覆盖 spec R-error-003：HTTP status = 500（内部状态错误）。
    #[test]
    fn invalid_state_transition_response_parts_returns_500() {
        let err = BulwarkError::InvalidStateTransition {
            from: "Deleted".to_string(),
            to: "Active".to_string(),
        };
        let (status, error_code, message, ex_code) = err.response_parts();
        assert_eq!(
            status, 500,
            "InvalidStateTransition 应映射为 500 Internal Server Error"
        );
        assert_eq!(error_code, "INVALID_STATE_TRANSITION");
        assert_eq!(message, "非法状态转换");
        assert!(ex_code.is_none());
    }

    /// 验证 InvalidStateTransition 变体不泄露内部状态名到响应体。
    #[test]
    fn invalid_state_transition_to_json_body_does_not_leak_states() {
        let err = BulwarkError::InvalidStateTransition {
            from: "InternalStateA".to_string(),
            to: "InternalStateB".to_string(),
        };
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "INVALID_STATE_TRANSITION");
        assert_eq!(body["message"], "非法状态转换");
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("InternalStateA"),
            "响应体不应泄露 from 状态名"
        );
        assert!(
            !message_str.contains("InternalStateB"),
            "响应体不应泄露 to 状态名"
        );
    }

    // ========================================================================
    // BW-ERR 错误码常量测试（0.6.1 新增，依据 spec error-exceptions R-error-004）
    // ========================================================================

    /// 验证 BW_ERR_009 常量值为 409001（并发登录冲突，FRD §3.4）。
    #[test]
    fn bw_err_009_constant_value() {
        assert_eq!(BulwarkError::BW_ERR_009, 409001);
    }

    /// 验证 BW_ERR_010 常量值为 403003（账号被封禁，FRD §3.4）。
    #[test]
    fn bw_err_010_constant_value() {
        assert_eq!(BulwarkError::BW_ERR_010, 403003);
    }

    /// 验证 BW_ERR_011 常量值为 401004（多账号体系冲突，FRD §3.4）。
    #[test]
    fn bw_err_011_constant_value() {
        assert_eq!(BulwarkError::BW_ERR_011, 401004);
    }

    /// 验证 BW_ERR_012 常量值为 400001（第三方登录失败，FRD §3.4）。
    #[test]
    fn bw_err_012_constant_value() {
        assert_eq!(BulwarkError::BW_ERR_012, 400001);
    }
}
