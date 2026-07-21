//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `NotLoginException` 与 `GarrisonException` 的 impl 块（从 mod.rs 迁移）。

use super::*;

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

impl GarrisonException {
    /// 创建基础异常实例（Builder 入口）。
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

    /// 链式设置 token_value。
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token_value = Some(token.into());
        self
    }

    /// 链式设置 login_id。
    pub fn with_login_id(mut self, login_id: i64) -> Self {
        self.login_id = Some(login_id);
        self
    }

    /// 链式设置 login_type。
    pub fn with_login_type(mut self, login_type: i32) -> Self {
        self.login_type = login_type;
        self
    }

    /// 链式添加额外上下文键值对。
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extras.insert(key.into(), value.into());
        self
    }

    /// 构建最终实例。
    pub fn build(self) -> Self {
        self
    }
}

impl From<GarrisonException> for GarrisonError {
    /// 将 `GarrisonException` 转换为 `GarrisonError::Exception` 变体。
    fn from(ex: GarrisonException) -> Self {
        GarrisonError::Exception(ex)
    }
}

impl From<GarrisonError> for GarrisonException {
    /// 将 `GarrisonError` 转换为 `GarrisonException`。
    ///
    /// 仅 `Exception` 变体直接返回原始 `GarrisonException`，其他变体根据语义映射 code：
    /// - `NotLogin` / `InvalidToken` / `ExpiredToken` → code=-1（未登录）
    /// - `NotPermission` / `NotRole` / `FirewallBlocked` → code=-2（无权限/拦截，403 语义）
    /// - 其他 → code=500（业务异常）
    fn from(err: GarrisonError) -> Self {
        match err {
            GarrisonError::Exception(ex) => ex,
            GarrisonError::NotLogin(msg) => GarrisonException::new(-1, msg),
            GarrisonError::InvalidToken(msg) => GarrisonException::new(-1, msg),
            GarrisonError::ExpiredToken(msg) => GarrisonException::new(-1, msg),
            GarrisonError::NotPermission(msg) => GarrisonException::new(-2, msg),
            GarrisonError::NotRole(msg) => GarrisonException::new(-2, msg),
            GarrisonError::FirewallBlocked(msg) => GarrisonException::new(-2, msg),
            other => GarrisonException::new(500, other.to_string()),
        }
    }
}

impl std::fmt::Display for GarrisonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "业务异常[{}]: {}", self.code, self.message)
    }
}

// ============================================================================
// IntoResponse 实现（cfg feature = "web-axum"）
// ============================================================================

/// 实现 `IntoResponse` 以便 `GarrisonException` 可直接作为 axum 响应返回。
///
/// 状态码映射规则（与 `GarrisonError::IntoResponse` 的 Exception 分支一致）：
/// - code = -1 → 401 Unauthorized
/// - code = -2 → 403 Forbidden
/// - 其他 → 500 Internal Server Error
///
/// 响应体为 JSON，包含 `code`、`message` 与 `extras` 字段。
#[cfg(feature = "web-axum")]
impl axum::response::IntoResponse for GarrisonException {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        // 完整异常记录到日志（不返回给客户端）
        tracing::error!(exception = ?self, "garrison exception");

        let status = match self.code {
            -1 => StatusCode::UNAUTHORIZED,
            -2 => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = axum::Json(serde_json::json!({
            "code": self.code,
            "message": self.message,
            "extras": self.extras,
        }));
        (status, body).into_response()
    }
}
