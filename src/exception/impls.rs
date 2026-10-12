// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `NotLoginException` 与 `GarrisonException` 的 impl 块（从 mod.rs 迁移）。

use super::*;
use crate::i18n::translate_error;

/// extras 敏感 key 黑名单（参照 audit `BUILTIN_MASK_FIELDS` 惯例）：`with_extra` 的 key 按 ASCII 小写命中时，值在日志（Debug）与 HTTP 响应体中均替换为 `"***"`。
const EXTRA_SENSITIVE_KEYS: &[&str] = &[
    "password",
    "password_hash",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "old_token",
    "new_token",
    "old_key",
    "new_key",
    "authorization",
    "credential",
    "api_key",
    "apikey",
];

/// extras 单值长度上限（字节，防响应体膨胀）。
const EXTRA_MAX_VALUE_LEN: usize = 256;
/// extras 键数量上限（防内部调试元数据滥用响应体）。
const EXTRA_MAX_ENTRIES: usize = 32;

/// 返回脱敏后的 extras 副本：敏感 key（[`EXTRA_SENSITIVE_KEYS`]）值替换为 `"***"`，超长值按 char boundary 安全截断至 [`EXTRA_MAX_VALUE_LEN`] + `…`，超过 [`EXTRA_MAX_ENTRIES`] 的键丢弃。
/// 供 `Debug`（日志路径）与 `IntoResponse`（响应体路径）共用，两处输出一致。
pub(crate) fn sanitize_extras(extras: &HashMap<String, String>) -> HashMap<String, String> {
    extras
        .iter()
        .take(EXTRA_MAX_ENTRIES)
        .map(|(k, v)| {
            let value = if EXTRA_SENSITIVE_KEYS.contains(&k.to_ascii_lowercase().as_str()) {
                "***".to_string()
            } else if v.len() > EXTRA_MAX_VALUE_LEN {
                let mut end = EXTRA_MAX_VALUE_LEN;
                while end > 0 && !v.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}\u{2026}", &v[..end])
            } else {
                v.clone()
            };
            (k.clone(), value)
        })
        .collect()
}

/// 统一脱敏 helper：超过 `keep` 字节保留前 `keep` 字节 + `***`，不超过则整体掩码为 `***`（短 token/login_id 全量输出即泄露）。
/// 用 `get(..keep)` 保证 char boundary 安全（非边界退化为整体掩码，不 panic）。
fn mask_preview(s: &str, keep: usize) -> String {
    match s.get(..keep) {
        Some(prefix) if s.len() > keep => format!("{prefix}***"),
        _ => "***".to_string(),
    }
}

impl NotLoginException {
    /// 创建新的未登录异常（`login_type` 默认空串）。
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            login_type: String::new(),
        }
    }

    /// 设置登录类型并返回 self（builder 模式）。
    pub fn with_login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = login_type.into();
        self
    }
}

impl std::fmt::Display for NotLoginException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err = GarrisonError::NotLogin(self.message.clone());
        let base = translate_error(&err);
        if self.login_type.is_empty() {
            f.write_str(&base)
        } else {
            // login_type 非空时追加标注，保证 Display 消费该字段（否则字段仅存不用，读取行为无法被测试捕获）
            write!(f, "{base} (login_type={})", self.login_type)
        }
    }
}

impl std::error::Error for NotLoginException {}

impl GarrisonException {
    /// 创建基础异常实例（Builder 入口）。
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

    /// 链式设置 login_id（与全局 login_id 一致为 `String` 语义）。
    pub fn with_login_id(mut self, login_id: impl Into<String>) -> Self {
        self.login_id = Some(login_id.into());
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
    /// 将 `GarrisonException` 转换为 `GarrisonError::Exception` 变体（Box 装载控制枚举体积）。
    fn from(ex: GarrisonException) -> Self {
        GarrisonError::Exception(Box::new(ex))
    }
}

impl From<GarrisonError> for GarrisonException {
    /// 转换 `GarrisonError`：`Exception` 变体原样返回；`NotLogin`/`InvalidToken`/`ExpiredToken` → code=-1（未登录），`NotPermission`/`NotRole`/`FirewallBlocked` → code=-2（403 语义），其他 → code=500。
    fn from(err: GarrisonError) -> Self {
        match err {
            GarrisonError::Exception(ex) => *ex,
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
        let err = GarrisonError::Exception(Box::new(self.clone()));
        f.write_str(&translate_error(&err))
    }
}

impl std::fmt::Debug for GarrisonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 脱敏：token_value 仅输出前 8 字符（短值整体掩码），防日志泄露
        let masked_token = match &self.token_value {
            Some(t) => format!("Some(\"{}\")", mask_preview(t, 8)),
            None => "None".to_string(),
        };
        // 脱敏：login_id 可能含手机号/邮箱等 PII，仅输出前 4 字符（短值整体掩码）
        let masked_login_id = match &self.login_id {
            Some(id) => format!("Some(\"{}\")", mask_preview(id, 4)),
            None => "None".to_string(),
        };
        // extras 经 sanitize_extras 掩码/截断/限量后输出，防误放入的密钥、PII 进入日志
        f.debug_struct("GarrisonException")
            .field("code", &self.code)
            .field("message", &self.message)
            .field("login_type", &self.login_type)
            .field("token_value", &masked_token)
            .field("login_id", &masked_login_id)
            .field("extras", &sanitize_extras(&self.extras))
            .finish()
    }
}

// IntoResponse 实现（cfg feature = "web-axum"）

/// 实现 `IntoResponse`，使 `GarrisonException` 可直接作为 axum 响应返回。
///
/// 状态码映射（与 `GarrisonError::IntoResponse` 的 Exception 分支一致）：code=-1 → 401，code=-2 → 403，其他 → 500；响应体 JSON 含 `code`、`message`、`extras`。
///
/// # 安全性
///
/// `extras` 经 `sanitize_extras` 处理（敏感 key 掩码、超长值截断、超量键丢弃）后写入响应体；脱敏黑名单是兜底而非白名单，调用方仍不应将内部调试元数据、PII 或密钥放入 extras。
#[cfg(feature = "web-axum")]
impl axum::response::IntoResponse for GarrisonException {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        // 完整异常记录到日志（不返回客户端）；?self 走手动 Debug，token_value/login_id/extras 均已脱敏
        tracing::error!(exception = ?self, "garrison exception");

        let status = match self.code {
            -1 => StatusCode::UNAUTHORIZED,
            -2 => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let mut body = serde_json::json!({
            "code": self.code,
            "message": self.message,
            "extras": sanitize_extras(&self.extras),
        });
        if let Some(id) = crate::context::request_id::current() {
            body[crate::context::request_id::REQUEST_ID_BODY_FIELD] =
                serde_json::Value::String(id.to_string());
        }
        let mut response = (status, axum::Json(body)).into_response();
        if let Some(id) = crate::context::request_id::current() {
            if let Ok(value) = axum::http::HeaderValue::from_str(id.as_ref()) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-request-id"),
                    value,
                );
            }
        }
        response
    }
}
