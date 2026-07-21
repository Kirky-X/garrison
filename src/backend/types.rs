//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AuthBackend 请求/响应类型定义。
//!
//! 包含 BackendRemote HTTP 通信所需的请求体结构，
//! 以及对现有 stp::LoginParams / session::TokenInfo / session::TokenSession 的 re-export。
//!
//! # 设计原则
//!
//! - **复用优先**（Rule 8）：LoginParams / TokenInfo / TokenSession 已存在于 garrison，
//!   通过类型别名或 re-export 复用，不创建重复定义
//! - **序列化兼容**：所有 HTTP 请求/响应结构体派生 `Serialize` + `Deserialize`，
//!   确保 BackendRemote 与 Auth Server 之间的 JSON 通信兼容

use serde::{Deserialize, Serialize};

// ============================================================================
// 现有类型 re-export（避免重复定义 — Rule 8）
// ============================================================================

/// 登录请求参数（re-export 自 stp 模块）。
///
/// 包含设备标识 / IP / User-Agent / remember_me / require_mfa。
pub use crate::stp::LoginParams;

/// Token 信息（re-export 自 session 模块）。
///
/// 包含 token 字符串 / 创建时间 / 最后活跃时间。
pub use crate::session::TokenInfo;

/// Session 数据（TokenSession 的类型别名）。
///
/// 包含 token 关联的 login_id / 创建时间 / 活跃时间 / 自定义属性 / 设备信息 / IP / UA。
pub type SessionData = crate::session::TokenSession;

// ============================================================================
// BackendRemote HTTP 请求体（用于 JSON 序列化）
// ============================================================================

/// check_login 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/check-login` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckLoginRequest {
    /// 待校验的 token 字符串。
    pub token: String,
}

/// check_permission 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/check-permission` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPermissionRequest {
    /// 待校验的 token 字符串。
    pub token: String,
    /// 待校验的权限标识。
    pub permission: String,
}

/// check_role 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/check-role` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRoleRequest {
    /// 待校验的 token 字符串。
    pub token: String,
    /// 待校验的角色标识。
    pub role: String,
}

/// check_api_key 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/check-api-key` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckApiKeyRequest {
    /// API Key 字符串。
    pub api_key: String,
    /// 命名空间（租户隔离标识）。
    pub namespace: String,
}

/// kickout 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/kickout` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickoutRequest {
    /// 待踢出的登录主体标识。
    pub login_id: String,
}

/// login 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/login` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// 登录主体标识。
    pub login_id: String,
    /// 登录参数。
    pub params: LoginParams,
}

/// logout 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/logout` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    /// 待登出的 token 字符串。
    pub token: String,
}

/// switch_to 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/switch-to` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchToRequest {
    /// 当前 token 字符串。
    pub token: String,
    /// 待切换到的登录主体标识。
    pub target_login_id: String,
}

/// renew_to_equivalent 请求体。
///
/// BackendRemote 调用 `POST /api/v1/auth/renew-to-equivalent` 时发送的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewToEquivalentRequest {
    /// 待续期的 token 字符串。
    pub token: String,
}

// ============================================================================
// BackendRemote HTTP 响应体（用于 JSON 反序列化）
// ============================================================================

/// 通用 API 响应包装。
///
/// Auth Server 所有端点返回的统一 JSON 结构。
/// 成功时 `data` 包含实际数据，失败时 `error_code` + `message` 描述错误。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// 业务数据（成功时存在）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// 错误码（失败时存在）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// 错误消息（失败时存在）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    /// 从成功数据构造响应。
    pub fn ok(data: T) -> Self {
        Self {
            data: Some(data),
            error_code: None,
            message: None,
        }
    }

    /// 从错误信息构造响应。
    pub fn err(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            data: None,
            error_code: Some(error_code.into()),
            message: Some(message.into()),
        }
    }

    /// 提取业务数据，失败时返回错误。
    ///
    /// 用于 BackendRemote 解析 HTTP 响应。
    pub fn into_result(self) -> Result<T, (String, String)> {
        match self.data {
            Some(v) => Ok(v),
            None => Err((
                self.error_code.unwrap_or_else(|| "UNKNOWN".to_string()),
                self.message.unwrap_or_else(|| "Unknown error".to_string()),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_response_ok_wraps_data() {
        let resp: ApiResponse<i32> = ApiResponse::ok(42);
        assert_eq!(resp.data, Some(42));
        assert!(resp.error_code.is_none());
        assert!(resp.message.is_none());
    }

    #[test]
    fn api_response_err_wraps_error_info() {
        let resp: ApiResponse<String> = ApiResponse::err("DENIED", "拒绝访问");
        assert!(resp.data.is_none());
        assert_eq!(resp.error_code.as_deref(), Some("DENIED"));
        assert_eq!(resp.message.as_deref(), Some("拒绝访问"));
    }

    #[test]
    fn into_result_ok_extracts_data() {
        let resp: ApiResponse<i32> = ApiResponse::ok(7);
        assert_eq!(resp.into_result().unwrap(), 7);
    }

    #[test]
    fn into_result_err_with_explicit_fields() {
        let resp: ApiResponse<i32> = ApiResponse::err("NOT_FOUND", "资源不存在");
        let (code, msg) = resp.into_result().unwrap_err();
        assert_eq!(code, "NOT_FOUND");
        assert_eq!(msg, "资源不存在");
    }

    #[test]
    fn into_result_err_with_none_fields_uses_defaults() {
        let resp: ApiResponse<i32> = ApiResponse {
            data: None,
            error_code: None,
            message: None,
        };
        let (code, msg) = resp.into_result().unwrap_err();
        assert_eq!(code, "UNKNOWN");
        assert_eq!(msg, "Unknown error");
    }
}
