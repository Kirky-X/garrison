// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! AuthBackend 请求/响应类型定义。
//!
//! 包含 BackendRemote HTTP 通信所需的请求体结构，
//! 以及对现有 stp::LoginParams / session::TokenInfo / session::TokenSession 的 re-export。
//!
//! # 设计原则
//!
//! - **复用优先**：LoginParams / TokenInfo / TokenSession 已存在于 garrison，
//!   通过类型别名或 re-export 复用，不创建重复定义
//! - **序列化兼容**：所有 HTTP 请求/响应结构体派生 `Serialize` + `Deserialize`，
//!   确保 BackendRemote 与 Auth Server 之间的 JSON 通信兼容

use serde::{Deserialize, Serialize};

// ============================================================================
// 现有类型 re-export（避免重复定义）
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
///
/// # login_id 反序列化不变量（渗透-注入-login_id 无长度上限-2 /
/// 渗透-会话与令牌-2 / 限流与爆破-1）
///
/// 反序列化即校验（422 拒绝，签发源头之前的第一道防线）：trim 后非空、
/// 不含 `\x1f` 与其他控制字符、字节长度 ≤
/// [`DEFAULT_LOGIN_ID_MAX_LEN`](crate::config::DEFAULT_LOGIN_ID_MAX_LEN)。
/// wire 层不读运行时配置，按框架默认常量封顶（stp 层
/// `config.login_id_max_len` 可进一步收紧）；错误信息不含输入内容回显。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// 登录主体标识。
    #[serde(deserialize_with = "validate_login_id_field")]
    pub login_id: String,
    /// 登录参数。
    pub params: LoginParams,
}

/// `LoginRequest.login_id` 的反序列化校验（wire 层硬上限 = 框架默认常量）。
///
/// 校验语义与 stp 层 `validate_login_id` 同源镜像（错误码一致）；
/// 长度上限取 [`DEFAULT_LOGIN_ID_MAX_LEN`] 而非运行时配置——HTTP 请求
/// 反序列化发生在配置消费点之前，按防 DoS 的框架默认封顶。
fn validate_login_id_field<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let max_len = crate::config::DEFAULT_LOGIN_ID_MAX_LEN as usize;
    let rejection = if value.is_empty() || value.trim().is_empty() {
        Some("login_id must not be empty or whitespace-only (stp-login-id-empty)")
    } else if value.contains('\x1f') {
        Some("login_id must not contain the unit separator (stp-login-id-sep)")
    } else if value.chars().any(|c| c.is_control()) {
        Some("login_id must not contain control characters (stp-login-id-control-char)")
    } else if value.len() > max_len {
        // 只回显长度上限，不回显输入内容
        Some("login_id exceeds the maximum length (stp-login-id-too-long)")
    } else {
        None
    };
    match rejection {
        Some(msg) => Err(serde::de::Error::custom(msg)),
        None => Ok(value),
    }
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
/// BackendRemote 调用 `POST /api/v1/auth/renew-to-equivalent`（外网 refresh
/// 端点同构）时发送的 JSON 结构。
///
/// # 未知字段拒绝（R2-2）
///
/// `deny_unknown_fields` 使携带未知字段（如误发的 `params.remember_me`）的
/// refresh 请求在反序列化期显性 4xx，而非静默忽略造成「字段已生效」的
/// 假象——refresh 的会话时长语义固定为承接旧会话（`effective_timeout`
/// 承接 + 剩余 TTL 落库），不接受任何续期参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    ///
    /// # 一致性检查
    ///
    /// `error_code` 存在时**一律视为错误**（错误优先于数据）：畸形/恶意响应
    /// 可能同时携带 `data` 与 `error_code`，此时以错误语义为准，防止
    /// 「data + error_code 并存」被静默当成功返回。
    pub fn into_result(self) -> Result<T, (String, String)> {
        if let Some(code) = self.error_code {
            return Err((
                code,
                self.message
                    .unwrap_or_else(|| "backend-unknown-error::".to_string()),
            ));
        }
        match self.data {
            Some(v) => Ok(v),
            None => Err(("UNKNOWN".to_string(), "backend-unknown-error::".to_string())),
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
        assert_eq!(msg, "backend-unknown-error::");
    }

    /// data 与 error_code 并存时错误优先，不得静默返回成功。
    #[test]
    fn into_result_error_takes_precedence_over_data() {
        let resp: ApiResponse<i32> = ApiResponse {
            data: Some(42),
            error_code: Some("INVALID_TOKEN".to_string()),
            message: Some("token 已过期".to_string()),
        };
        let (code, msg) = resp.into_result().unwrap_err();
        assert_eq!(code, "INVALID_TOKEN");
        assert_eq!(msg, "token 已过期");
    }

    // ------------------------------------------------------------------
    // LoginRequest.login_id 反序列化不变量（渗透-注入-login_id 无长度上限-2）
    // ------------------------------------------------------------------

    fn deser_login_request(body: &str) -> Result<LoginRequest, serde_json::Error> {
        serde_json::from_str(body)
    }

    fn login_body(login_id_json: &str) -> String {
        format!(
            r#"{{"login_id":{},"params":{{"remember_me":false,"require_mfa":false}}}}"#,
            login_id_json
        )
    }

    /// 256 字符（超框架默认上限 255）→ 反序列化拒绝（HTTP 层 422）。
    #[test]
    fn login_request_rejects_login_id_over_wire_max_len() {
        let long_id = "L".repeat(256);
        let err = deser_login_request(&login_body(&format!("\"{long_id}\"")))
            .expect_err("超上限 login_id 应拒绝");
        assert!(
            err.to_string().contains("stp-login-id-too-long"),
            "错误应含 too-long 码，实际: {err}"
        );
        assert!(!err.to_string().contains(&long_id), "错误不得回显输入内容");
    }

    /// 默认上限内 255 字符通过。
    #[test]
    fn login_request_accepts_login_id_at_wire_max_len() {
        let id = "L".repeat(255);
        let req = deser_login_request(&login_body(&format!("\"{id}\"")))
            .expect("255 字符 login_id 应通过");
        assert_eq!(req.login_id.len(), 255);
    }

    /// 空串 / 纯空白 / 控制字符 / \x1f 拒绝。
    #[test]
    fn login_request_rejects_invalid_login_id_shapes() {
        for (raw, code) in [
            ("\"\"", "stp-login-id-empty"),
            ("\"   \"", "stp-login-id-empty"),
            ("\"\\u001fadmin\"", "stp-login-id-sep"),
            ("\"admin\\nroot\"", "stp-login-id-control-char"),
        ] {
            let err =
                deser_login_request(&login_body(raw)).expect_err(&format!("login_id={raw} 应拒绝"));
            assert!(
                err.to_string().contains(code),
                "login_id={raw} 应含 {code}，实际: {err}"
            );
        }
    }

    /// R2-2：refresh 请求携带未知字段（如误发的 params.remember_me）反序列化期
    /// 显性拒绝，不再静默忽略。
    #[test]
    fn renew_request_rejects_unknown_fields() {
        let cases = [
            r#"{"token":"t","params":{"remember_me":true}}"#,
            r#"{"token":"t","remember_me":true}"#,
        ];
        for body in cases {
            let err: serde_json::Error = serde_json::from_str::<RenewToEquivalentRequest>(body)
                .expect_err(&format!("未知字段应拒绝: {body}"));
            assert!(
                err.to_string().contains("unknown field"),
                "应报 unknown field，实际: {err}"
            );
        }
        let ok: RenewToEquivalentRequest =
            serde_json::from_str(r#"{"token":"t"}"#).expect("仅 token 字段应通过");
        assert_eq!(ok.token, "t");
    }
}
