// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 错误类型定义模块：定义框架统一错误类型与 `GarrisonResult` 别名。

use crate::exception::GarrisonException;
use thiserror::Error;

/// Garrison 框架统一错误类型，涵盖登录、权限、Token、DAO、配置等各层错误场景。
///
/// Display 依据 i18n feature：未启用时硬编码中文，启用时按线程本地 locale 切换（详见 [`crate::i18n`]）。
#[derive(Error)]
pub enum GarrisonError {
    /// 未登录异常。
    NotLogin(String),

    /// 无权限异常。
    NotPermission(String),

    /// 无角色异常。
    NotRole(String),

    /// Token 无效异常。
    InvalidToken(String),

    /// Token 已吊销异常（RFC 7009 Token Revocation），适用于 refresh token 重用检测、令牌吊销等场景。
    TokenRevoked(String),

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

    /// 上下文错误（对应 GarrisonContext / Request / Response / Storage 异常）。
    Context(String),

    /// 业务异常（携带上下文的可恢复异常）；`Box` 装载控制枚举体积（`GarrisonException` 含 `HashMap`，内联会越过 clippy `result_large_err` 阈值）。
    Exception(Box<GarrisonException>),

    /// OAuth2 协议错误。
    OAuth2(String),

    /// 网络错误。
    Network(String),

    /// 上游响应无效（HTTP 502）：上游返回了响应但响应体无法解析（JSON 格式错误、必填字段缺失等）。
    /// 区别于 [`Network`](Self::Network)（网络层失败）与 [`OAuth2`](Self::OAuth2)（协议层错误），本变体专指"响应内容解析失败"。
    InvalidResponse(String),

    /// 参数无效错误。
    InvalidParam(String),

    /// 功能未实现（default 实现返回此错误）。
    NotImplemented(String),

    /// 防火墙拦截。
    ///
    /// 携带 strategy 名与原因，便于 audit-log 订阅。
    FirewallBlocked(String),

    /// 账号被封禁（对应 DisableServiceException，BW-ERR-010）。
    ///
    /// `service` 为被封禁服务名（如 "default" / "oidc"），`until` 为 `Some(time)` 定时解封、`None` 永久封禁；不泄露 user_id / tenant_id。
    DisableService {
        /// 被封禁的服务名（如 "default" / "oidc"）。
        service: String,
        /// 定时解封时间；`None` 表示永久封禁。
        until: Option<chrono::DateTime<chrono::Utc>>,
    },

    /// 未完成二次认证（对应 NotSafeException，BW-ERR-012）：`reason` 标识未完成的认证（如 "MFA_TOTP_REQUIRED"）。
    NotSafe {
        /// 未完成认证的原因标识。
        reason: String,
    },

    /// 非法状态转换：`from` / `to` 为状态枚举 Debug 输出，HTTP 500（内部状态错误，非用户错误）。
    InvalidStateTransition {
        /// 源状态（`format!("{:?}", state)` Debug 输出）。
        from: String,
        /// 目标状态。
        to: String,
    },

    /// SMS 限速超出（`window` = "hourly" / "daily"）。
    SmsRateLimitExceeded {
        /// 触发限速的窗口标识。
        window: String,
    },

    /// SMS 验证码尝试次数超限。
    SmsVerifyMaxAttempts,

    /// SMS 验证码不存在（已过期或未发送）。
    SmsCodeNotFound,

    /// SMS 通道已回收（异常发送检测触发）。
    SmsChannelRecycled,

    /// 请求速率超限（网关层限流，HTTP 429）：`retry_after_secs` 为建议等待秒数（经 `Retry-After` 头输出，下限 1），error_id `ratelimit.rate_limited`。
    RateLimited {
        /// 建议客户端等待的秒数（下限由 `retry_after_secs()` 强制为 1）。
        retry_after_secs: u64,
    },

    /// 邮箱限速超出（`email-verification` feature；`window` = "hourly" / "daily"）。
    #[cfg(feature = "email-verification")]
    EmailRateLimitExceeded {
        /// 触发限速的窗口标识。
        window: String,
    },

    /// 邮箱验证码尝试次数超限（`email-verification` feature）。
    #[cfg(feature = "email-verification")]
    EmailVerifyMaxAttempts,

    /// 邮箱验证码不存在（已过期或未发送，`email-verification` feature）。
    #[cfg(feature = "email-verification")]
    EmailCodeNotFound,

    /// 邮箱通道已回收（异常发送检测触发，`email-verification` feature）。
    #[cfg(feature = "email-verification")]
    EmailChannelRecycled,

    /// Credit 不足（多租户配额耗尽，`credit-metering` feature，HTTP 402）：对应 `CreditError::Insufficient`，不泄露 credit 配置细节。
    #[cfg(feature = "credit-metering")]
    CreditInsufficient {
        /// 租户 ID。
        tenant_id: i64,
        /// 请求的 credit 数。
        requested: u64,
        /// 剩余 credit 数。
        remaining: u64,
    },
}

// 手动 Debug：仅输出变体名 + Display 消息摘要（截断 200 字符），防内部路径/堆栈/OAuth2 detail 泄露到日志
impl std::fmt::Debug for GarrisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = self.to_string();
        let truncated = if display.len() > 200 {
            // 不在多字节 UTF-8 字符中间按字节硬切（经 into_response 的 error=?self 日志路径可达，构成远程 DoS），回退到最近 char boundary
            let mut end = 197;
            while end > 0 && !display.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &display[..end])
        } else {
            display
        };
        let variant = match self {
            Self::NotLogin(_) => "NotLogin",
            Self::NotPermission(_) => "NotPermission",
            Self::NotRole(_) => "NotRole",
            Self::InvalidToken(_) => "InvalidToken",
            Self::TokenRevoked(_) => "TokenRevoked",
            Self::ExpiredToken(_) => "ExpiredToken",
            Self::Dao(_) => "Dao",
            Self::Config(_) => "Config",
            Self::Internal(_) => "Internal",
            Self::Session(_) => "Session",
            Self::Annotation(_) => "Annotation",
            Self::Context(_) => "Context",
            Self::Exception(_) => "Exception",
            Self::OAuth2(_) => "OAuth2",
            Self::Network(_) => "Network",
            Self::InvalidResponse(_) => "InvalidResponse",
            Self::InvalidParam(_) => "InvalidParam",
            Self::NotImplemented(_) => "NotImplemented",
            Self::FirewallBlocked(_) => "FirewallBlocked",
            Self::DisableService { .. } => "DisableService",
            Self::NotSafe { .. } => "NotSafe",
            Self::InvalidStateTransition { .. } => "InvalidStateTransition",
            Self::SmsRateLimitExceeded { .. } => "SmsRateLimitExceeded",
            Self::SmsVerifyMaxAttempts => "SmsVerifyMaxAttempts",
            Self::SmsCodeNotFound => "SmsCodeNotFound",
            Self::SmsChannelRecycled => "SmsChannelRecycled",
            Self::RateLimited { .. } => "RateLimited",
            #[cfg(feature = "email-verification")]
            Self::EmailRateLimitExceeded { .. } => "EmailRateLimitExceeded",
            #[cfg(feature = "email-verification")]
            Self::EmailVerifyMaxAttempts => "EmailVerifyMaxAttempts",
            #[cfg(feature = "email-verification")]
            Self::EmailCodeNotFound => "EmailCodeNotFound",
            #[cfg(feature = "email-verification")]
            Self::EmailChannelRecycled => "EmailChannelRecycled",
            #[cfg(feature = "credit-metering")]
            Self::CreditInsufficient { .. } => "CreditInsufficient",
        };
        write!(f, "{}({})", variant, truncated)
    }
}

// Display 实现：始终委托 i18n 层翻译（未匹配 key 时回退错误自带文案）

impl std::fmt::Display for GarrisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::translate_error(self))
    }
}

/// Garrison 框架统一 Result 类型别名。
pub type GarrisonResult<T> = Result<T, GarrisonError>;

// From<CreditError> 实现（cfg feature = "credit-metering"）

/// `CreditError` → `GarrisonError`（支持 `?` 提升）：`Insufficient` 映射为 `CreditInsufficient`，ConfigInvalid/Dao/CycleExpired 映射为 Config/Dao/Internal。
#[cfg(feature = "credit-metering")]
impl From<crate::credit::CreditError> for GarrisonError {
    fn from(err: crate::credit::CreditError) -> Self {
        match err {
            crate::credit::CreditError::Insufficient {
                tenant_id,
                requested,
                remaining,
            } => GarrisonError::CreditInsufficient {
                tenant_id,
                requested,
                remaining,
            },
            crate::credit::CreditError::ConfigInvalid(msg) => GarrisonError::Config(msg),
            crate::credit::CreditError::Dao(msg) => GarrisonError::Dao(msg),
            crate::credit::CreditError::CycleExpired => {
                GarrisonError::Internal("credit-cycle-expired".to_string())
            },
        }
    }
}

// response_parts：框架无关的响应分片

impl GarrisonError {
    // BW-ERR 错误码常量
    // BW-ERR 常量：面向 audit-log / 监控埋点的数值追溯，与 response_parts() 的字符串 error_code（面向 HTTP 响应体）解耦
    // 编码规则（项目特定）：error_code = HTTP_status × 1000 + 序号（如 409001 = 409 × 1000 + 01）

    /// BW-ERR-009：并发登录冲突（超出设备并发上限，HTTP 409）。
    pub const BW_ERR_009: u32 = 409001;

    /// BW-ERR-010：账号被封禁（对应 `GarrisonError::DisableService`，HTTP 403）。
    pub const BW_ERR_010: u32 = 403003;

    /// BW-ERR-011：多账号体系冲突（同一 login_id 在不同 account_type 下冲突，HTTP 401）。
    pub const BW_ERR_011: u32 = 401004;

    /// BW-ERR-012：第三方登录失败（对应 `GarrisonError::NotSafe`，HTTP 400）。
    pub const BW_ERR_012: u32 = 400001;

    /// BW-ERR-013：Token 已吊销（RFC 7009；对应 `GarrisonError::TokenRevoked`，HTTP 401）。
    pub const BW_ERR_013: u32 = 401005;

    /// 返回 HTTP 响应分片 `(status_code, error_code, message, exception_code)`；框架无关，axum / actix-web / warp 适配器共用以保证行为一致。
    ///
    /// `message` 仅暴露通用描述（不泄漏内部细节），完整错误经 `tracing::error!` 记录；`exception_code` 仅 `Exception` 变体返回 `Some(code)`。
    pub fn response_parts(&self) -> (u16, &'static str, &'static str, Option<i32>) {
        let (status, error_code, _, fallback_msg, ex_code, _) = self.parts_and_msg_key();
        (status, error_code, fallback_msg, ex_code)
    }

    /// 稳定的机器可读错误码（如 `"NOT_LOGIN"`），与 [`Self::response_parts`] 同源（单一事实来源 `parts_and_msg_key`），供日志、监控埋点等非 HTTP 场景按变体检索。
    /// 唯一例外：`Exception` 变体在 HTTP 层按 `ex.code` 复用 `NOT_LOGIN` / `NOT_PERMISSION`，变体级机器码固定 `"EXCEPTION"`，保证对所有变体两两唯一。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Exception(_) => "EXCEPTION",
            _ => self.response_parts().1,
        }
    }

    /// 模块前缀错误码（`<module>.<snake>`，如 `auth.not_login`）：与旧码 [`Self::code`]（冻结原值，不 deprecate）并存，面向新集成方按模块维度检索。
    /// 单一事实来源 `parts_and_msg_key`（逐 arm 显式静态书写，非自动派生），对所有变体两两唯一（Exception 三个子 arm 为 `exception.not_login` / `exception.not_permission` / `exception.default`）。
    pub fn prefixed_code(&self) -> &'static str {
        let (_, _, _, _, _, error_id) = self.parts_and_msg_key();
        error_id
    }

    /// `Retry-After` 头值（秒）：仅 [`Self::RateLimited`] 返回 `Some(max(1, retry_after_secs))`（下限 1 防 0 秒误导立即重试），其余变体返回 `None`。
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after_secs } => Some((*retry_after_secs).max(1)),
            _ => None,
        }
    }

    /// 错误响应渲染的统一日志（axum / actix / warp 三框架适配器共用）。
    ///
    /// 限流拒绝是预期行为：429 攻击路径下 error 级无法被 EnvFilter 静音，构成日志洪水向量，故 `RateLimited` 降级 `warn`；其余变体保持 `error`。
    // 调用方仅存在于三个 web 适配器，按调用方并集门控避免三者全关时 dead_code
    #[cfg(any(feature = "web-axum", feature = "web-actix", feature = "web-warp"))]
    pub(crate) fn log_rejection(&self) {
        if matches!(self, Self::RateLimited { .. }) {
            tracing::warn!(error = ?self, "{}", crate::i18n::translate_detail("logs-error-rejection-rate-limited", &[]));
        } else {
            tracing::error!(error = ?self, "garrison rejection");
        }
    }

    /// 内部方法：单次 match 产出 (status, error_code, msg_key, fallback_msg, ex_code, error_id)，[`Self::response_parts`] 与 [`Self::response_parts_i18n`] 复用（DRY）。
    ///
    /// `error_code` 为冻结原值的旧码；`msg_key` 为 FTL key（如 `"not-login-msg"`）；`error_id` 为模块前缀码（`<module>.<snake>`，逐 arm 显式静态书写、不自动派生，命名风格与 miette dotted 码先例一致）。
    fn parts_and_msg_key(
        &self,
    ) -> (
        u16,
        &'static str,
        &'static str,
        &'static str,
        Option<i32>,
        &'static str,
    ) {
        match self {
            GarrisonError::NotLogin(_) => (
                401,
                "NOT_LOGIN",
                "not-login-msg",
                "Not logged in",
                None,
                "auth.not_login",
            ),
            GarrisonError::InvalidToken(_) => (
                401,
                "INVALID_TOKEN",
                "invalid-token-msg",
                "Invalid token",
                None,
                "auth.invalid_token",
            ),
            GarrisonError::TokenRevoked(_) => (
                401,
                "TOKEN_REVOKED",
                "token-revoked-msg",
                "Token revoked",
                None,
                "auth.token_revoked",
            ),
            GarrisonError::ExpiredToken(_) => (
                401,
                "EXPIRED_TOKEN",
                "expired-token-msg",
                "Token expired",
                None,
                "auth.expired_token",
            ),
            GarrisonError::NotPermission(_) => (
                403,
                "NOT_PERMISSION",
                "not-permission-msg",
                "Permission denied",
                None,
                "auth.not_permission",
            ),
            GarrisonError::NotRole(_) => (
                403,
                "NOT_ROLE",
                "not-role-msg",
                "Role required",
                None,
                "auth.not_role",
            ),
            GarrisonError::Dao(_) => (
                500,
                "DAO_ERROR",
                "dao-msg",
                "Data access error",
                None,
                "dao.error",
            ),
            GarrisonError::Config(_) => (
                500,
                "CONFIG_ERROR",
                "config-msg",
                "Configuration error",
                None,
                "config.error",
            ),
            GarrisonError::Internal(_) => (
                500,
                "INTERNAL_ERROR",
                "internal-msg",
                "Internal error",
                None,
                "internal.error",
            ),
            GarrisonError::Session(_) => (
                500,
                "SESSION_ERROR",
                "session-msg",
                "Session error",
                None,
                "session.error",
            ),
            GarrisonError::Annotation(_) => (
                500,
                "ANNOTATION_ERROR",
                "annotation-msg",
                "Annotation error",
                None,
                "annotation.error",
            ),
            GarrisonError::Context(_) => (
                500,
                "CONTEXT_ERROR",
                "context-msg",
                "Context error",
                None,
                "context.error",
            ),
            GarrisonError::OAuth2(_) => (
                500,
                "OAUTH2_ERROR",
                "oauth2-msg",
                "OAuth2 error",
                None,
                "oauth.error",
            ),
            GarrisonError::Network(_) => (
                502,
                "NETWORK_ERROR",
                "network-msg",
                "Network error",
                None,
                "network.error",
            ),
            GarrisonError::InvalidResponse(_) => (
                502,
                "INVALID_RESPONSE",
                "invalid-response-msg",
                "Invalid upstream response",
                None,
                "network.invalid_response",
            ),
            GarrisonError::InvalidParam(_) => (
                400,
                "INVALID_PARAM",
                "invalid-param-msg",
                "Invalid parameter",
                None,
                "validation.invalid_param",
            ),
            GarrisonError::NotImplemented(_) => (
                501,
                "NOT_IMPLEMENTED",
                "not-implemented-msg",
                "Not implemented",
                None,
                "internal.not_implemented",
            ),
            GarrisonError::FirewallBlocked(_) => (
                403,
                "FIREWALL_BLOCKED",
                "firewall-blocked-msg",
                "Firewall blocked",
                None,
                "firewall.blocked",
            ),
            GarrisonError::DisableService { .. } => (
                403,
                "DISABLE_SERVICE",
                "disable-service-msg",
                "Account disabled",
                None,
                "account.disable_service",
            ),
            GarrisonError::NotSafe { .. } => (
                400,
                "NOT_SAFE",
                "not-safe-msg",
                "Two-factor authentication required",
                None,
                "auth.not_safe",
            ),
            GarrisonError::InvalidStateTransition { .. } => (
                500,
                "INVALID_STATE_TRANSITION",
                "invalid-state-transition-msg",
                "Invalid state transition",
                None,
                "state.invalid_transition",
            ),
            GarrisonError::RateLimited { .. } => (
                429,
                "RATE_LIMITED",
                "rate-limited-msg",
                "Rate limited",
                None,
                "ratelimit.rate_limited",
            ),
            GarrisonError::SmsRateLimitExceeded { .. } => (
                429,
                "SMS_RATE_LIMIT_EXCEEDED",
                "sms-rate-limit-exceeded-msg",
                "SMS rate limit exceeded",
                None,
                "sms.rate_limit_exceeded",
            ),
            GarrisonError::SmsVerifyMaxAttempts => (
                400,
                "SMS_VERIFY_MAX_ATTEMPTS",
                "sms-verify-max-attempts-msg",
                "Verification code attempts exceeded",
                None,
                "sms.verify_max_attempts",
            ),
            GarrisonError::SmsCodeNotFound => (
                400,
                "SMS_CODE_NOT_FOUND",
                "sms-code-not-found-msg",
                "Verification code not found or expired",
                None,
                "sms.code_not_found",
            ),
            GarrisonError::SmsChannelRecycled => (
                403,
                "SMS_CHANNEL_RECYCLED",
                "sms-channel-recycled-msg",
                "SMS channel recycled",
                None,
                "sms.channel_recycled",
            ),
            #[cfg(feature = "email-verification")]
            GarrisonError::EmailRateLimitExceeded { .. } => (
                429,
                "EMAIL_RATE_LIMIT_EXCEEDED",
                "email-rate-limit-exceeded-msg",
                "Email sending too frequent",
                None,
                "email.rate_limit_exceeded",
            ),
            #[cfg(feature = "email-verification")]
            GarrisonError::EmailVerifyMaxAttempts => (
                400,
                "EMAIL_VERIFY_MAX_ATTEMPTS",
                "email-verify-max-attempts-msg",
                "Verification max attempts exceeded",
                None,
                "email.verify_max_attempts",
            ),
            #[cfg(feature = "email-verification")]
            GarrisonError::EmailCodeNotFound => (
                400,
                "EMAIL_CODE_NOT_FOUND",
                "email-code-not-found-msg",
                "Verification code not found or expired",
                None,
                "email.code_not_found",
            ),
            #[cfg(feature = "email-verification")]
            GarrisonError::EmailChannelRecycled => (
                403,
                "EMAIL_CHANNEL_RECYCLED",
                "email-channel-recycled-msg",
                "Email channel recycled",
                None,
                "email.channel_recycled",
            ),
            #[cfg(feature = "credit-metering")]
            GarrisonError::CreditInsufficient { .. } => (
                402,
                "CREDIT_INSUFFICIENT",
                "credit-insufficient-msg",
                "Credit insufficient",
                None,
                "credit.insufficient",
            ),
            // Exception 依据 GarrisonException.code 字段映射状态码
            // code = -1 → 未登录 → 401；code = -2 → 无权限 → 403；其他 → 500
            GarrisonError::Exception(ex) => match ex.code {
                -1 => (
                    401,
                    "NOT_LOGIN",
                    "exception-not-login-msg",
                    "Not logged in",
                    Some(ex.code),
                    "exception.not_login",
                ),
                -2 => (
                    403,
                    "NOT_PERMISSION",
                    "exception-not-permission-msg",
                    "Permission denied",
                    Some(ex.code),
                    "exception.not_permission",
                ),
                _ => (
                    500,
                    "EXCEPTION",
                    "exception-default-msg",
                    "Business exception",
                    Some(ex.code),
                    "exception.default",
                ),
            },
        }
    }

    /// 返回 i18n 化的 HTTP 响应分片：`message` 经 `translate_detail("xxx-msg", &[])` 按当前 locale 翻译（使用 `locales/{zh,en}.ftl` 的 `-msg` 后缀 keys），其余字段与 [`Self::response_parts`] 一致。
    ///
    /// `message` 仅暴露通用描述（不含变体 detail）；翻译失败回退硬编码 `&'static str`，不泄露 FTL key，完整错误经 `tracing::error!` 记录。
    pub fn response_parts_i18n(&self) -> (u16, &'static str, String, Option<i32>) {
        let (status, error_code, msg_key, fallback_msg, ex_code, _) = self.parts_and_msg_key();
        let translated = crate::i18n::translate_detail(msg_key, &[]);
        // 翻译失败（translate_detail 返回 key 本身）时回退硬编码 fallback，避免 FTL key 泄露到 HTTP 响应体
        let message = if translated == msg_key {
            fallback_msg.to_string()
        } else {
            translated
        };
        (status, error_code, message, ex_code)
    }

    /// 构造 JSON 响应体（框架无关，i18n 化）：统一字段 `error_code`（冻结旧码）、`error_id`（模块前缀码）、`message`（i18n 翻译）；`Exception` 变体额外含 `code`，请求存在 request id（[`crate::context::request_id::current`]）时含 `request_id`（omitempty）。
    pub fn to_json_body(&self) -> serde_json::Value {
        let (_, error_code, message, ex_code) = self.response_parts_i18n();
        let mut body = serde_json::json!({
            "error_code": error_code,
            "error_id": self.prefixed_code(),
            "message": message,
        });
        if let Some(code) = ex_code {
            body["code"] = serde_json::json!(code);
        }
        if let Some(id) = crate::context::request_id::current() {
            body[crate::context::request_id::REQUEST_ID_BODY_FIELD] =
                serde_json::json!(id.as_ref());
        }
        body
    }
}

// IntoResponse 实现（cfg feature = "web-axum"）

/// 实现 `IntoResponse`，使 extractor 的 `Rejection = GarrisonError` 可直接作为 axum 响应返回。
///
/// 状态码映射：NotLogin / InvalidToken / ExpiredToken → 401，NotPermission / NotRole → 403，其他 → 500（Exception 按 ex.code）。响应体仅暴露结构化错误码 + 通用消息（不泄漏内部细节），完整错误经 `tracing::error!` 记录。
#[cfg(feature = "web-axum")]
impl axum::response::IntoResponse for GarrisonError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::header::HeaderName;
        use axum::http::HeaderValue;
        use axum::http::StatusCode;

        // 完整错误记录到日志（不返回给客户端）；限流拒绝降级 warn（日志洪水防护）
        self.log_rejection();

        // 统一体单一事实来源：error_code + error_id + message（+ code / request_id）
        let json_value = self.to_json_body();
        // 状态码无需 i18n 分片（to_json_body 内部已完成翻译，避免双重翻译）
        let (status_code, _, _, _) = self.response_parts();
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // 防御性截断 4KB：当前 message 为固定字符串、body 恒 < 4KB，保护未来 message 含可变内容时不致响应体过大
        const MAX_BODY_SIZE: usize = 4096;
        let body_str = serde_json::to_string(&json_value).unwrap_or_else(|_| {
            // 序列化失败兜底体：携带 error_id 供错误检索（i18n 化英文，不泄露内部细节）
            format!(
                r#"{{"error_code":"INTERNAL_ERROR","error_id":"{}","message":"serialization failed"}}"#,
                self.prefixed_code()
            )
        });

        let truncated = body_str.len() > MAX_BODY_SIZE;
        let json_value = if truncated {
            serde_json::json!({
                "error_code": self.code(),
                "error_id": self.prefixed_code(),
                "message": "<truncated>",
            })
        } else {
            json_value
        };

        let mut response = (status, axum::Json(json_value)).into_response();
        let headers = response.headers_mut();
        if let Some(id) = crate::context::request_id::current() {
            if let Ok(value) = HeaderValue::from_str(id.as_ref()) {
                headers.insert(HeaderName::from_static("x-request-id"), value);
            }
        }
        if let Some(secs) = self.retry_after_secs() {
            headers.insert(
                HeaderName::from_static("retry-after"),
                HeaderValue::from(secs),
            );
        }
        response
    }
}

// miette::Diagnostic 实现（cfg feature = "miette"）
//
// 富错误渲染层（默认关闭，`--features miette` 启用）：保留 thiserror derive（错误定义 + source 链），miette 仅实现 Diagnostic trait，提供 code / severity / labels 富上下文。
// miette 惯例用 dotted kebab-case 错误码（如 `garrison.not_login`），与 response_parts 的 UPPER_SNAKE_CASE（面向 HTTP 响应体）解耦。
#[cfg(feature = "miette")]
impl miette::Diagnostic for GarrisonError {
    /// 返回稳定的 dotted kebab-case 错误代码（如 `garrison.not_login`）：从 `parts_and_msg_key()` 的 error_code 派生（`garrison.` + lowercase + 去尾部 `_error`，单一数据源）。
    fn code(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        let (_, error_code, _, _, _, _) = self.parts_and_msg_key();
        // 派生规则：garrison. + lowercase(error_code) + 去除尾部 "_error"
        let lower = error_code.to_ascii_lowercase();
        let stem = lower.strip_suffix("_error").unwrap_or(&lower);
        Some(Box::new(format!("garrison.{stem}") as String))
    }

    /// 所有变体均返回 `Severity::Error`（框架级错误需触发调用方错误处理路径）。
    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Error)
    }

    /// 返回 `None`：变体仅携带 `String` 消息或 `GarrisonException`，无源码位置信息（未来引入带 span 变体时可在此返回 label）。
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `code()` 覆盖全部变体且两两唯一、非空、全大写、与 `response_parts` 的 error_code 同源防漂移。
    #[test]
    fn error_code_covers_all_variants_unique_and_stable() {
        // extend/push 分支分别被 email-verification / credit-metering 门控：
        // 两者皆关闭时 mut 未被使用，此处显式 allow 以兼容 CI 的 -D warnings。
        #[cfg_attr(
            not(any(feature = "email-verification", feature = "credit-metering")),
            allow(unused_mut)
        )]
        let mut samples: Vec<GarrisonError> = vec![
            GarrisonError::NotLogin("a".into()),
            GarrisonError::NotPermission("a".into()),
            GarrisonError::NotRole("a".into()),
            GarrisonError::InvalidToken("a".into()),
            GarrisonError::TokenRevoked("a".into()),
            GarrisonError::ExpiredToken("a".into()),
            GarrisonError::Dao("a".into()),
            GarrisonError::Config("a".into()),
            GarrisonError::Internal("a".into()),
            GarrisonError::Session("a".into()),
            GarrisonError::Annotation("a".into()),
            GarrisonError::Context("a".into()),
            GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(-1, "a"))),
            GarrisonError::OAuth2("a".into()),
            GarrisonError::Network("a".into()),
            GarrisonError::InvalidResponse("a".into()),
            GarrisonError::InvalidParam("a".into()),
            GarrisonError::NotImplemented("a".into()),
            GarrisonError::FirewallBlocked("a".into()),
            GarrisonError::DisableService {
                service: "default".into(),
                until: None,
            },
            GarrisonError::NotSafe {
                reason: "MFA_TOTP_REQUIRED".into(),
            },
            GarrisonError::InvalidStateTransition {
                from: "Active".into(),
                to: "Revoked".into(),
            },
            GarrisonError::SmsRateLimitExceeded {
                window: "hourly".into(),
            },
            GarrisonError::SmsVerifyMaxAttempts,
            GarrisonError::SmsCodeNotFound,
            GarrisonError::SmsChannelRecycled,
            GarrisonError::RateLimited {
                retry_after_secs: 30,
            },
        ];
        #[cfg(feature = "email-verification")]
        samples.extend([
            GarrisonError::EmailRateLimitExceeded {
                window: "hourly".into(),
            },
            GarrisonError::EmailVerifyMaxAttempts,
            GarrisonError::EmailCodeNotFound,
            GarrisonError::EmailChannelRecycled,
        ]);
        #[cfg(feature = "credit-metering")]
        samples.push(GarrisonError::CreditInsufficient {
            tenant_id: 1,
            requested: 10,
            remaining: 0,
        });

        // 哨兵：新增 GarrisonError 变体必须同步加入 samples 列表，否则断言失败（防唯一性检查失去覆盖）
        #[cfg(all(feature = "credit-metering", feature = "email-verification"))]
        assert_eq!(
            samples.len(),
            32,
            "samples 未覆盖全部变体：新增变体须同步加入本测试列表"
        );
        #[cfg(all(feature = "credit-metering", not(feature = "email-verification")))]
        assert_eq!(
            samples.len(),
            28,
            "samples 未覆盖全部变体：新增变体须同步加入本测试列表"
        );
        #[cfg(all(not(feature = "credit-metering"), feature = "email-verification"))]
        assert_eq!(
            samples.len(),
            31,
            "samples 未覆盖全部变体：新增变体须同步加入本测试列表"
        );
        #[cfg(all(not(feature = "credit-metering"), not(feature = "email-verification")))]
        assert_eq!(
            samples.len(),
            27,
            "samples 未覆盖全部变体：新增变体须同步加入本测试列表"
        );

        let mut seen = std::collections::HashSet::new();
        for err in &samples {
            let code = err.code();
            assert!(!code.is_empty(), "code 不得为空");
            assert_eq!(code.to_uppercase(), code, "code 须全大写: {code}");
            assert!(seen.insert(code), "code 须两两唯一，重复: {code}");
        }
        assert_eq!(samples.len(), seen.len());

        // 稳定性：同变体重复取值一致；与 HTTP error_code 同源（Exception 例外——
        // HTTP 层按 ex.code 条件复用 NOT_LOGIN/NOT_PERMISSION，变体级固定 EXCEPTION）。
        for err in &samples {
            assert_eq!(err.code(), err.code(), "code 须稳定: {err:?}");
            if matches!(err, GarrisonError::Exception(_)) {
                assert_eq!(err.code(), "EXCEPTION", "Exception 变体级码固定 EXCEPTION");
            } else {
                assert_eq!(
                    err.code(),
                    err.response_parts().1,
                    "code 须与 response_parts error_code 同源: {err:?}"
                );
            }
        }
        assert_eq!(GarrisonError::NotLogin("x".into()).code(), "NOT_LOGIN");
        assert_eq!(GarrisonError::Session("x".into()).code(), "SESSION_ERROR");
    }

    /// 哨兵：`GarrisonError` 经 `Exception(Box<..>)` 后体积必须远低于 clippy `result_large_err` 阈值（128B），防未来变体膨胀回归。
    #[test]
    fn error_size_stays_within_result_large_err_budget() {
        let size = std::mem::size_of::<GarrisonError>();
        assert!(
            size <= 64,
            "GarrisonError 体积膨胀（{size} 字节）：请改用 Box 装载大 payload，\
             避免热路径 Result 越过 result_large_err 阈值"
        );
    }

    /// Debug 的变体名分支：日志/告警按变体名过滤，缺分支会让结构体变体的 Debug 失真。
    #[test]
    #[cfg_attr(
        not(any(feature = "email-verification", feature = "credit-metering")),
        allow(unused_mut)
    )]
    fn debug_prints_variant_name_for_struct_variants() {
        let mut cases: Vec<(GarrisonError, &str)> = vec![
            (
                GarrisonError::InvalidResponse("bad-json".into()),
                "InvalidResponse",
            ),
            (
                GarrisonError::FirewallBlocked("waf".into()),
                "FirewallBlocked",
            ),
            (
                GarrisonError::DisableService {
                    service: "default".into(),
                    until: None,
                },
                "DisableService",
            ),
            (
                GarrisonError::NotSafe {
                    reason: "MFA_TOTP_REQUIRED".into(),
                },
                "NotSafe",
            ),
            (
                GarrisonError::InvalidStateTransition {
                    from: "Active".into(),
                    to: "Revoked".into(),
                },
                "InvalidStateTransition",
            ),
            (
                GarrisonError::SmsRateLimitExceeded {
                    window: "hourly".into(),
                },
                "SmsRateLimitExceeded",
            ),
            (GarrisonError::SmsVerifyMaxAttempts, "SmsVerifyMaxAttempts"),
            (GarrisonError::SmsCodeNotFound, "SmsCodeNotFound"),
            (GarrisonError::SmsChannelRecycled, "SmsChannelRecycled"),
        ];
        #[cfg(feature = "email-verification")]
        cases.extend([
            (
                GarrisonError::EmailRateLimitExceeded {
                    window: "daily".into(),
                },
                "EmailRateLimitExceeded",
            ),
            (
                GarrisonError::EmailVerifyMaxAttempts,
                "EmailVerifyMaxAttempts",
            ),
            (GarrisonError::EmailCodeNotFound, "EmailCodeNotFound"),
            (GarrisonError::EmailChannelRecycled, "EmailChannelRecycled"),
        ]);
        #[cfg(feature = "credit-metering")]
        cases.push((
            GarrisonError::CreditInsufficient {
                tenant_id: 1,
                requested: 10,
                remaining: 0,
            },
            "CreditInsufficient",
        ));

        for (err, variant) in &cases {
            let debug = format!("{:?}", err);
            assert!(
                debug.starts_with(&format!("{variant}(")),
                "Debug 变体名前缀应为 {variant}，实际: {debug}"
            );
        }
    }

    /// Debug 对超长 Display 截断到 200 字符 + `...`，且在多字节字符边界回退（切碎 UTF-8 会 panic）。
    #[test]
    fn debug_truncates_long_message_on_char_boundary() {
        let cases = [
            "x".repeat(400),
            format!("{}尾", "错".repeat(300)),
            "🌠".repeat(200),
        ];
        for message in cases {
            let debug = format!("{:?}", GarrisonError::Internal(message.clone()));
            assert!(
                debug.contains("...)"),
                "超长消息应截断并以 `...)` 收尾，实际尾部: {}",
                &debug[debug.len().saturating_sub(16)..]
            );
            assert!(
                debug.len() < message.len(),
                "截断后长度应小于原始消息（{} < {}）",
                debug.len(),
                message.len()
            );
        }
    }

    /// `CreditError` → `GarrisonError` 的四条映射：Insufficient 保留配额三元组，其余按语义分流。
    #[cfg(feature = "credit-metering")]
    #[test]
    fn credit_error_maps_to_garrison_error() {
        let insufficient = GarrisonError::from(crate::credit::CreditError::Insufficient {
            tenant_id: 7,
            requested: 10,
            remaining: 3,
        });
        assert!(
            matches!(
                insufficient,
                GarrisonError::CreditInsufficient {
                    tenant_id: 7,
                    requested: 10,
                    remaining: 3
                }
            ),
            "Insufficient 应保留 tenant_id/requested/remaining"
        );
        assert!(matches!(
            GarrisonError::from(crate::credit::CreditError::ConfigInvalid("bad".into())),
            GarrisonError::Config(msg) if msg == "bad"
        ));
        assert!(matches!(
            GarrisonError::from(crate::credit::CreditError::Dao("down".into())),
            GarrisonError::Dao(msg) if msg == "down"
        ));
        assert!(matches!(
            GarrisonError::from(crate::credit::CreditError::CycleExpired),
            GarrisonError::Internal(msg) if msg == "credit-cycle-expired"
        ));
    }

    #[test]
    fn string_variants_display_includes_message() {
        let cases: [(GarrisonError, &str); 16] = [
            (
                GarrisonError::Session("会话已过期".into()),
                "Session error: 会话已过期",
            ),
            (
                GarrisonError::Annotation("注解校验失败".into()),
                "Annotation error: 注解校验失败",
            ),
            (
                GarrisonError::Context("上下文缺失".into()),
                "Context error: 上下文缺失",
            ),
            (GarrisonError::Dao("连接失败".into()), "DAO error: 连接失败"),
            (
                GarrisonError::Config("配置非法".into()),
                "Configuration error: 配置非法",
            ),
            (
                GarrisonError::InvalidToken("格式错误".into()),
                "Invalid token: 格式错误",
            ),
            (
                GarrisonError::ExpiredToken("已过期".into()),
                "Token expired: 已过期",
            ),
            (
                GarrisonError::NotPermission("无权限".into()),
                "Permission denied: 无权限",
            ),
            (
                GarrisonError::NotRole("无角色".into()),
                "Role denied: 无角色",
            ),
            (
                GarrisonError::NotLogin("请先登录".into()),
                "Not logged in: 请先登录",
            ),
            (
                GarrisonError::Internal("内部错误".into()),
                "Internal error: 内部错误",
            ),
            (
                GarrisonError::OAuth2("授权码无效".into()),
                "OAuth2 error: 授权码无效",
            ),
            (
                GarrisonError::Network("DNS 解析失败".into()),
                "Network error: DNS 解析失败",
            ),
            (
                GarrisonError::InvalidParam("client_id 为空".into()),
                "Invalid parameter: client_id 为空",
            ),
            (
                GarrisonError::NotImplemented("refresh_token 未实现".into()),
                "Not implemented: refresh_token 未实现",
            ),
            (
                GarrisonError::FirewallBlocked("IP 1.2.3.4 被拦截".into()),
                "Firewall blocked: IP 1.2.3.4 被拦截",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn new_variants_propagate_via_result() {
        fn fallible() -> GarrisonResult<()> {
            Err(GarrisonError::Session("测试".to_string()))
        }
        let result = fallible();
        assert!(matches!(result, Err(GarrisonError::Session(_))));
    }

    #[test]
    fn new_variants_coexist_with_existing() {
        let errors = [
            GarrisonError::NotLogin("a".to_string()),
            GarrisonError::Session("b".to_string()),
            GarrisonError::Annotation("c".to_string()),
            GarrisonError::Context("d".to_string()),
        ];
        assert_eq!(errors.len(), 4);
    }

    // GarrisonResult 类型别名与 IntoResponse 实现测试

    #[test]
    fn garrison_result_ok_carries_value() {
        fn ok_fn() -> GarrisonResult<i32> {
            Ok(42)
        }
        assert_eq!(ok_fn().unwrap(), 42);
    }

    #[test]
    fn garrison_result_err_propagates_via_question_mark() {
        fn inner() -> GarrisonResult<()> {
            Err(GarrisonError::Dao("db down".to_string()))
        }
        fn outer() -> GarrisonResult<()> {
            inner()?;
            Ok(())
        }
        assert!(matches!(outer(), Err(GarrisonError::Dao(_))));
    }

    // IntoResponse 状态码映射测试（参数化，cfg feature = "web-axum"）

    #[cfg(feature = "web-axum")]
    #[test]
    fn into_response_status_codes() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let cases: [(GarrisonError, StatusCode); 16] = [
            (
                GarrisonError::NotLogin("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                GarrisonError::NotPermission("x".into()),
                StatusCode::FORBIDDEN,
            ),
            (GarrisonError::NotRole("x".into()), StatusCode::FORBIDDEN),
            (
                GarrisonError::InvalidToken("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                GarrisonError::TokenRevoked("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                GarrisonError::ExpiredToken("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                GarrisonError::Dao("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::Config("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::Internal("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::Session("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::Annotation("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::Context("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::OAuth2("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                GarrisonError::InvalidParam("x".into()),
                StatusCode::BAD_REQUEST,
            ),
            (
                GarrisonError::NotImplemented("x".into()),
                StatusCode::NOT_IMPLEMENTED,
            ),
            (GarrisonError::Network("x".into()), StatusCode::BAD_GATEWAY),
        ];
        for (err, expected_status) in cases {
            let debug_name = format!("{:?}", err);
            let response = err.into_response();
            assert_eq!(
                response.status(),
                expected_status,
                "{debug_name} 状态码不匹配"
            );
        }
    }

    // Exception 变体测试

    #[test]
    fn exception_variant_display_includes_code_and_message() {
        use crate::exception::GarrisonException;
        let err = GarrisonError::Exception(Box::new(GarrisonException::new(-1, "请先登录")));
        assert_eq!(err.to_string(), "Business exception[-1]: 请先登录");
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn exception_not_login_returns_401() {
        use crate::exception::GarrisonException;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = GarrisonError::Exception(Box::new(GarrisonException::new(-1, "请先登录")));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn exception_not_permission_returns_403() {
        use crate::exception::GarrisonException;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = GarrisonError::Exception(Box::new(GarrisonException::new(-2, "无权限")));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn exception_other_code_returns_500() {
        use crate::exception::GarrisonException;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = GarrisonError::Exception(Box::new(GarrisonException::new(500, "业务异常")));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // InvalidResponse 变体测试（上游响应解析失败专用错误类型）

    #[test]
    fn invalid_response_variant_display_includes_message() {
        let err = GarrisonError::InvalidResponse("JSON 解析失败".to_string());
        assert_eq!(err.to_string(), "Invalid upstream response: JSON 解析失败");
    }

    #[test]
    fn invalid_response_response_parts_returns_502() {
        let (status, error_code, message, ex_code) =
            GarrisonError::InvalidResponse("missing access_token field".to_string())
                .response_parts();
        assert_eq!(
            status, 502,
            "InvalidResponse 应映射为 502 Bad Gateway（上游响应问题）"
        );
        assert_eq!(error_code, "INVALID_RESPONSE");
        assert_eq!(message, "Invalid upstream response");
        assert!(ex_code.is_none(), "InvalidResponse 不携带 exception code");
    }

    #[test]
    fn invalid_response_to_json_body_does_not_leak_detail() {
        let err = GarrisonError::InvalidResponse(
            "internal parser stack trace: serde_json::Error at line 42".to_string(),
        );
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "INVALID_RESPONSE");
        assert_eq!(body["message"], "Invalid upstream response");
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("internal parser stack trace"),
            "响应体 message 不应泄露原始 detail"
        );
        assert!(
            !message_str.contains("serde_json::Error"),
            "响应体 message 不应泄露内部错误类型"
        );
    }

    /// `invalid-response-msg` 在 En/Zh 两个 locale 均可翻译（曾缺失导致 En 回退中文）。
    #[test]
    fn invalid_response_msg_key_translates_in_both_locales() {
        let err = GarrisonError::InvalidResponse("bad upstream".to_string());

        let _zh = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let (_, _, zh_msg, _) = err.response_parts_i18n();
        assert_eq!(
            zh_msg, "上游响应无效",
            "zh locale 下 invalid-response-msg 应翻译为中文"
        );

        let _en = crate::i18n::set_locale(crate::i18n::GarrisonLocale::En);
        let (_, _, en_msg, _) = err.response_parts_i18n();
        assert_eq!(
            en_msg, "Invalid upstream response",
            "en locale 下 invalid-response-msg 应翻译为英文（不应回退到中文 fallback）"
        );
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn invalid_response_error_returns_502() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = GarrisonError::InvalidResponse("response body invalid".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    // 覆盖率补充：to_json_body / response_parts / Exception 变体

    #[test]
    fn to_json_body_returns_error_code_and_message() {
        let err = GarrisonError::NotLogin("token missing".to_string());
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "NOT_LOGIN");
        assert_eq!(body["message"], "Not logged in");
        assert!(body.get("code").is_none(), "普通错误变体不应包含 code 字段");
    }

    #[test]
    fn to_json_body_includes_code_for_exception_variant() {
        let err = GarrisonError::Exception(Box::new(crate::exception::GarrisonException {
            code: 1001,
            message: "自定义业务异常".to_string(),
            login_type: 1,
            token_value: None,
            login_id: None,
            extras: std::collections::HashMap::new(),
        }));
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "EXCEPTION");
        assert_eq!(body["code"], 1001);
    }

    #[test]
    fn response_parts_returns_correct_status_and_code() {
        let (status, code, _, _) = GarrisonError::NotLogin("".to_string()).response_parts();
        assert_eq!(status, 401);
        assert_eq!(code, "NOT_LOGIN");

        let (status, code, _, _) = GarrisonError::NotPermission("".to_string()).response_parts();
        assert_eq!(status, 403);
        assert_eq!(code, "NOT_PERMISSION");

        let (status, code, _, _) = GarrisonError::Dao("".to_string()).response_parts();
        assert_eq!(status, 500);
        assert_eq!(code, "DAO_ERROR");

        let (status, code, _, _) = GarrisonError::NotImplemented("".to_string()).response_parts();
        assert_eq!(status, 501);
        assert_eq!(code, "NOT_IMPLEMENTED");
    }

    // 响应体大小限制测试

    /// 响应体限制 4KB：超长 message 截断后仍为合法 JSON（保护未来 message 含可变内容时不致过大）。
    #[cfg(feature = "web-axum")]
    #[tokio::test]
    async fn error_response_body_limited_to_4kb() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt;

        let long_msg = "x".repeat(10 * 1024);
        let err = GarrisonError::InvalidParam(long_msg);
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

    // miette::Diagnostic 测试（cfg feature = "miette"）

    /// `Diagnostic::code()` 返回稳定 dotted kebab-case（选复合词变体验证 snake_case 转换）。
    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_code_returns_stable_identifier() {
        // 注：不 use miette::Diagnostic——GarrisonError 存在固有 `code() -> &'static str`
        // 会遮蔽 trait 方法，必须全限定调用（见下方循环体）。

        let cases: [(GarrisonError, &str); 5] = [
            (
                GarrisonError::NotLogin("x".to_string()),
                "garrison.not_login",
            ),
            (
                GarrisonError::NotPermission("x".to_string()),
                "garrison.not_permission",
            ),
            (
                GarrisonError::FirewallBlocked("x".to_string()),
                "garrison.firewall_blocked",
            ),
            (
                GarrisonError::NotImplemented("x".to_string()),
                "garrison.not_implemented",
            ),
            (
                GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(
                    500, "x",
                ))),
                "garrison.exception",
            ),
        ];
        for (err, expected) in cases {
            // 固有 code() 会遮蔽 trait 方法，必须全限定调用 miette::Diagnostic::code
            let code =
                miette::Diagnostic::code(&err).expect("code() 应返回 Some(Box<dyn Display>)");
            assert_eq!(
                code.to_string(),
                expected,
                "code() 应返回 dotted kebab-case 形式"
            );
        }
    }

    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_severity_returns_error_for_all_variants() {
        use miette::{Diagnostic, Severity};

        let errors = [
            GarrisonError::NotLogin(String::new()),
            GarrisonError::NotPermission(String::new()),
            GarrisonError::NotRole(String::new()),
            GarrisonError::InvalidToken(String::new()),
            GarrisonError::ExpiredToken(String::new()),
            GarrisonError::Dao(String::new()),
            GarrisonError::Config(String::new()),
            GarrisonError::Internal(String::new()),
            GarrisonError::Session(String::new()),
            GarrisonError::Annotation(String::new()),
            GarrisonError::Context(String::new()),
            GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(500, ""))),
            GarrisonError::OAuth2(String::new()),
            GarrisonError::Network(String::new()),
            GarrisonError::InvalidResponse(String::new()),
            GarrisonError::InvalidParam(String::new()),
            GarrisonError::NotImplemented(String::new()),
            GarrisonError::FirewallBlocked(String::new()),
            GarrisonError::DisableService {
                service: String::new(),
                until: None,
            },
            GarrisonError::NotSafe {
                reason: String::new(),
            },
            GarrisonError::InvalidStateTransition {
                from: String::new(),
                to: String::new(),
            },
            GarrisonError::SmsRateLimitExceeded {
                window: String::new(),
            },
            GarrisonError::SmsVerifyMaxAttempts,
            GarrisonError::SmsCodeNotFound,
            GarrisonError::SmsChannelRecycled,
            GarrisonError::RateLimited {
                retry_after_secs: 5,
            },
        ];
        for err in errors {
            let sev = err.severity().expect("severity() 应返回 Some");
            assert_eq!(sev, Severity::Error, "{:?} severity 应为 Error", err);
        }
    }

    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_labels_returns_none_for_string_variants() {
        use miette::Diagnostic;

        let cases: [GarrisonError; 5] = [
            GarrisonError::NotLogin("x".to_string()),
            GarrisonError::Dao("x".to_string()),
            GarrisonError::Config("x".to_string()),
            GarrisonError::OAuth2("x".to_string()),
            GarrisonError::FirewallBlocked("x".to_string()),
        ];
        for err in cases {
            assert!(err.labels().is_none(), "{:?} 的 labels() 应返回 None", err);
        }
    }

    /// `miette::Report::new(error)` 可构造且 Debug 渲染含错误代码（Diagnostic + Send + Sync + 'static 集成可达）。
    #[cfg(feature = "miette")]
    #[test]
    fn diagnostic_can_be_rendered_with_miette_handler() {
        let err = GarrisonError::NotLogin("test message".to_string());
        let report = miette::Report::new(err);
        let rendered = format!("{:?}", report);
        assert!(
            rendered.contains("garrison.not_login"),
            "miette::Report 的 Debug 渲染应包含错误代码 garrison.not_login，实际: {}",
            rendered
        );
    }

    // 覆盖率补充：FirewallBlocked 变体

    #[test]
    fn firewall_blocked_variant_display_includes_message() {
        let err = GarrisonError::FirewallBlocked("IP 1.2.3.4 被拦截".to_string());
        assert_eq!(err.to_string(), "Firewall blocked: IP 1.2.3.4 被拦截");
    }

    #[test]
    fn firewall_blocked_response_parts_returns_403() {
        let (status, error_code, message, ex_code) =
            GarrisonError::FirewallBlocked("bruteforce".to_string()).response_parts();
        assert_eq!(status, 403, "FirewallBlocked 应映射为 403 Forbidden");
        assert_eq!(error_code, "FIREWALL_BLOCKED");
        assert_eq!(message, "Firewall blocked");
        assert!(ex_code.is_none(), "FirewallBlocked 不携带 exception code");
    }

    #[test]
    fn firewall_blocked_to_json_body_returns_correct_json() {
        let err = GarrisonError::FirewallBlocked("ratelimit".to_string());
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "FIREWALL_BLOCKED");
        assert_eq!(body["message"], "Firewall blocked");
        assert!(
            body.get("code").is_none(),
            "FirewallBlocked 不应包含 code 字段"
        );
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn firewall_blocked_error_returns_403() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let err = GarrisonError::FirewallBlocked("ddos".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // DisableService / NotSafe / InvalidStateTransition 变体测试

    #[test]
    fn disable_service_display_includes_service_and_until() {
        let err = GarrisonError::DisableService {
            service: "default".to_string(),
            until: None,
        };
        assert_eq!(
            err.to_string(),
            "Account disabled: service=default, until=None"
        );

        let until = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err_with_until = GarrisonError::DisableService {
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

    #[test]
    fn disable_service_response_parts_returns_403() {
        let err = GarrisonError::DisableService {
            service: "default".to_string(),
            until: None,
        };
        let (status, error_code, message, ex_code) = err.response_parts();
        assert_eq!(status, 403, "DisableService 应映射为 403 Forbidden");
        assert_eq!(error_code, "DISABLE_SERVICE");
        assert_eq!(message, "Account disabled");
        assert!(ex_code.is_none(), "DisableService 不携带 exception code");
    }

    #[test]
    fn disable_service_to_json_body_does_not_leak_service() {
        let err = GarrisonError::DisableService {
            service: "sensitive-service-name".to_string(),
            until: None,
        };
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "DISABLE_SERVICE");
        assert_eq!(body["message"], "Account disabled");
        // message 不应包含 service 字段值
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("sensitive-service-name"),
            "响应体 message 不应泄露 service 字段值"
        );
    }

    #[test]
    fn not_safe_display_includes_reason() {
        let err = GarrisonError::NotSafe {
            reason: "MFA_TOTP_REQUIRED".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Second factor authentication required: MFA_TOTP_REQUIRED"
        );
    }

    #[test]
    fn not_safe_response_parts_returns_400() {
        let err = GarrisonError::NotSafe {
            reason: "WEBAUTHN_REQUIRED".to_string(),
        };
        let (status, error_code, message, ex_code) = err.response_parts();
        assert_eq!(status, 400, "NotSafe 应映射为 400 Bad Request");
        assert_eq!(error_code, "NOT_SAFE");
        assert_eq!(message, "Two-factor authentication required");
        assert!(ex_code.is_none(), "NotSafe 不携带 exception code");
    }

    #[test]
    fn not_safe_to_json_body_does_not_leak_reason() {
        let err = GarrisonError::NotSafe {
            reason: "internal-mfa-secret-leak".to_string(),
        };
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "NOT_SAFE");
        assert_eq!(body["message"], "Two-factor authentication required");
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("internal-mfa-secret-leak"),
            "响应体 message 不应泄露 reason 字段值"
        );
    }

    #[test]
    fn invalid_state_transition_display_includes_from_and_to() {
        let err = GarrisonError::InvalidStateTransition {
            from: "Expired".to_string(),
            to: "Active".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid state transition: Expired -> Active"
        );
    }

    #[test]
    fn invalid_state_transition_response_parts_returns_500() {
        let err = GarrisonError::InvalidStateTransition {
            from: "Deleted".to_string(),
            to: "Active".to_string(),
        };
        let (status, error_code, message, ex_code) = err.response_parts();
        assert_eq!(
            status, 500,
            "InvalidStateTransition 应映射为 500 Internal Server Error"
        );
        assert_eq!(error_code, "INVALID_STATE_TRANSITION");
        assert_eq!(message, "Invalid state transition");
        assert!(ex_code.is_none());
    }

    #[test]
    fn invalid_state_transition_to_json_body_does_not_leak_states() {
        let err = GarrisonError::InvalidStateTransition {
            from: "InternalStateA".to_string(),
            to: "InternalStateB".to_string(),
        };
        let body = err.to_json_body();
        assert_eq!(body["error_code"], "INVALID_STATE_TRANSITION");
        assert_eq!(body["message"], "Invalid state transition");
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

    // BW-ERR 错误码常量测试

    #[test]
    fn bw_err_constants_match_frd_spec() {
        assert_eq!(GarrisonError::BW_ERR_009, 409001); // 并发登录冲突
        assert_eq!(GarrisonError::BW_ERR_010, 403003); // 账号被封禁
        assert_eq!(GarrisonError::BW_ERR_011, 401004); // 多账号体系冲突
        assert_eq!(GarrisonError::BW_ERR_012, 400001); // 第三方登录失败
    }

    // RateLimited 变体

    /// 全变体样本列表（哨兵：新增变体须同步加入，防唯一性检查失去覆盖）。
    fn all_variant_samples() -> Vec<GarrisonError> {
        #[cfg_attr(
            not(any(feature = "email-verification", feature = "credit-metering")),
            allow(unused_mut)
        )]
        let mut samples: Vec<GarrisonError> = vec![
            GarrisonError::NotLogin("a".into()),
            GarrisonError::NotPermission("a".into()),
            GarrisonError::NotRole("a".into()),
            GarrisonError::InvalidToken("a".into()),
            GarrisonError::TokenRevoked("a".into()),
            GarrisonError::ExpiredToken("a".into()),
            GarrisonError::Dao("a".into()),
            GarrisonError::Config("a".into()),
            GarrisonError::Internal("a".into()),
            GarrisonError::Session("a".into()),
            GarrisonError::Annotation("a".into()),
            GarrisonError::Context("a".into()),
            GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(-1, "a"))),
            GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(-2, "a"))),
            GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(500, "a"))),
            GarrisonError::OAuth2("a".into()),
            GarrisonError::Network("a".into()),
            GarrisonError::InvalidResponse("a".into()),
            GarrisonError::InvalidParam("a".into()),
            GarrisonError::NotImplemented("a".into()),
            GarrisonError::FirewallBlocked("a".into()),
            GarrisonError::DisableService {
                service: "default".into(),
                until: None,
            },
            GarrisonError::NotSafe {
                reason: "MFA_TOTP_REQUIRED".into(),
            },
            GarrisonError::InvalidStateTransition {
                from: "Active".into(),
                to: "Revoked".into(),
            },
            GarrisonError::RateLimited {
                retry_after_secs: 30,
            },
            GarrisonError::SmsRateLimitExceeded {
                window: "hourly".into(),
            },
            GarrisonError::SmsVerifyMaxAttempts,
            GarrisonError::SmsCodeNotFound,
            GarrisonError::SmsChannelRecycled,
        ];
        #[cfg(feature = "email-verification")]
        samples.extend([
            GarrisonError::EmailRateLimitExceeded {
                window: "hourly".into(),
            },
            GarrisonError::EmailVerifyMaxAttempts,
            GarrisonError::EmailCodeNotFound,
            GarrisonError::EmailChannelRecycled,
        ]);
        #[cfg(feature = "credit-metering")]
        samples.push(GarrisonError::CreditInsufficient {
            tenant_id: 1,
            requested: 10,
            remaining: 0,
        });
        samples
    }

    #[test]
    fn rate_limited_response_parts_returns_429() {
        let (status, error_code, message, ex_code) = GarrisonError::RateLimited {
            retry_after_secs: 30,
        }
        .response_parts();
        assert_eq!(status, 429, "RateLimited 应映射为 429 Too Many Requests");
        assert_eq!(error_code, "RATE_LIMITED");
        assert_eq!(message, "Rate limited");
        assert!(ex_code.is_none(), "RateLimited 不携带 exception code");
    }

    /// retry_after_secs：0 → Some(1)（下限 1）、30 → Some(30)、其余变体 None。
    #[test]
    fn retry_after_secs_floor_and_none_for_other_variants() {
        assert_eq!(
            GarrisonError::RateLimited {
                retry_after_secs: 0
            }
            .retry_after_secs(),
            Some(1),
            "retry_after_secs=0 应取下限 1"
        );
        assert_eq!(
            GarrisonError::RateLimited {
                retry_after_secs: 30
            }
            .retry_after_secs(),
            Some(30)
        );
        assert_eq!(GarrisonError::NotLogin("x".into()).retry_after_secs(), None);
        assert_eq!(
            GarrisonError::SmsRateLimitExceeded {
                window: "hourly".into()
            }
            .retry_after_secs(),
            None,
            "SMS 限速是 429 但不走统一 Retry-After 头语义（短信发送窗口，非网关限流）"
        );
    }

    /// prefixed_code：全变体两两唯一且格式合法（手写字符检查替代 regex，测试面不引入 optional dep）。
    #[test]
    fn prefixed_code_covers_all_variants_unique_and_well_formed() {
        fn is_well_formed_error_id(s: &str) -> bool {
            let Some((module, name)) = s.split_once('.') else {
                return false;
            };
            let is_module_seg = |seg: &str| {
                let mut chars = seg.chars();
                matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
                    && seg.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            };
            let is_name_seg = |seg: &str| {
                !seg.is_empty()
                    && seg.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                    && !seg.starts_with('_')
            };
            is_module_seg(module) && is_name_seg(name)
        }

        let samples = all_variant_samples();
        let mut seen = std::collections::HashSet::new();
        for err in &samples {
            let error_id = err.prefixed_code();
            assert!(
                is_well_formed_error_id(error_id),
                "error_id 格式非法: {error_id}"
            );
            assert!(
                seen.insert(error_id),
                "error_id 须两两唯一，重复: {error_id}"
            );
        }
        assert_eq!(samples.len(), seen.len());
        // 与 miette dotted 码先例风格一致（模块.蛇形名）
        assert_eq!(
            GarrisonError::NotLogin("x".into()).prefixed_code(),
            "auth.not_login"
        );
        assert_eq!(
            GarrisonError::RateLimited {
                retry_after_secs: 1
            }
            .prefixed_code(),
            "ratelimit.rate_limited"
        );
        assert_eq!(
            GarrisonError::SmsRateLimitExceeded {
                window: "daily".into()
            }
            .prefixed_code(),
            "sms.rate_limit_exceeded"
        );
        // Exception 变体子 arm 各自独立（避免与 auth.* 冲突，保证唯一性）
        assert_eq!(
            GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(-1, "x")))
                .prefixed_code(),
            "exception.not_login"
        );
    }

    /// 旧码冻结锚定：全 arm 的 HTTP 状态码 / error_code / 变体级机器码逐一对照字面期望（新旧并存，不 deprecate）；行数与 `all_variant_samples()` 对齐作哨兵，防新增变体未同步扩表。
    #[test]
    fn legacy_error_codes_frozen_at_original_values() {
        // (样本, response_parts().0, response_parts().1, code())
        // Exception 变体 HTTP 层按 ex.code 条件复用 NOT_LOGIN / NOT_PERMISSION，
        // 变体级机器码固定 EXCEPTION，故两者不同。
        #[cfg_attr(
            not(any(feature = "email-verification", feature = "credit-metering")),
            allow(unused_mut)
        )]
        let mut cases: Vec<(GarrisonError, u16, &'static str, &'static str)> = vec![
            (
                GarrisonError::NotLogin(String::new()),
                401,
                "NOT_LOGIN",
                "NOT_LOGIN",
            ),
            (
                GarrisonError::NotPermission(String::new()),
                403,
                "NOT_PERMISSION",
                "NOT_PERMISSION",
            ),
            (
                GarrisonError::NotRole(String::new()),
                403,
                "NOT_ROLE",
                "NOT_ROLE",
            ),
            (
                GarrisonError::InvalidToken(String::new()),
                401,
                "INVALID_TOKEN",
                "INVALID_TOKEN",
            ),
            (
                GarrisonError::TokenRevoked(String::new()),
                401,
                "TOKEN_REVOKED",
                "TOKEN_REVOKED",
            ),
            (
                GarrisonError::ExpiredToken(String::new()),
                401,
                "EXPIRED_TOKEN",
                "EXPIRED_TOKEN",
            ),
            (
                GarrisonError::Dao(String::new()),
                500,
                "DAO_ERROR",
                "DAO_ERROR",
            ),
            (
                GarrisonError::Config(String::new()),
                500,
                "CONFIG_ERROR",
                "CONFIG_ERROR",
            ),
            (
                GarrisonError::Internal(String::new()),
                500,
                "INTERNAL_ERROR",
                "INTERNAL_ERROR",
            ),
            (
                GarrisonError::Session(String::new()),
                500,
                "SESSION_ERROR",
                "SESSION_ERROR",
            ),
            (
                GarrisonError::Annotation(String::new()),
                500,
                "ANNOTATION_ERROR",
                "ANNOTATION_ERROR",
            ),
            (
                GarrisonError::Context(String::new()),
                500,
                "CONTEXT_ERROR",
                "CONTEXT_ERROR",
            ),
            (
                GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(
                    -1, "a",
                ))),
                401,
                "NOT_LOGIN",
                "EXCEPTION",
            ),
            (
                GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(
                    -2, "a",
                ))),
                403,
                "NOT_PERMISSION",
                "EXCEPTION",
            ),
            (
                GarrisonError::Exception(Box::new(crate::exception::GarrisonException::new(
                    500, "a",
                ))),
                500,
                "EXCEPTION",
                "EXCEPTION",
            ),
            (
                GarrisonError::OAuth2(String::new()),
                500,
                "OAUTH2_ERROR",
                "OAUTH2_ERROR",
            ),
            (
                GarrisonError::Network(String::new()),
                502,
                "NETWORK_ERROR",
                "NETWORK_ERROR",
            ),
            (
                GarrisonError::InvalidResponse(String::new()),
                502,
                "INVALID_RESPONSE",
                "INVALID_RESPONSE",
            ),
            (
                GarrisonError::InvalidParam(String::new()),
                400,
                "INVALID_PARAM",
                "INVALID_PARAM",
            ),
            (
                GarrisonError::NotImplemented(String::new()),
                501,
                "NOT_IMPLEMENTED",
                "NOT_IMPLEMENTED",
            ),
            (
                GarrisonError::FirewallBlocked(String::new()),
                403,
                "FIREWALL_BLOCKED",
                "FIREWALL_BLOCKED",
            ),
            (
                GarrisonError::DisableService {
                    service: String::new(),
                    until: None,
                },
                403,
                "DISABLE_SERVICE",
                "DISABLE_SERVICE",
            ),
            (
                GarrisonError::NotSafe {
                    reason: String::new(),
                },
                400,
                "NOT_SAFE",
                "NOT_SAFE",
            ),
            (
                GarrisonError::InvalidStateTransition {
                    from: String::new(),
                    to: String::new(),
                },
                500,
                "INVALID_STATE_TRANSITION",
                "INVALID_STATE_TRANSITION",
            ),
            (
                GarrisonError::RateLimited {
                    retry_after_secs: 1,
                },
                429,
                "RATE_LIMITED",
                "RATE_LIMITED",
            ),
            (
                GarrisonError::SmsRateLimitExceeded {
                    window: String::new(),
                },
                429,
                "SMS_RATE_LIMIT_EXCEEDED",
                "SMS_RATE_LIMIT_EXCEEDED",
            ),
            (
                GarrisonError::SmsVerifyMaxAttempts,
                400,
                "SMS_VERIFY_MAX_ATTEMPTS",
                "SMS_VERIFY_MAX_ATTEMPTS",
            ),
            (
                GarrisonError::SmsCodeNotFound,
                400,
                "SMS_CODE_NOT_FOUND",
                "SMS_CODE_NOT_FOUND",
            ),
            (
                GarrisonError::SmsChannelRecycled,
                403,
                "SMS_CHANNEL_RECYCLED",
                "SMS_CHANNEL_RECYCLED",
            ),
        ];
        #[cfg(feature = "email-verification")]
        cases.extend([
            (
                GarrisonError::EmailRateLimitExceeded {
                    window: String::new(),
                },
                429,
                "EMAIL_RATE_LIMIT_EXCEEDED",
                "EMAIL_RATE_LIMIT_EXCEEDED",
            ),
            (
                GarrisonError::EmailVerifyMaxAttempts,
                400,
                "EMAIL_VERIFY_MAX_ATTEMPTS",
                "EMAIL_VERIFY_MAX_ATTEMPTS",
            ),
            (
                GarrisonError::EmailCodeNotFound,
                400,
                "EMAIL_CODE_NOT_FOUND",
                "EMAIL_CODE_NOT_FOUND",
            ),
            (
                GarrisonError::EmailChannelRecycled,
                403,
                "EMAIL_CHANNEL_RECYCLED",
                "EMAIL_CHANNEL_RECYCLED",
            ),
        ]);
        #[cfg(feature = "credit-metering")]
        cases.push((
            GarrisonError::CreditInsufficient {
                tenant_id: 1,
                requested: 10,
                remaining: 0,
            },
            402,
            "CREDIT_INSUFFICIENT",
            "CREDIT_INSUFFICIENT",
        ));

        assert_eq!(
            cases.len(),
            all_variant_samples().len(),
            "冻结表未覆盖全部变体：新增变体须同步加入本表"
        );
        for (err, status, error_code, variant_code) in cases {
            let parts = err.response_parts();
            assert_eq!(parts.0, status, "HTTP 状态码不得变更（冻结锚定）: {err:?}");
            assert_eq!(
                parts.1, error_code,
                "旧 error_code 不得变更（冻结锚定）: {err:?}"
            );
            assert_eq!(
                err.code(),
                variant_code,
                "变体级机器码不得变更（冻结锚定）: {err:?}"
            );
        }
    }

    #[test]
    fn to_json_body_contains_error_id_alongside_legacy_code() {
        let body = GarrisonError::NotLogin("token missing".into()).to_json_body();
        assert_eq!(body["error_code"], "NOT_LOGIN", "旧码冻结输出");
        assert_eq!(body["error_id"], "auth.not_login", "新码并存输出");
        assert_eq!(body["message"], "Not logged in");
    }

    #[tokio::test]
    async fn to_json_body_request_id_omitted_outside_scope_and_set_inside() {
        let body = GarrisonError::NotLogin("x".into()).to_json_body();
        assert!(
            body.get("request_id").is_none(),
            "无 request id 时响应体不得出现 request_id 字段"
        );

        let body =
            crate::context::request_id::scope(std::sync::Arc::from("unified-body-id"), async {
                GarrisonError::NotLogin("x".into()).to_json_body()
            })
            .await;
        assert_eq!(body["request_id"], "unified-body-id");
    }

    #[test]
    fn rate_limited_msg_key_translates_in_both_locales() {
        let err = GarrisonError::RateLimited {
            retry_after_secs: 30,
        };

        let _zh = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let (_, _, zh_msg, _) = err.response_parts_i18n();
        assert_eq!(
            zh_msg, "请求过于频繁，请稍后重试",
            "zh locale 下 rate-limited-msg 应翻译为中文"
        );

        let _en = crate::i18n::set_locale(crate::i18n::GarrisonLocale::En);
        let (_, _, en_msg, _) = err.response_parts_i18n();
        assert_eq!(
            en_msg, "Rate limited, please try again later",
            "en locale 下 rate-limited-msg 应翻译为英文（不应回退到 fallback）"
        );
    }

    #[test]
    fn rate_limited_to_json_body_does_not_leak_internal_value() {
        let body = GarrisonError::RateLimited {
            retry_after_secs: 12345,
        }
        .to_json_body();
        let message_str = body["message"].as_str().unwrap();
        assert!(
            !message_str.contains("12345"),
            "message 不应泄露 retry_after_secs 内部值: {message_str}"
        );
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn rate_limited_into_response_sets_retry_after_header() {
        use axum::response::IntoResponse;

        let response = GarrisonError::RateLimited {
            retry_after_secs: 30,
        }
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        let value = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "30");
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn non_rate_limited_into_response_has_no_retry_after_header() {
        use axum::response::IntoResponse;

        let response = GarrisonError::NotLogin("x".into()).into_response();
        assert!(response.headers().get("Retry-After").is_none());
    }

    #[cfg(feature = "web-axum")]
    #[test]
    fn rate_limited_into_response_retry_after_floor_is_one() {
        use axum::response::IntoResponse;

        let response = GarrisonError::RateLimited {
            retry_after_secs: 0,
        }
        .into_response();
        let value = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "1");
    }

    #[cfg(feature = "web-axum")]
    #[tokio::test]
    async fn into_response_x_request_id_header_matches_body_request_id() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt;

        let response =
            crate::context::request_id::scope(std::sync::Arc::from("hdr-body-match-id"), async {
                GarrisonError::NotLogin("x".into()).into_response()
            })
            .await;
        let header_value = response
            .headers()
            .get("X-Request-ID")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(header_value, "hdr-body-match-id");
        let body_json: serde_json::Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("body collect")
                .to_bytes(),
        )
        .expect("错误响应体应是合法 JSON");
        assert_eq!(body_json["request_id"], "hdr-body-match-id");

        let response = GarrisonError::NotLogin("x".into()).into_response();
        assert!(response.headers().get("X-Request-ID").is_none());
        let body_json: serde_json::Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("body collect")
                .to_bytes(),
        )
        .expect("错误响应体应是合法 JSON");
        assert!(body_json.get("request_id").is_none());
    }

    #[cfg(feature = "web-axum")]
    #[tokio::test]
    async fn rate_limited_into_response_unified_body() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt;

        let response = GarrisonError::RateLimited {
            retry_after_secs: 30,
        }
        .into_response();
        let body_json: serde_json::Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("body collect")
                .to_bytes(),
        )
        .expect("错误响应体应是合法 JSON");
        assert_eq!(body_json["error_code"], "RATE_LIMITED");
        assert_eq!(body_json["error_id"], "ratelimit.rate_limited");
    }

    /// 日志级别锁定：RateLimited 渲染不得产生 error 级事件（429 攻击路径下无法被 EnvFilter 静音，构成日志洪水向量），其余变体保持 error。
    #[cfg(feature = "web-axum")]
    #[tokio::test]
    #[serial_test::serial]
    async fn rate_limited_into_response_logs_warn_not_error() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let events: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct LevelCapture(std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>);
        impl<S> tracing_subscriber::layer::Layer<S> for LevelCapture
        where
            S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let level = event.metadata().level().to_string();
                let mut rendered = String::new();
                event.record(
                    &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                        rendered.push_str(&format!("{}={:?} ", field.name(), value));
                    },
                );
                self.0
                    .lock()
                    .expect("日志缓冲锁应可用")
                    .push((level, rendered));
            }
        }
        let _guard = tracing_subscriber::registry()
            .with(LevelCapture(events.clone()))
            .set_default();
        // interest 缓存是进程级全局态：并行非订阅者测试可能抢先首次注册 rejection
        // 事件 callsite 并缓存 Interest::never（事件被宏直接剔除），须显式重建
        tracing::callsite::rebuild_interest_cache();

        use axum::response::IntoResponse;
        // 以 error 级哨兵事件（NotLogin）判断捕获有效，缺失则重建后重试
        for _ in 0..3 {
            let _ = GarrisonError::RateLimited {
                retry_after_secs: 30,
            }
            .into_response();
            let _ = GarrisonError::NotLogin("x".into()).into_response();
            let snapshot = events.lock().expect("日志缓冲锁应可用").clone();
            if snapshot
                .iter()
                .any(|(level, msg)| level == "ERROR" && msg.contains("NotLogin"))
            {
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }

        let events = events.lock().expect("日志缓冲锁应可用").clone();
        assert!(
            !events
                .iter()
                .any(|(level, msg)| level == "ERROR" && msg.contains("RateLimited")),
            "RateLimited 渲染不得产生 error 级事件，实际: {events:?}"
        );
        assert!(
            events.iter().any(|(level, _)| level == "WARN"),
            "RateLimited 渲染应降级为 warn 级，实际: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|(level, msg)| level == "ERROR" && msg.contains("NotLogin")),
            "非限流变体应保持 error 级（哨兵：防止捕获层失效导致测试恒绿），实际: {events:?}"
        );
    }
}
