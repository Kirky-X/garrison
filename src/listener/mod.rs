//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 监听器模块，提供事件订阅抽象与编译期注册。
//!
//! 对应 `SaTokenListener`，
//! 通过 `inventory` crate 实现编译期监听器注册（替代 Java SPI）。
//!
//! 与 `plugin` 模块的区别：
//! - `GarrisonPlugin`：主动钩子（在特定方法前后被调用，如 `on_login`）
//! - `GarrisonListener`：被动订阅（订阅 `GarrisonEvent` 枚举的变体）
//!
//! 此模块仅在启用 `listener` 特性时编译。
//! 监听器失败仅记录 `tracing::warn!`，不中断主流程。

use crate::error::GarrisonResult;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;

/// 审计日志子模块。
///
/// 启用 `audit-log` feature 时编译，提供 `AuditLogListener` 持久化事件到 `audit_logs` 表。
#[cfg(feature = "audit-log")]
pub mod audit;

/// 请求上下文（T004 新增）。
///
/// 携带与 HTTP 请求相关的客户端信息，由事件广播方注入到 `GarrisonEvent` 的
/// `request_context` 字段，供 `to_audit_entry` 提取 ip 与 user_agent 填充审计日志。
///
/// # 字段
///
/// - `ip`: 客户端 IP 地址（可选，未知时为 `None`）
/// - `user_agent`: 客户端 User-Agent（可选，未知时为 `None`）
///
/// # ⚠️ PII 说明（ocr #3028）
///
/// `ip` 与 `user_agent` 属于**个人身份信息（PII）**：任何 listener / audit sink
/// 若将其持久化或输出到日志，即把 PII 写入存储层。实现方应：
/// - 遵循所在司法辖区的数据保护法规（如 GDPR / 个保法）确定留存期限与合法 basis；
/// - 优先使用部分掩码（如 `203.0.113.*`）或聚合统计；
/// - 审计场景参考 `AuditLogListener` 的 `mask_metadata` / `audit_mask_mode` 脱敏管线。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// 客户端 IP 地址（可选）。⚠️ 含 PII，持久化/输出前应脱敏（见类型级文档）。
    pub ip: Option<String>,
    /// 客户端 User-Agent（可选）。⚠️ 含 PII，持久化/输出前应脱敏（见类型级文档）。
    pub user_agent: Option<String>,
}

/// 事件载荷 token 脱敏（CWE-532 修复，v0.9.0）。
///
/// 长 token（>8 字符）输出前 8 字符 + `***`；短 token 输出固定占位 `***`。
/// `get(..8)` 为字符安全截取（避免多字节 UTF-8 中间截断 panic）。
///
/// # 语义契约
///
/// 自 v0.9.0 起，`Login` / `Logout` / `Kickout` / `Replaced` / `TokenExpired` /
/// `TokenRefresh` / `RevokeToken` / `SessionTimeout` 等事件的 token 类字段
/// **统一携带掩码形式**（非完整 token）：listener 直接打日志不再泄露活动会话
/// token，与 `GarrisonEvent` 手动 `Debug` 脱敏形成双保险（ocr #2370）。
/// 需要完整 token 的消费方不应通过事件获取（框架自身消费走内部调用链）。
/// `SessionExpiryListener` 等回调参数中的完整 token 打日志前也应使用本函数脱敏。
pub fn mask_token_for_event(token: &str) -> String {
    match token.get(..8) {
        Some(prefix) if token.len() > 8 => format!("{}***", prefix),
        _ => "***".to_string(),
    }
}

/// 事件枚举，定义框架广播的所有事件变体。
///
/// 派生 `Clone`、`PartialEq`；**`Debug` 为手动实现（非 derive）**：
/// `token` / `old_token` / `new_token` / `old_key` / `new_key` 等敏感字段在
/// `{:?}` 输出中脱敏（仅保留前 8 字节 + `***`，短密钥整体掩码），防止监听器或
/// 框架代码用 `{:?}` 打日志时泄露明文 token（ocr #2370）。
///
/// # v0.9.0 载荷脱敏（CWE-532）
///
/// 上述 token 类**字段值本身**也统一为 [`mask_token_for_event`] 掩码形式
/// （构造点脱敏）：即使 listener 以 `{:?}` 之外的方式（如 `token` 字段直读）
/// 输出日志，活动会话 token 也不会以明文进入日志系统。
#[derive(Clone, PartialEq)]
pub enum GarrisonEvent {
    /// 登录成功事件。
    Login {
        /// 登录主体标识。
        login_id: String,
        /// 登录后生成的 token（**掩码形式**：前 8 字符 + `***`，v0.9.0 起不含完整 token）。
        token: String,
        /// 登录设备信息（可选）。
        device: Option<String>,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 登出事件。
    Logout {
        /// 登录主体标识。
        login_id: String,
        /// 被登出的 token（**掩码形式**，v0.9.0 起不含完整 token）。
        token: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 被踢下线事件。
    Kickout {
        /// 登录主体标识。
        login_id: String,
        /// 被踢下线的 token（**掩码形式**，v0.9.0 起不含完整 token；空字符串表示按 login_id 整体踢出）。
        token: String,
        /// 踢出原因。
        reason: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 权限校验事件。
    PermissionCheck {
        /// 登录主体标识。
        login_id: String,
        /// 被校验的权限字符串。
        permission: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 角色校验事件。
    RoleCheck {
        /// 登录主体标识。
        login_id: String,
        /// 被校验的角色字符串。
        role: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// Token 过期事件。
    TokenExpired {
        /// 过期的 token（**掩码形式**，v0.9.0 起不含完整 token）。
        token: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 登录失败事件。
    ///
    /// 在 `login_with_password` 失败路径广播（invalid_credentials / hash_format_error）。
    /// 注意：login_id 字段使用 `String` 类型，以保持与现有变体一致
    ///（偏差 D-Phase11-1，依据规则 11 惯例优先于新颖）。
    LoginFailure {
        /// 登录主体标识。
        login_id: String,
        /// 失败原因（"invalid_credentials" / "hash_format_error"）。
        ///
        /// v0.4.2 安全审计 A-014: user_not_found 与 wrong_password 统一为 "invalid_credentials"，
        /// 防止日志/事件泄露用户存在性（防用户枚举）。
        reason: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// Token 刷新事件。
    ///
    /// 在 `refresh_token` 成功路径广播，携带旧 token 与新 token。
    TokenRefresh {
        /// 登录主体标识。
        login_id: String,
        /// 刷新前的旧 token（**掩码形式**，v0.9.0 起不含完整 token）。
        old_token: String,
        /// 刷新后的新 token（**掩码形式**，v0.9.0 起不含完整 token）。
        new_token: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// Token 主动吊销事件。
    ///
    /// 在 `SessionLogic::revoke_token` 调用时广播（携带被吊销的 token）。
    /// 与 `Logout` 事件的区别：`revoke_token` 语义为"token 失效"（如 OAuth2 token revocation），
    /// `Logout` 语义为"用户主动登出"（携带 login_id+token）。
    RevokeToken {
        /// 被吊销的 token。
        token: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 会话超时事件。
    ///
    /// 在 `check_login_simple` / `check_login_mixin` 判定 token 无效时广播。
    /// 若 token session 完全不存在（无法获取 login_id）则跳过广播。
    SessionTimeout {
        /// 登录主体标识。
        login_id: String,
        /// 超时的 token。
        token: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 账号锁定事件。
    ///
    /// 在 `check_brute_force` 阻断路径广播（暴力破解检测触发）。
    AccountLocked {
        /// 登录主体标识。
        login_id: String,
        /// 锁定原因（如 "brute_force: 5 failures in 1h"）。
        reason: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 防火墙阻断事件。
    ///
    /// 在 `check_login_hooks` 任一 hook 返回 Err 时广播。
    FirewallBlock {
        /// 登录主体标识。
        login_id: String,
        /// 阻断原因（hook 错误信息）。
        reason: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// API Key 轮换事件。
    ///
    /// 在 `ApiKeyHandler::rotate` 成功路径广播。
    TokenRotate {
        /// 轮换前的旧 key。
        old_key: String,
        /// 轮换后的新 key。
        new_key: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 临时凭据消费事件。
    ///
    /// 在 `TempCredentialHandler::consume` 成功消费时广播（value 为 Some 时）。
    TempCredentialConsumed {
        /// 被消费的凭据 key。
        key: String,
        /// 凭据载荷值。
        value: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    // ========================================================================
    // 变体（spec R-audit-log-005 要求，T076 Green）
    // ========================================================================
    /// 社交登录事件（spec R-audit-log-005）。
    ///
    /// 在社交登录（微信/支付宝等）成功时广播。
    SocialLogin {
        /// 社交登录 provider 名称（如 "wechat" / "alipay"）。
        provider: String,
        /// 社交平台返回的用户 ID。
        user_id: String,
        /// 关联的本地 login_id（首次登录可能为 None，绑定后才有）。
        login_id: Option<String>,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 租户切换事件（spec R-audit-log-005）。
    ///
    /// 在用户切换租户上下文时广播。
    TenantSwitch {
        /// 登录主体标识。
        login_id: String,
        /// 切换前的租户 ID。
        from_tenant: i64,
        /// 切换后的租户 ID。
        to_tenant: i64,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 设备封禁事件（spec R-audit-log-005）。
    ///
    /// 在设备被风控封禁时广播。
    DeviceBlock {
        /// 登录主体标识。
        login_id: String,
        /// 被封禁的设备标识。
        device: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 设备解封事件（spec R-audit-log-005）。
    ///
    /// 在设备被封禁后解封时广播。
    DeviceUnblock {
        /// 登录主体标识。
        login_id: String,
        /// 被解封的设备标识。
        device: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 配置热重载事件（spec R-audit-log-005）。
    ///
    /// 在运行时配置被热重载时广播。
    ConfigReload {
        /// 新配置版本号。
        config_version: u32,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 异常登录检测事件（spec R-anomalous-detector-dual-006）。
    ///
    /// 在定时分析引擎检测到异常登录模式时广播。
    #[cfg(feature = "anomalous-detector-dual")]
    AnomalousLoginDetected {
        /// 登录主体标识。
        login_id: String,
        /// 异常原因（`"burst_login"` / `"geo_jump"` / `"device_mutation"`）。
        reason: String,
        /// 检测详情（JSON 值）。
        detail: serde_json::Value,
        /// 检测时间戳（Unix 秒）。
        timestamp: i64,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 被顶替下线事件（超出最大登录数时，最旧会话被新会话顶替）。
    Replaced {
        /// 登录主体标识。
        login_id: String,
        /// 被顶替的 token。
        token: String,
        /// 顶替原因。
        reason: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// Credit 消费事件（多租户配额计量）。
    ///
    /// 在 `CreditMeter::consume_credit` 成功消费后广播。
    #[cfg(feature = "credit-metering")]
    CreditConsumed {
        /// 租户 ID。
        tenant_id: i64,
        /// 消费的资源类型。
        resource: String,
        /// 消费成本（原始 cost）。
        cost: u64,
        /// 消耗的 credit 数（cost * weight）。
        credits: u64,
        /// 消费后累计消费总量。
        total_consumed: u64,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// Credit 告警事件（配额阈值触发）。
    ///
    /// 在 `CreditMeter::consume_credit` 检测到 usage_percent >= alert_threshold 时广播。
    #[cfg(feature = "credit-metering")]
    CreditAlert {
        /// 租户 ID。
        tenant_id: i64,
        /// 触发的告警阈值（百分比，如 80 / 90 / 100）。
        threshold: u8,
        /// 当前使用百分比。
        usage_percent: f64,
        /// 当前累计消费量。
        total_consumed: u64,
        /// 配额上限。
        credit_limit: u64,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 邀请码创建事件。
    ///
    /// 在 `InvitationHandler::create` / `batch_create` 成功路径广播。
    InvitationCreated {
        /// 邀请码。
        code: String,
        /// 签发者 ID。
        issuer_id: String,
    },
    /// 邀请码吊销事件。
    ///
    /// 在 `InvitationHandler::revoke` 成功路径广播（首次吊销，幂等跳过）。
    InvitationRevoked {
        /// 邀请码。
        code: String,
        /// 签发者 ID。
        issuer_id: String,
    },
    /// 邀请码兑换事件。
    ///
    /// 在 `InvitationHandler::redeem` 成功路径广播。
    InvitationRedeemed {
        /// 邀请码。
        code: String,
        /// 兑换者 ID。
        redeemer_id: String,
    },
}

/// Debug 脱敏 helper（ocr #2370）：敏感字符串不输出明文。
///
/// 超过 8 字节保留前 8 字节 + `***`（保留可识别前缀供排障关联）；
/// 不超过 8 字节整体掩码为 `***`（短密钥全量输出即泄露）。
/// 用 `get(..8)` 而非字节切片：非 char boundary 时退化为整体掩码，不 panic。
fn redact_secret_for_debug(s: &str) -> String {
    match s.get(..8) {
        Some(prefix) if s.len() > 8 => format!("{prefix}***"),
        _ => "***".to_string(),
    }
}

impl std::fmt::Debug for GarrisonEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 脱敏范围：token 类字段（token/old_token/new_token/old_key/new_key）、
        // 凭据载荷（TempCredentialConsumed.value）与邀请码（code，兑换即凭据）。
        // login_id / device / ip 等保留明文（排障关联标识，PII 处理见 RequestContext 文档）。
        match self {
            GarrisonEvent::Login {
                login_id,
                token,
                device,
                request_context,
            } => f
                .debug_struct("Login")
                .field("login_id", login_id)
                .field("token", &redact_secret_for_debug(token))
                .field("device", device)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::Logout {
                login_id,
                token,
                request_context,
            } => f
                .debug_struct("Logout")
                .field("login_id", login_id)
                .field("token", &redact_secret_for_debug(token))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::Kickout {
                login_id,
                token,
                reason,
                request_context,
            } => f
                .debug_struct("Kickout")
                .field("login_id", login_id)
                .field("token", &redact_secret_for_debug(token))
                .field("reason", reason)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::PermissionCheck {
                login_id,
                permission,
                request_context,
            } => f
                .debug_struct("PermissionCheck")
                .field("login_id", login_id)
                .field("permission", permission)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::RoleCheck {
                login_id,
                role,
                request_context,
            } => f
                .debug_struct("RoleCheck")
                .field("login_id", login_id)
                .field("role", role)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::TokenExpired {
                token,
                request_context,
            } => f
                .debug_struct("TokenExpired")
                .field("token", &redact_secret_for_debug(token))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::LoginFailure {
                login_id,
                reason,
                request_context,
            } => f
                .debug_struct("LoginFailure")
                .field("login_id", login_id)
                .field("reason", reason)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::TokenRefresh {
                login_id,
                old_token,
                new_token,
                request_context,
            } => f
                .debug_struct("TokenRefresh")
                .field("login_id", login_id)
                .field("old_token", &redact_secret_for_debug(old_token))
                .field("new_token", &redact_secret_for_debug(new_token))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::RevokeToken {
                token,
                request_context,
            } => f
                .debug_struct("RevokeToken")
                .field("token", &redact_secret_for_debug(token))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::SessionTimeout {
                login_id,
                token,
                request_context,
            } => f
                .debug_struct("SessionTimeout")
                .field("login_id", login_id)
                .field("token", &redact_secret_for_debug(token))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::AccountLocked {
                login_id,
                reason,
                request_context,
            } => f
                .debug_struct("AccountLocked")
                .field("login_id", login_id)
                .field("reason", reason)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::FirewallBlock {
                login_id,
                reason,
                request_context,
            } => f
                .debug_struct("FirewallBlock")
                .field("login_id", login_id)
                .field("reason", reason)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::TokenRotate {
                old_key,
                new_key,
                request_context,
            } => f
                .debug_struct("TokenRotate")
                .field("old_key", &redact_secret_for_debug(old_key))
                .field("new_key", &redact_secret_for_debug(new_key))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::TempCredentialConsumed {
                key,
                value,
                request_context,
            } => f
                .debug_struct("TempCredentialConsumed")
                .field("key", key)
                .field("value", &redact_secret_for_debug(value))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::SocialLogin {
                provider,
                user_id,
                login_id,
                request_context,
            } => f
                .debug_struct("SocialLogin")
                .field("provider", provider)
                .field("user_id", user_id)
                .field("login_id", login_id)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::TenantSwitch {
                login_id,
                from_tenant,
                to_tenant,
                request_context,
            } => f
                .debug_struct("TenantSwitch")
                .field("login_id", login_id)
                .field("from_tenant", from_tenant)
                .field("to_tenant", to_tenant)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::DeviceBlock {
                login_id,
                device,
                request_context,
            } => f
                .debug_struct("DeviceBlock")
                .field("login_id", login_id)
                .field("device", device)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::DeviceUnblock {
                login_id,
                device,
                request_context,
            } => f
                .debug_struct("DeviceUnblock")
                .field("login_id", login_id)
                .field("device", device)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::ConfigReload {
                config_version,
                request_context,
            } => f
                .debug_struct("ConfigReload")
                .field("config_version", config_version)
                .field("request_context", request_context)
                .finish(),
            #[cfg(feature = "anomalous-detector-dual")]
            GarrisonEvent::AnomalousLoginDetected {
                login_id,
                reason,
                detail,
                timestamp,
                request_context,
            } => f
                .debug_struct("AnomalousLoginDetected")
                .field("login_id", login_id)
                .field("reason", reason)
                .field("detail", detail)
                .field("timestamp", timestamp)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::Replaced {
                login_id,
                token,
                reason,
                request_context,
            } => f
                .debug_struct("Replaced")
                .field("login_id", login_id)
                .field("token", &redact_secret_for_debug(token))
                .field("reason", reason)
                .field("request_context", request_context)
                .finish(),
            #[cfg(feature = "credit-metering")]
            GarrisonEvent::CreditConsumed {
                tenant_id,
                resource,
                cost,
                credits,
                total_consumed,
                request_context,
            } => f
                .debug_struct("CreditConsumed")
                .field("tenant_id", tenant_id)
                .field("resource", resource)
                .field("cost", cost)
                .field("credits", credits)
                .field("total_consumed", total_consumed)
                .field("request_context", request_context)
                .finish(),
            #[cfg(feature = "credit-metering")]
            GarrisonEvent::CreditAlert {
                tenant_id,
                threshold,
                usage_percent,
                total_consumed,
                credit_limit,
                request_context,
            } => f
                .debug_struct("CreditAlert")
                .field("tenant_id", tenant_id)
                .field("threshold", threshold)
                .field("usage_percent", usage_percent)
                .field("total_consumed", total_consumed)
                .field("credit_limit", credit_limit)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::InvitationCreated { code, issuer_id } => f
                .debug_struct("InvitationCreated")
                .field("code", &redact_secret_for_debug(code))
                .field("issuer_id", issuer_id)
                .finish(),
            GarrisonEvent::InvitationRevoked { code, issuer_id } => f
                .debug_struct("InvitationRevoked")
                .field("code", &redact_secret_for_debug(code))
                .field("issuer_id", issuer_id)
                .finish(),
            GarrisonEvent::InvitationRedeemed { code, redeemer_id } => f
                .debug_struct("InvitationRedeemed")
                .field("code", &redact_secret_for_debug(code))
                .field("redeemer_id", redeemer_id)
                .finish(),
        }
    }
}

/// 监听器 trait，提供事件订阅抽象。
///
/// trait 绑定 `Send + Sync`，核心方法为 `on_event`，实现方按事件类型选择性处理。
/// 与 `GarrisonPlugin` 的区别：plugin 是"主动钩子"（在特定方法前后被调用），
/// listener 是"被动订阅"（订阅事件类型）。
#[async_trait]
pub trait GarrisonListener: Send + Sync {
    /// 事件处理方法。
    ///
    /// 实现方按事件类型选择性处理，默认空实现返回 `Ok(())`。
    /// 监听器实现应快速返回或内部 spawn，避免阻塞主流程。
    ///
    /// v0.5.0 改为 async：支持 SQL-backed 监听器（如 AuditLogListener）
    /// 执行异步持久化操作。所有实现与调用方需 `.await`。
    async fn on_event(&self, _event: &GarrisonEvent) -> GarrisonResult<()> {
        Ok(())
    }
}

/// 监听器工厂函数指针，返回 `Arc<dyn GarrisonListener>`。
pub type GarrisonListenerFactoryFn = fn() -> Arc<dyn GarrisonListener>;

/// 监听器注册条目，用于 `inventory` 收集。
///
/// 通过 `inventory::submit! { GarrisonListenerEntry { factory: my_listener_factory } }` 注册监听器，
/// 运行期通过 `inventory::iter::<GarrisonListenerEntry>()` 遍历。
pub struct GarrisonListenerEntry {
    /// 监听器工厂函数。
    pub factory: GarrisonListenerFactoryFn,
}

// 编译期监听器注册收集点
inventory::collect!(GarrisonListenerEntry);

/// 监听器管理器，收集并管理所有已注册监听器。
///
/// 在 `GarrisonManager::builder()` 时通过 `inventory::iter` 收集所有已注册监听器。
/// `broadcast` 方法同步遍历所有监听器调用 `on_event`，
/// 单个监听器失败时仅记录 `tracing::warn!` 日志，不中断广播。
pub struct GarrisonListenerManager {
    /// 已注册的监听器列表（`RwLock` 保护，支持运行时 `register` 追加）。
    listeners: Arc<RwLock<Vec<Arc<dyn GarrisonListener>>>>,
}

mod manager_impl;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
