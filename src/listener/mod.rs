// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 监听器模块，提供事件订阅抽象与编译期注册（`inventory` crate，替代 Java SPI）。
//!
//! 与 `plugin` 的区别：plugin 是主动钩子（`on_login` 等方法前后），listener 是被动订阅
//! `GarrisonEvent` 变体；listener 失败仅记录 `tracing::warn!`，不中断主流程。

use crate::error::GarrisonResult;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;

/// 审计日志子模块。
///
/// 启用 `audit-log` feature 时编译，提供 `AuditLogListener` 持久化事件到 `audit_logs` 表。
#[cfg(feature = "audit-log")]
pub mod audit;

/// 审计事件防篡改 HMAC 链子模块。
///
/// 启用 `audit-log` feature 时编译：`AuditEventChain` 随机盐链首 + HMAC-SHA256
/// 链式签名，任一事件被篡改/删除/重排/伪造即校验失败，保证审计取证完整性。
#[cfg(feature = "audit-log")]
pub mod audit_chain;

/// 请求上下文。
///
/// 携带 HTTP 请求相关的客户端信息，由事件广播方注入 `GarrisonEvent` 的
/// `request_context` 字段，供 `to_audit_entry` 提取 ip 与 user_agent。
///
/// # ⚠️ PII 说明
///
/// `ip` 与 `user_agent` 属于**个人身份信息（PII）**：持久化或输出到日志即把 PII
/// 写入存储层。实现方应按司法辖区法规（GDPR / 个保法）确定留存期限与合法 basis，
/// 优先部分掩码或聚合统计；参考 `AuditLogListener` 的 `mask_metadata` /
/// `audit_mask_mode` 脱敏管线。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// 客户端 IP 地址（可选）。⚠️ 含 PII，持久化/输出前应脱敏（见类型级文档）。
    pub ip: Option<String>,
    /// 客户端 User-Agent（可选）。⚠️ 含 PII，持久化/输出前应脱敏（见类型级文档）。
    pub user_agent: Option<String>,
}

/// 事件载荷 token 脱敏（CWE-532）。
///
/// 长 token（>8 字符）输出前 8 字符 + `***`；短 token 输出固定占位 `***`。
/// `get(..8)` 为字符安全截取（避免多字节 UTF-8 中间截断 panic）。
///
/// 契约：各事件的 token 类字段**统一**为掩码形式（构造点脱敏），与 `GarrisonEvent`
/// 手动 `Debug` 脱敏形成双保险；需要完整 token 的消费方不应通过事件获取。
pub fn mask_token_for_event(token: &str) -> String {
    match token.get(..8) {
        Some(prefix) if token.len() > 8 => format!("{}***", prefix),
        _ => "***".to_string(),
    }
}

/// 事件枚举，定义框架广播的所有事件变体。
///
/// 派生 `Clone`、`PartialEq`；**`Debug` 为手动实现（非 derive）**：token / key 类
/// 敏感字段在 `{:?}` 中脱敏（前 8 字节 + `***`），且字段值本身也统一为掩码形式
/// （构造点脱敏，CWE-532），防 `{:?}` 或字段直读泄露明文 token。
#[derive(Clone, PartialEq)]
pub enum GarrisonEvent {
    /// 登录成功事件。
    Login {
        /// 登录主体标识。
        login_id: String,
        /// 登录后生成的 token（**掩码形式**：前 8 字符 + `***`，不含完整 token）。
        token: String,
        /// 登录设备信息（可选）。
        device: Option<String>,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 登出事件。
    Logout {
        /// 登录主体标识。
        login_id: String,
        /// 被登出的 token（**掩码形式**，不含完整 token）。
        token: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 被踢下线事件。
    Kickout {
        /// 登录主体标识。
        login_id: String,
        /// 被踢下线的 token（**掩码形式**，不含完整 token；空字符串表示按 login_id 整体踢出）。
        token: String,
        /// 踢出原因。
        reason: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 权限校验事件。
    PermissionCheck {
        /// 登录主体标识。
        login_id: String,
        /// 被校验的权限字符串。
        permission: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 角色校验事件。
    RoleCheck {
        /// 登录主体标识。
        login_id: String,
        /// 被校验的角色字符串。
        role: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// Token 过期事件。
    TokenExpired {
        /// 过期的 token（**掩码形式**，不含完整 token）。
        token: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 登录失败事件。
    ///
    /// 在 `login_with_password` 失败路径广播（invalid_credentials / hash_format_error）。
    LoginFailure {
        /// 登录主体标识。
        login_id: String,
        /// 失败原因（"invalid_credentials" / "hash_format_error"）。
        ///
        /// user_not_found 与 wrong_password 统一为 "invalid_credentials"，
        /// 防止日志/事件泄露用户存在性（防用户枚举）。
        reason: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 密码哈希惰性升级事件。
    ///
    /// 在 `login_with_password` verify 通过且存量哈希档位低于当前配置时广播——
    /// 登录路径重哈希并落库成功后才广播（落库失败不广播，不虚报审计）；
    /// 不携带新旧哈希值（哈希即凭据材料，事件载荷最小化）。
    PasswordRehashed {
        /// 登录主体标识。
        login_id: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// Token 刷新事件。
    ///
    /// 在 `refresh_token` 成功路径广播，携带旧 token 与新 token。
    TokenRefresh {
        /// 登录主体标识。
        login_id: String,
        /// 刷新前的旧 token（**掩码形式**，不含完整 token）。
        old_token: String,
        /// 刷新后的新 token（**掩码形式**，不含完整 token）。
        new_token: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// Token 主动吊销事件。
    ///
    /// 在 `SessionLogic::revoke_token` 调用时广播（如 OAuth2 token revocation）；
    /// 区别于 `Logout`（用户主动登出，携带 login_id+token）。
    RevokeToken {
        /// 被吊销的 token。
        token: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 会话超时事件。
    ///
    /// 在 `check_login_simple` / `check_login_mixin` 判定 token 无效时广播；
    /// token session 完全不存在（无法获取 login_id）时跳过广播。
    SessionTimeout {
        /// 登录主体标识。
        login_id: String,
        /// 超时的 token。
        token: String,
        /// 请求上下文（IP + User-Agent）。
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
        /// 请求上下文（IP + User-Agent）。
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
        /// 请求上下文（IP + User-Agent）。
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
        /// 请求上下文（IP + User-Agent）。
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
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    // 变体
    /// 社交登录事件。
    ///
    /// 在社交登录（微信/支付宝等）成功时广播。
    SocialLogin {
        /// 社交登录 provider 名称（如 "wechat" / "alipay"）。
        provider: String,
        /// 社交平台返回的用户 ID。
        user_id: String,
        /// 关联的本地 login_id（首次登录可能为 None，绑定后才有）。
        login_id: Option<String>,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 租户切换事件。
    ///
    /// 在用户切换租户上下文时广播。
    TenantSwitch {
        /// 登录主体标识。
        login_id: String,
        /// 切换前的租户 ID。
        from_tenant: i64,
        /// 切换后的租户 ID。
        to_tenant: i64,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 设备封禁事件。
    ///
    /// 在设备被风控封禁时广播。
    DeviceBlock {
        /// 登录主体标识。
        login_id: String,
        /// 被封禁的设备标识。
        device: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 设备解封事件。
    ///
    /// 在设备被封禁后解封时广播。
    DeviceUnblock {
        /// 登录主体标识。
        login_id: String,
        /// 被解封的设备标识。
        device: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 配置热重载事件。
    ///
    /// 在运行时配置被热重载时广播。
    ConfigReload {
        /// 新配置版本号。
        config_version: u32,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 异常登录检测事件。
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
        /// 请求上下文（IP + User-Agent）。
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
        /// 请求上下文（IP + User-Agent）。
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
    /// 扫码登录会话创建事件（第一方扫码登录）。
    ///
    /// 在 `QrLoginService::create_session` 成功路径广播。
    QrLoginCreated {
        /// 扫码会话 ID（掩码形式：前 8 字符 + `***`，构造点脱敏）。
        qr_id: String,
        /// 请求上下文（IP + User-Agent，待登录端）。
        request_context: Option<RequestContext>,
    },
    /// 扫码登录已扫码事件。
    ///
    /// 在 `QrLoginService::scan` 成功路径（Pending → Scanned）广播。
    QrLoginScanned {
        /// 扫码会话 ID（掩码形式）。
        qr_id: String,
        /// 确认者 login_id。
        app_login_id: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 扫码登录已确认事件。
    ///
    /// 在 `QrLoginService::confirm` Confirm 迁移成功路径广播。
    QrLoginConfirmed {
        /// 扫码会话 ID（掩码形式）。
        qr_id: String,
        /// 确认者 login_id。
        app_login_id: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
    /// 扫码登录已取消事件。
    ///
    /// 在 `QrLoginService::confirm` Cancel 迁移成功路径广播。
    QrLoginCancelled {
        /// 扫码会话 ID（掩码形式）。
        qr_id: String,
        /// 确认者 login_id。
        app_login_id: String,
        /// 请求上下文（IP + User-Agent）。
        request_context: Option<RequestContext>,
    },
}

/// Debug 脱敏 helper：敏感字符串不输出明文。
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
            GarrisonEvent::PasswordRehashed {
                login_id,
                request_context,
            } => f
                .debug_struct("PasswordRehashed")
                .field("login_id", login_id)
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
            GarrisonEvent::QrLoginCreated {
                qr_id,
                request_context,
            } => f
                .debug_struct("QrLoginCreated")
                .field("qr_id", &redact_secret_for_debug(qr_id))
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::QrLoginScanned {
                qr_id,
                app_login_id,
                request_context,
            } => f
                .debug_struct("QrLoginScanned")
                .field("qr_id", &redact_secret_for_debug(qr_id))
                .field("app_login_id", app_login_id)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::QrLoginConfirmed {
                qr_id,
                app_login_id,
                request_context,
            } => f
                .debug_struct("QrLoginConfirmed")
                .field("qr_id", &redact_secret_for_debug(qr_id))
                .field("app_login_id", app_login_id)
                .field("request_context", request_context)
                .finish(),
            GarrisonEvent::QrLoginCancelled {
                qr_id,
                app_login_id,
                request_context,
            } => f
                .debug_struct("QrLoginCancelled")
                .field("qr_id", &redact_secret_for_debug(qr_id))
                .field("app_login_id", app_login_id)
                .field("request_context", request_context)
                .finish(),
        }
    }
}

/// 监听器 trait：核心方法 `on_event`，默认空实现返回 `Ok(())`，trait 绑定 `Send + Sync`。
#[async_trait]
pub trait GarrisonListener: Send + Sync {
    /// 事件处理方法：实现方按事件类型选择性处理，应快速返回或内部 spawn，
    /// 避免阻塞主流程；支持异步监听器（如 SQL-backed `AuditLogListener`）。
    async fn on_event(&self, _event: &GarrisonEvent) -> GarrisonResult<()> {
        Ok(())
    }
}

/// 事件派发结果（OnCommit 档，[`broadcast_after_commit`](GarrisonListenerManager::broadcast_after_commit) 返回）。
///
/// 不变式：`dispatched + failed == 派发事件总数`。
/// `failed > 0` 表示存在 listener `Err` / panic 的事件，审计链存在缺口，
/// 调用方必须显性处理（告警 / 补偿），禁止静默忽略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DispatchOutcome {
    /// 所有 listener 均成功处理（返回 `Ok`）的事件数。
    pub dispatched: usize,
    /// 存在 listener `Err` 或 panic 的事件数（该事件的派发链有缺口）。
    pub failed: usize,
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
///
/// # 两档派发语义
///
/// - **Immediately 档**（`broadcast`）：事件产生即同步派发，不与任何数据库事务
///   绑定。单个监听器 `Err`/panic 仅记录 `tracing::warn!`，不中断广播、不返回
///   计数——适用于可容忍丢失的旁路事件。
/// - **OnCommit 档**（`broadcast_after_commit`）：事件先缓冲在
///   `GarrisonEventTx`（`dao` 模块的事务 guard），数据库事务 commit 成功后才
///   FIFO 派发，并返回 `DispatchOutcome`（`failed` 计数显性化审计链缺口）；
///   rollback 或未 commit 丢弃 guard 时缓冲事件不派发。适用于「业务写库与
///   事件必须同生共死」的场景（如登录日志 SQL 写 + `Login` 事件）。
///
/// 两档共用同一监听器集合与同一隔离承诺：单个监听器 `Err`/panic 均被
/// `catch_unwind` 捕获降级为 `tracing::warn!`，不中断、不传播，后续监听器
/// 与后续事件继续处理。
pub struct GarrisonListenerManager {
    /// 已注册的监听器列表（`RwLock` 保护，支持运行时 `register` 追加）。
    listeners: Arc<RwLock<Vec<Arc<dyn GarrisonListener>>>>,
}

mod manager_impl;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
