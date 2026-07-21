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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// 客户端 IP 地址（可选）。
    pub ip: Option<String>,
    /// 客户端 User-Agent（可选）。
    pub user_agent: Option<String>,
}

/// 事件枚举，定义框架广播的所有事件变体。
///
/// 派生 `Debug`、`Clone`、`PartialEq`，便于在监听器中复制、打印与比较。
#[derive(Debug, Clone, PartialEq)]
pub enum GarrisonEvent {
    /// 登录成功事件。
    Login {
        /// 登录主体标识。
        login_id: String,
        /// 登录后生成的 token。
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
        /// 被登出的 token。
        token: String,
        /// 请求上下文（IP + User-Agent，T004 新增）。
        request_context: Option<RequestContext>,
    },
    /// 被踢下线事件。
    Kickout {
        /// 登录主体标识。
        login_id: String,
        /// 被踢下线的 token。
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
        /// 过期的 token。
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
        /// 刷新前的旧 token。
        old_token: String,
        /// 刷新后的新 token。
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
/// 在 `GarrisonManager::init` 时通过 `inventory::iter` 收集所有已注册监听器。
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
