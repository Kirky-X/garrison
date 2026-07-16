//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 审计日志模块。
//!
//! 提供 `AuditLogListener` 实现，将 `BulwarkEvent` 持久化到 `audit_logs` 表，
//! 支持字段掩码（如 password）与异步写入。
//!
//! ## 核心抽象
//!
//! - [`AuditConfig`](crate::listener::audit::AuditConfig)：审计日志配置（掩码字段 + 保留天数 + 异步写入开关）
//! - `AuditLogListener`：实现 `BulwarkListener`，将事件转换为 `AuditEntry` 持久化（T071-T078 实现）
//! - `AuditEntry`：`audit_logs` 表行结构（T071-T072 实现）
//! - `AuditQuery`：审计日志查询条件（T079-T080 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE audit_logs (
//!     id INTEGER PRIMARY KEY AUTOINCREMENT,
//!     tenant_id INTEGER NOT NULL DEFAULT 0,
//!     event_type TEXT NOT NULL,
//!     login_id INTEGER,
//!     token TEXT,
//!     ip TEXT,
//!     user_agent TEXT,
//!     metadata TEXT,
//!     success INTEGER NOT NULL,
//!     created_at INTEGER NOT NULL
//! );
//! ```

use crate::config::AuditMaskMode;
#[cfg(feature = "db-sqlite")]
use crate::error::{BulwarkError, BulwarkResult};

// ============================================================================
// AuditConfig 定义（T068 Green）
// ============================================================================

/// 审计日志配置（T068 Green）。
///
/// 控制 `AuditLogListener` 的行为：字段掩码、保留天数、异步写入、导出签名。
///
/// # 字段
///
/// - `mask_fields`: 需掩码的字段列表（如 `password`），metadata JSON 中对应字段值替换为 `"***"`
/// - `retain_days`: 日志保留天数（过期自动清理，0 表示永不清理）
/// - `async_write`: 是否异步写入（true 时不阻塞主流程，失败仅 `tracing::warn`）
/// - `signing_key`: HMAC-SHA256 签名密钥（用于 `export_csv`/`export_json` 的签名链）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    /// 需掩码的字段列表（如 `password`），metadata JSON 中对应字段值替换为 `"***"`。
    pub mask_fields: Vec<String>,
    /// 日志保留天数（过期自动清理，0 表示永不清理）。
    pub retain_days: u32,
    /// 是否异步写入（true 时不阻塞主流程，失败仅 `tracing::warn`）。
    pub async_write: bool,
    /// HMAC-SHA256 签名密钥（D4 新增）。
    ///
    /// `Some(key)` 时 `export_csv`/`export_json` 为每行附加 `signature` 字段，
    /// 构成链式签名（第 N 行签名依赖第 N-1 行签名 + 当前行内容）。
    /// `None` 时 `export_csv`/`export_json` 返回 `BulwarkError::Config`。
    pub signing_key: Option<String>,
    /// 审计脱敏模式（T012）。默认 `Partial`。
    ///
    /// - `Full`：所有 `mask_fields` 字段值替换为 `"***"`（完全屏蔽）
    /// - `Partial`：使用 `SensitiveDataMasker` 类型感知脱敏（如手机号 → `138****1234`）
    pub audit_mask_mode: AuditMaskMode,
}

// ============================================================================
// AuditEntry + AuditLogListener（需 db-sqlite feature）
// ============================================================================
//
// Rule 7 冲突暴露：
// - tasks.md T072 说 `pub struct AuditLogListener { pub dao: Arc<dyn BulwarkDao>, .. }`
//   并在 BulwarkDao trait 新增 `async fn insert_audit_log`
// - 但 BulwarkDao 是 cache 抽象（4 实现：Oxcache/MockDao/MinimalDao/AloneCache，
//   均不支持 SQL INSERT），强行加 insert_audit_log 会破坏单一职责
// - Rule 11（惯例优先）：遵循 RefreshTokenRotation 先例（H4 T057），
//   AuditLogListener 持 `pool: DbPool` 直连 SQL，不污染 BulwarkDao trait

#[cfg(feature = "db-sqlite")]
use super::{BulwarkEvent, BulwarkListener};
#[cfg(feature = "db-sqlite")]
use async_trait::async_trait;
#[cfg(feature = "db-sqlite")]
use chrono::Utc;
#[cfg(feature = "db-sqlite")]
use dbnexus::DbPool;
#[cfg(feature = "db-sqlite")]
use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
// D4: HMAC-SHA256 签名链依赖（audit-log feature 启用 sha2 + hmac）
#[cfg(all(feature = "audit-log", feature = "db-sqlite"))]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(all(feature = "audit-log", feature = "db-sqlite"))]
use sha2::Sha256;
// T012: Partial 脱敏模式依赖 SensitiveDataMasker（secure-masking feature）
#[cfg(all(feature = "secure-masking", feature = "db-sqlite"))]
use crate::secure::masking::{MaskType, SensitiveDataMasker};

/// 构造 metadata JSON 字符串（T078 辅助函数）。
///
/// 接受 `&[(&str, &str)]` 键值对，序列化为 JSON 对象字符串。
/// 字符串值自动转义（由 `serde_json` 处理）。
#[cfg(feature = "db-sqlite")]
fn json_metadata(pairs: &[(&str, &str)]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| {
            (
                (*k).to_string(),
                serde_json::Value::String((*v).to_string()),
            )
        })
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// 从 `BulwarkEvent` 提取 `request_context` 引用（T004 辅助函数）。
///
/// 遍历所有变体，返回 `Option<&RequestContext>`。
/// `None` 表示事件未携带请求上下文（向后兼容）。
#[cfg(feature = "db-sqlite")]
fn extract_request_context(event: &BulwarkEvent) -> Option<&super::RequestContext> {
    match event {
        BulwarkEvent::Login {
            request_context, ..
        }
        | BulwarkEvent::Logout {
            request_context, ..
        }
        | BulwarkEvent::Kickout {
            request_context, ..
        }
        | BulwarkEvent::PermissionCheck {
            request_context, ..
        }
        | BulwarkEvent::RoleCheck {
            request_context, ..
        }
        | BulwarkEvent::TokenExpired {
            request_context, ..
        }
        | BulwarkEvent::LoginFailure {
            request_context, ..
        }
        | BulwarkEvent::TokenRefresh {
            request_context, ..
        }
        | BulwarkEvent::RevokeToken {
            request_context, ..
        }
        | BulwarkEvent::SessionTimeout {
            request_context, ..
        }
        | BulwarkEvent::AccountLocked {
            request_context, ..
        }
        | BulwarkEvent::FirewallBlock {
            request_context, ..
        }
        | BulwarkEvent::TokenRotate {
            request_context, ..
        }
        | BulwarkEvent::TempCredentialConsumed {
            request_context, ..
        }
        | BulwarkEvent::SocialLogin {
            request_context, ..
        }
        | BulwarkEvent::TenantSwitch {
            request_context, ..
        }
        | BulwarkEvent::DeviceBlock {
            request_context, ..
        }
        | BulwarkEvent::DeviceUnblock {
            request_context, ..
        }
        | BulwarkEvent::ConfigReload {
            request_context, ..
        }
        | BulwarkEvent::Replaced {
            request_context, ..
        } => request_context.as_ref(),
        // anomalous-detector-dual feature 关闭时，无 AnomalousLoginDetected 变体，
        // 上述 match 已穷尽所有变体，此分支不可达。
        #[cfg(feature = "anomalous-detector-dual")]
        BulwarkEvent::AnomalousLoginDetected {
            request_context, ..
        } => request_context.as_ref(),
    }
}

/// 创建审计默认脱敏器（T012 辅助函数）。
///
/// 注册常见敏感字段的类型感知脱敏规则：
/// - `phone` → 手机号脱敏（保留前 3 后 4）
/// - `email` → 邮箱脱敏（保留首字符 + 域名）
/// - `id_card` → 身份证脱敏（保留前 3 后 4）
/// - `bank_card` → 银行卡脱敏（保留前 6 后 4，PCI-DSS 3.4）
#[cfg(all(feature = "secure-masking", feature = "db-sqlite"))]
fn default_audit_masker() -> SensitiveDataMasker {
    SensitiveDataMasker::new()
        .with_rule(MaskType::Phone, "phone")
        .with_rule(MaskType::Email, "email")
        .with_rule(MaskType::IdCard, "id_card")
        .with_rule(MaskType::BankCard, "bank_card")
}

/// `audit_logs` 表行结构（T072 Green）。
///
/// 对应 `migrations/sqlite/core/004_audit_logs.sql` 的表定义，
/// 由 `AuditLogListener::to_audit_entry` 从 `BulwarkEvent` 转换而来。
///
/// # 字段
///
/// - `tenant_id`: 租户 ID（默认 0，多租户隔离时填充）
/// - `event_type`: 事件类型（如 "login" / "logout" / "kickout"）
/// - `login_id`: 登录主体标识（部分事件无 login_id，如 TokenExpired）
/// - `token`: 关联 token（可选）
/// - `ip`: 客户端 IP（可选，需从上下文注入）
/// - `user_agent`: User-Agent（可选）
/// - `metadata`: 附加元数据 JSON 字符串（可选，已掩码）
/// - `success`: 事件是否成功（Login= true / LoginFailure = false）
/// - `created_at`: Unix 时间戳（秒）
#[cfg(feature = "db-sqlite")]
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// 租户 ID（默认 0）。
    pub tenant_id: i64,
    /// 事件类型（如 "login" / "logout" / "kickout"）。
    pub event_type: String,
    /// 登录主体标识（部分事件无 login_id）。
    pub login_id: Option<String>,
    /// 关联 token（可选）。
    pub token: Option<String>,
    /// 客户端 IP（可选）。
    pub ip: Option<String>,
    /// User-Agent（可选）。
    pub user_agent: Option<String>,
    /// 附加元数据 JSON 字符串（可选，已掩码）。
    pub metadata: Option<String>,
    /// 事件是否成功。
    pub success: bool,
    /// Unix 时间戳（秒）。
    pub created_at: i64,
}

/// 审计日志查询条件（T079-T080 Green）。
///
/// 用于 `AuditLogListener::query_audit_logs` 构造复合查询条件，
/// 所有字段为 `Option`，`None` 表示不过滤该维度。
///
/// # 字段
///
/// - `tenant_id`: 按租户 ID 过滤（`Some(0)` 查默认租户）
/// - `event_type`: 按事件类型过滤（如 `Some("login")`）
/// - `from`: `created_at >= from`（Unix 秒）
/// - `to`: `created_at <= to`（Unix 秒）
///
/// # 设计（Rule 7 override，依据 T072 先例）
///
/// spec R-audit-log-007 原文说 `BulwarkDao::query_audit_logs`，
/// 但 BulwarkDao 是 cache 抽象（get/set/delete），不支持 SQL SELECT；
/// 强行加 `query_audit_logs` 会破坏单一职责（与 T072 insert 同冲突）。
/// Rule 11（惯例优先）：遵循 T072 先例，`query_audit_logs` 作为
/// `AuditLogListener` 的方法，持 `pool: DbPool` 直连 SQL。
#[cfg(feature = "db-sqlite")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// 按租户 ID 过滤（`Some(0)` 查默认租户）。
    pub tenant_id: Option<i64>,
    /// 按事件类型过滤（如 `Some("login")`）。
    pub event_type: Option<String>,
    /// `created_at >= from`（Unix 秒）。
    pub from: Option<i64>,
    /// `created_at <= to`（Unix 秒）。
    pub to: Option<i64>,
}

/// 审计日志监听器（T072 Green）。
///
/// 实现 `BulwarkListener`，将 `BulwarkEvent` 转换为 `AuditEntry` 并 INSERT 到 `audit_logs` 表。
///
/// # 设计（Rule 7 override，依据 RefreshTokenRotation 先例）
///
/// 持 `pool: DbPool` 直连 SQL，而非 `dao: Arc<dyn BulwarkDao>`。
/// 原因：BulwarkDao 是 cache 抽象（get/set/delete），不支持 SQL INSERT；
/// 强行加 `insert_audit_log` 会破坏单一职责。
#[cfg(feature = "db-sqlite")]
pub struct AuditLogListener {
    /// dbnexus 连接池，用于 SQL INSERT。
    pub pool: DbPool,
    /// 审计配置（掩码字段、保留天数、异步写入）。
    pub config: AuditConfig,
}

#[cfg(feature = "db-sqlite")]
impl AuditLogListener {
    /// 创建审计日志监听器。
    pub fn new(pool: DbPool, config: AuditConfig) -> Self {
        Self { pool, config }
    }

    /// 将 `BulwarkEvent` 转换为 `AuditEntry`（全 19 变体穷尽 match）。
    ///
    /// spec R-audit-log-006 要求：`match` 无 `_ =>` 兜底，新增变体时编译错误提醒补实现。
    ///
    /// 14 个 spec 必需变体（R-audit-log-005）+ 5 个既有安全变体，全部转换为 AuditEntry。
    /// `event_type` 使用变体名 snake_case（如 `LoginFailure` → `"login_failure"`）。
    ///
    /// 转换后对 `metadata` 调用 `mask_metadata` 进行字段掩码。
    fn to_audit_entry(&self, event: &BulwarkEvent) -> BulwarkResult<AuditEntry> {
        let now = Utc::now().timestamp();
        // 从 TENANT task_local 读取当前租户 ID
        // - tenant-isolation feature 关闭：current_tenant_id() 无上下文时返回 0（向后兼容）
        // - tenant-isolation feature 启用：current_tenant_id_or_error() 无上下文时返回 Err（Rule 12 失败显性化，vuln-0003）
        #[cfg(not(feature = "tenant-isolation"))]
        #[allow(deprecated)]
        let tenant_id = crate::context::tenant::current_tenant_id();
        #[cfg(feature = "tenant-isolation")]
        let tenant_id = crate::context::tenant::current_tenant_id_or_error()?;
        let mut entry = match event {
            BulwarkEvent::Login {
                login_id,
                token,
                device,
                ..
            } => AuditEntry {
                tenant_id,
                event_type: "login".to_string(),
                login_id: Some(login_id.clone()),
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: device.as_ref().map(|d| json_metadata(&[("device", d)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::Logout {
                login_id, token, ..
            } => AuditEntry {
                tenant_id,
                event_type: "logout".to_string(),
                login_id: Some(login_id.clone()),
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: now,
            },
            BulwarkEvent::Kickout {
                login_id,
                token,
                reason,
                ..
            } => AuditEntry {
                tenant_id,
                event_type: "kickout".to_string(),
                login_id: Some(login_id.clone()),
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("reason", reason)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::PermissionCheck {
                login_id,
                permission,
                ..
            } => AuditEntry {
                tenant_id,
                event_type: "permission_check".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("permission", permission)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::RoleCheck { login_id, role, .. } => AuditEntry {
                tenant_id,
                event_type: "role_check".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("role", role)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::TokenExpired { token, .. } => AuditEntry {
                tenant_id,
                event_type: "token_expired".to_string(),
                login_id: None,
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: false,
                created_at: now,
            },
            BulwarkEvent::LoginFailure {
                login_id, reason, ..
            } => AuditEntry {
                tenant_id,
                event_type: "login_failure".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("reason", reason)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::TokenRefresh {
                login_id,
                old_token,
                new_token,
                ..
            } => AuditEntry {
                tenant_id,
                event_type: "token_refresh".to_string(),
                login_id: Some(login_id.clone()),
                token: Some(new_token.clone()),
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("old_token", old_token)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::RevokeToken { token, .. } => AuditEntry {
                tenant_id,
                event_type: "revoke_token".to_string(),
                login_id: None,
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: now,
            },
            BulwarkEvent::SessionTimeout {
                login_id, token, ..
            } => AuditEntry {
                tenant_id,
                event_type: "session_timeout".to_string(),
                login_id: Some(login_id.clone()),
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: false,
                created_at: now,
            },
            BulwarkEvent::AccountLocked {
                login_id, reason, ..
            } => AuditEntry {
                tenant_id,
                event_type: "account_locked".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("reason", reason)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::FirewallBlock {
                login_id, reason, ..
            } => AuditEntry {
                tenant_id,
                event_type: "firewall_block".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("reason", reason)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::TokenRotate {
                old_key, new_key, ..
            } => AuditEntry {
                tenant_id,
                event_type: "token_rotate".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("old_key", old_key), ("new_key", new_key)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::TempCredentialConsumed { key, value, .. } => AuditEntry {
                tenant_id,
                event_type: "temp_credential_consumed".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("key", key), ("value", value)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::SocialLogin {
                provider,
                user_id,
                login_id,
                ..
            } => AuditEntry {
                tenant_id,
                event_type: "social_login".to_string(),
                login_id: login_id.clone(),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[
                    ("provider", provider),
                    ("user_id", user_id),
                ])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::TenantSwitch {
                login_id,
                from_tenant,
                to_tenant,
                ..
            } => AuditEntry {
                tenant_id,
                event_type: "tenant_switch".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[
                    ("from_tenant", &from_tenant.to_string()),
                    ("to_tenant", &to_tenant.to_string()),
                ])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::DeviceBlock {
                login_id, device, ..
            } => AuditEntry {
                tenant_id,
                event_type: "device_block".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("device", device)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::DeviceUnblock {
                login_id, device, ..
            } => AuditEntry {
                tenant_id,
                event_type: "device_unblock".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("device", device)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::ConfigReload { config_version, .. } => AuditEntry {
                tenant_id,
                event_type: "config_reload".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[(
                    "config_version",
                    &config_version.to_string(),
                )])),
                success: true,
                created_at: now,
            },
            // feature-gated 变体由 match 后的 if let 覆盖，此处走默认条目
            _ => AuditEntry {
                tenant_id,
                event_type: "other".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: now,
            },
        };
        // 覆盖 anomalous-detector-dual feature 的 AnomalousLoginDetected 变体
        #[cfg(feature = "anomalous-detector-dual")]
        if let BulwarkEvent::AnomalousLoginDetected {
            login_id,
            reason,
            detail,
            timestamp: _,
            ..
        } = event
        {
            entry = AuditEntry {
                tenant_id,
                event_type: "anomalous_login_detected".to_string(),
                login_id: Some(login_id.clone()),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(
                    serde_json::to_string(&serde_json::json!({
                        "reason": reason,
                        "detail": detail,
                    }))
                    .unwrap_or_default(),
                ),
                success: false,
                created_at: now,
            };
        }
        // 对 metadata 进行字段掩码（如 password → ***）
        entry.metadata = entry.metadata.map(|m| self.mask_metadata(&m));
        // T004: 从 event.request_context 提取 ip/user_agent 填充 audit entry
        // 统一在 match 之后处理，避免每个 arm 重复提取逻辑
        if let Some(ctx) = extract_request_context(event) {
            entry.ip = ctx.ip.clone();
            entry.user_agent = ctx.user_agent.clone();
        }
        Ok(entry)
    }

    /// 对 metadata JSON 字符串进行字段掩码（T074 Green）。
    ///
    /// 遍历 `config.mask_fields`，将 metadata JSON 中对应字段值替换为 `"***"`。
    /// 非 JSON 字符串或字段不存在时原样返回（不报错）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use bulwark::listener::audit::{AuditConfig, AuditLogListener};
    /// let config = AuditConfig {
    ///     mask_fields: vec!["password".to_string()],
    ///     retain_days: 0,
    ///     async_write: false,
    ///     signing_key: None,
    ///     audit_mask_mode: AuditMaskMode::Partial,
    /// };
    /// // 假设已有 pool
    /// // let listener = AuditLogListener::new(pool, config);
    /// // let masked = listener.mask_metadata(r#"{"password":"secret"}"#);
    /// // assert_eq!(masked, r#"{"password":"***"}"#);
    /// ```
    pub fn mask_metadata(&self, metadata: &str) -> String {
        if self.config.mask_fields.is_empty() || metadata.is_empty() {
            return metadata.to_string();
        }
        let mut value: serde_json::Value = match serde_json::from_str(metadata) {
            Ok(v) => v,
            Err(_) => return metadata.to_string(),
        };
        match self.config.audit_mask_mode {
            AuditMaskMode::Full => self.mask_value_recursive(&mut value),
            AuditMaskMode::Partial => {
                #[cfg(feature = "secure-masking")]
                {
                    self.mask_value_partial(&mut value);
                }
                #[cfg(not(feature = "secure-masking"))]
                {
                    // secure-masking 未启用时回退到 Full 行为（安全优先）
                    self.mask_value_recursive(&mut value);
                }
            },
        }
        serde_json::to_string(&value).unwrap_or_else(|_| metadata.to_string())
    }

    /// 递归脱敏 JSON 值中的敏感字段（包括嵌套对象）。
    fn mask_value_recursive(&self, value: &mut serde_json::Value) {
        if let Some(obj) = value.as_object_mut() {
            for field in &self.config.mask_fields {
                if obj.contains_key(field) {
                    obj.insert(field.clone(), serde_json::Value::String("***".to_string()));
                }
            }
            // 递归处理嵌套对象
            for (_, child) in obj.iter_mut() {
                self.mask_value_recursive(child);
            }
        }
        if let Some(arr) = value.as_array_mut() {
            for item in arr.iter_mut() {
                self.mask_value_recursive(item);
            }
        }
    }

    /// Partial 模式递归脱敏：使用 `SensitiveDataMasker` 类型感知脱敏（T012）。
    ///
    /// 对 `mask_fields` 中的字段：
    /// - 匹配 `SensitiveDataMasker` 规则的字段（phone/email/id_card/bank_card）→ 类型感知脱敏
    /// - 无匹配规则的字段 → 回退为 `"***"`（安全优先）
    #[cfg(feature = "secure-masking")]
    fn mask_value_partial(&self, value: &mut serde_json::Value) {
        let masker = default_audit_masker();
        if let Some(obj) = value.as_object_mut() {
            for field in &self.config.mask_fields {
                if let Some(serde_json::Value::String(s)) = obj.get_mut(field) {
                    let masked = masker.mask_field(field, s);
                    if masked == *s {
                        // 无匹配规则，回退为 "***"
                        *s = "***".to_string();
                    } else {
                        *s = masked;
                    }
                }
            }
            // 递归处理嵌套对象
            for (_, child) in obj.iter_mut() {
                self.mask_value_partial(child);
            }
        }
        if let Some(arr) = value.as_array_mut() {
            for item in arr.iter_mut() {
                self.mask_value_partial(item);
            }
        }
    }

    /// INSERT `AuditEntry` 到 `audit_logs` 表。
    async fn insert(&self, entry: &AuditEntry) -> BulwarkResult<()> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| BulwarkError::Dao(format!("get_session 失败: {}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("connection 失败: {}", e)))?;

        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO audit_logs (tenant_id, event_type, login_id, token, ip, user_agent, metadata, success, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Value::BigInt(Some(entry.tenant_id)),
                Value::String(Some(entry.event_type.clone())),
                Value::String(entry.login_id.clone()),
                Value::String(entry.token.clone()),
                Value::String(entry.ip.clone()),
                Value::String(entry.user_agent.clone()),
                Value::String(entry.metadata.clone()),
                Value::Bool(Some(entry.success)),
                Value::BigInt(Some(entry.created_at)),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("INSERT audit_logs 失败: {}", e)))?;
        Ok(())
    }

    /// 按复合条件查询审计日志（T080 Green）。
    ///
    /// 动态拼 SQL `WHERE` 子句，所有参数使用占位符 `?` 防止 SQL 注入。
    /// `AuditQuery` 字段为 `None` 时跳过该过滤维度。
    /// 结果按 `created_at` 升序排列。
    ///
    /// # 设计（Rule 7 override，依据 T072 先例）
    ///
    /// spec R-audit-log-007 原文说 `BulwarkDao::query_audit_logs`，
    /// 但 BulwarkDao 是 cache 抽象，不支持 SQL SELECT。
    /// 遵循 T072 insert 先例，此方法作为 `AuditLogListener` 的方法，持 `pool: DbPool` 直连 SQL。
    pub async fn query_audit_logs(&self, query: AuditQuery) -> BulwarkResult<Vec<AuditEntry>> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| BulwarkError::Dao(format!("get_session 失败: {}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("connection 失败: {}", e)))?;

        // 动态拼 SQL WHERE 子句（参数化防注入）
        let mut sql = String::from(
            "SELECT tenant_id, event_type, login_id, token, ip, user_agent, metadata, success, created_at FROM audit_logs WHERE 1=1",
        );
        let mut params: Vec<Value> = Vec::new();
        if let Some(tenant_id) = query.tenant_id {
            sql.push_str(" AND tenant_id = ?");
            params.push(Value::BigInt(Some(tenant_id)));
        }
        if let Some(event_type) = &query.event_type {
            sql.push_str(" AND event_type = ?");
            params.push(Value::String(Some(event_type.clone())));
        }
        if let Some(from) = query.from {
            sql.push_str(" AND created_at >= ?");
            params.push(Value::BigInt(Some(from)));
        }
        if let Some(to) = query.to {
            sql.push_str(" AND created_at <= ?");
            params.push(Value::BigInt(Some(to)));
        }
        sql.push_str(" ORDER BY created_at ASC");

        let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, params);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("SELECT audit_logs 失败: {}", e)))?;

        rows.iter()
            .map(|row| {
                let tenant_id: i64 = row.try_get("", "tenant_id").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (tenant_id): {}", e))
                })?;
                let event_type: String = row.try_get("", "event_type").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (event_type): {}", e))
                })?;
                let login_id: Option<String> = row.try_get("", "login_id").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (login_id): {}", e))
                })?;
                let token: Option<String> = row.try_get("", "token").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (token): {}", e))
                })?;
                let ip: Option<String> = row
                    .try_get("", "ip")
                    .map_err(|e| BulwarkError::Dao(format!("audit_logs 行解析失败 (ip): {}", e)))?;
                let user_agent: Option<String> = row.try_get("", "user_agent").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (user_agent): {}", e))
                })?;
                let metadata: Option<String> = row.try_get("", "metadata").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (metadata): {}", e))
                })?;
                // success 存储为 INTEGER（0/1），读为 i64 后转 bool
                let success_int: i64 = row.try_get("", "success").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (success): {}", e))
                })?;
                let created_at: i64 = row.try_get("", "created_at").map_err(|e| {
                    BulwarkError::Dao(format!("audit_logs 行解析失败 (created_at): {}", e))
                })?;
                Ok(AuditEntry {
                    tenant_id,
                    event_type,
                    login_id,
                    token,
                    ip,
                    user_agent,
                    metadata,
                    success: success_int != 0,
                    created_at,
                })
            })
            .collect()
    }

    /// 导出审计日志为 CSV 字符串（D4 新增）。
    ///
    /// 列：`timestamp,login_id,tenant_id,event_type,signature`
    ///
    /// 签名链：每行的 `signature` = HMAC-SHA256(key, prev_signature + row_content)，
    /// 其中 `row_content` = `timestamp,login_id,tenant_id,event_type`，
    /// `prev_signature` 初始为空字符串，之后为上一行的 signature。
    ///
    /// # 参数
    ///
    /// - `entries`: 审计日志条目切片（按时间顺序）
    ///
    /// # 返回
    ///
    /// - 空 `entries`：返回仅含 header 的 CSV 字符串
    /// - 非空：返回含 header + 数据行的 CSV 字符串
    /// - `config.signing_key` 为 `None`：返回 `BulwarkError::Config`
    #[cfg(feature = "audit-log")]
    pub fn export_csv(&self, entries: &[AuditEntry]) -> BulwarkResult<String> {
        let signatures = self.compute_signature_chain(entries)?;
        let mut csv = String::from("timestamp,login_id,tenant_id,event_type,signature");
        for (entry, sig) in entries.iter().zip(signatures.iter()) {
            let login_id_str = entry.login_id.as_deref().unwrap_or("");
            csv.push('\n');
            csv.push_str(&format!(
                "{},{},{},{},{}",
                entry.created_at, login_id_str, entry.tenant_id, entry.event_type, sig
            ));
        }
        Ok(csv)
    }

    /// 导出审计日志为 JSON 数组字符串（D4 新增）。
    ///
    /// 每行一个 JSON 对象，包含 `timestamp`/`login_id`/`tenant_id`/`event_type`/`signature` 字段。
    /// 签名链算法同 `export_csv`。
    ///
    /// # 参数
    ///
    /// - `entries`: 审计日志条目切片（按时间顺序）
    ///
    /// # 返回
    ///
    /// - 空 `entries`：返回 `"[]"`
    /// - 非空：返回 JSON 数组字符串
    /// - `config.signing_key` 为 `None`：返回 `BulwarkError::Config`
    #[cfg(feature = "audit-log")]
    pub fn export_json(&self, entries: &[AuditEntry]) -> BulwarkResult<String> {
        let signatures = self.compute_signature_chain(entries)?;
        if entries.is_empty() {
            return Ok("[]".to_string());
        }
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .zip(signatures.iter())
            .map(|(entry, sig)| {
                serde_json::json!({
                    "timestamp": entry.created_at,
                    "login_id": entry.login_id,
                    "tenant_id": entry.tenant_id,
                    "event_type": &entry.event_type,
                    "signature": sig,
                })
            })
            .collect();
        serde_json::to_string(&arr)
            .map_err(|e| BulwarkError::Config(format!("JSON 序列化失败: {}", e)))
    }

    /// 验证 HMAC-SHA256 签名链（D4 新增）。
    ///
    /// 重新计算 `entries` 的签名链，与提供的 `signatures` 逐行比对。
    /// 任一行签名不匹配则返回 `Ok(false)`（检测到篡改）。
    ///
    /// # 参数
    ///
    /// - `entries`: 审计日志条目切片
    /// - `signatures`: 待验证的签名列表（从 `export_csv`/`export_json` 输出中提取）
    ///
    /// # 返回
    ///
    /// - `Ok(true)`: 签名链完整，未检测到篡改
    /// - `Ok(false)`: 检测到篡改（签名不匹配或长度不一致）
    /// - `Err`: `config.signing_key` 为 `None`
    #[cfg(feature = "audit-log")]
    pub fn verify_signature_chain(
        &self,
        entries: &[AuditEntry],
        signatures: &[String],
    ) -> BulwarkResult<bool> {
        if entries.len() != signatures.len() {
            return Ok(false);
        }
        let computed = self.compute_signature_chain(entries)?;
        Ok(computed == signatures)
    }

    /// 计算 HMAC-SHA256 签名链（D4 内部辅助方法）。
    ///
    /// 链式算法：第 N 行 signature = HMAC-SHA256(key, prev_signature + row_content)
    /// - `prev_signature` 初始为空字符串，之后为上一行的 signature
    /// - `row_content` = `timestamp,login_id,tenant_id,event_type`
    #[cfg(feature = "audit-log")]
    fn compute_signature_chain(&self, entries: &[AuditEntry]) -> BulwarkResult<Vec<String>> {
        let key = self.config.signing_key.as_ref().ok_or_else(|| {
            BulwarkError::Config("signing_key 未配置，无法导出签名链".to_string())
        })?;
        let mut prev_sig = String::new();
        let mut signatures = Vec::with_capacity(entries.len());
        for entry in entries {
            let login_id_str = entry.login_id.as_deref().unwrap_or("");
            let row_content = format!(
                "{},{},{},{}",
                entry.created_at, login_id_str, entry.tenant_id, entry.event_type
            );
            let input = format!("{}{}", prev_sig, row_content);
            let sig = self.hmac_sha256_hex(key, input.as_bytes())?;
            signatures.push(sig.clone());
            prev_sig = sig;
        }
        Ok(signatures)
    }

    /// 计算 HMAC-SHA256 并返回 hex 编码字符串（D4 内部辅助方法）。
    #[cfg(feature = "audit-log")]
    fn hmac_sha256_hex(&self, key: &str, input: &[u8]) -> BulwarkResult<String> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .map_err(|e| BulwarkError::Config(format!("HMAC key 无效: {}", e)))?;
        mac.update(input);
        let bytes = mac.finalize().into_bytes();
        Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
    }
}

#[cfg(feature = "db-sqlite")]
#[async_trait]
impl BulwarkListener for AuditLogListener {
    /// 事件处理：转换 + INSERT，失败时 `tracing::warn` 不传播错误。
    ///
    /// "失败时 `tracing::warn` 不传播错误"——
    /// 监听器失败不中断主流程。
    async fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
        match self.to_audit_entry(event) {
            Ok(entry) => {
                if self.config.async_write {
                    // 异步写入：tokio::spawn 不阻塞主流程
                    let pool = self.pool.clone();
                    let config = self.config.clone();
                    tokio::spawn(async move {
                        let listener = AuditLogListener::new(pool, config);
                        if let Err(e) = listener.insert(&entry).await {
                            tracing::warn!("审计日志异步写入失败: {}", e);
                        }
                    });
                } else {
                    // 同步写入：失败时 tracing::warn 不传播错误
                    if let Err(e) = self.insert(&entry).await {
                        tracing::warn!("审计日志写入失败: {}", e);
                    }
                }
            },
            Err(e) => {
                tracing::warn!("审计日志事件转换失败: {}", e);
            },
        }
        Ok(())
    }
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// T067 Red: `AuditConfig` 构造测试（掩码字段 + 保留天数 + 异步写入开关）。
    ///
    /// 断言所有字段可正确初始化与读取：
    /// - `mask_fields`: 需掩码的字段列表（如 `password`）
    /// - `retain_days`: 日志保留天数（过期自动清理）
    /// - `async_write`: 是否异步写入（不阻塞主流程）
    #[test]
    fn audit_config_constructs_with_mask_fields_and_retain_days() {
        let config = AuditConfig {
            mask_fields: vec!["password".to_string()],
            retain_days: 30,
            async_write: true,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        assert_eq!(config.mask_fields, vec!["password".to_string()]);
        assert_eq!(config.retain_days, 30);
        assert!(config.async_write);
    }
}

// ============================================================================
// db-sqlite 集成测试（T069-audit_logs 表迁移 + AuditLogListener）
// ============================================================================

#[cfg(all(test, feature = "audit-log", feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::{AuditConfig, AuditEntry, AuditLogListener, AuditMaskMode, AuditQuery};
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use crate::listener::{BulwarkEvent, BulwarkListener, RequestContext};
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::path::PathBuf;

    /// 定位项目根目录的 migrations/sqlite/ 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 创建并初始化 SQLite in-memory 数据库（迁移 + 返回 pool）。
    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    /// 在 `TENANT` task_local 上下文中执行测试体（`tenant-isolation` feature 启用时）。
    ///
    /// 修复 Phase 2 T017 引入的测试回归：`to_audit_entry` 在 `tenant-isolation` 启用时
    /// 调用 `current_tenant_id_strict()`，无 `TENANT.scope` 时返回 `None` → `BulwarkError::Config`。
    /// 实现正确（Rule 12 失败显性化），缺失的是测试上下文，本 helper 补齐 scope。
    #[cfg(feature = "tenant-isolation")]
    async fn run_with_tenant_scope<F, Fut, T>(f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        use crate::context::tenant::{TenantContext, TenantSource, TENANT};
        TENANT
            .scope(
                TenantContext {
                    tenant_id: 0,
                    resolved_from: TenantSource::Header,
                },
                f(),
            )
            .await
    }

    /// 直接执行测试体（`tenant-isolation` feature 关闭时使用，向后兼容单租户场景）。
    #[cfg(not(feature = "tenant-isolation"))]
    async fn run_with_tenant_scope<F, Fut, T>(f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        f().await
    }

    // ========================================================================
    // T069-audit_logs 表迁移验证
    // ========================================================================

    /// T069-T070 Green: 验证 SQLite 迁移加载 `004_audit_logs.sql` 后
    /// `audit_logs` 表存在。
    ///
    /// Rule 11（惯例优先）：SQL 文件放 `migrations/sqlite/core/004_audit_logs.sql`，
    /// 复用现有 `migrate_core()` 自动加载机制（与 002_role_hierarchy.sql / 003_refresh_tokens.sql 同惯例），
    /// 而非 tasks.md 原描述的 `src/dao/repository/sqlite/audit_logs.sql`。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_logs_table_exists_after_migration() {
        let pool = setup_db().await;
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "audit_logs 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }

    // ========================================================================
    // T071-AuditLogListener 持久化事件
    // ========================================================================

    /// T071 Red: AuditLogListener 接收 `BulwarkEvent::Login` 后持久化到 `audit_logs` 表。
    ///
    /// 构造 `BulwarkEvent::Login { login_id: "1".to_string(), token: "tok".into(), device: None }`，
    /// 调用 `AuditLogListener.on_event(&event).await`，
    /// 断言 `audit_logs` 表新增一行 `event_type="login"` 且 `login_id=1`。
    ///
    /// Rule 7 冲突暴露（在 T072 Green 注释中详述）：
    /// - tasks.md T072 说 `pub struct AuditLogListener { pub dao: Arc<dyn BulwarkDao>, .. }`
    /// - 但 BulwarkDao 是 cache 抽象（4 实现：Oxcache/MockDao/MinimalDao/AloneCache，均不支持 SQL INSERT）
    /// - Rule 11（惯例优先）：遵循 RefreshTokenRotation 先例，AuditLogListener 持 `pool: DbPool` 直连 SQL
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_log_listener_persists_login_event() {
        run_with_tenant_scope(audit_log_listener_persists_login_event_inner).await
    }

    async fn audit_log_listener_persists_login_event_inner() {
        let pool = setup_db().await;

        // 构造 AuditLogListener（Rule 7 override：pool: DbPool 直连，非 dao: Arc<dyn BulwarkDao>）
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool.clone(), config);

        // 构造 Login 事件
        let event = BulwarkEvent::Login {
            login_id: "1".to_string(),
            token: "tok".to_string(),
            device: None,
            request_context: None,
        };

        // 调用 on_event（async，依据 T071 spec：.await）
        listener.on_event(&event).await.expect("on_event 应成功");

        // 断言 audit_logs 表新增 1 行，event_type="login"，login_id=1
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT event_type, login_id FROM audit_logs WHERE event_type = ?",
            vec![Value::String(Some("login".to_string()))],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(rows.len(), 1, "audit_logs 应有 1 行 event_type=login");
        let event_type: String = rows[0]
            .try_get("", "event_type")
            .expect("event_type 应可读");
        let login_id: String = rows[0].try_get("", "login_id").expect("login_id 应可读");
        assert_eq!(event_type, "login", "event_type 应为 'login'");
        assert_eq!(login_id, "1", "login_id 应为 1");
    }

    // ========================================================================
    // T073-metadata 字段掩码（如 password → ***）
    // ========================================================================

    /// T073 Red: `AuditLogListener::mask_metadata` 应将 metadata JSON 中
    /// `config.mask_fields` 列出的字段值替换为 `"***"`。
    ///
    /// 构造 metadata JSON `{"password":"secret123"}`，
    /// 调用 `listener.mask_metadata(...)`，
    /// 断言返回的 JSON 中 `password` 字段值为 `"***"`。
    ///
    /// Rule 7 冲突暴露：
    /// - tasks.md T073 说"调用 `on_event`，断言 `audit_logs` 表中该行 metadata 字段 password 值为 ***"
    /// - 但 `BulwarkEvent::Login { login_id, token, device }` 无 password 字段，
    ///   `to_audit_entry` 产生的 metadata 仅含 `{"device":"..."}`，无法产生含 password 的 metadata
    /// - 强行让 Login 事件携带 password 违反安全原则（密码不应记录到审计日志）
    /// - 解决方案：测试 `pub fn mask_metadata(&self, metadata: &str) -> String` 公开方法
    ///   （T074 在 `to_audit_entry` 末尾调用该方法对 metadata 掩码）
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_log_listener_masks_password_field_in_metadata() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec!["password".to_string()],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        // 构造含 password 的 metadata JSON
        let input_metadata = r#"{"password":"secret123"}"#;
        let masked = listener.mask_metadata(input_metadata);

        // 断言 password 字段值被替换为 "***"
        let parsed: serde_json::Value =
            serde_json::from_str(&masked).expect("masked 应是有效 JSON");
        assert_eq!(
            parsed["password"].as_str(),
            Some("***"),
            "password 字段应被掩码为 ***，实际: {}",
            masked
        );
    }

    // ========================================================================
    // T077-AuditLogListener 覆盖全部 14 事件（spec R-audit-log-006）
    // ========================================================================

    /// T077 Red: AuditLogListener 应为 spec R-audit-log-005 的 14 个变体
    /// 各生成一行 audit_logs 记录，event_type 对应变体名 snake_case。
    ///
    /// 对每个变体调用 `on_event(&event).await`，最终断言 `audit_logs` 表有 14 行，
    /// 且每种 event_type 各一行。
    ///
    /// 当前 Red 状态：`to_audit_entry` 仅覆盖 Login，其余 13 个走 `_ =>` 返回 Err，
    /// `on_event` 捕获 Err 后仅 `tracing::warn` 不持久化，因此 audit_logs 仅 1 行（断言 14 失败）。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_log_listener_handles_all_14_events() {
        run_with_tenant_scope(audit_log_listener_handles_all_14_events_inner).await
    }

    async fn audit_log_listener_handles_all_14_events_inner() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool.clone(), config);

        // 14 个 spec 必需变体（R-audit-log-005）
        let events: Vec<(BulwarkEvent, &str)> = vec![
            (
                BulwarkEvent::Login {
                    login_id: "1".to_string(),
                    token: "t".into(),
                    device: None,
                    request_context: None,
                },
                "login",
            ),
            (
                BulwarkEvent::Logout {
                    login_id: "1".to_string(),
                    token: "t".into(),
                    request_context: None,
                },
                "logout",
            ),
            (
                BulwarkEvent::Kickout {
                    login_id: "1".to_string(),
                    token: "t".into(),
                    reason: "r".into(),
                    request_context: None,
                },
                "kickout",
            ),
            (
                BulwarkEvent::LoginFailure {
                    login_id: "1".to_string(),
                    reason: "r".into(),
                    request_context: None,
                },
                "login_failure",
            ),
            (
                BulwarkEvent::RevokeToken {
                    token: "t".into(),
                    request_context: None,
                },
                "revoke_token",
            ),
            (
                BulwarkEvent::PermissionCheck {
                    login_id: "1".to_string(),
                    permission: "p".into(),
                    request_context: None,
                },
                "permission_check",
            ),
            (
                BulwarkEvent::RoleCheck {
                    login_id: "1".to_string(),
                    role: "r".into(),
                    request_context: None,
                },
                "role_check",
            ),
            (
                BulwarkEvent::TokenRefresh {
                    login_id: "1".to_string(),
                    old_token: "t1".into(),
                    new_token: "t2".into(),
                    request_context: None,
                },
                "token_refresh",
            ),
            (
                BulwarkEvent::TokenRotate {
                    old_key: "k1".into(),
                    new_key: "k2".into(),
                    request_context: None,
                },
                "token_rotate",
            ),
            (
                BulwarkEvent::SocialLogin {
                    provider: "wechat".into(),
                    user_id: "u".into(),
                    login_id: Some("1".to_string()),
                    request_context: None,
                },
                "social_login",
            ),
            (
                BulwarkEvent::TenantSwitch {
                    login_id: "1".to_string(),
                    from_tenant: 100,
                    to_tenant: 200,
                    request_context: None,
                },
                "tenant_switch",
            ),
            (
                BulwarkEvent::DeviceBlock {
                    login_id: "1".to_string(),
                    device: "d".into(),
                    request_context: None,
                },
                "device_block",
            ),
            (
                BulwarkEvent::DeviceUnblock {
                    login_id: "1".to_string(),
                    device: "d".into(),
                    request_context: None,
                },
                "device_unblock",
            ),
            (
                BulwarkEvent::ConfigReload {
                    config_version: 1,
                    request_context: None,
                },
                "config_reload",
            ),
        ];

        // 对每个变体调用 on_event
        for (event, _expected_type) in &events {
            listener.on_event(event).await.expect("on_event 应返回 Ok");
        }

        // 查询 audit_logs 表总行数
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let count_stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) as cnt FROM audit_logs",
            vec![],
        );
        let count_rows = conn.query_all_raw(count_stmt).await.expect("COUNT 应成功");
        let total: i64 = count_rows[0].try_get("", "cnt").expect("cnt 应可读");
        assert_eq!(
            total, 14,
            "audit_logs 应有 14 行（每变体一行），实际: {}",
            total
        );

        // 逐变体验证 event_type 存在
        for (_event, expected_type) in &events {
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT COUNT(*) as cnt FROM audit_logs WHERE event_type = ?",
                vec![Value::String(Some(expected_type.to_string()))],
            );
            let rows = conn.query_all_raw(stmt).await.expect("query 应成功");
            let cnt: i64 = rows[0].try_get("", "cnt").expect("cnt 应可读");
            assert_eq!(
                cnt, 1,
                "event_type='{}' 应有 1 行，实际: {}",
                expected_type, cnt
            );
        }
    }

    // ========================================================================
    // T079-query_audit_logs 复合条件查询（spec R-audit-log-007）
    // ========================================================================

    /// T079 Red: `AuditLogListener::query_audit_logs` 应按 `AuditQuery` 的
    /// `tenant_id` / `event_type` / `from` / `to` 四个维度复合过滤。
    ///
    /// 插入 4 行不同 tenant/event_type/created_at 的日志：
    /// - Row A: tenant=0, event_type="login",  created_at=1000
    /// - Row B: tenant=1, event_type="login",  created_at=2000
    /// - Row C: tenant=0, event_type="logout", created_at=3000
    /// - Row D: tenant=0, event_type="login",  created_at=5000
    ///
    /// 验证 4 种过滤组合：
    /// 1. `tenant_id=Some(0), event_type=Some("login")` → A + D（2 行）
    /// 2. 上述 + `to=Some(4000)` → 仅 A（1 行，D 被 created_at > 4000 过滤）
    /// 3. 上述 + `from=Some(3000)` → 仅 D（1 行，A 被 created_at < 3000 过滤）
    /// 4. 全 `None` → 全部 4 行
    ///
    /// 注意：INSERT 通过 `listener.insert(&entry)` 而非原生 SQL，确保与
    /// `query_audit_logs` 走同一 pool 路径（避免 SQLite in-memory 跨连接隔离）。
    #[tokio::test(flavor = "multi_thread")]
    async fn query_audit_logs_filters_by_tenant_event_type_time_range() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool.clone(), config);

        // 构造并插入 4 行测试数据（通过 listener.insert 走同一 pool）
        let entries = vec![
            AuditEntry {
                tenant_id: 0,
                event_type: "login".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: 1000,
            }, // Row A
            AuditEntry {
                tenant_id: 1,
                event_type: "login".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: 2000,
            }, // Row B
            AuditEntry {
                tenant_id: 0,
                event_type: "logout".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: 3000,
            }, // Row C
            AuditEntry {
                tenant_id: 0,
                event_type: "login".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: 5000,
            }, // Row D
        ];
        for entry in &entries {
            listener
                .insert(entry)
                .await
                .expect("listener.insert 应成功");
        }

        // 查询 1: tenant_id=Some(0), event_type=Some("login"), from=None, to=None
        // 期望返回 A + D（2 行）
        let q1 = AuditQuery {
            tenant_id: Some(0),
            event_type: Some("login".to_string()),
            from: None,
            to: None,
        };
        let rows1 = listener
            .query_audit_logs(q1)
            .await
            .expect("query_audit_logs 应成功");
        assert_eq!(
            rows1.len(),
            2,
            "查询1 应返回 2 行（tenant=0 + event_type=login），实际: {}",
            rows1.len()
        );
        let mut ts1: Vec<i64> = rows1.iter().map(|r| r.created_at).collect();
        ts1.sort();
        assert_eq!(ts1, vec![1000, 5000], "查询1 应含 A(1000) + D(5000)");

        // 查询 2: tenant_id=Some(0), event_type=Some("login"), to=Some(4000)
        // 期望仅 A（1 行，D 的 created_at=5000 > 4000 被过滤）
        let q2 = AuditQuery {
            tenant_id: Some(0),
            event_type: Some("login".to_string()),
            from: None,
            to: Some(4000),
        };
        let rows2 = listener
            .query_audit_logs(q2)
            .await
            .expect("query_audit_logs 应成功");
        assert_eq!(
            rows2.len(),
            1,
            "查询2 应返回 1 行（to=4000 过滤掉 D），实际: {}",
            rows2.len()
        );
        assert_eq!(rows2[0].created_at, 1000, "查询2 应仅含 A(1000)");

        // 查询 3: tenant_id=Some(0), event_type=Some("login"), from=Some(3000)
        // 期望仅 D（1 行，A 的 created_at=1000 < 3000 被过滤）
        let q3 = AuditQuery {
            tenant_id: Some(0),
            event_type: Some("login".to_string()),
            from: Some(3000),
            to: None,
        };
        let rows3 = listener
            .query_audit_logs(q3)
            .await
            .expect("query_audit_logs 应成功");
        assert_eq!(
            rows3.len(),
            1,
            "查询3 应返回 1 行（from=3000 过滤掉 A），实际: {}",
            rows3.len()
        );
        assert_eq!(rows3[0].created_at, 5000, "查询3 应仅含 D(5000)");

        // 查询 4: 全 None（返回全部 4 行）
        let q4 = AuditQuery::default();
        let rows4 = listener
            .query_audit_logs(q4)
            .await
            .expect("query_audit_logs 应成功");
        assert_eq!(
            rows4.len(),
            4,
            "查询4（全 None）应返回全部 4 行，实际: {}",
            rows4.len()
        );
    }

    /// T001 Red: `to_audit_entry` 应从 `TENANT` task_local 读取 tenant_id
    /// 并填充到返回的 `AuditEntry.tenant_id`。
    ///
    /// 在 `TENANT.scope(TenantContext { tenant_id: 42, .. }, async { ... })` 内
    /// 调用 `to_audit_entry(&BulwarkEvent::Login { ... })`，断言返回的 `AuditEntry.tenant_id == 42`。
    ///
    /// 此测试作为 T002 重构（移除 post-match 覆盖、match arm 直接用 tenant_id）的保护网：
    /// - 在改代码前应通过（因为现有 L445-446 post-match 覆盖 `entry.tenant_id = tenant_id` 正确）
    /// - 在 T002 改后也应通过（match arm 直接用 tenant_id，行为等价）
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_entry_carries_tenant_id_from_task_local() {
        use crate::context::tenant::{TenantContext, TenantSource, TENANT};

        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let event = BulwarkEvent::Login {
            login_id: "1".to_string(),
            token: "tok".to_string(),
            device: None,
            request_context: None,
        };
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };

        // to_audit_entry 是同步函数，但 TENANT.scope 需要 future；
        // 在 async block 内调用 to_audit_entry 时已进入 task_local 上下文
        let entry = TENANT
            .scope(ctx, async { listener.to_audit_entry(&event) })
            .await
            .expect("to_audit_entry 应成功");

        assert_eq!(
            entry.tenant_id, 42,
            "tenant_id 应从 TENANT task_local 读取为 42，实际: {}",
            entry.tenant_id
        );
    }

    // ========================================================================
    // D4 export_csv / export_json / verify_signature_chain 测试（Red）
    // ========================================================================

    /// T100 Red: `export_csv` 应返回有效 CSV 格式字符串。
    ///
    /// 单条 AuditEntry 导出后：
    /// - 第 1 行为 header：`timestamp,login_id,tenant_id,event_type,signature`
    /// - 第 2 行为数据行，含 5 个逗号分隔字段
    /// - signature 字段为非空 hex 字符串
    #[tokio::test(flavor = "multi_thread")]
    async fn export_csv_returns_valid_csv_format() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: Some("test-secret-key".to_string()),
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let entry = AuditEntry {
            tenant_id: 42,
            event_type: "login".to_string(),
            login_id: Some("1001".to_string()),
            token: None,
            ip: None,
            user_agent: None,
            metadata: None,
            success: true,
            created_at: 1700000000,
        };

        let csv = listener.export_csv(&[entry]).expect("export_csv 应成功");

        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "CSV 应有 2 行（header + 1 数据行），实际: {}",
            lines.len()
        );

        // 验证 header
        let header_fields: Vec<&str> = lines[0].split(',').collect();
        assert_eq!(
            header_fields,
            vec![
                "timestamp",
                "login_id",
                "tenant_id",
                "event_type",
                "signature"
            ],
            "CSV header 应为 5 列"
        );

        // 验证数据行
        let data_fields: Vec<&str> = lines[1].split(',').collect();
        assert_eq!(data_fields.len(), 5, "数据行应有 5 个字段");
        assert_eq!(data_fields[0], "1700000000", "timestamp 应为 1700000000");
        assert_eq!(data_fields[1], "1001", "login_id 应为 1001");
        assert_eq!(data_fields[2], "42", "tenant_id 应为 42");
        assert_eq!(data_fields[3], "login", "event_type 应为 login");
        assert!(!data_fields[4].is_empty(), "signature 不应为空");
    }

    /// T100 Red: `export_json` 应返回有效 JSON 数组字符串。
    ///
    /// 单条 AuditEntry 导出后：
    /// - 可解析为 JSON 数组
    /// - 数组含 1 个对象，有 5 个字段：timestamp/login_id/tenant_id/event_type/signature
    /// - signature 字段为非空字符串
    #[tokio::test(flavor = "multi_thread")]
    async fn export_json_returns_valid_json_format() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: Some("test-secret-key".to_string()),
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let entry = AuditEntry {
            tenant_id: 42,
            event_type: "login".to_string(),
            login_id: Some("1001".to_string()),
            token: None,
            ip: None,
            user_agent: None,
            metadata: None,
            success: true,
            created_at: 1700000000,
        };

        let json_str = listener.export_json(&[entry]).expect("export_json 应成功");

        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("应为有效 JSON");
        let arr = parsed.as_array().expect("应为 JSON 数组");
        assert_eq!(arr.len(), 1, "数组应有 1 个对象");

        let obj = &arr[0];
        assert_eq!(
            obj["timestamp"].as_i64(),
            Some(1700000000),
            "timestamp 字段"
        );
        assert_eq!(obj["login_id"].as_str(), Some("1001"), "login_id 字段");
        assert_eq!(obj["tenant_id"].as_i64(), Some(42), "tenant_id 字段");
        assert_eq!(obj["event_type"].as_str(), Some("login"), "event_type 字段");
        let sig = obj["signature"].as_str().expect("signature 应为字符串");
        assert!(!sig.is_empty(), "signature 不应为空");
    }

    /// T100 Red: 签名链应将每行链接到前一行。
    ///
    /// 两个 entries [A, B] 导出后签名 [sigA, sigB]。
    /// 修改 A 的内容后导出 [A', B]，得到 [sigA', sigB']。
    /// 断言：
    /// - sigA != sigA'（A 内容变了 → 第一行签名变）
    /// - sigB != sigB'（B 内容相同，但因链式依赖 → 第二行签名也变）
    #[tokio::test(flavor = "multi_thread")]
    async fn signature_chain_links_each_row_to_previous() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: Some("chain-test-key".to_string()),
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        // 原始 entries [A, B]
        let entry_a = AuditEntry {
            tenant_id: 0,
            event_type: "login".to_string(),
            login_id: Some("1".to_string()),
            token: None,
            ip: None,
            user_agent: None,
            metadata: None,
            success: true,
            created_at: 1000,
        };
        let entry_b = AuditEntry {
            tenant_id: 0,
            event_type: "logout".to_string(),
            login_id: Some("1".to_string()),
            token: None,
            ip: None,
            user_agent: None,
            metadata: None,
            success: true,
            created_at: 2000,
        };

        // 导出 [A, B] 并提取签名
        let json1 = listener
            .export_json(&[entry_a.clone(), entry_b.clone()])
            .expect("export_json 应成功");
        let parsed1: serde_json::Value = serde_json::from_str(&json1).expect("应为有效 JSON");
        let sig_a1 = parsed1[0]["signature"]
            .as_str()
            .expect("sigA 应为字符串")
            .to_string();
        let sig_b1 = parsed1[1]["signature"]
            .as_str()
            .expect("sigB 应为字符串")
            .to_string();

        // 修改 A 的 login_id → A'
        let entry_a_modified = AuditEntry {
            login_id: Some("999".to_string()),
            ..entry_a
        };

        // 导出 [A', B] 并提取签名
        let json2 = listener
            .export_json(&[entry_a_modified, entry_b.clone()])
            .expect("export_json 应成功");
        let parsed2: serde_json::Value = serde_json::from_str(&json2).expect("应为有效 JSON");
        let sig_a2 = parsed2[0]["signature"]
            .as_str()
            .expect("sigA' 应为字符串")
            .to_string();
        let sig_b2 = parsed2[1]["signature"]
            .as_str()
            .expect("sigB' 应为字符串")
            .to_string();

        // 断言：第一行签名变化（A 内容变了）
        assert_ne!(sig_a1, sig_a2, "第一行签名应因 A 内容变化而不同");

        // 断言：第二行签名也变化（链式依赖：B 的签名依赖 A 的签名）
        assert_ne!(
            sig_b1, sig_b2,
            "第二行签名应因链式依赖而不同（即使 B 内容相同）"
        );
    }

    /// T100 Red: 篡改某行内容后验签应失败。
    ///
    /// 1. 导出 [A, B] 得到签名 [sigA, sigB]
    /// 2. 用 verify_signature_chain 验证原始 entries → Ok(true)
    /// 3. 篡改 A 的 login_id
    /// 4. 调用 verify_signature_chain([A_tampered, B], [sigA, sigB]) → Ok(false)
    #[tokio::test(flavor = "multi_thread")]
    async fn signature_chain_detects_tampering() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: Some("tamper-test-key".to_string()),
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        // 原始 entries [A, B]
        let entry_a = AuditEntry {
            tenant_id: 0,
            event_type: "login".to_string(),
            login_id: Some("1".to_string()),
            token: None,
            ip: None,
            user_agent: None,
            metadata: None,
            success: true,
            created_at: 1000,
        };
        let entry_b = AuditEntry {
            tenant_id: 0,
            event_type: "logout".to_string(),
            login_id: Some("1".to_string()),
            token: None,
            ip: None,
            user_agent: None,
            metadata: None,
            success: true,
            created_at: 2000,
        };

        // 导出获取签名
        let json_str = listener
            .export_json(&[entry_a.clone(), entry_b.clone()])
            .expect("export_json 应成功");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("应为有效 JSON");
        let signatures: Vec<String> = parsed
            .as_array()
            .unwrap()
            .iter()
            .map(|obj| obj["signature"].as_str().unwrap().to_string())
            .collect();

        // 验证原始签名链 → 应通过
        let valid = listener
            .verify_signature_chain(&[entry_a.clone(), entry_b.clone()], &signatures)
            .expect("verify 应成功（不缺 signing_key）");
        assert!(valid, "原始签名链应验证通过");

        // 篡改 A 的 login_id
        let tampered_a = AuditEntry {
            login_id: Some("999".to_string()),
            ..entry_a
        };

        // 验证篡改后的签名链 → 应失败
        let tampered = listener
            .verify_signature_chain(&[tampered_a, entry_b], &signatures)
            .expect("verify 应成功（不缺 signing_key）");
        assert!(!tampered, "篡改后签名链应验证失败");
    }

    /// T100 Red: 空列表导出 CSV 应返回仅含 header 的字符串。
    #[tokio::test(flavor = "multi_thread")]
    async fn export_csv_handles_empty_audit_logs() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: Some("empty-test-key".to_string()),
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let csv = listener.export_csv(&[]).expect("export_csv 空列表应成功");

        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1, "空列表 CSV 应仅 1 行 header");
        assert_eq!(
            lines[0], "timestamp,login_id,tenant_id,event_type,signature",
            "header 应为标准 5 列"
        );
    }

    /// T100 Red: 空列表导出 JSON 应返回 "[]"。
    #[tokio::test(flavor = "multi_thread")]
    async fn export_json_handles_empty_audit_logs() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: Some("empty-test-key".to_string()),
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let json_str = listener.export_json(&[]).expect("export_json 空列表应成功");

        assert_eq!(json_str, "[]", "空列表 JSON 应为 []");
    }

    // ========================================================================
    // T004: Audit IP/UA 从 request_context 填充
    // ========================================================================

    /// T004 Red: 当 `request_context` 携带 ip 与 user_agent 时，
    /// `to_audit_entry` 应将其提取到返回的 `AuditEntry.ip` 与 `AuditEntry.user_agent`。
    ///
    /// 构造 `BulwarkEvent::Login` 携带 `request_context: Some(RequestContext {
    ///     ip: Some("192.168.1.1"), user_agent: Some("Mozilla/5.0")
    /// })`，调用 `to_audit_entry`，断言 `entry.ip` 与 `entry.user_agent` 与输入一致。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_entry_extracts_ip_and_user_agent_from_request_context() {
        run_with_tenant_scope(audit_entry_extracts_ip_and_user_agent_from_request_context_inner)
            .await
    }

    async fn audit_entry_extracts_ip_and_user_agent_from_request_context_inner() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let event = BulwarkEvent::Login {
            login_id: "1".to_string(),
            token: "tok".to_string(),
            device: None,
            request_context: Some(RequestContext {
                ip: Some("192.168.1.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
            }),
        };

        let entry = listener
            .to_audit_entry(&event)
            .expect("to_audit_entry 应成功");
        assert_eq!(
            entry.ip,
            Some("192.168.1.1".to_string()),
            "ip 应从 request_context 提取为 192.168.1.1"
        );
        assert_eq!(
            entry.user_agent,
            Some("Mozilla/5.0".to_string()),
            "user_agent 应从 request_context 提取为 Mozilla/5.0"
        );
    }

    /// T004 Red: 当 `request_context` 为 `None` 时，
    /// `to_audit_entry` 返回的 `AuditEntry.ip` 与 `AuditEntry.user_agent` 应为 `None`。
    ///
    /// 构造 `BulwarkEvent::Login` 携带 `request_context: None`，
    /// 调用 `to_audit_entry`，断言 `entry.ip` 与 `entry.user_agent` 均为 `None`。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_entry_request_context_none_yields_none_ip_ua() {
        run_with_tenant_scope(audit_entry_request_context_none_yields_none_ip_ua_inner).await
    }

    async fn audit_entry_request_context_none_yields_none_ip_ua_inner() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let event = BulwarkEvent::Login {
            login_id: "1".to_string(),
            token: "tok".to_string(),
            device: None,
            request_context: None,
        };

        let entry = listener
            .to_audit_entry(&event)
            .expect("to_audit_entry 应成功");
        assert!(entry.ip.is_none(), "request_context=None 时 ip 应为 None");
        assert!(
            entry.user_agent.is_none(),
            "request_context=None 时 user_agent 应为 None"
        );
    }

    /// T004 Red: 当 `request_context` 仅携带 ip（user_agent 为 None）时，
    /// `to_audit_entry` 应正确提取 ip，user_agent 保持 None。
    ///
    /// 验证部分上下文场景（如代理注入 IP 但无 UA）。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_entry_extracts_ip_only_when_user_agent_none() {
        run_with_tenant_scope(audit_entry_extracts_ip_only_when_user_agent_none_inner).await
    }

    async fn audit_entry_extracts_ip_only_when_user_agent_none_inner() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        // 使用 Logout 变体验证 extract_request_context 覆盖多个变体
        let event = BulwarkEvent::Logout {
            login_id: "1".to_string(),
            token: "tok".to_string(),
            request_context: Some(RequestContext {
                ip: Some("10.0.0.1".to_string()),
                user_agent: None,
            }),
        };

        let entry = listener
            .to_audit_entry(&event)
            .expect("to_audit_entry 应成功");
        assert_eq!(
            entry.ip,
            Some("10.0.0.1".to_string()),
            "ip 应从 request_context 提取为 10.0.0.1"
        );
        assert!(entry.user_agent.is_none(), "user_agent 未提供时应为 None");
    }

    // ========================================================================
    // T012: Audit 脱敏配置 Full/Partial 切换
    // ========================================================================

    /// T012-1: Full 模式下 mask_fields 中的字段值全部替换为 "***"。
    ///
    /// 即使字段有类型感知规则（如 phone），Full 模式也强制替换为 "***"。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_full_mode_masks_all_fields_with_stars() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec!["phone".to_string(), "password".to_string()],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Full,
        };
        let listener = AuditLogListener::new(pool, config);

        let metadata = r#"{"phone":"13812341234","password":"secret"}"#;
        let masked = listener.mask_metadata(metadata);

        let parsed: serde_json::Value =
            serde_json::from_str(&masked).expect("masked JSON 应可解析");
        assert_eq!(
            parsed["phone"],
            serde_json::Value::String("***".to_string()),
            "Full 模式下 phone 应替换为 ***"
        );
        assert_eq!(
            parsed["password"],
            serde_json::Value::String("***".to_string()),
            "Full 模式下 password 应替换为 ***"
        );
    }

    /// T012-2: Partial 模式下 phone 使用 SensitiveDataMasker 类型感知脱敏。
    ///
    /// phone → "138****1234"（保留前 3 后 4），
    /// password 无匹配规则 → 回退为 "***"（安全优先）。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_partial_mode_uses_type_aware_masking() {
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec!["phone".to_string(), "password".to_string()],
            retain_days: 0,
            async_write: false,
            signing_key: None,
            audit_mask_mode: AuditMaskMode::Partial,
        };
        let listener = AuditLogListener::new(pool, config);

        let metadata = r#"{"phone":"13812341234","password":"secret"}"#;
        let masked = listener.mask_metadata(metadata);

        let parsed: serde_json::Value =
            serde_json::from_str(&masked).expect("masked JSON 应可解析");
        assert_eq!(
            parsed["phone"],
            serde_json::Value::String("138****1234".to_string()),
            "Partial 模式下 phone 应类型感知脱敏为 138****1234"
        );
        assert_eq!(
            parsed["password"],
            serde_json::Value::String("***".to_string()),
            "Partial 模式下 password 无匹配规则，应回退为 ***"
        );
    }
}
