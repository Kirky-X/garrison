//! 审计日志模块（v0.5.0 新增，依据 proposal H3）。
//!
//! 提供 `AuditLogListener` 实现，将 `BulwarkEvent` 持久化到 `audit_logs` 表，
//! 支持字段掩码（如 password）与异步写入。
//!
//! ## 核心抽象
//!
//! - [`AuditConfig`]：审计日志配置（掩码字段 + 保留天数 + 异步写入开关）
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

use crate::error::{BulwarkError, BulwarkResult};

// ============================================================================
// AuditConfig 定义（T068 Green）
// ============================================================================

/// 审计日志配置（T068 Green）。
///
/// 控制 `AuditLogListener` 的行为：字段掩码、保留天数、异步写入。
///
/// # 字段
///
/// - `mask_fields`: 需掩码的字段列表（如 `password`），metadata JSON 中对应字段值替换为 `"***"`
/// - `retain_days`: 日志保留天数（过期自动清理，0 表示永不清理）
/// - `async_write`: 是否异步写入（true 时不阻塞主流程，失败仅 `tracing::warn`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    /// 需掩码的字段列表（如 `password`），metadata JSON 中对应字段值替换为 `"***"`。
    pub mask_fields: Vec<String>,
    /// 日志保留天数（过期自动清理，0 表示永不清理）。
    pub retain_days: u32,
    /// 是否异步写入（true 时不阻塞主流程，失败仅 `tracing::warn`）。
    pub async_write: bool,
}

// ============================================================================
// AuditEntry + AuditLogListener（T072 Green，需 db-sqlite feature）
// ============================================================================
//
// Rule 7 冲突暴露（依据 proposal H3 + tasks.md T072）：
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

/// 构造 metadata JSON 字符串（T078 辅助函数）。
///
/// 接受 `&[(&str, &str)]` 键值对，序列化为 JSON 对象字符串。
/// 字符串值自动转义（由 `serde_json` 处理）。
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
    pub login_id: Option<i64>,
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

/// 审计日志查询条件（T079-T080 Green，依据 spec R-audit-log-007）。
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

    /// 将 `BulwarkEvent` 转换为 `AuditEntry`（T078: 全 19 变体穷尽 match）。
    ///
    /// spec R-audit-log-006 要求：`match` 无 `_ =>` 兜底，新增变体时编译错误提醒补实现。
    ///
    /// 14 个 spec 必需变体（R-audit-log-005）+ 5 个既有安全变体，全部转换为 AuditEntry。
    /// `event_type` 使用变体名 snake_case（如 `LoginFailure` → `"login_failure"`）。
    ///
    /// T074: 转换后对 `metadata` 调用 `mask_metadata` 进行字段掩码。
    fn to_audit_entry(&self, event: &BulwarkEvent) -> BulwarkResult<AuditEntry> {
        let now = Utc::now().timestamp();
        let mut entry = match event {
            BulwarkEvent::Login {
                login_id,
                token,
                device,
            } => AuditEntry {
                tenant_id: 0,
                event_type: "login".to_string(),
                login_id: Some(*login_id),
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: device.as_ref().map(|d| json_metadata(&[("device", d)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::Logout { login_id, token } => AuditEntry {
                tenant_id: 0,
                event_type: "logout".to_string(),
                login_id: Some(*login_id),
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
            } => AuditEntry {
                tenant_id: 0,
                event_type: "kickout".to_string(),
                login_id: Some(*login_id),
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
            } => AuditEntry {
                tenant_id: 0,
                event_type: "permission_check".to_string(),
                login_id: Some(*login_id),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("permission", permission)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::RoleCheck { login_id, role } => AuditEntry {
                tenant_id: 0,
                event_type: "role_check".to_string(),
                login_id: Some(*login_id),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("role", role)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::TokenExpired { token } => AuditEntry {
                tenant_id: 0,
                event_type: "token_expired".to_string(),
                login_id: None,
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: false,
                created_at: now,
            },
            BulwarkEvent::LoginFailure { login_id, reason } => AuditEntry {
                tenant_id: 0,
                event_type: "login_failure".to_string(),
                login_id: Some(*login_id),
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
            } => AuditEntry {
                tenant_id: 0,
                event_type: "token_refresh".to_string(),
                login_id: Some(*login_id),
                token: Some(new_token.clone()),
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("old_token", old_token)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::RevokeToken { token } => AuditEntry {
                tenant_id: 0,
                event_type: "revoke_token".to_string(),
                login_id: None,
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: true,
                created_at: now,
            },
            BulwarkEvent::SessionTimeout { login_id, token } => AuditEntry {
                tenant_id: 0,
                event_type: "session_timeout".to_string(),
                login_id: Some(*login_id),
                token: Some(token.clone()),
                ip: None,
                user_agent: None,
                metadata: None,
                success: false,
                created_at: now,
            },
            BulwarkEvent::AccountLocked { login_id, reason } => AuditEntry {
                tenant_id: 0,
                event_type: "account_locked".to_string(),
                login_id: Some(*login_id),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("reason", reason)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::FirewallBlock { login_id, reason } => AuditEntry {
                tenant_id: 0,
                event_type: "firewall_block".to_string(),
                login_id: Some(*login_id),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("reason", reason)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::TokenRotate { old_key, new_key } => AuditEntry {
                tenant_id: 0,
                event_type: "token_rotate".to_string(),
                login_id: None,
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("old_key", old_key), ("new_key", new_key)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::TempCredentialConsumed { key, value } => AuditEntry {
                tenant_id: 0,
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
            } => AuditEntry {
                tenant_id: 0,
                event_type: "social_login".to_string(),
                login_id: *login_id,
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
            } => AuditEntry {
                tenant_id: 0,
                event_type: "tenant_switch".to_string(),
                login_id: Some(*login_id),
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
            BulwarkEvent::DeviceBlock { login_id, device } => AuditEntry {
                tenant_id: 0,
                event_type: "device_block".to_string(),
                login_id: Some(*login_id),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("device", device)])),
                success: false,
                created_at: now,
            },
            BulwarkEvent::DeviceUnblock { login_id, device } => AuditEntry {
                tenant_id: 0,
                event_type: "device_unblock".to_string(),
                login_id: Some(*login_id),
                token: None,
                ip: None,
                user_agent: None,
                metadata: Some(json_metadata(&[("device", device)])),
                success: true,
                created_at: now,
            },
            BulwarkEvent::ConfigReload { config_version } => AuditEntry {
                tenant_id: 0,
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
        };
        // T074: 对 metadata 进行字段掩码（如 password → ***）
        entry.metadata = entry.metadata.map(|m| self.mask_metadata(&m));
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
        if let Some(obj) = value.as_object_mut() {
            for field in &self.config.mask_fields {
                if obj.contains_key(field) {
                    obj.insert(field.clone(), serde_json::Value::String("***".to_string()));
                }
            }
        }
        serde_json::to_string(&value).unwrap_or_else(|_| metadata.to_string())
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
                Value::BigInt(entry.login_id),
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

    /// 按复合条件查询审计日志（T080 Green，依据 spec R-audit-log-007）。
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
                let login_id: Option<i64> = row.try_get("", "login_id").map_err(|e| {
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
}

#[cfg(feature = "db-sqlite")]
#[async_trait]
impl BulwarkListener for AuditLogListener {
    /// 事件处理：转换 + INSERT，失败时 `tracing::warn` 不传播错误。
    ///
    /// 依据 tasks.md T072："失败时 `tracing::warn` 不传播错误"——
    /// 监听器失败不中断主流程（依据 spec listener-system）。
    async fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
        match self.to_audit_entry(event) {
            Ok(entry) => {
                if let Err(e) = self.insert(&entry).await {
                    tracing::warn!("审计日志写入失败: {}", e);
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
        };
        assert_eq!(config.mask_fields, vec!["password".to_string()]);
        assert_eq!(config.retain_days, 30);
        assert!(config.async_write);
    }
}

// ============================================================================
// db-sqlite 集成测试（T069-T082: audit_logs 表迁移 + AuditLogListener）
// ============================================================================

#[cfg(all(test, feature = "audit-log", feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::{AuditConfig, AuditEntry, AuditLogListener, AuditQuery};
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use crate::listener::{BulwarkEvent, BulwarkListener};
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

    // ========================================================================
    // T069-T070: audit_logs 表迁移验证
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
    // T071-T072: AuditLogListener 持久化事件
    // ========================================================================

    /// T071 Red: AuditLogListener 接收 `BulwarkEvent::Login` 后持久化到 `audit_logs` 表。
    ///
    /// 构造 `BulwarkEvent::Login { login_id: 1, token: "tok".into(), device: None }`，
    /// 调用 `AuditLogListener.on_event(&event).await`，
    /// 断言 `audit_logs` 表新增一行 `event_type="login"` 且 `login_id=1`。
    ///
    /// Rule 7 冲突暴露（在 T072 Green 注释中详述）：
    /// - tasks.md T072 说 `pub struct AuditLogListener { pub dao: Arc<dyn BulwarkDao>, .. }`
    /// - 但 BulwarkDao 是 cache 抽象（4 实现：Oxcache/MockDao/MinimalDao/AloneCache，均不支持 SQL INSERT）
    /// - Rule 11（惯例优先）：遵循 RefreshTokenRotation 先例，AuditLogListener 持 `pool: DbPool` 直连 SQL
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_log_listener_persists_login_event() {
        let pool = setup_db().await;

        // 构造 AuditLogListener（Rule 7 override：pool: DbPool 直连，非 dao: Arc<dyn BulwarkDao>）
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
        };
        let listener = AuditLogListener::new(pool.clone(), config);

        // 构造 Login 事件
        let event = BulwarkEvent::Login {
            login_id: 1,
            token: "tok".to_string(),
            device: None,
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
        let login_id: i64 = rows[0].try_get("", "login_id").expect("login_id 应可读");
        assert_eq!(event_type, "login", "event_type 应为 'login'");
        assert_eq!(login_id, 1, "login_id 应为 1");
    }

    // ========================================================================
    // T073-T074: metadata 字段掩码（如 password → ***）
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
    // T077-T078: AuditLogListener 覆盖全部 14 事件（spec R-audit-log-006）
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
        let pool = setup_db().await;
        let config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
        };
        let listener = AuditLogListener::new(pool.clone(), config);

        // 14 个 spec 必需变体（R-audit-log-005）
        let events: Vec<(BulwarkEvent, &str)> = vec![
            (
                BulwarkEvent::Login {
                    login_id: 1,
                    token: "t".into(),
                    device: None,
                },
                "login",
            ),
            (
                BulwarkEvent::Logout {
                    login_id: 1,
                    token: "t".into(),
                },
                "logout",
            ),
            (
                BulwarkEvent::Kickout {
                    login_id: 1,
                    token: "t".into(),
                    reason: "r".into(),
                },
                "kickout",
            ),
            (
                BulwarkEvent::LoginFailure {
                    login_id: 1,
                    reason: "r".into(),
                },
                "login_failure",
            ),
            (
                BulwarkEvent::RevokeToken { token: "t".into() },
                "revoke_token",
            ),
            (
                BulwarkEvent::PermissionCheck {
                    login_id: 1,
                    permission: "p".into(),
                },
                "permission_check",
            ),
            (
                BulwarkEvent::RoleCheck {
                    login_id: 1,
                    role: "r".into(),
                },
                "role_check",
            ),
            (
                BulwarkEvent::TokenRefresh {
                    login_id: 1,
                    old_token: "t1".into(),
                    new_token: "t2".into(),
                },
                "token_refresh",
            ),
            (
                BulwarkEvent::TokenRotate {
                    old_key: "k1".into(),
                    new_key: "k2".into(),
                },
                "token_rotate",
            ),
            (
                BulwarkEvent::SocialLogin {
                    provider: "wechat".into(),
                    user_id: "u".into(),
                    login_id: Some(1),
                },
                "social_login",
            ),
            (
                BulwarkEvent::TenantSwitch {
                    login_id: 1,
                    from_tenant: 100,
                    to_tenant: 200,
                },
                "tenant_switch",
            ),
            (
                BulwarkEvent::DeviceBlock {
                    login_id: 1,
                    device: "d".into(),
                },
                "device_block",
            ),
            (
                BulwarkEvent::DeviceUnblock {
                    login_id: 1,
                    device: "d".into(),
                },
                "device_unblock",
            ),
            (
                BulwarkEvent::ConfigReload { config_version: 1 },
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
    // T079-T080: query_audit_logs 复合条件查询（spec R-audit-log-007）
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
}
