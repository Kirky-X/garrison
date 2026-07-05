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

    /// 将 `BulwarkEvent` 转换为 `AuditEntry`（T072: 仅 Login，T077-T078 扩展全 14 变体）。
    ///
    /// Rule 12（失败显性化）：未覆盖的变体返回 `BulwarkError::Config`，不静默跳过。
    ///
    /// T074: 转换后对 `metadata` 调用 `mask_metadata` 进行字段掩码。
    fn to_audit_entry(&self, event: &BulwarkEvent) -> BulwarkResult<AuditEntry> {
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
                metadata: device.as_ref().map(|d| format!("{{\"device\":\"{}\"}}", d)),
                success: true,
                created_at: Utc::now().timestamp(),
            },
            // T077-T078 将扩展其余 13 个变体；当前未覆盖的返回 Err（Rule 12）
            _ => {
                return Err(BulwarkError::Config(format!(
                    "AuditLogListener 暂不支持事件变体: {:?}",
                    event
                )));
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
    use super::{AuditConfig, AuditLogListener};
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
}
