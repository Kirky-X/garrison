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
