//! JWT RefreshToken Rotation 模块（v0.5.0 新增，依据 proposal H4）。
//!
//! 基于 hash chain 的 RefreshToken 轮换：每次 `rotate` 时，新 token 的
//! `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
//! 旧 token 标记为 `revoked`，防止重放攻击。
//!
//! ## 核心抽象
//!
//! - [`RefreshTokenRecord`]：`refresh_tokens` 表行结构（hash chain 字段）
//! - `RefreshTokenRotation`：rotate 服务（T057-T066 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE refresh_tokens (
//!     token_hash TEXT PRIMARY KEY,
//!     parent_token_hash TEXT,
//!     login_id INTEGER NOT NULL,
//!     tenant_id INTEGER NOT NULL DEFAULT 0,
//!     key_version INTEGER NOT NULL,
//!     expires_at INTEGER NOT NULL,
//!     revoked INTEGER NOT NULL DEFAULT 0,
//!     created_at INTEGER NOT NULL
//! );
//! ```

// ============================================================================
// RefreshTokenRecord 定义（T054 Green）
// ============================================================================

/// `refresh_tokens` 表行结构（T054 Green）。
///
/// 基于 hash chain 的 RefreshToken 记录：每次 `rotate` 时，新 token 的
/// `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
/// 旧 token 标记为 `revoked`，防止重放攻击。
///
/// # 字段
///
/// - `token_hash`: 当前 token 的 SHA-256 哈希（主键）
/// - `parent_token_hash`: 旧 token 的哈希（首次签发为 `None`）
/// - `login_id`: 关联用户 ID
/// - `tenant_id`: 租户 ID（多租户隔离）
/// - `key_version`: 密钥轮换版本号（支持密钥轮换时区分）
/// - `expires_at`: 过期时间（Unix 秒）
/// - `revoked`: 是否已撤销（rotate 后旧 token 标记为 true）
/// - `created_at`: 创建时间（Unix 秒）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenRecord {
    /// 当前 token 的 SHA-256 哈希（主键）。
    pub token_hash: String,
    /// 旧 token 的哈希（首次签发为 `None`）。
    pub parent_token_hash: Option<String>,
    /// 关联用户 ID。
    pub login_id: i64,
    /// 租户 ID（多租户隔离）。
    pub tenant_id: i64,
    /// 密钥轮换版本号。
    pub key_version: u32,
    /// 过期时间（Unix 秒）。
    pub expires_at: i64,
    /// 是否已撤销（rotate 后旧 token 标记为 true）。
    pub revoked: bool,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// T053 Red: `RefreshTokenRecord` 构造测试（hash chain 字段可读）。
    ///
    /// 断言所有字段可正确初始化与读取，包括：
    /// - `token_hash`: 新 token 的 SHA-256 哈希
    /// - `parent_token_hash`: 旧 token 的哈希（首次签发为 None）
    /// - `login_id` / `tenant_id`: 多租户隔离
    /// - `key_version`: 密钥轮换版本号
    /// - `expires_at` / `created_at`: 时间戳
    /// - `revoked`: 是否已撤销（防重放）
    #[test]
    fn refresh_token_record_constructs_with_hash_chain_fields() {
        let record = RefreshTokenRecord {
            token_hash: "abc".to_string(),
            parent_token_hash: Some("def".to_string()),
            login_id: 1,
            tenant_id: 0,
            key_version: 1,
            expires_at: 9999,
            revoked: false,
            created_at: 0,
        };
        assert_eq!(record.token_hash, "abc");
        assert_eq!(record.parent_token_hash, Some("def".to_string()));
        assert_eq!(record.login_id, 1);
        assert_eq!(record.tenant_id, 0);
        assert_eq!(record.key_version, 1);
        assert_eq!(record.expires_at, 9999);
        assert!(!record.revoked);
        assert_eq!(record.created_at, 0);
    }
}
