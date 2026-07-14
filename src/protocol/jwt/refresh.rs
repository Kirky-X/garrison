//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JWT RefreshToken Rotation 模块。
//!
//! 基于 hash chain 的 RefreshToken 轮换：每次 `rotate` 时，新 token 的
//! `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
//! 旧 token 标记为 `revoked`，防止重放攻击。
//!
//! ## 核心抽象
//!
//! - [`RefreshTokenRecord`](crate::protocol::jwt::refresh::RefreshTokenRecord)：`refresh_tokens` 表行结构（hash chain 字段）
//! - `RefreshTokenRotation`：rotate 服务（T057-T066 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE refresh_tokens (
//!     token_hash TEXT PRIMARY KEY,
//!     parent_token_hash TEXT,
//!     login_id TEXT NOT NULL,
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
/// ## Hash chain 字段（JWT 模块使用）
///
/// - `token_hash`: 当前 token 的 SHA-256 哈希（主键）
/// - `parent_token_hash`: 旧 token 的哈希（首次签发为 `None`）
/// - `login_id`: 关联用户 ID（JWT 模块使用）
/// - `tenant_id`: 租户 ID（多租户隔离）
/// - `key_version`: 密钥轮换版本号（支持密钥轮换时区分）
/// - `expires_at`: 过期时间（Unix 秒）
/// - `revoked`: 是否已撤销（rotate 后旧 token 标记为 true）
/// - `created_at`: 创建时间（Unix 秒）
///
/// ## OAuth2 扩展字段（v0.7.1 新增，`#[serde(default)]` 向后兼容）
///
/// - `client_id`: OAuth2 客户端 ID（JWT 模块不使用，设为 `None`）
/// - `scopes`: OAuth2 授权的 scope 列表（空格分隔，JWT 模块不使用）
/// - `username`: OAuth2 password grant type 用户名（JWT 模块不使用）
/// - `user_id`: OAuth2 user_id（与 `login_id` 区分：`login_id` 是 JWT 模块的 i64 ID，
///   `user_id` 是 OAuth2 的 `Option<i64>`，`client_credentials` 时为 `None`）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenRecord {
    /// 当前 token 的 SHA-256 哈希（主键）。
    pub token_hash: String,
    /// 旧 token 的哈希（首次签发为 `None`）。
    pub parent_token_hash: Option<String>,
    /// 关联用户 ID（JWT 模块使用）。
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

    /// OAuth2 客户端 ID（v0.7.1 新增，JWT 模块不使用）。
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth2 授权的 scope 列表（空格分隔，v0.7.1 新增）。
    #[serde(default)]
    pub scopes: Option<String>,
    /// OAuth2 password grant type 用户名（v0.7.1 新增）。
    #[serde(default)]
    pub username: Option<String>,
    /// OAuth2 user_id（与 `login_id` 区分，v0.7.1 新增）。
    #[serde(default)]
    pub user_id: Option<i64>,
}

// ============================================================================
// RefreshTokenRotation 服务（T057-db-sqlite gated）
// ============================================================================

#[cfg(feature = "db-sqlite")]
mod service {
    use super::RefreshTokenRecord;
    use crate::error::{BulwarkError, BulwarkResult};
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, RwLock};
    use uuid::Uuid;

    /// RefreshToken Rotation 服务（hash chain + rotate + reuse detection）。
    ///
    /// 完整实现在 T057-T066 逐步构建：
    /// - T057-`rotate` 基础实现（SHA-256 hash + INSERT new + UPDATE old revoked=1）
    /// - T059-`detect_reuse` 查表 revoked=1
    /// - T061-`revoke_chain` 递归 UPDATE parent_token_hash 链
    /// - T063-`rotate` 追加 reuse detection（重用则 revoke_chain 后返回 InvalidToken）
    ///
    /// # 字段
    ///
    /// - `pool`: SQLite 连接池（查 `refresh_tokens` 表）
    /// - `jwt_handler`: JWT 处理器（签发新 access token）
    /// - `key_version`: 密钥轮换版本号（写入新 record 的 key_version 字段）
    ///
    /// # Rule 7 冲突暴露
    ///
    /// tasks.md T058 原描述 `pub dao: Arc<dyn BulwarkDao>` 不够——
    /// `rotate` 需查 SQL（DbPool）+ 签发 access token（JwtHandler）+ 读 key_version。
    /// 决策：struct 持有 `pool: DbPool` + `jwt_handler: Arc<JwtHandler>` + `key_version: Arc<RwLock<u32>>`，
    /// 不持有 `dao`（BulwarkDao 是缓存层抽象，不支持 SQL 查询）。
    pub struct RefreshTokenRotation {
        /// SQLite 连接池（查 `refresh_tokens` 表）。
        pub pool: DbPool,
        /// JWT 处理器（签发新 access token）。
        pub jwt_handler: Arc<JwtHandler>,
        /// 密钥轮换版本号（写入新 record 的 key_version 字段）。
        pub key_version: Arc<RwLock<u32>>,
    }

    impl RefreshTokenRotation {
        /// 创建 RefreshTokenRotation 实例。
        ///
        /// # 参数
        /// - `pool`: SQLite 连接池（用于查 `refresh_tokens` 表）
        /// - `jwt_handler`: JWT 处理器（签发新 access token）
        /// - `key_version`: 密钥轮换版本号（写入新 record 的 key_version 字段）
        pub fn new(
            pool: DbPool,
            jwt_handler: Arc<JwtHandler>,
            key_version: Arc<RwLock<u32>>,
        ) -> Self {
            Self {
                pool,
                jwt_handler,
                key_version,
            }
        }

        /// 计算 SHA-256 并返回 hex 字符串。
        fn sha256_hex(s: &str) -> String {
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            let result = hasher.finalize();
            result.iter().map(|b| format!("{:02x}", b)).collect()
        }

        /// 获取当前 Unix 时间戳（秒）。
        fn now_unix() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        }

        /// T058 Green: rotate 旧 refresh token 为新 access + 新 refresh。
        ///
        /// 流程：
        /// 1. 计算 `old_hash = SHA-256(old_token)`
        /// 2. 查表验证 `old_hash` 存在且 `revoked=0`，读取 login_id / tenant_id
        ///    及 OAuth2 扩展字段（client_id / scopes / username / user_id）
        /// 3. 生成新 refresh token（UUID v4）+ 签发新 access token（JwtHandler，1 小时有效期）
        /// 4. 计算 `new_hash = SHA-256(new_refresh)`
        /// 5. INSERT new record（`parent_token_hash = old_hash`, `revoked=0`，7 天过期，
        ///    继承 OAuth2 扩展字段）
        /// 6. UPDATE old record `revoked=1`
        /// 7. 返回 `(new_access, new_refresh)`
        ///
        /// # 错误
        /// - `BulwarkError::InvalidToken`: old_token 不存在或已 revoked
        /// - `BulwarkError::Dao`: SQL 查询/INSERT/UPDATE 失败
        /// - `BulwarkError::Internal`: JwtHandler 签发失败（由 sign 透传）
        pub async fn rotate(&self, old_token: &str) -> BulwarkResult<(String, String)> {
            let old_hash = Self::sha256_hex(old_token);

            // reuse detection——若 old_hash 已 revoked，说明 token 被重用，
            // 吊销整个链（old_hash 及其所有子代）后返回 InvalidToken
            if self.detect_reuse(&old_hash).await? {
                self.revoke_chain(&old_hash).await?;
                return Err(BulwarkError::TokenRevoked(
                    "refresh token reuse detected, chain revoked".to_string(),
                ));
            }

            // 查表验证 old_hash 存在且 revoked=0
            // T005: 扩展 SELECT 读取 OAuth2 字段以便继承到新记录
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let select_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT login_id, tenant_id, client_id, scopes, username, user_id \
                 FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
                vec![Value::String(Some(old_hash.clone()))],
            );
            let row = conn
                .query_one_raw(select_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens 查询失败: {}", e)))?
                .ok_or_else(|| {
                    BulwarkError::InvalidToken(
                        "refresh token not found or already consumed".to_string(),
                    )
                })?;

            let login_id: String = row
                .try_get("", "login_id")
                .map_err(|e| BulwarkError::Dao(format!("login_id 读取失败: {}", e)))?;
            let tenant_id: i64 = row
                .try_get("", "tenant_id")
                .map_err(|e| BulwarkError::Dao(format!("tenant_id 读取失败: {}", e)))?;
            // T005: 读取 OAuth2 扩展字段（旧记录可能为 NULL，使用 ok().flatten() 容错）
            let client_id: Option<String> = row.try_get("", "client_id").ok().flatten();
            let scopes: Option<String> = row.try_get("", "scopes").ok().flatten();
            let username: Option<String> = row.try_get("", "username").ok().flatten();
            let user_id: Option<i64> = row.try_get("", "user_id").ok().flatten();

            // 生成新 refresh token + 签发新 access token
            let new_refresh = Uuid::new_v4().to_string();
            let new_access = self.jwt_handler.sign(&login_id, 3600)?;
            let new_hash = Self::sha256_hex(&new_refresh);
            let now = Self::now_unix();
            let kv = *self
                .key_version
                .read()
                .expect("key_version RwLock 不应 poisoned");

            // INSERT new record（parent_token_hash = old_hash, revoked=0, 7 天过期）
            // T005: 继承 OAuth2 扩展字段
            let insert_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO refresh_tokens \
                 (token_hash, parent_token_hash, login_id, tenant_id, key_version, \
                  expires_at, revoked, created_at, client_id, scopes, username, user_id) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    Value::String(Some(new_hash.clone())),
                    Value::String(Some(old_hash.clone())),
                    Value::String(Some(login_id.clone())),
                    Value::BigInt(Some(tenant_id)),
                    Value::BigInt(Some(kv as i64)),
                    Value::BigInt(Some(now + 86400 * 7)),
                    Value::BigInt(Some(0)),
                    Value::BigInt(Some(now)),
                    client_id
                        .clone()
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    scopes
                        .clone()
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    username
                        .clone()
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    user_id
                        .map(|i| Value::BigInt(Some(i)))
                        .unwrap_or(Value::BigInt(None)),
                ],
            );
            conn.execute_raw(insert_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens INSERT 失败: {}", e)))?;

            // UPDATE old record revoked=1
            let update_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                vec![Value::String(Some(old_hash))],
            );
            conn.execute_raw(update_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens UPDATE 失败: {}", e)))?;

            Ok((new_access, new_refresh))
        }

        /// T003 Green: 签发初始 refresh_token 并写入 refresh_tokens 表。
        ///
        /// 用于 OAuth2 authorization_code / password grant type 首次签发 refresh_token。
        /// 不存在父 token（`parent_token_hash = None`），`revoked = 0`。
        ///
        /// # 参数
        /// - `client_id`: OAuth2 客户端 ID
        /// - `user_id`: OAuth2 用户 ID（`client_credentials` 时为 `None`）
        /// - `scopes`: 授权的 scope 列表（空列表时存储为 `NULL`）
        /// - `username`: password grant type 用户名（其他 grant type 为 `None`）
        /// - `login_id`: JWT 模块的用户 ID（与 `user_id` 区分，通常相同但语义不同）
        /// - `tenant_id`: 租户 ID（多租户隔离）
        /// - `ttl_seconds`: refresh_token 有效期（秒）
        ///
        /// # 返回
        /// 原始 refresh_token 字符串（调用方需返回给客户端）
        ///
        /// # 错误
        /// - `BulwarkError::Dao`: SQL INSERT 失败
        pub async fn issue(
            &self,
            client_id: &str,
            user_id: Option<i64>,
            scopes: &[String],
            username: Option<&str>,
            login_id: i64,
            tenant_id: i64,
            ttl_seconds: i64,
        ) -> BulwarkResult<String> {
            let refresh_token = Uuid::new_v4().to_string();
            let token_hash = Self::sha256_hex(&refresh_token);
            let now = Self::now_unix();
            let kv = *self
                .key_version
                .read()
                .expect("key_version RwLock 不应 poisoned");

            let scopes_str = if scopes.is_empty() {
                None
            } else {
                Some(scopes.join(" "))
            };

            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let insert_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO refresh_tokens \
                 (token_hash, parent_token_hash, login_id, tenant_id, key_version, \
                  expires_at, revoked, created_at, client_id, scopes, username, user_id) \
                 VALUES (?, NULL, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
                vec![
                    Value::String(Some(token_hash)),
                    Value::BigInt(Some(login_id)),
                    Value::BigInt(Some(tenant_id)),
                    Value::BigInt(Some(kv as i64)),
                    Value::BigInt(Some(now + ttl_seconds)),
                    Value::BigInt(Some(now)),
                    Value::String(Some(client_id.to_string())),
                    scopes_str
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    username
                        .map(|s| Value::String(Some(s.to_string())))
                        .unwrap_or(Value::String(None)),
                    user_id
                        .map(|i| Value::BigInt(Some(i)))
                        .unwrap_or(Value::BigInt(None)),
                ],
            );
            conn.execute_raw(insert_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens INSERT 失败: {}", e)))?;

            Ok(refresh_token)
        }

        /// T004 Green: 验证 refresh_token 有效性（不轮换）。
        ///
        /// 用于 OAuth2 introspect 端点或调用方需要只读检查 token 有效性。
        ///
        /// # 参数
        /// - `token`: 原始 refresh_token 字符串（内部计算 SHA-256）
        ///
        /// # 返回
        /// - `Ok(Some(record))`: token 有效且未 revoked
        /// - `Ok(None)`: token 不存在或已 revoked
        /// - `Err(BulwarkError::Dao)`: SQL 查询失败
        pub async fn validate(&self, token: &str) -> BulwarkResult<Option<RefreshTokenRecord>> {
            let token_hash = Self::sha256_hex(token);
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT token_hash, parent_token_hash, login_id, tenant_id, \
                        key_version, expires_at, revoked, created_at, \
                        client_id, scopes, username, user_id \
                 FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
                vec![Value::String(Some(token_hash.clone()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens 查询失败: {}", e)))?;

            match row {
                Some(row) => {
                    let login_id: String = row
                        .try_get("", "login_id")
                        .map_err(|e| BulwarkError::Dao(format!("login_id 读取失败: {}", e)))?;
                    let tenant_id: i64 = row
                        .try_get("", "tenant_id")
                        .map_err(|e| BulwarkError::Dao(format!("tenant_id 读取失败: {}", e)))?;
                    let key_version: i64 = row
                        .try_get("", "key_version")
                        .map_err(|e| BulwarkError::Dao(format!("key_version 读取失败: {}", e)))?;
                    let expires_at: i64 = row
                        .try_get("", "expires_at")
                        .map_err(|e| BulwarkError::Dao(format!("expires_at 读取失败: {}", e)))?;
                    let revoked: i64 = row
                        .try_get("", "revoked")
                        .map_err(|e| BulwarkError::Dao(format!("revoked 读取失败: {}", e)))?;
                    let created_at: i64 = row
                        .try_get("", "created_at")
                        .map_err(|e| BulwarkError::Dao(format!("created_at 读取失败: {}", e)))?;
                    let parent_token_hash: Option<String> =
                        row.try_get("", "parent_token_hash").ok().flatten();
                    let client_id: Option<String> = row.try_get("", "client_id").ok().flatten();
                    let scopes: Option<String> = row.try_get("", "scopes").ok().flatten();
                    let username: Option<String> = row.try_get("", "username").ok().flatten();
                    let user_id: Option<i64> = row.try_get("", "user_id").ok().flatten();

                    // login_id 在 SQL 表中是 TEXT，需转为 i64
                    let login_id_i64: i64 = login_id.parse().unwrap_or(0);

                    Ok(Some(RefreshTokenRecord {
                        token_hash,
                        parent_token_hash,
                        login_id: login_id_i64,
                        tenant_id,
                        key_version: key_version as u32,
                        expires_at,
                        revoked: revoked == 1,
                        created_at,
                        client_id,
                        scopes,
                        username,
                        user_id,
                    }))
                },
                None => Ok(None),
            }
        }

        /// T060 Green: 检测 token 是否已被消费（revoked=1 即 reuse）。
        ///
        /// # 参数
        /// - `token_hash`: 已 SHA-256 哈希的 token hash（非原始 token）
        ///
        /// # 返回
        /// - `Ok(true)`: token 已 revoked（reuse 检测命中）
        /// - `Ok(false)`: token 未 revoked 或不存在
        /// - `Err(BulwarkError::Dao)`: SQL 查询失败
        ///
        /// # 语义
        /// 不存在与 revoked=0 同等对待（均返回 false）——
        /// 只有已 revoked 才视为 reuse。不存在视为"未签发"，由调用方决定如何处理。
        pub async fn detect_reuse(&self, token_hash: &str) -> BulwarkResult<bool> {
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(token_hash.to_string()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens 查询失败: {}", e)))?;

            // 不存在 → false（未签发，不算 reuse）；存在且 revoked=1 → true
            let revoked = match row {
                Some(row) => row
                    .try_get::<i64>("", "revoked")
                    .map_err(|e| BulwarkError::Dao(format!("revoked 读取失败: {}", e)))?,
                None => return Ok(false),
            };
            Ok(revoked == 1)
        }

        /// T062 Green: 撤销给定 token 及其所有子代（沿 parent_token_hash 反向递归）。
        ///
        /// 语义：reuse detection 命中 old_token 后，old_token 之后签发的所有
        /// 后代 token（即 parent_token_hash 链上以 old_token 为根的子树）
        /// 都应被吊销，防止攻击者继续使用被盗链。
        ///
        /// # 参数
        /// - `token_hash`: 起点 token hash（已 SHA-256 哈希）
        ///
        /// # 算法（迭代 + 栈，避免 async 递归 Box::pin 复杂度）
        /// 1. 把 `token_hash` 入栈
        /// 2. 出栈一个 hash，UPDATE 它 revoked=1
        /// 3. 查所有 `parent_token_hash == hash` 的 record（子代），入栈
        /// 4. 重复直到栈空
        ///
        /// # 错误
        /// - `BulwarkError::Dao`: SQL 查询/UPDATE 失败
        pub async fn revoke_chain(&self, token_hash: &str) -> BulwarkResult<()> {
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let mut stack = vec![token_hash.to_string()];
            while let Some(hash) = stack.pop() {
                // UPDATE current revoked=1
                let update_stmt = Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                    vec![Value::String(Some(hash.clone()))],
                );
                conn.execute_raw(update_stmt)
                    .await
                    .map_err(|e| BulwarkError::Dao(format!("refresh_tokens UPDATE 失败: {}", e)))?;

                // 查子代（parent_token_hash == hash）
                let select_stmt = Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT token_hash FROM refresh_tokens WHERE parent_token_hash = ?",
                    vec![Value::String(Some(hash))],
                );
                let rows = conn.query_all_raw(select_stmt).await.map_err(|e| {
                    BulwarkError::Dao(format!("refresh_tokens 查询子代失败: {}", e))
                })?;
                for row in rows {
                    let child_hash: String = row
                        .try_get("", "token_hash")
                        .map_err(|e| BulwarkError::Dao(format!("token_hash 读取失败: {}", e)))?;
                    stack.push(child_hash);
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "db-sqlite")]
pub use service::RefreshTokenRotation;

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
            client_id: None,
            scopes: None,
            username: None,
            user_id: None,
        };
        assert_eq!(record.token_hash, "abc");
        assert_eq!(record.parent_token_hash, Some("def".to_string()));
        assert_eq!(record.login_id, 1);
        assert_eq!(record.tenant_id, 0);
        assert_eq!(record.key_version, 1);
        assert_eq!(record.expires_at, 9999);
        assert!(!record.revoked);
        assert_eq!(record.created_at, 0);
        // v0.7.1 OAuth2 扩展字段默认为 None
        assert_eq!(record.client_id, None);
        assert_eq!(record.scopes, None);
        assert_eq!(record.username, None);
        assert_eq!(record.user_id, None);
    }

    /// T001 Red→Green: 旧 JSON（无 OAuth2 扩展字段）反序列化成功，新字段为 None。
    ///
    /// 验证 `#[serde(default)]` 向后兼容：v0.7.0 及更早版本序列化的
    /// `RefreshTokenRecord` JSON 不含 client_id/scopes/username/user_id，
    /// v0.7.1 反序列化时这些字段应为 None。
    #[test]
    fn refresh_token_record_old_json_deserializes_with_none_new_fields() {
        let old_json = r#"{
            "token_hash": "abc123",
            "parent_token_hash": null,
            "login_id": 42,
            "tenant_id": 1,
            "key_version": 2,
            "expires_at": 1700000000,
            "revoked": false,
            "created_at": 1699000000
        }"#;
        let record: RefreshTokenRecord = serde_json::from_str(old_json)
            .expect("旧 JSON 反序列化应成功（#[serde(default)] 保证向后兼容）");
        assert_eq!(record.token_hash, "abc123");
        assert_eq!(record.parent_token_hash, None);
        assert_eq!(record.login_id, 42);
        assert_eq!(record.tenant_id, 1);
        assert_eq!(record.key_version, 2);
        assert_eq!(record.expires_at, 1700000000);
        assert!(!record.revoked);
        assert_eq!(record.created_at, 1699000000);
        // 新字段应为 None
        assert_eq!(record.client_id, None);
        assert_eq!(record.scopes, None);
        assert_eq!(record.username, None);
        assert_eq!(record.user_id, None);
    }

    /// T001 Red→Green: 含 OAuth2 扩展字段的 JSON 序列化-反序列化往返一致。
    #[test]
    fn refresh_token_record_new_json_roundtrip() {
        let record = RefreshTokenRecord {
            token_hash: "new_hash".to_string(),
            parent_token_hash: Some("old_hash".to_string()),
            login_id: 100,
            tenant_id: 5,
            key_version: 3,
            expires_at: 1800000000,
            revoked: false,
            created_at: 1700000000,
            client_id: Some("client_123".to_string()),
            scopes: Some("read write admin".to_string()),
            username: Some("alice".to_string()),
            user_id: Some(42),
        };
        let json = serde_json::to_string(&record).expect("序列化应成功");
        let deserialized: RefreshTokenRecord = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(record, deserialized);
    }
}

// ============================================================================
// db-sqlite 集成测试（T055-refresh_tokens 表迁移 + rotate 服务）
// ============================================================================

#[cfg(all(test, feature = "protocol-jwt", feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::RefreshTokenRotation;
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use crate::error::BulwarkError;
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

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
    // T055-refresh_tokens 表迁移验证
    // ========================================================================

    /// T055-T056 Green: 验证 SQLite 迁移加载 `003_refresh_tokens.sql` 后
    /// `refresh_tokens` 表存在。
    ///
    /// Rule 11（惯例优先）：SQL 文件放 `migrations/sqlite/core/003_refresh_tokens.sql`，
    /// 复用现有 `migrate_core()` 自动加载机制（与 002_role_hierarchy.sql 同惯例），
    /// 而非 tasks.md 原描述的 `src/dao/repository/sqlite/refresh_tokens.sql`。
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_tokens_table_exists_after_migration() {
        let pool = setup_db().await;
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='refresh_tokens'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "refresh_tokens 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }

    // ========================================================================
    // 辅助函数（T057+ rotate 测试用）
    // ========================================================================

    /// 计算 SHA-256 并返回 hex 字符串。
    fn sha256_hex(s: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 向 refresh_tokens 表插入一条记录。
    async fn insert_refresh_token(
        pool: &DbPool,
        token_hash: &str,
        parent_token_hash: Option<&str>,
        login_id: i64,
        tenant_id: i64,
        key_version: u32,
        expires_at: i64,
        revoked: i64,
    ) {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO refresh_tokens (token_hash, parent_token_hash, login_id, tenant_id, key_version, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Value::String(Some(token_hash.to_string())),
                Value::String(parent_token_hash.map(|s| s.to_string())),
                Value::BigInt(Some(login_id)),
                Value::BigInt(Some(tenant_id)),
                Value::BigInt(Some(key_version as i64)),
                Value::BigInt(Some(expires_at)),
                Value::BigInt(Some(revoked)),
                Value::BigInt(Some(0)),
            ],
        );
        conn.execute_raw(stmt).await.expect("INSERT 应成功");
    }

    /// 查询 record 的 revoked 字段。
    async fn query_revoked(pool: &DbPool, token_hash: &str) -> i64 {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .unwrap()
            .expect("record 应存在");
        row.try_get::<i64>("", "revoked").unwrap()
    }

    /// 查询 record 的 (parent_token_hash, revoked)。
    async fn query_record(pool: &DbPool, token_hash: &str) -> (Option<String>, i64) {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT parent_token_hash, revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .unwrap()
            .expect("record 应存在");
        let parent: Option<String> = row.try_get("", "parent_token_hash").ok();
        let revoked: i64 = row.try_get("", "revoked").unwrap();
        (parent, revoked)
    }

    // ========================================================================
    // T057-rotate 测试
    // ========================================================================

    /// T057 Red: `rotate` 插入新 token 并标记旧 token 已消费。
    ///
    /// 流程：
    /// 1. 预先 INSERT old_token record（模拟已签发的 refresh token）
    /// 2. 调用 `rotate(old_token)` 返回 (new_access, new_refresh)
    /// 3. 断言 old_token 的 record revoked=1
    /// 4. 断言 new_refresh 的 record 已插入，parent_token_hash == SHA-256(old_token)
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_inserts_new_token_and_marks_old_consumed() {
        let pool = setup_db().await;

        // 预先 INSERT old_token record
        let old_token = "old_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        // 构造 RefreshTokenRotation（Rule 7：持有 pool + jwt_handler + key_version）
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // rotate
        let (new_access, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");
        assert!(!new_access.is_empty(), "new_access 应非空");
        assert!(!new_refresh.is_empty(), "new_refresh 应非空");

        // 断言 old_token revoked=1
        let old_revoked = query_revoked(&pool, &old_hash).await;
        assert_eq!(old_revoked, 1, "old_token 应标记为 revoked");

        // 断言 new_refresh 的 record 已插入，parent_token_hash == old_hash
        let new_hash = sha256_hex(&new_refresh);
        let (parent, revoked) = query_record(&pool, &new_hash).await;
        assert_eq!(
            parent,
            Some(old_hash),
            "new record 的 parent_token_hash 应等于 old_hash"
        );
        assert_eq!(revoked, 0, "new record 应未 revoked");
    }

    // ========================================================================
    // T059-detect_reuse 测试
    // ========================================================================

    /// T059 Red: `detect_reuse` 在 token 已被消费（revoked=1）时返回 true。
    ///
    /// 流程：
    /// 1. 预先 INSERT old_token record（revoked=0）
    /// 2. 调用 `rotate(old_token)` → old_token 标记为 revoked=1
    /// 3. 调用 `detect_reuse(SHA-256(old_token))` → 断言返回 `true`（已消费）
    /// 4. 用 new_refresh 的 hash 调用 `detect_reuse` → 断言返回 `false`（未消费）
    #[tokio::test(flavor = "multi_thread")]
    async fn detect_reuse_returns_true_when_token_already_consumed() {
        let pool = setup_db().await;

        let old_token = "old_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // rotate 后 old_token 应 revoked=1
        let (_, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");

        // detect_reuse(old_hash) → true（已被消费）
        let reused = rotation
            .detect_reuse(&old_hash)
            .await
            .expect("detect_reuse 应成功");
        assert!(reused, "已 revoked 的 token 应检测为 reuse");

        // detect_reuse(new_hash) → false（未消费）
        let new_hash = sha256_hex(&new_refresh);
        let new_reused = rotation
            .detect_reuse(&new_hash)
            .await
            .expect("detect_reuse 应成功");
        assert!(!new_reused, "未 revoked 的 token 不应检测为 reuse");
    }

    // ========================================================================
    // T061-revoke_chain 测试
    // ========================================================================

    /// T061 Red: `revoke_chain` 撤销给定 token 及其所有子代（沿 parent_token_hash 反向递归）。
    ///
    /// 构造链：t1 (parent=None) ← t2 (parent=t1) ← t3 (parent=t2)
    /// （t3 是最新，t1 是最老）
    ///
    /// 调用 `revoke_chain(SHA-256(t1))` → 应撤销 t1 及其所有子代（t2, t3）
    ///
    /// 断言：t1/t2/t3 的 revoked 字段全为 1
    ///
    /// **Rule 7 命名说明**：tasks.md 原测试名 `revoke_chain_revokes_all_parent_tokens`
    /// 与实际语义有歧义——实际撤销的是 t1 及其所有"子代"（descendant），
    /// 而非"父代"（parent）。此处沿用 tasks.md 命名以保持一致（Rule 11），
    /// 但语义以 doc comment 为准。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_chain_revokes_all_parent_tokens() {
        let pool = setup_db().await;

        // 构造链 t1 ← t2 ← t3（t3 最新）
        let t1_hash = sha256_hex("t1");
        let t2_hash = sha256_hex("t2");
        let t3_hash = sha256_hex("t3");
        insert_refresh_token(&pool, &t1_hash, None, 1, 0, 1, 9999, 0).await;
        insert_refresh_token(&pool, &t2_hash, Some(&t1_hash), 1, 0, 1, 9999, 0).await;
        insert_refresh_token(&pool, &t3_hash, Some(&t2_hash), 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // revoke_chain(t1_hash) → t1 + 所有子代（t2, t3）全 revoked
        rotation
            .revoke_chain(&t1_hash)
            .await
            .expect("revoke_chain 应成功");

        assert_eq!(query_revoked(&pool, &t1_hash).await, 1, "t1 应 revoked");
        assert_eq!(
            query_revoked(&pool, &t2_hash).await,
            1,
            "t2 应 revoked（子代）"
        );
        assert_eq!(
            query_revoked(&pool, &t3_hash).await,
            1,
            "t3 应 revoked（孙代）"
        );
    }

    // ========================================================================
    // T063-rotate with reuse detection 测试
    // ========================================================================

    /// T063 Red: `rotate` 检测到 old_token 重用时返回 `InvalidToken` 并吊销整个链。
    ///
    /// 流程：
    /// 1. 预先 INSERT t1 record（revoked=0）
    /// 2. `rotate("t1")` → 得到 t2（new_refresh），t1 revoked=1
    /// 3. `rotate("t1")` again（重用 t1） → 应返回 `BulwarkError::InvalidToken`
    /// 4. 断言 t1 的 revoked=1（已 revoked）
    /// 5. 断言 t2 的 revoked=1（链被吊销）
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_with_reuse_detection_revokes_chain() {
        let pool = setup_db().await;

        let t1_token = "t1_token_value";
        let t1_hash = sha256_hex(t1_token);
        insert_refresh_token(&pool, &t1_hash, None, 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // 第一次 rotate：t1 → t2（成功）
        let (_, t2_refresh) = rotation
            .rotate(t1_token)
            .await
            .expect("第一次 rotate 应成功");
        let t2_hash = sha256_hex(&t2_refresh);

        // 第二次 rotate（重用 t1）：应返回 TokenRevoked（RFC 7009 Token Revocation）
        let result = rotation.rotate(t1_token).await;
        assert!(
            matches!(result, Err(BulwarkError::TokenRevoked(_))),
            "重用已消费的 refresh token 应返回 TokenRevoked，实际: {:?}",
            result
        );

        // 断言 t1 和 t2 的链全被吊销
        assert_eq!(
            query_revoked(&pool, &t1_hash).await,
            1,
            "t1 应 revoked（重用检测后）"
        );
        assert_eq!(
            query_revoked(&pool, &t2_hash).await,
            1,
            "t2 应 revoked（链被吊销）"
        );
    }

    // ========================================================================
    // T003-issue 方法测试
    // ========================================================================

    /// T003 Red→Green: `issue` 后 `validate` 返回 Some，字段匹配。
    ///
    /// 流程：
    /// 1. `issue(client_id, user_id, scopes, username, login_id, tenant_id, ttl)`
    /// 2. `validate(refresh_token)` 返回 Some(record)
    /// 3. 断言 record 字段与传入参数匹配
    /// 4. 断言 parent_token_hash 为 None（首次签发）
    /// 5. 断言 revoked 为 false
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_creates_record_with_correct_fields() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(2)));

        let scopes = vec!["read".to_string(), "write".to_string()];
        let refresh_token = rotation
            .issue(
                "client_abc",
                Some(42),
                &scopes,
                Some("alice"),
                42,
                5,
                86400 * 7,
            )
            .await
            .expect("issue 应成功");

        let record = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功")
            .expect("record 应存在");

        assert_eq!(
            record.parent_token_hash, None,
            "首次签发 parent_token_hash 应为 None"
        );
        assert!(!record.revoked, "新签发的 token 应未 revoked");
        assert_eq!(record.tenant_id, 5);
        assert_eq!(record.key_version, 2);
        assert_eq!(record.login_id, 42);
        assert_eq!(record.client_id, Some("client_abc".to_string()));
        assert_eq!(record.scopes, Some("read write".to_string()));
        assert_eq!(record.username, Some("alice".to_string()));
        assert_eq!(record.user_id, Some(42));
    }

    /// T003 Red→Green: 空 scopes 列表时 scopes 字段为 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_with_empty_scopes_stores_none() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let refresh_token = rotation
            .issue(
                "client_xyz",
                None, // client_credentials 无 user_id
                &[],  // 空 scopes
                None,
                0,
                0,
                3600,
            )
            .await
            .expect("issue 应成功");

        let record = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功")
            .expect("record 应存在");

        assert_eq!(record.scopes, None, "空 scopes 列表应存储为 None");
        assert_eq!(record.user_id, None, "client_credentials 无 user_id");
        assert_eq!(record.username, None);
    }

    // ========================================================================
    // T004-validate 方法测试
    // ========================================================================

    /// T004 Red→Green: 有效 token 返回 Some。
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_returns_some_for_valid_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let refresh_token = rotation
            .issue("client_1", Some(1), &["read".to_string()], None, 1, 0, 3600)
            .await
            .expect("issue 应成功");

        let result = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功");
        assert!(result.is_some(), "有效 token 应返回 Some");
    }

    /// T004 Red→Green: 已 revoked token 返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_returns_none_for_revoked_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let refresh_token = rotation
            .issue("client_1", Some(1), &["read".to_string()], None, 1, 0, 3600)
            .await
            .expect("issue 应成功");

        // rotate 后旧 token 应被 revoked，validate 返回 None
        let _ = rotation
            .rotate(&refresh_token)
            .await
            .expect("rotate 应成功");
        let result = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功");
        assert!(result.is_none(), "已 revoked token 应返回 None");
    }

    /// T004 Red→Green: 不存在 token 返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_returns_none_for_nonexistent_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let result = rotation
            .validate("nonexistent_token_12345")
            .await
            .expect("validate 应成功");
        assert!(result.is_none(), "不存在的 token 应返回 None");
    }

    // ========================================================================
    // T005-rotate 继承 OAuth2 字段测试
    // ========================================================================

    /// T005 Red→Green: `issue` 带 OAuth2 字段后 `rotate`，新记录继承这些字段。
    ///
    /// 流程：
    /// 1. `issue` 带 client_id / scopes / username / user_id
    /// 2. `rotate(old_token)` 得到 new_refresh
    /// 3. `validate(new_refresh)` 返回 Some
    /// 4. 断言新记录继承 client_id / scopes / username / user_id
    /// 5. 断言新记录 parent_token_hash 指向旧记录 token_hash
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_inherits_oauth2_fields() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let scopes = vec!["admin".to_string(), "read".to_string()];
        let old_token = rotation
            .issue(
                "client_inherit",
                Some(99),
                &scopes,
                Some("bob"),
                99,
                3,
                86400,
            )
            .await
            .expect("issue 应成功");

        let old_hash = sha256_hex(&old_token);

        // rotate
        let (_, new_refresh) = rotation.rotate(&old_token).await.expect("rotate 应成功");

        // validate 新 token
        let new_record = rotation
            .validate(&new_refresh)
            .await
            .expect("validate 应成功")
            .expect("新 token 应存在");

        // 断言继承 OAuth2 字段
        assert_eq!(new_record.client_id, Some("client_inherit".to_string()));
        assert_eq!(new_record.scopes, Some("admin read".to_string()));
        assert_eq!(new_record.username, Some("bob".to_string()));
        assert_eq!(new_record.user_id, Some(99));
        // 断言 hash chain
        assert_eq!(
            new_record.parent_token_hash,
            Some(old_hash),
            "新记录 parent_token_hash 应指向旧记录 token_hash"
        );
        // 旧 token 应 revoked
        let old_record = rotation
            .validate(&old_token)
            .await
            .expect("validate 应成功");
        assert!(old_record.is_none(), "旧 token 应已 revoked");
    }

    /// T005 Red→Green: 旧记录（新字段 NULL）rotate 后新记录字段也为 None。
    ///
    /// 验证向后兼容：v0.7.0 及更早的 refresh_tokens 记录不含 OAuth2 字段，
    /// rotate 后新记录的 OAuth2 字段也应为 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_old_record_with_null_new_fields_inherits_none() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // 使用旧格式 INSERT（不含 OAuth2 字段，模拟 v0.7.0 记录）
        let old_token = "legacy_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        // rotate
        let (_, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");

        // validate 新 token
        let new_record = rotation
            .validate(&new_refresh)
            .await
            .expect("validate 应成功")
            .expect("新 token 应存在");

        // 断言 OAuth2 字段为 None（继承自旧记录的 NULL）
        assert_eq!(
            new_record.client_id, None,
            "旧记录 client_id 为 NULL，新记录应继承 None"
        );
        assert_eq!(new_record.scopes, None);
        assert_eq!(new_record.username, None);
        assert_eq!(new_record.user_id, None);
    }
}
