//! 社交登录协议插件模块（0.5.0 新增，依据 proposal H2 / spec social-login）。
//!
//! 提供 `SocialLoginProvider` trait 抽象社交登录第三方平台（微信/支付宝），
//! 统一 `get_authorization_url` / `exchange_token` / `get_user_info` 三个 OAuth2 流程方法。
//!
//! ## 子模块
//!
//! - `wechat`：微信扫码登录（`WechatProvider`，需 `social-wechat` feature）
//! - `alipay`：支付宝授权登录（`AlipayProvider`，需 `social-alipay` feature）
//!
//! ## 与 OAuth2 模块的关系
//!
//! `protocol::oauth2` 提供通用 OAuth2 客户端（Authorization Code / Client Credentials / Password），
//! 本模块针对社交平台特化（微信/支付宝的自定义 API 签名、用户信息格式）。

use crate::error::BulwarkResult;
use async_trait::async_trait;
use serde_json::Value;

// ============================================================================
// SocialProvider enum：社交平台标识
// ============================================================================

/// 社交登录平台标识（依据 spec social-login R-social-login-001）。
///
/// 用于 `SocialUserInfo.provider` 字段标识用户来源平台。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialProvider {
    /// 微信开放平台扫码登录。
    Wechat,
    /// 支付宝开放平台授权登录。
    Alipay,
    /// 微信小程序登录（v0.5.0+ 预留，实现推迟到 v0.5.1+）。
    WechatMiniApp,
}

// ============================================================================
// SocialUserInfo：社交用户信息
// ============================================================================

/// 社交用户信息（依据 spec social-login R-social-login-001）。
///
/// `exchange_token` / `get_user_info` 方法的返回类型，承载第三方平台返回的用户字段。
#[derive(Debug, Clone)]
pub struct SocialUserInfo {
    /// 用户来源平台标识。
    pub provider: SocialProvider,
    /// 第三方平台用户唯一 ID（微信 openid / 支付宝 user_id）。
    pub provider_user_id: String,
    /// 用户昵称（可能为空）。
    pub nickname: Option<String>,
    /// 用户头像 URL（可能为空）。
    pub avatar: Option<String>,
    /// 跨应用统一 ID（微信 unionid，用于同一开发者主体下多应用账号打通）。
    pub union_id: Option<String>,
    /// 第三方平台原始响应 JSON（调试用，不应依赖其结构）。
    pub raw: Value,
}

// ============================================================================
// 子模块声明
// ============================================================================

/// 微信扫码登录 provider（依据 spec social-login R-social-login-002）。
///
/// 启用 `social-wechat` feature 时编译。
#[cfg(feature = "social-wechat")]
pub mod wechat;

/// 支付宝授权登录 provider（依据 spec social-login R-social-login-003）。
///
/// 启用 `social-alipay` feature 时编译。
#[cfg(feature = "social-alipay")]
pub mod alipay;

// ============================================================================
// SocialBindingService（feature = "db-sqlite"，依据 spec social-login R-social-login-004）
// ============================================================================

/// 社交账号绑定服务（v0.5.0 新增，依据 spec social-login R-social-login-004）。
///
/// 提供 `find_or_create` 语义：首次社交登录时自动创建绑定关系并生成新 `login_id`，
/// 后续登录返回已有 `login_id`（幂等）。
///
/// # 设计决策（Decision Matrix 方案 A）
///
/// struct 同时持有：
/// - `pool: DbPool`：执行 SQL 查询/插入（`social_bindings` 表）
/// - `dao: Arc<dyn BulwarkDao>`：缓存层抽象（保留扩展点，当前未使用）
///
/// 与 `RoleHierarchyService` 模式一致：BulwarkDao 是 KV 缓存抽象，
/// 不支持 SQL SELECT/INSERT，故 `find_or_create` 实际用 `pool` 查 SQL。
/// `BulwarkDao` trait 的 `find_social_binding` / `insert_social_binding`
/// 默认方法返回 `NotImplemented`，仅为满足 spec trait 契约。
///
/// # 表结构
///
/// ```sql
/// CREATE TABLE social_bindings (
///     id               INTEGER PRIMARY KEY AUTOINCREMENT,
///     tenant_id        INTEGER NOT NULL DEFAULT 0,
///     login_id         INTEGER NOT NULL,
///     provider         TEXT    NOT NULL,
///     provider_user_id TEXT    NOT NULL,
///     union_id         TEXT,
///     created_at       INTEGER NOT NULL,
///     UNIQUE(tenant_id, provider, provider_user_id)
/// );
/// ```
///
/// `UNIQUE(tenant_id, provider, provider_user_id)` 保证同一租户下同一社交账号仅绑定一个 login_id。
#[cfg(feature = "db-sqlite")]
pub struct SocialBindingService {
    /// SQLite 连接池（查 `social_bindings` 表）。
    pub pool: dbnexus::DbPool,
    /// 缓存层抽象（保留扩展点，当前未使用）。
    pub dao: std::sync::Arc<dyn crate::dao::BulwarkDao>,
}

#[cfg(feature = "db-sqlite")]
impl SocialBindingService {
    /// 创建 `SocialBindingService` 实例。
    ///
    /// # 参数
    /// - `pool`: SQLite 连接池（用于查 `social_bindings` 表）
    /// - `dao`: 缓存层抽象（保留扩展点，当前未使用）
    pub fn new(pool: dbnexus::DbPool, dao: std::sync::Arc<dyn crate::dao::BulwarkDao>) -> Self {
        Self { pool, dao }
    }

    /// 查找或创建社交账号绑定关系（依据 spec social-login R-social-login-004）。
    ///
    /// # 流程
    ///
    /// 1. 按 `(tenant_id, provider, provider_user_id)` 查询 `social_bindings` 表
    /// 2. 命中 → 返回已有 `login_id`（幂等）
    /// 3. 未命中 → 用单条 `INSERT ... COALESCE((SELECT MAX(login_id)+1 ...), 1)` 原子插入
    ///    4. INSERT 成功 → SELECT 返回新建的 `login_id`
    ///    5. INSERT 失败（UNIQUE 冲突，并发场景下另一事务已插入）→ SELECT 返回已有 `login_id`
    ///
    /// # login_id 生成策略
    ///
    /// `login_id = COALESCE((SELECT MAX(login_id) + 1 FROM social_bindings WHERE tenant_id = ?), 1)`
    ///（按租户自增）。用单条 INSERT 的子查询生成，避免显式事务的连接占用问题
    ///（dbnexus 的 `begin_transaction` 在 sea-orm 连接池中可能死锁）。
    /// UNIQUE(tenant_id, provider, provider_user_id) 约束保证幂等性。
    ///
    /// # 参数
    /// - `user`: 社交用户信息（含 provider / provider_user_id / union_id）
    /// - `tenant_id`: 租户 ID（0=默认租户）
    ///
    /// # 返回
    /// - `Ok(login_id)`: 已有或新建的 login_id（String，UUID）
    ///
    /// # 错误
    /// - `BulwarkError::Dao`: SQL 查询/插入失败
    pub async fn find_or_create(
        &self,
        user: &SocialUserInfo,
        tenant_id: i64,
    ) -> crate::error::BulwarkResult<String> {
        use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

        let provider_str = provider_to_str(&user.provider);

        // 1. 查询已有绑定
        let session = self.pool.get_session("admin").await.map_err(|e| {
            crate::error::BulwarkError::Dao(format!("social_binding 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            crate::error::BulwarkError::Dao(format!("social_binding 获取 connection 失败: {}", e))
        })?;

        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            crate::error::BulwarkError::Dao(format!("social_binding 查询失败: {}", e))
        })?;

        // 2. 命中 → 返回已有 login_id
        if let Some(row) = rows.into_iter().next() {
            let login_id: String = row.try_get::<String>("", "login_id").map_err(|e| {
                crate::error::BulwarkError::Dao(format!("login_id 读取失败: {}", e))
            })?;
            return Ok(login_id);
        }

        // 3. 未命中 → 单条 INSERT（login_id 用 UUID 生成，UNIQUE 约束保证幂等性）
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let new_login_id = uuid::Uuid::new_v4().to_string();

        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO social_bindings \
             (tenant_id, login_id, provider, provider_user_id, union_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(new_login_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
                match user.union_id.clone() {
                    Some(s) => Value::String(Some(s)),
                    None => Value::String(None),
                },
                Value::BigInt(Some(created_at)),
            ],
        );
        // INSERT 可能因 UNIQUE 约束失败（并发场景下另一事务已插入相同绑定），
        // 此时忽略错误，下面 SELECT 会返回已有 login_id。
        match conn.execute_raw(stmt).await {
            Ok(result) if result.rows_affected() == 1 => {
                // INSERT 成功
            },
            Ok(result) => {
                return Err(crate::error::BulwarkError::Dao(format!(
                    "INSERT 未生效（rows_affected={}, 可能并发冲突）",
                    result.rows_affected()
                )));
            },
            Err(e) => {
                // 检查是否为 UNIQUE 约束冲突（SQLite 错误码 19 / 2067）
                let err_msg = e.to_string();
                if err_msg.contains("UNIQUE constraint failed")
                    || err_msg.contains("constraint failed")
                {
                    // 并发冲突，忽略错误，下面 SELECT 返回已有 login_id
                } else {
                    return Err(crate::error::BulwarkError::Dao(format!(
                        "INSERT social_bindings 失败: {}",
                        e
                    )));
                }
            },
        }

        // 4. SELECT 返回 login_id（INSERT 成功的新 login_id，或并发冲突时已有的 login_id）
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            crate::error::BulwarkError::Dao(format!("INSERT 后 SELECT login_id 失败: {}", e))
        })?;
        let row = rows.into_iter().next().ok_or_else(|| {
            crate::error::BulwarkError::Dao(
                "INSERT 后 SELECT 返回空（绑定未创建且查询失败）".into(),
            )
        })?;
        let login_id: String = row
            .try_get::<String>("", "login_id")
            .map_err(|e| crate::error::BulwarkError::Dao(format!("login_id 读取失败: {}", e)))?;

        Ok(login_id)
    }
}

/// 将 `SocialProvider` enum 转换为字符串标识（用于 `social_bindings.provider` 列）。
///
/// 值与 spec social-login R-social-login-001 `SocialProvider` 变体一一对应：
/// - `Wechat` → `"wechat"`
/// - `Alipay` → `"alipay"`
/// - `WechatMiniApp` → `"wechat_mini_app"`
#[cfg(feature = "db-sqlite")]
fn provider_to_str(provider: &SocialProvider) -> &'static str {
    match provider {
        SocialProvider::Wechat => "wechat",
        SocialProvider::Alipay => "alipay",
        SocialProvider::WechatMiniApp => "wechat_mini_app",
    }
}

// ============================================================================
// SocialLoginProvider trait：社交登录抽象
// ============================================================================

/// 社交登录服务提供方 trait（依据 spec social-login R-social-login-001）。
///
/// 定义三个异步方法覆盖 OAuth2 授权码流程：
/// - `get_authorization_url`：拼接授权页 URL（用户跳转到第三方平台授权）
/// - `exchange_token`：用授权码换取 access_token + provider_user_id（仅完成 code → access_token 一步，nickname/avatar 为 None，调用方需再调 `get_user_info`）
/// - `get_user_info`：用 access_token 获取用户信息（用于已缓存 token 的场景）
///
/// # 实现
///
/// - `WechatProvider`（`social-wechat` feature）
/// - `AlipayProvider`（`social-alipay` feature）
#[async_trait]
pub trait SocialLoginProvider: Send + Sync {
    /// 拼接第三方平台授权页 URL。
    ///
    /// # 参数
    /// - `state`: OAuth2 state 参数（CSRF 防护，调用方生成随机串并缓存校验）
    /// - `redirect_uri`: 授权回调 URL（需在第三方平台配置白名单）
    async fn get_authorization_url(&self, state: &str, redirect_uri: &str)
        -> BulwarkResult<String>;

    /// 用授权码换取用户信息。
    ///
    /// 仅完成 code → access_token 步骤；返回的 SocialUserInfo 中 nickname/avatar 为 None，调用方需再调 `get_user_info` 获取用户资料。
    ///
    /// # 参数
    /// - `code`: 授权码（第三方平台回调时附在 query 参数）
    /// - `state`: OAuth2 state 参数（校验一致性，防 CSRF）
    async fn exchange_token(&self, code: &str, state: &str) -> BulwarkResult<SocialUserInfo>;

    /// 用 access_token 获取用户信息。
    ///
    /// 用于已缓存 access_token 的场景（避免重复授权）。
    ///
    /// # 参数
    /// - `access_token`: 第三方平台访问令牌
    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<SocialUserInfo>;
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    /// 验证 `SocialLoginProvider` trait 可被 mock 实现并调用三个方法
    ///（依据 spec social-login R-social-login-001 验收标准 1）。
    ///
    /// Red 阶段：`SocialLoginProvider` / `SocialUserInfo` / `SocialProvider` 类型不存在 → 编译失败。
    /// Green 阶段（T098）：定义完整类型后测试通过。
    #[tokio::test]
    async fn social_login_provider_trait_defines_three_methods() {
        use super::*;

        struct MockSocialProvider;

        #[async_trait]
        impl SocialLoginProvider for MockSocialProvider {
            async fn get_authorization_url(
                &self,
                _state: &str,
                _redirect_uri: &str,
            ) -> BulwarkResult<String> {
                Ok("https://example.com/auth".into())
            }

            async fn exchange_token(
                &self,
                _code: &str,
                _state: &str,
            ) -> BulwarkResult<SocialUserInfo> {
                Ok(SocialUserInfo {
                    provider: SocialProvider::Wechat,
                    provider_user_id: "mock_openid".into(),
                    nickname: None,
                    avatar: None,
                    union_id: Some("mock_unionid".into()),
                    raw: serde_json::json!({"mock": true}),
                })
            }

            async fn get_user_info(&self, _access_token: &str) -> BulwarkResult<SocialUserInfo> {
                Ok(SocialUserInfo {
                    provider: SocialProvider::Wechat,
                    provider_user_id: "mock_openid".into(),
                    nickname: Some("MockUser".into()),
                    avatar: Some("https://example.com/avatar.png".into()),
                    union_id: Some("mock_unionid".into()),
                    raw: serde_json::json!({"mock": true}),
                })
            }
        }

        let provider = MockSocialProvider;

        // 验证 get_authorization_url 可调用且返回非空 URL
        let auth_url = provider
            .get_authorization_url("state123", "https://example.com/cb")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(!auth_url.is_empty(), "授权 URL 不应为空");

        // 验证 exchange_token 可调用且返回 SocialUserInfo
        let user_info = provider
            .exchange_token("code456", "state123")
            .await
            .expect("exchange_token 应返回 Ok");
        assert_eq!(user_info.provider, SocialProvider::Wechat);
        assert_eq!(user_info.provider_user_id, "mock_openid");
        assert_eq!(user_info.union_id.as_deref(), Some("mock_unionid"));

        // 验证 get_user_info 可调用且返回 SocialUserInfo
        let user_info = provider
            .get_user_info("access_token789")
            .await
            .expect("get_user_info 应返回 Ok");
        assert_eq!(user_info.nickname.as_deref(), Some("MockUser"));
        assert_eq!(
            user_info.avatar.as_deref(),
            Some("https://example.com/avatar.png")
        );
    }

    /// 验证 `SocialProvider` enum 含三个变体
    ///（依据 spec social-login R-social-login-001 验收标准 3）。
    #[test]
    fn social_provider_enum_has_three_variants() {
        use super::*;

        let wechat = SocialProvider::Wechat;
        let alipay = SocialProvider::Alipay;
        let mini_app = SocialProvider::WechatMiniApp;

        // 验证三个变体互不相等
        assert_ne!(wechat, alipay);
        assert_ne!(wechat, mini_app);
        assert_ne!(alipay, mini_app);
    }

    // ========================================================================
    // T106: SQLite 迁移加载验证（feature = "db-sqlite"）
    // ========================================================================

    /// T106 Green: 验证 `migrations/sqlite/core/005_social_bindings.sql`
    /// 被 `BulwarkMigration::migrate_core()` 加载后 `social_bindings` 表存在
    ///（依据 spec social-login R-social-login-004 验收标准 1）。
    ///
    /// 测试模式与 `role_hierarchy_table_exists_after_migration` 一致：
    /// 1. `init_dbnexus("sqlite::memory:")` 创建内存 SQLite
    /// 2. `BulwarkMigration::with_base_dir` 指向项目根目录 `migrations/sqlite/`
    /// 3. `migrate_core()` 执行 `core/*.sql`（含 005_social_bindings.sql）
    /// 4. 查询 `sqlite_master` 验证 `social_bindings` 表存在
    #[cfg(feature = "db-sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn social_bindings_table_exists_after_migration() {
        use crate::dao::{init_dbnexus, BulwarkMigration};
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        use std::path::PathBuf;

        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 应可用");
        let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");
        let migration = BulwarkMigration::with_base_dir(pool, base_dir);
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        // 至少 5 个迁移文件（001_init + 002_role_hierarchy + 003_refresh_tokens
        // + 004_audit_logs + 005_social_bindings）
        assert!(
            applied >= 5,
            "migrate_core 应至少执行 5 个文件（含 005_social_bindings），实际: {}",
            applied
        );

        let pool = migration.pool();
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='social_bindings'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "social_bindings 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }

    // ========================================================================
    // T107-T108: SocialBindingService Red-Green（feature = "db-sqlite"）
    // ========================================================================

    /// T107 Red: `SocialBindingService::find_or_create` 创建新绑定
    ///（依据 spec social-login R-social-login-004 验收标准 2）。
    ///
    /// Red 阶段：`SocialBindingService` 类型不存在 → 编译失败。
    /// Green 阶段（T108）：定义 `SocialBindingService { pool, dao }` + `find_or_create` 后测试通过。
    ///
    /// # 测试流程
    ///
    /// 1. 创建 SQLite in-memory DB + 迁移（含 005_social_bindings.sql）
    /// 2. 构造 `SocialBindingService::new(pool, dao)`（Decision Matrix 方案 A：pool + dao）
    /// 3. 构造 `SocialUserInfo { provider: Wechat, provider_user_id: "openid1", ... }`
    /// 4. 调用 `find_or_create(&user, tenant_id=0).await?`
    /// 5. 断言返回 `login_id` 为新生成的 String（UUID，非空）
    /// 6. 查询 `social_bindings` 表，断言有 1 行记录且 `provider_user_id == "openid1"`
    ///
    /// # SQLite 单连接内存数据库
    ///
    /// 用 `DbPool::with_config` 设置 `max_connections=1, min_connections=1`：
    /// - `sqlite::memory:` 每个 connection 独立内存数据库
    /// - dbnexus 默认 `min_connections=5` 会预创建多连接，导致第二次 `get_session` 拿到没迁移的新连接
    /// - 单连接池强制所有 `get_session` 复用同一个 connection，`:memory:` 即可工作
    #[cfg(feature = "db-sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn social_binding_service_find_or_create_creates_new_binding() {
        use super::*;
        use crate::dao::{tests::MockDao, BulwarkMigration};
        use dbnexus::{DbConfig, DbPool};
        use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
        use std::path::PathBuf;
        use std::sync::Arc;

        // 1. 初始化 SQLite 单连接内存数据库 + 迁移
        //    用 DbPool::with_config 而非 init_dbnexus，强制 max/min_connections=1
        //    避免 :memory: 的 per-connection 独立内存数据库问题
        let config = DbConfig {
            url: "sqlite::memory:".to_string(),
            max_connections: 1,
            min_connections: 1,
            ..Default::default()
        };
        let pool = DbPool::with_config(config)
            .await
            .expect("DbPool::with_config 应成功");
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 应可用");
        let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");
        let migration = BulwarkMigration::with_base_dir(pool, base_dir);
        migration.migrate_core().await.expect("migrate_core 应成功");
        let pool = migration.pool().clone();

        // 2. 构造 SocialBindingService（Decision Matrix 方案 A：pool + dao）
        let dao: Arc<dyn crate::dao::BulwarkDao> = Arc::new(MockDao::new());
        let svc = SocialBindingService::new(pool.clone(), dao);

        // 3. 构造 SocialUserInfo（模拟微信登录返回）
        let user = SocialUserInfo {
            provider: SocialProvider::Wechat,
            provider_user_id: "openid1".into(),
            nickname: None,
            avatar: None,
            union_id: Some("union1".into()),
            raw: serde_json::json!({}),
        };

        // 4. 调用 find_or_create
        let login_id = svc
            .find_or_create(&user, 0)
            .await
            .expect("find_or_create 应返回 Ok");

        // 5. 断言返回新生成的 login_id（非空 UUID）
        assert!(
            !login_id.is_empty(),
            "find_or_create 应返回新生成的 login_id（非空 UUID），实际: {}",
            login_id
        );

        // 6. 查询 social_bindings 表，验证有 1 行记录
        //    用 {} 作用域限制 session 生命周期，确保 connection 在第二次 find_or_create 前归还
        {
            let session = pool.get_session("admin").await.unwrap();
            let conn = session.connection().unwrap();
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT login_id, provider, provider_user_id FROM social_bindings \
                 WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?",
                vec![
                    Value::BigInt(Some(0)),
                    Value::String(Some("wechat".into())),
                    Value::String(Some("openid1".into())),
                ],
            );
            let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
            assert_eq!(rows.len(), 1, "social_bindings 表应有 1 行记录");
            let row = &rows[0];
            let db_login_id: String = row
                .try_get::<String>("", "login_id")
                .expect("login_id 字段应可读");
            let db_provider: String = row
                .try_get::<String>("", "provider")
                .expect("provider 字段应可读");
            let db_provider_user_id: String = row
                .try_get::<String>("", "provider_user_id")
                .expect("provider_user_id 字段应可读");
            assert_eq!(db_login_id, login_id, "表中的 login_id 应与返回值一致");
            assert_eq!(db_provider, "wechat", "provider 应为 'wechat'");
            assert_eq!(
                db_provider_user_id, "openid1",
                "provider_user_id 应为 'openid1'"
            );
        } // session 在此 drop，connection 归还连接池

        // 7. 再次调用 find_or_create 应返回相同 login_id（幂等性，已有绑定）
        let login_id_again = svc
            .find_or_create(&user, 0)
            .await
            .expect("find_or_create 二次调用应返回 Ok");
        assert_eq!(
            login_id_again, login_id,
            "已存在的绑定应返回相同 login_id（幂等性）"
        );
    }

    // ========================================================================
    // T021: 社交登录异常消息 i18n（feature = "i18n"）
    //
    // 验证 wechat / alipay 的 loc! 宏在中英文 locale 下返回正确翻译。
    // 直接调用 loc! 宏避免依赖 HTTP mock，聚焦 i18n 翻译正确性。
    // ========================================================================

    /// T021 i18n 测试 1：zh locale 下 wechat-token-request-failed 返回中文消息。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_wechat_token_request_failed_zh() {
        use crate::i18n::{set_locale, BulwarkLocale};
        let _guard = set_locale(BulwarkLocale::Zh);
        let msg = crate::loc!(
            "wechat-token-request-failed",
            "wechat token request failed: conn refused".to_string(),
            ("detail", "conn refused")
        );
        assert_eq!(msg, "微信 token 请求失败: conn refused");
    }

    /// T021 i18n 测试 2：en locale 下 wechat-token-request-failed 返回英文消息。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_wechat_token_request_failed_en() {
        use crate::i18n::{set_locale, BulwarkLocale};
        let _guard = set_locale(BulwarkLocale::En);
        let msg = crate::loc!(
            "wechat-token-request-failed",
            "wechat token request failed: conn refused".to_string(),
            ("detail", "conn refused")
        );
        assert_eq!(msg, "WeChat token request failed: conn refused");
    }

    /// T021 i18n 测试 3：zh locale 下 wechat-error-response 带 code+message 参数返回中文。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_wechat_error_response_with_code_message_zh() {
        use crate::i18n::{set_locale, BulwarkLocale};
        let _guard = set_locale(BulwarkLocale::Zh);
        let msg = crate::loc!(
            "wechat-error-response",
            "wechat error 40029: invalid code".to_string(),
            ("code", "40029"),
            ("message", "invalid code")
        );
        assert_eq!(msg, "微信错误 40029: invalid code");
    }

    /// T021 i18n 测试 4：zh locale 下 alipay-rsa-key-parse-failed 返回中文消息。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_alipay_rsa_key_parse_failed_zh() {
        use crate::i18n::{set_locale, BulwarkLocale};
        let _guard = set_locale(BulwarkLocale::Zh);
        let msg = crate::loc!(
            "alipay-rsa-key-parse-failed",
            "alipay rsa key parse failed: bad pem".to_string(),
            ("detail", "bad pem")
        );
        assert_eq!(msg, "支付宝 RSA 私钥解析失败: bad pem");
    }

    /// T021 i18n 测试 5：en locale 下 alipay-rsa-key-parse-failed 返回英文消息。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_alipay_rsa_key_parse_failed_en() {
        use crate::i18n::{set_locale, BulwarkLocale};
        let _guard = set_locale(BulwarkLocale::En);
        let msg = crate::loc!(
            "alipay-rsa-key-parse-failed",
            "alipay rsa key parse failed: bad pem".to_string(),
            ("detail", "bad pem")
        );
        assert_eq!(msg, "Alipay RSA private key parse failed: bad pem");
    }
}
