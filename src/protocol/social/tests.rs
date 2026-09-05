//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SocialLoginProvider` / `SocialUserInfo` / `provider_names` 单元测试。

use super::*;

/// 验证 `SocialLoginProvider` trait 可被 mock 实现并调用三个方法
///
/// Red 阶段：`SocialLoginProvider` / `SocialUserInfo` 类型不存在 → 编译失败。
/// Green 阶段（T098）：定义完整类型后测试通过。
#[tokio::test]
async fn social_login_provider_trait_defines_three_methods() {
    use super::mock::MockSocialProvider;

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
    assert_eq!(user_info.provider, provider_names::WECHAT);
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

/// 验证 `provider_names` 常量与字符串值一一对应
#[test]
fn provider_names_constants_match_expected_strings() {
    assert_eq!(provider_names::WECHAT, "wechat");
    assert_eq!(provider_names::ALIPAY, "alipay");
    assert_eq!(provider_names::WECHAT_MINI_APP, "wechat_mini_app");

    // 验证三个常量互不相等
    assert_ne!(provider_names::WECHAT, provider_names::ALIPAY);
    assert_ne!(provider_names::WECHAT, provider_names::WECHAT_MINI_APP);
    assert_ne!(provider_names::ALIPAY, provider_names::WECHAT_MINI_APP);
}

// ========================================================================
// SQLite 迁移加载验证（feature = "db-sqlite"）
// ========================================================================

/// T106 Green: 验证 `migrations/sqlite/core/005_social_bindings.sql`
/// 被 `GarrisonMigration::migrate_core()` 加载后 `social_bindings` 表存在
///
/// 测试模式与 `role_hierarchy_table_exists_after_migration` 一致：
/// 1. `init_dbnexus("sqlite::memory:")` 创建内存 SQLite
/// 2. `GarrisonMigration::with_base_dir` 指向项目根目录 `migrations/sqlite/`
/// 3. `migrate_core()` 执行 `core/*.sql`（含 005_social_bindings.sql）
/// 4. 查询 `sqlite_master` 验证 `social_bindings` 表存在
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn social_bindings_table_exists_after_migration() {
    use crate::dao::{init_dbnexus, GarrisonMigration};
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use std::path::PathBuf;

    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 应可用");
    let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");
    let migration = GarrisonMigration::with_base_dir(pool, base_dir);
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
// T107-SocialBindingService Red-Green（feature = "db-sqlite"）
// ========================================================================

/// T107 Red: `SocialBindingService::find_or_create` 创建新绑定
///
/// Red 阶段：`SocialBindingService` 类型不存在 → 编译失败。
/// Green 阶段（T108）：定义 `SocialBindingService { dao }` + `find_or_create` 后测试通过。
///
/// # 测试流程
///
/// 1. 创建 SQLite in-memory DB + 迁移（含 005_social_bindings.sql）
/// 2. 构造 `SocialBindingService::new(dao)`（dao 为 `GarrisonDaoDbnexus`）
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
    use crate::dao::{tests::MockDao, GarrisonDaoDbnexus, GarrisonMigration};
    use dbnexus::{DbConfig, DbPool, PoolConfig};
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::path::PathBuf;
    use std::sync::Arc;

    // 1. 初始化 SQLite 单连接内存数据库 + 迁移
    //    用 DbPool::with_config 而非 init_dbnexus，强制 max/min_connections=1
    //    避免 :memory: 的 per-connection 独立内存数据库问题
    let config = DbConfig {
        url: "sqlite::memory:".to_string(),
        pool_config: PoolConfig {
            max_connections: 1,
            min_connections: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let pool = DbPool::with_config(config)
        .await
        .expect("DbPool::with_config 应成功");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 应可用");
    let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");
    let migration = GarrisonMigration::with_base_dir(pool, base_dir);
    migration.migrate_core().await.expect("migrate_core 应成功");
    let pool = migration.pool().clone();

    // 2. 构造 SocialBindingService（dao 为 GarrisonDaoDbnexus）
    let kv: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(GarrisonDaoDbnexus::new(pool.clone(), kv));
    let svc = SocialBindingService::new(dao);

    // 3. 构造 SocialUserInfo（模拟微信登录返回）
    let user = SocialUserInfo {
        provider: provider_names::WECHAT.to_string(),
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
// 社交登录异常消息 i18n（feature = "i18n"）
//
// 验证 wechat / alipay 的 loc! 宏在中英文 locale 下返回正确翻译。
// 直接调用 loc! 宏避免依赖 HTTP mock，聚焦 i18n 翻译正确性。
// ========================================================================

/// T021 i18n 测试 1：zh locale 下 wechat-token-request-failed 返回中文消息。
#[cfg(feature = "i18n")]
#[test]
fn loc_i18n_wechat_token_request_failed_zh() {
    use crate::i18n::{set_locale, GarrisonLocale};
    let _guard = set_locale(GarrisonLocale::Zh);
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
    use crate::i18n::{set_locale, GarrisonLocale};
    let _guard = set_locale(GarrisonLocale::En);
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
    use crate::i18n::{set_locale, GarrisonLocale};
    let _guard = set_locale(GarrisonLocale::Zh);
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
    use crate::i18n::{set_locale, GarrisonLocale};
    let _guard = set_locale(GarrisonLocale::Zh);
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
    use crate::i18n::{set_locale, GarrisonLocale};
    let _guard = set_locale(GarrisonLocale::En);
    let msg = crate::loc!(
        "alipay-rsa-key-parse-failed",
        "alipay rsa key parse failed: bad pem".to_string(),
        ("detail", "bad pem")
    );
    assert_eq!(msg, "Alipay RSA private key parse failed: bad pem");
}

// ========================================================================
// SocialUserInfo trait 行为测试
// ========================================================================

/// SocialUserInfo Debug trait 输出字段名与值。
#[test]
fn social_user_info_debug_trait_outputs_fields() {
    let user = SocialUserInfo {
        provider: provider_names::WECHAT.to_string(),
        provider_user_id: "openid123".to_string(),
        nickname: Some("Alice".to_string()),
        avatar: Some("https://img.example.com/a.png".to_string()),
        union_id: Some("union456".to_string()),
        raw: serde_json::json!({"key": "value"}),
    };
    let debug_str = format!("{:?}", user);
    assert!(debug_str.contains("SocialUserInfo"));
    assert!(debug_str.contains("wechat"));
    assert!(debug_str.contains("openid123"));
    assert!(debug_str.contains("Alice"));
    assert!(debug_str.contains("union456"));
}

/// SocialUserInfo Clone trait 深拷贝正确。
#[test]
fn social_user_info_clone_creates_independent_copy() {
    let original = SocialUserInfo {
        provider: provider_names::ALIPAY.to_string(),
        provider_user_id: "uid789".to_string(),
        nickname: Some("Bob".to_string()),
        avatar: None,
        union_id: None,
        raw: serde_json::json!({}),
    };
    let cloned = original.clone();
    assert_eq!(cloned.provider, original.provider);
    assert_eq!(cloned.provider_user_id, original.provider_user_id);
    assert_eq!(cloned.nickname, original.nickname);
    assert_eq!(cloned.avatar, original.avatar);
    assert_eq!(cloned.union_id, original.union_id);
}

/// SocialUserInfo 所有 Option 字段为 None 时不 panic。
#[test]
fn social_user_info_with_all_none_options() {
    let user = SocialUserInfo {
        provider: provider_names::WECHAT_MINI_APP.to_string(),
        provider_user_id: "mini_openid".to_string(),
        nickname: None,
        avatar: None,
        union_id: None,
        raw: serde_json::json!({}),
    };
    assert!(user.nickname.is_none());
    assert!(user.avatar.is_none());
    assert!(user.union_id.is_none());
}

// ========================================================================
// SocialBindingService::find_or_create 错误路径测试（ScriptedBindingDao）
//
// 覆盖：find/insert DAO 错误透传、UNIQUE 约束冲突（SQLite/Postgres/MySQL/
// SQLSTATE 23505 四种消息特征）回查已有绑定、回查缺失/失败的 fail-closed 分支。
// ========================================================================

/// 脚本化 DAO：`find_social_binding` / `insert_social_binding` 按预设结果队列
/// 依次返回（队列耗尽后 find 返回 Ok(None)、insert 返回 Ok(())），
/// 其余方法委托内存 [`MockDao`](crate::dao::tests::MockDao)。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
struct ScriptedBindingDao {
    inner: crate::dao::tests::MockDao,
    /// find_social_binding 预设结果队列。
    find_results: parking_lot::Mutex<Vec<GarrisonResult<Option<String>>>>,
    /// insert_social_binding 预设结果队列。
    insert_results: parking_lot::Mutex<Vec<GarrisonResult<()>>>,
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[async_trait]
impl crate::dao::GarrisonDao for ScriptedBindingDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        self.inner.set(key, value, ttl_seconds).await
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.inner.update(key, value).await
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        self.inner.expire(key, seconds).await
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.inner.delete(key).await
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.inner.set_if_absent(key, value, ttl_seconds).await
    }

    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        self.inner.rename(old_key, new_key).await
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.inner.get_and_delete(key).await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.inner
            .compare_and_swap(key, expected, new_value, ttl_seconds)
            .await
    }

    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        self.inner.incr(key, ttl_seconds).await
    }

    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        self.inner.decr(key).await
    }

    async fn find_social_binding(
        &self,
        _tenant_id: i64,
        _provider: &str,
        _provider_user_id: &str,
    ) -> GarrisonResult<Option<String>> {
        let mut queue = self.find_results.lock();
        if queue.is_empty() {
            Ok(None)
        } else {
            queue.remove(0)
        }
    }

    async fn insert_social_binding(
        &self,
        _tenant_id: i64,
        _login_id: &str,
        _provider: &str,
        _provider_user_id: &str,
        _union_id: Option<&str>,
        _created_at: i64,
    ) -> GarrisonResult<()> {
        let mut queue = self.insert_results.lock();
        if queue.is_empty() {
            Ok(())
        } else {
            queue.remove(0)
        }
    }
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
fn make_scripted_binding_service(
    find_results: Vec<GarrisonResult<Option<String>>>,
    insert_results: Vec<GarrisonResult<()>>,
) -> SocialBindingService {
    use std::sync::Arc;
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(ScriptedBindingDao {
        inner: crate::dao::tests::MockDao::new(),
        find_results: parking_lot::Mutex::new(find_results),
        insert_results: parking_lot::Mutex::new(insert_results),
    });
    SocialBindingService::new(dao)
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
fn scripted_wechat_user() -> SocialUserInfo {
    SocialUserInfo {
        provider: provider_names::WECHAT.to_string(),
        provider_user_id: "openid-conflict".into(),
        nickname: None,
        avatar: None,
        union_id: Some("union-conflict".into()),
        raw: serde_json::json!({}),
    }
}

/// find_social_binding 失败应透传 Dao 错误（不做 insert）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_propagates_find_error() {
    let svc = make_scripted_binding_service(
        vec![Err(crate::error::GarrisonError::Dao("find-down".into()))],
        vec![],
    );
    let result = svc.find_or_create(&scripted_wechat_user(), 0).await;
    assert!(
        matches!(&result, Err(crate::error::GarrisonError::Dao(msg)) if msg.contains("find-down")),
        "find 失败应透传 Dao 错误，实际: {:?}",
        result
    );
}

/// insert 失败且消息不含任何 UNIQUE 冲突特征时应原样透传错误（非并发冲突）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_insert_non_unique_error_propagates() {
    let svc = make_scripted_binding_service(
        vec![Ok(None)],
        vec![Err(crate::error::GarrisonError::Dao(
            "db-deadlock-detected".into(),
        ))],
    );
    let result = svc.find_or_create(&scripted_wechat_user(), 0).await;
    assert!(
        matches!(&result, Err(crate::error::GarrisonError::Dao(msg)) if msg.contains("db-deadlock-detected")),
        "非 UNIQUE 冲突的 insert 错误应原样透传，实际: {:?}",
        result
    );
}

/// SQLite UNIQUE 冲突消息（"UNIQUE constraint failed"）→ 回查返回已有 login_id。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_sqlite_unique_conflict_returns_existing() {
    let svc = make_scripted_binding_service(
        vec![Ok(None), Ok(Some("login-sqlite-existing".to_string()))],
        vec![Err(crate::error::GarrisonError::Dao(
            "UNIQUE constraint failed: social_bindings.tenant_id, \
             social_bindings.provider, social_bindings.provider_user_id"
                .into(),
        ))],
    );
    let login_id = svc
        .find_or_create(&scripted_wechat_user(), 0)
        .await
        .expect("并发 UNIQUE 冲突应回查成功");
    assert_eq!(login_id, "login-sqlite-existing", "应返回已有绑定 login_id");
}

/// PostgreSQL UNIQUE 冲突消息（"duplicate key value violates unique constraint"）
/// → 回查返回已有 login_id。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_postgres_unique_conflict_returns_existing() {
    let svc = make_scripted_binding_service(
        vec![Ok(None), Ok(Some("login-pg-existing".to_string()))],
        vec![Err(crate::error::GarrisonError::Dao(
            "duplicate key value violates unique constraint \
             \"social_bindings_uniq\""
                .into(),
        ))],
    );
    let login_id = svc
        .find_or_create(&scripted_wechat_user(), 0)
        .await
        .expect("并发 UNIQUE 冲突应回查成功");
    assert_eq!(login_id, "login-pg-existing");
}

/// MySQL UNIQUE 冲突消息（"Duplicate entry"）→ 回查返回已有 login_id。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_mysql_unique_conflict_returns_existing() {
    let svc = make_scripted_binding_service(
        vec![Ok(None), Ok(Some("login-mysql-existing".to_string()))],
        vec![Err(crate::error::GarrisonError::Dao(
            "Duplicate entry 'openid-conflict' for key 'social_bindings.UNIQ'".into(),
        ))],
    );
    let login_id = svc
        .find_or_create(&scripted_wechat_user(), 0)
        .await
        .expect("并发 UNIQUE 冲突应回查成功");
    assert_eq!(login_id, "login-mysql-existing");
}

/// SQLSTATE 23505 冲突消息 → 回查返回已有 login_id。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_sqlstate_23505_conflict_returns_existing() {
    let svc = make_scripted_binding_service(
        vec![Ok(None), Ok(Some("login-23505-existing".to_string()))],
        vec![Err(crate::error::GarrisonError::Dao(
            "db-unique-violation-sqlstate-23505".into(),
        ))],
    );
    let login_id = svc
        .find_or_create(&scripted_wechat_user(), 0)
        .await
        .expect("并发 UNIQUE 冲突应回查成功");
    assert_eq!(login_id, "login-23505-existing");
}

/// UNIQUE 冲突后回查仍无记录（并发事务已回滚）→ fail-closed 返回
/// `dao-social-binding-insert-select` Dao 错误。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_conflict_requery_missing_returns_dao_error() {
    use crate::error::GarrisonError;
    let svc = make_scripted_binding_service(
        vec![Ok(None), Ok(None)],
        vec![Err(GarrisonError::Dao(
            "UNIQUE constraint failed: social_bindings.tenant_id".into(),
        ))],
    );
    let result = svc.find_or_create(&scripted_wechat_user(), 0).await;
    assert!(
        matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("dao-social-binding-insert-select")),
        "回查缺失应返回 dao-social-binding-insert-select 错误，实际: {:?}",
        result
    );
}

/// UNIQUE 冲突后回查本身失败 → 透传回查错误。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn find_or_create_conflict_requery_error_propagates() {
    use crate::error::GarrisonError;
    let svc = make_scripted_binding_service(
        vec![Ok(None), Err(GarrisonError::Dao("requery-down".into()))],
        vec![Err(GarrisonError::Dao(
            "UNIQUE constraint failed: social_bindings.tenant_id".into(),
        ))],
    );
    let result = svc.find_or_create(&scripted_wechat_user(), 0).await;
    assert!(
        matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("requery-down")),
        "回查失败应透传回查错误，实际: {:?}",
        result
    );
}
