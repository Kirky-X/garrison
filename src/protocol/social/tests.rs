// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `SocialLoginProvider` / `SocialUserInfo` / `provider_names` 单元测试。

use super::*;

#[tokio::test]
async fn social_login_provider_trait_defines_three_methods() {
    use super::mock::MockSocialProvider;

    let provider = MockSocialProvider;

    let auth_url = provider
        .get_authorization_url("state123", "https://example.com/cb")
        .await
        .expect("get_authorization_url 应返回 Ok");
    assert!(!auth_url.is_empty(), "授权 URL 不应为空");

    let user_info = provider
        .exchange_token("code456", "state123")
        .await
        .expect("exchange_token 应返回 Ok");
    assert_eq!(user_info.provider, provider_names::WECHAT);
    assert_eq!(user_info.provider_user_id, "mock_openid");
    assert_eq!(user_info.union_id.as_deref(), Some("mock_unionid"));

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

#[test]
fn provider_names_constants_match_expected_strings() {
    assert_eq!(provider_names::WECHAT, "wechat");
    assert_eq!(provider_names::ALIPAY, "alipay");
    assert_eq!(provider_names::WECHAT_MINI_APP, "wechat_mini_app");

    assert_ne!(provider_names::WECHAT, provider_names::ALIPAY);
    assert_ne!(provider_names::WECHAT, provider_names::WECHAT_MINI_APP);
    assert_ne!(provider_names::ALIPAY, provider_names::WECHAT_MINI_APP);
}

// SQLite 迁移加载验证（feature = "db-sqlite"）

/// 验证 `migrations/sqlite/core/005_social_bindings.sql` 经 `migrate_core()` 加载后 `social_bindings` 表存在。
///
/// 用 `DbPool::with_config` 强制单连接内存 SQLite：`:memory:` 每连接独立数据库，`init_dbnexus` 默认
/// `min_connections=5` 会让部分连接无表（flaky）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn social_bindings_table_exists_after_migration() {
    use crate::dao::GarrisonMigration;
    use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement};
    use dbnexus::{DbConfig, DbPool, PoolConfig};
    use std::path::PathBuf;

    // 单连接池强制所有 `get_session` 复用同一 connection，`:memory:` 才能工作
    //（与下方 `social_binding_service_find_or_create_creates_new_binding` 同配置）
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
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    // 至少 5 个迁移文件（001-005）
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

/// `find_or_create` 创建新绑定；用 `DbPool::with_config` 强制 `max/min_connections=1`——`:memory:` 每连接独立数据库，
/// 多连接会让第二次 `get_session` 拿到未迁移的新连接（dbnexus 默认 `min_connections=5`）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn social_binding_service_find_or_create_creates_new_binding() {
    use super::*;
    use crate::dao::{tests::MockDao, GarrisonDaoDbnexus, GarrisonMigration};
    use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use dbnexus::{DbConfig, DbPool, PoolConfig};
    use std::path::PathBuf;
    use std::sync::Arc;

    // 单连接池：:memory: 每连接独立库，必须复用同一 connection（与模块测试同配置）
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

    let kv: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(GarrisonDaoDbnexus::new(pool.clone(), kv));
    let svc = SocialBindingService::new(dao);

    let user = SocialUserInfo {
        provider: provider_names::WECHAT.to_string(),
        provider_user_id: "openid1".into(),
        nickname: None,
        avatar: None,
        union_id: Some("union1".into()),
        raw: serde_json::json!({}),
    };

    let login_id = svc
        .find_or_create(&user, 0)
        .await
        .expect("find_or_create 应返回 Ok");

    assert!(
        !login_id.is_empty(),
        "find_or_create 应返回新生成的 login_id（非空 UUID），实际: {}",
        login_id
    );

    // {} 作用域限制 session 生命周期：connection 在第二次 find_or_create 前归还单连接池
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

    let login_id_again = svc
        .find_or_create(&user, 0)
        .await
        .expect("find_or_create 二次调用应返回 Ok");
    assert_eq!(
        login_id_again, login_id,
        "已存在的绑定应返回相同 login_id（幂等性）"
    );
}

// 社交登录异常消息 i18n（feature = "i18n"）：wechat / alipay 的 loc! 宏中英文翻译

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

// SocialUserInfo trait 行为测试

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

// find_or_create 错误路径（ScriptedBindingDao）：DAO 错误透传、UNIQUE 冲突回查
// （SQLite/Postgres/MySQL/23505 四种消息特征）、回查缺失/失败的 fail-closed 分支

/// 脚本化 DAO：`find_social_binding` / `insert_social_binding` 按预设队列依次返回（耗尽后 find→Ok(None)、insert→Ok(())），
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

/// UNIQUE 冲突后回查无记录（并发事务已回滚）→ fail-closed 返回 `dao-social-binding-insert-select`。
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

// UNIQUE 冲突特征常量与 Debug 脱敏回归测试

/// 四个特征常量与冲突分支一一对应（防常量与匹配分支漂移；后端冲突用例从行为侧覆盖同一组常量）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[test]
fn unique_conflict_markers_match_service_constants() {
    use super::service::unique_conflict_markers as markers;
    use crate::error::GarrisonError;

    // 与 4 个后端冲突用例的消息逐字对应（单点维护防漂移）
    let cases = [
        (
            markers::SQLITE,
            "UNIQUE constraint failed: social_bindings.tenant_id",
        ),
        (
            markers::POSTGRES,
            "duplicate key value violates unique constraint \"social_bindings_uniq\"",
        ),
        (
            markers::MYSQL,
            "Duplicate entry 'openid-conflict' for key 'social_bindings.UNIQ'",
        ),
        (
            markers::SQLSTATE_UNIQUE,
            "db-unique-violation-sqlstate-23505",
        ),
    ];
    for (marker, message) in cases {
        assert!(
            message.contains(marker),
            "特征常量 {:?} 应命中对应后端冲突消息 {:?}",
            marker,
            message
        );
    }

    // 非冲突错误消息不命中任何特征（fail-closed 透传的前提）
    let non_conflict = GarrisonError::Dao("db-deadlock-detected".to_string()).to_string();
    assert!(
        !non_conflict.contains(markers::SQLITE)
            && !non_conflict.contains(markers::POSTGRES)
            && !non_conflict.contains(markers::MYSQL)
            && !non_conflict.contains(markers::SQLSTATE_UNIQUE),
        "非 UNIQUE 冲突错误不应命中任何特征常量，实际: {}",
        non_conflict
    );
}

/// Debug 脱敏 raw（不泄露第三方原始 JSON），其余字段正常输出，Clone 派生不受手动 Debug 影响。
#[test]
fn social_user_info_debug_redacts_raw_field() {
    let user = SocialUserInfo {
        provider: provider_names::WECHAT.to_string(),
        provider_user_id: "openid1".to_string(),
        nickname: Some("Alice".to_string()),
        avatar: None,
        union_id: None,
        raw: serde_json::json!({
            "access_token": "SECRET_TOKEN",
            "session_key": "SECRET_SESSION_KEY",
            "openid": "openid1"
        }),
    };

    let debug = format!("{:?}", user);
    assert!(
        debug.contains("SocialUserInfo"),
        "Debug 应保留类型名，实际: {}",
        debug
    );
    assert!(
        debug.contains("openid1"),
        "业务字段应正常输出，实际: {}",
        debug
    );
    assert!(
        debug.contains("<redacted"),
        "raw 应以 <redacted> 摘要输出，实际: {}",
        debug
    );
    assert!(
        !debug.contains("SECRET_TOKEN") && !debug.contains("SECRET_SESSION_KEY"),
        "Debug 不得泄露 raw 中的敏感凭据，实际: {}",
        debug
    );

    // 手动 Debug 不影响 Clone 派生
    let cloned = user.clone();
    assert_eq!(cloned.provider_user_id, "openid1");
    assert_eq!(cloned.raw, user.raw);
}
