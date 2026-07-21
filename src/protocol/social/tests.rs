//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SocialLoginProvider` / `SocialUserInfo` / `SocialProvider` 单元测试。

#[cfg(feature = "db-sqlite")]
use super::service::provider_to_str;
use super::*;

/// 验证 `SocialLoginProvider` trait 可被 mock 实现并调用三个方法
///
/// Red 阶段：`SocialLoginProvider` / `SocialUserInfo` / `SocialProvider` 类型不存在 → 编译失败。
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
    use crate::dao::{tests::MockDao, GarrisonMigration};
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
    let migration = GarrisonMigration::with_base_dir(pool, base_dir);
    migration.migrate_core().await.expect("migrate_core 应成功");
    let pool = migration.pool().clone();

    // 2. 构造 SocialBindingService（Decision Matrix 方案 A：pool + dao）
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
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
// SocialUserInfo / SocialProvider trait 行为测试
// ========================================================================

/// SocialUserInfo Debug trait 输出字段名与值。
#[test]
fn social_user_info_debug_trait_outputs_fields() {
    let user = SocialUserInfo {
        provider: SocialProvider::Wechat,
        provider_user_id: "openid123".to_string(),
        nickname: Some("Alice".to_string()),
        avatar: Some("https://img.example.com/a.png".to_string()),
        union_id: Some("union456".to_string()),
        raw: serde_json::json!({"key": "value"}),
    };
    let debug_str = format!("{:?}", user);
    assert!(debug_str.contains("SocialUserInfo"));
    assert!(debug_str.contains("Wechat"));
    assert!(debug_str.contains("openid123"));
    assert!(debug_str.contains("Alice"));
    assert!(debug_str.contains("union456"));
}

/// SocialUserInfo Clone trait 深拷贝正确。
#[test]
fn social_user_info_clone_creates_independent_copy() {
    let original = SocialUserInfo {
        provider: SocialProvider::Alipay,
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
        provider: SocialProvider::WechatMiniApp,
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

/// SocialProvider Clone trait 正确工作。
#[test]
fn social_provider_clone_works() {
    let wechat = SocialProvider::Wechat;
    let cloned = wechat.clone();
    assert_eq!(wechat, cloned);
}

/// SocialProvider Debug trait 输出变体名。
#[test]
fn social_provider_debug_outputs_variant_name() {
    let debug_wechat = format!("{:?}", SocialProvider::Wechat);
    assert!(debug_wechat.contains("Wechat"));

    let debug_alipay = format!("{:?}", SocialProvider::Alipay);
    assert!(debug_alipay.contains("Alipay"));

    let debug_mini = format!("{:?}", SocialProvider::WechatMiniApp);
    assert!(debug_mini.contains("WechatMiniApp"));
}

/// SocialProvider PartialEq 对相同和不同变体行为正确。
#[test]
fn social_provider_partial_eq_correct() {
    assert_eq!(SocialProvider::Wechat, SocialProvider::Wechat);
    assert_eq!(SocialProvider::Alipay, SocialProvider::Alipay);
    assert_eq!(SocialProvider::WechatMiniApp, SocialProvider::WechatMiniApp);
    assert_ne!(SocialProvider::Wechat, SocialProvider::Alipay);
    assert_ne!(SocialProvider::Wechat, SocialProvider::WechatMiniApp);
    assert_ne!(SocialProvider::Alipay, SocialProvider::WechatMiniApp);
}

/// provider_to_str 对所有 SocialProvider 变体返回正确字符串。
#[cfg(feature = "db-sqlite")]
#[test]
fn provider_to_str_all_variants_correct() {
    assert_eq!(provider_to_str(&SocialProvider::Wechat), "wechat");
    assert_eq!(provider_to_str(&SocialProvider::Alipay), "alipay");
    assert_eq!(
        provider_to_str(&SocialProvider::WechatMiniApp),
        "wechat_mini_app"
    );
}
