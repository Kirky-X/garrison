//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JWT 三模式集成测试（v0.4.2 新增，依据 spec protocol-jwt-modes）。
//!
//! 验证 `JwtHandler`（HS256/HS512 + refresh）+ `BulwarkLogicDefault` 三模式
//! （Stateless / Mixin / Simple）的端到端行为：
//! 1. `JwtHandler` HS256/HS512 sign → verify roundtrip
//! 2. `JwtHandler` refresh 产出新 token
//! 3. `JwtMode::Stateless`：仅 JWT verify，不查 session
//! 4. `JwtMode::Mixin`：JWT verify + session 二级校验
//! 5. `JwtMode::Simple`：仅 session 校验，不验证 JWT 签名
//! 6. 跨模式场景：Mixin 下 session 失效 → check_login 失败
//!
//! 运行：`cargo test --features "protocol-jwt cache-memory" --test jwt_modes_integration`

#![cfg(all(feature = "protocol-jwt", feature = "cache-memory"))]

use async_trait::async_trait;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::jwt::JwtHandler;
use bulwark::session::BulwarkSession;
use bulwark::stp::{
    with_current_token, BulwarkInterface, BulwarkLogicDefault, JwtMode, LoginParams, SessionLogic,
};
use jsonwebtoken::Algorithm;
use serial_test::serial;
use std::sync::Arc;

// ============================================================================
// MockInterface：BulwarkPermissionStrategyDefault::new() 必需
// ============================================================================

struct MockInterface;

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

// ============================================================================
// 辅助：构造带指定 JwtMode + token_style=jwt 的 BulwarkLogicDefault
// ============================================================================

async fn make_logic_with_mode(mode: JwtMode) -> Arc<BulwarkLogicDefault> {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = bulwark::config::BulwarkConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "jwt-modes-test-secret".to_string().into();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let firewall: Arc<dyn bulwark::strategy::BulwarkPermissionStrategy> = Arc::new(
        bulwark::strategy::BulwarkPermissionStrategyDefault::new(Arc::new(MockInterface)),
    );
    Arc::new(BulwarkLogicDefault::new(session, Arc::new(config), firewall).with_jwt_mode(mode))
}

// ============================================================================
// 1. JwtHandler 直接 API：HS256 / HS512 / refresh
// ============================================================================

/// HS256 sign → verify roundtrip：claims 字段一致。
#[tokio::test(flavor = "multi_thread")]
async fn hs256_sign_verify_roundtrip() {
    let handler = JwtHandler::new("hs256-secret");
    assert_eq!(handler.algorithm, Algorithm::HS256);

    let token = handler.sign("1001", 3600).expect("HS256 sign 应成功");
    assert!(token.contains('.'), "JWT 应为三段式：{}", token);

    let claims = handler.verify(&token).expect("HS256 verify 应成功");
    assert_eq!(claims.login_id, "1001".to_string());
    assert_eq!(claims.sub, "1001");
    assert!(claims.device.is_none(), "未设置 device 时应为 None");
}

/// HS512 sign → verify roundtrip。
#[tokio::test(flavor = "multi_thread")]
async fn hs512_sign_verify_roundtrip() {
    let handler = JwtHandler::new("hs512-secret").with_algorithm(Algorithm::HS512);
    assert_eq!(handler.algorithm, Algorithm::HS512);

    let token = handler.sign("2002", 7200).expect("HS512 sign 应成功");
    let claims = handler.verify(&token).expect("HS512 verify 应成功");
    assert_eq!(claims.login_id, "2002".to_string());
}

/// with_device 设置设备标识后 claims.device 为 Some。
#[tokio::test(flavor = "multi_thread")]
async fn with_device_sets_claims_device() {
    let handler = JwtHandler::new("device-secret").with_device("web-browser");
    let token = handler.sign("3003", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.device.as_deref(), Some("web-browser"));
}

/// 跨算法 verify 失败：HS256 签发的 token 不能被 HS512 handler 校验。
#[tokio::test(flavor = "multi_thread")]
async fn cross_algorithm_verify_fails() {
    let hs256 = JwtHandler::new("shared-secret");
    let hs512 = JwtHandler::new("shared-secret").with_algorithm(Algorithm::HS512);

    let token = hs256.sign("1001", 3600).unwrap();
    let result = hs512.verify(&token);
    assert!(result.is_err(), "HS256 token 不应被 HS512 handler 校验通过");
    match result.unwrap_err() {
        BulwarkError::InvalidToken(_) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// refresh 返回新 token 且可 verify，login_id 一致。
#[tokio::test(flavor = "multi_thread")]
async fn refresh_issues_new_valid_token() {
    let handler = JwtHandler::new("refresh-secret");
    let original = handler.sign("4004", 3600).unwrap();
    let refreshed = handler.refresh(&original, 7200).expect("refresh 应成功");
    let claims = handler.verify(&refreshed).unwrap();
    assert_eq!(
        claims.login_id,
        "4004".to_string(),
        "refresh 后 login_id 应一致"
    );
}

/// refresh 对无效 token 返回错误。
#[tokio::test(flavor = "multi_thread")]
async fn refresh_invalid_token_fails() {
    let handler = JwtHandler::new("refresh-secret");
    let result = handler.refresh("not.a.valid.jwt", 3600);
    assert!(result.is_err(), "无效 token refresh 应失败");
}

/// sign 对空 secret 返回 Config 错误。
#[tokio::test(flavor = "multi_thread")]
async fn sign_rejects_empty_secret() {
    let handler = JwtHandler::new("");
    let result = handler.sign("1001", 3600);
    assert!(result.is_err());
    match result.unwrap_err() {
        BulwarkError::Config(msg) => {
            assert!(
                msg.contains("secret"),
                "错误消息应提及 secret，实际: {}",
                msg
            );
        },
        other => panic!("期望 Config，实际: {:?}", other),
    }
}

/// sign 对负数 timeout 返回 Config 错误。
#[tokio::test(flavor = "multi_thread")]
async fn sign_rejects_negative_timeout() {
    let handler = JwtHandler::new("valid-secret");
    let result = handler.sign("1001", -1);
    assert!(result.is_err());
    match result.unwrap_err() {
        BulwarkError::Config(msg) => {
            assert!(
                msg.contains("timeout"),
                "错误消息应提及 timeout，实际: {}",
                msg
            );
        },
        other => panic!("期望 Config，实际: {:?}", other),
    }
}

// ============================================================================
// 2. JwtMode::Stateless：仅 JWT verify，不查 session
// ============================================================================

/// Stateless 模式下，用 JwtHandler 直接签发的 token（无 session）也能通过 check_login。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn stateless_mode_passes_with_jwt_only() {
    let logic = make_logic_with_mode(JwtMode::Stateless).await;

    // 用 JwtHandler 直接签发 token，不通过 login（确保无 session）
    let handler = JwtHandler::new("jwt-modes-test-secret");
    let token = handler.sign("5005", 3600).unwrap();

    // Stateless：仅 JWT verify，不查 session → 应通过
    let result = with_current_token(token, async { logic.check_login().await }).await;
    assert!(
        result.is_ok(),
        "Stateless 模式有效 JWT 应通过: {:?}",
        result.err()
    );
    assert!(result.unwrap(), "check_login 应返回 true");
}

/// Stateless 模式下，无效 JWT 被 check_login 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn stateless_mode_rejects_invalid_jwt() {
    let logic = make_logic_with_mode(JwtMode::Stateless).await;

    let result = with_current_token("invalid.jwt.token".to_string(), async {
        logic.check_login().await
    })
    .await;
    assert!(result.is_err(), "Stateless 模式无效 JWT 应被拒绝");
}

// ============================================================================
// 3. JwtMode::Mixin：JWT verify + session 二级校验
// ============================================================================

/// Mixin 模式：login 创建 session 后 check_login 通过。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mixin_mode_passes_with_jwt_and_session() {
    let logic = make_logic_with_mode(JwtMode::Mixin).await;

    let token = logic
        .login("6006", &LoginParams::default())
        .await
        .expect("login 应成功");
    let result = with_current_token(token, async { logic.check_login().await }).await;
    assert!(
        result.is_ok(),
        "Mixin 模式 login 后 check_login 应通过: {:?}",
        result.err()
    );
    assert!(result.unwrap(), "check_login 应返回 true");
}

/// Mixin 模式：仅 JWT 无 session 时 check_login 失败（session 二级校验）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mixin_mode_fails_with_jwt_only_no_session() {
    let logic = make_logic_with_mode(JwtMode::Mixin).await;

    // 用 JwtHandler 直接签发 token，不通过 login（无 session）
    let handler = JwtHandler::new("jwt-modes-test-secret");
    let token = handler.sign("7007", 3600).unwrap();

    let result = with_current_token(token, async { logic.check_login().await }).await;
    assert!(
        result.is_err(),
        "Mixin 模式仅 JWT 无 session 应失败（二级校验）"
    );
}

// ============================================================================
// 4. JwtMode::Simple：仅 session 校验，不验证 JWT 签名
// ============================================================================

/// Simple 模式：login 创建 session 后 check_login 通过（不验证 JWT 签名）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn simple_mode_passes_with_session_only() {
    // Simple 模式 token_style 可以是 uuid（不依赖 JWT）
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = bulwark::config::BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let firewall: Arc<dyn bulwark::strategy::BulwarkPermissionStrategy> = Arc::new(
        bulwark::strategy::BulwarkPermissionStrategyDefault::new(Arc::new(MockInterface)),
    );
    let logic = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_jwt_mode(JwtMode::Simple),
    );

    let token = logic
        .login("8008", &LoginParams::default())
        .await
        .expect("login 应成功");
    let result = with_current_token(token, async { logic.check_login().await }).await;
    assert!(
        result.is_ok(),
        "Simple 模式 login 后 check_login 应通过: {:?}",
        result.err()
    );
    assert!(result.unwrap(), "check_login 应返回 true");
}

/// Simple 模式：无 session 时 check_login 失败。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn simple_mode_fails_without_session() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = bulwark::config::BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let firewall: Arc<dyn bulwark::strategy::BulwarkPermissionStrategy> = Arc::new(
        bulwark::strategy::BulwarkPermissionStrategyDefault::new(Arc::new(MockInterface)),
    );
    let logic = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_jwt_mode(JwtMode::Simple),
    );

    // 直接用任意 token（无 session）
    let result = with_current_token("any-token-without-session".to_string(), async {
        logic.check_login().await
    })
    .await;
    assert!(result.is_err(), "Simple 模式无 session 应失败");
}

// ============================================================================
// 5. JwtMode::default() == Mixin（spec R-001）
// ============================================================================

/// JwtMode::default() 返回 Mixin（推荐模式为默认）。
#[test]
fn jwt_mode_default_is_mixin() {
    assert_eq!(JwtMode::default(), JwtMode::Mixin);
}

/// JwtMode 是 Copy（赋值后原值仍可用）。
#[test]
fn jwt_mode_is_copy() {
    let mode = JwtMode::Stateless;
    let copied = mode;
    assert_eq!(mode, copied);
    assert_eq!(mode, JwtMode::Stateless);
}
