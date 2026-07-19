//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::mock::MockDao;
use super::*;
use crate::core::token::UuidTokenStyle;
use crate::dao::BulwarkDao;
use async_trait::async_trait;
use std::time::Duration;

/// 辅助函数：创建 AuthLogicDefault 实例（使用 UuidTokenStyle + MockDao）。
/// 默认使用 DenyAllSwitchToGuard（L4 安全默认）。
fn make_auth_logic(timeout: u64, active_timeout: u64) -> AuthLogicDefault {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    AuthLogicDefault::new(session, token_handler, timeout as i64)
}

/// 辅助函数：创建 AuthLogicDefault 实例，注入 AllowAllSwitchToGuard（L4 测试用）。
/// 生产环境禁止使用此函数，应注入自定义权限 guard。
/// `#[allow(deprecated)]` 抑制 deprecated 警告（测试专用）。
#[allow(deprecated)]
fn make_auth_logic_allow_switch(timeout: u64, active_timeout: u64) -> AuthLogicDefault {
    make_auth_logic(timeout, active_timeout).with_switch_to_guard(Arc::new(AllowAllSwitchToGuard))
}

// ========================================================================
// login 测试
// ========================================================================

/// login 生成非空 token 并建立会话（spec Scenario）。
#[tokio::test]
async fn login_generates_token_and_session() {
    let auth = make_auth_logic(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    assert!(!token.is_empty());
    // is_login 应返回 true
    assert!(auth.is_login(&token).await.unwrap());
}

/// login 后 get_login_id 返回关联 ID（spec Scenario）。
#[tokio::test]
async fn login_associates_login_id() {
    let auth = make_auth_logic(3600, 86400);
    let token = auth.login("2002", None).await.unwrap();
    let login_id = auth.get_login_id(&token).await.unwrap();
    assert_eq!(login_id, Some("2002".to_string()));
}

/// login 多次生成不同 token。
#[tokio::test]
async fn login_generates_unique_tokens() {
    let auth = make_auth_logic(3600, 86400);
    let t1 = auth.login("1001", None).await.unwrap();
    let t2 = auth.login("1001", None).await.unwrap();
    assert_ne!(t1, t2);
}

// ========================================================================
// logout 测试
// ========================================================================

/// logout 销毁指定 token 会话（spec Scenario）。
#[tokio::test]
async fn logout_destroys_session() {
    let auth = make_auth_logic(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    assert!(auth.is_login(&token).await.unwrap());
    auth.logout(&token).await.unwrap();
    assert!(!auth.is_login(&token).await.unwrap());
}

/// logout 幂等处理无效 token（spec Scenario）。
#[tokio::test]
async fn logout_idempotent_for_invalid_token() {
    let auth = make_auth_logic(3600, 86400);
    // 不存在的 token 应返回 Ok(())
    let result = auth.logout("non-existent-token").await;
    assert!(result.is_ok());
}

/// logout 不影响同账号的其他 token（spec Scenario）。
#[tokio::test]
async fn logout_preserves_other_tokens() {
    let auth = make_auth_logic(3600, 86400);
    let t1 = auth.login("1001", None).await.unwrap();
    let t2 = auth.login("1001", None).await.unwrap();
    auth.logout(&t1).await.unwrap();
    // t2 仍应有效
    assert!(auth.is_login(&t2).await.unwrap());
    assert!(!auth.is_login(&t1).await.unwrap());
}

// ========================================================================
// is_login 测试
// ========================================================================

/// is_login 有效 token 返回 true（spec Scenario）。
#[tokio::test]
async fn is_login_valid_token_returns_true() {
    let auth = make_auth_logic(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    assert!(auth.is_login(&token).await.unwrap());
}

/// is_login 无效 token 返回 false（spec Scenario）。
#[tokio::test]
async fn is_login_invalid_token_returns_false() {
    let auth = make_auth_logic(3600, 86400);
    assert!(!auth.is_login("invalid-token").await.unwrap());
}

// ========================================================================
// get_login_id 测试
// ========================================================================

/// get_login_id 有效 token 返回 Some(id)（spec Scenario）。
#[tokio::test]
async fn get_login_id_valid_token_returns_some() {
    let auth = make_auth_logic(3600, 86400);
    let token = auth.login("3003", None).await.unwrap();
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("3003".to_string())
    );
}

/// get_login_id 无效 token 返回 None（spec Scenario）。
#[tokio::test]
async fn get_login_id_invalid_token_returns_none() {
    let auth = make_auth_logic(3600, 86400);
    assert_eq!(auth.get_login_id("invalid").await.unwrap(), None);
}

// ========================================================================
// verify_token 测试
// ========================================================================

/// verify_token 有效 token 返回 login_id（spec Scenario）。
#[tokio::test]
async fn verify_token_valid_returns_login_id() {
    let auth = make_auth_logic(3600, 86400);
    let token = auth.login("4004", None).await.unwrap();
    assert_eq!(auth.verify_token(&token).await.unwrap(), "4004".to_string());
}

/// verify_token 无效 token 返回 InvalidToken 错误（spec Scenario）。
#[tokio::test]
async fn verify_token_invalid_returns_error() {
    let auth = make_auth_logic(3600, 86400);
    let result = auth.verify_token("invalid-token").await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// verify_token 已过期 token 返回错误（spec Scenario）。
#[tokio::test]
async fn verify_token_expired_returns_error() {
    let auth = make_auth_logic(1, 1);
    let token = auth.login("5005", None).await.unwrap();
    // 等待 token 过期（timeout=1s + active_timeout=1s）
    tokio::time::sleep(Duration::from_secs(2)).await;
    let result = auth.verify_token(&token).await;
    assert!(result.is_err());
}

// ========================================================================
// switch_to 测试
// ========================================================================

/// R-001: switch_to 更新 login_id 并存储 switched_from（使用 AllowAll guard）。
#[tokio::test]
async fn switch_to_updates_login_id_and_stores_switched_from() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // ensure_token_in_account_session 拒绝创建新 Account-Session，
    // 需预先 login target 以确保其 Account-Session 存在。
    let _ = auth.login("2002", None).await.unwrap();
    auth.switch_to(&token, "2002").await.unwrap();
    // get_login_id 应返回新的 login_id
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("2002".to_string())
    );
    // attrs["switched_from"] 应存储原始 login_id
    let switched_from = auth.session.get(&token, "switched_from").await.unwrap();
    assert_eq!(switched_from, Some("1001".to_string()));
}

/// R-001: switch_to 后 token 仍然有效（is_login 返回 true）。
#[tokio::test]
async fn switch_to_preserves_token_validity() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // 需预先创建 target Account-Session。
    let _ = auth.login("2002", None).await.unwrap();
    auth.switch_to(&token, "2002").await.unwrap();
    assert!(auth.is_login(&token).await.unwrap());
}

/// R-001: switch_to 无效 token 返回 NotLogin 错误。
#[tokio::test]
async fn switch_to_invalid_token_returns_not_login() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let result = auth.switch_to("invalid-token", "2002").await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "无效 token 应返回 NotLogin，实际: {:?}",
        result
    );
}

/// R-001: switch_to 空 target_login_id 返回 InvalidParam 错误。
#[tokio::test]
async fn switch_to_empty_target_returns_invalid_param() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    let result = auth.switch_to(&token, "").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(_))),
        "空 target_login_id 应返回 InvalidParam，实际: {:?}",
        result
    );
}

/// R-001: switch_to 后 verify_token 返回新的 login_id。
#[tokio::test]
async fn switch_to_verify_token_returns_new_login_id() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // 需预先创建 target Account-Session。
    let _ = auth.login("9999", None).await.unwrap();
    auth.switch_to(&token, "9999").await.unwrap();
    assert_eq!(auth.verify_token(&token).await.unwrap(), "9999");
}

/// R-001: switch_to 多次切换，switched_from 记录最近一次的原始 login_id。
#[tokio::test]
async fn switch_to_multiple_times_updates_switched_from() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // 需预先创建 target Account-Session（2002 + 3003）。
    let _ = auth.login("2002", None).await.unwrap();
    let _ = auth.login("3003", None).await.unwrap();
    // 第一次切换：1001 -> 2002
    auth.switch_to(&token, "2002").await.unwrap();
    assert_eq!(
        auth.session.get(&token, "switched_from").await.unwrap(),
        Some("1001".to_string())
    );
    // 第二次切换：2002 -> 3003
    auth.switch_to(&token, "3003").await.unwrap();
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("3003".to_string())
    );
    // switched_from 应记录最近一次切换前的 login_id（2002）
    assert_eq!(
        auth.session.get(&token, "switched_from").await.unwrap(),
        Some("2002".to_string())
    );
}

/// R-001: switch_to 保留 TokenSession 的其他 attrs（不丢失已有属性）。
#[tokio::test]
async fn switch_to_preserves_existing_attrs() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // 需预先创建 target Account-Session。
    let _ = auth.login("2002", None).await.unwrap();
    // 设置一个自定义 attr
    auth.session.set(&token, "device", "web").await.unwrap();
    // 执行 switch_to
    auth.switch_to(&token, "2002").await.unwrap();
    // 原有 attr 应保留
    let device = auth.session.get(&token, "device").await.unwrap();
    assert_eq!(device, Some("web".to_string()));
    // switched_from 应也存在
    let switched_from = auth.session.get(&token, "switched_from").await.unwrap();
    assert_eq!(switched_from, Some("1001".to_string()));
}

// ========================================================================
// H1 修复测试：switch_to 必须从 original Account-Session 中移除 token
//（数据一致性：避免 list_devices(original) 误返回已切换 token，
// 避免 logout_by_login_id(original) 误杀已切到 target 的 token，
// 避免 enforce_max_login_count(original) 误算已切换 token）
// ========================================================================

/// H1: switch_to 后，original login_id 的 AccountSession.tokens 不应再包含该 token。
///
/// 复现：login("1001") 创建 token；login("2002") 预创建 target Account-Session；
/// switch_to(token, "2002") 后，原 1001 的 AccountSession.tokens 应不再含 token。
#[tokio::test]
async fn switch_to_removes_token_from_original_account_session() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    let _ = auth.login("2002", None).await.unwrap();

    // 切换前：original AccountSession 应包含 token
    let original_before = auth
        .session
        .get_account_session("1001")
        .await
        .unwrap()
        .expect("切换前 original AccountSession 应存在");
    assert!(
        original_before.tokens.iter().any(|ti| ti.token == token),
        "切换前 original AccountSession 应包含该 token"
    );

    // 执行 switch_to
    auth.switch_to(&token, "2002").await.unwrap();

    // 切换后：original AccountSession 不应再包含 token
    let original_after = auth
        .session
        .get_account_session("1001")
        .await
        .unwrap()
        .expect("切换后 original AccountSession 应仍存在");
    assert!(
        !original_after.tokens.iter().any(|ti| ti.token == token),
        "切换后 original AccountSession 不应再包含该 token（H1 数据一致性），实际 tokens: {:?}",
        original_after.tokens
    );

    // 同时：target AccountSession 应包含 token
    let target_after = auth
        .session
        .get_account_session("2002")
        .await
        .unwrap()
        .expect("切换后 target AccountSession 应存在");
    assert!(
        target_after.tokens.iter().any(|ti| ti.token == token),
        "切换后 target AccountSession 应包含该 token，实际 tokens: {:?}",
        target_after.tokens
    );
}

/// H1: switch_to 后，内存 login_token_map 也应从 original 移除该 token。
///
/// `list_devices(original)` 通过 `get_tokens_by_login_id` 读内存索引，
/// 若内存索引未同步移除，会导致 list_devices 误返回已切换的 token。
#[tokio::test]
async fn switch_to_removes_token_from_original_login_token_map() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    let _ = auth.login("2002", None).await.unwrap();

    // 切换前：original 内存索引应包含 token
    let tokens_before: Vec<String> = auth.session.get_tokens_by_login_id("1001");
    assert!(
        tokens_before.iter().any(|t| t == &token),
        "切换前 original 内存索引应包含该 token"
    );

    auth.switch_to(&token, "2002").await.unwrap();

    // 切换后：original 内存索引不应再包含 token
    let tokens_after: Vec<String> = auth.session.get_tokens_by_login_id("1001");
    assert!(
        !tokens_after.iter().any(|t| t == &token),
        "切换后 original 内存索引不应再包含该 token（H1 内存索引一致性），实际: {:?}",
        tokens_after
    );

    // target 内存索引应包含 token
    let target_tokens: Vec<String> = auth.session.get_tokens_by_login_id("2002");
    assert!(
        target_tokens.iter().any(|t| t == &token),
        "切换后 target 内存索引应包含该 token，实际: {:?}",
        target_tokens
    );
}

/// R-001: switch_to 默认实现返回 NotImplemented。
#[tokio::test]
async fn switch_to_default_impl_returns_not_implemented() {
    struct NoSwitchAuth;
    #[async_trait]
    impl AuthLogic for NoSwitchAuth {
        async fn login(&self, _id: &str, _params: Option<&str>) -> BulwarkResult<String> {
            Ok("token".to_string())
        }
        async fn logout(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn is_login(&self, _token: &str) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self, _token: &str) -> BulwarkResult<Option<String>> {
            Ok(Some("id".to_string()))
        }
        async fn verify_token(&self, _token: &str) -> BulwarkResult<String> {
            Ok("id".to_string())
        }
    }
    let auth = NoSwitchAuth;
    let result = auth.switch_to("token", "target").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "默认实现应返回 NotImplemented，实际: {:?}",
        result
    );
}

// ========================================================================
// L4 新增：switch_to 权限校验测试（依据安全审计 L4）
// ========================================================================

/// L4: 默认 DenyAllSwitchToGuard 应拒绝所有 switch_to 调用（fail-closed）。
#[tokio::test]
async fn switch_to_default_guard_denies_all_switches() {
    let auth = make_auth_logic(3600, 86400); // 默认 DenyAllSwitchToGuard
    let token = auth.login("1001", None).await.unwrap();
    // A6: 需预先创建 target Account-Session，否则 target_account_exists 校验先返回 InvalidParam
    let _ = auth.login("2002", None).await.unwrap();
    let result = auth.switch_to(&token, "2002").await;
    assert!(
        matches!(result, Err(BulwarkError::NotPermission(ref msg)) if msg.contains("deny-all")),
        "默认 guard 应拒绝切换并返回 NotPermission，实际: {:?}",
        result
    );
    // 验证 session 未被修改（login_id 仍为原值）
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("1001".to_string())
    );
}

/// L4: 自定义 guard 拒绝时返回 NotPermission 且不修改 session。
#[tokio::test]
async fn switch_to_custom_guard_denies_preserves_session() {
    struct DenyTargetGuard;
    #[async_trait]
    impl SwitchToGuard for DenyTargetGuard {
        async fn check(&self, _original: &str, target: &str) -> BulwarkResult<()> {
            if target == "admin" {
                return Err(BulwarkError::NotPermission(format!(
                    "禁止切换到管理员身份: {}",
                    target
                )));
            }
            Ok(())
        }
    }
    let auth = make_auth_logic(3600, 86400).with_switch_to_guard(Arc::new(DenyTargetGuard));
    let token = auth.login("1001", None).await.unwrap();
    // 需预先创建 target Account-Session（user-2002 + admin）。
    let _ = auth.login("user-2002", None).await.unwrap();
    // A6: admin 也需预先创建 Account-Session，否则 target_account_exists 校验先返回 InvalidParam
    let _ = auth.login("admin", None).await.unwrap();

    // 切换到 admin 应被拒绝
    let result = auth.switch_to(&token, "admin").await;
    assert!(
        matches!(result, Err(BulwarkError::NotPermission(ref msg)) if msg.contains("禁止切换")),
        "切换到 admin 应被拒绝，实际: {:?}",
        result
    );
    // session 未被修改
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("1001".to_string())
    );

    // 切换到 普通用户 应成功
    auth.switch_to(&token, "user-2002").await.unwrap();
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("user-2002".to_string())
    );
}

// ========================================================================
// A6 新增：target_account_exists 校验测试
// ========================================================================

/// A6: switch_to 切换到不存在的 target_login_id 应返回 InvalidParam。
///
/// target_account_exists 校验在 guard 检查前执行，确保不会执行到后续步骤
/// （如修改 session、调用 ensure_token_in_account_session）。
#[tokio::test]
async fn switch_to_nonexistent_target_returns_invalid_param() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // 不创建 "ghost-user" 的 Account-Session
    let result = auth.switch_to(&token, "ghost-user").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg.contains("core-auth-target-login-id-not-found")),
        "切换到不存在的 target 应返回 InvalidParam，实际: {:?}",
        result
    );
    // session 未被修改
    assert_eq!(
        auth.get_login_id(&token).await.unwrap(),
        Some("1001".to_string())
    );
}

/// A6: target_account_exists 校验在 guard 之前执行（target 不存在时优先返回 InvalidParam）。
///
/// 即使 guard 是 AllowAllSwitchToGuard，target 不存在仍应被拒绝。
#[tokio::test]
async fn switch_to_target_check_precedes_guard() {
    let auth = make_auth_logic_allow_switch(3600, 86400);
    let token = auth.login("1001", None).await.unwrap();
    // 不创建 "ghost" 的 Account-Session
    let result = auth.switch_to(&token, "ghost").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(_))),
        "target 不存在时应先返回 InvalidParam（而非 guard 的 NotPermission），实际: {:?}",
        result
    );
}

// ========================================================================
// renew_to_equivalent 测试
// ========================================================================

/// R-003: renew_to_equivalent 返回新 token，新 token 有效且 login_id 相同。
#[tokio::test]
async fn renew_to_equivalent_returns_new_valid_token_with_same_login_id() {
    let auth = make_auth_logic(3600, 86400);
    let old_token = auth.login("1001", None).await.unwrap();
    let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
    // 新 token 非空
    assert!(!new_token.is_empty());
    // 新 token 有效
    assert!(auth.is_login(&new_token).await.unwrap());
    // login_id 相同
    assert_eq!(
        auth.get_login_id(&new_token).await.unwrap(),
        Some("1001".to_string())
    );
}

/// R-003: renew_to_equivalent 生成与旧 token 不同的字符串。
#[tokio::test]
async fn renew_to_equivalent_generates_different_token_string() {
    let auth = make_auth_logic(3600, 86400);
    let old_token = auth.login("1001", None).await.unwrap();
    let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
    assert_ne!(old_token, new_token);
}

/// R-004: renew_to_equivalent 后旧 token 失效（session 已删除）。
#[tokio::test]
async fn renew_to_equivalent_invalidates_old_token() {
    let auth = make_auth_logic(3600, 86400);
    let old_token = auth.login("1001", None).await.unwrap();
    assert!(auth.is_login(&old_token).await.unwrap());
    let _new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
    // 旧 token 应已失效
    assert!(!auth.is_login(&old_token).await.unwrap());
}

/// R-003: renew_to_equivalent 保留旧 session 的 attrs。
#[tokio::test]
async fn renew_to_equivalent_preserves_attrs() {
    let auth = make_auth_logic(3600, 86400);
    let old_token = auth.login("1001", None).await.unwrap();
    // 设置自定义 attr
    auth.session
        .set(&old_token, "device", "web-chrome")
        .await
        .unwrap();
    auth.session.set(&old_token, "role", "admin").await.unwrap();
    // 置换
    let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
    // 新 token 应保留 attrs
    let device = auth.session.get(&new_token, "device").await.unwrap();
    assert_eq!(device, Some("web-chrome".to_string()));
    let role = auth.session.get(&new_token, "role").await.unwrap();
    assert_eq!(role, Some("admin".to_string()));
}

/// R-003: renew_to_equivalent 保留旧 session 的 device 字段。
#[tokio::test]
async fn renew_to_equivalent_preserves_device() {
    let auth = make_auth_logic(3600, 86400);
    let old_token = auth.login("1001", None).await.unwrap();
    // 设置 device
    auth.session
        .set_device(&old_token, "mobile-ios")
        .await
        .unwrap();
    // 置换
    let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
    // 新 token 应保留 device
    let ts = auth.session.get_token_session(&new_token).await.unwrap();
    assert!(ts.is_some(), "新 token session 应存在");
    assert_eq!(ts.unwrap().device, Some("mobile-ios".to_string()));
}

/// R-003: renew_to_equivalent 无效 token 返回 NotLogin 错误。
#[tokio::test]
async fn renew_to_equivalent_invalid_token_returns_not_login() {
    let auth = make_auth_logic(3600, 86400);
    let result = auth.renew_to_equivalent("invalid-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "无效 token 应返回 NotLogin，实际: {:?}",
        result
    );
}

/// R-003: renew_to_equivalent 继承剩余 TTL（不重置为原始 timeout）。
#[tokio::test]
async fn renew_to_equivalent_preserves_remaining_ttl() {
    // 手动构建 auth + dao，以便直接操作 DAO 的 TTL
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao.clone(), 3600, 86400));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    let auth = AuthLogicDefault::new(session, token_handler, 3600);

    let old_token = auth.login("1001", None).await.unwrap();

    // 手动缩短旧 token 的 TTL 到 100s（模拟部分过期）
    let token_session_key = format!("token:session:{}", old_token);
    dao.expire(&token_session_key, 100).await.unwrap();

    // 验证旧 token 剩余 TTL ≈ 100s
    let old_ttl = auth.session.get_token_timeout(&old_token).await.unwrap();
    assert!(old_ttl.is_some(), "旧 token 应有 TTL");
    let old_secs = old_ttl.unwrap().as_secs();
    assert!(old_secs <= 100, "旧 TTL 应 ≤ 100s，实际: {}", old_secs);

    // 置换
    let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();

    // 新 token 的 TTL 应继承剩余 TTL（≈100s），而非重置为 3600s
    let new_ttl = auth.session.get_token_timeout(&new_token).await.unwrap();
    assert!(new_ttl.is_some(), "新 token 应有 TTL");
    let new_secs = new_ttl.unwrap().as_secs();
    assert!(
        new_secs <= 100,
        "新 TTL 应继承剩余 TTL (≤100s)，实际: {}（可能被重置为 3600s）",
        new_secs
    );
}

/// R-003: renew_to_equivalent 默认实现返回 NotImplemented。
#[tokio::test]
async fn renew_to_equivalent_default_impl_returns_not_implemented() {
    struct NoRenewAuth;
    #[async_trait]
    impl AuthLogic for NoRenewAuth {
        async fn login(&self, _id: &str, _params: Option<&str>) -> BulwarkResult<String> {
            Ok("token".to_string())
        }
        async fn logout(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn is_login(&self, _token: &str) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self, _token: &str) -> BulwarkResult<Option<String>> {
            Ok(Some("id".to_string()))
        }
        async fn verify_token(&self, _token: &str) -> BulwarkResult<String> {
            Ok("id".to_string())
        }
    }
    let auth = NoRenewAuth;
    let result = auth.renew_to_equivalent("token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "默认实现应返回 NotImplemented，实际: {:?}",
        result
    );
}

// ========================================================================
// A9: renew_to_equivalent 顺序测试（先创建新 token，再失效旧 token）
// ========================================================================
//
// 历史背景：原 VULN-0020 修复采用"先 delete 后 create"消除双 token 窗口。
// strix vuln-0003（CWE-362 / CVSS 7.5）发现此顺序在 delete 与 create 之间
// 存在 DoS gap window，用户在此窗口内无任何有效 token。
// A9 修复：调换为"先 create 后 delete"，消除 DoS gap；双 token 窗口缩短至
// 毫秒级（create 与 delete 之间），且旧 token 在 delete 成功后立即失效。

/// 追踪 DAO 操作顺序的 wrapper。
///
/// 包装 `MockDao`，记录 `set("token:session:{new}")` 与 `delete("token:session:{old}")`
/// 的相对顺序，用于验证 A9 不变量：**新 token 必须在旧 token 删除之前创建**。
struct OrderTrackingDao {
    inner: MockDao,
    tracking_state: std::sync::Mutex<OrderTrackingState>,
}

struct OrderTrackingState {
    /// 是否开始追踪（仅在 renew_to_equivalent 期间启用）。
    enabled: bool,
    /// 旧 token（用于检测 delete("token:session:{old_token}") 是否已调用）。
    old_token: String,
    /// 新 token session 是否已创建（set("token:session:{new}") 已调用）。
    /// 注意：追踪期间 new_token 未知，因此只要 set 任意 token:session:* 且
    /// key != old_token 即视为"新 token 已创建"。
    new_token_created: bool,
    /// 旧 token 的 session key 是否已被 delete。
    old_token_deleted: bool,
    /// 是否检测到 DoS gap 违规（delete(old) 在 set(new) 之前）。
    /// A9 不变量：此值应为 false（不允许 delete 先于 create）。
    dos_gap_violation: bool,
}

impl OrderTrackingDao {
    fn new() -> Self {
        Self {
            inner: MockDao::new(),
            tracking_state: std::sync::Mutex::new(OrderTrackingState {
                enabled: false,
                old_token: String::new(),
                new_token_created: false,
                old_token_deleted: false,
                dos_gap_violation: false,
            }),
        }
    }

    /// 开始追踪 renew 操作顺序（login 完成后调用）。
    fn start_tracking(&self, old_token: String) {
        let mut state = self.tracking_state.lock().unwrap();
        state.enabled = true;
        state.old_token = old_token;
        state.new_token_created = false;
        state.old_token_deleted = false;
        state.dos_gap_violation = false;
    }

    /// 是否检测到 DoS gap 违规（delete(old) 在 set(new) 之前）。
    /// A9 不变量：应为 false。
    fn was_dos_gap_violation(&self) -> bool {
        self.tracking_state.lock().unwrap().dos_gap_violation
    }

    /// 旧 token 是否最终被删除（清理完成）。
    fn was_old_token_deleted(&self) -> bool {
        self.tracking_state.lock().unwrap().old_token_deleted
    }
}

#[async_trait]
impl BulwarkDao for OrderTrackingDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
        // 若正在追踪且 key 是 token:session:*（非 old_token），
        // 标记新 token 已创建。
        {
            let mut state = self.tracking_state.lock().unwrap();
            if state.enabled
                && key.starts_with("token:session:")
                && key != format!("token:session:{}", state.old_token)
            {
                state.new_token_created = true;
            }
        }
        self.inner.set(key, value, ttl_seconds).await
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        self.inner.update(key, value).await
    }

    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
        self.inner.expire(key, seconds).await
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        // 标记旧 token 已被 delete；同时检测 DoS gap 违规
        // （delete(old) 在 set(new) 之前 = DoS gap）
        {
            let mut state = self.tracking_state.lock().unwrap();
            if state.enabled && key == format!("token:session:{}", state.old_token) {
                if !state.new_token_created {
                    // 旧 token 被删除时，新 token 尚未创建 → DoS gap 违规
                    state.dos_gap_violation = true;
                }
                state.old_token_deleted = true;
            }
        }
        self.inner.delete(key).await
    }

    async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
        self.inner.get_timeout(key).await
    }
}

/// A9: renew_to_equivalent 必须先创建新 token session，再失效旧 token session。
///
/// 顺序为"先 create 后 delete"，消除 DoS gap（vuln-0003 / CWE-362 / CVSS 7.5）。
/// 旧实现"先 delete 后 create"在 delete 与 create 之间存在窗口期，用户无任何有效 token。
#[tokio::test]
async fn a9_renew_to_equivalent_creates_new_before_deleting_old() {
    let tracking_dao = Arc::new(OrderTrackingDao::new());
    let session = Arc::new(BulwarkSession::new(
        tracking_dao.clone() as Arc<dyn BulwarkDao>,
        3600,
        86400,
    ));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    let auth = AuthLogicDefault::new(session, token_handler, 3600);

    let old_token = auth.login("1001", None).await.unwrap();

    // 开始追踪 renew 操作的顺序
    tracking_dao.start_tracking(old_token.clone());

    // renew_to_equivalent 应成功
    let new_token = auth.renew_to_equivalent(&old_token).await;
    assert!(
        new_token.is_ok(),
        "renew 应成功，实际: {:?}",
        new_token.err()
    );

    // A9 不变量 1：不允许 DoS gap（delete(old) 在 set(new) 之前）
    assert!(
        !tracking_dao.was_dos_gap_violation(),
        "A9 违规：旧 token 在新 token 创建前被删除（DoS gap window），\
         应先创建新 token 再删除旧 token"
    );

    // A9 不变量 2：旧 token 最终应被删除（清理完成，避免旧 token 永久残留）
    assert!(
        tracking_dao.was_old_token_deleted(),
        "A9 清理校验：旧 token session 应在 renew 完成后被删除"
    );
}

/// A9: renew_to_equivalent 期间旧 token 在新 token 创建时仍应有效（无 DoS gap）。
///
/// 模拟攻击者/用户在 renew 过程中并发使用旧 token：旧 token 在新 token 完全建立前
/// 不应被失效。此测试通过追踪 DAO 操作时序验证：set(new) 发生时 delete(old) 尚未执行。
#[tokio::test]
async fn a9_renew_to_equivalent_old_token_valid_until_new_created() {
    let tracking_dao = Arc::new(OrderTrackingDao::new());
    let session = Arc::new(BulwarkSession::new(
        tracking_dao.clone() as Arc<dyn BulwarkDao>,
        3600,
        86400,
    ));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    let auth = AuthLogicDefault::new(session, token_handler, 3600);

    let old_token = auth.login("1002", None).await.unwrap();
    tracking_dao.start_tracking(old_token.clone());

    // 执行 renew
    let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();

    // 验证：renew 成功后旧 token 失效，新 token 有效
    assert!(
        !auth.is_login(&old_token).await.unwrap(),
        "renew 后旧 token 应失效"
    );
    assert!(
        auth.is_login(&new_token).await.unwrap(),
        "renew 后新 token 应有效"
    );
    assert_eq!(
        auth.get_login_id(&new_token).await.unwrap(),
        Some("1002".to_string()),
        "新 token 的 login_id 应与旧 token 相同"
    );

    // A9 核心校验：整个 renew 过程中无 DoS gap
    assert!(
        !tracking_dao.was_dos_gap_violation(),
        "A9 违规：renew 过程中存在 DoS gap（旧 token 先于新 token 创建被删除）"
    );
}

// ========================================================================
// remember_me 测试
// ========================================================================

/// 辅助函数：创建带 remember_me 配置的 AuthLogicDefault 实例。
fn make_auth_logic_with_remember_me(
    timeout: u64,
    active_timeout: u64,
    rm_enabled: bool,
    rm_timeout: i64,
) -> AuthLogicDefault {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    AuthLogicDefault::new(session, token_handler, timeout as i64)
        .with_remember_me(rm_enabled, rm_timeout)
}

/// R-005: login with remember_me=true 且 enabled 时使用扩展超时。
#[tokio::test]
async fn login_with_remember_me_true_uses_extended_timeout() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
    let token = auth.login("1001", Some("remember_me=true")).await.unwrap();
    // token 有效
    assert!(auth.is_login(&token).await.unwrap());
    // TTL 应接近 7776000s
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some(), "Token-Session 应有 TTL");
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs > 3_600 && secs <= 7_776_000,
        "remember_me TTL 应接近 7776000s，实际: {}s",
        secs
    );
}

/// R-005: login with remember_me=true 但 disabled 时使用默认超时。
#[tokio::test]
async fn login_with_remember_me_true_but_disabled_uses_default_timeout() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, false, 7_776_000);
    let token = auth.login("1001", Some("remember_me=true")).await.unwrap();
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some());
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs <= 3600,
        "disabled 时 TTL 应为默认 3600s，实际: {}s",
        secs
    );
}

/// R-005: login with remember_me=false 使用默认超时。
#[tokio::test]
async fn login_with_remember_me_false_uses_default_timeout() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
    let token = auth.login("1001", Some("remember_me=false")).await.unwrap();
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some());
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs <= 3600,
        "remember_me=false 时 TTL 应为默认 3600s，实际: {}s",
        secs
    );
}

/// R-005: login with None params 使用默认超时。
#[tokio::test]
async fn login_with_none_params_uses_default_timeout() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
    let token = auth.login("1001", None).await.unwrap();
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some());
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs <= 3600,
        "None params 时 TTL 应为默认 3600s，实际: {}s",
        secs
    );
}

/// R-005: login with empty params 使用默认超时。
#[tokio::test]
async fn login_with_empty_params_uses_default_timeout() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
    let token = auth.login("1001", Some("")).await.unwrap();
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some());
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs <= 3600,
        "empty params 时 TTL 应为默认 3600s，实际: {}s",
        secs
    );
}

/// R-005: login with remember_me=true 与其他参数组合仍检测到 remember_me。
#[tokio::test]
async fn login_with_remember_me_and_other_params() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
    let token = auth
        .login("1001", Some("remember_me=true&device=web"))
        .await
        .unwrap();
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some());
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs > 3_600 && secs <= 7_776_000,
        "组合参数中 remember_me=true 应使用扩展 TTL，实际: {}s",
        secs
    );
}

/// R-005: login with malformed params 使用默认超时（容错）。
#[tokio::test]
async fn login_with_malformed_params_uses_default_timeout() {
    let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
    let token = auth.login("1001", Some("malformed")).await.unwrap();
    let ttl = auth.session.get_token_timeout(&token).await.unwrap();
    assert!(ttl.is_some());
    let secs = ttl.unwrap().as_secs();
    assert!(
        secs <= 3600,
        "malformed params 时 TTL 应为默认 3600s，实际: {}s",
        secs
    );
}

/// R-005: parse_remember_me_param 各种输入解析正确。
#[test]
fn parse_remember_me_param_various_inputs() {
    assert!(parse_remember_me_param(Some("remember_me=true")));
    assert!(!parse_remember_me_param(Some("remember_me=false")));
    assert!(parse_remember_me_param(Some("remember_me=true&device=web")));
    assert!(parse_remember_me_param(Some("device=web&remember_me=true")));
    assert!(!parse_remember_me_param(Some("")));
    assert!(!parse_remember_me_param(None));
    assert!(!parse_remember_me_param(Some("remember_me=1")));
    assert!(!parse_remember_me_param(Some("malformed")));
}

// ========================================================================
// renew_to_equivalent 并发串行化测试（fix-refresh-race-and-test-contracts）
// ========================================================================

/// T001: 并发 renew_to_equivalent 同一 token 必须串行化（修复 CWE-362 TOCTOU 竞态）。
///
/// spec R-refresh-token-001: 3 个并发 renew 同一 token，恰好 1 个 Ok + 2 个 Err。
///
/// **Red 阶段**：当前 src/ 无锁，3 个全部 Ok → 测试失败（success_count=3 ≠ 1）。
/// **Green 阶段**：实现 per-token 锁后，第 1 个拿到锁成功，第 2/3 个拿到锁时旧 token
/// 已失效 → 返回 NotLogin 错误 → 测试通过。
///
/// 用 `tokio::spawn` 创建独立 task 真正并行（`tokio::join!` 在当前 task 内顺序 poll
/// 无法触发竞态）。`Arc<AuthLogicDefault>` 跨 task 共享，`renew_to_equivalent(&self)`
/// 是 `&self` 方法可共享调用。
#[tokio::test(flavor = "multi_thread")]
async fn renew_to_equivalent_concurrent_serialization() {
    let auth = Arc::new(make_auth_logic(3600, 86400));
    let old_token = auth.login("race-user", None).await.unwrap();

    // 用 tokio::spawn 真正并行 3 个 renew task（multi_thread runtime worker 并行）
    let auth1 = auth.clone();
    let auth2 = auth.clone();
    let auth3 = auth.clone();
    let old1 = old_token.clone();
    let old2 = old_token.clone();
    let old3 = old_token.clone();
    let h1 = tokio::spawn(async move { auth1.renew_to_equivalent(&old1).await });
    let h2 = tokio::spawn(async move { auth2.renew_to_equivalent(&old2).await });
    let h3 = tokio::spawn(async move { auth3.renew_to_equivalent(&old3).await });

    let res1 = h1.await.expect("h1 join failed");
    let res2 = h2.await.expect("h2 join failed");
    let res3 = h3.await.expect("h3 join failed");

    let results = [res1, res2, res3];
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    let err_count = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(
        success_count, 1,
        "并发 renew 应恰好 1 个成功，实际 {} 个成功 — 揭示 CWE-362 TOCTOU 竞态未修复",
        success_count
    );
    assert_eq!(
        err_count, 2,
        "并发 renew 应 2 个失败，实际 {} 个失败",
        err_count
    );
}

/// HIGH-1 修复：renew 完成后 renew_locks DashMap 不残留无引用 entry。
///
/// 验证内存清理逻辑（`src/core/auth/default.rs:418-430`）：
/// - renew 流程结束后 `drop(_renew_guard); drop(renew_lock);` 释放 Arc clone
/// - `remove_if(token, |_, lock| Arc::strong_count(lock) == 1)` 移除无等待者的 entry
///
/// 攻击场景：若无清理，攻击者可发送大量不同随机 token 灌满 DashMap 导致 OOM
///（CWE-770）。此测试验证：单次 renew 成功后，对应 token 的 entry 已被清理。
#[tokio::test]
async fn renew_locks_entry_cleaned_after_successful_renew() {
    let auth = Arc::new(make_auth_logic(3600, 86400));
    let old_token = auth.login("cleanup-user", None).await.unwrap();

    // renew 前 renew_locks 应为空（无并发 renew 进行中）
    assert!(
        auth.renew_locks.is_empty(),
        "renew 前 renew_locks 应为空，实际有 {} 个 entry",
        auth.renew_locks.len()
    );

    // 执行单次 renew
    let new_token = auth
        .renew_to_equivalent(&old_token)
        .await
        .expect("renew 应成功");

    // renew 后 renew_locks 应再次为空（entry 已被清理）
    assert!(
        auth.renew_locks.is_empty(),
        "renew 后 renew_locks 应被清理为空，实际残留 {} 个 entry",
        auth.renew_locks.len()
    );

    // 验证 renew 本身成功：旧 token 失效，新 token 有效
    assert!(
        !auth.is_login(&old_token).await.unwrap(),
        "旧 token 应已失效"
    );
    assert!(auth.is_login(&new_token).await.unwrap(), "新 token 应有效");
}

/// HIGH-1 修复：renew 失败（NotLogin）后 renew_locks entry 也应被清理。
///
/// 验证失败路径同样清理 entry（避免失败 renew 累积导致 OOM）。
/// 此测试对同一无效 token 调用 renew 多次，每次失败后 entry 应被清理。
#[tokio::test]
async fn renew_locks_entry_cleaned_after_failed_renew() {
    let auth = Arc::new(make_auth_logic(3600, 86400));

    // 对不存在的 token 调用 renew（应返回 NotLogin）
    for i in 0..5 {
        let fake_token = format!("fake-token-{}", i);
        let result = auth.renew_to_equivalent(&fake_token).await;
        assert!(result.is_err(), "fake token renew 应失败（迭代 {}）", i);
        // 每次失败后 renew_locks 应为空（entry 已清理）
        assert!(
            auth.renew_locks.is_empty(),
            "失败 renew 后 renew_locks 应清理为空（迭代 {}），实际残留 {} 个 entry",
            i,
            auth.renew_locks.len()
        );
    }
}

/// HIGH-1 修复：并发 renew 完成后 renew_locks 不残留 entry。
///
/// 此测试与 `renew_to_equivalent_concurrent_serialization` 互补：
/// 后者验证并发下的串行化语义，此测试验证并发完成后的内存清理。
#[tokio::test(flavor = "multi_thread")]
async fn renew_locks_entry_cleaned_after_concurrent_renew() {
    let auth = Arc::new(make_auth_logic(3600, 86400));
    let old_token = auth.login("concurrent-cleanup-user", None).await.unwrap();

    // 并发 3 个 renew 同一 token
    let auth1 = auth.clone();
    let auth2 = auth.clone();
    let auth3 = auth.clone();
    let old1 = old_token.clone();
    let old2 = old_token.clone();
    let old3 = old_token.clone();
    let h1 = tokio::spawn(async move { auth1.renew_to_equivalent(&old1).await });
    let h2 = tokio::spawn(async move { auth2.renew_to_equivalent(&old2).await });
    let h3 = tokio::spawn(async move { auth3.renew_to_equivalent(&old3).await });

    // 等所有 task 完成
    let _ = h1.await.expect("h1 join failed");
    let _ = h2.await.expect("h2 join failed");
    let _ = h3.await.expect("h3 join failed");

    // 所有 task 完成后 renew_locks 应为空（所有 entry 已清理）
    assert!(
        auth.renew_locks.is_empty(),
        "并发 renew 全部完成后 renew_locks 应清理为空，实际残留 {} 个 entry",
        auth.renew_locks.len()
    );
}
