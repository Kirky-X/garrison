//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 权限校验层测试（从 mod.rs 迁移）。

use super::mock::MockInterface;
use super::*;

/// 创建 PermissionCheckerDefault 实例（账号 1001 持有 user:read/user:write 权限 + admin/user 角色）。
fn make_checker() -> PermissionCheckerDefault {
    let interface = MockInterface::new()
        .with_perms("1001", vec!["user:read", "user:write"])
        .with_roles("1001", vec!["admin", "user"]);
    let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
    PermissionCheckerDefault::new(interface_arc)
}

// ========================================================================
// has_permission 测试
// ========================================================================

/// has_permission 持有权限返回 true（spec Scenario）。
#[tokio::test]
async fn has_permission_held_returns_true() {
    let checker = make_checker();
    assert!(checker.has_permission("1001", "user:read").await.unwrap());
}

/// has_permission 未持有权限返回 false（spec Scenario）。
#[tokio::test]
async fn has_permission_not_held_returns_false() {
    let checker = make_checker();
    assert!(!checker.has_permission("1001", "user:delete").await.unwrap());
}

/// has_permission 空字符串返回错误（spec Scenario）。
#[tokio::test]
async fn has_permission_empty_string_returns_error() {
    let checker = make_checker();
    let result = checker.has_permission("1001", "").await;
    assert!(result.is_err());
}

// ========================================================================
// has_role 测试
// ========================================================================

/// has_role 持有角色返回 true（spec Scenario）。
#[tokio::test]
async fn has_role_held_returns_true() {
    let checker = make_checker();
    assert!(checker.has_role("1001", "admin").await.unwrap());
}

/// has_role 未持有角色返回 false（spec Scenario）。
#[tokio::test]
async fn has_role_not_held_returns_false() {
    let checker = make_checker();
    assert!(!checker.has_role("1001", "superadmin").await.unwrap());
}

// ========================================================================
// check_permission 测试
// ========================================================================

/// check_permission 持有权限返回 Ok(())（spec Scenario）。
#[tokio::test]
async fn check_permission_held_returns_ok() {
    let checker = make_checker();
    assert!(checker.check_permission("1001", "user:read").await.is_ok());
}

/// check_permission 未持有权限返回 NotPermission 错误（spec Scenario）。
#[tokio::test]
async fn check_permission_not_held_returns_error() {
    let checker = make_checker();
    let result = checker.check_permission("1001", "user:delete").await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::NotPermission(_)) => {},
        other => panic!("期望 NotPermission，实际: {:?}", other),
    }
}

// ========================================================================
// check_role 测试
// ========================================================================

/// check_role 持有角色返回 Ok(())。
#[tokio::test]
async fn check_role_held_returns_ok() {
    let checker = make_checker();
    assert!(checker.check_role("1001", "admin").await.is_ok());
}

/// check_role 未持有角色返回 NotRole 错误（spec Scenario）。
#[tokio::test]
async fn check_role_not_held_returns_error() {
    let checker = make_checker();
    let result = checker.check_role("1001", "superadmin").await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::NotRole(_)) => {},
        other => panic!("期望 NotRole，实际: {:?}", other),
    }
}

// ========================================================================
// has_any_permission 测试
// ========================================================================

/// has_any_permission 任一匹配返回 true（spec Scenario）。
#[tokio::test]
async fn has_any_permission_any_match_returns_true() {
    let checker = make_checker();
    assert!(
        checker
            .has_any_permission("1001", &["user:read", "user:delete"])
            .await
    );
}

/// has_any_permission 全不匹配返回 false（spec Scenario）。
#[tokio::test]
async fn has_any_permission_no_match_returns_false() {
    let checker = make_checker();
    assert!(
        !checker
            .has_any_permission("1001", &["user:delete", "user:create"])
            .await
    );
}

// ========================================================================
// has_all_permissions 测试
// ========================================================================

/// has_all_permissions 全部匹配返回 true（spec Scenario）。
#[tokio::test]
async fn has_all_permissions_all_match_returns_true() {
    let checker = make_checker();
    assert!(
        checker
            .has_all_permissions("1001", &["user:read", "user:write"])
            .await
    );
}

/// has_all_permissions 部分匹配返回 false（spec Scenario）。
#[tokio::test]
async fn has_all_permissions_partial_match_returns_false() {
    let checker = make_checker();
    assert!(
        !checker
            .has_all_permissions("1001", &["user:read", "user:delete"])
            .await
    );
}

/// has_all_permissions 空列表返回 true（vacuous truth）。
#[tokio::test]
async fn has_all_permissions_empty_list_returns_true() {
    let checker = make_checker();
    assert!(checker.has_all_permissions("1001", &[]).await);
}

// ========================================================================
// authorize 测试
// ========================================================================

/// authorize 在权限匹配时返回 allowed=true 的 Decision。
///
/// 验证 `authorize(&AuthRequest{ login_id: 1001, action: "user:read", .. })`
/// 返回 `Decision { allowed: true, reason: ExplicitAllow, .. }`。
#[tokio::test]
async fn authorize_returns_decision_with_allowed_true_when_permission_matches() {
    let checker = make_checker();
    let request = AuthRequest::new("1001", "user:read");
    let decision = PermissionChecker::authorize(&checker, &request)
        .await
        .expect("authorize ok");
    assert!(decision.allowed);
    assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
}

/// T015 补充: authorize 在权限不匹配时返回 allowed=false + NoMatchingPermission。
#[tokio::test]
async fn authorize_returns_deny_when_permission_not_matched() {
    let checker = make_checker();
    let request = AuthRequest::new("1001", "user:delete");
    let decision = PermissionChecker::authorize(&checker, &request)
        .await
        .expect("authorize ok");
    assert!(!decision.allowed);
    assert_eq!(decision.reason, DecisionReason::NoMatchingPermission);
}

/// T015 补充: authorize 在权限字符串为空时返回 InvalidParam 错误。
#[tokio::test]
async fn authorize_returns_error_for_empty_permission() {
    let checker = make_checker();
    let request = AuthRequest::new("1001", "");
    let result = PermissionChecker::authorize(&checker, &request).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
}

/// check_permission 与 authorize 行为一致（向后兼容）。
///
/// 验证 `check_permission(login_id, perm)` 的返回值（Ok/Err）与
/// `authorize(&AuthRequest{..}).await?.allowed` 一致：
/// - allowed=true → check_permission 返回 Ok(())
/// - allowed=false → check_permission 返回 Err(NotPermission)
#[tokio::test]
async fn check_permission_delegates_to_authorize_and_returns_allowed() {
    let checker = make_checker();

    // 持有权限：authorize().allowed == true，check_permission == Ok
    let req_ok = AuthRequest::new("1001", "user:read");
    let decision_ok = PermissionChecker::authorize(&checker, &req_ok)
        .await
        .expect("authorize ok");
    assert!(decision_ok.allowed);
    assert!(checker.check_permission("1001", "user:read").await.is_ok());

    // 未持有权限：authorize().allowed == false，check_permission == Err
    let req_no = AuthRequest::new("1001", "user:delete");
    let decision_no = PermissionChecker::authorize(&checker, &req_no)
        .await
        .expect("authorize ok");
    assert!(!decision_no.allowed);
    assert!(checker
        .check_permission("1001", "user:delete")
        .await
        .is_err());
}

/// T017 补充: check_permission 的错误类型为 NotPermission（不是其他错误）。
#[tokio::test]
async fn check_permission_deny_returns_not_permission_error() {
    let checker = make_checker();
    let result = checker.check_permission("1001", "user:delete").await;
    match result.err() {
        Some(BulwarkError::NotPermission(msg)) => {
            assert!(msg.contains("1001"), "错误消息应含 login_id");
            assert!(msg.contains("user:delete"), "错误消息应含 permission");
        },
        other => panic!("期望 NotPermission，实际: {:?}", other),
    }
}

/// T017 补充: check_role 仍保持原行为（未持有角色返回 NotRole）。
#[tokio::test]
async fn check_role_still_returns_not_role_when_unmatched() {
    let checker = make_checker();
    let result = checker.check_role("1001", "superadmin").await;
    match result.err() {
        Some(BulwarkError::NotRole(_)) => {},
        other => panic!("期望 NotRole，实际: {:?}", other),
    }
}

/// T017 补充: Decision 可从 authorize 序列化为 JSON（端到端 trace 输出验证）。
#[tokio::test]
async fn authorize_decision_serializes_to_json() {
    let checker = make_checker();
    let request = AuthRequest::new("1001", "user:read");
    let decision = PermissionChecker::authorize(&checker, &request)
        .await
        .expect("authorize ok");
    let json = serde_json::to_value(&decision).expect("serialize Decision");
    assert_eq!(json["allowed"], serde_json::json!(true));
    assert_eq!(json["reason"], serde_json::json!("explicit_allow"));
}

// ========================================================================
// Unicode NFC 规范化 + 长度限制测试
// ========================================================================

/// check_permission 对 permission 字符串做 NFC 规范化。
///
/// NFD 形式 `"user:e\u{0301}read"`（e + COMBINING ACUTE ACCENT U+0301）应规范化为
/// NFC 形式 `"user:\u{00e9}read"`（LATIN SMALL LETTER E WITH ACUTE U+00E9）。
/// mock 存储 NFC 形式，传入 NFD 形式应规范化后匹配。
///
/// 注：任务描述原例 `"user\u{0301}:read"` → `"user\u{00e9}:read"` 不正确，
/// 因为 U+0301 会与前一个 'r' 组合形成 'ŕ'（U+0157），而非 'é'（U+00E9）。
/// 正确的 NFD→NFC 对为 `"user:e\u{0301}read"` → `"user:\u{00e9}read"`。
#[tokio::test]
async fn check_permission_normalizes_unicode() {
    let interface = MockInterface::new().with_perms("1001", vec!["user:\u{00e9}read"]);
    let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
    let checker = PermissionCheckerDefault::new(interface_arc);

    let nfd = "user:e\u{0301}read";
    let nfc = "user:\u{00e9}read";

    assert!(
        checker.check_permission("1001", nfd).await.is_ok(),
        "NFD 形式应规范化后匹配 NFC permission"
    );
    assert!(
        checker.check_permission("1001", nfc).await.is_ok(),
        "NFC 形式应直接匹配"
    );
}

/// check_permission 拒绝超过 256 字节的 permission 字符串（防止 DoS）。
#[tokio::test]
async fn check_permission_rejects_over_256_bytes() {
    let long_perm = "x".repeat(300); // 300 字节，超过 256 字节上限
    let checker = make_checker();
    let result = checker.check_permission("1001", &long_perm).await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(_))),
        "超长 permission 应返回 InvalidParam，实际: {:?}",
        result
    );
}

// ========================================================================
// 覆盖率补充：has_role 空角色 + check_role 错误消息验证
// ========================================================================

/// has_role 空字符串返回 InvalidParam 错误（覆盖行 180）。
#[tokio::test]
async fn has_role_empty_string_returns_error() {
    let checker = make_checker();
    let result = checker.has_role("1001", "").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg.contains("core-role-empty")),
        "has_role 空字符串应返回 InvalidParam，实际: {:?}",
        result
    );
}

/// check_role 未持有角色的错误消息包含 login_id 和 role（覆盖行 124-125 的 format）。
#[tokio::test]
async fn check_role_deny_message_includes_login_id_and_role() {
    let checker = make_checker();
    let result = checker.check_role("1001", "superadmin").await;
    match result.err() {
        Some(BulwarkError::NotRole(msg)) => {
            assert!(msg.contains("1001"), "错误消息应含 login_id，实际: {}", msg);
            assert!(
                msg.contains("superadmin"),
                "错误消息应含 role，实际: {}",
                msg
            );
        },
        other => panic!("期望 NotRole，实际: {:?}", other),
    }
}
