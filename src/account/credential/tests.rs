//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! credential 模块测试（从 mod.rs 迁移，Rule 25 合规）。

use super::mock::MockCredentialRepository;
use super::*;
use crate::dao::tests::MockDao;

// ========================================================================
// R-001: Credential trait 对象安全测试
// ========================================================================

/// R-001: `Credential` trait 可作 `Box<dyn Credential>` 使用（对象安全编译验证）。
///
/// 若 `Credential` trait 非对象安全（如使用了泛型方法），此测试无法编译。
#[test]
fn credential_trait_is_object_safe() {
    // 编译期验证：trait 可作 dyn 使用
    fn _assert_object_safe(_cred: Box<dyn Credential>) {}
    fn _assert_arc_object_safe(_cred: std::sync::Arc<dyn Credential>) {}
    // 空函数，仅验证类型签名编译通过
}

/// R-001: `CredentialRepository` trait 可作 `Arc<dyn CredentialRepository>` 使用。
#[test]
fn credential_repository_trait_is_object_safe() {
    fn _assert_object_safe(_repo: std::sync::Arc<dyn CredentialRepository>) {}
}

// ========================================================================
// R-002: CredentialModel 序列化测试
// ========================================================================

/// R-002: `CredentialModel` serde 序列化输出包含全部 8 字段。
#[test]
fn credential_model_serializes_all_8_fields() {
    let model = CredentialModel {
        id: "cred-001".to_string(),
        user_id: "alice".to_string(),
        credential_type: "password".to_string(),
        secret_data: "$argon2id$v=19$...".to_string(),
        label: Some("主密码".to_string()),
        created_at: 1700000000,
        enabled: true,
        priority: 0,
    };
    let json = serde_json::to_string(&model).expect("序列化应成功");
    // 验证全部 8 字段存在于 JSON 输出中
    assert!(
        json.contains("\"id\":\"cred-001\""),
        "JSON 缺少 id 字段: {}",
        json
    );
    assert!(
        json.contains("\"user_id\":\"alice\""),
        "JSON 缺少 user_id 字段: {}",
        json
    );
    assert!(
        json.contains("\"credential_type\":\"password\""),
        "JSON 缺少 credential_type 字段: {}",
        json
    );
    assert!(
        json.contains("\"secret_data\""),
        "JSON 缺少 secret_data 字段: {}",
        json
    );
    assert!(
        json.contains("\"label\":\"主密码\""),
        "JSON 缺少 label 字段: {}",
        json
    );
    assert!(
        json.contains("\"created_at\":1700000000"),
        "JSON 缺少 created_at 字段: {}",
        json
    );
    assert!(
        json.contains("\"enabled\":true"),
        "JSON 缺少 enabled 字段: {}",
        json
    );
    assert!(
        json.contains("\"priority\":0"),
        "JSON 缺少 priority 字段: {}",
        json
    );
}

/// R-002: `CredentialModel` serde 反序列化可解析包含全部 8 字段的完整 JSON。
#[test]
fn credential_model_deserializes_from_full_json() {
    let json = r#"{
            "id": "cred-002",
            "user_id": "bob",
            "credential_type": "totp",
            "secret_data": "{\"secret\":\"JBSWY3DPEHPK3PXP\"}",
            "label": null,
            "created_at": 1700000001,
            "enabled": false,
            "priority": 1
        }"#;
    let model: CredentialModel = serde_json::from_str(json).expect("反序列化应成功");
    assert_eq!(model.id, "cred-002");
    assert_eq!(model.user_id, "bob");
    assert_eq!(model.credential_type, "totp");
    assert!(model.secret_data.contains("JBSWY3DPEHPK3PXP"));
    assert!(model.label.is_none(), "label 应为 None");
    assert_eq!(model.created_at, 1700000001);
    assert!(!model.enabled, "enabled 应为 false");
    assert_eq!(model.priority, 1);
}

/// R-002: `label` 字段为 `None` 时序列化为 JSON `null`。
#[test]
fn credential_model_label_none_serializes_as_null() {
    let model = CredentialModel {
        id: "cred-003".to_string(),
        user_id: "carol".to_string(),
        credential_type: "password".to_string(),
        secret_data: "hash".to_string(),
        label: None,
        created_at: 0,
        enabled: true,
        priority: 0,
    };
    let json = serde_json::to_string(&model).expect("序列化应成功");
    assert!(
        json.contains("\"label\":null"),
        "label 为 None 时应序列化为 null，实际: {}",
        json
    );
}

/// R-002: `CredentialModel` Clone 后字段一致。
#[test]
fn credential_model_clone_preserves_fields() {
    let model = CredentialModel {
        id: "cred-004".to_string(),
        user_id: "dave".to_string(),
        credential_type: "webauthn".to_string(),
        secret_data: "key".to_string(),
        label: Some("YubiKey".to_string()),
        created_at: 1700000002,
        enabled: true,
        priority: 5,
    };
    let cloned = model.clone();
    assert_eq!(cloned.id, model.id);
    assert_eq!(cloned.user_id, model.user_id);
    assert_eq!(cloned.credential_type, model.credential_type);
    assert_eq!(cloned.secret_data, model.secret_data);
    assert_eq!(cloned.label, model.label);
    assert_eq!(cloned.created_at, model.created_at);
    assert_eq!(cloned.enabled, model.enabled);
    assert_eq!(cloned.priority, model.priority);
}

// ========================================================================
// R-003: CredentialRepository mock CRUD 测试
// ========================================================================

/// 辅助函数：构造测试用 CredentialModel。
fn make_model(id: &str, user: &str, cred_type: &str, priority: i32) -> CredentialModel {
    CredentialModel {
        id: id.to_string(),
        user_id: user.to_string(),
        credential_type: cred_type.to_string(),
        secret_data: "hash".to_string(),
        label: None,
        created_at: 0,
        enabled: true,
        priority,
    }
}

/// R-003: `create` + `find_by_user` 正常路径。
#[tokio::test]
async fn repository_create_and_find_by_user() {
    let repo = MockCredentialRepository::default();
    let m1 = make_model("c1", "alice", "password", 0);
    let m2 = make_model("c2", "alice", "totp", 1);
    repo.create(m1.clone()).await.unwrap();
    repo.create(m2.clone()).await.unwrap();

    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 2);
    // 按 priority 升序：password(0) 在前，totp(1) 在后
    assert_eq!(found[0].id, "c1");
    assert_eq!(found[1].id, "c2");
}

/// R-003: `create` 重复 ID 返回错误。
#[tokio::test]
async fn repository_create_duplicate_returns_error() {
    let repo = MockCredentialRepository::default();
    let m = make_model("c1", "alice", "password", 0);
    repo.create(m).await.unwrap();
    let dup = make_model("c1", "alice", "password", 0);
    let result = repo.create(dup).await;
    assert!(result.is_err(), "重复 create 应返回错误");
}

/// R-003: `find_by_user_and_type` 按 credential_type 过滤。
#[tokio::test]
async fn repository_find_by_user_and_type_filters() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    repo.create(make_model("c2", "alice", "totp", 1))
        .await
        .unwrap();
    repo.create(make_model("c3", "alice", "password", 2))
        .await
        .unwrap();

    let passwords = repo
        .find_by_user_and_type("alice", "password")
        .await
        .unwrap();
    assert_eq!(passwords.len(), 2);
    assert!(passwords.iter().all(|c| c.credential_type == "password"));

    let totps = repo.find_by_user_and_type("alice", "totp").await.unwrap();
    assert_eq!(totps.len(), 1);
    assert_eq!(totps[0].id, "c2");
}

/// R-003: `update` 覆盖写 + 不存在返回错误。
#[tokio::test]
async fn repository_update_overwrites_and_errors_on_missing() {
    let repo = MockCredentialRepository::default();
    let m = make_model("c1", "alice", "password", 0);
    repo.create(m).await.unwrap();

    // 更新已存在凭证
    let updated = CredentialModel {
        id: "c1".to_string(),
        user_id: "alice".to_string(),
        credential_type: "password".to_string(),
        secret_data: "new-hash".to_string(),
        label: Some("updated".to_string()),
        created_at: 100,
        enabled: false,
        priority: 5,
    };
    repo.update("alice", updated.clone()).await.unwrap();
    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found[0].secret_data, "new-hash");
    assert_eq!(found[0].label, Some("updated".to_string()));
    assert!(!found[0].enabled);
    assert_eq!(found[0].priority, 5);

    // 更新不存在凭证
    let missing = make_model("nonexistent", "alice", "password", 0);
    let result = repo.update("alice", missing).await;
    assert!(result.is_err(), "更新不存在的凭证应返回错误");
}

/// R-003: `delete` 删除 + 不存在返回错误。
#[tokio::test]
async fn repository_delete_removes_and_errors_on_missing() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    // 删除已存在凭证
    repo.delete("alice", "c1").await.unwrap();
    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 0, "删除后应查不到凭证");

    // 删除不存在凭证
    let result = repo.delete("alice", "c1").await;
    assert!(result.is_err(), "删除不存在的凭证应返回错误");
}

/// R-003: 多用户隔离 — 不同用户的凭证互不影响。
#[tokio::test]
async fn repository_multi_user_isolation() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    repo.create(make_model("c2", "bob", "password", 0))
        .await
        .unwrap();

    let alice_creds = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(alice_creds.len(), 1);
    assert_eq!(alice_creds[0].id, "c1");

    let bob_creds = repo.find_by_user("bob", "bob").await.unwrap();
    assert_eq!(bob_creds.len(), 1);
    assert_eq!(bob_creds[0].id, "c2");

    let empty = repo.find_by_user("carol", "carol").await.unwrap();
    assert_eq!(empty.len(), 0);
}

/// R-003: `CredentialRepository` 可作 `Arc<dyn CredentialRepository>` 使用。
#[tokio::test]
async fn repository_usable_as_trait_object() {
    let repo: std::sync::Arc<dyn CredentialRepository> =
        std::sync::Arc::new(MockCredentialRepository::default());
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 1);
}

// ========================================================================
// R-006: DaoCredentialRepository 测试（基于 MockDao）
// ========================================================================

/// 辅助函数：构造 DaoCredentialRepository（基于 MockDao）。
fn make_dao_repo() -> DaoCredentialRepository {
    DaoCredentialRepository::new(Arc::new(MockDao::new()))
}

/// R-006: `create` + `find_by_user` 正常路径（DAO key = `cred:{user_id}:{cred_id}`）。
#[tokio::test]
async fn dao_repo_create_and_find_by_user() {
    let repo = make_dao_repo();
    let m = make_model("c1", "alice", "password", 0);
    repo.create(m.clone()).await.unwrap();

    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "c1");
    assert_eq!(found[0].user_id, "alice");
    assert_eq!(found[0].credential_type, "password");
}

/// R-006: `find_by_user` 未知用户返回空 Vec。
#[tokio::test]
async fn dao_repo_find_by_user_returns_empty_for_unknown() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    let found = repo.find_by_user("bob", "bob").await.unwrap();
    assert!(found.is_empty(), "未知用户应返回空 Vec");
}

/// R-006: `find_by_user_and_type` 按 `credential_type` 过滤。
#[tokio::test]
async fn dao_repo_find_by_user_and_type_filters() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    repo.create(make_model("c2", "alice", "totp", 1))
        .await
        .unwrap();
    repo.create(make_model("c3", "alice", "password", 2))
        .await
        .unwrap();

    let passwords = repo
        .find_by_user_and_type("alice", "password")
        .await
        .unwrap();
    assert_eq!(passwords.len(), 2);
    assert!(passwords.iter().all(|c| c.credential_type == "password"));

    let totps = repo.find_by_user_and_type("alice", "totp").await.unwrap();
    assert_eq!(totps.len(), 1);
    assert_eq!(totps[0].id, "c2");
}

/// R-006: `update` 覆盖写 + 不存在返回错误。
#[tokio::test]
async fn dao_repo_update_overwrites_and_errors_on_missing() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    // 覆盖写已存在凭证
    let updated = CredentialModel {
        id: "c1".to_string(),
        user_id: "alice".to_string(),
        credential_type: "password".to_string(),
        secret_data: "new-hash".to_string(),
        label: Some("updated".to_string()),
        created_at: 100,
        enabled: false,
        priority: 5,
    };
    repo.update("alice", updated.clone()).await.unwrap();
    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found[0].secret_data, "new-hash");
    assert_eq!(found[0].label, Some("updated".to_string()));
    assert!(!found[0].enabled);
    assert_eq!(found[0].priority, 5);

    // 更新不存在凭证
    let missing = make_model("nonexistent", "alice", "password", 0);
    let result = repo.update("alice", missing).await;
    assert!(result.is_err(), "更新不存在的凭证应返回错误");
}

/// R-006: `delete` 删除 + 不存在返回错误。
#[tokio::test]
async fn dao_repo_delete_removes_and_errors_on_missing() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    repo.delete("alice", "c1").await.unwrap();
    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert!(found.is_empty(), "删除后应查不到凭证");

    // 删除不存在凭证
    let result = repo.delete("alice", "c1").await;
    assert!(result.is_err(), "删除不存在的凭证应返回错误");
}

/// R-006: 多用户隔离 — 不同用户的凭证互不影响（DAO key 含 user_id 前缀）。
#[tokio::test]
async fn dao_repo_multi_user_isolation() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    repo.create(make_model("c2", "bob", "password", 0))
        .await
        .unwrap();

    let alice = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].id, "c1");

    let bob = repo.find_by_user("bob", "bob").await.unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].id, "c2");

    // carol 无凭证
    let carol = repo.find_by_user("carol", "carol").await.unwrap();
    assert!(carol.is_empty());
}

/// R-006: 单用户多凭证类型（password + totp + webauthn 共存）。
#[tokio::test]
async fn dao_repo_multi_credential_types_per_user() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    repo.create(make_model("c2", "alice", "totp", 1))
        .await
        .unwrap();
    repo.create(make_model("c3", "alice", "webauthn", 2))
        .await
        .unwrap();

    let all = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(all.len(), 3);
    let types: Vec<&str> = all.iter().map(|c| c.credential_type.as_str()).collect();
    assert!(types.contains(&"password"));
    assert!(types.contains(&"totp"));
    assert!(types.contains(&"webauthn"));
}

/// R-006: `find_by_user` 返回含 `enabled=false` 的凭证（trait 层不过滤 enabled，业务层负责）。
#[tokio::test]
async fn dao_repo_find_returns_disabled_credentials() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    // 创建一个 enabled=false 的凭证
    let disabled = CredentialModel {
        id: "c2".to_string(),
        user_id: "alice".to_string(),
        credential_type: "totp".to_string(),
        secret_data: "secret".to_string(),
        label: None,
        created_at: 0,
        enabled: false,
        priority: 1,
    };
    repo.create(disabled).await.unwrap();

    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(
        found.len(),
        2,
        "find_by_user 应返回 enabled + disabled 凭证"
    );
    let disabled_cred = found.iter().find(|c| c.id == "c2").unwrap();
    assert!(!disabled_cred.enabled, "disabled 凭证 enabled 应为 false");
}

/// R-006: `find_by_user` 按 `priority` 升序返回（trait 契约）。
#[tokio::test]
async fn dao_repo_priority_order_ascending() {
    let repo = make_dao_repo();
    // 故意乱序插入：priority 5, 1, 3
    repo.create(make_model("c1", "alice", "password", 5))
        .await
        .unwrap();
    repo.create(make_model("c2", "alice", "totp", 1))
        .await
        .unwrap();
    repo.create(make_model("c3", "alice", "webauthn", 3))
        .await
        .unwrap();

    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 3);
    // 按 priority 升序：1, 3, 5
    assert_eq!(found[0].id, "c2");
    assert_eq!(found[0].priority, 1);
    assert_eq!(found[1].id, "c3");
    assert_eq!(found[1].priority, 3);
    assert_eq!(found[2].id, "c1");
    assert_eq!(found[2].priority, 5);
}

/// R-006: `create` 重复 ID 返回错误。
#[tokio::test]
async fn dao_repo_create_duplicate_returns_error() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    let dup = make_model("c1", "alice", "password", 0);
    let result = repo.create(dup).await;
    assert!(result.is_err(), "重复 create 应返回错误");
}

/// R-006: `DaoCredentialRepository` 可作 `Arc<dyn CredentialRepository>` 使用。
#[tokio::test]
async fn dao_repo_usable_as_trait_object() {
    let repo: Arc<dyn CredentialRepository> = Arc::new(make_dao_repo());
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 1);
}

// ========================================================================
// R-IDOR: IDOR 防护测试（vuln-0004 修复）
//
// 验证 CredentialRepository 的 find_by_user / update / delete 在 caller_login_id
// 与目标凭证 owner 不一致时返回 GarrisonError::NotPermission（403 Forbidden）。
// 同时验证 update 不得改变 user_id 字段（防止凭证跨用户转移）。
// 覆盖 MockCredentialRepository + DaoCredentialRepository 两个实现。
// ========================================================================

/// 辅助：断言 err 是 NotPermission（IDOR 拒绝）。
fn assert_idor_denied(err: GarrisonError, ctx: &str) {
    assert!(
        matches!(err, GarrisonError::NotPermission(_)),
        "{} 应返回 NotPermission（IDOR 拒绝），实际: {:?}",
        ctx,
        err
    );
}

// ------------------------------------------------------------------------
// IDOR: find_by_user 跨用户查询拒绝
// ------------------------------------------------------------------------

/// IDOR: Mock - alice 调用 find_by_user 查询 bob 的凭证应被拒绝。
#[tokio::test]
async fn mock_find_by_user_denied_when_caller_not_target() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let err = repo
        .find_by_user("alice", "bob")
        .await
        .expect_err("alice 查询 bob 凭证应被拒绝");
    assert_idor_denied(err, "mock find_by_user alice→bob");
}

/// IDOR: DAO - alice 调用 find_by_user 查询 bob 的凭证应被拒绝。
#[tokio::test]
async fn dao_find_by_user_denied_when_caller_not_target() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let err = repo
        .find_by_user("alice", "bob")
        .await
        .expect_err("alice 查询 bob 凭证应被拒绝");
    assert_idor_denied(err, "dao find_by_user alice→bob");
}

/// IDOR: 合法 caller 查询自己的凭证应成功（正向用例）。
#[tokio::test]
async fn dao_find_by_user_succeeds_when_caller_is_owner() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();
    repo.create(make_model("c2", "alice", "totp", 1))
        .await
        .unwrap();

    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found.len(), 2, "alice 查询自己的凭证应成功返回 2 条");
}

// ------------------------------------------------------------------------
// IDOR: delete 跨用户删除拒绝
// ------------------------------------------------------------------------

/// IDOR: Mock - alice 尝试删除 bob 的凭证应被拒绝。
#[tokio::test]
async fn mock_delete_denied_when_caller_not_owner() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let err = repo
        .delete("alice", "c1")
        .await
        .expect_err("alice 删除 bob 的凭证应被拒绝");
    assert_idor_denied(err, "mock delete alice→bob c1");

    // 验证 bob 的凭证未被删除
    let remaining = repo.find_by_user("bob", "bob").await.unwrap();
    assert_eq!(remaining.len(), 1, "拒绝后 bob 的凭证应仍存在");
    assert_eq!(remaining[0].id, "c1");
}

/// IDOR: DAO - alice 尝试删除 bob 的凭证应被拒绝。
#[tokio::test]
async fn dao_delete_denied_when_caller_not_owner() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let err = repo
        .delete("alice", "c1")
        .await
        .expect_err("alice 删除 bob 的凭证应被拒绝");
    assert_idor_denied(err, "dao delete alice→bob c1");

    // 验证 bob 的凭证未被删除
    let remaining = repo.find_by_user("bob", "bob").await.unwrap();
    assert_eq!(remaining.len(), 1, "拒绝后 bob 的凭证应仍存在");
}

/// IDOR: 合法 caller 删除自己的凭证应成功（正向用例）。
#[tokio::test]
async fn dao_delete_succeeds_when_caller_is_owner() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    repo.delete("alice", "c1").await.unwrap();
    let remaining = repo.find_by_user("alice", "alice").await.unwrap();
    assert!(remaining.is_empty(), "alice 删除自己的凭证后应查不到");
}

// ------------------------------------------------------------------------
// IDOR: update 跨用户修改拒绝
// ------------------------------------------------------------------------

/// IDOR: Mock - alice 尝试更新 bob 的凭证应被拒绝。
#[tokio::test]
async fn mock_update_denied_when_caller_not_owner() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    // alice 伪造一条 user_id=bob 的更新（典型 IDOR 攻击）
    let forged = make_model("c1", "bob", "password", 0);
    let err = repo
        .update("alice", forged)
        .await
        .expect_err("alice 更新 bob 的凭证应被拒绝");
    assert_idor_denied(err, "mock update alice→bob c1");

    // 验证 bob 的凭证未被修改
    let remaining = repo.find_by_user("bob", "bob").await.unwrap();
    assert_eq!(remaining[0].secret_data, "hash", "凭证应未被修改");
}

/// IDOR: DAO - alice 尝试更新 bob 的凭证应被拒绝。
#[tokio::test]
async fn dao_update_denied_when_caller_not_owner() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let forged = CredentialModel {
        id: "c1".to_string(),
        user_id: "bob".to_string(),
        credential_type: "password".to_string(),
        secret_data: "attacker-hash".to_string(),
        label: None,
        created_at: 0,
        enabled: true,
        priority: 0,
    };
    let err = repo
        .update("alice", forged)
        .await
        .expect_err("alice 更新 bob 的凭证应被拒绝");
    assert_idor_denied(err, "dao update alice→bob c1");

    // 验证 bob 的凭证未被修改
    let remaining = repo.find_by_user("bob", "bob").await.unwrap();
    assert_eq!(
        remaining[0].secret_data, "hash",
        "凭证 secret_data 应未被攻击者覆盖"
    );
}

// ------------------------------------------------------------------------
// IDOR: update 禁止 user_id 转移
// ------------------------------------------------------------------------

/// IDOR: Mock - alice 尝试通过 update 把自己的凭证 user_id 改成 bob（跨用户转移）应被拒绝。
#[tokio::test]
async fn mock_update_denied_when_user_id_transferred() {
    let repo = MockCredentialRepository::default();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    // alice 把自己的凭证 user_id 改成 bob（凭证转移攻击）
    let transfer = CredentialModel {
        id: "c1".to_string(),
        user_id: "bob".to_string(), // 试图改变 owner
        credential_type: "password".to_string(),
        secret_data: "hash".to_string(),
        label: None,
        created_at: 0,
        enabled: true,
        priority: 0,
    };
    let err = repo
        .update("alice", transfer)
        .await
        .expect_err("alice 转移凭证到 bob 应被拒绝");
    assert_idor_denied(err, "mock update user_id transfer");

    // 验证凭证仍属于 alice
    let alice_creds = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(alice_creds.len(), 1, "凭证应仍属于 alice");
    assert_eq!(alice_creds[0].user_id, "alice");
}

/// IDOR: DAO - alice 尝试通过 update 把自己的凭证 user_id 改成 bob 应被拒绝。
#[tokio::test]
async fn dao_update_denied_when_user_id_transferred() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    let transfer = CredentialModel {
        id: "c1".to_string(),
        user_id: "bob".to_string(), // 试图改变 owner
        credential_type: "password".to_string(),
        secret_data: "hash".to_string(),
        label: None,
        created_at: 0,
        enabled: true,
        priority: 0,
    };
    let err = repo
        .update("alice", transfer)
        .await
        .expect_err("alice 转移凭证到 bob 应被拒绝");
    assert_idor_denied(err, "dao update user_id transfer");

    // 验证凭证仍属于 alice
    let alice_creds = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(alice_creds.len(), 1, "凭证应仍属于 alice");
    assert_eq!(alice_creds[0].user_id, "alice");
}

/// IDOR: 合法 caller 更新自己的凭证（不改 user_id）应成功（正向用例）。
#[tokio::test]
async fn dao_update_succeeds_when_caller_is_owner_and_user_id_unchanged() {
    let repo = make_dao_repo();
    repo.create(make_model("c1", "alice", "password", 0))
        .await
        .unwrap();

    let updated = CredentialModel {
        id: "c1".to_string(),
        user_id: "alice".to_string(), // user_id 保持不变
        credential_type: "password".to_string(),
        secret_data: "new-hash".to_string(),
        label: Some("updated".to_string()),
        created_at: 100,
        enabled: false,
        priority: 5,
    };
    repo.update("alice", updated).await.unwrap();

    let found = repo.find_by_user("alice", "alice").await.unwrap();
    assert_eq!(found[0].secret_data, "new-hash");
    assert_eq!(found[0].label, Some("updated".to_string()));
    assert!(!found[0].enabled);
    assert_eq!(found[0].priority, 5);
}

// ------------------------------------------------------------------------
// IDOR: trait object 动态分发也生效
// ------------------------------------------------------------------------

/// IDOR: 通过 `Arc<dyn CredentialRepository>` 调用也应执行 IDOR 校验。
#[tokio::test]
async fn trait_object_enforces_idor_on_delete() {
    let repo: Arc<dyn CredentialRepository> = Arc::new(make_dao_repo());
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let err = repo
        .delete("alice", "c1")
        .await
        .expect_err("trait object: alice 删除 bob 的凭证应被拒绝");
    assert_idor_denied(err, "trait object delete alice→bob");
}

/// IDOR: 通过 `Arc<dyn CredentialRepository>` 调用 find_by_user 也应执行校验。
#[tokio::test]
async fn trait_object_enforces_idor_on_find_by_user() {
    let repo: Arc<dyn CredentialRepository> = Arc::new(make_dao_repo());
    repo.create(make_model("c1", "bob", "password", 0))
        .await
        .unwrap();

    let err = repo
        .find_by_user("alice", "bob")
        .await
        .expect_err("trait object: alice 查询 bob 凭证应被拒绝");
    assert_idor_denied(err, "trait object find_by_user alice→bob");
}
