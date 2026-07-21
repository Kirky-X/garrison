//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::mock::MockDao;
use super::*;
use crate::error::GarrisonError;
use std::time::{SystemTime, UNIX_EPOCH};

/// 创建 ApiKeyHandler（使用 MockDao）。
fn make_handler() -> ApiKeyHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    ApiKeyHandler::new(dao)
}

// ========================================================================
// ApiKeyHandler 构造测试
// ========================================================================

/// 构造 ApiKeyHandler（spec Scenario）。
#[test]
fn new_creates_handler() {
    let _handler = make_handler();
}

// ========================================================================
// generate 测试
// ========================================================================

/// 成功生成 API Key，返回 64 字符（spec Scenario）。
#[tokio::test]
async fn generate_returns_64_chars() {
    let handler = make_handler();
    let key = handler
        .generate("1001", vec!["read".into()], 3600)
        .await
        .unwrap();
    assert_eq!(key.len(), 64);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
}

/// 复用同一 handler 多次生成不同 key（spec Scenario）。
#[tokio::test]
async fn generate_multiple_times_returns_different_keys() {
    let handler = make_handler();
    let k1 = handler.generate("1001", vec![], 3600).await.unwrap();
    let k2 = handler.generate("1001", vec![], 3600).await.unwrap();
    assert_ne!(k1, k2);
}

/// timeout <= 0 返回错误（spec Scenario）。
#[tokio::test]
async fn generate_zero_timeout_returns_error() {
    let handler = make_handler();
    let result = handler.generate("1001", vec![], 0).await;
    assert!(result.is_err());
}

/// key 前缀正确（spec Scenario）。
///
/// generate 默认 namespace="default"，存储格式变为
/// `garrison:apikey:default:<key>`。
#[tokio::test]
async fn generate_uses_correct_key_prefix() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = handler
        .generate("1001", vec!["read".into()], 3600)
        .await
        .unwrap();
    let dao_key = format!("garrison:apikey:default:{}", key);
    let value = dao.get(&dao_key).await.unwrap();
    assert!(value.is_some());
    let info: ApiKeyInfo = serde_json::from_str(&value.unwrap()).unwrap();
    assert_eq!(info.login_id, "1001");
    assert_eq!(info.scopes, vec!["read".to_string()]);
    assert!(!info.revoked);
    assert_eq!(info.namespace, "default");
}

// ========================================================================
// verify 测试
// ========================================================================

/// 成功校验返回 ApiKeyInfo（spec Scenario）。
#[tokio::test]
async fn verify_success_returns_info() {
    let handler = make_handler();
    let key = handler
        .generate("1001", vec!["read".into(), "write".into()], 3600)
        .await
        .unwrap();
    let info = handler.verify(&key).await.unwrap();
    assert_eq!(info.login_id, "1001");
    assert_eq!(info.scopes, vec!["read".to_string(), "write".to_string()]);
    assert!(!info.revoked);
}

/// 校验不存在的 key 返回错误（spec Scenario）。
#[tokio::test]
async fn verify_nonexistent_returns_error() {
    let handler = make_handler();
    let result = handler.verify("nonexistent-key").await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 校验已吊销的 key 返回错误（spec Scenario）。
#[tokio::test]
async fn verify_revoked_returns_error() {
    let handler = make_handler();
    let key = handler.generate("1001", vec![], 3600).await.unwrap();
    handler.revoke(&key).await.unwrap();
    let result = handler.verify(&key).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 校验已过期的 key 返回错误（spec Scenario）。
#[tokio::test]
async fn verify_expired_returns_error() {
    let handler = make_handler();
    // 生成一个 1 秒过期的 key
    let key = handler.generate("1001", vec![], 1).await.unwrap();
    // 等待 2 秒
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    let result = handler.verify(&key).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
    }
}

// ========================================================================
// revoke 测试
// ========================================================================

/// 成功吊销（spec Scenario）。
#[tokio::test]
async fn revoke_success() {
    let handler = make_handler();
    let key = handler.generate("1001", vec![], 3600).await.unwrap();
    let result = handler.revoke(&key).await;
    assert!(result.is_ok());
    // 再次 verify 应失败
    let verify_result = handler.verify(&key).await;
    assert!(verify_result.is_err());
}

/// 吊销不存在的 key 返回错误（spec Scenario）。
#[tokio::test]
async fn revoke_nonexistent_returns_error() {
    let handler = make_handler();
    let result = handler.revoke("nonexistent-key").await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

// ========================================================================
// rotate 测试
// ========================================================================

/// 成功轮换（spec Scenario）。
#[tokio::test]
async fn rotate_success() {
    let handler = make_handler();
    let old_key = handler
        .generate("1001", vec!["read".into()], 3600)
        .await
        .unwrap();
    let new_key = handler.rotate(&old_key).await.unwrap();
    assert_ne!(old_key, new_key);
    assert_eq!(new_key.len(), 64);
    // old_key 应被吊销
    let old_result = handler.verify(&old_key).await;
    assert!(old_result.is_err());
    // new_key 应有效，且保留 login_id 和 scopes
    let info = handler.verify(&new_key).await.unwrap();
    assert_eq!(info.login_id, "1001");
    assert_eq!(info.scopes, vec!["read".to_string()]);
}

/// 轮换不存在的 key 返回错误（spec Scenario）。
#[tokio::test]
async fn rotate_nonexistent_returns_error() {
    let handler = make_handler();
    let result = handler.rotate("nonexistent-key").await;
    assert!(result.is_err());
}

// ========================================================================
// MockDao 方法覆盖测试
// ========================================================================

/// 验证 MockDao::expire 和 delete 方法可正常调用。
///
/// 覆盖 MockDao 的 expire 和 delete trait 方法（此前测试未直接调用）。
#[tokio::test]
async fn mock_dao_expire_and_delete_covered() {
    let dao = MockDao::new();
    dao.set("k", "v", 3600).await.unwrap();

    // expire 正常键
    dao.expire("k", 7200).await.unwrap();
    let got = dao.get("k").await.unwrap();
    assert_eq!(got, Some("v".to_string()));

    // delete 正常键
    dao.delete("k").await.unwrap();
    let got = dao.get("k").await.unwrap();
    assert!(got.is_none());
}

/// 验证 generate 拒绝负数 timeout。
#[tokio::test]
async fn generate_negative_timeout_returns_error() {
    let handler = make_handler();
    let result = handler.generate("1001", vec![], -1).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GarrisonError::InvalidParam(_)
    ));
}

/// 验证 revoke 后 rotate 返回错误（old_key 已吊销）。
#[tokio::test]
async fn rotate_revoked_key_returns_error() {
    let handler = make_handler();
    let key = handler
        .generate("1001", vec!["read".into()], 3600)
        .await
        .unwrap();
    // 先吊销
    handler.revoke(&key).await.unwrap();
    // 再 rotate 应失败（verify 会因 revoked 返回 InvalidToken）
    let result = handler.rotate(&key).await;
    assert!(result.is_err());
}

// ========================================================================
// LoginId newtype 接入（impl Into<LoginId>）
// ========================================================================

/// 验证 `ApiKeyHandler::generate` 接受 String 形式 login_id。
#[tokio::test]
async fn generate_accepts_login_id_numeric() {
    let handler = make_handler();
    let key = handler
        .generate("1001".to_string(), vec!["read".into()], 3600)
        .await
        .unwrap();
    let info = handler.verify(&key).await.unwrap();
    assert_eq!(info.login_id, "1001");
}

// ========================================================================
// 0.4.2 Phase 8: API Key Namespace
// ========================================================================

/// R-001: ApiKeyInfo 序列化包含 namespace 字段。
#[test]
fn apikey_info_serializes_with_namespace() {
    let info = ApiKeyInfo {
        login_id: "1".to_string(),
        scopes: vec![],
        expire_at: 0,
        revoked: false,
        namespace: "internal".to_string(),
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("\"namespace\""), "JSON 应包含 namespace 字段");
    assert!(json.contains("\"internal\""), "namespace 值应为 internal");
}

/// R-001: 旧 JSON（无 namespace 字段）反序列化时 namespace = "default"
#[test]
fn apikey_info_old_json_deserializes_with_default_namespace() {
    // 旧格式 JSON：无 namespace 字段（v0.4.1 及之前生成的 key）
    let old_json = r#"{"login_id":"1","scopes":[],"expire_at":0,"revoked":false}"#;
    let info: ApiKeyInfo = serde_json::from_str(old_json).unwrap();
    assert_eq!(
        info.namespace, "default",
        "旧 JSON 应反序列化为 namespace=default"
    );
    assert_eq!(info.login_id, "1");
}

/// R-002: generate_with_namespace 用新格式 `garrison:apikey:<namespace>:<key>` 存储
#[tokio::test]
#[serial_test::serial]
async fn generate_with_namespace_stores_new_format_key() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();
    // 新格式：garrison:apikey:internal:<key>
    let dao_key = format!("garrison:apikey:internal:{}", key);
    let value = dao.get(&dao_key).await.unwrap();
    assert!(value.is_some(), "新格式 key 应存在: {}", dao_key);
    let info: ApiKeyInfo = serde_json::from_str(&value.unwrap()).unwrap();
    assert_eq!(info.namespace, "internal");
    assert_eq!(info.login_id, "1001");
    // 旧格式不应存在
    let old_key = format!("garrison:apikey:{}", key);
    let old_value = dao.get(&old_key).await.unwrap();
    assert!(old_value.is_none(), "旧格式 key 不应存在");
}

/// R-002: verify 兼容旧格式 key（无 namespace）。
///
/// 手动写入旧格式 `garrison:apikey:<key>`，verify 应能查到。
#[tokio::test]
#[serial_test::serial]
async fn verify_compatible_with_old_key_format() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    // 模拟旧格式 key（v0.4.1 及之前生成的）
    let old_key = "deadbeef".repeat(8); // 64 hex chars
    let old_dao_key = format!("garrison:apikey:{}", old_key);
    let info = ApiKeyInfo {
        login_id: "2002".to_string(),
        scopes: vec!["legacy".into()],
        expire_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600,
        revoked: false,
        namespace: "default".to_string(),
    };
    let value = serde_json::to_string(&info).unwrap();
    dao.set(&old_dao_key, &value, 3600).await.unwrap();
    // verify 应能找到（先查旧格式命中）
    let verified = handler.verify(&old_key).await.unwrap();
    assert_eq!(verified.login_id, "2002");
    assert_eq!(verified.scopes, vec!["legacy".to_string()]);
}

/// R-003: list_by_namespace 返回指定 namespace 下未吊销的 ApiKeyInfo
#[tokio::test]
#[serial_test::serial]
async fn list_by_namespace_returns_only_matching_namespace() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    // internal namespace 下生成 1 个 key
    let _k1 = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();
    // partner namespace 下生成 1 个 key
    let _k2 = handler
        .generate_with_namespace("2002", "partner", vec!["write".into()], 3600)
        .await
        .unwrap();
    // 列出 internal namespace
    let internal_keys = handler.list_by_namespace("internal").await.unwrap();
    assert_eq!(internal_keys.len(), 1, "internal namespace 应有 1 个 key");
    assert_eq!(internal_keys[0].login_id, "1001");
    assert_eq!(internal_keys[0].namespace, "internal");
    // 列出 partner namespace
    let partner_keys = handler.list_by_namespace("partner").await.unwrap();
    assert_eq!(partner_keys.len(), 1, "partner namespace 应有 1 个 key");
    assert_eq!(partner_keys[0].login_id, "2002");
    // 不存在的 namespace 返回空
    let empty = handler.list_by_namespace("nonexistent").await.unwrap();
    assert!(empty.is_empty(), "不存在的 namespace 应返回空 Vec");
}

/// R-003: list_by_namespace 过滤已吊销的 key
#[tokio::test]
#[serial_test::serial]
async fn list_by_namespace_filters_revoked_keys() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let k1 = handler
        .generate_with_namespace("1001", "internal", vec![], 3600)
        .await
        .unwrap();
    let _k2 = handler
        .generate_with_namespace("1002", "internal", vec![], 3600)
        .await
        .unwrap();
    // 吊销 k1
    handler.revoke(&k1).await.unwrap();
    let keys = handler.list_by_namespace("internal").await.unwrap();
    assert_eq!(keys.len(), 1, "吊销后应只剩 1 个未吊销 key");
    assert_eq!(keys[0].login_id, "1002");
}

/// R-004: namespace 隔离——verify_with_namespace 严格匹配 namespace
#[tokio::test]
#[serial_test::serial]
async fn verify_with_namespace_enforces_isolation() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    // 在 internal namespace 生成 key
    let key = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();
    // 用正确 namespace 校验应成功
    let info = handler
        .verify_with_namespace(&key, "internal")
        .await
        .unwrap();
    assert_eq!(info.login_id, "1001");
    assert_eq!(info.namespace, "internal");
    // 用错误 namespace 校验应失败（key 不存在该 namespace 下）
    let wrong = handler.verify_with_namespace(&key, "partner").await;
    assert!(
        matches!(wrong, Err(GarrisonError::InvalidToken(_))),
        "跨 namespace 校验应返回 InvalidToken，实际: {:?}",
        wrong
    );
}

/// R-004: 普通 verify（不带 namespace）能找到任意 namespace 下的 key
#[tokio::test]
#[serial_test::serial]
async fn verify_without_namespace_scans_all_namespaces() {
    let handler = make_handler();
    let key = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();
    // 不带 namespace 的 verify 通过扫描新格式找到
    let info = handler.verify(&key).await.unwrap();
    assert_eq!(info.login_id, "1001");
    assert_eq!(info.namespace, "internal");
}

/// Constraints: namespace 验证——空字符串、过长、非法字符都应返回 InvalidParam
#[tokio::test]
async fn generate_with_namespace_validates_namespace() {
    let handler = make_handler();
    // 空字符串
    let r = handler.generate_with_namespace("1", "", vec![], 3600).await;
    assert!(
        matches!(r, Err(GarrisonError::InvalidParam(_))),
        "空 namespace 应报错"
    );
    // 过长（65 字符）
    let long_ns = "a".repeat(65);
    let r = handler
        .generate_with_namespace("1", &long_ns, vec![], 3600)
        .await;
    assert!(
        matches!(r, Err(GarrisonError::InvalidParam(_))),
        "65 字符 namespace 应报错"
    );
    // 非法字符（含空格）
    let r = handler
        .generate_with_namespace("1", "has space", vec![], 3600)
        .await;
    assert!(
        matches!(r, Err(GarrisonError::InvalidParam(_))),
        "含空格 namespace 应报错"
    );
    // 合法字符边界：64 字符、含 _ -
    let r = handler
        .generate_with_namespace("1", &"a".repeat(64), vec![], 3600)
        .await;
    assert!(r.is_ok(), "64 字符 namespace 应通过");
    let r = handler
        .generate_with_namespace("1", "ns_name-1", vec![], 3600)
        .await;
    assert!(r.is_ok(), "含 _ - 数字 的 namespace 应通过");
}

// ========================================================================
// 覆盖率补充：错误分支与边界路径
// ========================================================================

/// 验证 verify_with_namespace 在 JSON namespace 与请求 namespace 不匹配时返回 InvalidToken。
///
/// 覆盖 verify_with_namespace 中 namespace 二次校验失败分支。
#[tokio::test]
#[serial_test::serial]
async fn verify_with_namespace_returns_error_when_namespace_mismatch() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = "deadbeef".repeat(8); // 64 hex chars
    let dao_key = format!("garrison:apikey:internal:{}", key);
    // 写入 namespace 不一致的 ApiKeyInfo（dao_key 用 internal，JSON 中 namespace=other）
    let info = ApiKeyInfo {
        login_id: "1001".to_string(),
        scopes: vec![],
        expire_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600,
        revoked: false,
        namespace: "other".to_string(),
    };
    let value = serde_json::to_string(&info).unwrap();
    dao.set(&dao_key, &value, 3600).await.unwrap();
    // verify_with_namespace 应返回 InvalidToken（namespace 不匹配）
    let result = handler.verify_with_namespace(&key, "internal").await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(ref msg)) if msg.starts_with("apikey-namespace-mismatch::")),
        "namespace 不匹配应返回 InvalidToken，实际: {:?}",
        result
    );
}

/// 验证 verify 在 value 不是有效 JSON 时返回 Internal 错误。
///
/// 覆盖 decode_and_check 的反序列化失败分支。
#[tokio::test]
async fn verify_returns_internal_error_when_json_invalid() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = "deadbeef".repeat(8);
    let dao_key = format!("garrison:apikey:{}", key);
    dao.set(&dao_key, "invalid-json", 3600).await.unwrap();
    let result = handler.verify(&key).await;
    assert!(
        matches!(result, Err(GarrisonError::Internal(ref msg)) if msg.contains("apikey-deserialize")),
        "无效 JSON 应返回 Internal 错误，实际: {:?}",
        result
    );
}

/// 验证 revoke 在 value 不是有效 JSON 时返回 Internal 错误。
///
/// 覆盖 revoke_at 的反序列化失败分支。
#[tokio::test]
async fn revoke_returns_internal_error_when_json_invalid() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = "deadbeef".repeat(8);
    let dao_key = format!("garrison:apikey:{}", key);
    dao.set(&dao_key, "invalid-json", 3600).await.unwrap();
    let result = handler.revoke(&key).await;
    assert!(
        matches!(result, Err(GarrisonError::Internal(ref msg)) if msg.contains("apikey-deserialize")),
        "无效 JSON 应返回 Internal 错误，实际: {:?}",
        result
    );
}

// ========================================================================
// E4 修复验证：API Key 反向索引 O(1) 查询
// ========================================================================

/// E4: 验证 `idx_key_for` helper 返回正确的索引 key 格式。
#[test]
fn e4_idx_key_for_returns_correct_format() {
    let key = "abcd1234".repeat(8); // 64 chars
    let idx_key = super::handler::idx_key_for(&key);
    assert_eq!(
        idx_key,
        format!("garrison:apikey:idx:{}", key),
        "E4: 索引 key 格式应为 garrison:apikey:idx:<key>"
    );
}

/// E4: 验证 handler.rs 源码不再使用 `keys("garrison:apikey:*:<key>")` 全表扫描。
///
/// 通过 `include_str!` 读取源文件并检查 `verify` / `revoke` 不再使用
/// `garrison:apikey:*:` 通配符模式（旧 verify/revoke 的 O(N) 扫描路径）。
///
/// `list_by_namespace` 仍合法使用 `keys("garrison:apikey:<namespace>:*")`（用于
/// 列举指定 namespace 下所有 key，非单点查询），其模式为
/// `garrison:apikey:<namespace>:*`（通配符在末尾），不在禁用范围。
#[test]
fn e4_source_verify_revoke_have_no_keys_scan() {
    let source = include_str!("handler.rs");
    // 过滤掉所有注释行，只检查真实代码
    let code_only: String = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//!") || trimmed.starts_with("///") || trimmed.starts_with("//"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    // 检查代码中不再出现 `garrison:apikey:*:` 模式（旧 verify/revoke 的 O(N) 扫描路径）。
    // 注意：`list_by_namespace` 使用 `garrison:apikey:<namespace>:*`（通配符在末尾），
    // 不匹配此模式，因此不受影响。
    assert!(
        !code_only.contains("\"garrison:apikey:*:"),
        "E4: handler.rs 代码不应再使用 garrison:apikey:*: 通配符扫描模式（verify/revoke 旧路径）"
    );
    // 检查代码中存在反向索引查询
    assert!(
        code_only.contains("idx_key_for"),
        "E4: handler.rs 代码应使用 idx_key_for 构造反向索引 key"
    );
    assert!(
        code_only.contains("garrison:apikey:idx:"),
        "E4: handler.rs 代码应包含 garrison:apikey:idx: 索引 key 前缀"
    );
}

/// E4: 验证 `generate_with_namespace` 同步写入反向索引。
///
/// 生成 key 后，`garrison:apikey:idx:<key>` 应存在，value 为 dao_key
/// （`garrison:apikey:<namespace>:<key>`）。
#[tokio::test]
#[serial_test::serial]
async fn e4_generate_with_namespace_writes_reverse_index() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();

    let idx_key = format!("garrison:apikey:idx:{}", key);
    let idx_value = dao.get(&idx_key).await.unwrap();
    assert!(
        idx_value.is_some(),
        "E4: 反向索引 garrison:apikey:idx:<key> 应存在"
    );

    let expected_dao_key = format!("garrison:apikey:internal:{}", key);
    assert_eq!(
        idx_value.unwrap(),
        expected_dao_key,
        "E4: 索引 value 应为 dao_key（garrison:apikey:<namespace>:<key>）"
    );
}

/// E4: 验证默认 `generate`（namespace="default"）也写入反向索引。
#[tokio::test]
#[serial_test::serial]
async fn e4_generate_writes_reverse_index_default_namespace() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = handler.generate("1001", vec![], 3600).await.unwrap();

    let idx_key = format!("garrison:apikey:idx:{}", key);
    let idx_value = dao.get(&idx_key).await.unwrap();
    assert!(idx_value.is_some(), "E4: 默认 generate 也应写入反向索引");

    let expected_dao_key = format!("garrison:apikey:default:{}", key);
    assert_eq!(
        idx_value.unwrap(),
        expected_dao_key,
        "E4: 默认 namespace 的索引 value 应为 garrison:apikey:default:<key>"
    );
}

/// E4: 验证 `verify` 通过反向索引找到 key（不再依赖 keys() 扫描）。
///
/// 生成 key 后，即使 DAO 中有大量其他 key，verify 也应 O(1) 命中。
#[tokio::test]
#[serial_test::serial]
async fn e4_verify_uses_reverse_index() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());

    // 预填充一些干扰 key（模拟生产环境中大量 key 共存的场景）
    for i in 0..50 {
        let noise_key = format!("garrison:apikey:noise:{}:{}", i, "a".repeat(64));
        dao.set(&noise_key, "noise", 3600).await.unwrap();
    }

    let key = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();
    let info = handler.verify(&key).await.unwrap();
    assert_eq!(info.login_id, "1001");
    assert_eq!(info.namespace, "internal");
}

/// E4: 验证 `revoke` 通过反向索引找到 key。
#[tokio::test]
#[serial_test::serial]
async fn e4_revoke_uses_reverse_index() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = handler
        .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
        .await
        .unwrap();

    handler.revoke(&key).await.unwrap();

    // verify 应失败（已吊销）
    let result = handler.verify(&key).await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(_))),
        "E4: revoke 后 verify 应返回 InvalidToken"
    );
}

/// E4: 验证 `verify` 在无反向索引时回退到旧格式 `garrison:apikey:<key>`。
///
/// 手动写入旧格式 key（不写索引），verify 应能通过回退路径找到。
#[tokio::test]
#[serial_test::serial]
async fn e4_verify_falls_back_to_legacy_format() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = "deadbeef".repeat(8); // 64 hex chars
    let old_dao_key = format!("garrison:apikey:{}", key);
    let info = ApiKeyInfo {
        login_id: "legacy-user".to_string(),
        scopes: vec!["legacy".into()],
        expire_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600,
        revoked: false,
        namespace: "default".to_string(),
    };
    let value = serde_json::to_string(&info).unwrap();
    dao.set(&old_dao_key, &value, 3600).await.unwrap();
    // 不写入反向索引

    let verified = handler.verify(&key).await.unwrap();
    assert_eq!(
        verified.login_id, "legacy-user",
        "E4: 无索引时应回退到旧格式 garrison:apikey:<key>"
    );
}

/// E4: 验证 `revoke` 在无反向索引时回退到旧格式。
#[tokio::test]
#[serial_test::serial]
async fn e4_revoke_falls_back_to_legacy_format() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = "cafebeef".repeat(8);
    let old_dao_key = format!("garrison:apikey:{}", key);
    let info = ApiKeyInfo {
        login_id: "legacy-revoke".to_string(),
        scopes: vec![],
        expire_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600,
        revoked: false,
        namespace: "default".to_string(),
    };
    let value = serde_json::to_string(&info).unwrap();
    dao.set(&old_dao_key, &value, 3600).await.unwrap();
    // 不写入反向索引

    handler.revoke(&key).await.unwrap();
    let result = handler.verify(&key).await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(_))),
        "E4: revoke 旧格式 key 后 verify 应失败"
    );
}

/// E4: 验证反向索引的 TTL 与主 key 一致。
///
/// 使用 `crate::dao::tests::MockDao`（支持 TTL 跟踪）验证索引和主 key 的
/// 剩余 TTL 接近（均 ≤ timeout 秒）。
#[tokio::test]
#[serial_test::serial]
async fn e4_index_has_same_ttl_as_key() {
    let dao = Arc::new(crate::dao::tests::MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let timeout = 3600i64;
    let key = handler
        .generate_with_namespace("ttl-test", "internal", vec![], timeout)
        .await
        .unwrap();

    let dao_key = format!("garrison:apikey:internal:{}", key);
    let idx_key = format!("garrison:apikey:idx:{}", key);

    let key_ttl = dao.get_timeout(&dao_key).await.unwrap();
    let idx_ttl = dao.get_timeout(&idx_key).await.unwrap();

    assert!(key_ttl.is_some(), "E4: 主 key 应有 TTL");
    assert!(idx_ttl.is_some(), "E4: 反向索引应有 TTL（与主 key 一致）");

    let key_secs = key_ttl.unwrap().as_secs();
    let idx_secs = idx_ttl.unwrap().as_secs();
    // 两者都应 ≤ timeout（刚写入，接近 timeout）
    assert!(
        key_secs <= timeout as u64,
        "E4: 主 key TTL 应 ≤ {}，实际: {}",
        timeout,
        key_secs
    );
    assert!(
        idx_secs <= timeout as u64,
        "E4: 索引 TTL 应 ≤ {}，实际: {}",
        timeout,
        idx_secs
    );
    // 两者差距应 ≤ 2 秒（写入顺序相邻）
    let diff = key_secs.abs_diff(idx_secs);
    assert!(
        diff <= 2,
        "E4: 主 key 与索引的 TTL 差距应 ≤ 2s，实际: {}s",
        diff
    );
}

/// E4: 验证 `rotate` 为新 key 写入反向索引。
///
/// rotate 后：
/// - old_key 应被吊销（verify 失败）
/// - new_key 应有效且反向索引存在
#[tokio::test]
#[serial_test::serial]
async fn e4_rotate_writes_index_for_new_key() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let old_key = handler
        .generate("1001", vec!["read".into()], 3600)
        .await
        .unwrap();

    let new_key = handler.rotate(&old_key).await.unwrap();
    assert_ne!(old_key, new_key);

    // old_key 应被吊销
    let old_result = handler.verify(&old_key).await;
    assert!(old_result.is_err(), "old_key 应被吊销");

    // new_key 应有效
    let info = handler.verify(&new_key).await.unwrap();
    assert_eq!(info.login_id, "1001");

    // new_key 的反向索引应存在
    let new_idx_key = format!("garrison:apikey:idx:{}", new_key);
    let idx_value = dao.get(&new_idx_key).await.unwrap();
    assert!(idx_value.is_some(), "E4: rotate 后新 key 的反向索引应存在");
}

/// E4: 验证多个 namespace 的 key 都有正确的反向索引。
#[tokio::test]
#[serial_test::serial]
async fn e4_multiple_namespaces_all_indexed() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());

    let k1 = handler
        .generate_with_namespace("1001", "internal", vec![], 3600)
        .await
        .unwrap();
    let k2 = handler
        .generate_with_namespace("2002", "partner", vec![], 3600)
        .await
        .unwrap();
    let k3 = handler
        .generate_with_namespace("3003", "default", vec![], 3600)
        .await
        .unwrap();

    // 三个 key 的反向索引都应存在
    for (key, ns) in &[(&k1, "internal"), (&k2, "partner"), (&k3, "default")] {
        let idx_key = format!("garrison:apikey:idx:{}", key);
        let idx_value = dao.get(&idx_key).await.unwrap();
        assert!(
            idx_value.is_some(),
            "E4: namespace={} 的 key 反向索引应存在",
            ns
        );
        let expected_dao_key = format!("garrison:apikey:{}:{}", ns, key);
        assert_eq!(
            idx_value.unwrap(),
            expected_dao_key,
            "E4: namespace={} 的索引 value 应为 {}",
            ns,
            expected_dao_key
        );
    }

    // verify 三个 key 都能通过反向索引找到
    assert_eq!(handler.verify(&k1).await.unwrap().login_id, "1001");
    assert_eq!(handler.verify(&k2).await.unwrap().login_id, "2002");
    assert_eq!(handler.verify(&k3).await.unwrap().login_id, "3003");
}

/// E4: 验证 `verify` 对不存在的 key 返回 InvalidToken（O(1) 路径，无扫描）。
#[tokio::test]
async fn e4_verify_nonexistent_key_returns_invalid_token() {
    let handler = make_handler();
    let result = handler.verify("nonexistent-key-12345").await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(_))),
        "E4: 不存在的 key 应返回 InvalidToken（无扫描），实际: {:?}",
        result
    );
}

/// E4: 验证 `revoke` 对不存在的 key 返回 InvalidToken（O(1) 路径，无扫描）。
#[tokio::test]
async fn e4_revoke_nonexistent_key_returns_invalid_token() {
    let handler = make_handler();
    let result = handler.revoke("nonexistent-key-67890").await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(_))),
        "E4: 不存在的 key 应返回 InvalidToken（无扫描），实际: {:?}",
        result
    );
}

/// E4: 验证索引存在但 dao_key 已被删除时，verify 回退到 legacy 路径。
///
/// 模拟场景：管理员手动 delete 了主 key 但索引残留。verify 应继续查找
/// legacy 格式，最终返回 InvalidToken。
#[tokio::test]
#[serial_test::serial]
async fn e4_verify_falls_through_when_dao_key_deleted() {
    let dao = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao.clone());
    let key = handler
        .generate_with_namespace("1001", "internal", vec![], 3600)
        .await
        .unwrap();

    // 手动删除主 key（保留索引）
    let dao_key = format!("garrison:apikey:internal:{}", key);
    dao.delete(&dao_key).await.unwrap();

    // verify 应回退到 legacy，最终返回 InvalidToken
    let result = handler.verify(&key).await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(_))),
        "E4: 索引存在但主 key 已删除时应返回 InvalidToken，实际: {:?}",
        result
    );
}
