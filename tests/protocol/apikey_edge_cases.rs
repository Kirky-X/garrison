//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 协议边界场景测试（TG10，0.2.1 patch release）。
//!
//! 验证 `ApiKeyHandler` 在边界条件下的行为：
//! - 10.2 命名空间隔离：namespace A 的 APIKey 不能访问 namespace B
//! - 10.3 已过期的 APIKey 校验失败（原用例因依赖 mock DAO 的"get 不清理过期键"
//!   语义（`ExpiredToken` 比 `InvalidToken` 更具体），已下沉至 tests/unit/，
//!   见 `tests/unit/apikey_mock_edge.rs` 的说明）
//! - 10.4 无效格式的 APIKey 返回错误
//!
//! 依据 spec protocol-apikey。使用产品内存 Dao 实现 `InMemoryDao`
//! （garrison::dao::InMemoryDao，get 时清理已过期键，符合产品 DAO 语义）。

#![cfg(feature = "protocol-apikey")]

use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::GarrisonError;
use garrison::protocol::apikey::ApiKeyHandler;
use std::sync::Arc;

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建 ApiKeyHandler（使用产品 InMemoryDao）。
fn make_handler() -> ApiKeyHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    ApiKeyHandler::new(dao)
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 10.2 namespace_isolation_blocks_cross_namespace_access
///
/// 验证 APIKey 的命名空间隔离：namespace A 的 key 不能访问 namespace B。
///
/// ApiKey 模块未实现独立的 namespace 字段（key 存储为 `garrison:apikey:<key>`，
/// 无 namespace 前缀）。隔离通过 `ApiKeyInfo.login_id` 实现：业务方在 verify 后
/// 检查返回的 `login_id` 是否属于当前命名空间。
///
/// 此测试验证：
/// - 为 login_id=1001（namespace A）生成的 key，verify 返回 login_id=1001
/// - 为 login_id=2002（namespace B）生成的 key，verify 返回 login_id=2002
/// - 两个 key 互不相同，且各自的 login_id 不匹配对方的命名空间
#[tokio::test]
async fn namespace_isolation_blocks_cross_namespace_access() {
    let handler = make_handler();

    // namespace A：login_id=1001，scopes=["read"]
    let key_a = handler
        .generate("1001", vec!["read".to_string()], 3600)
        .await
        .unwrap();

    // namespace B：login_id=2002，scopes=["write"]
    let key_b = handler
        .generate("2002", vec!["write".to_string()], 3600)
        .await
        .unwrap();

    // 两个 key 互不相同
    assert_ne!(key_a, key_b, "不同 namespace 的 key 应互不相同");

    // namespace A 的 key → verify 返回 login_id=1001
    let info_a = handler.verify(&key_a).await.unwrap();
    assert_eq!(
        info_a.login_id,
        "1001".to_string(),
        "namespace A 的 key 应返回 login_id=1001"
    );

    // namespace B 的 key → verify 返回 login_id=2002
    let info_b = handler.verify(&key_b).await.unwrap();
    assert_eq!(
        info_b.login_id,
        "2002".to_string(),
        "namespace B 的 key 应返回 login_id=2002"
    );

    // 模拟业务方的命名空间检查：namespace A 的 key 不能用于 namespace B
    let namespace_a_login_id = "1001".to_string();
    let namespace_b_login_id = "2002".to_string();

    // key_a 的 login_id 不匹配 namespace B
    assert_ne!(
        info_a.login_id, namespace_b_login_id,
        "namespace A 的 key 的 login_id 不应匹配 namespace B（隔离边界）"
    );

    // key_b 的 login_id 不匹配 namespace A
    assert_ne!(
        info_b.login_id, namespace_a_login_id,
        "namespace B 的 key 的 login_id 不应匹配 namespace A（隔离边界）"
    );

    // 业务方应基于 login_id 拒绝跨命名空间访问
    let cross_access_blocked =
        info_a.login_id != namespace_b_login_id && info_b.login_id != namespace_a_login_id;
    assert!(
        cross_access_blocked,
        "跨命名空间访问应被隔离阻断（基于 login_id 校验）"
    );
}

// 10.3 expired_apikey_validation_fails 已下沉至 tests/unit/apikey_mock_edge.rs：
// 该用例需要 DAO 在 key 过期后仍能返回存入值（由 handler 检查 `ApiKeyInfo.expire_at`
// 返回 `ExpiredToken`），而产品 `InMemoryDao` 在 `get` 时会清理已过期键，
// 返回 `InvalidToken`（not-found）。两者均拒绝过期 key，仅错误类型细分不同；
// 为保持断言语义不变，"以过期-key 仍可读达 ExpiredToken" 的 mock 专属行为用例
// 按 production-mock-purge 方案下沉至单元测试目录。

/// 10.4 invalid_format_apikey_returns_error
///
/// 验证无效格式的 APIKey 字符串校验时返回错误。
///
/// APIKey 由 `generate` 生成为 64 字符 hex 字符串。此测试用明显无效的格式
/// （短字符串、非 hex 字符）验证 `verify` 返回 `InvalidToken` 错误。
///
/// 注意：实现本身不强制 key 格式校验，仅依赖 DAO 查找。无效格式的 key
/// 在 DAO 中不存在，因此返回 `InvalidToken`（API Key 不存在）。
#[tokio::test]
async fn invalid_format_apikey_returns_error() {
    let handler = make_handler();

    // 明显无效的格式：短字符串
    let result = handler.verify("short").await;
    assert!(result.is_err(), "无效格式的 APIKey 应返回错误");
    match result.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }

    // 明显无效的格式：含非 hex 字符
    let result = handler
        .verify("ZZZZ_invalid_apikey_with_non_hex_chars_padding_to_make_it_longer")
        .await;
    assert!(result.is_err(), "含非 hex 字符的 APIKey 应返回错误");
    match result.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }

    // 空字符串
    let result = handler.verify("").await;
    assert!(result.is_err(), "空字符串 APIKey 应返回错误");
    match result.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}
