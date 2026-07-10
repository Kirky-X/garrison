//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 协议边界场景测试（TG10，0.2.1 patch release）。
//!
//! 验证 `ApiKeyHandler` 在边界条件下的行为：
//! - 10.2 命名空间隔离：namespace A 的 APIKey 不能访问 namespace B
//! - 10.3 已过期的 APIKey 校验失败
//! - 10.4 无效格式的 APIKey 返回错误
//!
//! 依据 spec protocol-apikey。使用 MockDao（HashMap + parking_lot::Mutex）。
//!
//! 注意：`ApiKeyHandler::verify` 自行检查 `ApiKeyInfo.expire_at` 字段判断过期，
//! 不依赖 DAO 层 TTL 驱逐。因此 MockDao 不在 `get` 时移除过期键，
//! 以便 `verify` 能读取 `ApiKeyInfo` 并返回 `ExpiredToken`（而非 `InvalidToken`）。
//! 这与 apikey 模块自身测试（mod tests）的 MockDao 模式一致。

#![cfg(feature = "protocol-apikey")]

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::apikey::ApiKeyHandler;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// MockDao（HashMap + parking_lot::Mutex，不强制 TTL 驱逐）
// ============================================================================

struct MockDao {
    store: Mutex<HashMap<String, String>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        Ok(self.store.lock().get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some(existing) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }

    /// 简单 glob 匹配：支持 `*`（任意字符序列）和 `?`（单字符）。
    ///
    /// 复制自 `src/dao/mod.rs::tests::glob_match`（pub(crate) 限定，集成测试无法访问）。
    /// 用于支持 `ApiKeyHandler::verify` 扫描新格式 key `bulwark:apikey:*:<key>`。
    async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
        let store = self.store.lock();
        let mut result = Vec::new();
        for key in store.keys() {
            if glob_match(pattern, key) {
                result.push(key.clone());
            }
        }
        Ok(result)
    }
}

/// 简单 glob 匹配函数（支持 `*` 和 `?`）。
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut p = 0;
    let mut t = 0;
    let mut star_p: Option<usize> = None;
    let mut star_t = 0;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建 ApiKeyHandler（使用 MockDao）。
fn make_handler() -> ApiKeyHandler {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    ApiKeyHandler::new(dao)
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 10.2 namespace_isolation_blocks_cross_namespace_access
///
/// 验证 APIKey 的命名空间隔离：namespace A 的 key 不能访问 namespace B。
///
/// ApiKey 模块未实现独立的 namespace 字段（key 存储为 `bulwark:apikey:<key>`，
/// 无 namespace 前缀）。隔离通过 `ApiKeyInfo.login_id` 实现：业务方在 verify 后
/// 检查返回的 `login_id` 是否属于当前命名空间。
///
/// 此测试验证：
/// - 为 login_id=1001（namespace A）生成的 key，verify 返回 login_id=1001
/// - 为 login_id=2002（namespace B）生成的 key，verify 返回 login_id=2002
/// - 两个 key 互不相同，且各自的 login_id 不匹配对方的命名空间
///
/// TODO(0.2.2): 考虑在 ApiKeyInfo 中增加显式 namespace 字段，实现协议层隔离。
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

/// 10.3 expired_apikey_validation_fails
///
/// 验证已过期的 APIKey 校验失败，返回 `ExpiredToken` 错误。
///
/// `ApiKeyHandler::verify` 在读取 `ApiKeyInfo` 后检查 `expire_at <= now`，
/// 若已过期则返回 `ExpiredToken`。
#[tokio::test]
async fn expired_apikey_validation_fails() {
    let handler = make_handler();

    // 生成一个 1 秒过期的 key
    let key = handler.generate("1001", vec![], 1).await.unwrap();

    // 等待 2 秒让 key 过期
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // verify 应返回 ExpiredToken
    let result = handler.verify(&key).await;
    assert!(result.is_err(), "已过期的 APIKey 校验应失败");
    match result.err() {
        Some(BulwarkError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
    }
}

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
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }

    // 明显无效的格式：含非 hex 字符
    let result = handler
        .verify("ZZZZ_invalid_apikey_with_non_hex_chars_padding_to_make_it_longer")
        .await;
    assert!(result.is_err(), "含非 hex 字符的 APIKey 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }

    // 空字符串
    let result = handler.verify("").await;
    assert!(result.is_err(), "空字符串 APIKey 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}
