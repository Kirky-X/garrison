//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DAO 模块测试与跨模块共享 mock（从 mod.rs 迁移，Rule 25 合规）。

use super::*;
// 兼容层：重导出 mock 模块的 MockDao 与 glob_match，保持旧路径
// `crate::dao::tests::MockDao` / `crate::dao::tests::glob_match` 可用
#[cfg(feature = "protocol-apikey")]
pub(crate) use super::glob_match;
pub use super::MockDao;
use crate::error::GarrisonError;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// ------------------------------------------------------------------------
// GarrisonDaoOxcache keys() 测试（CRIT-001 修复验证）
// 仅在 anomalous-detector-dual + cache-memory/cache-redis 启用时编译
// ------------------------------------------------------------------------
#[cfg(all(
    feature = "anomalous-detector-dual",
    any(feature = "cache-memory", feature = "cache-redis")
))]
mod oxcache_keys_tests {
    use super::*;

    /// 无 key 时 keys() 返回空 Vec。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_oxcache_keys_empty() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let keys = dao.keys("anomalous:login:*").await.unwrap();
        assert!(keys.is_empty(), "无 key 时 keys() 应返回空 Vec");
    }

    /// set 3 个 key，keys("anomalous:login:*") 返回 2 个匹配的 key。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_oxcache_keys_pattern_match() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("anomalous:login:1:1", "v1", 3600).await.unwrap();
        dao.set("anomalous:login:2:2", "v2", 3600).await.unwrap();
        dao.set("other:key", "v3", 3600).await.unwrap();

        let mut keys = dao.keys("anomalous:login:*").await.unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "anomalous:login:1:1".to_string(),
                "anomalous:login:2:2".to_string()
            ],
            "keys() 应返回 2 个匹配 anomalous:login:* 的 key"
        );
    }

    /// TTL 过期后 keys() 返回空且 key_index 已惰性清理。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_oxcache_keys_clears_expired() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("anomalous:login:1:1", "v1", 1).await.unwrap();
        // 等待 TTL 过期（1s + 1s 余量）
        tokio::time::sleep(Duration::from_secs(2)).await;
        let keys = dao.keys("anomalous:login:*").await.unwrap();
        assert!(
            keys.is_empty(),
            "TTL 过期后 keys() 应返回空 Vec（惰性清理）"
        );
        // 再次调用 keys() 验证 key_index 已清理（不会 panic 或残留）
        let keys2 = dao.keys("anomalous:login:*").await.unwrap();
        assert!(keys2.is_empty(), "清理后再次 keys() 仍应返回空");
    }

    /// delete 后 keys() 返回空。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_oxcache_keys_after_delete() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("anomalous:login:1:1", "v1", 3600).await.unwrap();
        let keys = dao.keys("anomalous:login:*").await.unwrap();
        assert_eq!(keys.len(), 1, "set 后应有 1 个 key");
        dao.delete("anomalous:login:1:1").await.unwrap();
        let keys = dao.keys("anomalous:login:*").await.unwrap();
        assert!(keys.is_empty(), "delete 后 keys() 应返回空 Vec");
    }
}

// ------------------------------------------------------------------------
// 契约测试：验证 GarrisonDao trait 行为契约（使用 MockDao）
// 对应 dao-oxcache-basic spec 的 4 个 scenario
// ------------------------------------------------------------------------

/// Scenario: set 与 get 配对。
/// WHEN 调用 set("key1", "value1", 3600) 后 get("key1")
/// THEN 返回 Some("value1")
#[tokio::test]
async fn mock_set_get_pair() {
    let dao = MockDao::new();
    dao.set("key1", "value1", 3600).await.unwrap();
    let got = dao.get("key1").await.unwrap();
    assert_eq!(got, Some("value1".to_string()));
}

/// Scenario: 过期自动删除。
/// WHEN set("key1", "value1", 1) 并等待 2 秒
/// THEN get("key1") 返回 None
#[tokio::test]
async fn mock_expire_auto_delete() {
    let dao = MockDao::new();
    dao.set("key1", "value1", 1).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = dao.get("key1").await.unwrap();
    assert!(got.is_none(), "过期后 get 应返回 None");
}

/// Scenario: delete 删除键。
/// WHEN set("key1", "value1", 3600) 后 delete("key1")
/// THEN get("key1") 返回 None
#[tokio::test]
async fn mock_delete_removes_key() {
    let dao = MockDao::new();
    dao.set("key1", "value1", 3600).await.unwrap();
    dao.delete("key1").await.unwrap();
    let got = dao.get("key1").await.unwrap();
    assert!(got.is_none(), "delete 后 get 应返回 None");
}

/// Scenario: update 更新值（保留 TTL）。
/// WHEN set("key1", "value1", 3600) 后 update("key1", "value2")
/// THEN get("key1") 返回 Some("value2")
/// AND  TTL 保持 3600（不重置）
#[tokio::test]
async fn mock_update_preserves_ttl() {
    let dao = MockDao::new();
    // 用短 TTL 验证 update 不重置 TTL
    dao.set("key1", "value1", 2).await.unwrap();
    // 立即 update（在 TTL 内）
    dao.update("key1", "value2").await.unwrap();
    // 验证值已更新
    let got = dao.get("key1").await.unwrap();
    assert_eq!(got, Some("value2".to_string()));
    // 等待原 TTL 过期（2 秒 + 1 秒余量）
    tokio::time::sleep(Duration::from_secs(3)).await;
    // update 保留了原 TTL，应已过期
    let got = dao.get("key1").await.unwrap();
    assert!(
        got.is_none(),
        "update 不应重置 TTL，原 TTL 过期后应返回 None"
    );
}

/// 验证 update 不存在的键返回错误（Fail Loud 原则）。
#[tokio::test]
async fn mock_update_missing_key_errors() {
    let dao = MockDao::new();
    let result = dao.update("missing", "value").await;
    assert!(
        matches!(result, Err(GarrisonError::Dao(_))),
        "update 不存在的键应返回 Dao 错误"
    );
}

/// 验证 expire 重置过期时间。
#[tokio::test]
async fn mock_expire_resets_ttl() {
    let dao = MockDao::new();
    dao.set("key1", "value1", 1).await.unwrap();
    // 在过期前重置 TTL
    dao.expire("key1", 3600).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    // 原 TTL 已过，但 expire 重置后应仍存在
    let got = dao.get("key1").await.unwrap();
    assert_eq!(got, Some("value1".to_string()));
}

/// 验证 expire 不存在的键返回错误。
#[tokio::test]
async fn mock_expire_missing_key_errors() {
    let dao = MockDao::new();
    let result = dao.expire("missing", 3600).await;
    assert!(
        matches!(result, Err(GarrisonError::Dao(_))),
        "expire 不存在的键应返回 Dao 错误"
    );
}

/// 验证 set(ttl=0) 表示永久驻留。
#[tokio::test]
async fn mock_set_zero_ttl_means_permanent() {
    let dao = MockDao::new();
    dao.set("perm", "value", 0).await.unwrap();
    // 即使等待也不会过期（mock 用 Instant，sleep 仅作示意）
    tokio::time::sleep(Duration::from_millis(10)).await;
    let got = dao.get("perm").await.unwrap();
    assert_eq!(got, Some("value".to_string()));
}

/// 验证 get 不存在的键返回 None（不报错）。
#[tokio::test]
async fn mock_get_missing_returns_none() {
    let dao = MockDao::new();
    let got = dao.get("never_set").await.unwrap();
    assert!(got.is_none());
}

/// 验证 MockDao::default() 等价于 new()。
///
/// 覆盖 MockDao 的 Default trait 实现。
#[tokio::test]
async fn mock_dao_default_equals_new() {
    let dao = MockDao::default();
    dao.set("default_key", "default_value", 60).await.unwrap();
    let got = dao.get("default_key").await.unwrap();
    assert_eq!(got, Some("default_value".to_string()));
}

/// 验证 expire(key, 0) 将键设为永久驻留。
///
/// 覆盖 MockDao::expire 的 `seconds == 0` 分支（expire_at = None）。
#[tokio::test]
async fn mock_expire_zero_seconds_means_permanent() {
    let dao = MockDao::new();
    dao.set("k", "v", 1).await.unwrap();
    // expire(0) 改为永久驻留
    dao.expire("k", 0).await.unwrap();
    // 等待原 TTL 过期
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = dao.get("k").await.unwrap();
    assert_eq!(got, Some("v".to_string()), "expire(0) 应改为永久驻留");
}

// ------------------------------------------------------------------------
// 4 方法扩展测试（v0.4.2 spec dao-garrison-dao）
// ------------------------------------------------------------------------

/// R-001: set_permanent 设置后 get 返回值。
#[tokio::test]
async fn mock_set_permanent_persists_value() {
    let dao = MockDao::new();
    dao.set_permanent("perm_key", "perm_value").await.unwrap();
    let got = dao.get("perm_key").await.unwrap();
    assert_eq!(got, Some("perm_value".to_string()));
}

/// R-001: set_permanent 永久键短时间等待不过期。
#[tokio::test]
async fn mock_set_permanent_does_not_expire_quickly() {
    let dao = MockDao::new();
    dao.set_permanent("perm_key", "perm_value").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let got = dao.get("perm_key").await.unwrap();
    assert_eq!(got, Some("perm_value".to_string()), "永久键不应过期");
}

/// R-002: get_timeout 永久键返回 None。
#[tokio::test]
async fn mock_get_timeout_returns_none_for_permanent_key() {
    let dao = MockDao::new();
    dao.set_permanent("perm", "v").await.unwrap();
    let timeout = dao.get_timeout("perm").await.unwrap();
    assert!(timeout.is_none(), "永久键应返回 None");
}

/// R-002: get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
#[tokio::test]
async fn mock_get_timeout_returns_some_for_ttl_key() {
    let dao = MockDao::new();
    dao.set("ttl_key", "v", 3600).await.unwrap();
    let timeout = dao.get_timeout("ttl_key").await.unwrap();
    assert!(timeout.is_some(), "TTL 键应返回 Some");
    let remaining = timeout.unwrap();
    assert!(
        remaining <= Duration::from_secs(3600),
        "剩余时间应 ≤ 原 TTL"
    );
}

/// R-002: get_timeout 不存在的键返回 None。
#[tokio::test]
async fn mock_get_timeout_returns_none_for_missing_key() {
    let dao = MockDao::new();
    let timeout = dao.get_timeout("missing").await.unwrap();
    assert!(timeout.is_none(), "不存在的键应返回 None");
}

/// R-003: keys("garrison:apikey:*") 返回命名空间下所有 key。
#[tokio::test]
async fn mock_keys_returns_namespace_matches() {
    let dao = MockDao::new();
    dao.set("garrison:apikey:abc123", "v1", 3600).await.unwrap();
    dao.set("garrison:apikey:def456", "v2", 3600).await.unwrap();
    dao.set("garrison:session:xyz", "v3", 3600).await.unwrap();
    let keys = dao.keys("garrison:apikey:*").await.unwrap();
    assert_eq!(keys.len(), 2, "应匹配 2 个 apikey");
    assert!(keys.contains(&"garrison:apikey:abc123".to_string()));
    assert!(keys.contains(&"garrison:apikey:def456".to_string()));
}

/// R-003: keys("*") 返回所有 key。
#[tokio::test]
async fn mock_keys_star_returns_all() {
    let dao = MockDao::new();
    dao.set("k1", "v1", 3600).await.unwrap();
    dao.set("k2", "v2", 3600).await.unwrap();
    let keys = dao.keys("*").await.unwrap();
    assert!(keys.len() >= 2, "应至少返回 2 个 key");
}

/// R-003: keys 无匹配返回空 Vec。
#[tokio::test]
async fn mock_keys_no_match_returns_empty() {
    let dao = MockDao::new();
    dao.set("k1", "v1", 3600).await.unwrap();
    let keys = dao.keys("nonexistent:*").await.unwrap();
    assert!(keys.is_empty(), "无匹配应返回空 Vec");
}

/// R-003: keys 支持 ? 单字符通配符。
#[tokio::test]
async fn mock_keys_supports_question_mark() {
    let dao = MockDao::new();
    dao.set("key1", "v1", 3600).await.unwrap();
    dao.set("key2", "v2", 3600).await.unwrap();
    dao.set("key10", "v3", 3600).await.unwrap();
    let keys = dao.keys("key?").await.unwrap();
    assert_eq!(
        keys.len(),
        2,
        "? 应匹配单个字符，key1/key2 匹配，key10 不匹配"
    );
}

/// R-004: rename 重命名后 old 不存在，new 存在。
#[tokio::test]
async fn mock_rename_moves_key() {
    let dao = MockDao::new();
    dao.set("old_key", "value", 3600).await.unwrap();
    dao.rename("old_key", "new_key").await.unwrap();
    let old = dao.get("old_key").await.unwrap();
    let new = dao.get("new_key").await.unwrap();
    assert!(old.is_none(), "rename 后 old_key 应不存在");
    assert_eq!(new, Some("value".to_string()), "rename 后 new_key 应有值");
}

/// R-004: rename 不存在的 old_key 返回 InvalidParam。
#[tokio::test]
async fn mock_rename_missing_key_returns_invalid_param() {
    let dao = MockDao::new();
    let result = dao.rename("missing", "new").await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(_))),
        "rename 不存在的键应返回 InvalidParam，实际: {:?}",
        result
    );
}

// ------------------------------------------------------------------------
// oxcache 集成测试（feature = "cache-memory" 或 "cache-redis"）
// ------------------------------------------------------------------------

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
mod oxcache_tests {
    use super::*;

    /// Scenario: set 与 get 配对。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_set_get_pair() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_key1", "value1", 3600).await.unwrap();
        let got = dao.get("oc_key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// Scenario: 过期自动删除。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_expire_auto_delete() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_key2", "value1", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("oc_key2").await.unwrap();
        assert!(got.is_none(), "过期后 get 应返回 None");
    }

    /// Scenario: delete 删除键。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_delete_removes_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_key3", "value1", 3600).await.unwrap();
        dao.delete("oc_key3").await.unwrap();
        let got = dao.get("oc_key3").await.unwrap();
        assert!(got.is_none(), "delete 后 get 应返回 None");
    }

    /// 验证 oxcache update 更新值（仅验证值，TTL 保留见 ignore 测试）。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_update_changes_value() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_key4", "value1", 3600).await.unwrap();
        dao.update("oc_key4", "value2").await.unwrap();
        let got = dao.get("oc_key4").await.unwrap();
        assert_eq!(got, Some("value2".to_string()));
    }

    /// 验证 update 不存在的键返回错误。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_update_missing_key_errors() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let result = dao.update("oc_missing", "value").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(_))),
            "update 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 expire 重置过期时间。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_expire_resets_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_key5", "value1", 1).await.unwrap();
        dao.expire("oc_key5", 3600).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("oc_key5").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// 验证 GarrisonDaoOxcache::new() 直接构造（init_oxcache_dao 包装已移除）。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_new_direct_construction() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_init", "init_value", 60).await.unwrap();
        let got = dao.get("oc_init").await.unwrap();
        assert_eq!(got, Some("init_value".to_string()));
    }

    /// Scenario: update 更新值（保留 TTL）。
    ///
    /// oxcache 0.3 的 Cache<K,V> 暴露了 ttl() 方法，update 用 ttl() + set_with_ttl 保留原 TTL。
    ///
    /// 参见：dao-oxcache-basic spec Requirement "GarrisonDao 抽象 trait" Scenario "update 更新值（保留 TTL）"
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_update_preserves_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_ttl", "value1", 2).await.unwrap();
        dao.update("oc_ttl", "value2").await.unwrap();
        // update 保留了原 TTL（2 秒），sleep 后应过期
        tokio::time::sleep(Duration::from_secs(3)).await;
        let got = dao.get("oc_ttl").await.unwrap();
        assert!(
            got.is_none(),
            "update 不应重置 TTL，原 TTL 过期后应返回 None"
        );
    }

    /// 验证 expire(key, 0) 将键设为永久驻留（不删除）。
    ///
    /// 覆盖 GarrisonDaoOxcache::expire 的 `seconds == 0` 分支：
    /// 通过 get + set_with_ttl(None) 实现 0=永久语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_expire_zero_seconds_makes_permanent() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        // 设置短 TTL，键会在 1 秒后过期
        dao.set("oc_perm", "value1", 1).await.unwrap();
        // expire(0) 将键改为永久驻留
        dao.expire("oc_perm", 0).await.unwrap();
        // 等待原 TTL 过期
        tokio::time::sleep(Duration::from_secs(2)).await;
        // 键应仍存在（已改为永久驻留）
        let got = dao.get("oc_perm").await.unwrap();
        assert_eq!(
            got,
            Some("value1".to_string()),
            "expire(0) 应将键改为永久驻留，不应过期"
        );
    }

    /// 验证 expire(0) 对不存在的键返回 Dao 错误。
    ///
    /// 覆盖 GarrisonDaoOxcache::expire 的 `seconds == 0` 分支中
    /// `ok_or_else(|| GarrisonError::Dao(...))` 错误路径。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_expire_zero_seconds_missing_key_errors() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let result = dao.expire("oc_missing_perm", 0).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(_))),
            "expire(0) 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 expire 对不存在的键返回 Dao 错误（seconds > 0 分支）。
    ///
    /// 覆盖 GarrisonDaoOxcache::expire 的 `else` 分支中
    /// `if !updated { return Err(...) }` 错误路径。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_expire_missing_key_errors() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let result = dao.expire("oc_missing_expire", 3600).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-key-missing")),
            "expire 不存在的键应返回含 'dao-key-missing' 的 Dao 错误，实际: {:?}",
            result
        );
    }

    /// 验证 set(ttl=0) 写入永久驻留的键。
    ///
    /// 覆盖 GarrisonDaoOxcache::set 的 `ttl_seconds == 0` 分支（ttl=None）：
    /// 键应永久驻留，不会因短时间等待而过期。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_set_with_zero_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        // set(ttl=0) 表示永久驻留
        dao.set("oc_zero_ttl", "permanent_value", 0).await.unwrap();
        // 等待 2 秒，验证键未过期
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("oc_zero_ttl").await.unwrap();
        assert_eq!(
            got,
            Some("permanent_value".to_string()),
            "set(ttl=0) 应写入永久驻留的键，2 秒后仍应存在"
        );
    }

    // --------------------------------------------------------------------
    // v0.4.2 4 方法扩展测试
    // --------------------------------------------------------------------

    /// R-001: set_permanent 写入永久键，短时间等待不过期。
    ///
    /// 覆盖 GarrisonDaoOxcache::set_permanent 重写实现（用 set_with_ttl_sync(None)）。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_set_permanent_persists_without_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set_permanent("oc_perm", "perm_value").await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("oc_perm").await.unwrap();
        assert_eq!(
            got,
            Some("perm_value".to_string()),
            "set_permanent 应写入永久键，2 秒后仍应存在"
        );
    }

    /// R-002: get_timeout 永久键返回 None。
    ///
    /// 覆盖 GarrisonDaoOxcache::get_timeout 重写实现（用 ttl_sync）。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_get_timeout_returns_none_for_permanent_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set_permanent("oc_perm_ttl", "v").await.unwrap();
        let timeout = dao.get_timeout("oc_perm_ttl").await.unwrap();
        assert!(timeout.is_none(), "永久键应返回 None");
    }

    /// R-002: get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_get_timeout_returns_some_for_ttl_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_ttl_key", "v", 3600).await.unwrap();
        let timeout = dao.get_timeout("oc_ttl_key").await.unwrap();
        assert!(timeout.is_some(), "TTL 键应返回 Some");
        let remaining = timeout.unwrap();
        assert!(
            remaining <= Duration::from_secs(3600),
            "剩余时间应 ≤ 原 TTL"
        );
    }

    /// R-002: get_timeout 不存在的键返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_get_timeout_returns_none_for_missing_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let timeout = dao.get_timeout("oc_missing_ttl").await.unwrap();
        assert!(timeout.is_none(), "不存在的键应返回 None");
    }

    /// R-003: keys 行为取决于 feature gate。
    ///
    /// - 启用 `anomalous-detector-dual`：keys() 通过 key_index 返回匹配的 key 列表
    /// - 未启用 `anomalous-detector-dual`：keys() 返回 NotImplemented（oxcache 不支持原生 key scan）
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_keys_behavior() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_key1", "v1", 3600).await.unwrap();
        let result = dao.keys("oc_*").await;
        #[cfg(feature = "anomalous-detector-dual")]
        {
            let keys = result.expect("anomalous-detector-dual 启用时 keys() 应返回 key 列表");
            assert!(
                keys.iter().any(|k| k.contains("oc_key1")),
                "keys 应包含 oc_key1, 实际: {:?}",
                keys
            );
        }
        #[cfg(not(feature = "anomalous-detector-dual"))]
        {
            assert!(
                matches!(result, Err(GarrisonError::NotImplemented(_))),
                "未启用 anomalous-detector-dual 时 keys() 应返回 NotImplemented, 实际: {:?}",
                result
            );
        }
    }

    /// R-004: rename 重命名后 old 不存在，new 存在。
    ///
    /// 覆盖 GarrisonDaoOxcache::rename 重写实现（用 get → ttl_sync → set_with_ttl_sync → delete）。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_rename_moves_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_old", "value", 3600).await.unwrap();
        dao.rename("oc_old", "oc_new").await.unwrap();
        let old = dao.get("oc_old").await.unwrap();
        let new = dao.get("oc_new").await.unwrap();
        assert!(old.is_none(), "rename 后 oc_old 应不存在");
        assert_eq!(new, Some("value".to_string()), "rename 后 oc_new 应有值");
    }

    /// R-004: rename 不存在的 old_key 返回 InvalidParam。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_rename_missing_key_returns_invalid_param() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let result = dao.rename("oc_missing_old", "oc_new").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "rename 不存在的键应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// R-004: rename 保留原键 TTL（重写实现的核心价值）。
    ///
    /// 验证 GarrisonDaoOxcache::rename 用 ttl_sync + set_with_ttl_sync 保留 TTL，
    /// 而非默认实现的 set_permanent（丢失 TTL）。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_rename_preserves_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        // 设置短 TTL（2 秒）
        dao.set("oc_short_ttl", "value", 2).await.unwrap();
        // rename 到新 key
        dao.rename("oc_short_ttl", "oc_renamed").await.unwrap();
        // 验证新 key 存在
        let got = dao.get("oc_renamed").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        // 等待原 TTL 过期（2 秒 + 1 秒余量）
        tokio::time::sleep(Duration::from_secs(3)).await;
        // rename 保留了原 TTL，应已过期
        let got = dao.get("oc_renamed").await.unwrap();
        assert!(
            got.is_none(),
            "rename 应保留原 TTL，原 TTL 过期后应返回 None"
        );
    }

    /// R-001: oxcache get_and_delete 返回值并删除 key。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_get_and_delete_returns_value_and_removes_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("oc_atomic", "value", 3600).await.unwrap();
        let got = dao.get_and_delete("oc_atomic").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        let after = dao.get("oc_atomic").await.unwrap();
        assert!(after.is_none(), "get_and_delete 后 key 应不存在");
    }

    /// R-001: oxcache get_and_delete 不存在的 key 返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_get_and_delete_missing_returns_none() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let got = dao.get_and_delete("oc_missing").await.unwrap();
        assert!(got.is_none());
    }

    /// R-001: oxcache get_and_delete 并发原子性验证。
    #[tokio::test(flavor = "multi_thread")]
    async fn oxcache_get_and_delete_concurrent_only_one_succeeds() {
        let dao = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
        dao.set("oc_concurrent", "value", 3600).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let d = dao.clone();
            handles.push(tokio::spawn(async move {
                d.get_and_delete("oc_concurrent").await
            }));
        }

        let mut success = 0;
        let mut none_count = 0;
        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                Ok(Some(_)) => success += 1,
                Ok(None) => none_count += 1,
                Err(e) => panic!("get_and_delete 不应返回错误: {:?}", e),
            }
        }

        assert_eq!(success, 1, "并发调用仅一个返回 Some");
        assert_eq!(none_count, 9, "其他 9 个返回 None");
    }

    // --------------------------------------------------------------------
    // 多租户 key 前缀测试
    // --------------------------------------------------------------------

    /// R-tenant-isolation-003: tenant-isolation feature 启用且 TENANT 上下文存在时，
    /// GarrisonDao 的 set/get 实际操作的 key 为 `tenant:{tid}:original_key`。
    ///
    /// 通过公共 API 验证（不直接探测内部存储 key，避免 get 自身再次 prepend 前缀）：
    /// 1. tenant 42 在 TENANT.scope 内 set("shared_key", "tenant_42_value")
    /// 2. 同一 TENANT.scope 内 get("shared_key") 应返回 Some（证明 set/get 用同一前缀）
    /// 3. tenant 1 在另一 TENANT.scope 内 get("shared_key") 应返回 None（证明跨租户隔离）
    /// 4. tenant 1 在另一 TENANT.scope 内 set("shared_key", "tenant_1_value") 应不影响 tenant 42 的值
    #[cfg(feature = "tenant-isolation")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dao_key_prefixed_with_tenant_when_isolation_enabled() {
        use crate::context::tenant::{TenantContext, TenantSource, TENANT};

        let dao = GarrisonDaoOxcache::new().await.unwrap();

        // tenant 42 写入
        let ctx_42 = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };
        TENANT
            .scope(ctx_42.clone(), async {
                dao.set("shared_key", "tenant_42_value", 3600)
                    .await
                    .unwrap();
                // 同租户 get 应命中（证明 set 与 get 用相同前缀 `tenant:42:`）
                let got = dao.get("shared_key").await.unwrap();
                assert_eq!(
                    got,
                    Some("tenant_42_value".to_string()),
                    "同租户 get 应命中 set 写入的值（前缀一致）"
                );
            })
            .await;

        // tenant 1 跨租户访问应隔离
        let ctx_1 = TenantContext {
            tenant_id: 1,
            resolved_from: TenantSource::Header,
        };
        TENANT
            .scope(ctx_1, async {
                // 跨租户 get 应返回 None（key 前缀不同：`tenant:1:` vs `tenant:42:`）
                let got = dao.get("shared_key").await.unwrap();
                assert!(
                    got.is_none(),
                    "跨租户 get 应返回 None（隔离失败），实际: {:?}",
                    got
                );

                // tenant 1 写入同名 key 不应影响 tenant 42
                dao.set("shared_key", "tenant_1_value", 3600).await.unwrap();
                let got_self = dao.get("shared_key").await.unwrap();
                assert_eq!(
                    got_self,
                    Some("tenant_1_value".to_string()),
                    "tenant 1 应读到自己的值"
                );
            })
            .await;

        // 回到 tenant 42 验证值未被 tenant 1 覆盖
        TENANT
            .scope(ctx_42.clone(), async {
                let got = dao.get("shared_key").await.unwrap();
                assert_eq!(
                    got,
                    Some("tenant_42_value".to_string()),
                    "tenant 42 的值不应被 tenant 1 覆盖（隔离失败）"
                );
            })
            .await;
    }

    /// R-tenant-isolation-003: TENANT 上下文不存在时 key 不变（不 panic）。
    ///
    /// 验证：不在 TENANT.scope 内调用 set/get，key 应保持原样（无前缀）。
    #[cfg(feature = "tenant-isolation")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dao_key_unchanged_when_tenant_context_absent() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();

        // 不在 TENANT.scope 内，TENANT.try_get() 返回 Err，key 应保持原样
        dao.set("no_ctx_key", "value", 3600).await.unwrap();
        let got = dao.get("no_ctx_key").await.unwrap();
        assert_eq!(
            got,
            Some("value".to_string()),
            "TENANT 上下文不存在时 key 应保持原样（无前缀）"
        );

        // 带前缀的 key 应返回 None（因 set 时未加前缀）
        let prefixed = dao.get("tenant:0:no_ctx_key").await.unwrap();
        assert!(
            prefixed.is_none(),
            "TENANT 上下文不存在时不应有带前缀的 key"
        );
    }

    /// R-tenant-isolation-003: delete 也应使用带前缀的 key。
    ///
    /// 验证：在 TENANT.scope 内 set 后，用 delete 删除原始 key 应能成功删除
    ///（delete 内部加前缀 `tenant:42:`，与 set 写入的 key 匹配）。
    /// 通过公共 API 验证：delete 后同租户 get 应返回 None。
    #[cfg(feature = "tenant-isolation")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dao_delete_uses_prefixed_key_in_tenant_context() {
        use crate::context::tenant::{TenantContext, TenantSource, TENANT};

        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };

        TENANT
            .scope(ctx, async {
                dao.set("del_key", "value", 3600).await.unwrap();
                // 先确认值已写入
                assert_eq!(
                    dao.get("del_key").await.unwrap(),
                    Some("value".to_string()),
                    "set 后同租户 get 应命中"
                );

                // delete 用原始 key，内部应加前缀匹配到 `tenant:42:del_key`
                dao.delete("del_key").await.unwrap();

                // 同租户 get 应返回 None（证明 delete 命中了带前缀的 key）
                let after = dao.get("del_key").await.unwrap();
                assert!(
                    after.is_none(),
                    "delete 后同租户 get 应返回 None（delete 也加了前缀）"
                );
            })
            .await;
    }
}

// ------------------------------------------------------------------------
// get_and_delete 原子方法测试（v0.4.2 spec protocol-sso-toctou R-001）
// ------------------------------------------------------------------------

/// R-001: get_and_delete 返回值并删除 key。
#[tokio::test]
async fn mock_get_and_delete_returns_value_and_removes_key() {
    let dao = MockDao::new();
    dao.set("atomic_key", "value", 3600).await.unwrap();
    let got = dao.get_and_delete("atomic_key").await.unwrap();
    assert_eq!(got, Some("value".to_string()));
    // key 应已被删除
    let after = dao.get("atomic_key").await.unwrap();
    assert!(after.is_none(), "get_and_delete 后 key 应不存在");
}

/// R-001: get_and_delete 不存在的 key 返回 None。
#[tokio::test]
async fn mock_get_and_delete_missing_returns_none() {
    let dao = MockDao::new();
    let got = dao.get_and_delete("missing").await.unwrap();
    assert!(got.is_none(), "不存在的 key 应返回 None");
}

/// R-001: get_and_delete 并发调用同一 key 仅一个返回 Some（原子性验证）。
///
/// 使用 10 个并发任务同时调用 get_and_delete，仅一个应返回 Some。
/// 这是 TOCTOU 修复的核心验证测试。
#[tokio::test(flavor = "multi_thread")]
async fn mock_get_and_delete_concurrent_only_one_succeeds() {
    let dao = Arc::new(MockDao::new());
    dao.set("concurrent_key", "value", 3600).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let d = dao.clone();
        handles.push(tokio::spawn(async move {
            d.get_and_delete("concurrent_key").await
        }));
    }

    let mut success = 0;
    let mut none_count = 0;
    for handle in handles {
        let result = handle.await.unwrap();
        match result {
            Ok(Some(_)) => success += 1,
            Ok(None) => none_count += 1,
            Err(e) => panic!("get_and_delete 不应返回错误: {:?}", e),
        }
    }

    assert_eq!(success, 1, "并发调用仅一个返回 Some");
    assert_eq!(none_count, 9, "其他 9 个返回 None");
}

// ========================================================================
// 覆盖率补充：GarrisonDao trait 默认方法测试
// ========================================================================

/// 最小化 DAO 实现，只实现 5 个必需方法，不重写任何默认方法。
///
/// 用于验证 trait 默认实现的行为：
/// - `set_permanent` 默认委托 `set(key, value, 0)`
/// - `get_timeout` 默认返回 `NotImplemented`
/// - `keys` 默认返回 `NotImplemented`
/// - `rename` 默认 `get → set_permanent → delete`
pub struct MinimalDao {
    store: Mutex<HashMap<String, String>>,
}

impl Default for MinimalDao {
    fn default() -> Self {
        Self::new()
    }
}

impl MinimalDao {
    /// 创建空的 MinimalDao 实例。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for MinimalDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.store.lock().get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        match self.store.lock().get_mut(key) {
            Some(existing) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(()) // MinimalDao 不支持 TTL，no-op
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
}

/// R-001: `set_permanent` 默认实现委托 `set(key, value, 0)`。
#[tokio::test]
async fn default_set_permanent_delegates_to_set_with_ttl_zero() {
    let dao = MinimalDao::new();
    // 调用默认实现的 set_permanent
    dao.set_permanent("perm_key", "perm_value").await.unwrap();
    // 验证值已写入（通过 get 读取）
    let val = dao.get("perm_key").await.unwrap();
    assert_eq!(val.as_deref(), Some("perm_value"));
}

/// R-002: `get_timeout` 默认实现返回 `NotImplemented`。
#[tokio::test]
async fn default_get_timeout_returns_not_implemented() {
    let dao = MinimalDao::new();
    dao.set("key", "value", 3600).await.unwrap();
    let result = dao.get_timeout("key").await;
    assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
}

/// R-003: `keys` 默认实现返回 `NotImplemented`。
#[tokio::test]
async fn default_keys_returns_not_implemented() {
    let dao = MinimalDao::new();
    dao.set("key1", "v1", 0).await.unwrap();
    let result = dao.keys("*").await;
    assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
}

/// R-004: `rename` 默认实现执行 `get → set_permanent → delete` 三步操作。
#[tokio::test]
async fn default_rename_get_set_permanent_delete() {
    let dao = MinimalDao::new();
    dao.set("old_key", "old_value", 0).await.unwrap();
    // 调用默认实现的 rename
    dao.rename("old_key", "new_key").await.unwrap();
    // 验证 old_key 已被删除
    assert!(dao.get("old_key").await.unwrap().is_none());
    // 验证 new_key 已写入
    assert_eq!(
        dao.get("new_key").await.unwrap().as_deref(),
        Some("old_value")
    );
}

/// R-004: `rename` 对不存在的 key 返回 `InvalidParam`。
#[tokio::test]
async fn default_rename_missing_key_returns_invalid_param() {
    let dao = MinimalDao::new();
    let result = dao.rename("nonexistent", "new_key").await;
    assert!(matches!(result, Err(GarrisonError::InvalidParam(_))));
}

// ========================================================================
// 覆盖率补充：社交账号绑定关系默认实现
// ========================================================================

/// `find_social_binding` 默认实现返回 `NotImplemented`（GarrisonDao 是 KV 缓存抽象，不支持 SQL）。
///
/// 覆盖 trait 默认实现（行 208-218）。
#[tokio::test]
async fn default_find_social_binding_returns_not_implemented() {
    let dao = MinimalDao::new();
    let result = dao.find_social_binding(0, "wechat", "wx_openid").await;
    assert!(
        matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("find_social_binding")),
        "find_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// `insert_social_binding` 默认实现返回 `NotImplemented`。
///
/// 覆盖 trait 默认实现（行 236-249）。
#[tokio::test]
async fn default_insert_social_binding_returns_not_implemented() {
    let dao = MinimalDao::new();
    let result = dao
        .insert_social_binding(0, 1001, "wechat", "wx_openid", None, 1700000000)
        .await;
    assert!(
        matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("insert_social_binding")),
        "insert_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// `compare_and_update_if_greater` 默认实现返回 `NotImplemented`（M2 修复）。
///
/// 默认实现原为 get → parse → compare → set 四步操作，存在 TOCTOU 竞态。
/// M2 修复：改为返回 `NotImplemented`（fail-closed），强制后端重写以使用原子 CAS。
/// 此测试验证 MinimalDao（不重写任何默认方法）调用时返回 NotImplemented。
#[tokio::test]
async fn default_compare_and_update_if_greater_returns_not_implemented() {
    let dao = MinimalDao::new();
    let result = dao.compare_and_update_if_greater("key", 1, 60).await;
    assert!(
        matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("compare_and_update_if_greater")),
        "compare_and_update_if_greater 默认实现应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// `decr` 默认实现返回 `NotImplemented`（M2 修复）。
///
/// 默认实现原为 get → parse → update/delete 三步组合，存在 TOCTOU 竞态：
/// 并发调用同一 key 时多个调用可能基于同一过时 get 值计算新值并覆盖写入，
/// 导致"跨越式递减"（实际递减量大于 1）。`SmsRateLimiter::decrement_counter`
/// 的 flaky test（`concurrent_send_does_not_exceed_limit`）即由此引发。
/// M2 修复：改为返回 `NotImplemented`（fail-closed），与
/// `compare_and_update_if_greater` 对齐，强制后端重写以使用原子 decr。
///
/// 此测试验证 MinimalDao（不重写任何默认方法）调用 decr 时返回 NotImplemented。
#[tokio::test]
async fn default_decr_returns_not_implemented() {
    let dao = MinimalDao::new();
    // 即使 key 存在（get 会返回 Some），decr 默认实现也直接返回 NotImplemented，
    // 不进入 get → parse → update/delete 路径，避免静默引入 TOCTOU 竞态
    dao.set("counter", "5", 60).await.unwrap();
    let result = dao.decr("counter").await;
    assert!(
        matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("decr") && msg.contains("原子 decr")),
        "decr 默认实现应返回 NotImplemented（含 '原子 decr' 提示），实际: {:?}",
        result
    );
    // 验证 key 未被修改（默认实现完全 short-circuit，不执行任何 DAO 操作）
    let after = dao.get("counter").await.unwrap();
    assert_eq!(
        after.as_deref(),
        Some("5"),
        "decr 默认实现 short-circuit 后 key 不应被修改"
    );
}

/// `get_and_delete` 默认实现（非原子 get → delete）在键存在时返回值并删除。
///
/// 覆盖 trait 默认实现（行 182-188）。
#[tokio::test]
async fn default_get_and_delete_returns_value_and_removes_key() {
    let dao = MinimalDao::new();
    dao.set("k1", "v1", 60).await.unwrap();
    let val = dao.get_and_delete("k1").await.unwrap();
    assert_eq!(val, Some("v1".to_string()));
    assert!(dao.get("k1").await.unwrap().is_none());
}

/// `get_and_delete` 默认实现对不存在的键返回 None 且不报错。
#[tokio::test]
async fn default_get_and_delete_missing_key_returns_none() {
    let dao = MinimalDao::new();
    let val = dao.get_and_delete("nope").await.unwrap();
    assert!(val.is_none());
}

// ========================================================================
// Redis 部署模式配置测试
// ========================================================================

/// R-002: RedisConfig::default() 返回 Single 模式，url 为 "redis://127.6379"。
#[test]
fn redis_config_default_returns_single_mode() {
    let config = RedisConfig::default();
    assert_eq!(
        config.mode,
        RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string()
        }
    );
    assert_eq!(config.password, None);
    assert_eq!(config.db, 0);
    assert_eq!(config.connection_timeout_secs, 5);
    assert_eq!(config.pool_size, 10);
}

/// R-002: RedisConfig serde 序列化/反序列化 round-trip。
#[test]
fn redis_config_serde_roundtrip() {
    let config = RedisConfig {
        mode: RedisDeploymentMode::Cluster {
            urls: vec![
                "redis://10.0.0.1:6379".to_string(),
                "redis://10.0.0.2:6379".to_string(),
                "redis://10.0.0.3:6379".to_string(),
            ],
        },
        password: Some("secret".to_string()),
        db: 1,
        connection_timeout_secs: 10,
        pool_size: 20,
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: RedisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.mode, deserialized.mode);
    assert_eq!(config.password, deserialized.password);
    assert_eq!(config.db, deserialized.db);
    assert_eq!(
        config.connection_timeout_secs,
        deserialized.connection_timeout_secs
    );
    assert_eq!(config.pool_size, deserialized.pool_size);
}

/// R-002: RedisConfig serde 用 `#[serde(default)]` 支持部分覆盖。
#[test]
fn redis_config_serde_partial_override() {
    // 仅提供 mode，其余字段应使用 default
    let json = r#"{"mode":{"mode":"cluster","urls":["redis://10.0.0.1:6379"]}}"#;
    let config: RedisConfig = serde_json::from_str(json).unwrap();
    match config.mode {
        RedisDeploymentMode::Cluster { urls } => {
            assert_eq!(urls, vec!["redis://10.0.0.1:6379".to_string()]);
        },
        _ => panic!("期望 Cluster 模式"),
    }
    // 其余字段应为 default 值
    assert_eq!(config.password, None);
    assert_eq!(config.db, 0);
    assert_eq!(config.connection_timeout_secs, 5);
    assert_eq!(config.pool_size, 10);
}

/// R-001: RedisDeploymentMode 各变体 Display 输出可读。
#[test]
fn redis_deployment_mode_display() {
    let single = RedisDeploymentMode::Single {
        url: "redis://127.0.0.1:6379".to_string(),
    };
    assert!(format!("{}", single).contains("single"));
    assert!(format!("{}", single).contains("redis://127.0.0.1:6379"));

    let sentinel = RedisDeploymentMode::Sentinel {
        master_name: "mymaster".to_string(),
        urls: vec!["redis://s1:26379".to_string()],
    };
    let s = format!("{}", sentinel);
    assert!(s.contains("sentinel"));
    assert!(s.contains("mymaster"));

    let cluster = RedisDeploymentMode::Cluster {
        urls: vec!["redis://c1:6379".to_string(), "redis://c2:6379".to_string()],
    };
    let c = format!("{}", cluster);
    assert!(c.contains("cluster"));
    assert!(c.contains("2 nodes"));

    let ms = RedisDeploymentMode::MasterSlave {
        master_url: "redis://master:6379".to_string(),
        slave_urls: vec!["redis://slave1:6379".to_string()],
    };
    let m = format!("{}", ms);
    assert!(m.contains("master-slave"));
    assert!(m.contains("master:6379"));
    assert!(m.contains("1 slaves"));
}

/// R-001: RedisDeploymentMode PartialEq 比较。
#[test]
fn redis_deployment_mode_eq() {
    let a = RedisDeploymentMode::Single {
        url: "redis://127.0.0.1:6379".to_string(),
    };
    let b = RedisDeploymentMode::Single {
        url: "redis://127.0.0.1:6379".to_string(),
    };
    let c = RedisDeploymentMode::Single {
        url: "redis://10.0.0.1:6379".to_string(),
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

/// R-003: with_redis_config builder 方法在 cache-redis feature 下存在并存储配置。
#[cfg(feature = "cache-redis")]
#[tokio::test(flavor = "multi_thread")]
async fn with_redis_config_stores_config() {
    let dao = GarrisonDaoOxcache::new().await.unwrap();
    assert!(
        dao.redis_config().is_none(),
        "新建实例的 redis_config 应为 None"
    );
    let config = RedisConfig {
        mode: RedisDeploymentMode::Sentinel {
            master_name: "mymaster".to_string(),
            urls: vec![
                "redis://s1:26379".to_string(),
                "redis://s2:26379".to_string(),
                "redis://s3:26379".to_string(),
            ],
        },
        password: Some("pass123".to_string()),
        db: 2,
        connection_timeout_secs: 15,
        pool_size: 50,
    };
    let dao = dao.with_redis_config(config);
    let stored = dao.redis_config().expect("with_redis_config 后应有配置");
    assert!(matches!(
        &stored.mode,
        RedisDeploymentMode::Sentinel { master_name, urls }
        if master_name == "mymaster" && urls.len() == 3
    ));
    assert_eq!(stored.password, Some("pass123".to_string()));
    assert_eq!(stored.db, 2);
    assert_eq!(stored.connection_timeout_secs, 15);
    assert_eq!(stored.pool_size, 50);
}

/// R-003: 未调用 with_redis_config 时 redis_config 为 None。
#[cfg(feature = "cache-redis")]
#[tokio::test(flavor = "multi_thread")]
async fn without_redis_config_returns_none() {
    let dao = GarrisonDaoOxcache::new().await.unwrap();
    assert!(
        dao.redis_config().is_none(),
        "未调用 with_redis_config 时 redis_config 应为 None"
    );
}

// ========================================================================
// 覆盖率补充：GarrisonDao trait 默认方法（incr / eval_lua）
// ========================================================================

/// `incr` 默认实现初始化新键为 1。
///
/// 覆盖 trait 默认实现中 `None` 分支（键不存在时 set 初始值 1）。
#[tokio::test]
async fn default_incr_initializes_new_key() {
    let dao = MinimalDao::new();
    let result = dao.incr("counter", 3600).await.unwrap();
    assert_eq!(result, 1, "新键应初始化为 1");
    // 验证值已写入
    let val = dao.get("counter").await.unwrap();
    assert_eq!(val.as_deref(), Some("1"));
}

/// `incr` 默认实现递增已存在键的值。
///
/// 覆盖 trait 默认实现中 `Some` 分支（键存在时 parse + update）。
#[tokio::test]
async fn default_incr_increments_existing_key() {
    let dao = MinimalDao::new();
    dao.set("counter", "5", 3600).await.unwrap();
    let result = dao.incr("counter", 3600).await.unwrap();
    assert_eq!(result, 6, "已存在键 5 应递增为 6");
    // 再次递增
    let result = dao.incr("counter", 3600).await.unwrap();
    assert_eq!(result, 7, "已存在键 6 应递增为 7");
}

/// `incr` 默认实现遇到非数字值时返回 Dao 错误（Rule 12：禁止静默吞掉 parse 失败）。
///
/// 覆盖 trait 默认实现中 `v.parse().map_err(...)` 错误路径。
#[tokio::test]
async fn default_incr_handles_non_numeric_value() {
    let dao = MinimalDao::new();
    dao.set("bad_counter", "not_a_number", 3600).await.unwrap();
    let result = dao.incr("bad_counter", 3600).await;
    assert!(result.is_err(), "非数字值应返回错误而非静默回退到 0");
    match result {
        Err(GarrisonError::Dao(msg)) => {
            assert!(
                msg.contains("incr: 现存值非 u64"),
                "错误消息应指明 parse 失败，实际: {}",
                msg
            );
        },
        other => panic!("期望 Dao 错误（非数字值 parse 失败），实际: {:?}", other),
    }
}

/// `eval_lua` 默认实现返回 `NotImplemented`。
///
/// 覆盖 trait 默认实现（仅 Redis 后端支持 Lua 脚本）。
#[tokio::test]
async fn default_eval_lua_returns_not_implemented() {
    let dao = MinimalDao::new();
    let result = dao
        .eval_lua("return 1", vec!["k".to_string()], vec!["a".to_string()])
        .await;
    assert!(
        matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("eval_lua")),
        "eval_lua 默认实现应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// MinimalDao::default() 等价于 new()。
///
/// 覆盖 MinimalDao 的 Default trait 实现。
#[tokio::test]
async fn minimal_dao_default_equals_new() {
    let dao = MinimalDao::default();
    dao.set("k", "v", 60).await.unwrap();
    let got = dao.get("k").await.unwrap();
    assert_eq!(got.as_deref(), Some("v"));
}
