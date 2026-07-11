//! 封禁库 trait 与持久化数据模型定义。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 本模块定义接口契约（`DisableEntry` struct + `DisableRepository` trait）
//! 与默认实现 `DefaultDisableRepository`（持有 `Arc<dyn BulwarkDao>` 委托持久化）。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 封禁条目，记录单个 login_id 在指定 service 上的封禁状态。
///
/// 持久化为 JSON 存储在 DAO 中，key 格式 `disable:{service}:{login_id}`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableEntry {
    /// 被封禁的登录主体标识。
    pub login_id: String,
    /// 封禁服务名称（如 "default"、"payment"），支持多服务独立封禁。
    pub service: String,
    /// 封禁到期时间；`None` 表示永久封禁。
    pub until: Option<DateTime<Utc>>,
    /// 封禁级别（0=普通封禁，1+=阶梯封禁，业务方可据此分级阻断）。
    pub level: u32,
    /// 封禁创建时间。
    pub created_at: DateTime<Utc>,
}

/// 封禁库 trait，提供账号封禁/解封/查询能力。
///
/// 独立于 [`BulwarkDao`](crate::dao::BulwarkDao) trait，通过持有 `Arc<dyn BulwarkDao>` 委托实现。
/// key 格式：`disable:{service}:{login_id}`，value 为 [`DisableEntry`] 的 JSON 序列化。
#[async_trait]
pub trait DisableRepository: Send + Sync {
    /// 封禁指定 login_id 的指定 service。
    ///
    /// # 参数
    /// - `login_id`: 被封禁的登录主体标识。
    /// - `service`: 封禁服务名称。
    /// - `until`: 封禁到期时间；`None` 表示永久封禁。
    /// - `level`: 封禁级别（0=普通，1+=阶梯）。
    /// - `duration_secs`: DAO 存储 TTL（秒）；0 表示永久驻留（不自动过期）。
    async fn disable(
        &self,
        login_id: &str,
        service: &str,
        until: Option<DateTime<Utc>>,
        level: u32,
        duration_secs: u64,
    ) -> BulwarkResult<()>;

    /// 解封指定 login_id 的指定 service。
    ///
    /// # 参数
    /// - `login_id`: 被解封的登录主体标识。
    /// - `service`: 封禁服务名称。
    async fn untie_disable(&self, login_id: &str, service: &str) -> BulwarkResult<()>;

    /// 查询指定 login_id 的指定 service 是否被封禁。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `service`: 封禁服务名称。
    ///
    /// # 返回
    /// - `Ok(true)`: 已封禁。
    /// - `Ok(false)`: 未封禁。
    async fn is_disable(&self, login_id: &str, service: &str) -> BulwarkResult<bool>;

    /// 获取封禁到期时间。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `service`: 封禁服务名称。
    ///
    /// # 返回
    /// - `Ok(Some(time))`: 定时解封时间。
    /// - `Ok(None)`: 永久封禁或未封禁。
    async fn get_disable_time(
        &self,
        login_id: &str,
        service: &str,
    ) -> BulwarkResult<Option<DateTime<Utc>>>;

    /// 获取封禁级别。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `service`: 封禁服务名称。
    ///
    /// # 返回
    /// - `Ok(level)`: 封禁级别（0=普通，1+=阶梯）。
    /// - `Ok(0)`: 未封禁。
    async fn get_disable_level(&self, login_id: &str, service: &str) -> BulwarkResult<u32>;
}

// ============================================================================
// DefaultDisableRepository：基于 BulwarkDao 的默认实现
// ============================================================================

/// 默认封禁库实现，持有 `Arc<dyn BulwarkDao>` 委托持久化。
///
/// key 格式：`disable:{service}:{login_id}`（service 在前，便于按 service 前缀扫描）。
/// value 为 [`DisableEntry`] 的 JSON 序列化。
///
/// # 错误处理
///
/// - 序列化 `DisableEntry` 失败 → `BulwarkError::Internal`
/// - 反序列化 `DisableEntry` 失败 → `BulwarkError::Internal`
/// - DAO 读写失败 → 透传底层 `BulwarkError::Dao`
pub struct DefaultDisableRepository {
    /// DAO 实例，委托持久化封禁条目。
    dao: Arc<dyn BulwarkDao>,
}

impl DefaultDisableRepository {
    /// 创建新的 `DefaultDisableRepository` 实例。
    ///
    /// # 参数
    /// - `dao`: DAO 实例（`Arc<dyn BulwarkDao>`），用于读写封禁条目。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 构造封禁 key：`disable:{service}:{login_id}`。
    ///
    /// service 在前以便按 service 前缀扫描（如 `keys("disable:default:*")`）。
    fn disable_key(service: &str, login_id: &str) -> String {
        format!("disable:{}:{}", service, login_id)
    }
}

#[async_trait]
impl DisableRepository for DefaultDisableRepository {
    async fn disable(
        &self,
        login_id: &str,
        service: &str,
        until: Option<DateTime<Utc>>,
        level: u32,
        duration_secs: u64,
    ) -> BulwarkResult<()> {
        let entry = DisableEntry {
            login_id: login_id.to_string(),
            service: service.to_string(),
            until,
            level,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&entry).map_err(|e| {
            BulwarkError::Internal(format!("序列化 DisableEntry 为 JSON 失败: {}", e))
        })?;
        let key = Self::disable_key(service, login_id);
        self.dao.set(&key, &json, duration_secs).await
    }

    async fn untie_disable(&self, login_id: &str, service: &str) -> BulwarkResult<()> {
        let key = Self::disable_key(service, login_id);
        self.dao.delete(&key).await
    }

    async fn is_disable(&self, login_id: &str, service: &str) -> BulwarkResult<bool> {
        let key = Self::disable_key(service, login_id);
        match self.dao.get(&key).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    async fn get_disable_time(
        &self,
        login_id: &str,
        service: &str,
    ) -> BulwarkResult<Option<DateTime<Utc>>> {
        let key = Self::disable_key(service, login_id);
        match self.dao.get(&key).await? {
            Some(json) => {
                let entry: DisableEntry = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("反序列化 DisableEntry 失败: {}", e))
                })?;
                Ok(entry.until)
            },
            None => Ok(None),
        }
    }

    async fn get_disable_level(&self, login_id: &str, service: &str) -> BulwarkResult<u32> {
        let key = Self::disable_key(service, login_id);
        match self.dao.get(&key).await? {
            Some(json) => {
                let entry: DisableEntry = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("反序列化 DisableEntry 失败: {}", e))
                })?;
                Ok(entry.level)
            },
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    // ========================================================================
    // T016: disable / untie_disable 方法测试
    // ========================================================================

    /// disable 写入：调用 disable 后 DAO 中存在对应 key，value 为合法 DisableEntry JSON。
    #[tokio::test]
    async fn t016_disable_writes_entry_to_dao() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        let until = Utc::now() + chrono::Duration::seconds(3600);
        repo.disable("user:1001", "default", Some(until), 0, 3600)
            .await
            .unwrap();
        let key = "disable:default:user:1001";
        let stored = dao.get(key).await.unwrap();
        assert!(stored.is_some(), "disable 后 DAO 中应存在对应 key");
        let entry: DisableEntry = serde_json::from_str(&stored.unwrap()).unwrap();
        assert_eq!(entry.login_id, "user:1001");
        assert_eq!(entry.service, "default");
        assert_eq!(entry.until, Some(until));
        assert_eq!(entry.level, 0);
    }

    /// untie_disable 删除：disable 后调用 untie_disable，DAO 中 key 不存在。
    #[tokio::test]
    async fn t016_untie_disable_removes_entry_from_dao() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:1002", "default", None, 0, 0)
            .await
            .unwrap();
        let key = "disable:default:user:1002";
        assert!(dao.get(key).await.unwrap().is_some());
        repo.untie_disable("user:1002", "default").await.unwrap();
        assert!(
            dao.get(key).await.unwrap().is_none(),
            "untie_disable 后 DAO 中 key 应不存在"
        );
    }

    /// key 格式验证：disable 后 DAO 中 key 为 `disable:{service}:{login_id}`，
    /// service 在前 login_id 在后（便于按 service 前缀扫描）。
    #[tokio::test]
    async fn t016_disable_key_format_is_service_then_login_id() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:1003", "payment", None, 0, 0)
            .await
            .unwrap();
        // 验证 key 顺序：service 在前，login_id 在后
        let expected_key = "disable:payment:user:1003";
        assert!(
            dao.get(expected_key).await.unwrap().is_some(),
            "key 应为 disable:payment:user:1003（service 在前）"
        );
        // 验证反序 key 不存在
        let wrong_key = "disable:user:1003:payment";
        assert!(
            dao.get(wrong_key).await.unwrap().is_none(),
            "反序 key 不应存在"
        );
    }

    /// 永久封禁 duration_secs=0：disable 传入 duration_secs=0 时，DAO 中 key 永久驻留（无 TTL）。
    #[tokio::test]
    async fn t016_disable_with_zero_duration_is_permanent() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:1004", "default", None, 0, 0)
            .await
            .unwrap();
        let key = "disable:default:user:1004";
        // get_timeout 返回 None 表示永久驻留（无 TTL）
        let timeout = dao.get_timeout(key).await.unwrap();
        assert!(
            timeout.is_none(),
            "duration_secs=0 应为永久驻留，get_timeout 应返回 None"
        );
    }

    /// level 传递：disable 传入 level=2 时，序列化的 JSON 中 level 字段为 2。
    #[tokio::test]
    async fn t016_disable_passes_level_to_entry() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:1005", "default", None, 2, 3600)
            .await
            .unwrap();
        let key = "disable:default:user:1005";
        let stored = dao.get(key).await.unwrap().unwrap();
        let entry: DisableEntry = serde_json::from_str(&stored).unwrap();
        assert_eq!(entry.level, 2, "disable 传入 level=2 应写入 entry.level=2");
    }

    /// 多次 disable 覆盖：对同一 login_id+service 多次 disable，DAO 中只保留最后一次。
    #[tokio::test]
    async fn t016_multiple_disable_overwrites_previous() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        // 第一次 disable(level=1)
        repo.disable("user:1006", "default", None, 1, 0)
            .await
            .unwrap();
        let key = "disable:default:user:1006";
        let entry1: DisableEntry =
            serde_json::from_str(&dao.get(key).await.unwrap().unwrap()).unwrap();
        assert_eq!(entry1.level, 1);
        // 第二次 disable(level=3)
        repo.disable("user:1006", "default", None, 3, 0)
            .await
            .unwrap();
        let entry2: DisableEntry =
            serde_json::from_str(&dao.get(key).await.unwrap().unwrap()).unwrap();
        assert_eq!(entry2.level, 3, "第二次 disable 应覆盖第一次，level 应为 3");
    }

    /// disable 后 is_disable 间接验证：disable 后 is_disable 返回 Ok(true)。
    #[tokio::test]
    async fn t016_disable_then_is_disable_returns_true() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        // 未封禁时 is_disable 返回 false
        assert_eq!(
            repo.is_disable("user:1007", "default").await.unwrap(),
            false,
            "未封禁时 is_disable 应返回 false"
        );
        // disable 后 is_disable 返回 true
        repo.disable("user:1007", "default", None, 0, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.is_disable("user:1007", "default").await.unwrap(),
            true,
            "disable 后 is_disable 应返回 true"
        );
    }

    /// untie_disable 不存在不报错：对未封禁的 login_id 调用 untie_disable 返回 Ok(())。
    #[tokio::test]
    async fn t016_untie_disable_missing_key_returns_ok() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        // 对未封禁的 login_id 调用 untie_disable
        let result = repo.untie_disable("never_disabled", "default").await;
        assert!(
            result.is_ok(),
            "untie_disable 对不存在的 key 应返回 Ok，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // T017: 查询方法 is_disable / get_disable_time / get_disable_level 测试
    // ========================================================================

    /// 未封禁 is_disable=false（service 隔离）：同一 login_id 在 "default" service 被封禁，
    /// 但在 "payment" service 上 is_disable 应返回 false（多 service 独立封禁）。
    #[tokio::test]
    async fn t017_is_disable_returns_false_for_unbanned_service() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        // 在 "default" service 上封禁
        repo.disable("user:2001", "default", None, 0, 0)
            .await
            .unwrap();
        // 同一 login_id 在 "payment" service 上应未封禁
        assert_eq!(
            repo.is_disable("user:2001", "payment").await.unwrap(),
            false,
            "同一 login_id 在未封禁的 service 上 is_disable 应返回 false"
        );
    }

    /// 已封禁 is_disable=true（定时封禁）：disable 传入 until=Some(future) 后
    /// is_disable 返回 Ok(true)。
    #[tokio::test]
    async fn t017_is_disable_returns_true_for_timed_ban() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        let until = Utc::now() + chrono::Duration::seconds(3600);
        repo.disable("user:2002", "default", Some(until), 0, 3600)
            .await
            .unwrap();
        assert_eq!(
            repo.is_disable("user:2002", "default").await.unwrap(),
            true,
            "定时封禁后 is_disable 应返回 true"
        );
    }

    /// get_disable_time 永久封禁返回 None：disable(until=None) 后
    /// get_disable_time 返回 Ok(None)（永久封禁无到期时间）。
    #[tokio::test]
    async fn t017_get_disable_time_returns_none_for_permanent_ban() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:2003", "default", None, 0, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.get_disable_time("user:2003", "default").await.unwrap(),
            None,
            "永久封禁 get_disable_time 应返回 Ok(None)"
        );
    }

    /// get_disable_time 定时封禁返回 Some：disable(until=Some(time)) 后
    /// get_disable_time 返回 Ok(Some(time))，且时间值精确匹配。
    #[tokio::test]
    async fn t017_get_disable_time_returns_some_for_timed_ban() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        let until = Utc::now() + chrono::Duration::seconds(7200);
        repo.disable("user:2004", "default", Some(until), 0, 7200)
            .await
            .unwrap();
        let result = repo.get_disable_time("user:2004", "default").await.unwrap();
        assert_eq!(
            result,
            Some(until),
            "定时封禁 get_disable_time 应返回 Ok(Some(until))，时间值精确匹配"
        );
    }

    /// get_disable_level 正确值：disable(level=2) 后 get_disable_level 返回 Ok(2)。
    #[tokio::test]
    async fn t017_get_disable_level_returns_correct_value() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:2005", "default", None, 2, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.get_disable_level("user:2005", "default")
                .await
                .unwrap(),
            2,
            "disable(level=2) 后 get_disable_level 应返回 Ok(2)"
        );
    }

    /// 反序列化失败返回 Err：手动向 DAO 写入损坏 JSON，get_disable_time 返回 Err(Internal)。
    ///
    /// 覆盖 `serde_json::from_str` 失败路径，验证错误被包装为 `BulwarkError::Internal`。
    #[tokio::test]
    async fn t017_get_disable_time_returns_err_on_deserialize_failure() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        // 手动写入损坏 JSON 到 disable key
        let key = "disable:default:user:2006";
        dao.set(key, "{invalid json}", 0).await.unwrap();
        let result = repo.get_disable_time("user:2006", "default").await;
        assert!(
            matches!(result, Err(BulwarkError::Internal(ref msg)) if msg.contains("反序列化 DisableEntry 失败")),
            "损坏 JSON 应返回 Err(BulwarkError::Internal) 含 '反序列化 DisableEntry 失败'，实际: {:?}",
            result
        );
    }

    /// untie_disable 后 is_disable=false：disable 后 untie_disable，is_disable 返回 Ok(false)。
    #[tokio::test]
    async fn t017_is_disable_returns_false_after_untie_disable() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:2007", "default", None, 0, 0)
            .await
            .unwrap();
        // 封禁后 is_disable 应为 true
        assert_eq!(
            repo.is_disable("user:2007", "default").await.unwrap(),
            true,
            "disable 后 is_disable 应为 true"
        );
        // untie_disable 后 is_disable 应为 false
        repo.untie_disable("user:2007", "default").await.unwrap();
        assert_eq!(
            repo.is_disable("user:2007", "default").await.unwrap(),
            false,
            "untie_disable 后 is_disable 应返回 false"
        );
    }

    /// get_disable_time 未封禁返回 None：未 disable 时 get_disable_time 返回 Ok(None)。
    #[tokio::test]
    async fn t017_get_disable_time_returns_none_when_not_banned() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        assert_eq!(
            repo.get_disable_time("never_banned", "default")
                .await
                .unwrap(),
            None,
            "未封禁时 get_disable_time 应返回 Ok(None)"
        );
    }

    // ========================================================================
    // T018: 阶梯封禁 level 支持测试
    // ========================================================================

    /// level=0 普通封禁：disable(level=0) 后 get_disable_level 返回 Ok(0)。
    ///
    /// 验证默认封禁级别 0（普通封禁）可正确存储与读取。
    #[tokio::test]
    async fn t018_level_zero_normal_ban() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:3001", "default", None, 0, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.get_disable_level("user:3001", "default")
                .await
                .unwrap(),
            0,
            "level=0 普通封禁，get_disable_level 应返回 Ok(0)"
        );
    }

    /// level=1 一级封禁：disable(level=1) 后 get_disable_level 返回 Ok(1)。
    ///
    /// 验证一级阶梯封禁（如限制部分功能）可正确存储与读取。
    #[tokio::test]
    async fn t018_level_one_first_escalation() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:3002", "default", None, 1, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.get_disable_level("user:3002", "default")
                .await
                .unwrap(),
            1,
            "level=1 一级封禁，get_disable_level 应返回 Ok(1)"
        );
    }

    /// level=3 三级封禁：disable(level=3) 后 get_disable_level 返回 Ok(3)。
    ///
    /// 验证三级阶梯封禁（如完全封禁）可正确存储与读取。
    #[tokio::test]
    async fn t018_level_three_full_ban() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:3003", "default", None, 3, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.get_disable_level("user:3003", "default")
                .await
                .unwrap(),
            3,
            "level=3 三级封禁，get_disable_level 应返回 Ok(3)"
        );
    }

    /// get_disable_level 返回正确值（高 level + JSON 持久化验证）：
    /// disable(level=10) 后 get_disable_level 返回 Ok(10)，
    /// 且 DAO 中的 JSON 反序列化后 level 字段也为 10。
    ///
    /// 验证高 level 值无截断/溢出，且 level 字段在 JSON 持久化层正确传递。
    #[tokio::test]
    async fn t018_get_disable_level_returns_correct_high_value() {
        let dao = Arc::new(MockDao::new());
        let repo = DefaultDisableRepository::new(dao.clone());
        repo.disable("user:3004", "default", None, 10, 0)
            .await
            .unwrap();
        // 通过 API 验证
        assert_eq!(
            repo.get_disable_level("user:3004", "default")
                .await
                .unwrap(),
            10,
            "level=10 高级封禁，get_disable_level 应返回 Ok(10) 无截断"
        );
        // 通过直接反序列化 DAO 中的 JSON 验证持久化层正确传递 level 字段
        let key = "disable:default:user:3004";
        let stored = dao.get(key).await.unwrap().unwrap();
        let entry: DisableEntry = serde_json::from_str(&stored).unwrap();
        assert_eq!(
            entry.level, 10,
            "DAO 中的 JSON 反序列化后 level 字段应为 10"
        );
    }
}
