//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `DistributedLimiter` 适配器，用 `BulwarkDao::incr` 实现原子计数。
//!
//! `incr(key, amount)` 通过循环 `dao.incr(key, 0)` amount 次实现。
//! `incr_with_ttl(key, amount, ttl)` 通过循环 `dao.incr(key, ttl_secs)` amount 次实现。
//! `atomic_check_and_incr` 优先调用 `dao.eval_lua` 执行 Lua 脚本（Redis 后端原子），
//! 非 Redis 后端降级为 `incr` + 阈值判断。

use crate::dao::BulwarkDao;
use crate::error::BulwarkError;
use async_trait::async_trait;
use limiteron::error::LimiteronError;
use limiteron::limiters::{DistributedLimiter, Limiter};
use std::sync::Arc;
use std::time::Duration;

use super::errors::map_to_limiter_err;

/// `DistributedLimiter` 适配器，用 `BulwarkDao::incr` 实现原子计数。
///
/// `incr(key, amount)` 通过循环 `dao.incr(key, 0)` amount 次实现。
/// `incr_with_ttl(key, amount, ttl)` 通过循环 `dao.incr(key, ttl_secs)` amount 次实现。
pub struct BulwarkDaoDistributedLimiter {
    pub(super) dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoDistributedLimiter {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 原子 check-and-increment（Lua 脚本实现）。
    ///
    /// 原子递增计数器并检查是否超过阈值：
    /// 1. 调用 `eval_lua` 执行 INCR + EXPIRE Lua 脚本（Redis 后端原子操作）
    /// 2. 若返回计数 > 阈值，拒绝（计数已递增，TTL 后自动重置）
    /// 3. 若 `eval_lua` 返回 `NotImplemented`（非 Redis 后端），降级到 `incr` + 阈值判断
    ///
    /// # 参数
    /// - `key`: 计数器键。
    /// - `threshold`: 允许的最大计数（超过则拒绝）。
    /// - `ttl`: 计数器窗口 TTL（首次创建时设置）。
    ///
    /// # 返回
    /// - `Ok(true)`: 允许（计数 <= 阈值）。
    /// - `Ok(false)`: 拒绝（计数 > 阈值）。
    pub async fn atomic_check_and_incr(
        &self,
        key: &str,
        threshold: u64,
        ttl: Duration,
    ) -> Result<bool, LimiteronError> {
        const LUA_SCRIPT: &str = "local c=redis.call('INCR',KEYS[1]); if c==1 then redis.call('EXPIRE',KEYS[1],ARGV[2]) end; return c";
        let keys = vec![key.to_string()];
        let args = vec![threshold.to_string(), ttl.as_secs().to_string()];

        match self.dao.eval_lua(LUA_SCRIPT, keys, args).await {
            Ok(values) => {
                let count: u64 = values
                    .first()
                    .ok_or_else(|| {
                        map_to_limiter_err(BulwarkError::Dao("limiter-eval-lua-empty".to_string()))
                    })?
                    .parse()
                    .map_err(|e| {
                        map_to_limiter_err(BulwarkError::Dao(format!(
                            "eval_lua 返回值解析失败: {}",
                            e
                        )))
                    })?;
                Ok(count <= threshold)
            },
            Err(BulwarkError::NotImplemented(_)) => {
                // 降级：非 Redis 后端，用 incr + 阈值判断（进程内原子）
                let count = self
                    .dao
                    .incr(key, ttl.as_secs())
                    .await
                    .map_err(map_to_limiter_err)?;
                Ok(count <= threshold)
            },
            Err(e) => Err(map_to_limiter_err(e)),
        }
    }
}

#[async_trait]
impl Limiter for BulwarkDaoDistributedLimiter {
    async fn allow(&self, cost: u64) -> Result<bool, LimiteronError> {
        // Limiter trait 的 allow 无 key 参数，用固定 key 计数
        // 真正的分布式限流通过 incr + get_count + 阈值判断实现
        self.incr("_global", cost).await?;
        Ok(true)
    }
}

#[async_trait]
impl DistributedLimiter for BulwarkDaoDistributedLimiter {
    async fn incr(&self, key: &str, amount: u64) -> Result<u64, LimiteronError> {
        let mut count = 0u64;
        for _ in 0..amount {
            count = self.dao.incr(key, 0).await.map_err(map_to_limiter_err)?;
        }
        if amount == 0 {
            count = self.get_count(key).await?;
        }
        Ok(count)
    }

    async fn incr_with_ttl(
        &self,
        key: &str,
        amount: u64,
        ttl: Duration,
    ) -> Result<u64, LimiteronError> {
        let ttl_secs = ttl.as_secs();
        let mut count = 0u64;
        for _ in 0..amount {
            count = self
                .dao
                .incr(key, ttl_secs)
                .await
                .map_err(map_to_limiter_err)?;
        }
        if amount == 0 {
            count = self.get_count(key).await?;
        }
        Ok(count)
    }

    async fn get_count(&self, key: &str) -> Result<u64, LimiteronError> {
        match self.dao.get(key).await.map_err(map_to_limiter_err)? {
            None => Ok(0),
            // M-3: parse 失败显性化 — 脏数据返回错误而非静默用 0
            Some(val) => val.parse::<u64>().map_err(|e| {
                map_to_limiter_err(BulwarkError::Dao(format!(
                    "get_count parse 失败 (key={}, val={}): {}",
                    key, val, e
                )))
            }),
        }
    }

    async fn reset(&self, key: &str) -> Result<(), LimiteronError> {
        self.dao.delete(key).await.map_err(map_to_limiter_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn BulwarkDao> {
        Arc::new(MockDao::new())
    }

    // --- BulwarkDaoDistributedLimiter 测试 ---

    #[tokio::test]
    async fn limiter_incr_and_get_count() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());

        let count1 = limiter.incr("test:key", 1).await.unwrap();
        assert_eq!(count1, 1);

        let count2 = limiter.incr("test:key", 1).await.unwrap();
        assert_eq!(count2, 2);

        assert_eq!(limiter.get_count("test:key").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn limiter_incr_with_ttl() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        let count = limiter
            .incr_with_ttl("ttl:key", 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(limiter.get_count("ttl:key").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn limiter_reset() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        limiter.incr("reset:key", 3).await.unwrap();
        assert_eq!(limiter.get_count("reset:key").await.unwrap(), 3);

        limiter.reset("reset:key").await.unwrap();
        assert_eq!(limiter.get_count("reset:key").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn limiter_get_count_nonexistent() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        assert_eq!(limiter.get_count("noexist").await.unwrap(), 0);
    }

    // --- M-3: unwrap_or(0) 静默吞错修复测试 ---

    /// M-3: DistributedLimiter::get_count 遇到脏数据时返回错误（非静默用 0）。
    #[tokio::test]
    async fn m3_limiter_get_count_dirty_data_returns_err() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        limiter
            .dao
            .set("dirty-count-key", "not-a-number", 0)
            .await
            .unwrap();
        let result = limiter.get_count("dirty-count-key").await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    // ------------------------------------------------------------------------
    // T010: Redis Lua 脚本原子化限速（check-and-increment）测试
    // ------------------------------------------------------------------------

    /// T010: 并发 100 次 atomic_check_and_incr（阈值 10）结果精确为 10 通过 + 90 拒绝。
    ///
    /// 验证 BulwarkDaoDistributedLimiter::atomic_check_and_incr 通过 eval_lua 实现
    /// 原子 check-and-increment：100 个并发任务同时调用，仅前 10 个通过（count <= 10），
    /// 后 90 个被拒绝（count > 10）。
    #[tokio::test(flavor = "multi_thread")]
    async fn t010_atomic_check_and_incr_concurrent_threshold() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dao = Arc::new(MockDao::new());
        let limiter = Arc::new(BulwarkDaoDistributedLimiter::new(
            dao as Arc<dyn BulwarkDao>,
        ));

        let key = "rate_limit:t010:concurrent";
        let threshold = 10u64;
        let ttl = Duration::from_secs(60);

        let allowed = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..100 {
            let l = limiter.clone();
            let a = allowed.clone();
            let r = rejected.clone();
            handles.push(tokio::spawn(async move {
                let ok = l
                    .atomic_check_and_incr(key, threshold, ttl)
                    .await
                    .expect("atomic_check_and_incr 不应失败");
                if ok {
                    a.fetch_add(1, Ordering::SeqCst);
                } else {
                    r.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task panicked");
        }

        assert_eq!(
            allowed.load(Ordering::SeqCst),
            10,
            "应精确 10 次通过，实际: {}",
            allowed.load(Ordering::SeqCst)
        );
        assert_eq!(
            rejected.load(Ordering::SeqCst),
            90,
            "应精确 90 次拒绝，实际: {}",
            rejected.load(Ordering::SeqCst)
        );
    }

    /// T010: 单线程连续 5 次 atomic_check_and_incr（阈值 3）— 前 3 通过，后 2 拒绝。
    #[tokio::test]
    async fn t010_atomic_check_and_incr_sequential_threshold() {
        let dao = Arc::new(MockDao::new());
        let limiter = BulwarkDaoDistributedLimiter::new(dao as Arc<dyn BulwarkDao>);

        let key = "rate_limit:t010:seq";
        let threshold = 3u64;
        let ttl = Duration::from_secs(60);

        assert!(limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(!limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(!limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
    }

    /// T010: eval_lua 默认实现返回 NotImplemented（BulwarkDaoOxcache 不支持 Lua）。
    ///
    /// 验证 trait 默认实现：未重写 eval_lua 的实现者调用时返回 NotImplemented。
    #[tokio::test]
    async fn t010_eval_lua_default_returns_not_implemented() {
        use crate::dao::tests::MinimalDao;

        let dao = MinimalDao::new();
        let result = dao
            .eval_lua(
                "return 'test'",
                vec!["k1".to_string()],
                vec!["a1".to_string()],
            )
            .await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "eval_lua 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // --- 补充覆盖：limiter 边界路径 ---

    /// Limiter::allow 始终返回 Ok(true)（全局计数器递增但不拒绝）。
    #[tokio::test]
    async fn limiter_allow_returns_true() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        let result = limiter.allow(3).await;
        assert!(result.is_ok(), "allow 应返回 Ok");
        assert!(result.unwrap(), "allow 应返回 true");
        // 验证全局计数器已递增
        assert!(
            limiter.get_count("_global").await.unwrap() >= 3,
            "_global 计数器应 >= 3"
        );
    }

    /// incr amount=0 时返回当前 count（不递增）。
    #[tokio::test]
    async fn limiter_incr_zero_amount_returns_current_count() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        // 先递增到 3
        limiter.incr("zero_key", 3).await.unwrap();
        // amount=0 应返回当前值 3
        let count = limiter.incr("zero_key", 0).await.unwrap();
        assert_eq!(count, 3, "amount=0 应返回当前 count 而不递增");
    }

    /// incr_with_ttl amount=0 时返回当前 count。
    #[tokio::test]
    async fn limiter_incr_with_ttl_zero_amount_returns_current_count() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        limiter
            .incr_with_ttl("ttl_zero_key", 2, Duration::from_secs(60))
            .await
            .unwrap();
        let count = limiter
            .incr_with_ttl("ttl_zero_key", 0, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(count, 2, "amount=0 应返回当前 count");
    }

    /// atomic_check_and_incr 在 eval_lua 成功时正确判断阈值。
    ///
    /// MockDao 支持 eval_lua（返回 INCR 结果），验证成功路径。
    #[tokio::test]
    async fn atomic_check_and_incr_eval_lua_success_path() {
        let dao = Arc::new(MockDao::new());
        let limiter = BulwarkDaoDistributedLimiter::new(dao as Arc<dyn BulwarkDao>);

        // 阈值 5，首次 INCR 返回 1 <= 5 → 允许
        let ok = limiter
            .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(ok, "count 1 <= 5 应允许");

        // 继续递增到 6 > 5 → 拒绝
        for _ in 0..5 {
            limiter
                .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
                .await
                .unwrap();
        }
        let blocked = limiter
            .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!blocked, "count 7 > 5 应拒绝");
    }
}
