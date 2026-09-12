//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `DistributedLimiter` 适配器，用 `GarrisonDao::incr` 实现原子计数。
//!
//! `incr(key, amount)` 通过循环 `dao.incr(key, 0)` amount 次实现。
//! `incr_with_ttl(key, amount, ttl)` 通过循环 `dao.incr(key, ttl_secs)` amount 次实现。
//! `atomic_check_and_incr` 优先调用 `dao.eval_lua` 执行 Lua 脚本（Redis 后端原子），
//! 非 Redis 后端降级为 `incr` + 阈值判断。
//!
//! # 非原子性声明
//!
//! `GarrisonDao::incr` 每次仅递增 1。`incr` / `incr_with_ttl` 在 `amount > 1` 时
//! 循环调用 DAO：单次调用原子，但**整体递增非原子**——并发调用方的单步调用可交错，
//! 返回计数与最终计数可能偏离单次 `INCRBY` 语义。`amount > 1` 需要精确限流时，
//! 应优先使用 [`GarrisonDaoDistributedLimiter::atomic_check_and_incr`]（Redis Lua 原子）。

use crate::dao::GarrisonDao;
use crate::error::GarrisonError;
use async_trait::async_trait;
use limiteron::error::LimiteronError;
use limiteron::limiters::{DistributedLimiter, Limiter};
use std::sync::Arc;
use std::time::Duration;

use super::errors::map_to_limiter_err;

/// `DistributedLimiter` 适配器，用 `GarrisonDao::incr` 实现原子计数。
///
/// `incr(key, amount)` 通过循环 `dao.incr(key, 0)` amount 次实现。
/// `incr_with_ttl(key, amount, ttl)` 通过循环 `dao.incr(key, ttl_secs)` amount 次实现。
pub struct GarrisonDaoDistributedLimiter {
    pub(super) dao: Arc<dyn GarrisonDao>,
    /// [`Limiter::allow`] 对全局计数器 `_global` 使用的阈值（超过则拒绝）。
    ///
    /// 默认 `u64::MAX`（等效不限制、仅计数），保持与旧版「恒允许」行为兼容；
    /// 通过 [`Self::with_global_threshold`] 设置真实阈值后才会产生拒绝。
    global_threshold: u64,
}

impl GarrisonDaoDistributedLimiter {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    ///
    /// # 注意
    /// 此构造下 [`Limiter::allow`] 等效不限制（阈值 `u64::MAX`，仅计数不拒绝）。
    /// 需要真实限流请改用 [`Self::with_global_threshold`] 或直接使用
    /// [`Self::atomic_check_and_incr`]。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            dao,
            global_threshold: u64::MAX,
        }
    }

    /// 创建带全局阈值的适配器实例。
    ///
    /// [`Limiter::allow`] 递增 `_global` 后与 `threshold` 比较，超过返回
    /// `Ok(false)`（真实拒绝），未超过返回 `Ok(true)`。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    /// - `threshold`: 允许的最大全局计数（超过则拒绝）。
    pub fn with_global_threshold(dao: Arc<dyn GarrisonDao>, threshold: u64) -> Self {
        Self {
            dao,
            global_threshold: threshold,
        }
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
                        map_to_limiter_err(GarrisonError::Dao(
                            "limiter-eval-lua-empty::".to_string(),
                        ))
                    })?
                    .parse()
                    .map_err(|e| {
                        map_to_limiter_err(GarrisonError::Dao(format!(
                            "limiteron-eval-lua-parse-failed::{}",
                            e
                        )))
                    })?;
                Ok(count <= threshold)
            },
            Err(GarrisonError::NotImplemented(_)) => {
                // 降级：非 Redis 后端，用 incr + 阈值判断。
                //
                // TOCTOU 竞态声明：此降级路径「incr → 比较阈值」整体不原子——
                // `dao.incr` 仅单次调用原子（且无原子 incr 的后端默认实现为
                // get→update 组合，自身标注 TOCTOU），并发下多个调用方可能都
                // 观察到 count <= threshold 而超额放行。精确限流必须依赖
                // eval_lua（Redis）或后端原子 CAS 实现；此路径仅为 best-effort
                // 降级，不应作为精确配额依据。
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
impl Limiter for GarrisonDaoDistributedLimiter {
    /// 递增全局计数器 `_global` 并与阈值比较。
    ///
    /// - `new` 构造（阈值 `u64::MAX`）：仅计数，恒返回 `Ok(true)`（向后兼容）。
    /// - `with_global_threshold` 构造：`count > threshold` 时返回 `Ok(false)`（真实拒绝）。
    async fn allow(&self, cost: u64) -> Result<bool, LimiteronError> {
        // Limiter trait 的 allow 无 key 参数，用固定 key 计数
        let count = self.incr("_global", cost).await?;
        Ok(count <= self.global_threshold)
    }
}

#[async_trait]
impl DistributedLimiter for GarrisonDaoDistributedLimiter {
    /// 递增计数器 `amount` 次（每次 +1）。
    ///
    /// # 非原子性声明
    ///
    /// `GarrisonDao::incr` 每次仅递增 1 且无 `INCRBY` 语义，本方法在
    /// `amount > 1` 时循环调用 DAO：单次调用原子，但整体递增**非原子**，
    /// 并发交错可使返回计数偏离单次 `INCRBY` 语义。精确批量递增需后端提供
    /// 批量接口或使用 [`Self::atomic_check_and_incr`]（Redis Lua）。
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

    /// 递增计数器 `amount` 次（每次 +1，首次创建 key 时设置 TTL）。
    ///
    /// # 非原子性声明
    ///
    /// 与 [`Self::incr`] 相同，`amount > 1` 时循环调用 DAO，整体递增非原子。
    ///
    /// # TTL 语义
    ///
    /// 按 `GarrisonDao::incr` 契约，`ttl_secs` 仅在 key 首次创建时生效，已存在
    /// 的 key 不重置 TTL。循环中每次都传 `ttl_secs`：仅第一次调用实际创建 key
    /// 并设置 TTL，后续调用 TTL 参数被后端忽略（这是循环实现下的预期行为，
    /// 并非双重刷新）。
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
                map_to_limiter_err(GarrisonError::Dao(format!(
                    "limiteron-get-count-parse-failed::{}::{}::{}",
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

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(MockDao::new())
    }

    // --- GarrisonDaoDistributedLimiter 测试 ---

    #[tokio::test]
    async fn limiter_incr_and_get_count() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());

        let count1 = limiter.incr("test:key", 1).await.unwrap();
        assert_eq!(count1, 1);

        let count2 = limiter.incr("test:key", 1).await.unwrap();
        assert_eq!(count2, 2);

        assert_eq!(limiter.get_count("test:key").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn limiter_incr_with_ttl() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        let count = limiter
            .incr_with_ttl("ttl:key", 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(limiter.get_count("ttl:key").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn limiter_reset() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        limiter.incr("reset:key", 3).await.unwrap();
        assert_eq!(limiter.get_count("reset:key").await.unwrap(), 3);

        limiter.reset("reset:key").await.unwrap();
        assert_eq!(limiter.get_count("reset:key").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn limiter_get_count_nonexistent() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        assert_eq!(limiter.get_count("noexist").await.unwrap(), 0);
    }

    // --- M-3: unwrap_or(0) 静默吞错修复测试 ---

    /// M-3: DistributedLimiter::get_count 遇到脏数据时返回错误（非静默用 0）。
    #[tokio::test]
    async fn m3_limiter_get_count_dirty_data_returns_err() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        limiter
            .dao
            .set("dirty-count-key", "not-a-number", 0)
            .await
            .unwrap();
        let result = limiter.get_count("dirty-count-key").await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron 计数读取解析失败"),
            "错误消息应包含翻译后的解析失败提示，实际: {}",
            err_msg
        );
    }

    // ------------------------------------------------------------------------
    // T010: Redis Lua 脚本原子化限速（check-and-increment）测试
    // ------------------------------------------------------------------------

    /// T010: 并发 100 次 atomic_check_and_incr（阈值 10）结果精确为 10 通过 + 90 拒绝。
    ///
    /// 验证 GarrisonDaoDistributedLimiter::atomic_check_and_incr 通过 eval_lua 实现
    /// 原子 check-and-increment：100 个并发任务同时调用，仅前 10 个通过（count <= 10），
    /// 后 90 个被拒绝（count > 10）。
    #[tokio::test(flavor = "multi_thread")]
    async fn t010_atomic_check_and_incr_concurrent_threshold() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dao = Arc::new(MockDao::new());
        let limiter = Arc::new(GarrisonDaoDistributedLimiter::new(
            dao as Arc<dyn GarrisonDao>,
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
        let limiter = GarrisonDaoDistributedLimiter::new(dao as Arc<dyn GarrisonDao>);

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

    /// T010: eval_lua 默认实现返回 NotImplemented（GarrisonDaoOxcache 不支持 Lua）。
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
            matches!(result, Err(GarrisonError::NotImplemented(_))),
            "eval_lua 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // --- 补充覆盖：limiter 边界路径 ---

    /// Limiter::allow 默认构造（阈值 u64::MAX）恒返回 Ok(true)，仅计数不拒绝。
    #[tokio::test]
    async fn limiter_allow_returns_true() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        let result = limiter.allow(3).await;
        assert!(result.is_ok(), "allow 应返回 Ok");
        assert!(result.unwrap(), "allow 应返回 true");
        // 验证全局计数器已递增
        assert!(
            limiter.get_count("_global").await.unwrap() >= 3,
            "_global 计数器应 >= 3"
        );
    }

    /// Limiter::allow 设置全局阈值后按 count > threshold 真实拒绝。
    #[tokio::test]
    async fn limiter_allow_with_global_threshold_rejects() {
        let limiter = GarrisonDaoDistributedLimiter::with_global_threshold(make_dao(), 5);
        assert!(limiter.allow(2).await.unwrap(), "count 2 <= 5 应允许");
        assert!(limiter.allow(2).await.unwrap(), "count 4 <= 5 应允许");
        assert!(!limiter.allow(2).await.unwrap(), "count 6 > 5 应拒绝");
        assert!(!limiter.allow(1).await.unwrap(), "count 7 > 5 应继续拒绝");
    }

    /// incr amount > 1 时计数累计正确（非原子性已文档化，此处验证功能语义）。
    #[tokio::test]
    async fn limiter_incr_amount_greater_than_one() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        let count = limiter.incr("batch:key", 5).await.unwrap();
        assert_eq!(count, 5, "amount=5 应累计到 5");
        assert_eq!(limiter.get_count("batch:key").await.unwrap(), 5);
    }

    /// incr amount=0 时返回当前 count（不递增）。
    #[tokio::test]
    async fn limiter_incr_zero_amount_returns_current_count() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        // 先递增到 3
        limiter.incr("zero_key", 3).await.unwrap();
        // amount=0 应返回当前值 3
        let count = limiter.incr("zero_key", 0).await.unwrap();
        assert_eq!(count, 3, "amount=0 应返回当前 count 而不递增");
    }

    /// incr_with_ttl amount=0 时返回当前 count。
    #[tokio::test]
    async fn limiter_incr_with_ttl_zero_amount_returns_current_count() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
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
        let limiter = GarrisonDaoDistributedLimiter::new(dao as Arc<dyn GarrisonDao>);

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
