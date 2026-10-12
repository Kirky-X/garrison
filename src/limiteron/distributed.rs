// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `DistributedLimiter` 适配器，用 `GarrisonDao::incr` 实现原子计数。
//!
//! `incr(key, amount)` / `incr_with_ttl(key, amount, ttl)` 通过循环 `dao.incr` amount 次实现。
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
#[cfg(feature = "firewall-ratelimit")]
use limiteron::error::StorageError;
use limiteron::limiters::{DistributedLimiter, Limiter};
use std::sync::Arc;
use std::time::Duration;

use super::errors::map_to_limiter_err;

/// `DistributedLimiter` 适配器，用 `GarrisonDao::incr` 实现计数（`incr` / `incr_with_ttl`
/// 循环 `dao.incr` amount 次实现，原子性声明见模块文档）。
pub struct GarrisonDaoDistributedLimiter {
    pub(super) dao: Arc<dyn GarrisonDao>,
    /// [`Limiter::allow`] 对全局计数器 `_global` 使用的阈值（超过则拒绝）。
    ///
    /// 默认 `u64::MAX`（等效不限制、仅计数，观测模式）；经 [`Self::with_global_threshold`]
    /// 设置真实阈值后才会产生拒绝。
    global_threshold: u64,
}

impl GarrisonDaoDistributedLimiter {
    /// 创建适配器实例（此构造下 [`Limiter::allow`] 等效不限制：阈值 `u64::MAX`，仅计数不拒绝）。
    ///
    /// 需要真实限流请改用 [`Self::with_global_threshold`] 或直接使用 [`Self::atomic_check_and_incr`]。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            dao,
            global_threshold: u64::MAX,
        }
    }

    /// 创建带全局阈值的适配器实例。
    ///
    /// [`Limiter::allow`] 递增 `_global` 后与 `threshold` 比较，超过返回 `Ok(false)`（真实拒绝），未超过返回 `Ok(true)`。
    pub fn with_global_threshold(dao: Arc<dyn GarrisonDao>, threshold: u64) -> Self {
        Self {
            dao,
            global_threshold: threshold,
        }
    }

    /// 原子 check-and-increment（Lua 脚本实现）。
    ///
    /// 原子递增计数器并检查是否超过阈值：调用 `eval_lua` 执行 INCR + EXPIRE Lua 脚本
    /// （Redis 后端原子操作）；返回计数 > 阈值则拒绝（计数已递增，TTL 后自动重置）；
    /// `eval_lua` 返回 `NotImplemented`（非 Redis 后端）时降级到 `incr` + 阈值判断。
    /// 返回 `Ok(true)` 允许（计数 <= 阈值），`Ok(false)` 拒绝（计数 > 阈值）。
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
                // TOCTOU 竞态声明：此降级路径「incr → 比较阈值」整体不原子——`dao.incr` 仅单次
                // 调用原子（无原子 incr 的后端默认实现为 get→update 组合，自身即标注 TOCTOU），
                // 并发下多个调用方可能都观察到 count <= threshold 而超额放行。精确限流必须依赖
                // eval_lua（Redis）或后端原子 CAS 实现；此路径仅为 best-effort 降级，
                // 不应作为精确配额依据。
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

    /// `limiteron::oxcache_lua` 由 limiteron 的 `lua-script` feature 门控，garrison 侧仅
    /// `firewall-ratelimit` 传递启用（`Cargo.toml` `[features]`），故本方法随该 feature
    /// 编译；策略层（同 feature 门控）是唯一调用方。
    #[cfg(feature = "firewall-ratelimit")]
    /// 滑动窗口判定（镜像 limiteron `RedisDistributedLimiter::allow_sliding_window` 的脚本
    /// 契约，供 garrison 防火墙限流策略直连滑窗判定）：以
    /// `limiteron::oxcache_lua::SLIDING_WINDOW_SCRIPT` 经 [`GarrisonDao::eval_lua`] 执行
    /// 原子 read-filter-check-write：`KEYS=[窗口键, {窗口键}:seq]`（hash tag 共置，Redis
    /// Cluster 同 slot）、`ARGV=[window_ms, max_requests]`，返回 `{allowed, count, reset_time}`
    /// （时钟源在脚本内）。`eval_lua` 返回 `NotImplemented`（非 Redis 后端，如 oxcache）时错误
    /// **透传**，由调用方（策略层）决定降级路径——本方法不做内部降级，避免第二份滑动窗口实现。
    /// 错误：`ConfigError`（key 为空或响应形状不符），或透传 `eval_lua` 的错误（含 `NotImplemented`）。
    pub async fn allow_sliding_window(
        &self,
        key: &str,
        window_ms: u64,
        max_requests: u64,
    ) -> Result<(bool, u64, u64), LimiteronError> {
        if key.is_empty() {
            return Err(LimiteronError::ConfigError(
                "strategy-sliding-window-key-empty::".to_string(),
            ));
        }
        let seq_key = format!("{{{key}}}:seq");
        let vals = self
            .dao
            .eval_lua(
                limiteron::oxcache_lua::SLIDING_WINDOW_SCRIPT,
                vec![key.to_string(), seq_key],
                vec![window_ms.to_string(), max_requests.to_string()],
            )
            .await
            .map_err(map_to_limiter_err)?;
        match vals.as_slice() {
            [allowed, count, reset] => {
                let count = count.parse::<u64>().map_err(|_| {
                    LimiteronError::StorageError(StorageError::QueryError(format!(
                        "strategy-sliding-window-count-parse::{}",
                        count
                    )))
                })?;
                let reset = reset.parse::<u64>().unwrap_or(0);
                Ok((allowed == "1", count, reset))
            },
            _ => Err(LimiteronError::StorageError(StorageError::QueryError(
                "strategy-sliding-window-response-length::".to_string(),
            ))),
        }
    }
}

#[async_trait]
impl Limiter for GarrisonDaoDistributedLimiter {
    /// 递增全局计数器 `_global` 并与阈值比较。
    ///
    /// `new` 构造（阈值 `u64::MAX`）仅计数、恒返回 `Ok(true)`（观测模式）；
    /// `with_global_threshold` 构造在 `count > threshold` 时返回 `Ok(false)`（真实拒绝）。
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
    /// `GarrisonDao::incr` 每次仅递增 1 且无 `INCRBY` 语义：单次调用原子，但 `amount > 1`
    /// 时整体递增**非原子**，并发交错可使返回计数偏离单次 `INCRBY` 语义。精确批量递增需后端
    /// 批量接口或 [`Self::atomic_check_and_incr`]（Redis Lua）。
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
    /// 非原子性与 [`Self::incr`] 相同。TTL 语义：按 `GarrisonDao::incr` 契约，`ttl_secs`
    /// 仅在 key 首次创建时生效，已存在的 key 不重置 TTL；循环中每次都传 `ttl_secs` 是循环
    /// 实现下的预期行为，并非双重刷新。
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
            // parse 失败显性化 — 脏数据返回错误而非静默用 0
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
    use crate::dao::InMemoryDao;

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(InMemoryDao::new())
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

    // --- 脏数据显性化测试 ---

    /// DistributedLimiter::get_count 遇到脏数据时返回错误（非静默用 0）。
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
            err_msg.contains("get count parse failed"),
            "错误消息应包含解析失败标识（嵌套错误不经过翻译链，断言取 locale 无关片段），实际: {}",
            err_msg
        );
    }

    // ------------------------------------------------------------------------
    // Redis Lua 脚本原子化限速（check-and-increment）测试
    // ------------------------------------------------------------------------

    /// 并发 100 次 atomic_check_and_incr（阈值 10）结果精确为 10 通过 + 90 拒绝：
    /// 验证经 eval_lua 的原子 check-and-increment，仅前 10 个任务通过（count <= 10），后 90 个被拒。
    #[tokio::test(flavor = "multi_thread")]
    async fn t010_atomic_check_and_incr_concurrent_threshold() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dao = Arc::new(InMemoryDao::new());
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

    /// 单线程连续 5 次 atomic_check_and_incr（阈值 3）— 前 3 通过，后 2 拒绝。
    #[tokio::test]
    async fn t010_atomic_check_and_incr_sequential_threshold() {
        let dao = Arc::new(InMemoryDao::new());
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

    /// eval_lua 默认实现返回 NotImplemented（GarrisonDaoOxcache 不支持 Lua）。
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

    // --- allow_sliding_window：滑窗判定（防火墙限流直连入口，随 feature 门控） ---

    /// 同窗内前 max_requests 个请求放行、第 max_requests+1 个被拒
    /// （MockDao 模拟器识别 ZREMRANGEBYSCORE 模式；count 为判定时窗口计数，
    /// 即 add 前计数，与模拟器/脚本的 check-then-add 语义一致）。
    #[tokio::test]
    #[cfg(feature = "firewall-ratelimit")]
    async fn sliding_window_allows_then_blocks_at_threshold() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());

        for expected_count in 0..3 {
            let (allowed, count, _reset) = limiter
                .allow_sliding_window("rl:ip:10.0.0.1", 60_000, 3)
                .await
                .unwrap();
            assert!(allowed, "计数 {expected_count} 时应放行");
            assert_eq!(count, expected_count, "判定时计数应为 {expected_count}");
        }
        let (allowed, count, _reset) = limiter
            .allow_sliding_window("rl:ip:10.0.0.1", 60_000, 3)
            .await
            .unwrap();
        assert!(!allowed, "第 4 个请求应被拒（达到阈值）");
        assert_eq!(count, 3, "被拒时判定计数应为 3（已达上限）");
    }

    /// 不同 key 相互独立（作用域隔离）。
    #[tokio::test]
    #[cfg(feature = "firewall-ratelimit")]
    async fn sliding_window_keys_are_independent() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        let (a1, _, _) = limiter
            .allow_sliding_window("rl:ip:a", 60_000, 1)
            .await
            .unwrap();
        let (b1, _, _) = limiter
            .allow_sliding_window("rl:ip:b", 60_000, 1)
            .await
            .unwrap();
        assert!(a1 && b1, "不同 key 的首个请求都应放行");
        let (a2, _, _) = limiter
            .allow_sliding_window("rl:ip:a", 60_000, 1)
            .await
            .unwrap();
        assert!(!a2, "key a 达限后被拒");
        let (b2, _, _) = limiter
            .allow_sliding_window("rl:ip:b", 60_000, 1)
            .await
            .unwrap();
        assert!(!b2, "key b 达限后被拒");
    }

    /// 空 key 拒绝（fail-fast，镜像库侧 ConfigError 语义）。
    #[tokio::test]
    #[cfg(feature = "firewall-ratelimit")]
    async fn sliding_window_empty_key_rejected() {
        let limiter = GarrisonDaoDistributedLimiter::new(make_dao());
        let result = limiter.allow_sliding_window("", 60_000, 1).await;
        assert!(
            matches!(result, Err(LimiteronError::ConfigError(_))),
            "空 key 应返回 ConfigError，实际: {:?}",
            result
        );
    }

    /// eval_lua 返回 NotImplemented 时透传（策略层据此走降级路径）。
    #[tokio::test]
    #[cfg(feature = "firewall-ratelimit")]
    async fn sliding_window_not_implemented_passthrough() {
        use crate::dao::tests::MinimalDao;

        let limiter = GarrisonDaoDistributedLimiter::new(Arc::new(MinimalDao::new()));
        let result = limiter.allow_sliding_window("rl:ip:x", 60_000, 1).await;
        assert!(
            matches!(result, Err(LimiteronError::StorageError(_))),
            "NotImplemented 应经 map_to_limiter_err 透传为 StorageError，实际: {:?}",
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
        limiter.incr("zero_key", 3).await.unwrap();
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
    /// InMemoryDao 支持 eval_lua（返回 INCR 结果），验证成功路径。
    #[tokio::test]
    async fn atomic_check_and_incr_eval_lua_success_path() {
        let dao = Arc::new(InMemoryDao::new());
        let limiter = GarrisonDaoDistributedLimiter::new(dao as Arc<dyn GarrisonDao>);

        // 阈值 5，首次 INCR 返回 1 <= 5 → 允许
        let ok = limiter
            .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(ok, "count 1 <= 5 应允许");

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
