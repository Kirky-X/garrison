//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 自适应阈值提供器适配器。
//!
//! 包装 limiteron `RuleBasedAdaptiveLimiter` 的 AIMD 阈值调整能力，
//! 为 Garrison 防火墙策略（如 DDoS）提供基于下游 P99 响应时间 + 错误率的动态阈值。
//!
//! # 设计
//!
//! DDoS 等策略的计数逻辑通过 [`GarrisonDaoDistributedLimiter::atomic_check_and_incr`] 完成
//! （fixed window counter 语义），阈值是固定配置值。本适配器将固定阈值替换为
//! limiteron `RuleBasedAdaptiveLimiter` 计算的动态阈值——后者根据下游健康指标
//! 用 AIMD（加性增、乘性减）策略自动收紧或放宽。
//!
//! # 与 limiteron 原生的区别
//!
//! `RuleBasedAdaptiveLimiter` 实现了 `Limiter` trait，通过 `allow(cost)` / `check(key)`
//! 同时做阈值检查和委托内部限流。但 Garrison 的 DDoS 策略用自己的 `atomic_check_and_incr`
//! 做原子计数+检查，不能直接走 `Limiter` trait。因此本适配器仅借用
//! `RuleBasedAdaptiveLimiter` 的 `maybe_adjust` 阈值调整能力（通过 `allow(0)` 触发），
//! 用 [`NoopLimiter`] 作为空操作 inner，避免干扰实际计数。
//!
//! # 示例
//!
//! ```ignore
//! use garrison::limiteron::adaptive::AdaptiveThresholdProvider;
//! use limiteron::limiters::adaptive::AdaptiveConfig;
//! use std::time::Duration;
//!
//! let config = AdaptiveConfig::builder()
//!     .initial_threshold(100)
//!     .min_threshold(10)
//!     .max_threshold(1000)
//!     .target_p99_ms(200.0)
//!     .target_error_rate(0.05)
//!     .build();
//!
//! let provider = AdaptiveThresholdProvider::new(config);
//!
//! // 外部喂入下游指标
//! provider.record_downstream(50.0, false);
//!
//! // 获取当前动态阈值（触发 AIMD 调整）
//! let threshold = provider.current_threshold().await;
//! ```

use async_trait::async_trait;
use limiteron::error::LimiteronError;
use limiteron::limiters::adaptive::{AdaptiveConfig, DownstreamMetrics, RuleBasedAdaptiveLimiter};
use limiteron::limiters::Limiter;
use std::sync::Arc;

/// 空操作限流器，作为 `RuleBasedAdaptiveLimiter` 的 inner。
///
/// `allow` / `check` 总是返回成功，不做任何计数。
/// DDoS 策略的实际计数通过 `atomic_check_and_incr` 完成，
/// 此 inner 仅用于让 `RuleBasedAdaptiveLimiter` 的方法链能正常执行以触发 `maybe_adjust`。
struct NoopLimiter;

#[async_trait]
impl Limiter for NoopLimiter {
    async fn allow(&self, _cost: u64) -> Result<bool, LimiteronError> {
        Ok(true)
    }
}

/// 自适应阈值提供器。
///
/// 包装 limiteron `RuleBasedAdaptiveLimiter`，为 Garrison 防火墙策略提供动态阈值。
///
/// # AIMD 策略
///
/// - **过载**（P99 > target 或 error_rate > target）：阈值乘 `decrease_factor` 收紧
/// - **健康**：阈值乘 `increase_factor` 放宽
/// - 结果 clamp 到 `[min_threshold, max_threshold]`
/// - 冷却期内不调整（防振荡）
///
/// # 线程安全
///
/// `RuleBasedAdaptiveLimiter` 内部用 `AtomicU64`（无锁读）+ `Mutex<Instant>`（冷却判断），
/// 本包装器可直接跨线程共享。
pub struct AdaptiveThresholdProvider {
    inner: RuleBasedAdaptiveLimiter,
}

impl AdaptiveThresholdProvider {
    /// 创建自适应阈值提供器。
    ///
    /// # 参数
    /// - `config`: AIMD 配置（initial/min/max threshold、target P99/error rate、因子等）。
    pub fn new(config: AdaptiveConfig) -> Self {
        let noop: Arc<dyn Limiter> = Arc::new(NoopLimiter);
        let metrics = Arc::new(DownstreamMetrics::new(config.window_size));
        Self {
            inner: RuleBasedAdaptiveLimiter::new(noop, config, metrics),
        }
    }

    /// 触发 AIMD 阈值调整并返回当前动态阈值。
    ///
    /// 内部调用 `allow(0)` 以触发 `maybe_adjust`（`NoopLimiter` 无副作用），
    /// 然后返回 `current_threshold`。调用方应将此阈值用于 `atomic_check_and_incr` 的 threshold 参数。
    ///
    /// # 返回
    /// 当前动态阈值（已 clamp 到 `[min_threshold, max_threshold]`）。
    pub async fn current_threshold(&self) -> u64 {
        // allow(0) 触发 maybe_adjust + 前置检查（0 <= threshold 恒真）
        // NoopLimiter::allow(0) 返回 Ok(true)，无副作用
        let _ = self.inner.allow(0).await;
        self.inner.current_threshold()
    }

    /// 记录下游指标（响应时间 + 是否错误）。
    ///
    /// 外部调用方在每次请求完成后调用此方法喂入指标，
    /// `RuleBasedAdaptiveLimiter` 的 `maybe_adjust` 会基于这些采样点计算 P99 和错误率。
    ///
    /// # 参数
    /// - `response_time_ms`: 本次请求的响应时间（毫秒）。
    /// - `is_error`: 本次请求是否为错误。
    pub fn record_downstream(&self, response_time_ms: f64, is_error: bool) {
        self.inner.record_downstream(response_time_ms, is_error);
    }

    /// 获取下游指标采集器引用。
    ///
    /// 外部可查询当前 P99 响应时间、错误率、采样点数量。
    pub fn metrics(&self) -> &Arc<DownstreamMetrics> {
        self.inner.metrics()
    }

    /// 重置动态阈值为初始值。
    ///
    /// 将 `current_threshold` 恢复为 `config.initial_threshold`，
    /// 同时重置调整时间戳以允许立即进行下一次调整。
    pub fn reset(&self) {
        self.inner.reset();
    }
}

impl std::fmt::Debug for AdaptiveThresholdProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptiveThresholdProvider")
            .field("current_threshold", &self.inner.current_threshold())
            .field("sample_count", &self.inner.metrics().sample_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_config() -> AdaptiveConfig {
        AdaptiveConfig::builder()
            .initial_threshold(100)
            .min_threshold(10)
            .max_threshold(1000)
            .target_p99_ms(200.0)
            .target_error_rate(0.1)
            .increase_factor(1.1)
            .decrease_factor(0.8)
            .adjust_interval(Duration::from_millis(1))
            .cooldown(Duration::from_millis(1))
            .window_size(50)
            .build()
    }

    /// 初始阈值正确返回。
    #[tokio::test]
    async fn initial_threshold() {
        let provider = AdaptiveThresholdProvider::new(make_config());
        assert_eq!(provider.current_threshold().await, 100);
    }

    /// 喂入健康指标后阈值增长。
    #[tokio::test]
    async fn threshold_increases_on_healthy_metrics() {
        let provider = AdaptiveThresholdProvider::new(make_config());
        let initial = provider.current_threshold().await;

        for _ in 0..10 {
            provider.record_downstream(50.0, false);
        }
        std::thread::sleep(Duration::from_millis(5));

        let new_threshold = provider.current_threshold().await;
        assert!(
            new_threshold > initial,
            "健康指标下阈值应增长: {new_threshold} <= {initial}"
        );
    }

    /// 喂入高错误率后阈值降低。
    #[tokio::test]
    async fn threshold_decreases_on_high_error_rate() {
        let provider = AdaptiveThresholdProvider::new(make_config());
        let initial = provider.current_threshold().await;

        for _ in 0..10 {
            provider.record_downstream(50.0, true);
        }
        std::thread::sleep(Duration::from_millis(5));

        let new_threshold = provider.current_threshold().await;
        assert!(
            new_threshold < initial,
            "高错误率下阈值应降低: {new_threshold} >= {initial}"
        );
    }

    /// 喂入高 P99 后阈值降低。
    #[tokio::test]
    async fn threshold_decreases_on_high_p99() {
        let provider = AdaptiveThresholdProvider::new(make_config());
        let initial = provider.current_threshold().await;

        for _ in 0..10 {
            provider.record_downstream(1000.0, false);
        }
        std::thread::sleep(Duration::from_millis(5));

        let new_threshold = provider.current_threshold().await;
        assert!(
            new_threshold < initial,
            "高 P99 下阈值应降低: {new_threshold} >= {initial}"
        );
    }

    /// 阈值不低于 min_threshold。
    #[tokio::test]
    async fn threshold_respects_min() {
        let config = AdaptiveConfig::builder()
            .initial_threshold(20)
            .min_threshold(10)
            .max_threshold(1000)
            .target_p99_ms(1.0)
            .target_error_rate(0.0)
            .decrease_factor(0.1)
            .cooldown(Duration::from_millis(1))
            .build();
        let provider = AdaptiveThresholdProvider::new(config);

        for _ in 0..20 {
            provider.record_downstream(1000.0, true);
        }
        std::thread::sleep(Duration::from_millis(5));

        for _ in 0..5 {
            let _ = provider.current_threshold().await;
            std::thread::sleep(Duration::from_millis(3));
        }

        let threshold = provider.current_threshold().await;
        assert!(threshold >= 10, "阈值不应低于 min: {threshold}");
    }

    /// 阈值不超过 max_threshold。
    #[tokio::test]
    async fn threshold_respects_max() {
        let config = AdaptiveConfig::builder()
            .initial_threshold(900)
            .min_threshold(10)
            .max_threshold(1000)
            .target_p99_ms(10000.0)
            .target_error_rate(1.0)
            .increase_factor(1.5)
            .cooldown(Duration::from_millis(1))
            .build();
        let provider = AdaptiveThresholdProvider::new(config);

        for _ in 0..10 {
            provider.record_downstream(1.0, false);
        }
        std::thread::sleep(Duration::from_millis(5));

        for _ in 0..5 {
            let _ = provider.current_threshold().await;
            std::thread::sleep(Duration::from_millis(3));
        }

        let threshold = provider.current_threshold().await;
        assert!(threshold <= 1000, "阈值不应超过 max: {threshold}");
    }

    /// reset 恢复初始阈值。
    #[tokio::test]
    async fn reset_restores_initial() {
        let provider = AdaptiveThresholdProvider::new(make_config());

        for _ in 0..10 {
            provider.record_downstream(500.0, true);
        }
        std::thread::sleep(Duration::from_millis(5));
        let decreased = provider.current_threshold().await;
        assert!(decreased < 100, "阈值应已降低");

        provider.reset();
        assert_eq!(provider.current_threshold().await, 100);
    }

    /// metrics() 可查询采样点。
    #[tokio::test]
    async fn metrics_accessible() {
        let provider = AdaptiveThresholdProvider::new(make_config());
        provider.record_downstream(100.0, false);
        provider.record_downstream(200.0, true);

        let metrics = provider.metrics();
        assert_eq!(metrics.sample_count(), 2);
        assert!(metrics.p99_response_time() > 0.0);
        assert!((metrics.error_rate() - 0.5).abs() < f64::EPSILON);
    }

    /// Debug trait 输出 current_threshold 和 sample_count。
    #[test]
    fn debug_impl() {
        let provider = AdaptiveThresholdProvider::new(make_config());
        let debug = format!("{:?}", provider);
        assert!(debug.contains("AdaptiveThresholdProvider"));
        assert!(debug.contains("current_threshold"));
    }
}
