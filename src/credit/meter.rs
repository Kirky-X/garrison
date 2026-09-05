//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量引擎。
//!
//! `CreditMeter` 提供 team-level credit 消费、查询、重置 API。
//! 热数据走 KV 缓存（`GarrisonDao`），冷数据走 SQL（可选）。

use crate::credit::config::CreditConfig;
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use crate::credit::error::CreditError;
use crate::credit::error::{CreditConsumeResult, CreditResult, CreditUsage};
#[cfg(feature = "metrics-prometheus")]
use crate::credit::metrics::CreditMetrics;
use crate::credit::storage::{CreditMeta, CreditMeterStorage};
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use crate::credit::CreditConsumptionRecord;
use crate::dao::GarrisonDao;
use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;

/// Credit 计量引擎。
///
/// 提供 team-level credit 消费、查询、重置 API。
/// 热数据走 KV 缓存（`GarrisonDao`），冷数据走 SQL（可选）。
pub struct CreditMeter {
    dao: Arc<dyn GarrisonDao>,
    config: Arc<RwLock<CreditConfig>>,
    storage: CreditMeterStorage,
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<crate::listener::GarrisonListenerManager>>,
    #[cfg(feature = "metrics-prometheus")]
    metrics: Option<Arc<CreditMetrics>>,
}

impl CreditMeter {
    /// 创建计量引擎实例。
    pub fn new(dao: Arc<dyn GarrisonDao>, config: CreditConfig) -> Self {
        let storage = CreditMeterStorage::new(dao.clone());
        Self {
            dao,
            config: Arc::new(RwLock::new(config)),
            storage,
            #[cfg(feature = "listener")]
            listener_manager: None,
            #[cfg(feature = "metrics-prometheus")]
            metrics: None,
        }
    }

    /// 注入监听器管理器（用于广播 CreditConsumed / CreditAlert 事件）。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(
        mut self,
        lm: Arc<crate::listener::GarrisonListenerManager>,
    ) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 注入 Credit 计量指标（用于 Prometheus 可观测性）。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<CreditMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 消费 credit（热路径）。
    ///
    /// 1. 从 `CreditSchedule` 获取 resource weight → `credits = cost * weight`
    /// 2. 检查周期是否过期，过期则重置
    /// 3. KV incr 递增 consumed
    /// 4. 检查是否超过 credit_limit
    /// 5. 计算 usage_percent，检查 alert_thresholds
    /// 6. 更新 meta
    /// 7. 广播事件（若 listener 已注入）
    /// 8. 异步写入 SQL 流水（若 persist_history = true）
    pub async fn consume_credit(
        &self,
        tenant_id: i64,
        resource: &str,
        cost: u64,
    ) -> CreditResult<CreditConsumeResult> {
        let config = self.config.read().clone();
        let credits = cost * config.schedule.weight_for(resource);

        // 检查并执行周期重置
        self.check_and_reset_cycle(tenant_id).await?;

        // 计算 TTL
        let now = Utc::now().naive_utc();
        let window_start = self.storage.get_window_start(tenant_id).await?;
        let cycle_end = config.cycle.cycle_end(window_start, now);
        let ttl = (cycle_end - now.and_utc().timestamp()).max(1) as u64;

        // 递增 consumed
        let new_count = self.storage.incr_consumed(tenant_id, credits, ttl).await?;

        // 检查限额
        let credit_limit = config.credit_limit;
        let allowed = credit_limit == 0 || new_count <= credit_limit;
        let remaining = credit_limit.saturating_sub(new_count);
        let usage_percent = if credit_limit == 0 {
            0.0
        } else {
            (new_count as f64 / credit_limit as f64) * 100.0
        };

        // 检查告警阈值
        let alerts_triggered: Vec<u8> = config
            .alert_thresholds
            .iter()
            .filter(|&&t| usage_percent >= t as f64)
            .copied()
            .collect();

        // 获取/初始化 window_start（Rolling 模式）
        let actual_window_start = match &config.cycle {
            crate::credit::cycle::CreditCycle::Rolling { .. } => {
                let ws = match self.storage.get_window_start(tenant_id).await? {
                    Some(ts) => ts,
                    None => {
                        let ts = now.and_utc().timestamp();
                        self.storage.set_window_start(tenant_id, ts, ttl).await?;
                        ts
                    },
                };
                ws
            },
            _ => config.cycle.cycle_start(window_start, now),
        };

        let cycle_reset_at = config.cycle.cycle_end(
            match &config.cycle {
                crate::credit::cycle::CreditCycle::Rolling { .. } => Some(actual_window_start),
                _ => None,
            },
            now,
        );

        // 更新 meta
        let meta = CreditMeta {
            consumed: new_count,
            limit: credit_limit,
            window_start: actual_window_start,
            window_end: cycle_reset_at,
            cycle: config.cycle.clone(),
        };
        self.storage.set_meta(tenant_id, &meta, ttl).await?;

        // 广播 CreditConsumed 事件
        #[cfg(feature = "listener")]
        self.broadcast_consumed_event(tenant_id, resource, cost, credits, new_count);

        // 广播 CreditAlert 事件
        #[cfg(feature = "listener")]
        for &threshold in &alerts_triggered {
            self.broadcast_alert_event(
                tenant_id,
                threshold,
                usage_percent,
                new_count,
                credit_limit,
            );
        }

        // 记录 Prometheus 指标
        #[cfg(feature = "metrics-prometheus")]
        if let Some(ref metrics) = self.metrics {
            let tid = tenant_id.to_string();
            metrics.record_consumed(&tid, resource, credits);
            metrics.set_remaining(&tid, remaining);
            for &threshold in &alerts_triggered {
                metrics.record_alert(&tid, threshold);
            }
        }

        // 异步写入 SQL 流水
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        if config.persist_history {
            let dao = self.dao.clone();
            let res = resource.to_string();
            let cycle_start = actual_window_start;
            tokio::spawn(async move {
                if let Err(e) = dao
                    .insert_credit_consumption(
                        tenant_id,
                        &res,
                        cost,
                        credits,
                        new_count,
                        cycle_start,
                    )
                    .await
                {
                    tracing::warn!(
                        tenant_id,
                        resource = %res,
                        error = %e,
                        "credit: async persist consumption record failed"
                    );
                }
            });
        }

        Ok(CreditConsumeResult {
            allowed,
            consumed_credits: credits,
            total_consumed: new_count,
            remaining,
            usage_percent,
            alerts_triggered,
            cycle_reset_at,
        })
    }

    /// 查询当前周期 credit 使用情况。
    pub async fn get_credit_usage(&self, tenant_id: i64) -> CreditResult<CreditUsage> {
        let config = self.config.read().clone();
        let now = Utc::now().naive_utc();
        let consumed = self.storage.get_consumed(tenant_id).await?.unwrap_or(0);
        let credit_limit = config.credit_limit;
        let remaining = credit_limit.saturating_sub(consumed);
        let usage_percent = if credit_limit == 0 {
            0.0
        } else {
            (consumed as f64 / credit_limit as f64) * 100.0
        };

        let window_start = self.storage.get_window_start(tenant_id).await?;
        let cycle_start = config.cycle.cycle_start(window_start, now);
        let cycle_reset_at = config.cycle.cycle_end(window_start, now);

        Ok(CreditUsage {
            tenant_id,
            consumed,
            limit: credit_limit,
            remaining,
            usage_percent,
            cycle_start,
            cycle_reset_at,
            cycle: config.cycle,
        })
    }

    /// 手动重置 credit 计数（管理员操作）。
    pub async fn reset_credit(&self, tenant_id: i64) -> CreditResult<()> {
        self.storage.reset(tenant_id).await
    }

    /// 检查并执行周期重置（若当前时间已超过周期边界）。
    ///
    /// 返回 `true` 表示已执行重置，`false` 表示周期未过期。
    pub async fn check_and_reset_cycle(&self, tenant_id: i64) -> CreditResult<bool> {
        let config = self.config.read().clone();
        let now = Utc::now().naive_utc();
        let window_start = self.storage.get_window_start(tenant_id).await?;

        if config.cycle.is_expired(window_start, now) {
            self.storage.reset(tenant_id).await?;
            // Rolling 模式下重置后清除 window_start，下次消费时重新设置
            if let crate::credit::cycle::CreditCycle::Rolling { .. } = &config.cycle {
                let ws_key = format!("credit:{}:window_start", tenant_id);
                let _ = self.dao.delete(&ws_key).await;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 查询历史消费流水（SQL）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    pub async fn get_usage_history(
        &self,
        tenant_id: i64,
        from_ts: i64,
        to_ts: i64,
    ) -> CreditResult<Vec<CreditConsumptionRecord>> {
        let records = self
            .dao
            .query_credit_consumption(tenant_id, from_ts, to_ts)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-query-history::{}", e)))?;
        Ok(records
            .into_iter()
            .map(|r| CreditConsumptionRecord {
                tenant_id: r.0,
                resource: r.1,
                cost: r.2,
                credits: r.3,
                total_consumed: r.4,
                cycle_start: r.5,
                created_at: r.6,
            })
            .collect())
    }

    /// 广播 CreditConsumed 事件。
    #[cfg(feature = "listener")]
    fn broadcast_consumed_event(
        &self,
        tenant_id: i64,
        resource: &str,
        cost: u64,
        credits: u64,
        total_consumed: u64,
    ) {
        if let Some(lm) = &self.listener_manager {
            let event = crate::listener::GarrisonEvent::CreditConsumed {
                tenant_id,
                resource: resource.to_string(),
                cost,
                credits,
                total_consumed,
                request_context: None,
            };
            // broadcast 是 async，spawn 避免阻塞消费热路径
            let lm = lm.clone();
            tokio::spawn(async move {
                lm.broadcast(&event).await;
            });
        }
    }

    /// 广播 CreditAlert 事件。
    #[cfg(feature = "listener")]
    fn broadcast_alert_event(
        &self,
        tenant_id: i64,
        threshold: u8,
        usage_percent: f64,
        total_consumed: u64,
        credit_limit: u64,
    ) {
        if let Some(lm) = &self.listener_manager {
            let event = crate::listener::GarrisonEvent::CreditAlert {
                tenant_id,
                threshold,
                usage_percent,
                total_consumed,
                credit_limit,
                request_context: None,
            };
            let lm = lm.clone();
            tokio::spawn(async move {
                lm.broadcast(&event).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::config::CreditConfig;
    use crate::credit::cycle::CreditCycle;
    use crate::credit::schedule::CreditSchedule;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(MockDao::new())
    }

    fn make_config(limit: u64) -> CreditConfig {
        CreditConfig {
            credit_limit: limit,
            cycle: CreditCycle::Rolling { days: 30 },
            schedule: CreditSchedule::default(),
            alert_thresholds: vec![80, 90, 100],
            persist_history: false,
        }
    }

    /// 限额内消费应允许。
    #[tokio::test]
    async fn test_consume_within_limit_allowed() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        let result = meter.consume_credit(42, "login", 5).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.consumed_credits, 5);
        assert_eq!(result.total_consumed, 5);
        assert_eq!(result.remaining, 95);
    }

    /// 超限消费应拒绝。
    #[tokio::test]
    async fn test_consume_exceeds_limit_denied() {
        let meter = CreditMeter::new(make_dao(), make_config(10));
        // 消费 10 次
        for _ in 0..10 {
            let r = meter.consume_credit(42, "login", 1).await.unwrap();
            assert!(r.allowed);
        }
        // 第 11 次超限
        let result = meter.consume_credit(42, "login", 1).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    /// 带权重的消费：resource="sms" weight=5, cost=1 → credits=5。
    #[tokio::test]
    async fn test_consume_with_weight_schedule() {
        let mut schedule = CreditSchedule::new();
        schedule.insert("sms", 5);
        let config = CreditConfig {
            credit_limit: 100,
            cycle: CreditCycle::Rolling { days: 30 },
            schedule,
            alert_thresholds: vec![80],
            persist_history: false,
        };
        let meter = CreditMeter::new(make_dao(), config);
        let result = meter.consume_credit(42, "sms", 1).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.consumed_credits, 5);
        assert_eq!(result.total_consumed, 5);
    }

    /// 使用率达到 80% 时触发告警。
    #[tokio::test]
    async fn test_consume_triggers_alert_at_threshold() {
        let meter = CreditMeter::new(make_dao(), make_config(10));
        // 消费 8 次 → 80%
        let result = meter.consume_credit(42, "login", 8).await.unwrap();
        assert!(result.allowed);
        assert!(
            result.alerts_triggered.contains(&80),
            "80% 应触发告警，alerts: {:?}",
            result.alerts_triggered
        );
    }

    /// 多级告警阈值同时触发。
    #[tokio::test]
    async fn test_consume_multiple_alert_thresholds() {
        let meter = CreditMeter::new(make_dao(), make_config(10));
        // 消费 10 次 → 100%
        let result = meter.consume_credit(42, "login", 10).await.unwrap();
        assert!(result.allowed);
        assert!(result.alerts_triggered.contains(&80));
        assert!(result.alerts_triggered.contains(&90));
        assert!(result.alerts_triggered.contains(&100));
    }

    /// credit_limit = 0 时不限制。
    #[tokio::test]
    async fn test_credit_limit_zero_unlimited() {
        let meter = CreditMeter::new(make_dao(), make_config(0));
        let result = meter.consume_credit(42, "login", 1000).await.unwrap();
        assert!(result.allowed, "limit=0 应不限制");
    }

    /// get_credit_usage 返回当前状态。
    #[tokio::test]
    async fn test_get_credit_usage_returns_current_state() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        meter.consume_credit(42, "login", 10).await.unwrap();
        let usage = meter.get_credit_usage(42).await.unwrap();
        assert_eq!(usage.tenant_id, 42);
        assert_eq!(usage.consumed, 10);
        assert_eq!(usage.limit, 100);
        assert_eq!(usage.remaining, 90);
    }

    /// reset_credit 清除所有计数。
    #[tokio::test]
    async fn test_reset_credit_clears_all() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        meter.consume_credit(42, "login", 50).await.unwrap();
        meter.reset_credit(42).await.unwrap();
        let usage = meter.get_credit_usage(42).await.unwrap();
        assert_eq!(usage.consumed, 0);
    }

    /// 恰好消费到限额（total == limit）仍应允许，remaining = 0，usage = 100%。
    #[tokio::test]
    async fn test_consume_exactly_at_limit_allowed() {
        let meter = CreditMeter::new(make_dao(), make_config(10));
        let result = meter.consume_credit(42, "login", 10).await.unwrap();
        assert!(result.allowed, "恰好到达限额应允许（<= 语义）");
        assert_eq!(result.remaining, 0);
        assert!((result.usage_percent - 100.0).abs() < f64::EPSILON);
    }

    /// 超限后 usage_percent > 100%，remaining 饱和到 0。
    #[tokio::test]
    async fn test_consume_over_limit_usage_percent_and_remaining() {
        let meter = CreditMeter::new(make_dao(), make_config(10));
        meter.consume_credit(42, "login", 10).await.unwrap();
        let result = meter.consume_credit(42, "login", 5).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0, "remaining 应饱和为 0");
        assert!(
            result.usage_percent > 100.0,
            "usage: {}",
            result.usage_percent
        );
        assert_eq!(result.total_consumed, 15);
    }

    /// cost = 0 的消费：credits = 0，不递增计数，允许通过。
    #[tokio::test]
    async fn test_consume_zero_cost() {
        let meter = CreditMeter::new(make_dao(), make_config(10));
        let result = meter.consume_credit(42, "login", 0).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.consumed_credits, 0);
        assert_eq!(result.total_consumed, 0);
        assert_eq!(result.remaining, 10);
        assert!(result.alerts_triggered.is_empty(), "0% 不应触发任何告警");
    }

    /// 权重为 0 的 schedule：credits = cost * 0 = 0，允许通过。
    #[tokio::test]
    async fn test_consume_zero_weight_resource() {
        let config = CreditConfig {
            credit_limit: 10,
            cycle: CreditCycle::Rolling { days: 30 },
            schedule: CreditSchedule::with_default(0),
            alert_thresholds: vec![80],
            persist_history: false,
        };
        let meter = CreditMeter::new(make_dao(), config);
        let result = meter.consume_credit(42, "anything", 5).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.consumed_credits, 0);
    }

    /// credit_limit = 0（不限额）时 usage_percent 恒为 0.0。
    #[tokio::test]
    async fn test_get_usage_limit_zero_usage_percent_zero() {
        let meter = CreditMeter::new(make_dao(), make_config(0));
        meter.consume_credit(42, "login", 1000).await.unwrap();
        let usage = meter.get_credit_usage(42).await.unwrap();
        assert_eq!(
            usage.usage_percent, 0.0,
            "limit=0 时 usage_percent 应为 0.0"
        );
        assert_eq!(usage.remaining, 0);
        assert_eq!(usage.limit, 0);
    }

    /// get_credit_usage 在无任何消费时返回全零状态。
    #[tokio::test]
    async fn test_get_credit_usage_fresh_tenant() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        let usage = meter.get_credit_usage(42).await.unwrap();
        assert_eq!(usage.consumed, 0);
        assert_eq!(usage.remaining, 100);
        assert_eq!(usage.usage_percent, 0.0);
        assert_eq!(usage.cycle, CreditCycle::Rolling { days: 30 });
    }

    /// Fixed 周期消费：cycle_reset_at 为未来时间且 day-of-month 等于配置值。
    #[tokio::test]
    async fn test_consume_fixed_cycle_reset_at() {
        let config = CreditConfig {
            credit_limit: 100,
            cycle: CreditCycle::Fixed { day_of_month: 15 },
            schedule: CreditSchedule::default(),
            alert_thresholds: vec![80],
            persist_history: false,
        };
        let meter = CreditMeter::new(make_dao(), config);
        let result = meter.consume_credit(42, "login", 1).await.unwrap();
        let now_ts = Utc::now().timestamp();
        assert!(
            result.cycle_reset_at > now_ts,
            "reset_at {} 应在未来（now {}）",
            result.cycle_reset_at,
            now_ts
        );
        use chrono::TimeZone;
        let reset = Utc.timestamp_opt(result.cycle_reset_at, 0).unwrap();
        assert_eq!(chrono::Datelike::day(&reset), 15, "重置日应为配置的 15 号");
        assert_eq!(
            reset.time(),
            chrono::NaiveTime::MIN,
            "重置时间应为 00:00 UTC"
        );
    }

    /// Rolling 周期：cycle_reset_at = window_start + days * 86400。
    #[tokio::test]
    async fn test_consume_rolling_cycle_reset_at() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        let result = meter.consume_credit(42, "login", 1).await.unwrap();
        let window_start = meter
            .storage
            .get_window_start(42)
            .await
            .unwrap()
            .expect("Rolling 首次消费应写入 window_start");
        assert_eq!(result.cycle_reset_at, window_start + 30 * 86400);
    }

    /// check_and_reset_cycle：周期未过期返回 false，不清计数。
    #[tokio::test]
    async fn test_check_and_reset_cycle_not_expired() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        meter.consume_credit(42, "login", 3).await.unwrap();
        let reset = meter.check_and_reset_cycle(42).await.unwrap();
        assert!(!reset, "未过期应返回 false");
        let usage = meter.get_credit_usage(42).await.unwrap();
        assert_eq!(usage.consumed, 3, "未过期不应清计数");
    }

    /// check_and_reset_cycle：周期过期返回 true，清计数且删除 window_start。
    #[tokio::test]
    async fn test_check_and_reset_cycle_expired() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        meter.consume_credit(42, "login", 3).await.unwrap();
        // 将 window_start 拨回 31 天前 → Rolling(30d) 过期
        let past = Utc::now().timestamp() - 31 * 86400;
        meter
            .storage
            .set_window_start(42, past, 86400)
            .await
            .unwrap();
        let reset = meter.check_and_reset_cycle(42).await.unwrap();
        assert!(reset, "过期应返回 true");
        // Rolling 重置后 window_start 应被删除
        assert!(
            meter.storage.get_window_start(42).await.unwrap().is_none(),
            "Rolling 过期重置应删除 window_start"
        );
        let usage = meter.get_credit_usage(42).await.unwrap();
        assert_eq!(usage.consumed, 0, "过期重置应清零计数");
    }

    /// 过期后再次消费：从 0 重新累计，且重新写入 window_start。
    #[tokio::test]
    async fn test_consume_after_cycle_expiry_starts_fresh() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        meter.consume_credit(42, "login", 50).await.unwrap();
        // 拨回 window_start 使周期过期
        let past = Utc::now().timestamp() - 31 * 86400;
        meter
            .storage
            .set_window_start(42, past, 86400)
            .await
            .unwrap();
        // 再消费 → 周期重置生效，本次消费从 0 开始
        let result = meter.consume_credit(42, "login", 7).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.total_consumed, 7, "周期过期后应重新累计");
        assert!(
            meter.storage.get_window_start(42).await.unwrap().is_some(),
            "重置后再次消费应重新写入 window_start"
        );
    }

    /// 租户隔离：两个租户的消费计数互不影响。
    #[tokio::test]
    async fn test_consume_tenant_isolation() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        meter.consume_credit(1, "login", 10).await.unwrap();
        meter.consume_credit(2, "login", 20).await.unwrap();
        let usage1 = meter.get_credit_usage(1).await.unwrap();
        let usage2 = meter.get_credit_usage(2).await.unwrap();
        assert_eq!(usage1.consumed, 10);
        assert_eq!(usage2.consumed, 20);
        // 重置租户 1 不影响租户 2
        meter.reset_credit(1).await.unwrap();
        assert_eq!(meter.get_credit_usage(1).await.unwrap().consumed, 0);
        assert_eq!(meter.get_credit_usage(2).await.unwrap().consumed, 20);
    }

    /// 注入 listener 后消费应广播 CreditConsumed 事件（含 CreditAlert）。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn test_consume_broadcasts_events_via_listener_manager() {
        use crate::error::GarrisonResult;
        use crate::listener::{GarrisonEvent, GarrisonListener, GarrisonListenerManager};
        use async_trait::async_trait;
        use parking_lot::Mutex;

        /// 捕获 CreditConsumed / CreditAlert 事件的测试监听器。
        #[derive(Default)]
        struct CapturingListener {
            consumed: Mutex<Vec<(i64, String, u64, u64)>>,
            alerts: Mutex<Vec<(i64, u8)>>,
        }

        #[async_trait]
        impl GarrisonListener for CapturingListener {
            async fn on_event(&self, event: &GarrisonEvent) -> GarrisonResult<()> {
                match event {
                    GarrisonEvent::CreditConsumed {
                        tenant_id,
                        resource,
                        cost,
                        credits,
                        ..
                    } => {
                        self.consumed
                            .lock()
                            .push((*tenant_id, resource.clone(), *cost, *credits));
                    },
                    GarrisonEvent::CreditAlert {
                        tenant_id,
                        threshold,
                        ..
                    } => {
                        self.alerts.lock().push((*tenant_id, *threshold));
                    },
                    _ => {},
                }
                Ok(())
            }
        }

        let listener = Arc::new(CapturingListener::default());
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(listener.clone());

        let meter = CreditMeter::new(make_dao(), make_config(10)).with_listener_manager(lm);
        // 消费 10/10 → 100% → 触发 80/90/100 三级告警
        let result = meter.consume_credit(42, "login", 10).await.unwrap();
        assert!(result.alerts_triggered.contains(&100));

        // broadcast 在 tokio::spawn 中执行，轮询等待事件到达（上限 2s）
        let mut got_consumed = false;
        let mut got_alert = false;
        for _ in 0..40 {
            got_consumed = !listener.consumed.lock().is_empty();
            got_alert = !listener.alerts.lock().is_empty();
            if got_consumed && got_alert {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(got_consumed, "应广播 CreditConsumed 事件");
        let consumed = listener.consumed.lock();
        assert_eq!(consumed[0], (42, "login".to_string(), 10, 10));
        assert!(got_alert, "应广播 CreditAlert 事件");
        assert!(
            listener
                .alerts
                .lock()
                .iter()
                .any(|&(t, th)| t == 42 && th == 100),
            "应包含 threshold=100 的告警"
        );
    }

    /// 注入 CreditMetrics 后消费应记录 consumed / remaining / alert 指标。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn test_consume_records_prometheus_metrics() {
        use crate::credit::metrics::CreditMetrics;

        let registry = prometheus::Registry::new();
        let metrics = Arc::new(CreditMetrics::register_to(&registry).unwrap());
        let meter = CreditMeter::new(make_dao(), make_config(10)).with_metrics(metrics.clone());
        // 消费 8/10 → 80% → 触发 80 告警
        meter.consume_credit(42, "sms", 8).await.unwrap();

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("garrison_credit_consumed_total{resource=\"sms\",tenant_id=\"42\"} 8"),
            "应记录 consumed=8: {}",
            output
        );
        assert!(
            output.contains("garrison_credit_remaining{tenant_id=\"42\"} 2"),
            "应记录 remaining=2: {}",
            output
        );
        assert!(
            output.contains("garrison_credit_alerts_total{tenant_id=\"42\",threshold=\"80\"} 1"),
            "应记录 alert threshold=80: {}",
            output
        );
    }

    // ========================================================================
    // persist_history / get_usage_history（需 db feature 的 SQL 流水接口）
    // ========================================================================

    /// 测试用 DAO：在 MockDao 之上内存记录 credit 消费流水，
    /// 用于覆盖 persist_history 异步落库与 get_usage_history 查询映射。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    /// 流水记录行：(tenant_id, resource, cost, credits, total, cycle_start, created_at)
    type HistoryRecord = (i64, String, u64, u64, u64, i64, i64);

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    struct HistoryTestDao {
        inner: MockDao,
        records: parking_lot::Mutex<Vec<HistoryRecord>>,
        /// 置位后 insert_credit_consumption 返回 Err（错误注入）。
        fail_insert: parking_lot::Mutex<bool>,
    }

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    impl HistoryTestDao {
        fn new() -> Self {
            Self {
                inner: MockDao::new(),
                records: parking_lot::Mutex::new(Vec::new()),
                fail_insert: parking_lot::Mutex::new(false),
            }
        }

        /// 开启 insert 错误注入（模拟 SQL 落库失败）。
        fn set_fail_insert(&self, fail: bool) {
            *self.fail_insert.lock() = fail;
        }

        /// 直接插入一条流水记录（绕过 meter 的异步路径，时间戳可控）。
        fn push_record(
            &self,
            tenant_id: i64,
            resource: &str,
            cost: u64,
            credits: u64,
            total: u64,
            cycle_start: i64,
            created_at: i64,
        ) {
            self.records.lock().push((
                tenant_id,
                resource.to_string(),
                cost,
                credits,
                total,
                cycle_start,
                created_at,
            ));
        }
    }

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[async_trait::async_trait]
    impl GarrisonDao for HistoryTestDao {
        async fn get(&self, key: &str) -> crate::error::GarrisonResult<Option<String>> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> crate::error::GarrisonResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> crate::error::GarrisonResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> crate::error::GarrisonResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> crate::error::GarrisonResult<()> {
            self.inner.delete(key).await
        }
        async fn incr(&self, key: &str, ttl_seconds: u64) -> crate::error::GarrisonResult<u64> {
            self.inner.incr(key, ttl_seconds).await
        }
        async fn decr(&self, key: &str) -> crate::error::GarrisonResult<u64> {
            self.inner.decr(key).await
        }
        async fn set_if_absent(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> crate::error::GarrisonResult<bool> {
            self.inner.set_if_absent(key, value, ttl_seconds).await
        }
        async fn rename(&self, old_key: &str, new_key: &str) -> crate::error::GarrisonResult<()> {
            self.inner.rename(old_key, new_key).await
        }
        async fn get_and_delete(&self, key: &str) -> crate::error::GarrisonResult<Option<String>> {
            self.inner.get_and_delete(key).await
        }
        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<&str>,
            new_value: &str,
            ttl_seconds: u64,
        ) -> crate::error::GarrisonResult<bool> {
            self.inner
                .compare_and_swap(key, expected, new_value, ttl_seconds)
                .await
        }

        async fn insert_credit_consumption(
            &self,
            tenant_id: i64,
            resource: &str,
            cost: u64,
            credits: u64,
            total_consumed: u64,
            cycle_start: i64,
        ) -> crate::error::GarrisonResult<()> {
            if *self.fail_insert.lock() {
                return Err(crate::error::GarrisonError::NotImplemented(
                    "injected insert failure".to_string(),
                ));
            }
            let created_at = Utc::now().timestamp();
            self.records.lock().push((
                tenant_id,
                resource.to_string(),
                cost,
                credits,
                total_consumed,
                cycle_start,
                created_at,
            ));
            Ok(())
        }

        async fn query_credit_consumption(
            &self,
            tenant_id: i64,
            from_ts: i64,
            to_ts: i64,
        ) -> crate::error::GarrisonResult<Vec<(i64, String, u64, u64, u64, i64, i64)>> {
            Ok(self
                .records
                .lock()
                .iter()
                .filter(|r| r.0 == tenant_id && r.6 >= from_ts && r.6 <= to_ts)
                .cloned()
                .collect())
        }
    }

    /// persist_history = true 时消费应异步写入流水记录。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[tokio::test]
    async fn test_consume_persist_history_writes_record() {
        let dao = Arc::new(HistoryTestDao::new());
        let config = CreditConfig {
            persist_history: true,
            ..make_config(100)
        };
        let meter = CreditMeter::new(dao.clone(), config);
        let result = meter.consume_credit(42, "login", 5).await.unwrap();
        assert_eq!(result.consumed_credits, 5);

        // 落库在 tokio::spawn 中异步执行，轮询等待（上限 2s）
        let mut written = false;
        for _ in 0..40 {
            if !dao.records.lock().is_empty() {
                written = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(written, "persist_history=true 应异步写入流水");
        let records = dao.records.lock();
        assert_eq!(records[0].0, 42);
        assert_eq!(records[0].1, "login");
        assert_eq!(records[0].2, 5, "cost 应为原始 cost");
        assert_eq!(records[0].3, 5, "credits 应为 cost * weight");
        assert_eq!(records[0].4, 5, "total_consumed 应为消费后累计");
    }

    /// persist_history = false 时不写流水。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[tokio::test]
    async fn test_consume_persist_history_disabled_skips_record() {
        let dao = Arc::new(HistoryTestDao::new());
        let meter = CreditMeter::new(dao.clone(), make_config(100));
        meter.consume_credit(42, "login", 5).await.unwrap();
        // 留出异步任务执行机会
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            dao.records.lock().is_empty(),
            "persist_history=false 不应写流水"
        );
    }

    /// persist_history 落库失败不应影响消费结果（仅 tracing::warn 记录）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[tokio::test]
    async fn test_consume_persist_history_insert_error_is_non_blocking() {
        let dao = Arc::new(HistoryTestDao::new());
        dao.set_fail_insert(true);
        let config = CreditConfig {
            persist_history: true,
            ..make_config(100)
        };
        let meter = CreditMeter::new(dao, config);
        // 落库失败不应向上传播：消费结果仍然正常
        let result = meter.consume_credit(42, "login", 5).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.total_consumed, 5);
        // 留出异步任务执行机会（warn 分支在 spawn 内执行）
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    /// get_usage_history 将 DAO 元组正确映射为 CreditConsumptionRecord，
    /// 且按 tenant 与时间范围过滤。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[tokio::test]
    async fn test_get_usage_history_maps_and_filters_records() {
        let dao = Arc::new(HistoryTestDao::new());
        // tenant 42 两条（一条在窗口内、一条在窗口外），tenant 43 一条
        dao.push_record(42, "login", 1, 1, 1, 1_000, 5_000);
        dao.push_record(42, "sms", 2, 10, 11, 1_000, 6_000);
        dao.push_record(43, "login", 1, 1, 1, 1_000, 5_500);

        let meter = CreditMeter::new(dao, make_config(100));
        let records = meter.get_usage_history(42, 4_500, 5_500).await.unwrap();
        assert_eq!(
            records.len(),
            1,
            "应只含 tenant=42 且 created_at ∈ [4500, 5500] 的记录"
        );
        let r = &records[0];
        assert_eq!(r.tenant_id, 42);
        assert_eq!(r.resource, "login");
        assert_eq!(r.cost, 1);
        assert_eq!(r.credits, 1);
        assert_eq!(r.total_consumed, 1);
        assert_eq!(r.cycle_start, 1_000);
        assert_eq!(r.created_at, 5_000);
    }

    /// get_usage_history 在 DAO 未实现 SQL 查询时返回 Dao 错误（fail-fast）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[tokio::test]
    async fn test_get_usage_history_not_implemented_returns_err() {
        let meter = CreditMeter::new(make_dao(), make_config(100));
        let result = meter.get_usage_history(42, 0, 1).await;
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("credit-query-history::"),
            "应包装为 credit-query-history 前缀错误: {}",
            err
        );
    }
}
