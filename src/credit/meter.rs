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
}
