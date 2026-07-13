//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 异常登录定时分析引擎（双引擎的定时部分）。
//!
//! `AnomalousLoginAnalyzer` 与实时引擎 `AnomalousLoginStrategy` 互补：
//! - 实时引擎（`anomalous.rs`）：登录时即时检测异地跳变（haversine 距离）
//! - 定时引擎（本模块）：定期扫描历史登录记录，识别 burst / geo_jump / device_mutation 模式
//!
//! # 算法
//!
//! 1. `record_login` 将每次登录记录写入 DAO（key: `anomalous:login:{login_id}:{timestamp}`，TTL 24h）
//! 2. `analyze_once` 扫描时间窗口内（1h）所有登录记录，按 login_id 分组
//! 3. 检测 3 种异常：
//!    - `burst_login`：单个 login_id 登录次数 > `burst_threshold`（默认 5）
//!    - `geo_jump`：单个 login_id 不同 geo > 2（None 不计入）
//!    - `device_mutation`：单个 login_id 不同 device > 3（None 不计入）

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// 最大扫描 key 数量（DoS 防护）。
const MAX_SCAN: usize = 10_000;
/// 登录记录 TTL（秒，24h）。
const RECORD_TTL_SECS: u64 = 86_400;
/// 扫描时间窗口（秒，1h）。
const SCAN_WINDOW_SECS: i64 = 3_600;

/// 登录结果枚举。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginResult {
    /// 登录成功。
    Success,
    /// 登录失败。
    Failed,
}

/// 异常登录记录（spec R-001）。
///
/// 每次登录（成功/失败）均写入 DAO，供定时分析引擎扫描。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalousLoginRecord {
    /// 登录主体标识。
    pub login_id: String,
    /// 登录 IP 地址。
    pub ip: String,
    /// 地理位置标识（如 "CN-Beijing"），无法定位时为 None。
    pub geo: Option<String>,
    /// 设备指纹标识，无法识别时为 None。
    pub device: Option<String>,
    /// 登录时间戳（Unix 秒）。
    pub timestamp: i64,
    /// 登录结果。
    pub result: LoginResult,
}

/// 异常登录分析器配置（spec R-007）。
#[derive(Debug, Clone)]
pub struct AnomalousAnalyzerConfig {
    /// 定时扫描间隔（秒，默认 3600）。
    pub interval_secs: u64,
    /// burst 登录阈值（次数 > 此值则告警，默认 5）。
    pub burst_threshold: u32,
    /// 最大扫描 key 数量（DoS 防护，默认 10_000）。
    pub max_scan: usize,
}

impl Default for AnomalousAnalyzerConfig {
    fn default() -> Self {
        Self {
            interval_secs: 3600,
            burst_threshold: 5,
            max_scan: MAX_SCAN,
        }
    }
}

impl AnomalousAnalyzerConfig {
    /// 校验配置合法性（spec R-007）。
    ///
    /// # 错误
    /// - `interval_secs` 为 0
    /// - `burst_threshold` 为 0
    /// - `max_scan` 为 0
    pub fn validate(&self) -> BulwarkResult<()> {
        if self.interval_secs == 0 {
            return Err(BulwarkError::Config("interval_secs 不能为 0".to_string()));
        }
        if self.burst_threshold == 0 {
            return Err(BulwarkError::Config("burst_threshold 不能为 0".to_string()));
        }
        if self.max_scan == 0 {
            return Err(BulwarkError::Config("max_scan 不能为 0".to_string()));
        }
        Ok(())
    }
}

/// 异常登录检测事件（spec R-006）。
///
/// 在定时分析引擎检测到异常模式时生成，可转换为 `BulwarkEvent` 广播。
#[derive(Debug, Clone)]
pub struct AnomalousLoginDetected {
    /// 登录主体标识。
    pub login_id: String,
    /// 异常原因（`"burst_login"` / `"geo_jump"` / `"device_mutation"`）。
    pub reason: String,
    /// 检测详情（JSON 值）。
    pub detail: serde_json::Value,
    /// 检测时间戳（Unix 秒）。
    pub timestamp: i64,
}

impl From<AnomalousLoginDetected> for BulwarkEvent {
    fn from(e: AnomalousLoginDetected) -> Self {
        BulwarkEvent::AnomalousLoginDetected {
            login_id: e.login_id,
            reason: e.reason,
            detail: e.detail,
            timestamp: e.timestamp,
            request_context: None,
        }
    }
}

/// 异常登录定时分析引擎。
///
/// 通过 `start(self)` 消费自身并 spawn 定时任务，
/// 调用方持有 `shutdown_tx` 以优雅停止。
pub struct AnomalousLoginAnalyzer {
    /// DAO 抽象层（用于登录记录持久化与扫描）。
    dao: Arc<dyn BulwarkDao>,
    /// 分析器配置。
    config: AnomalousAnalyzerConfig,
    /// 监听器管理器（可选，Some 时广播事件）。
    listener_manager: Option<Arc<BulwarkListenerManager>>,
    /// shutdown 信号接收端（调用方持有发送端）。
    shutdown_rx: watch::Receiver<bool>,
}

impl AnomalousLoginAnalyzer {
    /// 创建分析器实例。
    ///
    /// # 参数
    /// - `dao`: DAO 抽象层。
    /// - `config`: 分析器配置。
    /// - `shutdown_rx`: shutdown 信号接收端（调用方持有 `shutdown_tx`）。
    /// - `listener_manager`: 监听器管理器（None 时不广播事件）。
    pub fn new(
        dao: Arc<dyn BulwarkDao>,
        config: AnomalousAnalyzerConfig,
        shutdown_rx: watch::Receiver<bool>,
        listener_manager: Option<Arc<BulwarkListenerManager>>,
    ) -> Self {
        Self {
            dao,
            config,
            listener_manager,
            shutdown_rx,
        }
    }

    /// 记录一次登录事件（spec R-001）。
    ///
    /// 将登录记录序列化为 JSON 存入 DAO，
    /// key 格式 `anomalous:login:{login_id}:{nanos}`，TTL 24h。
    ///
    /// # 纳秒精度（HIGH-002 修复）
    /// key 使用纳秒精度时间戳（而非 record.timestamp 的秒级），
    /// 避免同一秒内同一 login_id 的多次登录互相覆盖。
    /// `record.timestamp` 仍为秒级（用于时间窗口过滤），key 的纳秒仅用于唯一性。
    ///
    /// # 错误
    /// - `login_id` 为空 → `InvalidParam`
    /// - `login_id` 包含 `:` → `InvalidParam`（破坏 key 解析）
    /// - 序列化失败 → `Internal`
    pub async fn record_login(&self, record: &AnomalousLoginRecord) -> BulwarkResult<()> {
        if record.login_id.is_empty() {
            return Err(BulwarkError::InvalidParam("login_id 不能为空".to_string()));
        }
        if record.login_id.contains(':') {
            return Err(BulwarkError::InvalidParam(
                "login_id 不能包含 ':'".to_string(),
            ));
        }
        let key = Self::make_storage_key(&record.login_id, record.timestamp);
        let value = serde_json::to_string(record)
            .map_err(|e| BulwarkError::Internal(format!("序列化登录记录失败: {}", e)))?;
        self.dao.set(&key, &value, RECORD_TTL_SECS).await
    }

    /// 生成存储 key（纳秒精度避免同秒覆盖，HIGH-002 修复）。
    ///
    /// key 格式：`anomalous:login:{login_id}:{nanos}`
    /// `nanos` 取自 `SystemTime::now()` 的纳秒时间戳，保证同秒内多次调用产生不同 key。
    fn make_storage_key(login_id: &str, timestamp_secs: i64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(timestamp_secs as u128);
        format!("anomalous:login:{}:{}", login_id, nanos)
    }

    /// 执行一次分析扫描（使用当前时间戳）。
    ///
    /// 扫描时间窗口内的所有登录记录，返回检测到的异常事件列表。
    pub async fn analyze(&self) -> BulwarkResult<Vec<AnomalousLoginDetected>> {
        let now = chrono::Utc::now().timestamp();
        Self::analyze_once(&self.dao, &self.config, now).await
    }

    /// 核心分析逻辑（spec R-003 / R-004 / R-005）。
    ///
    /// 关联函数，接收固定 `now` 参数便于测试。
    ///
    /// # 算法
    /// 1. `dao.keys("anomalous:login:*")` 获取所有 key（受 `max_scan` 限制）
    /// 2. 反序列化每条记录，失败的 `tracing::warn!` 跳过
    /// 3. 过滤时间窗口内记录（`timestamp >= now - 3600 && timestamp <= now`）
    /// 4. 按 login_id 分组
    /// 5. 检测 3 种异常：burst / geo_jump / device_mutation
    ///
    /// # 性能监控（HIGH-001）
    /// 记录扫描总耗时，超过 1s 时 `tracing::warn!`（Redis 后端 N+1 查询需优化为批量 mget）。
    /// oxcache 内存后端 get_sync <100ns，10000 次 get ~1ms，无需优化。
    async fn analyze_once(
        dao: &Arc<dyn BulwarkDao>,
        config: &AnomalousAnalyzerConfig,
        now: i64,
    ) -> BulwarkResult<Vec<AnomalousLoginDetected>> {
        let scan_start = std::time::Instant::now();

        let keys = dao.keys("anomalous:login:*").await?;
        let keys: Vec<String> = keys.into_iter().take(config.max_scan).collect();

        let mut grouped: HashMap<String, Vec<AnomalousLoginRecord>> = HashMap::new();

        for key in &keys {
            match dao.get(key).await {
                Ok(Some(value)) => match serde_json::from_str::<AnomalousLoginRecord>(&value) {
                    Ok(record) => {
                        if record.timestamp >= now - SCAN_WINDOW_SECS && record.timestamp <= now {
                            grouped
                                .entry(record.login_id.clone())
                                .or_default()
                                .push(record);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("反序列化登录记录失败（key={}）: {}", key, e);
                    },
                },
                Ok(None) => {},
                Err(e) => {
                    tracing::warn!("读取登录记录失败（key={}）: {}", key, e);
                },
            }
        }

        let mut events = Vec::new();

        for (login_id, records) in grouped {
            // burst_login: 登录次数 > burst_threshold（spec R-003）
            if records.len() > config.burst_threshold as usize {
                events.push(AnomalousLoginDetected {
                    login_id: login_id.clone(),
                    reason: "burst_login".to_string(),
                    detail: serde_json::json!({
                        "count": records.len(),
                        "threshold": config.burst_threshold,
                    }),
                    timestamp: now,
                });
            }

            // geo_jump: 不同 geo > 2（None 不计入，spec R-004）
            let distinct_geo: HashSet<&str> =
                records.iter().filter_map(|r| r.geo.as_deref()).collect();
            if distinct_geo.len() > 2 {
                events.push(AnomalousLoginDetected {
                    login_id: login_id.clone(),
                    reason: "geo_jump".to_string(),
                    detail: serde_json::json!({
                        "distinct_geo": distinct_geo.len(),
                        "geo": distinct_geo.iter().collect::<Vec<_>>(),
                    }),
                    timestamp: now,
                });
            }

            // device_mutation: 不同 device > 3（None 不计入，spec R-005）
            let distinct_device: HashSet<&str> =
                records.iter().filter_map(|r| r.device.as_deref()).collect();
            if distinct_device.len() > 3 {
                events.push(AnomalousLoginDetected {
                    login_id: login_id.clone(),
                    reason: "device_mutation".to_string(),
                    detail: serde_json::json!({
                        "distinct_device": distinct_device.len(),
                        "device": distinct_device.iter().collect::<Vec<_>>(),
                    }),
                    timestamp: now,
                });
            }
        }

        // HIGH-001: 扫描时间监控（Redis 后端 N+1 查询需优化为批量 mget）
        let scan_elapsed = scan_start.elapsed();
        if scan_elapsed > Duration::from_secs(1) {
            tracing::warn!(
                elapsed_ms = scan_elapsed.as_millis(),
                key_count = keys.len(),
                "异常登录分析扫描耗时超过 1s，Redis 后端需优化为批量 mget"
            );
        } else {
            tracing::debug!(
                elapsed_ms = scan_elapsed.as_millis(),
                key_count = keys.len(),
                "异常登录分析扫描完成"
            );
        }

        Ok(events)
    }

    /// 启动定时分析任务（spec R-002）。
    ///
    /// 消费 `self`，spawn 一个 tokio 任务：
    /// - 按 `interval_secs` 间隔定期执行 `analyze_once`
    /// - 检测到异常时通过 `listener_manager` 广播事件（若 Some）
    /// - 分析失败仅 `tracing::warn!`，不中断循环
    /// - 收到 shutdown 信号时优雅停止
    ///
    /// # 返回
    /// `JoinHandle<()>`，调用方可 `.await` 等待任务结束，
    /// 或通过 [`shutdown`](Self::shutdown) 优雅停止。
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        let dao = self.dao;
        let config = self.config;
        let listener_manager = self.listener_manager;
        let mut shutdown_rx = self.shutdown_rx;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = chrono::Utc::now().timestamp();
                        match Self::analyze_once(&dao, &config, now).await {
                            Ok(events) => {
                                for event in events {
                                    if let Some(ref lm) = listener_manager {
                                        let bulwark_event: BulwarkEvent = event.into();
                                        lm.broadcast(&bulwark_event).await;
                                    }
                                }
                            },
                            Err(e) => {
                                tracing::warn!("异常登录分析失败: {}", e);
                            },
                        }
                    },
                    _ = shutdown_rx.changed() => {
                        tracing::info!(
                            "异常登录分析引擎收到 shutdown 信号，停止"
                        );
                        break;
                    },
                }
            }
        })
    }

    /// 优雅停止分析器任务（默认 5 秒超时，T008）。
    ///
    /// 发送 shutdown 信号后等待任务结束，超时则强制 abort。
    /// 适用于异步上下文（BulwarkManager 的同步 Drop 仍用 `handle.abort()`）。
    ///
    /// # 参数
    /// - `handle`: [`start`](Self::start) 返回的 `JoinHandle<()>`。
    /// - `shutdown_tx`: `watch::Sender<bool>` shutdown 信号发送端。
    ///
    /// # 返回
    /// - `Ok(())`: 任务正常结束（或已被 cancelled）。
    /// - `Err(Internal)`: 任务 panic 或超时被 abort。
    pub async fn shutdown(
        handle: tokio::task::JoinHandle<()>,
        shutdown_tx: watch::Sender<bool>,
    ) -> BulwarkResult<()> {
        Self::shutdown_with_timeout(handle, shutdown_tx, Duration::from_secs(5)).await
    }

    /// 优雅停止分析器任务（自定义超时，T008）。
    ///
    /// 1. 发送 shutdown 信号（`shutdown_tx.send(true)`）
    /// 2. 用 `tokio::time::timeout` 包裹 `handle.await`
    /// 3. 超时后调用 `abort_handle.abort()` 强制终止
    ///
    /// # 参数
    /// - `handle`: [`start`](Self::start) 返回的 `JoinHandle<()>`。
    /// - `shutdown_tx`: `watch::Sender<bool>` shutdown 信号发送端。
    /// - `timeout`: 超时时间。
    ///
    /// # 返回
    /// - `Ok(())`: 任务正常结束（或已被 cancelled）。
    /// - `Err(Internal)`: 任务 panic 或超时被 abort。
    pub async fn shutdown_with_timeout(
        handle: tokio::task::JoinHandle<()>,
        shutdown_tx: watch::Sender<bool>,
        timeout: Duration,
    ) -> BulwarkResult<()> {
        let _ = shutdown_tx.send(true);
        let abort_handle = handle.abort_handle();
        match tokio::time::timeout(timeout, handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) if e.is_cancelled() => Ok(()),
            Ok(Err(e)) => Err(BulwarkError::Internal(format!("分析器任务 panic: {}", e))),
            Err(_) => {
                abort_handle.abort();
                Err(BulwarkError::Internal(format!(
                    "shutdown 超时 {}ms，已强制 abort",
                    timeout.as_millis()
                )))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    // ========================================================================
    // LoginResult 序列化测试
    // ========================================================================

    #[test]
    fn login_result_serde_roundtrip() {
        let success = LoginResult::Success;
        let failed = LoginResult::Failed;
        let success_json = serde_json::to_string(&success).unwrap();
        let failed_json = serde_json::to_string(&failed).unwrap();
        assert_eq!(success_json, "\"success\"");
        assert_eq!(failed_json, "\"failed\"");
        let success_de: LoginResult = serde_json::from_str(&success_json).unwrap();
        let failed_de: LoginResult = serde_json::from_str(&failed_json).unwrap();
        assert_eq!(success_de, LoginResult::Success);
        assert_eq!(failed_de, LoginResult::Failed);
    }

    // ========================================================================
    // AnomalousLoginRecord 序列化与字段测试
    // ========================================================================

    #[test]
    fn anomalous_login_record_serde_roundtrip() {
        let record = AnomalousLoginRecord {
            login_id: "1001".to_string(),
            ip: "1.2.3.4".to_string(),
            geo: Some("CN-Beijing".to_string()),
            device: Some("web-chrome".to_string()),
            timestamp: 1700000000,
            result: LoginResult::Success,
        };
        let json = serde_json::to_string(&record).unwrap();
        let de: AnomalousLoginRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(de.login_id, "1001");
        assert_eq!(de.ip, "1.2.3.4");
        assert_eq!(de.geo, Some("CN-Beijing".to_string()));
        assert_eq!(de.device, Some("web-chrome".to_string()));
        assert_eq!(de.timestamp, 1700000000);
        assert_eq!(de.result, LoginResult::Success);
    }

    #[test]
    fn anomalous_login_record_optional_fields_none() {
        let record = AnomalousLoginRecord {
            login_id: "1001".to_string(),
            ip: "1.2.3.4".to_string(),
            geo: None,
            device: None,
            timestamp: 1700000000,
            result: LoginResult::Failed,
        };
        let json = serde_json::to_string(&record).unwrap();
        let de: AnomalousLoginRecord = serde_json::from_str(&json).unwrap();
        assert!(de.geo.is_none());
        assert!(de.device.is_none());
        assert_eq!(de.result, LoginResult::Failed);
    }

    // ========================================================================
    // AnomalousAnalyzerConfig 测试
    // ========================================================================

    #[test]
    fn analyzer_config_default() {
        let config = AnomalousAnalyzerConfig::default();
        assert_eq!(config.interval_secs, 3600);
        assert_eq!(config.burst_threshold, 5);
        assert_eq!(config.max_scan, 10_000);
    }

    #[test]
    fn analyzer_config_validate_ok() {
        let config = AnomalousAnalyzerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn analyzer_config_validate_zero_interval() {
        let config = AnomalousAnalyzerConfig {
            interval_secs: 0,
            burst_threshold: 5,
            max_scan: 100,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn analyzer_config_validate_zero_burst() {
        let config = AnomalousAnalyzerConfig {
            interval_secs: 3600,
            burst_threshold: 0,
            max_scan: 100,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn analyzer_config_validate_zero_max_scan() {
        let config = AnomalousAnalyzerConfig {
            interval_secs: 3600,
            burst_threshold: 5,
            max_scan: 0,
        };
        assert!(config.validate().is_err());
    }

    // ========================================================================
    // record_login 测试
    // ========================================================================

    #[tokio::test]
    async fn record_login_persists_record() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let (tx, rx) = watch::channel(false);
        let analyzer =
            AnomalousLoginAnalyzer::new(dao.clone(), AnomalousAnalyzerConfig::default(), rx, None);
        let record = AnomalousLoginRecord {
            login_id: "1001".to_string(),
            ip: "1.2.3.4".to_string(),
            geo: Some("CN-Beijing".to_string()),
            device: Some("web".to_string()),
            timestamp: 1700000000,
            result: LoginResult::Success,
        };
        analyzer.record_login(&record).await.unwrap();

        // record_login 用纳秒精度 key（HIGH-002），用 keys() 查找
        let keys = dao.keys("anomalous:login:1001:*").await.unwrap();
        assert_eq!(keys.len(), 1, "record_login 后应有 1 个 key");
        let stored = dao.get(&keys[0]).await.unwrap();
        assert!(stored.is_some());
        let de: AnomalousLoginRecord = serde_json::from_str(&stored.unwrap()).unwrap();
        assert_eq!(de.login_id, "1001");
        assert_eq!(de.ip, "1.2.3.4");
        let _ = tx;
    }

    #[tokio::test]
    async fn record_login_empty_login_id_errors() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let (_tx, rx) = watch::channel(false);
        let analyzer =
            AnomalousLoginAnalyzer::new(dao, AnomalousAnalyzerConfig::default(), rx, None);
        let record = AnomalousLoginRecord {
            login_id: "".to_string(),
            ip: "1.2.3.4".to_string(),
            geo: None,
            device: None,
            timestamp: 1700000000,
            result: LoginResult::Success,
        };
        let result = analyzer.record_login(&record).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "空 login_id 应返回 InvalidParam"
        );
    }

    #[tokio::test]
    async fn record_login_colon_in_login_id_errors() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let (_tx, rx) = watch::channel(false);
        let analyzer =
            AnomalousLoginAnalyzer::new(dao, AnomalousAnalyzerConfig::default(), rx, None);
        let record = AnomalousLoginRecord {
            login_id: "user:1001".to_string(),
            ip: "1.2.3.4".to_string(),
            geo: None,
            device: None,
            timestamp: 1700000000,
            result: LoginResult::Success,
        };
        let result = analyzer.record_login(&record).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "包含 ':' 的 login_id 应返回 InvalidParam"
        );
    }

    /// HIGH-002: 同秒内多次 record_login 不覆盖。
    /// 同一 login_id 同一秒内调用 record_login 3 次，
    /// keys() 应返回 3 个不同的 key（纳秒精度避免覆盖）。
    #[tokio::test]
    async fn record_login_same_second_no_overwrite() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let (_tx, rx) = watch::channel(false);
        let analyzer =
            AnomalousLoginAnalyzer::new(dao.clone(), AnomalousAnalyzerConfig::default(), rx, None);
        let now = 1700000000i64;
        // 同一 login_id 同一秒内 3 次登录
        for i in 0..3 {
            let record = AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now,
                result: LoginResult::Success,
            };
            analyzer.record_login(&record).await.unwrap();
        }
        // keys() 应返回 3 个不同的 key（纳秒精度避免覆盖）
        let keys = dao.keys("anomalous:login:1001:*").await.unwrap();
        assert_eq!(
            keys.len(),
            3,
            "同秒内 3 次 record_login 应产生 3 个不同的 key（HIGH-002 修复）"
        );
        // 验证 3 个 key 互不相同
        let unique: HashSet<&str> = keys.iter().map(|s| s.as_str()).collect();
        assert_eq!(unique.len(), 3, "3 个 key 应互不相同");
    }

    // ========================================================================
    // analyze_once 测试（核心检测逻辑）
    // ========================================================================

    /// 辅助函数：创建并插入登录记录到 DAO。
    async fn insert_records(dao: &Arc<dyn BulwarkDao>, records: &[AnomalousLoginRecord]) {
        for record in records {
            let key = format!("anomalous:login:{}:{}", record.login_id, record.timestamp);
            let value = serde_json::to_string(record).unwrap();
            dao.set(&key, &value, RECORD_TTL_SECS).await.unwrap();
        }
    }

    #[tokio::test]
    async fn analyze_empty_returns_empty() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, 1700000000)
            .await
            .unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn analyze_burst_below_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records: Vec<AnomalousLoginRecord> = (0..5)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let burst_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "burst_login")
            .collect();
        assert!(
            burst_events.is_empty(),
            "5 条记录（== 阈值 5）不应触发 burst"
        );
    }

    #[tokio::test]
    async fn analyze_burst_above_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records: Vec<AnomalousLoginRecord> = (0..6)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let burst_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "burst_login")
            .collect();
        assert_eq!(
            burst_events.len(),
            1,
            "6 条记录（> 阈值 5）应触发 1 次 burst"
        );
        assert_eq!(burst_events[0].login_id, "1001");
    }

    #[tokio::test]
    async fn analyze_burst_event_fields() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records: Vec<AnomalousLoginRecord> = (0..10)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 50 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let burst = events.iter().find(|e| e.reason == "burst_login").unwrap();
        assert_eq!(burst.login_id, "1001");
        assert_eq!(burst.timestamp, now);
        assert_eq!(burst.detail["count"], 10);
        assert_eq!(burst.detail["threshold"], 5);
    }

    #[tokio::test]
    async fn analyze_geo_jump_below_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records = vec![
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "1.1.1.1".to_string(),
                geo: Some("CN-Beijing".to_string()),
                device: None,
                timestamp: now - 100,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "2.2.2.2".to_string(),
                geo: Some("CN-Shanghai".to_string()),
                device: None,
                timestamp: now - 50,
                result: LoginResult::Success,
            },
        ];
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let geo_events: Vec<_> = events.iter().filter(|e| e.reason == "geo_jump").collect();
        assert!(
            geo_events.is_empty(),
            "2 个不同 geo（== 阈值 2）不应触发 geo_jump"
        );
    }

    #[tokio::test]
    async fn analyze_geo_jump_above_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records = vec![
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "1.1.1.1".to_string(),
                geo: Some("CN-Beijing".to_string()),
                device: None,
                timestamp: now - 100,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "2.2.2.2".to_string(),
                geo: Some("CN-Shanghai".to_string()),
                device: None,
                timestamp: now - 80,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "3.3.3.3".to_string(),
                geo: Some("US-NewYork".to_string()),
                device: None,
                timestamp: now - 50,
                result: LoginResult::Success,
            },
        ];
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let geo_events: Vec<_> = events.iter().filter(|e| e.reason == "geo_jump").collect();
        assert_eq!(
            geo_events.len(),
            1,
            "3 个不同 geo（> 阈值 2）应触发 1 次 geo_jump"
        );
        assert_eq!(geo_events[0].detail["distinct_geo"], 3);
    }

    #[tokio::test]
    async fn analyze_geo_jump_none_excluded() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        // 2 个有 geo + 10 个 None → distinct_geo = 2（== 阈值，不触发）
        let mut records = vec![
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "1.1.1.1".to_string(),
                geo: Some("CN-Beijing".to_string()),
                device: None,
                timestamp: now - 100,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "2.2.2.2".to_string(),
                geo: Some("CN-Shanghai".to_string()),
                device: None,
                timestamp: now - 50,
                result: LoginResult::Success,
            },
        ];
        for i in 0..10 {
            records.push(AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("10.0.0.{}", i),
                geo: None,
                device: None,
                timestamp: now - 10 - i as i64,
                result: LoginResult::Success,
            });
        }
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let geo_events: Vec<_> = events.iter().filter(|e| e.reason == "geo_jump").collect();
        assert!(
            geo_events.is_empty(),
            "None geo 不计入，2 个有 geo 不应触发 geo_jump"
        );
    }

    #[tokio::test]
    async fn analyze_device_mutation_below_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records = vec![
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "1.1.1.1".to_string(),
                geo: None,
                device: Some("web".to_string()),
                timestamp: now - 100,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "2.2.2.2".to_string(),
                geo: None,
                device: Some("ios".to_string()),
                timestamp: now - 50,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "3.3.3.3".to_string(),
                geo: None,
                device: Some("android".to_string()),
                timestamp: now - 30,
                result: LoginResult::Success,
            },
        ];
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let device_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "device_mutation")
            .collect();
        assert!(
            device_events.is_empty(),
            "3 个不同 device（== 阈值 3）不应触发 device_mutation"
        );
    }

    #[tokio::test]
    async fn analyze_device_mutation_above_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        let records = vec![
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "1.1.1.1".to_string(),
                geo: None,
                device: Some("web".to_string()),
                timestamp: now - 100,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "2.2.2.2".to_string(),
                geo: None,
                device: Some("ios".to_string()),
                timestamp: now - 80,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "3.3.3.3".to_string(),
                geo: None,
                device: Some("android".to_string()),
                timestamp: now - 60,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "4.4.4.4".to_string(),
                geo: None,
                device: Some("tablet".to_string()),
                timestamp: now - 40,
                result: LoginResult::Success,
            },
        ];
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let device_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "device_mutation")
            .collect();
        assert_eq!(
            device_events.len(),
            1,
            "4 个不同 device（> 阈值 3）应触发 1 次 device_mutation"
        );
        assert_eq!(device_events[0].detail["distinct_device"], 4);
    }

    #[tokio::test]
    async fn analyze_device_mutation_none_excluded() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        // 3 个有 device + 10 个 None → distinct_device = 3（== 阈值，不触发）
        let mut records = vec![
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "1.1.1.1".to_string(),
                geo: None,
                device: Some("web".to_string()),
                timestamp: now - 100,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "2.2.2.2".to_string(),
                geo: None,
                device: Some("ios".to_string()),
                timestamp: now - 80,
                result: LoginResult::Success,
            },
            AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: "3.3.3.3".to_string(),
                geo: None,
                device: Some("android".to_string()),
                timestamp: now - 60,
                result: LoginResult::Success,
            },
        ];
        for i in 0..10 {
            records.push(AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("10.0.0.{}", i),
                geo: None,
                device: None,
                timestamp: now - 10 - i as i64,
                result: LoginResult::Success,
            });
        }
        insert_records(&dao, &records).await;
        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let device_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "device_mutation")
            .collect();
        assert!(
            device_events.is_empty(),
            "None device 不计入，3 个有 device 不应触发 device_mutation"
        );
    }

    // ========================================================================
    // 时间窗口与 max_scan 测试
    // ========================================================================

    #[tokio::test]
    async fn analyze_time_window_filter() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        // 窗口内的记录（6 条，触发 burst）
        let in_window: Vec<AnomalousLoginRecord> = (0..6)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &in_window).await;
        // 窗口外的记录（6 条，不应计入）
        let out_window: Vec<AnomalousLoginRecord> = (0..6)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("5.6.7.{}", i),
                geo: None,
                device: None,
                timestamp: now - SCAN_WINDOW_SECS - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &out_window).await;

        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let burst = events.iter().find(|e| e.reason == "burst_login").unwrap();
        // 只计入窗口内 6 条
        assert_eq!(burst.detail["count"], 6);
    }

    #[tokio::test]
    async fn analyze_max_scan_limit() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        // 插入 20 条记录
        let records: Vec<AnomalousLoginRecord> = (0..20)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &records).await;
        // max_scan = 5，只扫描前 5 条（<= 阈值 5，不触发 burst）
        let config = AnomalousAnalyzerConfig {
            interval_secs: 3600,
            burst_threshold: 5,
            max_scan: 5,
        };
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let burst_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "burst_login")
            .collect();
        assert!(
            burst_events.is_empty(),
            "max_scan=5 只扫描 5 条，不触发 burst"
        );
    }

    // ========================================================================
    // 反序列化容错测试
    // ========================================================================

    #[tokio::test]
    async fn analyze_deserialization_failure_skips() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        // 插入 6 条有效记录（触发 burst）
        let records: Vec<AnomalousLoginRecord> = (0..6)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &records).await;
        // 插入 2 条损坏记录
        dao.set("anomalous:login:1001:bad1", "not-json", RECORD_TTL_SECS)
            .await
            .unwrap();
        dao.set("anomalous:login:1001:bad2", "{invalid}", RECORD_TTL_SECS)
            .await
            .unwrap();

        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        // 损坏记录应被跳过，不影响有效记录的 burst 检测
        let burst = events.iter().find(|e| e.reason == "burst_login");
        assert!(burst.is_some(), "损坏记录应跳过，6 条有效记录仍触发 burst");
        assert_eq!(burst.unwrap().detail["count"], 6);
    }

    // ========================================================================
    // 多用户场景测试
    // ========================================================================

    #[tokio::test]
    async fn analyze_multiple_users() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let now = 1700000000i64;
        // 用户 1001：6 条记录（触发 burst）
        let user_a: Vec<AnomalousLoginRecord> = (0..6)
            .map(|i| AnomalousLoginRecord {
                login_id: "1001".to_string(),
                ip: format!("1.2.3.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &user_a).await;
        // 用户 1002：6 条记录（触发 burst）
        let user_b: Vec<AnomalousLoginRecord> = (0..6)
            .map(|i| AnomalousLoginRecord {
                login_id: "1002".to_string(),
                ip: format!("5.6.7.{}", i),
                geo: None,
                device: None,
                timestamp: now - 100 - i as i64,
                result: LoginResult::Success,
            })
            .collect();
        insert_records(&dao, &user_b).await;

        let config = AnomalousAnalyzerConfig::default();
        let events = AnomalousLoginAnalyzer::analyze_once(&dao, &config, now)
            .await
            .unwrap();
        let burst_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == "burst_login")
            .collect();
        assert_eq!(burst_events.len(), 2, "两个用户各触发 1 次 burst");
        let login_ids: HashSet<&str> = burst_events.iter().map(|e| e.login_id.as_str()).collect();
        assert!(login_ids.contains("1001"));
        assert!(login_ids.contains("1002"));
    }

    // ========================================================================
    // start + shutdown 集成测试
    // ========================================================================

    #[tokio::test]
    async fn start_shutdown_stops_task() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let (tx, rx) = watch::channel(false);
        let config = AnomalousAnalyzerConfig {
            interval_secs: 3600,
            burst_threshold: 5,
            max_scan: 100,
        };
        let analyzer = AnomalousLoginAnalyzer::new(dao, config, rx, None);
        let handle = analyzer.start();
        // 发送 shutdown 信号
        let _ = tx.send(true);
        // 等待任务结束（给 1 秒超时）
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("任务应在 shutdown 信号后 1 秒内结束")
            .expect("任务不应 panic");
    }

    // ========================================================================
    // From<AnomalousLoginDetected> for BulwarkEvent 测试
    // ========================================================================

    #[test]
    fn from_anomalous_login_detected_to_bulwark_event() {
        let detected = AnomalousLoginDetected {
            login_id: "1001".to_string(),
            reason: "burst_login".to_string(),
            detail: serde_json::json!({"count": 10}),
            timestamp: 1700000000,
        };
        let event: BulwarkEvent = detected.into();
        match event {
            BulwarkEvent::AnomalousLoginDetected {
                login_id,
                reason,
                detail,
                timestamp,
                ..
            } => {
                assert_eq!(login_id, "1001");
                assert_eq!(reason, "burst_login");
                assert_eq!(detail["count"], 10);
                assert_eq!(timestamp, 1700000000);
            },
            _ => panic!("期望 AnomalousLoginDetected 事件"),
        }
    }

    // ========================================================================
    // T008: shutdown + shutdown_with_timeout 测试
    // ========================================================================

    /// shutdown_with_timeout 对慢任务（不响应 shutdown 信号）超时后强制 abort。
    ///
    /// 创建一个永远 pending 的任务，100ms 超时后应返回 Err 且错误信息包含"超时"。
    #[tokio::test]
    async fn shutdown_with_timeout_aborts_slow_task() {
        let handle = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let (tx, _rx) = watch::channel(false);

        let result =
            AnomalousLoginAnalyzer::shutdown_with_timeout(handle, tx, Duration::from_millis(100))
                .await;

        assert!(result.is_err(), "慢任务应超时返回 Err");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("超时"),
            "错误信息应包含 '超时'，实际: {}",
            err_msg
        );
    }

    /// shutdown_with_timeout 对正常结束的任务返回 Ok。
    #[tokio::test]
    async fn shutdown_with_timeout_normal_completion() {
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        });
        let (tx, _rx) = watch::channel(false);

        let result =
            AnomalousLoginAnalyzer::shutdown_with_timeout(handle, tx, Duration::from_secs(1)).await;

        assert!(result.is_ok(), "正常结束的任务应返回 Ok");
    }

    /// shutdown_with_timeout 对响应 shutdown 信号的任务返回 Ok。
    ///
    /// 任务通过 `rx.has_changed()` 检测信号并退出，验证 shutdown 信号机制有效。
    #[tokio::test]
    async fn shutdown_with_timeout_responds_to_signal() {
        let (tx, rx) = watch::channel(false);
        let rx = rx;
        let handle = tokio::spawn(async move {
            loop {
                if rx.has_changed().unwrap_or(false) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let result =
            AnomalousLoginAnalyzer::shutdown_with_timeout(handle, tx, Duration::from_secs(1)).await;

        assert!(result.is_ok(), "响应 shutdown 信号的任务应返回 Ok");
    }

    /// shutdown_with_timeout 对已 cancelled 的任务返回 Ok（幂等）。
    #[tokio::test]
    async fn shutdown_with_timeout_already_cancelled() {
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        });
        let (tx, _rx) = watch::channel(false);
        handle.abort();

        let result =
            AnomalousLoginAnalyzer::shutdown_with_timeout(handle, tx, Duration::from_secs(1)).await;

        assert!(result.is_ok(), "已 cancelled 的任务应返回 Ok（幂等）");
    }

    /// shutdown_with_timeout 对 panic 的任务返回 Err（包含 panic 信息）。
    #[tokio::test]
    async fn shutdown_with_timeout_panic_task() {
        let handle = tokio::spawn(async {
            panic!("任务 panic 测试");
        });
        let (tx, _rx) = watch::channel(false);

        // 等待任务 panic 完成
        tokio::time::sleep(Duration::from_millis(50)).await;

        let result =
            AnomalousLoginAnalyzer::shutdown_with_timeout(handle, tx, Duration::from_secs(1)).await;

        assert!(result.is_err(), "panic 任务应返回 Err");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("panic"),
            "错误信息应包含 'panic'，实际: {}",
            err_msg
        );
    }

    /// start + shutdown 集成测试：正常 shutdown 信号路径。
    ///
    /// 创建真实 analyzer，start 后用 shutdown_with_timeout 停止，
    /// 验证任务在 1 秒内响应 shutdown 信号退出。
    #[tokio::test]
    async fn start_then_shutdown_normal_stop() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let (tx, rx) = watch::channel(false);
        let config = AnomalousAnalyzerConfig {
            interval_secs: 3600,
            burst_threshold: 5,
            max_scan: 100,
        };
        let analyzer = AnomalousLoginAnalyzer::new(dao, config, rx, None);
        let handle = analyzer.start();

        let result =
            AnomalousLoginAnalyzer::shutdown_with_timeout(handle, tx, Duration::from_secs(1)).await;

        assert!(result.is_ok(), "正常 shutdown 应返回 Ok");
    }
}
