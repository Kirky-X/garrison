// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Back-channel logout 投递器：队列 drain + POST logout token 到 RP 端点。
//!
//! 投递安全语义（对齐 dex `backchannel.go` 的 `CheckRedirect → ErrUseLastResponse`）：
//!
//! - **禁止跟随重定向**：`redirect::Policy::none()` 使 3xx 响应原样返回、
//!   不改发请求——重定向会把 POST 降级为 GET 并丢弃 `logout_token` 体，
//!   RP 侧永远收不到 token；302/3xx 一律按未投递处理（计入重试）。
//! - **单 RP 超时封顶**：client 级总超时（默认 5s），挂起的 RP 不阻塞
//!   队列 drain；超时按投递失败计入重试。
//!
//! 调度语义：投递失败递增 `pending_retries` 并按指数退避推后 `next_attempt_at`
//! （队列侧执行），退避未到期的行不进批——失败行不占批次槽位，健康行不被
//! 队头阻塞，对失败 RP 的重发压力随连续失败次数指数衰减。
//! 退役语义：到达 `max_ttl_at` 仍未成功的行置 `failed` 并 `tracing::warn!`
//! （不静默丢），后台 drain 不再触碰。

use super::queue::{BackChannelQueue, QueueEntry};
use crate::error::{GarrisonError, GarrisonResult};
use dbnexus::DbPool;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// 单 RP 投递超时封顶（client 级总超时）。
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// 队列行投递窗口默认值：24 小时。
pub const DEFAULT_MAX_TTL_SECS: i64 = 24 * 60 * 60;

/// 单次 drain 取批上限默认值。
pub const DEFAULT_BATCH_SIZE: i64 = 32;

/// 投递器配置。`Default` 对齐本模块常量（生产语义）。
#[derive(Debug, Clone)]
pub struct DelivererConfig {
    /// 单 RP 投递超时。
    pub timeout: Duration,
    /// 单次 drain 的取批上限。
    pub batch_size: i64,
}

impl Default for DelivererConfig {
    fn default() -> Self {
        Self {
            timeout: DELIVERY_TIMEOUT,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

/// 一轮 drain 的投递结果计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainSummary {
    /// 投递成功（RP 返回 2xx）。
    pub delivered: usize,
    /// 投递失败、未超 MaxTtl，计数已递增留待下轮。
    pub retried: usize,
    /// 投递失败且已过 MaxTtl，置 failed 退役。
    pub failed: usize,
}

impl DrainSummary {
    /// 是否有任何实际动作（空轮询为 false，后台任务据此免日志噪音）。
    pub fn has_activity(&self) -> bool {
        *self != Self::default()
    }
}

enum Verdict {
    /// RP 返回 2xx，已确认投递。
    Delivered,
    /// 未投递成功且未超窗，留待下轮。
    Retried,
    /// 未投递成功且已超窗，已退役。
    Failed,
}

/// 投递器：从队列 drain pending 行，向 RP back-channel 端点投递。
pub struct BackChannelDeliverer {
    queue: Arc<BackChannelQueue>,
    /// client_id → back-channel logout URI（部署方配置的 client 列表）。
    endpoints: BTreeMap<String, String>,
    http: reqwest::Client,
    config: DelivererConfig,
}

impl BackChannelDeliverer {
    /// 构造投递器（队列自带生产默认 MaxTtl 窗口）。
    pub fn new(
        pool: DbPool,
        endpoints: impl IntoIterator<Item = (String, String)>,
        config: DelivererConfig,
    ) -> GarrisonResult<Self> {
        let queue = Arc::new(BackChannelQueue::new(pool, DEFAULT_MAX_TTL_SECS));
        Self::with_queue(queue, endpoints, config)
    }

    /// 以既有队列构造投递器（与入队 listener 共享同一队列配置时使用）。
    pub fn with_queue(
        queue: Arc<BackChannelQueue>,
        endpoints: impl IntoIterator<Item = (String, String)>,
        config: DelivererConfig,
    ) -> GarrisonResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| GarrisonError::Config(format!("backchannel-http-client::{}", e)))?;
        Ok(Self {
            queue,
            endpoints: endpoints.into_iter().collect(),
            http,
            config,
        })
    }

    /// 队列引用（探针/运维查询用）。
    pub fn queue(&self) -> &BackChannelQueue {
        &self.queue
    }

    /// drain 一批 pending 行：逐行投递并落终态/重试计数。
    ///
    /// 单行失败不中断本轮（显性化计入 summary），队列读写错误向上传播。
    pub async fn drain_once(&self) -> GarrisonResult<DrainSummary> {
        let rows = self.queue.pending_batch(self.config.batch_size).await?;
        let mut summary = DrainSummary::default();
        for row in &rows {
            match self.deliver_one(row).await? {
                Verdict::Delivered => summary.delivered += 1,
                Verdict::Retried => summary.retried += 1,
                Verdict::Failed => summary.failed += 1,
            }
        }
        Ok(summary)
    }

    /// 启动后台 drain 任务：按固定间隔取批投递，随 `JoinHandle` 生命周期运行。
    ///
    /// 单轮失败仅 `warn` 显性化、下轮重试，不终止循环。周期内无 pending 行时
    /// 空转（无日志噪音）。
    pub fn spawn_drain_loop(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match self.drain_once().await {
                    Ok(summary) if summary.has_activity() => {
                        tracing::info!(
                            delivered = summary.delivered,
                            retried = summary.retried,
                            failed = summary.failed,
                            "backchannel-logout drain 完成"
                        );
                    },
                    Ok(_) => {},
                    Err(e) => {
                        tracing::warn!("backchannel-logout drain 失败（下轮重试）::{}", e);
                    },
                }
            }
        })
    }

    /// 投递单行并落库终态。
    async fn deliver_one(&self, row: &QueueEntry) -> GarrisonResult<Verdict> {
        let outcome = match self.endpoints.get(&row.client_id) {
            None => Err("no-endpoint-configured".to_string()),
            Some(uri) => match self.post_logout_token(uri, &row.logout_token).await {
                Ok(()) => Ok(()),
                Err(reason) => Err(reason),
            },
        };
        match outcome {
            Ok(()) => {
                self.queue.mark_delivered(&row.id).await?;
                Ok(Verdict::Delivered)
            },
            Err(reason) => {
                // 超窗判定对全部失败原因统一生效（缺端点的行同样退役，不得永久重试）
                let now = super::queue::unix_now_millis()?;
                if now >= row.max_ttl_at {
                    let retries = self.queue.increment_retries(&row.id).await?;
                    self.queue.mark_failed(&row.id).await?;
                    // 退役显性化（不静默丢）：日志不含 token 本体，仅行标识与计数
                    tracing::warn!(
                        queue_id = %row.id,
                        client_id = %row.client_id,
                        retries,
                        reason = %reason,
                        "backchannel-logout 投递超过 MaxTtl，置 failed 退役（不再投递）"
                    );
                    Ok(Verdict::Failed)
                } else {
                    // 重试原因 debug 级可观测（pending 刷屏场景不升 warn）
                    tracing::debug!(
                        queue_id = %row.id,
                        client_id = %row.client_id,
                        reason = %reason,
                        "backchannel-logout 投递失败，计入重试"
                    );
                    self.queue.increment_retries(&row.id).await?;
                    Ok(Verdict::Retried)
                }
            },
        }
    }

    /// POST `logout_token` 表单体到 RP 端点；2xx 视为成功。
    async fn post_logout_token(&self, uri: &str, logout_token: &str) -> Result<(), String> {
        let resp = self
            .http
            .post(uri)
            .form(&[("logout_token", logout_token)])
            .send()
            .await
            .map_err(|e| format!("transport::{}", e))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            // 3xx 到不了这里（Policy::none 不跟随），落到此分支的 3xx 同样按失败计
            Err(format!("http-status-{}", status.as_u16()))
        }
    }
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::queue::STATUS_PENDING;
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup(max_ttl_secs: i64) -> (DbPool, Arc<BackChannelQueue>) {
        let pool = setup_db().await;
        let queue = Arc::new(BackChannelQueue::new(pool.clone(), max_ttl_secs));
        (pool, queue)
    }

    fn deliverer(queue: Arc<BackChannelQueue>, uri: String) -> BackChannelDeliverer {
        BackChannelDeliverer::with_queue(
            queue,
            vec![("client-a".to_string(), uri)],
            DelivererConfig {
                timeout: Duration::from_millis(800),
                batch_size: 32,
            },
        )
        .expect("投递器构造应成功")
    }

    /// 常量对齐设计（单 RP 5s 封顶 / MaxTtl 24h）。
    #[test]
    fn default_config_matches_spec() {
        let config = DelivererConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(DEFAULT_MAX_TTL_SECS, 24 * 60 * 60);
    }

    /// 投递成功路径：logout_token 以表单体 POST，RP 2xx 后置 delivered。
    #[tokio::test]
    async fn delivers_logout_token_as_form_post() {
        let (_pool, queue) = setup(3600).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("logout_token=eyJ"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();
        let summary = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .expect("drain 应成功");
        assert_eq!(
            summary,
            DrainSummary {
                delivered: 1,
                retried: 0,
                failed: 0
            }
        );
        assert_eq!(queue.count_by_status(STATUS_PENDING).await.unwrap(), 0);
        assert_eq!(queue.count_by_status("delivered").await.unwrap(), 1);
        server.verify().await;
    }

    /// RP 返回 302 不被跟随（重定向目标零请求）、按未投递处理计入重试。
    #[tokio::test]
    async fn redirect_302_is_not_followed_and_counts_as_retry() {
        let (_pool, queue) = setup(3600).await;
        // 重定向目标：若被跟随（POST 降 GET）会命中此 mock
        let redirect_target = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&redirect_target)
            .await;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", &format!("{}/landing", redirect_target.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;

        let row_id = queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();
        let summary = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .expect("drain 应成功");
        assert_eq!(
            summary,
            DrainSummary {
                delivered: 0,
                retried: 1,
                failed: 0
            },
            "302 必须按未投递处理"
        );

        let entry = queue.find_by_id(&row_id).await.unwrap().expect("行应存在");
        assert_eq!(entry.status, STATUS_PENDING, "行应留在 pending 等待重试");
        assert_eq!(entry.pending_retries, 1, "302 应计入重试计数");
        assert!(
            entry.next_attempt_at > super::super::queue::unix_now_millis().unwrap(),
            "失败行应被退避推后，不立即重试"
        );

        // 退避期内同一行不再被投递（不对已知失败 RP 连续重发）
        let second = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .unwrap();
        assert_eq!(
            second,
            DrainSummary::default(),
            "退避未到期的行不得重复投递"
        );

        server.verify().await;
        redirect_target.verify().await;
    }

    /// RP 挂起时按配置超时失败并计入重试（不阻塞 drain）。
    #[tokio::test]
    async fn hanging_rp_hits_timeout_and_counts_as_retry() {
        let (_pool, queue) = setup(3600).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .expect(1)
            .mount(&server)
            .await;

        let row_id = queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();
        let start = std::time::Instant::now();
        let summary = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .expect("drain 应成功");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(4),
            "投递应在超时封顶内返回，实际 {:?}",
            elapsed
        );
        assert_eq!(
            summary,
            DrainSummary {
                delivered: 0,
                retried: 1,
                failed: 0
            },
            "超时按投递失败计入重试"
        );
        let entry = queue.find_by_id(&row_id).await.unwrap().expect("行应存在");
        assert_eq!(entry.pending_retries, 1, "超时应计入重试计数");
        server.verify().await;
    }

    /// drain 幂等：已 delivered 行不重复投递（RP 只收到一次 POST）。
    #[tokio::test]
    async fn drain_does_not_redeliver_delivered_rows() {
        let (_pool, queue) = setup(3600).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("logout_token=eyJ"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();
        let d = deliverer(Arc::clone(&queue), server.uri());
        let first = d.drain_once().await.unwrap();
        assert_eq!(first.delivered, 1);
        let second = d.drain_once().await.unwrap();
        assert_eq!(
            second,
            DrainSummary::default(),
            "第二轮不得重复投递已 delivered 行"
        );
        server.verify().await;
    }

    /// 进程内日志捕获 writer（fmt Layer 的 MakeWriter，收集格式化行）。
    #[derive(Clone)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<String>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            LogCaptureWriter(self.0.clone())
        }
    }

    struct LogCaptureWriter(Arc<std::sync::Mutex<Vec<String>>>);

    impl std::io::Write for LogCaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("日志缓冲锁应可用")
                .push(String::from_utf8_lossy(buf).to_string());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 失败递增计数；超过 MaxTtl 的行置 failed 并 warn 显性化；
    /// 退役行不再投递（drain 幂等）。
    #[tokio::test]
    async fn expired_row_fails_with_warn_and_stops_being_retried() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        // max_ttl_secs = 0 → max_ttl_at = 入队时刻，任何失败即超窗
        let (_pool, queue) = setup(0).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();

        let logs = LogCapture(Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(logs.clone()),
        );
        let _guard = subscriber.set_default();

        let summary = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .expect("drain 应成功");
        assert_eq!(
            summary,
            DrainSummary {
                delivered: 0,
                retried: 0,
                failed: 1
            },
            "超窗失败行应置 failed"
        );
        assert_eq!(queue.count_by_status("failed").await.unwrap(), 1);

        // warn 显性化：退役必须落日志（含 queue_id 与退役原因）
        let captured = logs.0.lock().unwrap().join("\n");
        assert!(
            captured.contains("置 failed 退役"),
            "超 MaxTtl 退役必须输出 warn，实际日志: {captured}"
        );

        // 退役行不再投递：RP 请求计数停在 1
        let second = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .unwrap();
        assert_eq!(second, DrainSummary::default());
        server.verify().await;
    }

    /// 未达 MaxTtl 的失败行保持 pending、计数递增（重试面）。
    #[tokio::test]
    async fn failure_before_max_ttl_increments_retries_only() {
        let (_pool, queue) = setup(3600).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let row_id = queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();
        let summary = deliverer(Arc::clone(&queue), server.uri())
            .drain_once()
            .await
            .unwrap();
        assert_eq!(
            summary,
            DrainSummary {
                delivered: 0,
                retried: 1,
                failed: 0
            }
        );
        let entry = queue.find_by_id(&row_id).await.unwrap().expect("行应存在");
        assert_eq!(entry.pending_retries, 1, "失败计数应落库");
        assert_eq!(entry.status, STATUS_PENDING, "未超窗失败行保持 pending");
        assert!(
            entry.next_attempt_at > super::super::queue::unix_now_millis().unwrap(),
            "失败行应按退避推后下次投递时刻"
        );
        assert_eq!(queue.count_by_status("failed").await.unwrap(), 0);
    }

    /// 配置缺端点的 client：投递失败计入重试（显性化，不静默丢）。
    #[tokio::test]
    async fn missing_endpoint_counts_as_retry() {
        let (_pool, queue) = setup(3600).await;
        let deliverer = BackChannelDeliverer::with_queue(
            Arc::clone(&queue),
            Vec::<(String, String)>::new(),
            DelivererConfig {
                timeout: Duration::from_millis(800),
                batch_size: 32,
            },
        )
        .unwrap();
        let row_id = queue
            .enqueue("unconfigured", "eyJ.header.payload")
            .await
            .unwrap();
        let summary = deliverer.drain_once().await.unwrap();
        assert_eq!(summary.retried, 1, "缺端点按失败计入重试");
        let entry = queue.find_by_id(&row_id).await.unwrap().expect("行应存在");
        assert_eq!(entry.pending_retries, 1);
        assert!(
            entry.next_attempt_at > super::super::queue::unix_now_millis().unwrap(),
            "缺端点失败行同样按退避推后"
        );
    }

    /// 防饥饿：退避中的死 RP 行不占批次槽位，健康 RP 的后入队行照常投递，
    /// 且退避期内不对死 RP 重发（二轮 0 请求）。
    #[tokio::test]
    async fn backed_off_dead_rp_does_not_starve_healthy_rps() {
        let (_pool, queue) = setup(3600).await;
        let dead = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&dead)
            .await;
        let healthy = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&healthy)
            .await;

        let deliverer = BackChannelDeliverer::with_queue(
            Arc::clone(&queue),
            vec![
                ("client-dead".to_string(), dead.uri()),
                ("client-fresh".to_string(), healthy.uri()),
            ],
            DelivererConfig {
                timeout: Duration::from_millis(800),
                batch_size: 32,
            },
        )
        .unwrap();

        // 第 1 轮：死 RP 行失败并被退避推后
        queue
            .enqueue("client-dead", "eyJ.header.payload")
            .await
            .unwrap();
        let first = deliverer.drain_once().await.unwrap();
        assert_eq!(first.retried, 1);

        // 第 2 轮：死行仍在退避期，其后入队的健康行必须照常投递
        queue
            .enqueue("client-fresh", "eyJ.header.payload")
            .await
            .unwrap();
        let second = deliverer.drain_once().await.unwrap();
        assert_eq!(
            second,
            DrainSummary {
                delivered: 1,
                retried: 0,
                failed: 0
            },
            "退避中的失败行不得阻塞健康行投递"
        );

        dead.verify().await;
        healthy.verify().await;
    }

    /// 后台 drain 任务：入队行在周期内被投递并置 delivered。
    #[tokio::test]
    async fn spawn_drain_loop_delivers_pending_rows() {
        let (_pool, queue) = setup(3600).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        queue
            .enqueue("client-a", "eyJ.header.payload")
            .await
            .unwrap();

        let deliverer = Arc::new(deliverer(Arc::clone(&queue), server.uri()));
        let handle = deliverer.spawn_drain_loop(Duration::from_millis(50));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while queue.count_by_status("delivered").await.unwrap() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "后台 drain 应在窗口内完成投递"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        handle.abort();
    }
}
