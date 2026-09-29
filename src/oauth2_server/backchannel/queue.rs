// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `oauth2_backchannel_queue` 持久化投递队列存取。
//!
//! 表结构由 `migrations/*/core/017_oauth2_backchannel_queue.sql` 创建
//! （四方言同名成对）。时间列统一存 Unix 毫秒（BIGINT）：drain 排序键为
//! `(next_attempt_at, created_at, id)`——失败行经 `increment_retries` 把
//! `next_attempt_at` 按指数退避推后，投递到期的健康行（含更晚入队者）不被
//! 队头的失败行阻塞；`id` 用 UUID v7（时间有序），作同毫秒 `created_at`
//! 并列时的稳定 tiebreaker。
//!
//! 存取走 `DbPool` 直连（admin 会话），与 `AuditLogListener` 同款先例——
//! `GarrisonDao` 是缓存抽象不支持 SQL，本表不进 Repository trait 面。

use crate::dao::repository::make_statement;
use crate::error::{GarrisonError, GarrisonResult};
use dbnexus::sea_orm::{ConnectionTrait, QueryResult, Value};
use dbnexus::DbPool;

/// 待投递。
pub const STATUS_PENDING: &str = "pending";
/// 已投递（RP 返回 2xx）。
pub const STATUS_DELIVERED: &str = "delivered";
/// 已退役（超过 MaxTtl 仍未投递成功，warn 显性化后不再投递）。
pub const STATUS_FAILED: &str = "failed";

/// 重试退避基数（毫秒）：第 n 次重试的 `next_attempt_at` 推后
/// `min(base × 2^(n-1), cap)`。
pub const DEFAULT_RETRY_BACKOFF_MILLIS: i64 = 5_000;
/// 重试退避封顶（毫秒）：退避上限 10 分钟，保证 MaxTtl 窗口内仍有重试机会。
pub const RETRY_BACKOFF_CAP_MILLIS: i64 = 600_000;

/// 第 `retries` 次重试（从 1 计）前的退避时长（毫秒）：指数增长、封顶截断。
pub fn retry_backoff_millis(base_millis: i64, cap_millis: i64, retries: i64) -> i64 {
    let mut delay = base_millis.max(0);
    // 指数部分封顶在 cap 本身：溢出与超限由 saturating + cap 截断兜底
    for _ in 1..retries.max(1) {
        delay = delay.saturating_mul(2);
        if delay >= cap_millis {
            return cap_millis.max(0);
        }
    }
    delay.min(cap_millis.max(0))
}

/// 队列行。
#[derive(Debug, Clone)]
pub struct QueueEntry {
    /// 行 ID（UUID v7，时间有序——drain 排序的稳定 tiebreaker；调用方生成，
    /// 不依赖自增）。
    pub id: String,
    /// 目标 RP 的 client_id。
    pub client_id: String,
    /// 已签发的 logout token（JWT 紧凑序列化）。
    pub logout_token: String,
    /// 投递状态（pending / delivered / failed）。
    pub status: String,
    /// 已重试次数（投递失败递增）。
    pub pending_retries: i64,
    /// 入队时间（Unix 毫秒）。
    pub created_at: i64,
    /// 下次允许投递的时间（Unix 毫秒；失败后按退避推后，到期前行不进批）。
    pub next_attempt_at: i64,
    /// 投递截止（Unix 毫秒；超过后失败即置 failed 退役）。
    pub max_ttl_at: i64,
}

/// 队列存取器。
pub struct BackChannelQueue {
    pool: DbPool,
    /// 入队行投递窗口（秒）：`max_ttl_at = 入队时刻 + max_ttl_secs`。
    max_ttl_secs: i64,
    /// 重试退避基数（毫秒）。
    retry_backoff_base_millis: i64,
    /// 重试退避封顶（毫秒）。
    retry_backoff_cap_millis: i64,
}

impl BackChannelQueue {
    /// 构造队列存取器。`max_ttl_secs` 为入队行的投递窗口（生产默认 24h，
    /// 见 [`crate::oauth2_server::backchannel::DEFAULT_MAX_TTL_SECS`]）；
    /// 退避参数取生产默认（5s 起、10min 封顶）。
    pub fn new(pool: DbPool, max_ttl_secs: i64) -> Self {
        Self {
            pool,
            max_ttl_secs,
            retry_backoff_base_millis: DEFAULT_RETRY_BACKOFF_MILLIS,
            retry_backoff_cap_millis: RETRY_BACKOFF_CAP_MILLIS,
        }
    }

    /// 覆写退避参数（测试缩短退避用；生产路径不经此构造）。
    pub fn with_backoff(mut self, base_millis: i64, cap_millis: i64) -> Self {
        self.retry_backoff_base_millis = base_millis;
        self.retry_backoff_cap_millis = cap_millis;
        self
    }

    /// 入队一行待投递 logout token，返回行 ID。
    pub async fn enqueue(&self, client_id: &str, logout_token: &str) -> GarrisonResult<String> {
        let id = uuid::Uuid::now_v7().to_string();
        let now = unix_now_millis()?;
        let max_ttl_at = now
            .checked_add(self.max_ttl_secs.saturating_mul(1000))
            .ok_or_else(|| GarrisonError::InvalidParam("backchannel-ttl-overflow".to_string()))?;
        self.execute(
            "INSERT INTO oauth2_backchannel_queue (id, client_id, logout_token, status, pending_retries, created_at, next_attempt_at, max_ttl_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Value::String(Some(id.clone())),
                Value::String(Some(client_id.to_string())),
                Value::String(Some(logout_token.to_string())),
                Value::String(Some(STATUS_PENDING.to_string())),
                Value::BigInt(Some(0)),
                Value::BigInt(Some(now)),
                Value::BigInt(Some(now)),
                Value::BigInt(Some(max_ttl_at)),
            ],
            "enqueue",
        )
        .await?;
        Ok(id)
    }

    /// 取一批到期待投递行（按 `(next_attempt_at, created_at, id)` 升序）。
    ///
    /// 退避中的行（`next_attempt_at` 在未来）不进批——失败行不占批次槽位，
    /// 其后入队的健康行不被队头阻塞。
    pub async fn pending_batch(&self, limit: i64) -> GarrisonResult<Vec<QueueEntry>> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-get-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-connection::{}", e)))?;
        let now = unix_now_millis()?;
        let stmt = make_statement(
            conn,
            "SELECT id, client_id, logout_token, status, pending_retries, created_at, next_attempt_at, max_ttl_at FROM oauth2_backchannel_queue WHERE status = ? AND next_attempt_at <= ? ORDER BY next_attempt_at ASC, created_at ASC, id ASC LIMIT ?",
            vec![
                Value::String(Some(STATUS_PENDING.to_string())),
                Value::BigInt(Some(now)),
                Value::BigInt(Some(limit)),
            ],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-pending::{}", e)))?;
        rows.iter().map(parse_entry).collect()
    }

    /// 按行 ID 读取（运维探针与重试状态回读用；含未到期行）。
    pub async fn find_by_id(&self, id: &str) -> GarrisonResult<Option<QueueEntry>> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-get-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-connection::{}", e)))?;
        let stmt = make_statement(
            conn,
            "SELECT id, client_id, logout_token, status, pending_retries, created_at, next_attempt_at, max_ttl_at FROM oauth2_backchannel_queue WHERE id = ?",
            vec![Value::String(Some(id.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-find::{}", e)))?;
        row.map(|r| parse_entry(&r)).transpose()
    }

    /// 标记投递成功。
    pub async fn mark_delivered(&self, id: &str) -> GarrisonResult<()> {
        self.transition(id, STATUS_DELIVERED).await
    }

    /// 标记退役（超过 MaxTtl 仍未投递成功，由投递器 warn 显性化后调用）。
    pub async fn mark_failed(&self, id: &str) -> GarrisonResult<()> {
        self.transition(id, STATUS_FAILED).await
    }

    /// 投递失败后的重试登记：计数递增并按指数退避推后 `next_attempt_at`，
    /// 返回递增后的计数。
    ///
    /// 退避使失败行让出批次槽位：到期前 `pending_batch` 不再返回该行，
    /// 对已知失败 RP 的重发压力随连续失败次数指数衰减。
    pub async fn increment_retries(&self, id: &str) -> GarrisonResult<i64> {
        let current = self
            .find_by_id(id)
            .await?
            .ok_or_else(|| GarrisonError::Dao(format!("backchannel-queue-missing-row::{id}")))?
            .pending_retries;
        let next_retries = current + 1;
        let now = unix_now_millis()?;
        let delay = retry_backoff_millis(
            self.retry_backoff_base_millis,
            self.retry_backoff_cap_millis,
            next_retries,
        );
        let next_attempt_at = now.checked_add(delay).ok_or_else(|| {
            GarrisonError::InvalidParam("backchannel-backoff-overflow".to_string())
        })?;
        self.execute(
            "UPDATE oauth2_backchannel_queue SET pending_retries = pending_retries + 1, next_attempt_at = ? WHERE id = ?",
            vec![
                Value::BigInt(Some(next_attempt_at)),
                Value::String(Some(id.to_string())),
            ],
            "increment-retries",
        )
        .await?;
        Ok(next_retries)
    }

    /// 按状态计数（测试与运维探针用）。
    pub async fn count_by_status(&self, status: &str) -> GarrisonResult<i64> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-get-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-connection::{}", e)))?;
        let stmt = make_statement(
            conn,
            "SELECT count(*) AS cnt FROM oauth2_backchannel_queue WHERE status = ?",
            vec![Value::String(Some(status.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-count::{}", e)))?
            .ok_or_else(|| GarrisonError::Dao("backchannel-queue-count-missing-row".to_string()))?;
        row.try_get::<i64>("", "cnt")
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-parse-count::{}", e)))
    }

    async fn transition(&self, id: &str, status: &str) -> GarrisonResult<()> {
        self.execute(
            "UPDATE oauth2_backchannel_queue SET status = ? WHERE id = ?",
            vec![
                Value::String(Some(status.to_string())),
                Value::String(Some(id.to_string())),
            ],
            "transition",
        )
        .await?;
        Ok(())
    }

    async fn execute(&self, sql: &str, values: Vec<Value>, op: &str) -> GarrisonResult<u64> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-get-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-connection::{}", e)))?;
        let stmt = make_statement(conn, sql, values);
        let result = conn
            .execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-{op}::{}", e)))?;
        Ok(result.rows_affected())
    }
}

fn parse_entry(row: &QueryResult) -> GarrisonResult<QueueEntry> {
    Ok(QueueEntry {
        id: get_string(row, "id")?,
        client_id: get_string(row, "client_id")?,
        logout_token: get_string(row, "logout_token")?,
        status: get_string(row, "status")?,
        pending_retries: get_i64(row, "pending_retries")?,
        created_at: get_i64(row, "created_at")?,
        next_attempt_at: get_i64(row, "next_attempt_at")?,
        max_ttl_at: get_i64(row, "max_ttl_at")?,
    })
}

fn get_string(row: &QueryResult, col: &str) -> GarrisonResult<String> {
    row.try_get::<Option<String>>("", col)
        .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-parse-{col}::{}", e)))?
        .ok_or_else(|| GarrisonError::Dao(format!("backchannel-queue-null-{col}")))
}

fn get_i64(row: &QueryResult, col: &str) -> GarrisonResult<i64> {
    row.try_get::<Option<i64>>("", col)
        .map_err(|e| GarrisonError::Dao(format!("backchannel-queue-parse-{col}::{}", e)))?
        .ok_or_else(|| GarrisonError::Dao(format!("backchannel-queue-null-{col}")))
}

pub(crate) fn unix_now_millis() -> GarrisonResult<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .map_err(|e| GarrisonError::Internal(format!("system-clock-error::{}", e)))
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;

    /// sqlite 面自动跑（017 迁移由 setup_db 自动应用）；postgres 面的等价
    /// roundtrip 走下方 `#[ignore]` 集成测试（SQL 经 make_statement 双后端通用）。
    async fn setup_queue(max_ttl_secs: i64) -> (DbPool, BackChannelQueue) {
        let pool = setup_db().await;
        let queue = BackChannelQueue::new(pool.clone(), max_ttl_secs);
        (pool, queue)
    }

    /// 入队 → pending 批次可见，字段 roundtrip 一致；初始即到期
    /// （`next_attempt_at == created_at`）；id 为时间有序 v7。
    #[tokio::test]
    async fn enqueue_then_pending_batch_roundtrip() {
        let (_pool, queue) = setup_queue(3600).await;
        let id = queue
            .enqueue("client-a", "token-jwt")
            .await
            .expect("入队应成功");
        assert!(!id.is_empty(), "应返回生成的行 ID");
        let parsed = uuid::Uuid::parse_str(&id).expect("行 ID 应为合法 UUID");
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::SortRand),
            "行 ID 应为 UUID v7（时间有序 tiebreaker）"
        );

        let batch = queue.pending_batch(10).await.expect("批次查询应成功");
        assert_eq!(batch.len(), 1, "pending 批次应恰有一行");
        let row = &batch[0];
        assert_eq!(row.id, id);
        assert_eq!(row.client_id, "client-a");
        assert_eq!(row.logout_token, "token-jwt");
        assert_eq!(row.status, STATUS_PENDING);
        assert_eq!(row.pending_retries, 0);
        assert_eq!(
            row.next_attempt_at, row.created_at,
            "入队行初始即到期，不得自带退避"
        );
        assert!(
            row.max_ttl_at >= row.created_at + 3600_000 - 1000,
            "max_ttl_at 应为入队时刻 + 窗口，实际: {:?}",
            row
        );
        assert_eq!(queue.count_by_status(STATUS_PENDING).await.unwrap(), 1);
    }

    /// 行 ID 为 UUID v7：时间有序，同毫秒并列时作 drain 排序的稳定 tiebreaker。
    #[test]
    fn enqueue_generates_time_ordered_v7_ids() {
        let a = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        // 同毫秒内 v7 递增与否依赖实现细节，这里只锁「可解析且版本为 v7」
        for id in [a, b] {
            assert_eq!(id.get_version(), Some(uuid::Version::SortRand));
        }
    }

    /// FIFO：先入队先出批；LIMIT 截断批次。
    #[tokio::test]
    async fn pending_batch_is_fifo_and_respects_limit() {
        let (_pool, queue) = setup_queue(3600).await;
        for i in 0..3 {
            queue
                .enqueue(&format!("client-{i}"), "t")
                .await
                .expect("入队应成功");
            // created_at 毫秒精度同毫秒可能并列，间隔 5ms 保证 FIFO 断言确定性
            // （同毫秒并列由 v7 id tiebreaker 稳定，但不保证 FIFO 语义）
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let batch = queue.pending_batch(2).await.expect("批次查询应成功");
        assert_eq!(batch.len(), 2, "LIMIT 应截断批次");
        assert_eq!(batch[0].client_id, "client-0", "FIFO 应先取最早入队行");
        assert_eq!(batch[1].client_id, "client-1");
    }

    /// 退避中的失败行不进批，也不阻塞其后入队的健康行（防队头阻塞）。
    #[tokio::test]
    async fn deferred_failed_row_does_not_block_later_rows() {
        let (_pool, queue) = setup_queue(3600).await;
        let dead = queue.enqueue("client-dead", "t").await.unwrap();
        queue.increment_retries(&dead).await.unwrap();
        queue.enqueue("client-fresh", "t").await.unwrap();

        let batch = queue.pending_batch(10).await.unwrap();
        let clients: Vec<&str> = batch.iter().map(|r| r.client_id.as_str()).collect();
        assert_eq!(
            clients,
            vec!["client-fresh"],
            "退避未到期的行不得进批，更不得阻塞其后入队行"
        );
    }

    /// 重试退避指数增长且封顶：第 n 次失败后的下次可投时刻按
    /// `min(base × 2^(n-1), cap)` 推后；退避期内不进批（大退避面，
    /// 幅度远超 DB 往返延迟）、到期后重新进批（小退避面）。
    #[tokio::test]
    async fn increment_retries_schedules_exponential_backoff() {
        // 大退避面：退避幅度下界可精确断言（next_attempt_at 相对增量前时刻
        // ≥ base），且 2s ≫ DB 往返延迟，「不进批」断言无竞态
        let pool = setup_db().await;
        let queue = BackChannelQueue::new(pool.clone(), 3600).with_backoff(2_000, 600_000);
        let slow_id = queue.enqueue("client-slow", "t").await.unwrap();

        let before = unix_now_millis().unwrap();
        assert_eq!(queue.increment_retries(&slow_id).await.unwrap(), 1);
        let entry = queue.find_by_id(&slow_id).await.unwrap().unwrap();
        assert!(
            entry.next_attempt_at - before >= 2_000,
            "退避至少推后一个基数，实际 {}ms",
            entry.next_attempt_at - before
        );
        assert!(
            queue.pending_batch(10).await.unwrap().is_empty(),
            "退避期内行不得进批"
        );

        // 小退避面：到期后必回批；指数倍增与封顶的下界逐次可断言
        let queue = BackChannelQueue::new(pool.clone(), 3600).with_backoff(50, 200);
        let id = queue.enqueue("client-fast", "t").await.unwrap();

        let before = unix_now_millis().unwrap();
        assert_eq!(queue.increment_retries(&id).await.unwrap(), 1);
        let entry = queue.find_by_id(&id).await.unwrap().unwrap();
        assert!(
            entry.next_attempt_at - before >= 50,
            "第 1 次退避下界 50ms，实际 {}ms",
            entry.next_attempt_at - before
        );
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert_eq!(
            queue.pending_batch(10).await.unwrap().len(),
            1,
            "到期后行应重新进批"
        );

        // 第 2 次失败：退避 2 倍增（下界 100ms）
        let before = unix_now_millis().unwrap();
        assert_eq!(queue.increment_retries(&id).await.unwrap(), 2);
        let entry = queue.find_by_id(&id).await.unwrap().unwrap();
        assert!(
            entry.next_attempt_at - before >= 100,
            "第 2 次退避下界 100ms（2 倍增），实际 {}ms",
            entry.next_attempt_at - before
        );

        // 连续失败至封顶：退避停在 cap=200ms（下界可精确断言；
        // 精确封顶数学由 retry_backoff_millis 纯函数测试锁定）
        for _ in 0..4 {
            tokio::time::sleep(std::time::Duration::from_millis(210)).await;
            queue.increment_retries(&id).await.unwrap();
        }
        // 封顶下界断言的时刻基准取在末次递增之前（与上方两步同法）
        let before = unix_now_millis().unwrap();
        assert_eq!(queue.increment_retries(&id).await.unwrap(), 7);
        let entry = queue.find_by_id(&id).await.unwrap().unwrap();
        assert_eq!(entry.pending_retries, 7, "计数应逐次落库");
        assert!(
            entry.next_attempt_at - before >= 200,
            "退避应在 200ms 封顶，实际 {}ms",
            entry.next_attempt_at - before
        );
    }

    /// 退避时长函数：指数增长、封顶截断、零基数与溢出安全。
    #[test]
    fn retry_backoff_millis_grows_exponentially_and_caps() {
        let base = 5_000;
        let cap = 600_000;
        assert_eq!(retry_backoff_millis(base, cap, 1), 5_000);
        assert_eq!(retry_backoff_millis(base, cap, 2), 10_000);
        assert_eq!(retry_backoff_millis(base, cap, 3), 20_000);
        assert_eq!(retry_backoff_millis(base, cap, 8), 600_000, "超过 cap 截断");
        assert_eq!(
            retry_backoff_millis(i64::MAX / 2, cap, 40),
            cap,
            "大指数溢出安全"
        );
        assert_eq!(retry_backoff_millis(0, cap, 3), 0, "零基数不产生退避");
    }

    /// delivered / failed 终态行不再出现在 pending 批次。
    #[tokio::test]
    async fn terminal_states_leave_pending_batch() {
        let (_pool, queue) = setup_queue(3600).await;
        let a = queue.enqueue("client-a", "t").await.unwrap();
        let b = queue.enqueue("client-b", "t").await.unwrap();

        queue.mark_delivered(&a).await.expect("标记投递应成功");
        queue.mark_failed(&b).await.expect("标记退役应成功");

        assert!(
            queue.pending_batch(10).await.unwrap().is_empty(),
            "终态行不得留在 pending 批次"
        );
        assert_eq!(queue.count_by_status(STATUS_DELIVERED).await.unwrap(), 1);
        assert_eq!(queue.count_by_status(STATUS_FAILED).await.unwrap(), 1);
    }
}

/// postgres 后端 roundtrip（真实库，需 DATABASE_URL，独立 feature 门控避免
/// full 组合（db-sqlite 面）引用 db-postgres 专属迁移通道）：
/// `cargo test --features db-postgres --lib backchannel -- --ignored`。
#[cfg(all(test, feature = "db-postgres"))]
mod postgres_tests {
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "requires postgres DATABASE_URL (set SINNAN_TEST_DATABASE_URL to run)"]
    async fn queue_roundtrip_on_postgres_backend() {
        let url = std::env::var("DATABASE_URL")
            .or_else(|_| std::env::var("SINNAN_TEST_DATABASE_URL"))
            .expect("DATABASE_URL 或 SINNAN_TEST_DATABASE_URL 必须设置才能运行此测试");
        let pool = crate::dao::init_dbnexus(&url)
            .await
            .expect("init_dbnexus 应成功（数据库可达）");
        let migration = crate::dao::GarrisonMigration::with_base_dir(
            pool.clone(),
            std::path::PathBuf::from("migrations/postgres"),
        );
        migration
            .migrate_core()
            .await
            .expect("目录迁移（含 017）应成功");
        let queue = BackChannelQueue::new(pool, 3600);
        let id = queue.enqueue("client-pg", "token-pg").await.unwrap();
        // 共享库可能残留他次运行的 pending 行，断言「本行可见/可消费」而非全局计数
        let batch = queue.pending_batch(100).await.unwrap();
        let mine = batch
            .iter()
            .find(|row| row.id == id)
            .expect("刚入队的行应出现在 pending 批次");
        assert_eq!(mine.client_id, "client-pg");
        queue.mark_delivered(&id).await.unwrap();
        let after = queue.pending_batch(100).await.unwrap();
        assert!(
            after.iter().all(|row| row.id != id),
            "已投递行不得再出现在 pending 批次"
        );
    }
}
