// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 事件派发事务绑定（OnCommit 语义）——`GarrisonEventTx` RAII 事务 guard。
//!
//! 解决「写库 + 广播事件」不一致的问题：事件缓冲在 guard 中，事务 commit 成功后才派发；
//! rollback 或未 commit 丢弃 guard 时缓冲事件随之丢弃。
//!
//! # 事务路由边界
//!
//! - 经 guard `execute`（内部 `Session::execute_raw`）的 SQL **加入本事务**（in-tx 路由）。
//! - 既有 DAO / Repository 经 `session.connection()` 的 SQL **不加入本事务**（auto-commit），混用由调用方保证顺序。
//! - DDL 不可经 `execute` 执行；`execute` 为 admin 特权直通通道（dbnexus 对 admin 跳过全部表级权限检查，且 SQL 解析
//!   失败同样放行）——`sql` 内容即权限边界，禁止拼接不可信输入，详见 [`GarrisonEventTx::execute`] 的 `# Security` 段。
//!
//! # 生命周期（状态机在类型层面表达「提交后不可再用」）
//!
//! ```text
//! begin ──→ on_commit / execute（可重复） ──→ commit(mut self)   → 派发缓冲事件
//!                                        └─→ rollback(mut self) → 丢弃缓冲事件
//! 未 commit / rollback 即 drop ──→ 缓冲丢弃 + tracing::warn（uncommitted）+ dbnexus 级联回滚
//! commit 失败 ──→ Err + 缓冲丢弃 + warn（commit-failed）
//! commit 成功后派发中途被取消 ──→ 剩余丢弃 + warn（dispatch-cancelled，携带已派发/总数）
//! ```
//!
//! # 并发 guard 的锁等待语义（生产后端）
//!
//! 并发 guard 各持独立 Session = 独立事务：postgres / mysql 下触碰同一行将持行锁直至 `commit`
//!（锁窗口显著长于 auto-commit）；sqlite 文件库并发写会 `SQLITE_BUSY`。begin→commit 之间只放该事务强相关的写与逻辑。
//!
//! # async 取消窗口（已知边界）
//!
//! 派发游标逐事件推进：中途取消时 `Drop` 以 dispatch-cancelled 原因 warn，但两个残余窗口无法精确归因——
//! 取消点恰在 `session.commit().await` 期间（DB 是否已提交不可知，按 commit-failed warn）；取消点恰在最后一个
//! 事件的派发 await 期间（在途事件是否到达 listener 不可知）。`Drop` 告警网保证丢弃可见，不保证精确归因。
//!
//! # 典型用法
//!
//! ```rust,ignore
//! let mut tx = GarrisonEventTx::begin(&pool, listener_manager).await?;
//! tx.execute("INSERT INTO app_login_log (...) VALUES (...)").await?;
//! tx.on_commit(GarrisonEvent::Login { .. });
//! let outcome = tx.commit().await?; // DB 提交成功后才派发事件
//! ```

use crate::error::{GarrisonError, GarrisonResult};
// 依赖方向单向：事务 guard 归 dao、依赖 listener；listener 生产代码不反向依赖
// dao（audit.rs 有意持 DbPool 直连），防止未来出现模块环。
use crate::listener::{DispatchOutcome, GarrisonEvent, GarrisonListenerManager};
use dbnexus::DbPool;
use std::sync::Arc;

/// 事件派发事务 guard（OnCommit 语义）。
///
/// 持有一个独立的 dbnexus `Session`（从 `DbPool` 获取）与监听器管理器引用，
/// 缓冲 `GarrisonEvent` 至 commit 成功后派发。参阅[模块文档](super)了解
/// 事务路由边界与生命周期。
pub struct GarrisonEventTx {
    /// 事务会话；`commit`/`rollback` 时 `take`，`None` 表示已终结。
    session: Option<dbnexus::Session>,
    /// OnCommit 档派发通道。
    lm: Arc<GarrisonListenerManager>,
    /// 缓冲事件（FIFO）。
    buffer: Vec<GarrisonEvent>,
    /// DB commit 是否已成功；`Drop` 据此区分 commit-failed 与派发取消两种丢弃。
    committed: bool,
    /// 已完成派发的缓冲前缀长度（派发游标）；commit 成功后逐事件推进，
    /// future 被取消时停在原位，供 `Drop` 判定「已派发/总数」。
    dispatched: usize,
}

impl GarrisonEventTx {
    /// 从池获取独立 Session 并开启事务（固定 `"admin"` 角色：进程内框架通道，非用户输入，绕过表级权限检查）；begin 失败返回 `Err` 不产生 guard。
    pub async fn begin(pool: &DbPool, lm: Arc<GarrisonListenerManager>) -> GarrisonResult<Self> {
        let session = pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("event-tx-get-session::{}", e)))?;
        session
            .begin_transaction()
            .await
            .map_err(|e| GarrisonError::Dao(format!("event-tx-begin::{}", e)))?;
        Ok(Self {
            session: Some(session),
            lm,
            buffer: Vec::new(),
            committed: false,
            dispatched: 0,
        })
    }

    /// 缓冲事件，commit 成功后按 FIFO 顺序派发。
    pub fn on_commit(&mut self, event: GarrisonEvent) {
        self.buffer.push(event);
    }

    /// 在本事务内执行写 SQL（INSERT / UPDATE / DELETE），返回受影响行数；仅经 guard 的写加入本事务
    ///（DAO / Repository 经 `session.connection()` 的 SQL 为 auto-commit，不加入）。
    ///
    /// # Security（特权直通通道）
    ///
    /// `begin` 以固定 `"admin"` 角色建 Session，dbnexus 对 admin **跳过全部表级权限检查，且 SQL 解析失败同样放行**——
    /// `sql` 内容即权限边界：严禁拼接不可信输入；签名不支持占位符绑定（继承 `Session::execute_raw`），
    /// 含动态值的写应改用支持参数绑定的 DAO / Repository 通道，确需本通道时仅限框架内部受控 SQL。
    pub async fn execute(&self, sql: &str) -> GarrisonResult<u64> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| GarrisonError::Internal("event-tx-already-finished".to_string()))?;
        let result = session
            .execute_raw(sql)
            .await
            .map_err(|e| GarrisonError::Dao(format!("event-tx-execute::{}", e)))?;
        Ok(result.rows_affected())
    }

    /// 提交事务（消耗 `self`，提交后不可再用——编译期保证）并按 FIFO 派发全部缓冲事件。
    ///
    /// commit 失败（含 dbnexus `Arc::try_unwrap` 并发冲突）返回 `Err`，缓冲不派发、随 guard 丢弃并由 `Drop` warn；
    /// 单个 listener `Err`/panic 不中断派发，计入 [`DispatchOutcome::failed`]（审计链缺口显性化）。
    /// 派发中途 future 被取消时无返回值，`Drop` 以 dispatch-cancelled 原因 warn 已派发/总数。
    pub async fn commit(mut self) -> GarrisonResult<DispatchOutcome> {
        let session = self
            .session
            .take()
            .ok_or_else(|| GarrisonError::Internal("event-tx-already-finished".to_string()))?;
        session
            .commit()
            .await
            .map_err(|e| GarrisonError::Dao(format!("event-tx-commit::{}", e)))?;
        // 提交后立即归还池连接：dbnexus 仅在 Session Drop 时归还槽位，持有跨派发阶段会让
        // 同步审计 listener（audit.rs 直连同一池取连接）在并发 in-flight commit ≥ 池上限时
        // 等满 acquire_timeout 并计入 failed，放大本特性要消除的审计链缺口。
        drop(session);
        self.committed = true;
        let mut outcome = DispatchOutcome::default();
        for index in self.dispatched..self.buffer.len() {
            let one = self
                .lm
                .broadcast_after_commit(std::slice::from_ref(&self.buffer[index]))
                .await;
            outcome.dispatched += one.dispatched;
            outcome.failed += one.failed;
            self.dispatched = index + 1;
        }
        Ok(outcome)
    }

    /// 回滚事务（消耗 `self`）并丢弃全部缓冲事件——事件与未提交写同生共死，回滚结果不影响「事件不派发」语义。
    pub async fn rollback(mut self) -> GarrisonResult<()> {
        let session = self
            .session
            .take()
            .ok_or_else(|| GarrisonError::Internal("event-tx-already-finished".to_string()))?;
        self.buffer.clear();
        session
            .rollback()
            .await
            .map_err(|e| GarrisonError::Dao(format!("event-tx-rollback::{}", e)))?;
        Ok(())
    }
}

impl Drop for GarrisonEventTx {
    fn drop(&mut self) {
        // 兜底安全网：缓冲事件未派发即丢弃的三条路径都在此显性化——
        // (1) 未 commit/rollback 即 drop：打开事务随 SessionState drop 级联回滚（sqlx 语义），连接入池；
        // (2) commit() 失败后 guard 被消耗：session 已 take、buffer 非空且未 committed；
        // (3) commit 成功后派发中途被取消：游标停在中途，warn 已派发/总数让审计链缺口可见。
        let open_tx = self.session.take().is_some();
        if open_tx {
            tracing::warn!(
                "garrison-event-tx-dropped-without-commit: {} buffered event(s) discarded, \
                 kinds: [{}], open transaction rolled back via dbnexus drop cascade",
                self.buffer.len(),
                event_summary(&self.buffer)
            );
        } else if !self.buffer.is_empty() && !self.committed {
            tracing::warn!(
                "garrison-event-tx-discarded-after-commit-failure: commit returned Err, \
                 {} buffered event(s) discarded without dispatch, kinds: [{}]",
                self.buffer.len(),
                event_summary(&self.buffer)
            );
        } else if self.committed && self.dispatched < self.buffer.len() {
            tracing::warn!(
                "garrison-event-tx-dispatch-cancelled-after-commit: commit succeeded but the \
                 dispatch future was cancelled mid-dispatch, {} of {} event(s) dispatched, \
                 remaining discarded without dispatch, kinds: [{}]",
                self.dispatched,
                self.buffer.len(),
                event_summary(&self.buffer[self.dispatched..])
            );
        }
        self.buffer.clear();
    }
}

/// 事件丢弃 warn 的事件摘要：按变体名聚合计数（如 `Login=1, PermissionCheck=2`）。
/// `event_kind` 为穷尽 match（无 `_` 兜底），新增变体在此编译报错提醒；仅取变体名控制兜底日志体积。
fn event_summary(events: &[GarrisonEvent]) -> String {
    let mut counts: Vec<(&'static str, usize)> = Vec::new();
    for event in events {
        let kind = event_kind(event);
        match counts.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, count)) => *count += 1,
            None => counts.push((kind, 1)),
        }
    }
    counts
        .iter()
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// [`GarrisonEvent`] 变体名（丢弃 warn 摘要用）。
fn event_kind(event: &GarrisonEvent) -> &'static str {
    match event {
        GarrisonEvent::Login { .. } => "Login",
        GarrisonEvent::Logout { .. } => "Logout",
        GarrisonEvent::Kickout { .. } => "Kickout",
        GarrisonEvent::PermissionCheck { .. } => "PermissionCheck",
        GarrisonEvent::RoleCheck { .. } => "RoleCheck",
        GarrisonEvent::TokenExpired { .. } => "TokenExpired",
        GarrisonEvent::LoginFailure { .. } => "LoginFailure",
        GarrisonEvent::PasswordRehashed { .. } => "PasswordRehashed",
        GarrisonEvent::TokenRefresh { .. } => "TokenRefresh",
        GarrisonEvent::RevokeToken { .. } => "RevokeToken",
        GarrisonEvent::SessionTimeout { .. } => "SessionTimeout",
        GarrisonEvent::AccountLocked { .. } => "AccountLocked",
        GarrisonEvent::FirewallBlock { .. } => "FirewallBlock",
        GarrisonEvent::Replaced { .. } => "Replaced",
        GarrisonEvent::ConfigReload { .. } => "ConfigReload",
        GarrisonEvent::SocialLogin { .. } => "SocialLogin",
        GarrisonEvent::TenantSwitch { .. } => "TenantSwitch",
        GarrisonEvent::TokenRotate { .. } => "TokenRotate",
        GarrisonEvent::TempCredentialConsumed { .. } => "TempCredentialConsumed",
        GarrisonEvent::InvitationCreated { .. } => "InvitationCreated",
        GarrisonEvent::InvitationRedeemed { .. } => "InvitationRedeemed",
        GarrisonEvent::InvitationRevoked { .. } => "InvitationRevoked",
        GarrisonEvent::QrLoginCreated { .. } => "QrLoginCreated",
        GarrisonEvent::QrLoginScanned { .. } => "QrLoginScanned",
        GarrisonEvent::QrLoginConfirmed { .. } => "QrLoginConfirmed",
        GarrisonEvent::QrLoginCancelled { .. } => "QrLoginCancelled",
        GarrisonEvent::DeviceBlock { .. } => "DeviceBlock",
        GarrisonEvent::DeviceUnblock { .. } => "DeviceUnblock",
        #[cfg(feature = "anomalous-detector-dual")]
        GarrisonEvent::AnomalousLoginDetected { .. } => "AnomalousLoginDetected",
        #[cfg(feature = "credit-metering")]
        GarrisonEvent::CreditConsumed { .. } => "CreditConsumed",
        #[cfg(feature = "credit-metering")]
        GarrisonEvent::CreditAlert { .. } => "CreditAlert",
    }
}

// 单元测试（事件派发事务绑定；覆盖 commit/rollback/drop 三路径、FIFO、并发、
// commit 失败与派发取消的 warn 捕获；listener 以运行时 register 注入 mock，绕开 inventory 污染）

#[cfg(all(test, feature = "db-sqlite", feature = "listener"))]
mod tests {
    use super::*;
    use crate::dao::{init_dbnexus, GarrisonMigration};
    use crate::listener::GarrisonListener;
    use async_trait::async_trait;
    use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement};
    use parking_lot::Mutex;
    use std::path::PathBuf;

    /// 建池 + 项目 core 迁移 + 专用测试表，供事务写断言。
    async fn setup_pool() -> dbnexus::DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migrations_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("sqlite");
        let migration = GarrisonMigration::with_base_dir(pool.clone(), migrations_dir);
        migration.migrate_core().await.expect("migrate_core 应成功");
        let session = pool.get_session("admin").await.expect("get_session 应成功");
        session
            .execute_raw_ddl(
                "CREATE TABLE garrison_event_tx_test \
                 (id INTEGER PRIMARY KEY, tag TEXT NOT NULL)",
            )
            .await
            .expect("建测试表应成功");
        drop(session);
        pool
    }

    /// 构造仅含 inventory 注册项 + 一个运行时 listener 的 manager。
    fn manager_with(listener: Arc<dyn GarrisonListener>) -> Arc<GarrisonListenerManager> {
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(listener);
        lm
    }

    /// 新 Session 查询测试表内指定 tag 的行数（auto-commit 路径，验证事务结果）。
    async fn count_rows(pool: &dbnexus::DbPool, tag: &str) -> i64 {
        let session = pool.get_session("admin").await.expect("get_session 应成功");
        let conn = session.connection().expect("connection 应可用");
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT count(*) AS cnt FROM garrison_event_tx_test WHERE tag = ?",
            vec![tag.to_string().into()],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .expect("count 查询应成功")
            .expect("count 应返回一行");
        row.try_get::<i64>("", "cnt").expect("cnt 列应存在")
    }

    /// 记录到达事件的测试标签（运行时注册，绕开 inventory）。
    struct RecordingListener {
        tags: Mutex<Vec<String>>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                tags: Mutex::new(Vec::new()),
            }
        }

        fn snapshot(&self) -> Vec<String> {
            self.tags.lock().clone()
        }
    }

    #[async_trait]
    impl GarrisonListener for RecordingListener {
        async fn on_event(&self, event: &GarrisonEvent) -> GarrisonResult<()> {
            self.tags.lock().push(event_tag(event));
            Ok(())
        }
    }

    /// 进入 `on_event` 即永久挂起的 listener：先经 oneshot 通知测试已到达派发 await 点，再 `pending()` 永不返回，
    /// 使 commit future 停在派发期间直至被取消。
    struct BlockingListener {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    #[async_trait]
    impl GarrisonListener for BlockingListener {
        async fn on_event(&self, _event: &GarrisonEvent) -> GarrisonResult<()> {
            if let Some(tx) = self.entered.lock().take() {
                let _ = tx.send(());
            }
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    /// 事件测试标签：FIFO 顺序与到达断言的鉴别符。
    fn event_tag(event: &GarrisonEvent) -> String {
        match event {
            GarrisonEvent::Login { login_id, .. } => format!("login:{login_id}"),
            GarrisonEvent::PermissionCheck { permission, .. } => {
                format!("perm:{permission}")
            },
            GarrisonEvent::Logout { login_id, .. } => format!("logout:{login_id}"),
            _ => "other".to_string(),
        }
    }

    fn login_event(login_id: &str) -> GarrisonEvent {
        GarrisonEvent::Login {
            login_id: login_id.to_string(),
            token: "T1".to_string(),
            device: None,
            request_context: None,
        }
    }

    fn perm_event(permission: &str) -> GarrisonEvent {
        GarrisonEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: permission.to_string(),
            request_context: None,
        }
    }

    /// commit 后才派发 + 写与事件同事务（listener 在 commit 前未收到、commit 后收到，且 DB 行存在）。
    #[tokio::test(flavor = "multi_thread")]
    async fn commit_dispatches_after_db_commit() {
        let pool = setup_pool().await;
        let recorder = Arc::new(RecordingListener::new());
        let lm = manager_with(recorder.clone());

        let mut guard = GarrisonEventTx::begin(&pool, lm)
            .await
            .expect("begin 应成功");
        guard.on_commit(login_event("1001"));
        assert!(
            recorder.snapshot().is_empty(),
            "commit 前 listener 不应收到缓冲事件"
        );

        let affected = guard
            .execute("INSERT INTO garrison_event_tx_test (id, tag) VALUES (1, 'committed')")
            .await
            .expect("事务内 INSERT 应成功");
        assert_eq!(affected, 1, "INSERT 应影响 1 行");

        guard.commit().await.expect("commit 应成功");

        assert_eq!(
            recorder.snapshot(),
            vec!["login:1001".to_string()],
            "commit 后 listener 应恰好收到缓冲的 Login 事件"
        );
        assert_eq!(
            count_rows(&pool, "committed").await,
            1,
            "事务提交后写入的行应可见"
        );
    }

    /// rollback 丢弃缓冲事件与事务写（listener 未收到，新 Session 查 count == 0）。
    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_discards_events_and_writes() {
        let pool = setup_pool().await;
        let recorder = Arc::new(RecordingListener::new());
        let lm = manager_with(recorder.clone());

        let mut guard = GarrisonEventTx::begin(&pool, lm)
            .await
            .expect("begin 应成功");
        guard.on_commit(login_event("2001"));
        guard
            .execute("INSERT INTO garrison_event_tx_test (id, tag) VALUES (2, 'rolled-back')")
            .await
            .expect("事务内 INSERT 应成功");

        guard.rollback().await.expect("rollback 应成功");

        assert!(
            recorder.snapshot().is_empty(),
            "rollback 后缓冲事件不应派发"
        );
        assert_eq!(
            count_rows(&pool, "rolled-back").await,
            0,
            "回滚后事务内写入的行不应存在"
        );
    }

    /// 未 commit/rollback 即 drop 的 RAII 安全网：listener 未收到、事务写经 dbnexus 级联回滚不可见（Drop 仅 warn 不 panic）。
    #[tokio::test(flavor = "multi_thread")]
    async fn drop_without_commit_is_safe() {
        let pool = setup_pool().await;
        let recorder = Arc::new(RecordingListener::new());
        let lm = manager_with(recorder.clone());

        let mut guard = GarrisonEventTx::begin(&pool, lm)
            .await
            .expect("begin 应成功");
        guard.on_commit(login_event("3001"));
        guard
            .execute("INSERT INTO garrison_event_tx_test (id, tag) VALUES (3, 'dropped')")
            .await
            .expect("事务内 INSERT 应成功");
        drop(guard);

        assert!(
            recorder.snapshot().is_empty(),
            "未提交即 drop，缓冲事件不应派发"
        );
        assert_eq!(
            count_rows(&pool, "dropped").await,
            0,
            "级联回滚后事务内写入的行不应存在"
        );
    }

    /// OnCommit 派发顺序为 FIFO（listener 到达顺序 == 缓冲顺序）。
    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_order_is_fifo() {
        let pool = setup_pool().await;
        let recorder = Arc::new(RecordingListener::new());
        let lm = manager_with(recorder.clone());

        let mut guard = GarrisonEventTx::begin(&pool, lm)
            .await
            .expect("begin 应成功");
        guard.on_commit(perm_event("p1"));
        guard.on_commit(perm_event("p2"));
        guard.on_commit(perm_event("p3"));
        guard.commit().await.expect("commit 应成功");

        assert_eq!(
            recorder.snapshot(),
            vec![
                "perm:p1".to_string(),
                "perm:p2".to_string(),
                "perm:p3".to_string()
            ],
            "派发顺序应与缓冲顺序一致（FIFO）"
        );
    }

    /// 并发 guard 无串扰：各自 listener 恰好收到各自事件，各自事务写各自可见。
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_txs_no_crosstalk() {
        let pool_a = setup_pool().await;
        let pool_b = setup_pool().await;
        let recorder_a = Arc::new(RecordingListener::new());
        let recorder_b = Arc::new(RecordingListener::new());
        let lm_a = manager_with(recorder_a.clone());
        let lm_b = manager_with(recorder_b.clone());

        let (outcome_a, outcome_b) = tokio::join!(
            async {
                let mut guard = GarrisonEventTx::begin(&pool_a, lm_a)
                    .await
                    .expect("begin a 应成功");
                guard.on_commit(login_event("tx-a"));
                guard
                    .execute("INSERT INTO garrison_event_tx_test (id, tag) VALUES (10, 'tx-a')")
                    .await
                    .expect("事务 a 内 INSERT 应成功");
                guard.commit().await.expect("commit a 应成功")
            },
            async {
                let mut guard = GarrisonEventTx::begin(&pool_b, lm_b)
                    .await
                    .expect("begin b 应成功");
                guard.on_commit(login_event("tx-b"));
                guard
                    .execute("INSERT INTO garrison_event_tx_test (id, tag) VALUES (11, 'tx-b')")
                    .await
                    .expect("事务 b 内 INSERT 应成功");
                guard.commit().await.expect("commit b 应成功")
            },
        );
        assert_eq!(
            outcome_a.dispatched + outcome_a.failed,
            1,
            "guard a 派发事件总数应为 1"
        );
        assert_eq!(
            outcome_b.dispatched + outcome_b.failed,
            1,
            "guard b 派发事件总数应为 1"
        );

        assert_eq!(
            recorder_a.snapshot(),
            vec!["login:tx-a".to_string()],
            "listener a 应恰好收到 guard a 的事件"
        );
        assert_eq!(
            recorder_b.snapshot(),
            vec!["login:tx-b".to_string()],
            "listener b 应恰好收到 guard b 的事件"
        );
        assert_eq!(count_rows(&pool_a, "tx-a").await, 1, "事务 a 写应可见");
        assert_eq!(count_rows(&pool_b, "tx-b").await, 1, "事务 b 写应可见");
    }

    /// `GarrisonEventTx` 需跨 `.await` 持有（Session 字段均为 Send + Sync），
    /// 编译期检查，仿 repository::tests 先例。
    #[test]
    fn garrison_event_tx_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GarrisonEventTx>();
    }

    // --------------------------------------------------------------------
    // 缓冲事件丢弃显性化：tracing 捕获层断言丢弃 warn
    // （CollectLayer 仿 web_warp request_id 先例；tracing 的 callsite interest
    // 缓存是进程级全局态，并行非订阅者测试可能抢先缓存 Interest::never，
    // 故捕获缺失时重建 interest 后重试）
    // --------------------------------------------------------------------

    /// 进程内 tracing 捕获层：记录 (级别, 事件字段渲染)。
    struct CollectLayer(Arc<Mutex<Vec<(String, String)>>>);

    impl<S> tracing_subscriber::layer::Layer<S> for CollectLayer
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let level = event.metadata().level().to_string();
            let mut rendered = String::new();
            event.record(
                &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                    rendered.push_str(&format!("{}={:?} ", field.name(), value));
                },
            );
            self.0.lock().push((level, rendered));
        }
    }

    /// 初始化线程局部捕获订阅者并重建 callsite interest 缓存。
    fn init_capture(logs: &Arc<Mutex<Vec<(String, String)>>>) -> tracing::subscriber::DefaultGuard {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let guard = tracing_subscriber::registry()
            .with(CollectLayer(logs.clone()))
            .set_default();
        tracing::callsite::rebuild_interest_cache();
        guard
    }

    /// commit 失败路径显性化：以 session 层预提交消费事务驱动 dbnexus 真实 commit 错误——
    /// guard.commit() 返回 Err、缓冲不派发、产生 commit-failed 丢弃 warn（含事件类型摘要）。
    ///
    /// `Arc::try_unwrap` 并发冲突变体无法经公共 API 稳定构造（`commit(mut self)` 的 move 语义
    /// 禁止同一 guard 并发查询与提交，正是类型层设计目标），故不覆盖。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn commit_failure_discards_events_with_warn() {
        let pool = setup_pool().await;
        let recorder = Arc::new(RecordingListener::new());
        let lm = manager_with(recorder.clone());

        let mut warn_captured = false;
        for _ in 0..3 {
            let logs: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
            let _capture = init_capture(&logs);

            let mut guard = GarrisonEventTx::begin(&pool, lm.clone())
                .await
                .expect("begin 应成功");
            guard.on_commit(login_event("4001"));
            guard
                .session
                .as_ref()
                .expect("session 应存在")
                .commit()
                .await
                .expect("session 层预提交应成功");

            let result = guard.commit().await;
            assert!(
                matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("event-tx-commit")),
                "session 层事务已被消费，guard.commit() 应返回 Dao 错误，实际: {result:?}"
            );

            let lines = logs.lock().clone();
            if lines.iter().any(|(level, msg)| {
                level == "WARN"
                    && msg.contains("garrison-event-tx-discarded-after-commit-failure")
                    && msg.contains("Login=1")
            }) {
                warn_captured = true;
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            warn_captured,
            "commit 失败路径应产生 commit-failed 丢弃 warn（含事件类型摘要）"
        );
        assert!(
            recorder.snapshot().is_empty(),
            "commit 失败后缓冲事件不应派发"
        );
    }

    /// 未 commit 即 drop 的 uncommitted 丢弃 warn（捕获层）：携带条数与事件类型摘要。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn drop_without_commit_warns_with_event_summary() {
        let pool = setup_pool().await;
        let recorder = Arc::new(RecordingListener::new());
        let lm = manager_with(recorder.clone());

        let mut warn_captured = false;
        for _ in 0..3 {
            let logs: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
            let _capture = init_capture(&logs);

            let mut guard = GarrisonEventTx::begin(&pool, lm.clone())
                .await
                .expect("begin 应成功");
            guard.on_commit(login_event("5001"));
            drop(guard);

            let lines = logs.lock().clone();
            if lines.iter().any(|(level, msg)| {
                level == "WARN"
                    && msg.contains("garrison-event-tx-dropped-without-commit")
                    && msg.contains("Login=1")
            }) {
                warn_captured = true;
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            warn_captured,
            "未 commit 即 drop 应产生 uncommitted 丢弃 warn（含事件类型摘要）"
        );
        assert!(
            recorder.snapshot().is_empty(),
            "未提交即 drop，缓冲事件不应派发"
        );
    }

    /// commit 成功后派发中途被取消：超时取消 commit future（取消点落在派发 await、游标停在 0），
    /// 产生 dispatch-cancelled 丢弃 warn（已派发/总数 + 剩余事件摘要）。
    ///
    /// 取消点确定性：阻塞 listener 先发 entered 信号再挂起，取消时游标必然未推进；
    /// 若取消点落在 `session.commit()` await（判定 committed 之前），entered 与 warn 断言会失败而非误报。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn cancel_mid_dispatch_warns_with_dispatched_count() {
        let pool = setup_pool().await;

        let mut warn_captured = false;
        for _ in 0..3 {
            let logs: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
            let _capture = init_capture(&logs);

            let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel();
            let lm = manager_with(Arc::new(BlockingListener {
                entered: Mutex::new(Some(entered_tx)),
            }));

            let mut guard = GarrisonEventTx::begin(&pool, lm)
                .await
                .expect("begin 应成功");
            guard.on_commit(login_event("6001"));

            let result =
                tokio::time::timeout(std::time::Duration::from_secs(5), guard.commit()).await;
            assert!(
                result.is_err(),
                "listener 永久挂起，commit 应被超时取消而非完成: {result:?}"
            );
            assert!(
                matches!(entered_rx.try_recv(), Ok(())),
                "取消应发生在 listener 进入 on_event（派发 await 点）之后"
            );

            let lines = logs.lock().clone();
            if lines.iter().any(|(level, msg)| {
                level == "WARN"
                    && msg.contains("garrison-event-tx-dispatch-cancelled-after-commit")
                    && msg.contains("0 of 1")
                    && msg.contains("Login=1")
            }) {
                warn_captured = true;
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            warn_captured,
            "派发中途被取消应产生 dispatch-cancelled 丢弃 warn（含已派发/总数与摘要）"
        );
    }
}
