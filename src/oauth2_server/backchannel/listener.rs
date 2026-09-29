// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Logout 事件 → logout token 入队 listener。
//!
//! 消费 `GarrisonEvent::Logout`，对每个配置的 RP 签发 logout token 并写入
//! `oauth2_backchannel_queue`。两档派发均可达（两档共用同一监听器集合）：
//!
//! - **OnCommit 档**：事务内登出经 `GarrisonEventTx::on_commit` 缓冲 Logout
//!   事件，commit 成功后派发到本 listener——回滚 / 丢弃 guard 则不入队，
//!   队列行与业务写同生共死。
//! - **Immediately 档**：session 登出路径为 auto-commit 会话写、无事务上下文，
//!   登出完成后直接广播（入队时点会话写已持久），见
//!   `stp::session` 登出实现处的档位说明注释。

use super::queue::BackChannelQueue;
use super::token::LogoutTokenIssuer;
use crate::error::GarrisonResult;
use crate::listener::{GarrisonEvent, GarrisonListener};
use async_trait::async_trait;
use dbnexus::DbPool;
use std::sync::Arc;

/// 接收 back-channel logout 推送的 RP 配置。
#[derive(Debug, Clone)]
pub struct BackChannelRecipient {
    /// RP 的 client_id（写入 logout token `aud` 与队列行）。
    pub client_id: String,
    /// RP 的 back-channel logout 端点（部署方配置，非 discovery fetch）。
    pub logout_uri: String,
}

/// 入队 listener：Logout 事件 → 逐 RP 签发 + 入队。
pub struct BackChannelLogoutListener {
    queue: Arc<BackChannelQueue>,
    issuer: Arc<LogoutTokenIssuer>,
    recipients: Vec<BackChannelRecipient>,
}

impl BackChannelLogoutListener {
    /// 构造入队 listener。
    ///
    /// `max_ttl_secs` 为入队行投递窗口（生产默认 24h）。非 Logout 事件直接
    /// 忽略（触发仅挂 session 登出路径，Kickout 等事件不投递）。
    pub fn new(
        pool: DbPool,
        issuer: Arc<LogoutTokenIssuer>,
        recipients: Vec<BackChannelRecipient>,
        max_ttl_secs: i64,
    ) -> Self {
        Self {
            queue: Arc::new(BackChannelQueue::new(pool, max_ttl_secs)),
            issuer,
            recipients,
        }
    }

    /// 队列存取器引用（供装配方构造投递器时复用同一队列配置）。
    pub fn queue(&self) -> Arc<BackChannelQueue> {
        Arc::clone(&self.queue)
    }
}

#[async_trait]
impl GarrisonListener for BackChannelLogoutListener {
    async fn on_event(&self, event: &GarrisonEvent) -> GarrisonResult<()> {
        // 事件载荷 token 为掩码形式（CWE-532 契约），登出主体取 login_id 写入
        // logout token 的 sub；掩码 token 不参与任何投递数据。
        let GarrisonEvent::Logout { login_id, .. } = event else {
            return Ok(());
        };
        for recipient in &self.recipients {
            let jwt = self
                .issuer
                .issue(&recipient.client_id, Some(login_id), None)?;
            self.queue.enqueue(&recipient.client_id, &jwt).await?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "db-sqlite", feature = "listener"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;
    use crate::listener::GarrisonListenerManager;
    use crate::oauth2_server::backchannel::queue::STATUS_PENDING;
    use crate::protocol::jwt::JwtHandler;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn recipient(client_id: &str) -> BackChannelRecipient {
        BackChannelRecipient {
            client_id: client_id.to_string(),
            logout_uri: "https://rp.example.com/backchannel".to_string(),
        }
    }

    async fn wired_listener(
        pool: dbnexus::DbPool,
        recipients: Vec<BackChannelRecipient>,
    ) -> BackChannelLogoutListener {
        let issuer = Arc::new(LogoutTokenIssuer::new(
            Arc::new(JwtHandler::new(SECRET)),
            "https://op.example.com",
        ));
        BackChannelLogoutListener::new(pool, issuer, recipients, 3600)
    }

    fn logout_event(login_id: &str) -> GarrisonEvent {
        GarrisonEvent::Logout {
            login_id: login_id.to_string(),
            token: "abcd1234***（掩码）".to_string(),
            request_context: None,
        }
    }

    /// OnCommit 档：Logout 事件经 GarrisonEventTx 缓冲，commit 后派发入队。
    #[tokio::test]
    async fn logout_via_on_commit_enqueues_after_commit() {
        let pool = setup_db().await;
        let listener = wired_listener(pool.clone(), vec![recipient("client-a")]).await;
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(Arc::new(listener));

        let mut tx = crate::dao::GarrisonEventTx::begin(&pool, Arc::clone(&lm))
            .await
            .expect("事务应开启");
        tx.on_commit(logout_event("alice"));
        tx.commit().await.expect("提交应成功");

        // 提交后派发入队（测试构建下 manager 混有 inventory ErrListener 桩，
        // DispatchOutcome 计数被污染，验收语义以队列状态为准）
        let queue = BackChannelQueue::new(pool, 3600);
        assert_eq!(
            queue.count_by_status(STATUS_PENDING).await.unwrap(),
            1,
            "事务提交后队列必须出现待投递行"
        );
        let batch = queue.pending_batch(10).await.unwrap();
        assert_eq!(batch[0].client_id, "client-a");
        // 队列里的 logout token 应为可解码 JWT（签发即入队）
        assert_eq!(
            batch[0].logout_token.split('.').count(),
            3,
            "入队载荷应为三段 JWT"
        );
    }

    /// OnCommit 档回滚：缓冲事件随 guard 丢弃，队列不残留行。
    #[tokio::test]
    async fn rollback_discards_buffered_logout_enqueue() {
        let pool = setup_db().await;
        let listener = wired_listener(pool.clone(), vec![recipient("client-a")]).await;
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(Arc::new(listener));

        let mut tx = crate::dao::GarrisonEventTx::begin(&pool, Arc::clone(&lm))
            .await
            .expect("事务应开启");
        tx.on_commit(logout_event("alice"));
        tx.rollback().await.expect("回滚应成功");

        let queue = BackChannelQueue::new(pool, 3600);
        assert_eq!(
            queue.count_by_status(STATUS_PENDING).await.unwrap(),
            0,
            "回滚后队列不得出现行"
        );
    }

    /// Immediately 档：无事务上下文的登出广播同样触发入队。
    #[tokio::test]
    async fn immediately_broadcast_logout_enqueues() {
        let pool = setup_db().await;
        let listener = wired_listener(pool.clone(), vec![recipient("client-a")]).await;
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(Arc::new(listener));

        lm.broadcast(&logout_event("alice")).await;

        let queue = BackChannelQueue::new(pool, 3600);
        assert_eq!(queue.count_by_status(STATUS_PENDING).await.unwrap(), 1);
    }

    /// 非 Logout 事件不入队（触发仅挂 session 登出路径）。
    #[tokio::test]
    async fn non_logout_events_are_ignored() {
        let pool = setup_db().await;
        let listener = wired_listener(pool.clone(), vec![recipient("client-a")]).await;
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(Arc::new(listener));

        lm.broadcast(&GarrisonEvent::Login {
            login_id: "alice".to_string(),
            token: "abcd1234***".to_string(),
            device: None,
            request_context: None,
        })
        .await;

        let queue = BackChannelQueue::new(pool, 3600);
        assert_eq!(queue.count_by_status(STATUS_PENDING).await.unwrap(), 0);
    }

    /// 多 RP 配置：一次登出逐 RP 各入队一行（aud 各自绑定）。
    #[tokio::test]
    async fn each_recipient_gets_its_own_row() {
        let pool = setup_db().await;
        let listener = wired_listener(
            pool.clone(),
            vec![recipient("client-a"), recipient("client-b")],
        )
        .await;
        let lm = Arc::new(GarrisonListenerManager::new());
        lm.register(Arc::new(listener));

        lm.broadcast(&logout_event("alice")).await;

        let queue = BackChannelQueue::new(pool, 3600);
        assert_eq!(queue.count_by_status(STATUS_PENDING).await.unwrap(), 2);
        let batch = queue.pending_batch(10).await.unwrap();
        let mut clients: Vec<&str> = batch.iter().map(|r| r.client_id.as_str()).collect();
        clients.sort_unstable();
        assert_eq!(clients, vec!["client-a", "client-b"]);
    }
}
