//! OIDC Back-Channel Logout 持久化投递：OP 侧登出向 RP 推送 logout token。
//!
//! 链路 [`token`] 签发（仅 `sub` / 可选 `sid` 与 `events` 声明，不带身份资料）→ [`listener`](crate::oauth2_server::backchannel::listener) 在
//! `GarrisonEvent::Logout` 时逐 RP 入队 `oauth2_backchannel_queue`（OnCommit 档经 `on_commit` 缓冲、
//! commit 后派发，回滚不入队；Immediately 档走 auto-commit 的 session 登出路径，登出后直接广播）→
//! [`deliver`](crate::oauth2_server::backchannel::deliver) 后台 drain 后 POST：单 RP 超时 5s、禁止跟随重定向（302 按未投递处理，防 POST 降 GET
//! 丢 token）、失败按指数退避重试，超 MaxTtl（默认 24h）置 `failed` 并 warn 显性化。
//!
//! RP 端点由部署方按 client 配置解析（队列行只存 `client_id`），不做 OIDC discovery 与订阅管理面。

pub mod token;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub mod deliver;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub mod listener;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub mod queue;

pub use token::{
    LogoutTokenClaims, LogoutTokenIssuer, BACKCHANNEL_LOGOUT_EVENT_URI, LOGOUT_TOKEN_TTL_SECS,
};

#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub use deliver::{BackChannelDeliverer, DelivererConfig, DrainSummary, DEFAULT_MAX_TTL_SECS};

#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub use listener::{BackChannelLogoutListener, BackChannelRecipient};

#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub use queue::{
    BackChannelQueue, QueueEntry, DEFAULT_RETRY_BACKOFF_MILLIS, RETRY_BACKOFF_CAP_MILLIS,
};
