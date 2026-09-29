// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OIDC Back-Channel Logout 持久化投递。
//!
//! OP 侧登出时向依赖方（RP）推送 logout token 的完整链路：
//!
//! 1. **签发**（[`token`]）：复用 `protocol::jwt` 密钥材料签发仅含会话标识
//!    （`sub` / 可选 `sid`）与 `events` 声明的 logout token，不携带身份资料。
//! 2. **入队**（[`listener`]）：`GarrisonEvent::Logout` 触发，逐 RP 写入
//!    `oauth2_backchannel_queue` 持久化队列。两档派发语义：
//!    - OnCommit 档：事务内登出经 `GarrisonEventTx::on_commit` 缓冲 Logout
//!      事件，commit 成功后派发入队，回滚/丢弃 guard 不入队（与业务写同生共死）；
//!    - Immediately 档：session 登出路径为 auto-commit 会话写、无事务上下文，
//!      登出完成后直接广播（入队时点会话写已持久）。
//! 3. **投递**（[`deliver`]）：后台任务从队列 drain，向 RP 的 back-channel
//!    端点 POST `logout_token`；单 RP 超时 5s 封顶、禁止跟随重定向（302 按
//!    未投递处理，防 POST 降 GET 丢 token）；失败重试计数递增并按指数退避
//!    推后下次投递时刻（退避未到期不进批，失败行不阻塞健康行），超 MaxTtl
//!    （默认 24h）置 `failed` 并 warn 显性化（不静默丢）。
//!
//! RP 的 back-channel 端点由部署方按 client 配置（本模块不做 OIDC discovery
//! fetch，也不做推送订阅管理面）；队列行只存 `client_id`，投递时按配置解析
//! 端点。

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
