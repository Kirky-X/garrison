// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 找回密码/可恢复流程（吸收 authgear forgot-password 防枚举语义）。
//!
//! # 流程
//!
//! 提交标识 → 签发自包含 ActionToken（sub + purpose=password_reset + jti + exp，复用 `protocol::jwt`）→
//! DAO `set_if_absent` 一次性消费登记 → 验证后先授权 restricted 凭据操作再消费 token，消费失败回滚
//! （两段式防竞态）→ 新密码写入 + `app_password_history` 追加 → 经 `secure::email` 发送。
//!
//! # 安全不变式
//!
//! - 防枚举：未知标识走同路径 dummy token + 相同限流计数与响应外形（对齐 authgear service.go:121-128）。
//! - 防跨用户改密：消费时校验 token.sub 与签发时落 DAO 的绑定 subject 一致，改写一律拒绝。
//! - 防重放：jti 经 `GarrisonDao::set_if_absent` 原子消费，二次消费与并发消费恰一成功。
//! - 最小授权：restricted 会话仅可达改密端点，其余一律 [`GarrisonError::NotPermission`](crate::error::GarrisonError::NotPermission)
//!   （HTTP 403）；标记在 reset 返回后保留（fail-safe），宿主显式清除。
//!
//! # Key 空间
//!
//! `pwdreset:bind:{jti}` code-subject 绑定、`pwdreset:bindt:{jti}` code-tenant 绑定（缺绑定的旧 token
//! fail-closed 拒绝）、`pwdreset:jti:{jti}` 一次性消费登记、`pwdreset:rate:{identifier}` 防枚举限流
//! （与登录限流键隔离）；TTL 均为 ActionToken 剩余寿命（rate 为请求窗口）。
//!
//! # Feature 门禁
//!
//! `account-password-reset` = `protocol-jwt` + `account-credential` + `account-policy` + `email-verification`。

pub mod action_token;
pub mod consumer;
pub mod restricted;
pub mod service;

#[cfg(test)]
mod tests;

pub use action_token::{
    ActionTokenClaims, ActionTokenService, IssuedActionToken, DEFAULT_TOKEN_TTL_SECS,
    PURPOSE_PASSWORD_RESET,
};
pub use consumer::ActionTokenConsumer;
pub use restricted::{RestrictedSessionGuard, ENDPOINT_PASSWORD_CHANGE, RESTRICTED_ATTR_KEY};
pub use service::{
    EmailResetMailSender, PasswordResetService, ResetIdentityResolver, ResetMailSender,
    ResetRequestOutcome, DEFAULT_RATE_LIMIT_MAX, DEFAULT_RATE_WINDOW_SECS, DUMMY_RESET_SUBJECT,
    HISTORY_CHECK_COUNT,
};
