// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 找回密码/可恢复流程（吸收 authgear forgot-password 防枚举语义）。
//!
//! # 流程（六个阶段）
//!
//! ①用户提交标识 → ②签发 ActionToken（自包含 JWT：sub + purpose=password_reset +
//! jti + exp，复用 `protocol::jwt`）→ ③DAO `set_if_absent` 一次性消费登记 →
//! ④验证通过后先授权凭据操作（restricted 会话标记）再消费 token，消费失败
//! 则凭据操作回滚（两段式防竞态）→ ⑤新密码写入 + `app_password_history` 追加 →
//! ⑥邮件通道复用 `secure::email` 发送设施与脱敏惯例。
//!
//! # 安全不变式
//!
//! - **防枚举**：未知标识走同路径 dummy token + 相同限流计数与相同响应外形，
//!   消除「存在性预言机」（对齐 authgear forgotpassword 的 service.go:121-128）。
//! - **防跨用户改密**：code-subject 绑定（flow 跨请求会话状态）在签发时落 DAO，
//!   消费时校验 token.sub 与绑定 subject 一致，主体改写一律拒绝。
//! - **防重放**：jti 经 `GarrisonDao::set_if_absent` 原子消费，二次消费与并发
//!   消费恰一成功。
//! - **最小授权**：恢复会话打 restricted 标记，仅可访问改密端点，其余端点
//!   一律 [`GarrisonError::NotPermission`]（HTTP 403）；标记在 reset 返回后
//!   保留（fail-safe），宿主显式清除。
//!
//! # Key 空间
//!
//! | key | TTL | 用途 |
//! |-----|-----|------|
//! | `pwdreset:bind:{jti}` | ActionToken 剩余寿命 | code-subject 绑定（flow 会话状态） |
//! | `pwdreset:bindt:{jti}` | ActionToken 剩余寿命 | code-tenant 绑定（subject∈tenant 校验，缺绑定的旧 token fail-closed 拒绝） |
//! | `pwdreset:jti:{jti}` | ActionToken 剩余寿命 | 一次性消费登记（set_if_absent 原子语义） |
//! | `pwdreset:rate:{identifier}` | 请求窗口 | 防枚举限流计数（与登录限流键隔离、口径一致） |
//!
//! # Feature 门禁
//!
//! `account-password-reset` = `protocol-jwt` + `account-credential` +
//! `account-policy` + `email-verification`（均为 crate 内既有 feature，无新外部依赖）。

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
