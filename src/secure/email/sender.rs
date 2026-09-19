// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! EmailSender trait 定义。
//!
//! 业务方实现此 trait 接入任意邮件发送通道（SMTP / HTTP 网关等）。
//! 框架不内置具体发送实现（`email-verification-smtp` feature 除外）。

// re-export from mod.rs for convenience
pub use super::EmailSender;
