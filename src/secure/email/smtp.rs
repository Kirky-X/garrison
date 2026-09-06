//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SmtpEmailSender 实现：基于 lettre 的内置 SMTP 邮件发送。
//!
//! 仅在 `email-verification-smtp` feature 启用时编译。
//! 业务方也可不启用此 feature，自行实现 `EmailSender` trait 接入 HTTP 邮件网关。

use super::{EmailSender, GarrisonResult};
use crate::error::GarrisonError;
use async_trait::async_trait;

/// SMTP 配置。
#[derive(Clone)]
pub struct SmtpConfig {
    /// SMTP 服务器地址。
    pub host: String,
    /// SMTP 端口（默认 587）。
    pub port: u16,
    /// 认证用户名。
    pub username: String,
    /// 认证密码。
    pub password: String,
    /// 发件人显示名称（默认 "Garrison"）。
    pub from_name: String,
    /// 发件人邮箱地址（默认同 username）。
    pub from_addr: String,
    /// 是否使用 TLS（默认 true）。
    pub use_tls: bool,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("from_name", &self.from_name)
            .field("from_addr", &self.from_addr)
            .field("use_tls", &self.use_tls)
            .finish()
    }
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 587,
            username: String::new(),
            password: String::new(),
            from_name: "Garrison".to_string(),
            from_addr: String::new(),
            use_tls: true,
        }
    }
}

/// 基于 lettre 的 SMTP 邮件发送器。
pub struct SmtpEmailSender {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from_addr: String,
    from_name: String,
}

impl SmtpEmailSender {
    /// 从配置创建 SMTP 发送器实例。
    pub fn from_config(config: &SmtpConfig) -> GarrisonResult<Self> {
        use lettre::transport::smtp::authentication::Credentials;

        let from_addr = if config.from_addr.is_empty() {
            config.username.clone()
        } else {
            config.from_addr.clone()
        };

        let builder = if config.use_tls {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&config.host)
        } else {
            tracing::warn!(
                host = %config.host,
                port = config.port,
                "SMTP configured without TLS (builder_dangerous); credentials may be exposed in plaintext"
            );
            Ok(lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(&config.host))
        }.map_err(|e| GarrisonError::Config(format!("email-smtp-builder-failed::{}", e)))?;

        let transport = builder
            .port(config.port)
            .credentials(Credentials::new(
                config.username.clone(),
                config.password.clone(),
            ))
            .build();

        Ok(Self {
            transport,
            from_addr,
            from_name: config.from_name.clone(),
        })
    }
}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    async fn send(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()> {
        use lettre::{AsyncTransport, Message};

        let from = format!("{} <{}>", self.from_name, self.from_addr);
        let email =
            Message::builder()
                .from(from.parse().map_err(|e| {
                    GarrisonError::Internal(format!("email-from-parse-failed::{}", e))
                })?)
                .to(to.parse().map_err(|e| {
                    GarrisonError::Internal(format!("email-to-parse-failed::{}", e))
                })?)
                .subject(subject)
                .body(body.to_string())
                .map_err(|e| GarrisonError::Internal(format!("email-build-failed::{}", e)))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| GarrisonError::Network(format!("email-smtp-send-failed::{}", e)))?;

        Ok(())
    }
}
