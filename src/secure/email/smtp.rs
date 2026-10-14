// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

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
    ///
    /// # ⚠️ 危险配置（务必阅读）
    ///
    /// `false` 时用 `builder_dangerous` 构建明文 SMTP 传输：凭据（`username`/`password`）与邮件正文全部明文上网，
    /// 链路窃听者可截获；构造时仅 `tracing::warn!` 告警、不拒绝（保留内网无 TLS relay / 本地 mailhog 兼容）。
    /// 生产必须保持 `true`（STARTTLS）；仅内网可信 relay、本地测试容器可关闭，且需确保告警被监控采集。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造指向回环高位端口的配置（无 SMTP 服务，连接必失败：只验证失败路径映射）。
    fn config_without_tls() -> SmtpConfig {
        SmtpConfig {
            host: "127.0.0.1".to_string(),
            port: 1,
            username: "noreply@example.com".to_string(),
            password: "secret".to_string(),
            from_name: "Garrison".to_string(),
            from_addr: String::new(),
            use_tls: false,
        }
    }

    /// Debug 输出必须脱敏 SMTP 密码（CWE-532）。
    #[test]
    fn debug_redacts_password() {
        let config = SmtpConfig {
            password: "smtp-secret".to_string(),
            ..config_without_tls()
        };
        let debug = format!("{config:?}");
        assert!(
            debug.contains("<redacted>"),
            "应输出 <redacted>，实际: {debug}"
        );
        assert!(
            !debug.contains("smtp-secret"),
            "不得泄露密码明文，实际: {debug}"
        );
    }

    /// `from_addr` 为空回退到 `username`；显式设置时按原值使用；无 TLS 配置仍可构造（仅告警）。
    #[test]
    fn from_config_resolves_from_addr_and_accepts_plaintext_transport() {
        let fallback = SmtpEmailSender::from_config(&config_without_tls())
            .expect("无 TLS 配置应可构造（仅告警不拒绝）");
        assert_eq!(
            fallback.from_addr, "noreply@example.com",
            "空 from_addr 应回退 username"
        );
        assert_eq!(fallback.from_name, "Garrison");

        let explicit = SmtpEmailSender::from_config(&SmtpConfig {
            from_addr: "support@example.com".to_string(),
            ..config_without_tls()
        })
        .expect("显式 from_addr 应可构造");
        assert_eq!(explicit.from_addr, "support@example.com");

        let starttls = SmtpEmailSender::from_config(&SmtpConfig {
            use_tls: true,
            ..config_without_tls()
        })
        .expect("STARTTLS 配置应可构造");
        assert_eq!(starttls.from_addr, "noreply@example.com");
    }

    /// 发件人/收件人地址非法：构造消息前显性报错（不发起连接）。
    #[tokio::test]
    async fn send_rejects_invalid_addresses_before_connecting() {
        let sender = SmtpEmailSender::from_config(&config_without_tls()).expect("构造应成功");

        let bad_recipient = sender
            .send("not-an-email", "subject", "body")
            .await
            .expect_err("非法收件人必须显性拒绝");
        assert!(
            matches!(&bad_recipient, GarrisonError::Internal(m) if m.contains("email-to-parse-failed")),
            "错误应指明 email-to-parse-failed，实际: {bad_recipient:?}"
        );

        let bad_sender = SmtpEmailSender::from_config(&SmtpConfig {
            from_addr: "not-an-email".to_string(),
            ..config_without_tls()
        })
        .expect("构造应成功");
        let err = bad_sender
            .send("to@example.com", "subject", "body")
            .await
            .expect_err("非法发件人必须显性拒绝");
        assert!(
            matches!(&err, GarrisonError::Internal(m) if m.contains("email-from-parse-failed")),
            "错误应指明 email-from-parse-failed，实际: {err:?}"
        );
    }

    /// 传输层失败映射为 `Network`（回环无 SMTP 服务 → 连接失败）。
    #[tokio::test]
    async fn send_maps_transport_failure_to_network_error() {
        let sender = SmtpEmailSender::from_config(&config_without_tls()).expect("构造应成功");
        let err = sender
            .send("to@example.com", "subject", "body")
            .await
            .expect_err("无 SMTP 服务时发送必须失败");
        assert!(
            matches!(&err, GarrisonError::Network(m) if m.contains("email-smtp-send-failed")),
            "错误应指明 email-smtp-send-failed，实际: {err:?}"
        );
    }
}
