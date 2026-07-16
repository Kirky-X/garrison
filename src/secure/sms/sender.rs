//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SmsSender trait 的实现集合。

#[cfg(test)]
use super::{BulwarkResult, NoopSmsSender, SmsSender};
#[cfg(test)]
use async_trait::async_trait;

/// NoopSmsSender 的 SmsSender 实现（仅日志，用于测试）。
#[cfg(test)]
#[async_trait]
impl SmsSender for NoopSmsSender {
    async fn send(&self, phone: &str, _code: &str) -> BulwarkResult<()> {
        tracing::debug!(phone = phone, "NoopSmsSender 发送验证码（code 已省略）");
        Ok(())
    }
}
