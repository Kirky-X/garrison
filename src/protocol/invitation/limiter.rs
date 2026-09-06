//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邀请码防爆破尝试锁定器。
//!
//! 经 `GarrisonDao::incr` 的窗口 TTL 语义按来源标识（如 IP）计数，
//! 超过阈值后拒绝后续 `validate`/`redeem` 尝试，直至窗口过期或显式 `reset`。
//!
//! 仅在启用 `protocol-invitation` 特性时编译。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::Arc;

/// 尝试计数键前缀。
const ATTEMPT_KEY_PREFIX: &str = "garrison:invitation:attempt:";

/// 防爆破尝试锁定器（默认 10 次 / 600 秒窗口）。
pub struct InvitationAttemptLimiter {
    /// DAO 抽象层，用于尝试计数。
    pub(crate) dao: Arc<dyn GarrisonDao>,
    /// 窗口内允许的最大尝试次数。
    pub(crate) max_attempts: u32,
    /// 计数窗口秒数。
    pub(crate) window_seconds: u64,
}

impl InvitationAttemptLimiter {
    /// 以默认阈值（10 次 / 600 秒窗口）创建。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            dao,
            max_attempts: 10,
            window_seconds: 600,
        }
    }

    /// 自定义阈值与窗口创建。
    pub fn with_config(dao: Arc<dyn GarrisonDao>, max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            dao,
            max_attempts,
            window_seconds,
        }
    }

    /// 记录一次尝试并判断是否超限。
    ///
    /// 经 `dao.incr` 原子计数（窗口 TTL 语义：键不存在时以 `window_seconds` 建键）；
    /// 计数超过 `max_attempts` 时返回锁定错误。每次调用都计数——无论调用方后续成败。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: 超过阈值（`invitation-too-many-attempts::<source>` 前缀）。
    pub async fn check(&self, source: &str) -> GarrisonResult<()> {
        let key = format!("{}{}", ATTEMPT_KEY_PREFIX, source_digest_hex(source));
        let count = self.dao.incr(&key, self.window_seconds).await?;
        if count > self.max_attempts as u64 {
            return Err(GarrisonError::InvalidParam(format!(
                "invitation-too-many-attempts::{}",
                source
            )));
        }
        Ok(())
    }

    /// 清除来源的尝试计数（redeem 成功后调用；对无计数来源幂等）。
    pub async fn reset(&self, source: &str) -> GarrisonResult<()> {
        let key = format!("{}{}", ATTEMPT_KEY_PREFIX, source_digest_hex(source));
        self.dao.delete(&key).await
    }
}

/// source 的 SHA-256 十六进制摘要（防超长/特殊字符进入存储键）。
///
/// 取 SHA-256 而非 MD5：source 为攻击者可控输入（如 IP），MD5 存在实用
/// chosen-prefix 碰撞攻击，可被用于污染他人计数键。
fn source_digest_hex(source: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}
