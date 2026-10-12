// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SignHandler 实现：构造、签名生成、签名校验、HKDF 派生与 Drop 零化。
//!
//! 类型定义见 [`SignHandler`](crate::protocol::sign::SignHandler)。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{HmacSha256, SignHandler, DEFAULT_TIMESTAMP_WINDOW, HKDF_INFO, MIN_APP_SECRET_LEN};

impl SignHandler {
    /// 创建签名处理器：`app_key` 不可为空、`app_secret` 至少 32 字节；
    /// 违者返回 `Config` 错误。
    pub fn new(
        app_key: impl Into<String>,
        app_secret: impl Into<String>,
        dao: Arc<dyn GarrisonDao>,
    ) -> GarrisonResult<Self> {
        let app_key = app_key.into();
        let app_secret = app_secret.into();
        if app_key.is_empty() {
            return Err(GarrisonError::Config("sign-app-key-empty::".to_string()));
        }
        // 强制 app_secret 最小 32 字节（256 位）
        if app_secret.len() < MIN_APP_SECRET_LEN {
            return Err(GarrisonError::Config(format!(
                "sign-app-secret-too-short::{}::{}",
                app_secret.len(),
                MIN_APP_SECRET_LEN
            )));
        }
        // 性能优化：构造时一次性派生 HKDF 密钥，避免 sign/validate 热路径重复计算
        let hkdf = Hkdf::<Sha256>::new(Some(app_key.as_bytes()), app_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        // expand 在 IKM 长度合法时不会失败（32 字节远小于 SHA256 最大输出 255*32）
        hkdf.expand(HKDF_INFO, &mut derived_key)
            .expect("HKDF expand 32 bytes must not fail");
        Ok(Self {
            app_key,
            app_secret,
            dao,
            timestamp_window: DEFAULT_TIMESTAMP_WINDOW,
            derived_key,
        })
    }

    /// 设置时间戳窗口（秒），默认 300 秒。
    pub fn with_timestamp_window(mut self, seconds: i64) -> Self {
        self.timestamp_window = seconds;
        self
    }

    /// 获取 app_key。
    pub fn app_key(&self) -> &str {
        &self.app_key
    }

    /// 获取时间戳窗口。
    pub fn timestamp_window(&self) -> i64 {
        self.timestamp_window
    }

    /// 用 HKDF-SHA256 从 (app_secret, app_key) 派生 HMAC 密钥：salt=app_key 提供
    /// 域分隔（防同一密钥跨用途复用），info 版本化。构造时已一次性派生并缓存，
    /// 此方法仅供测试验证派生结果。
    #[cfg(test)]
    #[allow(dead_code, reason = "test helper: 仅供测试验证派生密钥结果")]
    fn derive_hmac_key(&self) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(self.app_key.as_bytes()), self.app_secret.as_bytes());
        let mut okm = [0u8; 32];
        // expand 在 IKM 长度合法时不会失败（32 字节远小于 SHA256 最大输出 255*32）
        hkdf.expand(HKDF_INFO, &mut okm)
            .expect("HKDF expand 32 bytes must not fail");
        okm
    }

    /// 生成签名：`base64(hmac_sha256(hkdf_key, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"))`，
    /// 使用构造时缓存的 `derived_key`（`hkdf_key` 定义见模块头）。
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        body_sha256: &str,
    ) -> String {
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, timestamp, nonce, body_sha256
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.derived_key).expect("HMAC accepts 32-byte key");
        mac.update(payload.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }

    /// 校验签名：时间戳窗口检查 → nonce 原子防重放（`incr`，TTL = 窗口）→
    /// 重算签名并常量时间比较。时间戳越窗返回 `ExpiredToken`，nonce 重放或
    /// 签名不匹配返回 `InvalidToken`。
    pub async fn validate(
        &self,
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        body_sha256: &str,
        signature: &str,
    ) -> GarrisonResult<()> {
        // 时间戳窗口校验
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| GarrisonError::Internal(format!("sign-clock::{}", e)))?;
        // 溢出防护：timestamp 为外部可控 i64，`now - timestamp` 用 checked_sub 显式
        // 处理——溢出意味着 |now - timestamp| 必然远超任何合理窗口，直接按窗口外拒绝
        // （不泄露额外信息）；checked_sub 成功后 diff 不可能为 i64::MIN，abs() 无二次溢出。
        let diff = now
            .checked_sub(timestamp)
            .ok_or_else(|| GarrisonError::ExpiredToken("sign-timestamp-window".to_string()))?;
        if diff.abs() > self.timestamp_window {
            return Err(GarrisonError::ExpiredToken(
                "sign-timestamp-window".to_string(),
            ));
        }

        // nonce 防重放：原子自增（消除 get/set TOCTOU 竞态）；key 带 `app_key`
        // 前缀隔离多应用（不同 app_key 的相同 nonce 互不冲突）；`incr` 返回值
        // > 1 即 nonce 已被使用过（重放），直接拒绝。
        let nonce_key = format!("garrison:sign:nonce:{}:{}", self.app_key, nonce);
        let count = self
            .dao
            .incr(&nonce_key, self.timestamp_window as u64)
            .await?;
        if count > 1 {
            return Err(GarrisonError::InvalidToken("sign-nonce-replay".to_string()));
        }

        // 重算签名并常量时间比较（复用构造时缓存的 derived_key）
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, timestamp, nonce, body_sha256
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.derived_key).expect("HMAC accepts 32-byte key");
        mac.update(payload.as_bytes());
        let signature_bytes = STANDARD
            .decode(signature)
            .map_err(|e| GarrisonError::InvalidToken(format!("sign-base64-decode::{}", e)))?;
        match mac.verify_slice(&signature_bytes) {
            Ok(_) => {},
            Err(_) => {
                return Err(GarrisonError::InvalidToken("sign-mismatch".to_string()));
            },
        }

        // nonce 已由 incr 原子写入（TTL = timestamp_window），无需再 set
        Ok(())
    }
}

// Drop 零化仅在 `protocol-zeroize` feature 下编译（零开销默认构建）：启用后
// `app_secret` 与 `derived_key` 在 handler 析构时被覆写，未启用时不保证清除
// （可能残留于已释放堆块 / swap / core dump）；字段级安全说明见 `sign/mod.rs`。
#[cfg(feature = "protocol-zeroize")]
impl Drop for SignHandler {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.app_secret.zeroize();
        self.derived_key.zeroize();
    }
}
