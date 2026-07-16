//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SignHandler 实现：构造、签名生成、签名校验、HKDF 派生与 Drop 零化。
//!
//! 类型定义见 [`SignHandler`](crate::protocol::sign::SignHandler)。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{HmacSha256, SignHandler, DEFAULT_TIMESTAMP_WINDOW, HKDF_INFO, MIN_APP_SECRET_LEN};

impl SignHandler {
    /// 创建新的签名处理器。
    ///
    /// # 参数
    /// - `app_key`: 应用标识，不可为空。
    /// - `app_secret`: HMAC 密钥（最小 32 字节）。
    /// - `dao`: DAO 抽象层实例。
    ///
    /// # 错误
    /// - `BulwarkError::Config`: app_key 为空或 app_secret 短于 32 字节。
    pub fn new(
        app_key: impl Into<String>,
        app_secret: impl Into<String>,
        dao: Arc<dyn BulwarkDao>,
    ) -> BulwarkResult<Self> {
        let app_key = app_key.into();
        let app_secret = app_secret.into();
        if app_key.is_empty() {
            return Err(BulwarkError::Config("app_key 不可为空".to_string()));
        }
        // 强制 app_secret 最小 32 字节（256 位）
        if app_secret.len() < MIN_APP_SECRET_LEN {
            return Err(BulwarkError::Config(format!(
                "app_secret 长度不足：当前 {} 字节，要求至少 {} 字节（256 位）",
                app_secret.len(),
                MIN_APP_SECRET_LEN
            )));
        }
        // 性能优化：构造时一次性派生 HKDF 密钥，避免 sign/validate 热路径重复计算
        let hkdf = Hkdf::<Sha256>::new(Some(app_key.as_bytes()), app_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        // expand 在 IKM 长度合法时不会失败（32 字节远小于 SHA256 最大输出 255*32）
        hkdf.expand(HKDF_INFO, &mut derived_key)
            .expect("HKDF expand 32 字节不会失败");
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

    /// 用 HKDF-SHA256 从 (app_secret, app_key) 派生 HMAC 密钥。
    ///
    /// HKDF 提供域分隔，防止同一密钥在不同用途间复用导致跨协议攻击。
    /// - IKM = app_secret
    /// - salt = app_key（域分隔）
    /// - info = "bulwark-sign-v2"（版本化上下文）
    /// - 输出 = 32 字节（HMAC-SHA256 密钥长度）
    ///
    /// 性能优化：派生密钥在构造时一次性计算并缓存到 `self.derived_key`，
    /// 此方法仅供测试验证派生结果使用。
    #[cfg(test)]
    #[allow(dead_code)]
    fn derive_hmac_key(&self) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(self.app_key.as_bytes()), self.app_secret.as_bytes());
        let mut okm = [0u8; 32];
        // expand 在 IKM 长度合法时不会失败（32 字节远小于 SHA256 最大输出 255*32）
        hkdf.expand(HKDF_INFO, &mut okm)
            .expect("HKDF expand 32 字节不会失败");
        okm
    }

    /// 生成签名。
    ///
    /// 签名算法：
    /// `base64(hmac_sha256(hkdf_key, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"))`
    ///
    /// 其中 `hkdf_key = HKDF-SHA256(app_secret, salt=app_key, info="bulwark-sign-v2")`。
    ///
    /// 性能优化：使用构造时缓存的 `derived_key`，避免每次签名重复 HKDF 计算。
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

    /// 校验签名。
    ///
    /// 校验逻辑：(1) 检查时间戳窗口；(2) 检查 nonce 未被使用过；
    /// (3) 重新计算签名并常量时间比较；(4) 校验成功后存储 nonce。
    ///
    /// # 参数
    /// - `method`: HTTP 方法。
    /// - `path`: 请求路径。
    /// - `timestamp`: 请求时间戳（秒）。
    /// - `nonce`: 随机串。
    /// - `body_sha256`: 请求体 SHA-256。
    /// - `signature`: 待校验的签名。
    ///
    /// # 返回
    /// - `Ok(())`: 校验通过。
    /// - `Err(BulwarkError::ExpiredToken)`: 时间戳超出窗口。
    /// - `Err(BulwarkError::InvalidToken)`: nonce 重放或签名不匹配。
    pub async fn validate(
        &self,
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        body_sha256: &str,
        signature: &str,
    ) -> BulwarkResult<()> {
        // (1) 时间戳窗口校验
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| BulwarkError::Internal(format!("获取系统时间失败: {}", e)))?;
        if (now - timestamp).abs() > self.timestamp_window {
            return Err(BulwarkError::ExpiredToken("签名时间戳超出窗口".to_string()));
        }

        // (2) nonce 防重放检查
        let nonce_key = format!("bulwark:sign:nonce:{}", nonce);
        if self.dao.get(&nonce_key).await?.is_some() {
            return Err(BulwarkError::InvalidToken("nonce 重放".to_string()));
        }

        // (3) 重新计算签名并常量时间比较（使用 HKDF 派生密钥）
        // 性能优化：使用构造时缓存的 derived_key，避免每次校验重复 HKDF 计算
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, timestamp, nonce, body_sha256
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.derived_key).expect("HMAC accepts 32-byte key");
        mac.update(payload.as_bytes());
        // 将传入的 signature（Base64）解码为字节
        let signature_bytes = STANDARD
            .decode(signature)
            .map_err(|e| BulwarkError::InvalidToken(format!("签名 Base64 解码失败: {}", e)))?;
        // 使用 verify_slice 进行常量时间比较
        match mac.verify_slice(&signature_bytes) {
            Ok(_) => {},
            Err(_) => {
                return Err(BulwarkError::InvalidToken("签名不匹配".to_string()));
            },
        }

        // (4) 校验成功，存储 nonce（TTL = timestamp_window）
        self.dao
            .set(&nonce_key, "1", self.timestamp_window as u64)
            .await?;
        Ok(())
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for SignHandler {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.app_secret.zeroize();
        self.derived_key.zeroize();
    }
}
