//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 签名协议模块，提供请求签名生成与校验 + nonce 防重放。
//!
//! 对应 微服务网关签名认证，
//! 基于 HMAC-SHA256 + Base64 实现请求签名。
//!
//! 仅在启用 `protocol-sign` 特性时编译。
//!
//! ## 签名算法
//!
//! `sign = base64(hmac_sha256(hkdf_key, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"))`
//!
//! 其中 `hkdf_key = HKDF-SHA256(app_secret, salt=app_key, info="bulwark-sign-v2")`。
//!
//! ## Key 命名空间
//!
//! 所有 sign nonce 存储在 `bulwark:sign:nonce:<nonce>` 命名空间下。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 默认时间戳窗口（秒）。
const DEFAULT_TIMESTAMP_WINDOW: i64 = 300;

/// app_secret 最小长度（32 字节 = 256 位，满足 HMAC-SHA256 安全要求）。
const MIN_APP_SECRET_LEN: usize = 32;

/// HKDF info 上下文字符串（域分隔，防止同一密钥在不同用途间复用）。
const HKDF_INFO: &[u8] = b"bulwark-sign-v2";

/// HMAC-SHA256 类型别名。
type HmacSha256 = Hmac<Sha256>;

/// API 签名处理器。
///
/// 持有 `app_key`、`app_secret` 与 `Arc<dyn BulwarkDao>`（用于 nonce 存储）。
/// 实现 `Send + Sync`，可在多线程环境共享。
///
/// `app_secret` 最小 32 字节，内部用 HKDF-SHA256 派生 HMAC 密钥。
///
/// 性能优化：HKDF 派生密钥在构造时一次性计算并缓存到 `derived_key` 字段，
/// `sign`/`validate` 直接使用缓存密钥，避免每次签名重复 HKDF 计算。
pub struct SignHandler {
    /// 应用标识。
    app_key: String,
    /// 应用密钥（原始，HKDF 输入材料）。
    /// 保留用于 `protocol-zeroize` feature 下的 Drop 零化；非 zeroize 构建中不再被读取。
    #[cfg_attr(not(feature = "protocol-zeroize"), allow(dead_code))]
    app_secret: String,
    /// DAO 抽象层，用于 nonce 存储。
    dao: Arc<dyn BulwarkDao>,
    /// 时间戳窗口（秒）。
    timestamp_window: i64,
    /// HKDF 派生密钥（构造时一次性计算，sign/validate 直接使用）。
    derived_key: [u8; 32],
}

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

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::mock::MockDao;
    use super::*;

    /// 测试用 app_secret（32 字节，满足最小长度要求）。
    const TEST_APP_SECRET: &str = "test-secret-key-with-32-bytes!!!";

    /// 创建 SignHandler（使用 MockDao）。
    fn make_handler() -> SignHandler {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        SignHandler::new("app-001", TEST_APP_SECRET, dao).unwrap()
    }

    /// 获取当前时间戳。
    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // ========================================================================
    // SignHandler 构造测试
    // ========================================================================

    /// 构造 SignHandler，字段正确填充（spec Scenario）。
    #[test]
    fn new_populates_fields() {
        let handler = make_handler();
        assert_eq!(handler.app_key(), "app-001");
        assert_eq!(handler.timestamp_window(), 300);
    }

    /// app_key 为空返回 Config 错误（spec Scenario）。
    #[test]
    fn new_empty_app_key_returns_config_error() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let result = SignHandler::new("", TEST_APP_SECRET, dao);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {},
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// app_secret 短于 32 字节返回 Config 错误。
    #[test]
    fn new_short_app_secret_returns_config_error() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let result = SignHandler::new("app-001", "short-secret", dao);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("32") && msg.contains("字节"),
                    "错误消息应包含最小长度提示: {}",
                    msg
                );
            },
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// app_secret 正好 32 字节通过校验。
    #[test]
    fn new_app_secret_exactly_32_bytes_passes() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // 正好 32 字节
        let secret_32 = "0123456789abcdef0123456789abcdef";
        assert_eq!(secret_32.len(), 32);
        let result = SignHandler::new("app-001", secret_32, dao);
        assert!(result.is_ok());
    }

    /// 自定义时间窗口（spec Scenario）。
    #[test]
    fn with_timestamp_window_sets_window() {
        let handler = make_handler().with_timestamp_window(120);
        assert_eq!(handler.timestamp_window(), 120);
    }

    // ========================================================================
    // sign 测试
    // ========================================================================

    /// 标准签名生成，返回 Base64 字符串（spec Scenario）。
    #[test]
    fn sign_returns_base64_string() {
        let handler = make_handler();
        let sig = handler.sign(
            "POST",
            "/api/v1/users",
            1700000000,
            "nonce-abc",
            "e3b0c44298fc1c149afbf4c8996fb924",
        );
        // Base64 编码的 HMAC-SHA256 应为 44 字符（32 字节 → 44 字符含 padding）
        assert_eq!(sig.len(), 44);
        assert!(sig
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    /// 不同 body_sha256 产生不同签名（spec Scenario）。
    #[test]
    fn sign_different_body_sha256_produces_different_signatures() {
        let handler = make_handler();
        let s1 = handler.sign("POST", "/api", 1700000000, "n", "aaa");
        let s2 = handler.sign("POST", "/api", 1700000000, "n", "bbb");
        assert_ne!(s1, s2);
    }

    /// 不同 method 产生不同签名（spec Scenario）。
    #[test]
    fn sign_different_method_produces_different_signatures() {
        let handler = make_handler();
        let s1 = handler.sign("GET", "/api", 1700000000, "n", "body");
        let s2 = handler.sign("POST", "/api", 1700000000, "n", "body");
        assert_ne!(s1, s2);
    }

    /// HKDF 派生确保不同 app_key 产生不同签名（域分隔）。
    #[test]
    fn sign_different_app_key_produces_different_signatures() {
        let dao1: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let dao2: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let h1 = SignHandler::new("app-key-1", TEST_APP_SECRET, dao1).unwrap();
        let h2 = SignHandler::new("app-key-2", TEST_APP_SECRET, dao2).unwrap();
        let s1 = h1.sign("POST", "/api", 1700000000, "n", "body");
        let s2 = h2.sign("POST", "/api", 1700000000, "n", "body");
        // 相同 app_secret 但不同 app_key → HKDF salt 不同 → 派生密钥不同 → 签名不同
        assert_ne!(s1, s2, "不同 app_key 应通过 HKDF salt 产生不同签名");
    }

    // ========================================================================
    // validate 测试
    // ========================================================================

    /// 成功校验（spec Scenario）。
    #[tokio::test]
    async fn validate_success() {
        let handler = make_handler();
        let ts = now_ts();
        let sig = handler.sign("POST", "/api/v1/users", ts, "nonce-1", "body-sha256");
        let result = handler
            .validate("POST", "/api/v1/users", ts, "nonce-1", "body-sha256", &sig)
            .await;
        assert!(result.is_ok());
    }

    /// 校验成功后 nonce 存入 dao（spec Scenario）。
    #[tokio::test]
    async fn validate_success_stores_nonce() {
        let dao = Arc::new(MockDao::new());
        let handler = SignHandler::new("app-001", TEST_APP_SECRET, dao.clone()).unwrap();
        let ts = now_ts();
        let sig = handler.sign("GET", "/api", ts, "nonce-store", "body");
        handler
            .validate("GET", "/api", ts, "nonce-store", "body", &sig)
            .await
            .unwrap();
        let key = "bulwark:sign:nonce:nonce-store";
        let stored = dao.get(key).await.unwrap();
        assert!(stored.is_some());
    }

    /// 签名不匹配返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_signature_mismatch_returns_error() {
        let handler = make_handler();
        let ts = now_ts();
        let result = handler
            .validate(
                "POST",
                "/api",
                ts,
                "nonce-mismatch",
                "body",
                "forged-signature",
            )
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// 时间戳过期返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_expired_timestamp_returns_error() {
        let handler = make_handler();
        let old_ts = now_ts() - 600; // 超过 300 秒窗口
        let sig = handler.sign("POST", "/api", old_ts, "nonce-exp", "body");
        let result = handler
            .validate("POST", "/api", old_ts, "nonce-exp", "body", &sig)
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::ExpiredToken(_)) => {},
            other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
        }
    }

    /// 未来时间戳返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_future_timestamp_returns_error() {
        let handler = make_handler();
        let future_ts = now_ts() + 600;
        let sig = handler.sign("POST", "/api", future_ts, "nonce-fut", "body");
        let result = handler
            .validate("POST", "/api", future_ts, "nonce-fut", "body", &sig)
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::ExpiredToken(_)) => {},
            other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
        }
    }

    /// nonce 重放被拒绝（spec Scenario）。
    #[tokio::test]
    async fn validate_nonce_replay_rejected() {
        let handler = make_handler();
        let ts = now_ts();
        let sig = handler.sign("POST", "/api", ts, "nonce-replay", "body");
        // 第一次校验成功
        let first = handler
            .validate("POST", "/api", ts, "nonce-replay", "body", &sig)
            .await;
        assert!(first.is_ok());
        // 第二次校验失败（nonce 重放）
        let second = handler
            .validate("POST", "/api", ts, "nonce-replay", "body", &sig)
            .await;
        assert!(second.is_err());
        match second.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// method 大小写差异导致签名不匹配（spec Scenario）。
    #[tokio::test]
    async fn validate_method_case_difference_returns_error() {
        let handler = make_handler();
        let ts = now_ts();
        let sig = handler.sign("POST", "/api", ts, "nonce-case", "body");
        let result = handler
            .validate("post", "/api", ts, "nonce-case", "body", &sig)
            .await;
        assert!(result.is_err());
    }
}
