//! API 签名协议模块，提供请求签名生成与校验 + nonce 防重放。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的微服务网关签名认证，
//! 基于 HMAC-SHA256 + Base64 实现请求签名。
//!
//! 仅在启用 `protocol-sign` 特性时编译。
//!
//! ## 签名算法（依据 spec protocol-sign）
//!
//! `sign = base64(hmac_sha256(app_secret, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_md5}"))`
//!
//! ## Key 命名空间
//!
//! 所有 sign nonce 存储在 `bulwark:sign:nonce:<nonce>` 命名空间下。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 默认时间戳窗口（秒）。
const DEFAULT_TIMESTAMP_WINDOW: i64 = 300;

/// HMAC-SHA256 类型别名。
type HmacSha256 = Hmac<Sha256>;

/// API 签名处理器（依据 spec protocol-sign）。
///
/// 持有 `app_key`、`app_secret` 与 `Arc<dyn BulwarkDao>`（用于 nonce 存储）。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct SignHandler {
    /// 应用标识。
    app_key: String,
    /// HMAC 密钥。
    app_secret: String,
    /// DAO 抽象层，用于 nonce 存储。
    dao: Arc<dyn BulwarkDao>,
    /// 时间戳窗口（秒）。
    timestamp_window: i64,
}

impl SignHandler {
    /// 创建新的签名处理器（依据 spec protocol-sign）。
    ///
    /// # 参数
    /// - `app_key`: 应用标识，不可为空。
    /// - `app_secret`: HMAC 密钥。
    /// - `dao`: DAO 抽象层实例。
    ///
    /// # 错误
    /// - `BulwarkError::Config`: app_key 为空。
    pub fn new(
        app_key: impl Into<String>,
        app_secret: impl Into<String>,
        dao: Arc<dyn BulwarkDao>,
    ) -> BulwarkResult<Self> {
        let app_key = app_key.into();
        if app_key.is_empty() {
            return Err(BulwarkError::Config("app_key 不可为空".to_string()));
        }
        Ok(Self {
            app_key,
            app_secret: app_secret.into(),
            dao,
            timestamp_window: DEFAULT_TIMESTAMP_WINDOW,
        })
    }

    /// 设置时间戳窗口（秒），默认 300 秒（依据 spec protocol-sign）。
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

    /// 生成签名（依据 spec protocol-sign）。
    ///
    /// 签名算法：`base64(hmac_sha256(app_secret, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_md5}"))`。
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        body_md5: &str,
    ) -> String {
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, timestamp, nonce, body_md5
        );
        let mut mac = HmacSha256::new_from_slice(self.app_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }

    /// 校验签名（依据 spec protocol-sign）。
    ///
    /// 校验逻辑：(1) 检查时间戳窗口；(2) 检查 nonce 未被使用过；
    /// (3) 重新计算签名并常量时间比较；(4) 校验成功后存储 nonce。
    ///
    /// # 参数
    /// - `method`: HTTP 方法。
    /// - `path`: 请求路径。
    /// - `timestamp`: 请求时间戳（秒）。
    /// - `nonce`: 随机串。
    /// - `body_md5`: 请求体 MD5。
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
        body_md5: &str,
        signature: &str,
    ) -> BulwarkResult<()> {
        // (1) 时间戳窗口校验
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| BulwarkError::Internal(format!("获取系统时间失败: {}", e)))?;
        if (now - timestamp).abs() > self.timestamp_window {
            return Err(BulwarkError::ExpiredToken(
                "签名时间戳超出窗口".to_string(),
            ));
        }

        // (2) nonce 防重放检查
        let nonce_key = format!("bulwark:sign:nonce:{}", nonce);
        if self.dao.get(&nonce_key).await?.is_some() {
            return Err(BulwarkError::InvalidToken(
                "nonce 重放".to_string(),
            ));
        }

        // (3) 重新计算签名并常量时间比较
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, timestamp, nonce, body_md5
        );
        let mut mac = HmacSha256::new_from_slice(self.app_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        // 将传入的 signature（Base64）解码为字节
        let signature_bytes = STANDARD
            .decode(signature)
            .map_err(|e| BulwarkError::InvalidToken(format!("签名 Base64 解码失败: {}", e)))?;
        // 使用 verify_slice 进行常量时间比较
        match mac.verify_slice(&signature_bytes) {
            Ok(_) => {}
            Err(_) => {
                return Err(BulwarkError::InvalidToken(
                    "签名不匹配".to_string(),
                ));
            }
        }

        // (4) 校验成功，存储 nonce（TTL = timestamp_window）
        self.dao
            .set(&nonce_key, "1", self.timestamp_window as u64)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// 测试用 Mock DAO。
    struct MockDao {
        data: Mutex<HashMap<String, String>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let data = self.data.lock().await;
            Ok(data.get(key).cloned())
        }

        async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            let mut data = self.data.lock().await;
            data.insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut data = self.data.lock().await;
            if data.contains_key(key) {
                data.insert(key.to_string(), value.to_string());
                Ok(())
            } else {
                Err(BulwarkError::Dao("key 不存在".to_string()))
            }
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            let mut data = self.data.lock().await;
            data.remove(key);
            Ok(())
        }
    }

    /// 创建 SignHandler（使用 MockDao）。
    fn make_handler() -> SignHandler {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        SignHandler::new("app-001", "secret-xyz", dao).unwrap()
    }

    /// 获取当前时间戳。
    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // ========================================================================
    // SignHandler 构造测试（依据 spec protocol-sign）
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
        let result = SignHandler::new("", "secret", dao);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {}
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// 自定义时间窗口（spec Scenario）。
    #[test]
    fn with_timestamp_window_sets_window() {
        let handler = make_handler().with_timestamp_window(120);
        assert_eq!(handler.timestamp_window(), 120);
    }

    // ========================================================================
    // sign 测试（依据 spec protocol-sign）
    // ========================================================================

    /// 标准签名生成，返回 Base64 字符串（spec Scenario）。
    #[test]
    fn sign_returns_base64_string() {
        let handler = make_handler();
        let sig = handler.sign("POST", "/api/v1/users", 1700000000, "nonce-abc", "d41d8cd98f00b204e9800998ecf8427e");
        // Base64 编码的 HMAC-SHA256 应为 44 字符（32 字节 → 44 字符含 padding）
        assert_eq!(sig.len(), 44);
        assert!(sig.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    /// 不同 body_md5 产生不同签名（spec Scenario）。
    #[test]
    fn sign_different_body_md5_produces_different_signatures() {
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

    // ========================================================================
    // validate 测试（依据 spec protocol-sign）
    // ========================================================================

    /// 成功校验（spec Scenario）。
    #[tokio::test]
    async fn validate_success() {
        let handler = make_handler();
        let ts = now_ts();
        let sig = handler.sign("POST", "/api/v1/users", ts, "nonce-1", "body-md5");
        let result = handler.validate("POST", "/api/v1/users", ts, "nonce-1", "body-md5", &sig).await;
        assert!(result.is_ok());
    }

    /// 校验成功后 nonce 存入 dao（spec Scenario）。
    #[tokio::test]
    async fn validate_success_stores_nonce() {
        let dao = Arc::new(MockDao::new());
        let handler = SignHandler::new("app", "secret", dao.clone()).unwrap();
        let ts = now_ts();
        let sig = handler.sign("GET", "/api", ts, "nonce-store", "body");
        handler.validate("GET", "/api", ts, "nonce-store", "body", &sig).await.unwrap();
        let key = "bulwark:sign:nonce:nonce-store";
        let stored = dao.get(key).await.unwrap();
        assert!(stored.is_some());
    }

    /// 签名不匹配返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_signature_mismatch_returns_error() {
        let handler = make_handler();
        let ts = now_ts();
        let result = handler.validate("POST", "/api", ts, "nonce-mismatch", "body", "forged-signature").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {}
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// 时间戳过期返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_expired_timestamp_returns_error() {
        let handler = make_handler();
        let old_ts = now_ts() - 600; // 超过 300 秒窗口
        let sig = handler.sign("POST", "/api", old_ts, "nonce-exp", "body");
        let result = handler.validate("POST", "/api", old_ts, "nonce-exp", "body", &sig).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::ExpiredToken(_)) => {}
            other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
        }
    }

    /// 未来时间戳返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_future_timestamp_returns_error() {
        let handler = make_handler();
        let future_ts = now_ts() + 600;
        let sig = handler.sign("POST", "/api", future_ts, "nonce-fut", "body");
        let result = handler.validate("POST", "/api", future_ts, "nonce-fut", "body", &sig).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::ExpiredToken(_)) => {}
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
        let first = handler.validate("POST", "/api", ts, "nonce-replay", "body", &sig).await;
        assert!(first.is_ok());
        // 第二次校验失败（nonce 重放）
        let second = handler.validate("POST", "/api", ts, "nonce-replay", "body", &sig).await;
        assert!(second.is_err());
        match second.err() {
            Some(BulwarkError::InvalidToken(_)) => {}
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// method 大小写差异导致签名不匹配（spec Scenario）。
    #[tokio::test]
    async fn validate_method_case_difference_returns_error() {
        let handler = make_handler();
        let ts = now_ts();
        let sig = handler.sign("POST", "/api", ts, "nonce-case", "body");
        let result = handler.validate("post", "/api", ts, "nonce-case", "body", &sig).await;
        assert!(result.is_err());
    }
}
