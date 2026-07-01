//! API Key 协议模块，提供 API Key 生成/校验/吊销/轮换。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 API 接口鉴权能力，
//! 适用于服务间调用与开放 API 场景。
//!
//! 仅在启用 `protocol-apikey` 特性时编译。
//!
//! ## Key 命名空间（依据 spec protocol-apikey）
//!
//! 所有 API Key 存储在 `bulwark:apikey:<key>` 命名空间下，
//! 与 session/sign/sso/temp 模块隔离。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// API Key 元数据（依据 spec protocol-apikey）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyInfo {
    /// 登录主体标识。
    pub login_id: i64,
    /// 作用域列表。
    pub scopes: Vec<String>,
    /// 过期时间戳（秒）。
    pub expire_at: i64,
    /// 是否已吊销。
    pub revoked: bool,
}

/// API Key 处理器（依据 spec protocol-apikey）。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于 API Key 存储。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct ApiKeyHandler {
    /// DAO 抽象层，用于 API Key 存储。
    dao: Arc<dyn BulwarkDao>,
}

impl ApiKeyHandler {
    /// 创建新的 API Key 处理器（依据 spec protocol-apikey）。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 生成 API Key（依据 spec protocol-apikey）。
    ///
    /// 生成 64 字符随机 hex 字符串，存储到 `bulwark:apikey:<key>`，
    /// value 为 JSON `ApiKeyInfo`，TTL 为 `timeout` 秒。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `scopes`: 作用域列表。
    /// - `timeout`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: timeout <= 0。
    pub async fn generate(
        &self,
        login_id: i64,
        scopes: Vec<String>,
        timeout: i64,
    ) -> BulwarkResult<String> {
        if timeout <= 0 {
            return Err(BulwarkError::InvalidParam("timeout 必须大于 0".to_string()));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| BulwarkError::Internal(format!("获取系统时间失败: {}", e)))?;
        let info = ApiKeyInfo {
            login_id,
            scopes,
            expire_at: now + timeout,
            revoked: false,
        };
        let value = serde_json::to_string(&info)
            .map_err(|e| BulwarkError::Internal(format!("序列化 ApiKeyInfo 失败: {}", e)))?;
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let dao_key = format!("bulwark:apikey:{}", key);
        self.dao.set(&dao_key, &value, timeout as u64).await?;
        Ok(key)
    }

    /// 校验 API Key（依据 spec protocol-apikey）。
    ///
    /// 校验逻辑：(1) 读取 key 对应的 `ApiKeyInfo`；(2) 检查 `revoked == false`；
    /// (3) 检查 `expire_at > 当前时间戳`；(4) 返回 `ApiKeyInfo`。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: key 不存在或已吊销。
    /// - `BulwarkError::ExpiredToken`: key 已过期。
    pub async fn verify(&self, key: &str) -> BulwarkResult<ApiKeyInfo> {
        let dao_key = format!("bulwark:apikey:{}", key);
        let value = self.dao.get(&dao_key).await?;
        let value =
            value.ok_or_else(|| BulwarkError::InvalidToken("API Key 不存在".to_string()))?;
        let info: ApiKeyInfo = serde_json::from_str(&value)
            .map_err(|e| BulwarkError::Internal(format!("反序列化 ApiKeyInfo 失败: {}", e)))?;
        if info.revoked {
            return Err(BulwarkError::InvalidToken("API Key 已吊销".to_string()));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| BulwarkError::Internal(format!("获取系统时间失败: {}", e)))?;
        if info.expire_at <= now {
            return Err(BulwarkError::ExpiredToken("API Key 已过期".to_string()));
        }
        Ok(info)
    }

    /// 吊销 API Key（依据 spec protocol-apikey）。
    ///
    /// 将 `ApiKeyInfo` 的 `revoked` 设为 `true` 并写回 dao（保留 TTL）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: key 不存在。
    pub async fn revoke(&self, key: &str) -> BulwarkResult<()> {
        let dao_key = format!("bulwark:apikey:{}", key);
        let value = self.dao.get(&dao_key).await?;
        let value =
            value.ok_or_else(|| BulwarkError::InvalidToken("API Key 不存在".to_string()))?;
        let mut info: ApiKeyInfo = serde_json::from_str(&value)
            .map_err(|e| BulwarkError::Internal(format!("反序列化 ApiKeyInfo 失败: {}", e)))?;
        info.revoked = true;
        let new_value = serde_json::to_string(&info)
            .map_err(|e| BulwarkError::Internal(format!("序列化 ApiKeyInfo 失败: {}", e)))?;
        // 使用 update 保留 TTL
        self.dao.update(&dao_key, &new_value).await
    }

    /// 轮换 API Key（依据 spec protocol-apikey）。
    ///
    /// 轮换逻辑：(1) 读取 old_key 的 `ApiKeyInfo`；(2) 校验有效（未吊销、未过期）；
    /// (3) 吊销 old_key；(4) 生成新 key（保留 login_id/scopes/剩余 TTL）；(5) 返回新 key。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: old_key 不存在或已吊销。
    /// - `BulwarkError::ExpiredToken`: old_key 已过期。
    pub async fn rotate(&self, old_key: &str) -> BulwarkResult<String> {
        // (1)(2) 校验 old_key
        let info = self.verify(old_key).await?;
        // (3) 吊销 old_key
        self.revoke(old_key).await?;
        // (4) 生成新 key（保留 login_id/scopes/剩余 TTL）
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| BulwarkError::Internal(format!("获取系统时间失败: {}", e)))?;
        let remaining_ttl = info.expire_at - now;
        if remaining_ttl <= 0 {
            return Err(BulwarkError::ExpiredToken(
                "API Key 已过期，无法轮换".to_string(),
            ));
        }
        self.generate(info.login_id, info.scopes, remaining_ttl)
            .await
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

    /// 创建 ApiKeyHandler（使用 MockDao）。
    fn make_handler() -> ApiKeyHandler {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        ApiKeyHandler::new(dao)
    }

    // ========================================================================
    // ApiKeyHandler 构造测试（依据 spec protocol-apikey）
    // ========================================================================

    /// 构造 ApiKeyHandler（spec Scenario）。
    #[test]
    fn new_creates_handler() {
        let _handler = make_handler();
    }

    // ========================================================================
    // generate 测试（依据 spec protocol-apikey）
    // ========================================================================

    /// 成功生成 API Key，返回 64 字符（spec Scenario）。
    #[tokio::test]
    async fn generate_returns_64_chars() {
        let handler = make_handler();
        let key = handler
            .generate(1001, vec!["read".into()], 3600)
            .await
            .unwrap();
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 复用同一 handler 多次生成不同 key（spec Scenario）。
    #[tokio::test]
    async fn generate_multiple_times_returns_different_keys() {
        let handler = make_handler();
        let k1 = handler.generate(1001, vec![], 3600).await.unwrap();
        let k2 = handler.generate(1001, vec![], 3600).await.unwrap();
        assert_ne!(k1, k2);
    }

    /// timeout <= 0 返回错误（spec Scenario）。
    #[tokio::test]
    async fn generate_zero_timeout_returns_error() {
        let handler = make_handler();
        let result = handler.generate(1001, vec![], 0).await;
        assert!(result.is_err());
    }

    /// key 前缀正确（spec Scenario）。
    #[tokio::test]
    async fn generate_uses_correct_key_prefix() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        let key = handler
            .generate(1001, vec!["read".into()], 3600)
            .await
            .unwrap();
        let dao_key = format!("bulwark:apikey:{}", key);
        let value = dao.get(&dao_key).await.unwrap();
        assert!(value.is_some());
        let info: ApiKeyInfo = serde_json::from_str(&value.unwrap()).unwrap();
        assert_eq!(info.login_id, 1001);
        assert_eq!(info.scopes, vec!["read".to_string()]);
        assert!(!info.revoked);
    }

    // ========================================================================
    // verify 测试（依据 spec protocol-apikey）
    // ========================================================================

    /// 成功校验返回 ApiKeyInfo（spec Scenario）。
    #[tokio::test]
    async fn verify_success_returns_info() {
        let handler = make_handler();
        let key = handler
            .generate(1001, vec!["read".into(), "write".into()], 3600)
            .await
            .unwrap();
        let info = handler.verify(&key).await.unwrap();
        assert_eq!(info.login_id, 1001);
        assert_eq!(info.scopes, vec!["read".to_string(), "write".to_string()]);
        assert!(!info.revoked);
    }

    /// 校验不存在的 key 返回错误（spec Scenario）。
    #[tokio::test]
    async fn verify_nonexistent_returns_error() {
        let handler = make_handler();
        let result = handler.verify("nonexistent-key").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// 校验已吊销的 key 返回错误（spec Scenario）。
    #[tokio::test]
    async fn verify_revoked_returns_error() {
        let handler = make_handler();
        let key = handler.generate(1001, vec![], 3600).await.unwrap();
        handler.revoke(&key).await.unwrap();
        let result = handler.verify(&key).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// 校验已过期的 key 返回错误（spec Scenario）。
    #[tokio::test]
    async fn verify_expired_returns_error() {
        let handler = make_handler();
        // 生成一个 1 秒过期的 key
        let key = handler.generate(1001, vec![], 1).await.unwrap();
        // 等待 2 秒
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let result = handler.verify(&key).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::ExpiredToken(_)) => {},
            other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // revoke 测试（依据 spec protocol-apikey）
    // ========================================================================

    /// 成功吊销（spec Scenario）。
    #[tokio::test]
    async fn revoke_success() {
        let handler = make_handler();
        let key = handler.generate(1001, vec![], 3600).await.unwrap();
        let result = handler.revoke(&key).await;
        assert!(result.is_ok());
        // 再次 verify 应失败
        let verify_result = handler.verify(&key).await;
        assert!(verify_result.is_err());
    }

    /// 吊销不存在的 key 返回错误（spec Scenario）。
    #[tokio::test]
    async fn revoke_nonexistent_returns_error() {
        let handler = make_handler();
        let result = handler.revoke("nonexistent-key").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // rotate 测试（依据 spec protocol-apikey）
    // ========================================================================

    /// 成功轮换（spec Scenario）。
    #[tokio::test]
    async fn rotate_success() {
        let handler = make_handler();
        let old_key = handler
            .generate(1001, vec!["read".into()], 3600)
            .await
            .unwrap();
        let new_key = handler.rotate(&old_key).await.unwrap();
        assert_ne!(old_key, new_key);
        assert_eq!(new_key.len(), 64);
        // old_key 应被吊销
        let old_result = handler.verify(&old_key).await;
        assert!(old_result.is_err());
        // new_key 应有效，且保留 login_id 和 scopes
        let info = handler.verify(&new_key).await.unwrap();
        assert_eq!(info.login_id, 1001);
        assert_eq!(info.scopes, vec!["read".to_string()]);
    }

    /// 轮换不存在的 key 返回错误（spec Scenario）。
    #[tokio::test]
    async fn rotate_nonexistent_returns_error() {
        let handler = make_handler();
        let result = handler.rotate("nonexistent-key").await;
        assert!(result.is_err());
    }
}
