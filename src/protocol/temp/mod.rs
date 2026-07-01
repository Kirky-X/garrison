//! 临时凭证协议模块，提供短时有效、一次性使用的临时访问凭证。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的临时 Token 机制，
//! 适用于邀请码、密码重置链接、邮箱验证码等场景。
//!
//! 仅在启用 `protocol-temp` 特性时编译。
//!
//! ## Key 命名空间（依据 spec protocol-temp）
//!
//! 所有临时凭据存储在 `bulwark:temp:<prefix>:<random>` 命名空间下，
//! 与 session/sign/sso/apikey 模块隔离。`prefix` 用于区分业务场景
//! （如 `invite`、`reset`、`verify`），不允许包含 `:` 以避免解析歧义。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use std::sync::Arc;
use uuid::Uuid;

/// 临时凭证处理器（依据 spec protocol-temp）。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于临时凭据存储。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct TempCredentialHandler {
    /// DAO 抽象层，用于临时凭据存储。
    dao: Arc<dyn BulwarkDao>,
}

impl TempCredentialHandler {
    /// 创建新的临时凭证处理器（依据 spec protocol-temp）。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 签发临时凭据（依据 spec protocol-temp）。
    ///
    /// 生成 key 格式为 `bulwark:temp:<prefix>:<random>`，其中 `<random>` 为
    /// 64 字符随机 hex 字符串。value 原样存储传入的 `value`，TTL 为 `ttl_seconds` 秒。
    ///
    /// # 参数
    /// - `prefix`: 业务场景前缀（不可包含 `:`）。
    /// - `value`: 凭证载荷（允许空字符串）。
    /// - `ttl_seconds`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: `prefix` 包含 `:` 或 `ttl_seconds <= 0`。
    pub async fn issue(
        &self,
        prefix: &str,
        value: &str,
        ttl_seconds: i64,
    ) -> BulwarkResult<String> {
        if prefix.contains(':') {
            return Err(BulwarkError::InvalidParam(
                "prefix 不可包含 ':'".to_string(),
            ));
        }
        if ttl_seconds <= 0 {
            return Err(BulwarkError::InvalidParam(
                "ttl_seconds 必须大于 0".to_string(),
            ));
        }
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let random = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let key = format!("bulwark:temp:{}:{}", prefix, random);
        self.dao
            .set(&key, value, ttl_seconds as u64)
            .await?;
        Ok(key)
    }

    /// 读取临时凭据（依据 spec protocol-temp）。
    ///
    /// 读取后不删除凭据（与 [`consume`](Self::consume) 区分）。
    ///
    /// # 返回
    /// - `Ok(Some(value))`: 凭据存在。
    /// - `Ok(None)`: 凭据不存在或已过期。
    pub async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        self.dao.get(key).await
    }

    /// 撤销临时凭据（依据 spec protocol-temp）。
    ///
    /// 从 dao 中删除指定凭据。即使凭据不存在也返回 `Ok(())`（幂等语义）。
    pub async fn revoke(&self, key: &str) -> BulwarkResult<()> {
        // delete 是幂等的：不存在的 key 删除返回 Ok(())
        self.dao.delete(key).await
    }

    /// 消费临时凭据（依据 spec protocol-temp）。
    ///
    /// 原子地读取并删除凭据（get + delete 组合），保证一次性使用语义。
    ///
    /// # 返回
    /// - `Ok(Some(value))`: 凭据存在且已被消费（删除）。
    /// - `Ok(None)`: 凭据不存在或已过期。
    pub async fn consume(&self, key: &str) -> BulwarkResult<Option<String>> {
        let value = self.dao.get(key).await?;
        if value.is_some() {
            // 存在则删除（一次性使用语义）
            self.dao.delete(key).await?;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// 测试用 Mock DAO（与 apikey 模块一致的结构）。
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

    /// 创建 handler（使用 MockDao）。
    fn make_handler() -> TempCredentialHandler {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        TempCredentialHandler::new(dao)
    }

    // ========================================================================
    // TempCredentialHandler 构造测试（依据 spec protocol-temp）
    // ========================================================================

    /// 构造 handler（spec Scenario）。
    #[test]
    fn new_creates_handler() {
        let _handler = make_handler();
    }

    // ========================================================================
    // issue 测试（依据 spec protocol-temp）
    // ========================================================================

    /// 成功签发，key 前缀正确（spec Scenario）。
    #[tokio::test]
    async fn issue_returns_key_with_correct_prefix() {
        let handler = make_handler();
        let key = handler.issue("invite", "payload-data", 600).await.unwrap();
        assert!(key.starts_with("bulwark:temp:invite:"));
    }

    /// 复用同一 handler 多次签发返回不同 key（spec Scenario）。
    #[tokio::test]
    async fn issue_multiple_times_returns_different_keys() {
        let handler = make_handler();
        let k1 = handler.issue("invite", "v1", 60).await.unwrap();
        let k2 = handler.issue("invite", "v1", 60).await.unwrap();
        assert_ne!(k1, k2);
    }

    /// 不同 prefix 产生不同命名空间（spec Scenario）。
    #[tokio::test]
    async fn issue_different_prefix_different_namespace() {
        let handler = make_handler();
        let k1 = handler.issue("invite", "v1", 60).await.unwrap();
        let k2 = handler.issue("reset", "v2", 60).await.unwrap();
        assert!(k1.starts_with("bulwark:temp:invite:"));
        assert!(k2.starts_with("bulwark:temp:reset:"));
    }

    /// ttl_seconds <= 0 返回错误（spec Scenario）。
    #[tokio::test]
    async fn issue_zero_ttl_returns_error() {
        let handler = make_handler();
        let result = handler.issue("invite", "data", 0).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {}
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// prefix 包含冒号返回错误（spec Scenario）。
    #[tokio::test]
    async fn issue_prefix_with_colon_returns_error() {
        let handler = make_handler();
        let result = handler.issue("inv:ite", "data", 60).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {}
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// value 为空字符串允许存储（spec Scenario）。
    #[tokio::test]
    async fn issue_empty_value_allowed() {
        let dao = Arc::new(MockDao::new());
        let handler = TempCredentialHandler::new(dao.clone());
        let key = handler.issue("invite", "", 60).await.unwrap();
        let value = dao.get(&key).await.unwrap();
        assert_eq!(value, Some("".to_string()));
    }

    // ========================================================================
    // get 测试（依据 spec protocol-temp）
    // ========================================================================

    /// 读取存在的凭据，多次读取不删除（spec Scenario）。
    #[tokio::test]
    async fn get_returns_value_without_deleting() {
        let handler = make_handler();
        let key = handler.issue("invite", "data", 60).await.unwrap();
        let v1 = handler.get(&key).await.unwrap();
        let v2 = handler.get(&key).await.unwrap();
        assert_eq!(v1, Some("data".to_string()));
        assert_eq!(v2, Some("data".to_string()));
    }

    /// 读取不存在的凭据返回 None（spec Scenario）。
    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let handler = make_handler();
        let result = handler.get("bulwark:temp:invite:nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    // ========================================================================
    // revoke 测试（依据 spec protocol-temp）
    // ========================================================================

    /// 撤销存在的凭据（spec Scenario）。
    #[tokio::test]
    async fn revoke_existing_returns_ok() {
        let handler = make_handler();
        let key = handler.issue("invite", "data", 60).await.unwrap();
        let result = handler.revoke(&key).await;
        assert!(result.is_ok());
        // 再次 get 应为 None
        let value = handler.get(&key).await.unwrap();
        assert_eq!(value, None);
    }

    /// 撤销不存在的凭据返回 Ok（幂等语义，spec Scenario）。
    #[tokio::test]
    async fn revoke_nonexistent_returns_ok() {
        let handler = make_handler();
        let result = handler.revoke("bulwark:temp:invite:nonexistent").await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // consume 测试（依据 spec protocol-temp）
    // ========================================================================

    /// 成功消费存在的凭据（spec Scenario）。
    #[tokio::test]
    async fn consume_returns_value_and_deletes() {
        let handler = make_handler();
        let key = handler.issue("invite", "data", 60).await.unwrap();
        let value = handler.consume(&key).await.unwrap();
        assert_eq!(value, Some("data".to_string()));
        // 再次 consume 应为 None
        let again = handler.consume(&key).await.unwrap();
        assert_eq!(again, None);
    }

    /// 重复消费返回 None（spec Scenario）。
    #[tokio::test]
    async fn consume_twice_returns_none_second_time() {
        let handler = make_handler();
        let key = handler.issue("invite", "data", 60).await.unwrap();
        let v1 = handler.consume(&key).await.unwrap();
        let v2 = handler.consume(&key).await.unwrap();
        assert_eq!(v1, Some("data".to_string()));
        assert_eq!(v2, None);
    }

    /// 消费不存在的凭据返回 None（spec Scenario）。
    #[tokio::test]
    async fn consume_nonexistent_returns_none() {
        let handler = make_handler();
        let value = handler.consume("bulwark:temp:invite:nonexistent").await.unwrap();
        assert_eq!(value, None);
    }

    /// revoke 后 consume 失败返回 None（spec Scenario）。
    #[tokio::test]
    async fn consume_after_revoke_returns_none() {
        let handler = make_handler();
        let key = handler.issue("invite", "data", 60).await.unwrap();
        handler.revoke(&key).await.unwrap();
        let value = handler.consume(&key).await.unwrap();
        assert_eq!(value, None);
    }

    // ========================================================================
    // Key 命名空间隔离测试（依据 spec protocol-temp）
    // ========================================================================

    /// temp key 与 apikey 命名空间隔离（spec Scenario）。
    #[tokio::test]
    async fn temp_namespace_isolated() {
        let dao = Arc::new(MockDao::new());
        // 模拟同时存在 temp key 与 apikey key
        dao.set("bulwark:temp:invite:abc", "temp-value", 60).await.unwrap();
        dao.set("bulwark:apikey:abc", "apikey-value", 60).await.unwrap();
        let handler = TempCredentialHandler::new(dao.clone());
        // consume temp key 不影响 apikey key
        let value = handler.consume("bulwark:temp:invite:abc").await.unwrap();
        assert_eq!(value, Some("temp-value".to_string()));
        let apikey_value = dao.get("bulwark:apikey:abc").await.unwrap();
        assert_eq!(apikey_value, Some("apikey-value".to_string()));
    }
}
