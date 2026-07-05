//! API Key 协议模块，提供 API Key 生成/校验/吊销/轮换。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 API 接口鉴权能力，
//! 适用于服务间调用与开放 API 场景。
//!
//! 仅在启用 `protocol-apikey` 特性时编译。
//!
//! ## Key 命名空间（依据 spec protocol-apikey-namespace）
//!
//! v0.4.2 起，所有 API Key 存储格式由 `bulwark:apikey:<key>` 升级为
//! `bulwark:apikey:<namespace>:<key>`，支持多租户/多场景隔离。
//! `verify` 兼容旧格式（无 namespace）以保护历史 key 不失效。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
// v0.4.2: listener_manager 注入（feature-gated，依据 spec listener-events-extend R-001）
#[cfg(feature = "listener")]
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
// 0.4.2: LoginId newtype 接入（impl Into<LoginId> 公开 API + i64 内部层）
use crate::stp::login_id::LoginId;
use crate::stp::login_id_to_i64;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// API Key 元数据（依据 spec protocol-apikey / protocol-apikey-namespace）。
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
    /// 命名空间（v0.4.2 新增，依据 spec protocol-apikey-namespace R-001）。
    ///
    /// - 新生成 key 必带 namespace（默认 `"default"`）
    /// - 旧 JSON 数据（无 `namespace` 字段）反序列化时通过 `#[serde(default)]` 填充为 `"default"`
    /// - 与 key 存储路径 `bulwark:apikey:<namespace>:<key>` 中的 namespace 严格一致
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

/// `ApiKeyInfo::namespace` 的默认值：`"default"`（依据 spec protocol-apikey-namespace R-001）。
///
/// 旧 JSON 数据不含 `namespace` 字段时，serde 用此函数填充默认值，保证向后兼容。
fn default_namespace() -> String {
    "default".to_string()
}

/// 校验 namespace 合法性（依据 spec protocol-apikey-namespace Constraints）。
///
/// 规则：
/// - 长度 1-64 字符
/// - 仅允许 `[a-zA-Z0-9_-]`
///
/// # 错误
/// - `BulwarkError::InvalidParam`: namespace 为空、过长或包含非法字符。
fn validate_namespace(namespace: &str) -> BulwarkResult<()> {
    if namespace.is_empty() {
        return Err(BulwarkError::InvalidParam("namespace 不能为空".to_string()));
    }
    if namespace.len() > 64 {
        return Err(BulwarkError::InvalidParam(format!(
            "namespace 长度不能超过 64 字符，实际: {}",
            namespace.len()
        )));
    }
    if !namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(BulwarkError::InvalidParam(format!(
            "namespace 仅允许 [a-zA-Z0-9_-]，实际: {}",
            namespace
        )));
    }
    Ok(())
}

/// API Key 处理器（依据 spec protocol-apikey）。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于 API Key 存储。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct ApiKeyHandler {
    /// DAO 抽象层，用于 API Key 存储。
    dao: Arc<dyn BulwarkDao>,
    /// v0.4.2：可选监听器管理器，注入后 rotate 广播 ApiKeyRotate 事件
    ///（依据 spec listener-events-extend R-001）。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
}

impl ApiKeyHandler {
    /// 创建新的 API Key 处理器（依据 spec protocol-apikey）。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self {
            dao,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 `BulwarkListenerManager`，启用 ApiKeyRotate 事件广播
    ///（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 注入后 `rotate` 成功时广播 `BulwarkEvent::ApiKeyRotate`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<BulwarkListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
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
    /// - `BulwarkError::Config`: 传入 `LoginId::String` 形式，内部层尚未完成迁移。
    pub async fn generate(
        &self,
        login_id: impl Into<LoginId>,
        scopes: Vec<String>,
        timeout: i64,
    ) -> BulwarkResult<String> {
        self.generate_with_namespace(login_id, &default_namespace(), scopes, timeout)
            .await
    }

    /// 生成带 namespace 的 API Key（依据 spec protocol-apikey-namespace R-002）。
    ///
    /// 生成 64 字符随机 hex 字符串，存储到 `bulwark:apikey:<namespace>:<key>`，
    /// value 为 JSON `ApiKeyInfo`（含 `namespace` 字段），TTL 为 `timeout` 秒。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `namespace`: 命名空间（1-64 字符，仅 `[a-zA-Z0-9_-]`）。
    /// - `scopes`: 作用域列表。
    /// - `timeout`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: timeout <= 0 或 namespace 非法。
    /// - `BulwarkError::Config`: 传入 `LoginId::String` 形式，内部层尚未完成迁移。
    pub async fn generate_with_namespace(
        &self,
        login_id: impl Into<LoginId>,
        namespace: &str,
        scopes: Vec<String>,
        timeout: i64,
    ) -> BulwarkResult<String> {
        let login_id: i64 = login_id_to_i64(login_id.into())?;
        if timeout <= 0 {
            return Err(BulwarkError::InvalidParam("timeout 必须大于 0".to_string()));
        }
        validate_namespace(namespace)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| BulwarkError::Internal(format!("获取系统时间失败: {}", e)))?;
        let info = ApiKeyInfo {
            login_id,
            scopes,
            expire_at: now + timeout,
            revoked: false,
            namespace: namespace.to_string(),
        };
        let value = serde_json::to_string(&info)
            .map_err(|e| BulwarkError::Internal(format!("序列化 ApiKeyInfo 失败: {}", e)))?;
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let dao_key = format!("bulwark:apikey:{}:{}", namespace, key);
        self.dao.set(&dao_key, &value, timeout as u64).await?;
        Ok(key)
    }

    /// 校验 API Key（依据 spec protocol-apikey / protocol-apikey-namespace R-002）。
    ///
    /// 校验逻辑（向后兼容）：
    /// 1. 先查旧格式 `bulwark:apikey:<key>`（无 namespace，历史 key）
    /// 2. 未命中再扫描新格式 `bulwark:apikey:*:<key>`（含 namespace）
    /// 3. 找到后检查 `revoked == false` 且 `expire_at > now`
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: key 不存在或已吊销。
    /// - `BulwarkError::ExpiredToken`: key 已过期。
    pub async fn verify(&self, key: &str) -> BulwarkResult<ApiKeyInfo> {
        // 1. 先查旧格式（无 namespace）
        let old_dao_key = format!("bulwark:apikey:{}", key);
        if let Some(value) = self.dao.get(&old_dao_key).await? {
            return self.decode_and_check(&value).await;
        }
        // 2. 扫描新格式 bulwark:apikey:*:<key>
        let pattern = format!("bulwark:apikey:*:{}", key);
        let matched = self.dao.keys(&pattern).await?;
        for dao_key in matched {
            if let Some(value) = self.dao.get(&dao_key).await? {
                return self.decode_and_check(&value).await;
            }
        }
        Err(BulwarkError::InvalidToken("API Key 不存在".to_string()))
    }

    /// 校验指定 namespace 下的 API Key（依据 spec protocol-apikey-namespace R-004）。
    ///
    /// 严格匹配 `bulwark:apikey:<namespace>:<key>`，不兼容旧格式，不跨 namespace。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: namespace 非法。
    /// - `BulwarkError::InvalidToken`: key 不存在或已吊销。
    /// - `BulwarkError::ExpiredToken`: key 已过期。
    pub async fn verify_with_namespace(
        &self,
        key: &str,
        namespace: &str,
    ) -> BulwarkResult<ApiKeyInfo> {
        validate_namespace(namespace)?;
        let dao_key = format!("bulwark:apikey:{}:{}", namespace, key);
        let value = self.dao.get(&dao_key).await?;
        let value =
            value.ok_or_else(|| BulwarkError::InvalidToken("API Key 不存在".to_string()))?;
        let info = self.decode_and_check(&value).await?;
        // 二次校验：JSON 中 namespace 必须与请求 namespace 一致（防止存储错位）
        if info.namespace != namespace {
            return Err(BulwarkError::InvalidToken(format!(
                "API Key namespace 不匹配：期望 {}，实际 {}",
                namespace, info.namespace
            )));
        }
        Ok(info)
    }

    /// 解码 ApiKeyInfo 并校验 revoked / expire（verify 内部复用）。
    async fn decode_and_check(&self, value: &str) -> BulwarkResult<ApiKeyInfo> {
        let info: ApiKeyInfo = serde_json::from_str(value)
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

    /// 吊销 API Key（依据 spec protocol-apikey / protocol-apikey-namespace R-002）。
    ///
    /// 向后兼容：先查旧格式 `bulwark:apikey:<key>`，未命中再扫描新格式。
    /// 找到后将 `revoked` 设为 `true` 并写回 dao（保留 TTL）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: key 不存在。
    pub async fn revoke(&self, key: &str) -> BulwarkResult<()> {
        // 1. 先查旧格式
        let old_dao_key = format!("bulwark:apikey:{}", key);
        if self.dao.get(&old_dao_key).await?.is_some() {
            return self.revoke_at(&old_dao_key).await;
        }
        // 2. 扫描新格式
        let pattern = format!("bulwark:apikey:*:{}", key);
        let matched = self.dao.keys(&pattern).await?;
        if let Some(dao_key) = matched.into_iter().next() {
            return self.revoke_at(&dao_key).await;
        }
        Err(BulwarkError::InvalidToken("API Key 不存在".to_string()))
    }

    /// 内部：根据 dao_key 吊销（写回 revoked=true，保留 TTL）。
    async fn revoke_at(&self, dao_key: &str) -> BulwarkResult<()> {
        let value = self.dao.get(dao_key).await?;
        let value =
            value.ok_or_else(|| BulwarkError::InvalidToken("API Key 不存在".to_string()))?;
        let mut info: ApiKeyInfo = serde_json::from_str(&value)
            .map_err(|e| BulwarkError::Internal(format!("反序列化 ApiKeyInfo 失败: {}", e)))?;
        info.revoked = true;
        let new_value = serde_json::to_string(&info)
            .map_err(|e| BulwarkError::Internal(format!("序列化 ApiKeyInfo 失败: {}", e)))?;
        // 使用 update 保留 TTL
        self.dao.update(dao_key, &new_value).await
    }

    /// 列出指定 namespace 下所有未吊销的 ApiKeyInfo（依据 spec protocol-apikey-namespace R-003）。
    ///
    /// 通过 `BulwarkDao::keys("bulwark:apikey:<namespace>:*")` 扫描所有 key，
    /// 反序列化 value 为 `ApiKeyInfo`，过滤已吊销的。
    ///
    /// # 性能警告
    /// 依赖 `BulwarkDao::keys`，大规模 key 场景下性能差（全量扫描 + 过滤）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: namespace 非法。
    /// - `BulwarkError::Internal`: 反序列化失败。
    pub async fn list_by_namespace(&self, namespace: &str) -> BulwarkResult<Vec<ApiKeyInfo>> {
        validate_namespace(namespace)?;
        let pattern = format!("bulwark:apikey:{}:*", namespace);
        let dao_keys = self.dao.keys(&pattern).await?;
        let mut result = Vec::with_capacity(dao_keys.len());
        for dao_key in dao_keys {
            let value = self.dao.get(&dao_key).await?;
            if let Some(v) = value {
                let info: ApiKeyInfo = serde_json::from_str(&v).map_err(|e| {
                    BulwarkError::Internal(format!("反序列化 ApiKeyInfo 失败: {}", e))
                })?;
                if !info.revoked {
                    result.push(info);
                }
            }
        }
        Ok(result)
    }

    /// 轮换 API Key（依据 spec protocol-apikey）。
    ///
    /// 轮换逻辑：(1) 读取 old_key 的 `ApiKeyInfo`；(2) 校验有效（未吊销、未过期）；
    /// (3) 吊销 old_key；(4) 生成新 key（保留 login_id/scopes/剩余 TTL）；(5) 返回新 key。
    ///
    /// v0.4.2 扩展：成功时若注入了 `listener_manager`，广播 `BulwarkEvent::ApiKeyRotate`
    ///（依据 spec listener-events-extend R-001）。
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
        let new_key = self
            .generate(info.login_id, info.scopes, remaining_ttl)
            .await?;
        // v0.4.2: 广播 ApiKeyRotate 事件（依据 spec listener-events-extend R-001）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::ApiKeyRotate {
                old_key: old_key.to_string(),
                new_key: new_key.clone(),
            })
            .await;
        }
        Ok(new_key)
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

        /// v0.4.2: keys 复用 dao::tests::glob_match（避免重复实现 glob 逻辑）。
        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            let data = self.data.lock().await;
            let mut result = Vec::new();
            for key in data.keys() {
                if crate::dao::tests::glob_match(pattern, key) {
                    result.push(key.clone());
                }
            }
            Ok(result)
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
    ///
    /// v0.4.2: generate 默认 namespace="default"，存储格式变为
    /// `bulwark:apikey:default:<key>`（依据 spec protocol-apikey-namespace R-002）。
    #[tokio::test]
    async fn generate_uses_correct_key_prefix() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        let key = handler
            .generate(1001, vec!["read".into()], 3600)
            .await
            .unwrap();
        let dao_key = format!("bulwark:apikey:default:{}", key);
        let value = dao.get(&dao_key).await.unwrap();
        assert!(value.is_some());
        let info: ApiKeyInfo = serde_json::from_str(&value.unwrap()).unwrap();
        assert_eq!(info.login_id, 1001);
        assert_eq!(info.scopes, vec!["read".to_string()]);
        assert!(!info.revoked);
        assert_eq!(info.namespace, "default");
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

    // ========================================================================
    // MockDao 方法覆盖测试
    // ========================================================================

    /// 验证 MockDao::expire 和 delete 方法可正常调用。
    ///
    /// 覆盖 MockDao 的 expire 和 delete trait 方法（此前测试未直接调用）。
    #[tokio::test]
    async fn mock_dao_expire_and_delete_covered() {
        let dao = MockDao::new();
        dao.set("k", "v", 3600).await.unwrap();

        // expire 正常键
        dao.expire("k", 7200).await.unwrap();
        let got = dao.get("k").await.unwrap();
        assert_eq!(got, Some("v".to_string()));

        // delete 正常键
        dao.delete("k").await.unwrap();
        let got = dao.get("k").await.unwrap();
        assert!(got.is_none());
    }

    /// 验证 generate 拒绝负数 timeout。
    #[tokio::test]
    async fn generate_negative_timeout_returns_error() {
        let handler = make_handler();
        let result = handler.generate(1001, vec![], -1).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BulwarkError::InvalidParam(_)));
    }

    /// 验证 revoke 后 rotate 返回错误（old_key 已吊销）。
    #[tokio::test]
    async fn rotate_revoked_key_returns_error() {
        let handler = make_handler();
        let key = handler
            .generate(1001, vec!["read".into()], 3600)
            .await
            .unwrap();
        // 先吊销
        handler.revoke(&key).await.unwrap();
        // 再 rotate 应失败（verify 会因 revoked 返回 InvalidToken）
        let result = handler.rotate(&key).await;
        assert!(result.is_err());
    }

    // ========================================================================
    // 0.4.2 新增: LoginId newtype 接入（impl Into<LoginId>）
    // ========================================================================

    use crate::stp::login_id::LoginId;

    /// 验证 `ApiKeyHandler::generate` 接受 `LoginId::Numeric`（i64 兼容路径）。
    #[tokio::test]
    async fn generate_accepts_login_id_numeric() {
        let handler = make_handler();
        let key = handler
            .generate(LoginId::Numeric(1001), vec!["read".into()], 3600)
            .await
            .unwrap();
        let info = handler.verify(&key).await.unwrap();
        assert_eq!(info.login_id, 1001);
    }

    /// 验证 `ApiKeyHandler::generate` 对 `LoginId::String` 返回 `BulwarkError::Config`。
    #[tokio::test]
    async fn generate_rejects_login_id_string_with_config_error() {
        let handler = make_handler();
        let result = handler
            .generate(LoginId::String("user-uuid".to_string()), vec![], 3600)
            .await;
        assert!(
            matches!(result, Err(BulwarkError::Config(_))),
            "String-form login_id 在 v0.4.2 应返回 Config 错误，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // 0.4.2 Phase 8: API Key Namespace（依据 spec protocol-apikey-namespace）
    // ========================================================================

    /// R-001: ApiKeyInfo 序列化包含 namespace 字段（依据 spec protocol-apikey-namespace R-001）。
    #[test]
    fn apikey_info_serializes_with_namespace() {
        let info = ApiKeyInfo {
            login_id: 1,
            scopes: vec![],
            expire_at: 0,
            revoked: false,
            namespace: "internal".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"namespace\""), "JSON 应包含 namespace 字段");
        assert!(json.contains("\"internal\""), "namespace 值应为 internal");
    }

    /// R-001: 旧 JSON（无 namespace 字段）反序列化时 namespace = "default"
    /// （依据 spec protocol-apikey-namespace R-001 向后兼容）。
    #[test]
    fn apikey_info_old_json_deserializes_with_default_namespace() {
        // 旧格式 JSON：无 namespace 字段（v0.4.1 及之前生成的 key）
        let old_json = r#"{"login_id":1,"scopes":[],"expire_at":0,"revoked":false}"#;
        let info: ApiKeyInfo = serde_json::from_str(old_json).unwrap();
        assert_eq!(
            info.namespace, "default",
            "旧 JSON 应反序列化为 namespace=default"
        );
        assert_eq!(info.login_id, 1);
    }

    /// R-002: generate_with_namespace 用新格式 `bulwark:apikey:<namespace>:<key>` 存储
    /// （依据 spec protocol-apikey-namespace R-002）。
    #[tokio::test]
    #[serial_test::serial]
    async fn generate_with_namespace_stores_new_format_key() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        let key = handler
            .generate_with_namespace(1001, "internal", vec!["read".into()], 3600)
            .await
            .unwrap();
        // 新格式：bulwark:apikey:internal:<key>
        let dao_key = format!("bulwark:apikey:internal:{}", key);
        let value = dao.get(&dao_key).await.unwrap();
        assert!(value.is_some(), "新格式 key 应存在: {}", dao_key);
        let info: ApiKeyInfo = serde_json::from_str(&value.unwrap()).unwrap();
        assert_eq!(info.namespace, "internal");
        assert_eq!(info.login_id, 1001);
        // 旧格式不应存在
        let old_key = format!("bulwark:apikey:{}", key);
        let old_value = dao.get(&old_key).await.unwrap();
        assert!(old_value.is_none(), "旧格式 key 不应存在");
    }

    /// R-002: verify 兼容旧格式 key（无 namespace，依据 spec protocol-apikey-namespace R-002）。
    ///
    /// 手动写入旧格式 `bulwark:apikey:<key>`，verify 应能查到。
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_compatible_with_old_key_format() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        // 模拟旧格式 key（v0.4.1 及之前生成的）
        let old_key = "deadbeef".repeat(8); // 64 hex chars
        let old_dao_key = format!("bulwark:apikey:{}", old_key);
        let info = ApiKeyInfo {
            login_id: 2002,
            scopes: vec!["legacy".into()],
            expire_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 3600,
            revoked: false,
            namespace: "default".to_string(),
        };
        let value = serde_json::to_string(&info).unwrap();
        dao.set(&old_dao_key, &value, 3600).await.unwrap();
        // verify 应能找到（先查旧格式命中）
        let verified = handler.verify(&old_key).await.unwrap();
        assert_eq!(verified.login_id, 2002);
        assert_eq!(verified.scopes, vec!["legacy".to_string()]);
    }

    /// R-003: list_by_namespace 返回指定 namespace 下未吊销的 ApiKeyInfo
    /// （依据 spec protocol-apikey-namespace R-003）。
    #[tokio::test]
    #[serial_test::serial]
    async fn list_by_namespace_returns_only_matching_namespace() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        // internal namespace 下生成 1 个 key
        let _k1 = handler
            .generate_with_namespace(1001, "internal", vec!["read".into()], 3600)
            .await
            .unwrap();
        // partner namespace 下生成 1 个 key
        let _k2 = handler
            .generate_with_namespace(2002, "partner", vec!["write".into()], 3600)
            .await
            .unwrap();
        // 列出 internal namespace
        let internal_keys = handler.list_by_namespace("internal").await.unwrap();
        assert_eq!(internal_keys.len(), 1, "internal namespace 应有 1 个 key");
        assert_eq!(internal_keys[0].login_id, 1001);
        assert_eq!(internal_keys[0].namespace, "internal");
        // 列出 partner namespace
        let partner_keys = handler.list_by_namespace("partner").await.unwrap();
        assert_eq!(partner_keys.len(), 1, "partner namespace 应有 1 个 key");
        assert_eq!(partner_keys[0].login_id, 2002);
        // 不存在的 namespace 返回空
        let empty = handler.list_by_namespace("nonexistent").await.unwrap();
        assert!(empty.is_empty(), "不存在的 namespace 应返回空 Vec");
    }

    /// R-003: list_by_namespace 过滤已吊销的 key
    /// （依据 spec protocol-apikey-namespace R-003 验收标准"未吊销的"）。
    #[tokio::test]
    #[serial_test::serial]
    async fn list_by_namespace_filters_revoked_keys() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        let k1 = handler
            .generate_with_namespace(1001, "internal", vec![], 3600)
            .await
            .unwrap();
        let _k2 = handler
            .generate_with_namespace(1002, "internal", vec![], 3600)
            .await
            .unwrap();
        // 吊销 k1
        handler.revoke(&k1).await.unwrap();
        let keys = handler.list_by_namespace("internal").await.unwrap();
        assert_eq!(keys.len(), 1, "吊销后应只剩 1 个未吊销 key");
        assert_eq!(keys[0].login_id, 1002);
    }

    /// R-004: namespace 隔离——verify_with_namespace 严格匹配 namespace
    /// （依据 spec protocol-apikey-namespace R-004）。
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_with_namespace_enforces_isolation() {
        let dao = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone());
        // 在 internal namespace 生成 key
        let key = handler
            .generate_with_namespace(1001, "internal", vec!["read".into()], 3600)
            .await
            .unwrap();
        // 用正确 namespace 校验应成功
        let info = handler
            .verify_with_namespace(&key, "internal")
            .await
            .unwrap();
        assert_eq!(info.login_id, 1001);
        assert_eq!(info.namespace, "internal");
        // 用错误 namespace 校验应失败（key 不存在该 namespace 下）
        let wrong = handler.verify_with_namespace(&key, "partner").await;
        assert!(
            matches!(wrong, Err(BulwarkError::InvalidToken(_))),
            "跨 namespace 校验应返回 InvalidToken，实际: {:?}",
            wrong
        );
    }

    /// R-004: 普通 verify（不带 namespace）能找到任意 namespace 下的 key
    /// （依据 spec protocol-apikey-namespace R-004 "或扫描所有 namespace"）。
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_without_namespace_scans_all_namespaces() {
        let handler = make_handler();
        let key = handler
            .generate_with_namespace(1001, "internal", vec!["read".into()], 3600)
            .await
            .unwrap();
        // 不带 namespace 的 verify 通过扫描新格式找到
        let info = handler.verify(&key).await.unwrap();
        assert_eq!(info.login_id, 1001);
        assert_eq!(info.namespace, "internal");
    }

    /// Constraints: namespace 验证——空字符串、过长、非法字符都应返回 InvalidParam
    /// （依据 spec protocol-apikey-namespace Constraints）。
    #[tokio::test]
    async fn generate_with_namespace_validates_namespace() {
        let handler = make_handler();
        // 空字符串
        let r = handler.generate_with_namespace(1, "", vec![], 3600).await;
        assert!(
            matches!(r, Err(BulwarkError::InvalidParam(_))),
            "空 namespace 应报错"
        );
        // 过长（65 字符）
        let long_ns = "a".repeat(65);
        let r = handler
            .generate_with_namespace(1, &long_ns, vec![], 3600)
            .await;
        assert!(
            matches!(r, Err(BulwarkError::InvalidParam(_))),
            "65 字符 namespace 应报错"
        );
        // 非法字符（含空格）
        let r = handler
            .generate_with_namespace(1, "has space", vec![], 3600)
            .await;
        assert!(
            matches!(r, Err(BulwarkError::InvalidParam(_))),
            "含空格 namespace 应报错"
        );
        // 合法字符边界：64 字符、含 _ -
        let r = handler
            .generate_with_namespace(1, &"a".repeat(64), vec![], 3600)
            .await;
        assert!(r.is_ok(), "64 字符 namespace 应通过");
        let r = handler
            .generate_with_namespace(1, "ns_name-1", vec![], 3600)
            .await;
        assert!(r.is_ok(), "含 _ - 数字 的 namespace 应通过");
    }
}
