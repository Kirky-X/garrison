//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `ApiKeyHandler` 实现。
//!
//! 包含 API Key 生成/校验/吊销/轮换逻辑，以及辅助函数
//! `default_namespace`、`validate_namespace`。
//!
//! 仅在启用 `protocol-apikey` 特性时编译。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::{ApiKeyHandler, ApiKeyInfo};

/// `ApiKeyInfo::namespace` 的默认值：`"default"`。
///
/// 旧 JSON 数据不含 `namespace` 字段时，serde 用此函数填充默认值，保证向后兼容。
pub(crate) fn default_namespace() -> String {
    "default".to_string()
}

/// 校验 namespace 合法性。
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

impl ApiKeyHandler {
    /// 创建新的 API Key 处理器。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self {
            dao,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 `BulwarkListenerManager`，启用 TokenRotate 事件广播
    ///
    ///
    /// 注入后 `rotate` 成功时广播 `BulwarkEvent::TokenRotate`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<BulwarkListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 生成 API Key。
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
        login_id: impl Into<String>,
        scopes: Vec<String>,
        timeout: i64,
    ) -> BulwarkResult<String> {
        self.generate_with_namespace(login_id, &default_namespace(), scopes, timeout)
            .await
    }

    /// 生成带 namespace 的 API Key。
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
    pub async fn generate_with_namespace(
        &self,
        login_id: impl Into<String>,
        namespace: &str,
        scopes: Vec<String>,
        timeout: i64,
    ) -> BulwarkResult<String> {
        let login_id: String = login_id.into();
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

    /// 校验 API Key。
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

    /// 校验指定 namespace 下的 API Key。
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

    /// 吊销 API Key。
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

    /// 列出指定 namespace 下所有未吊销的 ApiKeyInfo。
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

    /// 轮换 API Key。
    ///
    /// 轮换逻辑：(1) 读取 old_key 的 `ApiKeyInfo`；(2) 校验有效（未吊销、未过期）；
    /// (3) 吊销 old_key；(4) 生成新 key（保留 login_id/scopes/剩余 TTL）；(5) 返回新 key。
    ///
    /// v0.4.2 扩展：成功时若注入了 `listener_manager`，广播 `BulwarkEvent::TokenRotate`
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
        // 广播 TokenRotate 事件
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::TokenRotate {
                old_key: old_key.to_string(),
                new_key: new_key.clone(),
                request_context: None,
            })
            .await;
        }
        Ok(new_key)
    }
}
