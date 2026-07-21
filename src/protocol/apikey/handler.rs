//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `ApiKeyHandler` 实现。
//!
//! 包含 API Key 生成/校验/吊销/轮换逻辑，以及辅助函数
//! `default_namespace`、`validate_namespace`。
//!
//! 仅在启用 `protocol-apikey` 特性时编译。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
#[cfg(feature = "listener")]
use crate::listener::{GarrisonEvent, GarrisonListenerManager};
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

/// E4: 构造 API Key 反向索引的存储 key。
///
/// 反向索引格式：`garrison:apikey:idx:<key>`，value 为对应的 dao_key
/// （`garrison:apikey:<namespace>:<key>`），使 `verify` / `revoke` 能以 O(1)
/// 查询替代 `keys("garrison:apikey:*:<key>")` 全表扫描。
///
/// # 设计说明
///
/// 任务规格建议使用 `sha256(key)` 作为索引 key 的一部分。本实现直接使用 `key`
/// 本身，因为：
/// 1. `protocol-apikey` feature 不依赖 `sha2` crate（Cargo.toml 受文件边界限制
///    不可修改），添加 sha2 依赖会破坏 feature 隔离
/// 2. API Key 本身已是 64 字符的随机 hex 字符串（两个 UUID v4 simple 拼接），
///    具备固定长度、高熵、URL 安全（仅 `[0-9a-f]`）的特性，功能上等价于
///    `sha256(key)` 的输出
/// 3. 索引 key 长度固定（`garrison:apikey:idx:` + 64 hex = 82 字符），无特殊字符
///
/// # 参数
/// - `key`: API Key（64 字符 hex 字符串）
pub(crate) fn idx_key_for(key: &str) -> String {
    format!("garrison:apikey:idx:{}", key)
}

/// 校验 namespace 合法性。
///
/// 规则：
/// - 长度 1-64 字符
/// - 仅允许 `[a-zA-Z0-9_-]`
///
/// # 错误
/// - `GarrisonError::InvalidParam`: namespace 为空、过长或包含非法字符。
fn validate_namespace(namespace: &str) -> GarrisonResult<()> {
    if namespace.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "apikey-namespace-empty".to_string(),
        ));
    }
    if namespace.len() > 64 {
        return Err(GarrisonError::InvalidParam(format!(
            "apikey-namespace-too-long::{}",
            namespace.len()
        )));
    }
    if !namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(GarrisonError::InvalidParam(format!(
            "apikey-namespace-invalid-chars::{}",
            namespace
        )));
    }
    Ok(())
}

impl ApiKeyHandler {
    /// 创建新的 API Key 处理器。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            dao,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 `GarrisonListenerManager`，启用 TokenRotate 事件广播
    ///
    ///
    /// 注入后 `rotate` 成功时广播 `GarrisonEvent::TokenRotate`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 生成 API Key。
    ///
    /// 生成 64 字符随机 hex 字符串，存储到 `garrison:apikey:<key>`，
    /// value 为 JSON `ApiKeyInfo`，TTL 为 `timeout` 秒。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `scopes`: 作用域列表。
    /// - `timeout`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: timeout <= 0。
    pub async fn generate(
        &self,
        login_id: impl Into<String>,
        scopes: Vec<String>,
        timeout: i64,
    ) -> GarrisonResult<String> {
        self.generate_with_namespace(login_id, &default_namespace(), scopes, timeout)
            .await
    }

    /// 生成带 namespace 的 API Key。
    ///
    /// 生成 64 字符随机 hex 字符串，存储到 `garrison:apikey:<namespace>:<key>`，
    /// value 为 JSON `ApiKeyInfo`（含 `namespace` 字段），TTL 为 `timeout` 秒。
    ///
    /// # E4 修复：同步写入反向索引
    ///
    /// 生成 key 时同步写入反向索引 `garrison:apikey:idx:<key> -> <dao_key>`，
    /// 使 `verify` / `revoke` 能以 O(1) 查询替代 `keys("garrison:apikey:*:<key>")`
    /// 全表扫描，避免攻击者用大量 key 触发 OOM。
    ///
    /// 反向索引的 TTL 与主 key 相同（`timeout` 秒），确保索引随主 key 一起过期，
    /// 不会残留指向已失效 key 的索引条目。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `namespace`: 命名空间（1-64 字符，仅 `[a-zA-Z0-9_-]`）。
    /// - `scopes`: 作用域列表。
    /// - `timeout`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: timeout <= 0 或 namespace 非法。
    pub async fn generate_with_namespace(
        &self,
        login_id: impl Into<String>,
        namespace: &str,
        scopes: Vec<String>,
        timeout: i64,
    ) -> GarrisonResult<String> {
        let login_id: String = login_id.into();
        if timeout <= 0 {
            return Err(GarrisonError::InvalidParam(
                "apikey-timeout-positive".to_string(),
            ));
        }
        validate_namespace(namespace)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| GarrisonError::Internal(format!("apikey-clock::{}", e)))?;
        let info = ApiKeyInfo {
            login_id,
            scopes,
            expire_at: now + timeout,
            revoked: false,
            namespace: namespace.to_string(),
        };
        let value = serde_json::to_string(&info)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let dao_key = format!("garrison:apikey:{}:{}", namespace, key);
        self.dao.set(&dao_key, &value, timeout as u64).await?;
        // E4: 同步写入反向索引（TTL 与主 key 一致），使 verify/revoke 能 O(1) 查询
        let idx_key = idx_key_for(&key);
        self.dao.set(&idx_key, &dao_key, timeout as u64).await?;
        Ok(key)
    }

    /// 校验 API Key。
    ///
    /// 校验逻辑（E4 优化 + 向后兼容）：
    /// 1. **O(1) 反向索引查询**：查 `garrison:apikey:idx:<key>` 获取 dao_key
    /// 2. **回退到旧格式**：查 `garrison:apikey:<key>`（无 namespace，v0.4.1 历史 key）
    /// 3. 找到后检查 `revoked == false` 且 `expire_at > now`
    ///
    /// # E4 修复
    ///
    /// 原实现使用 `keys("garrison:apikey:*:<key>")` 全表扫描，时间复杂度 O(N)
    /// （N 为 DAO 中所有 apikey 条目数）。攻击者可通过大量 generate 调用填满
    /// DAO，使单次 verify 耗时显著上升，最终拖垮服务（DoS）。
    ///
    /// 新实现优先查反向索引（O(1)），仅在索引未命中时回退到旧格式单 key 查询
    /// （也是 O(1)），完全消除 `keys()` 扫描路径。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: key 不存在或已吊销。
    /// - `GarrisonError::ExpiredToken`: key 已过期。
    pub async fn verify(&self, key: &str) -> GarrisonResult<ApiKeyInfo> {
        // 1. E4: O(1) 反向索引查询（新生成的 key 都会写入索引）
        let idx_key = idx_key_for(key);
        if let Some(dao_key) = self.dao.get(&idx_key).await? {
            if let Some(value) = self.dao.get(&dao_key).await? {
                return self.decode_and_check(&value).await;
            }
            // 索引存在但 dao_key 已被删除（极少见，如管理员手动 delete）：
            // 继续走 legacy 回退，避免误判为不存在
        }
        // 2. 回退：旧格式 garrison:apikey:<key>（无 namespace，v0.4.1 历史 key）
        let old_dao_key = format!("garrison:apikey:{}", key);
        if let Some(value) = self.dao.get(&old_dao_key).await? {
            return self.decode_and_check(&value).await;
        }
        Err(GarrisonError::InvalidToken("apikey-not-found".to_string()))
    }

    /// 校验指定 namespace 下的 API Key。
    ///
    /// 严格匹配 `garrison:apikey:<namespace>:<key>`，不兼容旧格式，不跨 namespace。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: namespace 非法。
    /// - `GarrisonError::InvalidToken`: key 不存在或已吊销。
    /// - `GarrisonError::ExpiredToken`: key 已过期。
    pub async fn verify_with_namespace(
        &self,
        key: &str,
        namespace: &str,
    ) -> GarrisonResult<ApiKeyInfo> {
        validate_namespace(namespace)?;
        let dao_key = format!("garrison:apikey:{}:{}", namespace, key);
        let value = self.dao.get(&dao_key).await?;
        let value =
            value.ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found".to_string()))?;
        let info = self.decode_and_check(&value).await?;
        // 二次校验：JSON 中 namespace 必须与请求 namespace 一致（防止存储错位）
        if info.namespace != namespace {
            return Err(GarrisonError::InvalidToken(format!(
                "apikey-namespace-mismatch::{}::{}",
                namespace, info.namespace
            )));
        }
        Ok(info)
    }

    /// 解码 ApiKeyInfo 并校验 revoked / expire（verify 内部复用）。
    async fn decode_and_check(&self, value: &str) -> GarrisonResult<ApiKeyInfo> {
        let info: ApiKeyInfo = serde_json::from_str(value)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        if info.revoked {
            return Err(GarrisonError::InvalidToken("apikey-revoked".to_string()));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| GarrisonError::Internal(format!("apikey-clock::{}", e)))?;
        if info.expire_at <= now {
            return Err(GarrisonError::ExpiredToken("apikey-expired".to_string()));
        }
        Ok(info)
    }

    /// 吊销 API Key。
    ///
    /// 吊销逻辑（E4 优化 + 向后兼容）：
    /// 1. **O(1) 反向索引查询**：查 `garrison:apikey:idx:<key>` 获取 dao_key
    /// 2. **回退到旧格式**：查 `garrison:apikey:<key>`（无 namespace，v0.4.1 历史 key）
    /// 3. 找到后将 `revoked` 设为 `true` 并写回 dao（保留 TTL）
    ///
    /// # E4 修复
    ///
    /// 与 `verify` 同理，原实现使用 `keys("garrison:apikey:*:<key>")` 全表扫描，
    /// 新实现改为 O(1) 反向索引查询 + O(1) 旧格式回退，完全消除 `keys()` 扫描。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: key 不存在。
    pub async fn revoke(&self, key: &str) -> GarrisonResult<()> {
        // 1. E4: O(1) 反向索引查询
        let idx_key = idx_key_for(key);
        if let Some(dao_key) = self.dao.get(&idx_key).await? {
            return self.revoke_at(&dao_key).await;
        }
        // 2. 回退：旧格式 garrison:apikey:<key>（无 namespace，v0.4.1 历史 key）
        let old_dao_key = format!("garrison:apikey:{}", key);
        if self.dao.get(&old_dao_key).await?.is_some() {
            return self.revoke_at(&old_dao_key).await;
        }
        Err(GarrisonError::InvalidToken("apikey-not-found".to_string()))
    }

    /// 内部：根据 dao_key 吊销（写回 revoked=true，保留 TTL）。
    async fn revoke_at(&self, dao_key: &str) -> GarrisonResult<()> {
        let value = self.dao.get(dao_key).await?;
        let value =
            value.ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found".to_string()))?;
        let mut info: ApiKeyInfo = serde_json::from_str(&value)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        info.revoked = true;
        let new_value = serde_json::to_string(&info)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        // 使用 update 保留 TTL
        self.dao.update(dao_key, &new_value).await
    }

    /// 列出指定 namespace 下所有未吊销的 ApiKeyInfo。
    ///
    /// 通过 `GarrisonDao::keys("garrison:apikey:<namespace>:*")` 扫描所有 key，
    /// 反序列化 value 为 `ApiKeyInfo`，过滤已吊销的。
    ///
    /// # 性能警告
    /// 依赖 `GarrisonDao::keys`，大规模 key 场景下性能差（全量扫描 + 过滤）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: namespace 非法。
    /// - `GarrisonError::Internal`: 反序列化失败。
    pub async fn list_by_namespace(&self, namespace: &str) -> GarrisonResult<Vec<ApiKeyInfo>> {
        validate_namespace(namespace)?;
        let pattern = format!("garrison:apikey:{}:*", namespace);
        let dao_keys = self.dao.keys(&pattern).await?;
        let mut result = Vec::with_capacity(dao_keys.len());
        for dao_key in dao_keys {
            let value = self.dao.get(&dao_key).await?;
            if let Some(v) = value {
                let info: ApiKeyInfo = serde_json::from_str(&v)
                    .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
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
    /// v0.4.2 扩展：成功时若注入了 `listener_manager`，广播 `GarrisonEvent::TokenRotate`
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: old_key 不存在或已吊销。
    /// - `GarrisonError::ExpiredToken`: old_key 已过期。
    pub async fn rotate(&self, old_key: &str) -> GarrisonResult<String> {
        // (1)(2) 校验 old_key
        let info = self.verify(old_key).await?;
        // (3) 吊销 old_key
        self.revoke(old_key).await?;
        // (4) 生成新 key（保留 login_id/scopes/剩余 TTL）
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| GarrisonError::Internal(format!("apikey-clock::{}", e)))?;
        let remaining_ttl = info.expire_at - now;
        if remaining_ttl <= 0 {
            return Err(GarrisonError::ExpiredToken(
                "apikey-expired-cannot-rotate".to_string(),
            ));
        }
        let new_key = self
            .generate(info.login_id, info.scopes, remaining_ttl)
            .await?;
        // 广播 TokenRotate 事件
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&GarrisonEvent::TokenRotate {
                old_key: old_key.to_string(),
                new_key: new_key.clone(),
                request_context: None,
            })
            .await;
        }
        Ok(new_key)
    }
}
