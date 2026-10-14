// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

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

/// `last_used_at` 节流写入阈值（秒）。
///
/// `verify` 成功后仅当距上次记录超过该阈值才写回，避免每请求写放大。
const LAST_USED_UPDATE_THROTTLE_SECS: i64 = 60;

/// `ApiKeyInfo::namespace` 的默认值：`"default"`。
///
/// `generate` 不指定 namespace 时使用该值。
pub(crate) fn default_namespace() -> String {
    "default".to_string()
}

/// 计算 `sha256(input)` 的 hex 编码（64 字符小写）：`key_secret` 哈希后存储
/// （CWE-916），明文 secret 永不落库。
fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        // write! 写入预分配 buffer，替代 format! 每字节一次 String 分配
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

/// 构造 API Key 反向索引的存储 key：`garrison:apikey:idx:<key_id>` → dao_key
/// （`garrison:apikey:<namespace>:<key_id>`），使 `verify` / `revoke` 以 O(1) 查询
/// 替代 `keys("garrison:apikey:*:<key_id>")` 全表扫描。索引使用公开的 `key_id`
/// （32 字符随机 hex，非机密），本身不泄露 secret。
pub(crate) fn idx_key_for(key_id: &str) -> String {
    format!("garrison:apikey:idx:{}", key_id)
}

/// 提取 API Key 的可安全记录公开引用（事件广播 / 审计日志用）。CWE-916「key_secret
/// 永不落库」要求任何持久化路径都不得写入明文 secret：双段格式只返回 `key_id`；
/// 不含 `.` 的异常输入截断为前 8 hex 字符 + `…`（不足以暴力还原完整凭证）。
///
/// 仅 `listener` 启用时编译（唯一调用方是 rotate 的 TokenRotate 事件广播）。
#[cfg(feature = "listener")]
pub(crate) fn public_key_ref(key: &str) -> String {
    match key.split_once('.') {
        Some((key_id, _)) => key_id.to_string(),
        None => {
            let prefix: String = key.chars().take(8).collect();
            format!("{}\u{2026}", prefix)
        },
    }
}

/// 校验 namespace 合法性：长度 1-64、仅 `[a-zA-Z0-9_-]`；非法返回 `InvalidParam`。
fn validate_namespace(namespace: &str) -> GarrisonResult<()> {
    if namespace.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "apikey-namespace-empty::".to_string(),
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
    // "idx" 与反向索引键空间 `garrison:apikey:idx:<key_id>` 碰撞：
    // 若允许 namespace="idx"，其数据键 `garrison:apikey:idx:<key_id>` 会与索引键重叠，
    // generate 时第二次 set 覆盖第一次写入，导致该 namespace 下 key 全部失效（功能性 DoS）。
    if namespace == "idx" {
        return Err(GarrisonError::InvalidParam(
            "apikey-namespace-reserved::idx".to_string(),
        ));
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
            allowed_scopes: None,
            track_last_used: false,
            max_age_secs: None,
            allow_global_verify: false,
        }
    }

    /// 显式放开无命名空间的 `verify()` 全局校验（默认禁用）。
    ///
    /// `verify()` 经反向索引可跨 namespace 校验任意 key；默认禁用强制业务方
    /// 走 `verify_with_namespace`（租户隔离）。开启时输出 warn 供审计留存。
    pub fn with_allow_global_verify(mut self, allow: bool) -> Self {
        if allow {
            tracing::warn!(
                "{}",
                crate::i18n::translate_detail("logs-apikey-global-verify-enabled", &[])
            );
        }
        self.allow_global_verify = allow;
        self
    }

    /// 注入 `GarrisonListenerManager`：`rotate` 成功时广播 `GarrisonEvent::TokenRotate`
    /// （未注入时不广播；需启用 `listener` feature）。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 设置作用域允许列表（opt-in）：设置后 `generate*` 拒绝列表外 scope
    /// （`InvalidParam`，防拼写错误/越权）；未设置允许任意 scope。可用
    /// [`super::ApiKeyScope`] 构建规范列表。
    pub fn with_allowed_scopes(mut self, allowed: Vec<String>) -> Self {
        self.allowed_scopes = Some(allowed);
        self
    }

    /// 启用 `last_used_at` 追踪（opt-in）：verify 成功时节流更新（距上次记录超过
    /// `LAST_USED_UPDATE_THROTTLE_SECS` 秒才写回，避免写放大）；默认关闭保持
    /// `verify` 只读语义。
    pub fn with_last_used_tracking(mut self, enabled: bool) -> Self {
        self.track_last_used = enabled;
        self
    }

    /// 设置 API Key 最大生命周期（秒）：设置后 `verify` 检查
    /// `created_at + secs >= now`，超期返回 `TokenExpired`；未设置仅依赖 `expire_at`。
    pub fn with_max_age(mut self, secs: i64) -> Self {
        self.max_age_secs = Some(secs);
        self
    }

    /// 生成 API Key：返回 `key_id.key_secret` 双段格式（各 32 hex，`.` 分隔），
    /// `key_secret` 不落库（仅存 sha256）；存于 `garrison:apikey:default:<key_id>`，
    /// TTL = `timeout` 秒。`timeout <= 0` 返回 `InvalidParam`。
    pub async fn generate(
        &self,
        login_id: impl Into<String>,
        scopes: Vec<String>,
        timeout: i64,
    ) -> GarrisonResult<String> {
        self.generate_internal(login_id, &default_namespace(), scopes, timeout, None, None)
            .await
    }

    /// 生成带 namespace 的 API Key：存 `garrison:apikey:<namespace>:<key_id>`（JSON
    /// `ApiKeyInfo`，TTL = `timeout` 秒），并同步写反向索引（TTL 与主 key 一致）使
    /// `verify` / `revoke` 以 O(1) 查询。`timeout <= 0`、namespace 非法或 scope 不在
    /// 允许列表返回 `InvalidParam`。
    pub async fn generate_with_namespace(
        &self,
        login_id: impl Into<String>,
        namespace: &str,
        scopes: Vec<String>,
        timeout: i64,
    ) -> GarrisonResult<String> {
        self.generate_internal(login_id, namespace, scopes, timeout, None, None)
            .await
    }

    /// 生成带完整选项的 API Key（显式 `owner_id` + 每 key `rate_limit`）：用于把
    /// key 归属到 `login_id` 以外主体，或设置每 key 速率上限。
    pub async fn generate_with_options(
        &self,
        login_id: impl Into<String>,
        namespace: &str,
        scopes: Vec<String>,
        timeout: i64,
        owner_id: Option<String>,
        rate_limit: Option<u32>,
    ) -> GarrisonResult<String> {
        self.generate_internal(login_id, namespace, scopes, timeout, owner_id, rate_limit)
            .await
    }

    /// 内部：统一生成逻辑（哈希存储 + 双段格式 + 反向索引）。
    async fn generate_internal(
        &self,
        login_id: impl Into<String>,
        namespace: &str,
        scopes: Vec<String>,
        timeout: i64,
        owner_id: Option<String>,
        rate_limit: Option<u32>,
    ) -> GarrisonResult<String> {
        let login_id: String = login_id.into();
        if timeout <= 0 {
            return Err(GarrisonError::InvalidParam(
                "apikey-timeout-positive::".to_string(),
            ));
        }
        validate_namespace(namespace)?;
        // opt-in scope 校验
        if let Some(allowed) = &self.allowed_scopes {
            for scope in &scopes {
                if !allowed.iter().any(|a| a == scope) {
                    return Err(GarrisonError::InvalidParam(format!(
                        "apikey-scope-not-allowed::{}",
                        scope
                    )));
                }
            }
        }
        let now = current_ts()?;
        // key_id（公开）+ key_secret（机密），各 32 hex
        let key_id = Uuid::new_v4().simple().to_string();
        let key_secret = Uuid::new_v4().simple().to_string();
        let info = ApiKeyInfo {
            login_id: login_id.clone(),
            scopes,
            expire_at: now + timeout,
            revoked: false,
            namespace: namespace.to_string(),
            key_id: key_id.clone(),
            // CWE-916：只存 secret 的哈希，明文 secret 永不落库
            secret_hash: sha256_hex(&key_secret),
            owner_id: owner_id.or(Some(login_id)),
            last_used_at: None,
            rate_limit,
            created_at: now,
        };
        let value = serde_json::to_string(&info)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        let dao_key = format!("garrison:apikey:{}:{}", namespace, key_id);
        // set_if_absent 原子创建：key_id 为 32 位随机 hex，碰撞即显式报错，
        // 不允许覆盖既有 key（GarrisonDao 无 mset，主 key/索引双写无法单事务）
        if !self
            .dao
            .set_if_absent(&dao_key, &value, timeout as u64)
            .await?
        {
            return Err(GarrisonError::Dao(format!(
                "apikey-generate-key-collision::{}",
                dao_key
            )));
        }
        // 反向索引（TTL 与主 key 一致），O(1) verify/revoke。
        // 补偿：索引写失败时回删主 key——否则留下 verify（走索引）找不到、
        // 而 verify_with_namespace（直查）仍能命中的孤儿 key，两条校验路径行为不一致。
        let idx_key = idx_key_for(&key_id);
        if let Err(e) = self
            .dao
            .set_if_absent(&idx_key, &dao_key, timeout as u64)
            .await
        {
            if let Err(del_err) = self.dao.delete(&dao_key).await {
                tracing::warn!(dao_key = %dao_key, error = %del_err, "apikey generate compensation delete failed (orphan key may remain)");
            }
            return Err(e);
        }
        // 对外返回双段 token；key_secret 仅此一次可见
        Ok(format!("{}.{}", key_id, key_secret))
    }

    /// 校验 API Key：`key_id.key_secret` → 查反向索引得 dao_key → 常量时间比较
    /// `sha256(key_secret)` 与 `secret_hash`（O(1)）；不含 `.` 的输入直接 `InvalidToken`。
    /// key 不存在/不匹配/已吊销返回 `InvalidToken`，过期返回 `ExpiredToken`。
    ///
    /// **不校验** `ApiKeyInfo::owner_id` 与调用方主体的关系（框架不持有主体上下文）
    /// ——归属（IDOR）校验属应用层契约：调用方应自行比较 `owner_id` 与请求主体再授权。
    pub async fn verify(&self, key: &str) -> GarrisonResult<ApiKeyInfo> {
        // fail-closed：无命名空间校验可跨租户命中任意 key，默认禁用。
        // rotate / update_last_used 等管理操作走 verify_internal 不受影响。
        if !self.allow_global_verify {
            return Err(GarrisonError::InvalidParam(
                "apikey-global-verify-disabled::".to_string(),
            ));
        }
        self.verify_internal(key).await
    }

    /// verify 的内部全量校验（不受 allow_global_verify 开关约束）。
    async fn verify_internal(&self, key: &str) -> GarrisonResult<ApiKeyInfo> {
        let (dao_key, value, secret) = self.lookup(key).await?;
        let info = self.decode_and_check(&value, &secret)?;
        self.check_max_age(&info)?;
        self.maybe_touch_last_used(&dao_key, &info).await;
        Ok(info)
    }

    /// 校验指定 namespace 下的 API Key：严格匹配 `garrison:apikey:<namespace>:<key_id>`，
    /// 不跨 namespace（IDOR 防护核心）。namespace 非法返回 `InvalidParam`；key 不存在/
    /// 不匹配/已吊销/namespace 不一致返回 `InvalidToken`；过期返回 `ExpiredToken`。
    pub async fn verify_with_namespace(
        &self,
        key: &str,
        namespace: &str,
    ) -> GarrisonResult<ApiKeyInfo> {
        validate_namespace(namespace)?;
        // 只接受双段格式 key_id.key_secret；单段输入无法定位存储记录
        let (key_id, key_secret) = key
            .split_once('.')
            .ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        let dao_key = format!("garrison:apikey:{}:{}", namespace, key_id);
        let value = self
            .dao
            .get(&dao_key)
            .await?
            .ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        let info = self.decode_and_check(&value, key_secret)?;
        // 二次校验：JSON 中 namespace 必须与请求 namespace 一致（防止存储错位 / 跨 namespace）
        if info.namespace != namespace {
            return Err(GarrisonError::InvalidToken(format!(
                "apikey-namespace-mismatch::{}::{}",
                namespace, info.namespace
            )));
        }
        self.check_max_age(&info)?;
        self.maybe_touch_last_used(&dao_key, &info).await;
        Ok(info)
    }

    /// 内部：反查存储记录，返回 `(dao_key, value, provided_secret)`。仅支持双段格式
    /// `key_id.key_secret`：不含 `.`、索引缺失或记录缺失均返回 `InvalidToken`。
    async fn lookup(&self, key: &str) -> GarrisonResult<(String, String, String)> {
        let (key_id, key_secret) = key
            .split_once('.')
            .ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        let idx_key = idx_key_for(key_id);
        let dao_key = self
            .dao
            .get(&idx_key)
            .await?
            .ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        let value = self
            .dao
            .get(&dao_key)
            .await?
            .ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        Ok((dao_key, value, key_secret.to_string()))
    }

    /// 解码 ApiKeyInfo 并校验 revoked / expire / secret（verify 内部复用）。
    ///
    /// 必须提供 `secret` 且常量时间比较通过（CWE-916：消除"按存在性校验"弱点）。
    fn decode_and_check(&self, value: &str, secret: &str) -> GarrisonResult<ApiKeyInfo> {
        let info: ApiKeyInfo = serde_json::from_str(value)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        if info.revoked {
            return Err(GarrisonError::InvalidToken("apikey-revoked::".to_string()));
        }
        let now = current_ts()?;
        if info.expire_at <= now {
            return Err(GarrisonError::ExpiredToken("apikey-expired::".to_string()));
        }
        // CWE-916：必须校验 secret 哈希（常量时间比较）
        let computed = sha256_hex(secret);
        if !crate::secure::ct_eq::constant_time_eq(computed.as_bytes(), info.secret_hash.as_bytes())
        {
            return Err(GarrisonError::InvalidToken(
                "apikey-secret-mismatch".to_string(),
            ));
        }
        Ok(info)
    }

    /// 检查 API Key 是否超过最大生命周期：仅当 `max_age_secs` 已设置时检查
    /// （`created_at` 为必填字段始终可校验），超期返回 `TokenExpired`。
    fn check_max_age(&self, info: &ApiKeyInfo) -> GarrisonResult<()> {
        if let Some(max_age) = self.max_age_secs {
            let now = current_ts()?;
            if info.created_at + max_age < now {
                return Err(GarrisonError::ExpiredToken(
                    "apikey-max-age-exceeded".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// 节流更新 `last_used_at`（启用追踪且距上次记录超阈值时写回）：写回失败
    /// **不影响校验结果**（availability 优先），但以 `warn` 记录、不静默吞掉。
    ///
    /// lost-revoke 防护：不复用 verify 进入时的旧 `info`（可能已过期于并发
    /// `revoke`），而是 re-read 最新值，发现 `revoked == true` 即放弃写回——防
    /// 整 JSON 覆盖把已吊销状态回退为 false。残留：re-read 与 `update` 间仍有
    /// micro-race 窗口，靠 60s 节流 + revoked 前置检查把概率与影响降到可接受
    /// （`GarrisonDao` trait 无 CAS/字段级更新，此为架构上限）。
    async fn maybe_touch_last_used(&self, dao_key: &str, info: &ApiKeyInfo) {
        if !self.track_last_used {
            return;
        }
        let now = match current_ts() {
            Ok(n) => n,
            Err(_) => return,
        };
        let stale = info
            .last_used_at
            .is_none_or(|t| now - t > LAST_USED_UPDATE_THROTTLE_SECS);
        if !stale {
            return;
        }
        // re-read 最新值，绝不用 verify 进入时的旧 info 覆盖写
        let current = match self.dao.get(dao_key).await {
            Ok(Some(v)) => v,
            Ok(None) => return, // key 已删，放弃更新
            Err(e) => {
                tracing::warn!(dao_key = %dao_key, error = %e, "apikey last_used_at re-read failed (does not affect verification)");
                return;
            },
        };
        let mut updated: ApiKeyInfo = match serde_json::from_str(&current) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(error = %e, "apikey last_used_at deserialization failed (does not affect verification)");
                return;
            },
        };
        if updated.revoked {
            // 已被并发吊销，绝不回退 revoked 状态（lost-revoke 防护核心）
            return;
        }
        updated.last_used_at = Some(now);
        match serde_json::to_string(&updated) {
            Ok(v) => {
                if let Err(e) = self.dao.update(dao_key, &v).await {
                    tracing::warn!(dao_key = %dao_key, error = %e, "apikey last_used_at update failed (does not affect verification)");
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "apikey last_used_at serialization failed (does not affect verification)");
            },
        }
    }

    /// 吊销 API Key：经反向索引定位 dao_key，置 `revoked = true` 写回（保留 TTL）；
    /// key 不存在返回 `InvalidToken`。
    pub async fn revoke(&self, key: &str) -> GarrisonResult<()> {
        let (dao_key, _value, _secret) = self.lookup(key).await?;
        self.revoke_at(&dao_key).await
    }

    /// 内部：根据 dao_key 吊销（写回 revoked=true，保留 TTL）。
    async fn revoke_at(&self, dao_key: &str) -> GarrisonResult<()> {
        let value = self.dao.get(dao_key).await?;
        let value =
            value.ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        let mut info: ApiKeyInfo = serde_json::from_str(&value)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        info.revoked = true;
        let new_value = serde_json::to_string(&info)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        // 使用 update 保留 TTL
        self.dao.update(dao_key, &new_value).await
    }

    /// 列出指定 namespace 下所有未吊销的 ApiKeyInfo（`keys` 全量扫描 + 过滤，管理面
    /// 操作，大规模 key 下性能差）。依赖 `GarrisonDao::keys`：`GarrisonDaoOxcache` 需
    /// `dao-key-index` feature（由 `protocol-apikey` 传递启用），否则返回 `NotImplemented`。
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

    /// 列出指定 namespace 下"陈旧"的未吊销 key（`last_used_at < cutoff_ts` 或从未
    /// 使用），用于识别应轮换/回收的 key。错误同 [`list_by_namespace`](Self::list_by_namespace)。
    pub async fn get_keys_older_than(
        &self,
        namespace: &str,
        cutoff_ts: i64,
    ) -> GarrisonResult<Vec<ApiKeyInfo>> {
        let all = self.list_by_namespace(namespace).await?;
        Ok(all
            .into_iter()
            .filter(|info| info.last_used_at.is_none_or(|t| t < cutoff_ts))
            .collect())
    }

    /// 显式更新 API Key 的 `last_used_at` 为当前时间（保留 TTL），供校验之外的
    /// 场景（如异步审计）主动记录使用时间。
    ///
    /// CWE-916：必须先通过 [`Self::verify`] 的完整校验（secret 常量时间比较 +
    /// revoked/expire fail-closed）才允许写回——仅凭 `key_id` 即可更新会构成越权写。
    /// key 不存在/不匹配/已吊销返回 `InvalidToken`，过期返回 `ExpiredToken`。
    pub async fn update_last_used(&self, key: &str) -> GarrisonResult<()> {
        // CWE-916：走全量校验（含 secret 哈希常量时间比较），不得绕过。
        // 管理操作持有完整 key，不受 allow_global_verify 开关约束。
        let info = self.verify_internal(key).await?;
        // verify 成功 ⇒ 必为双段格式 key，`key_id` 非空，可由 namespace + key_id 重建 dao_key
        let dao_key = format!("garrison:apikey:{}:{}", info.namespace, info.key_id);
        // 写回前 re-read 最新值，避免用 verify 时的旧快照把并发 revoke 回退
        let current = self
            .dao
            .get(&dao_key)
            .await?
            .ok_or_else(|| GarrisonError::InvalidToken("apikey-not-found::".to_string()))?;
        let mut updated: ApiKeyInfo = serde_json::from_str(&current)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        if updated.revoked {
            // 已被并发吊销，绝不回退 revoked 状态（与 maybe_touch_last_used 同防护）
            return Err(GarrisonError::InvalidToken("apikey-revoked::".to_string()));
        }
        updated.last_used_at = Some(current_ts()?);
        let new_value = serde_json::to_string(&updated)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        self.dao.update(&dao_key, &new_value).await
    }

    /// 轮换 API Key：校验 old_key → 生成新 key（保留 login_id/scopes/owner_id/
    /// rate_limit/剩余 TTL）并持久化 → 吊销 old_key → 返回新 key（双段格式）。成功时
    /// 若注入 listener 则广播 `TokenRotate`（需 `listener` feature）。
    ///
    /// 先 generate 后 revoke：generate 失败/任务被取消时原 key 仍完整有效可直接重试，
    /// 消除"revoke 成功后 generate 失败 → 原 key 永久丢失"的不可恢复窗口；代价是吊销
    /// 前存在极短 double-valid 窗口。
    ///
    /// `rotate` 非原子（verify → generate → revoke 跨 await），并发 rotate 同一 old_key
    /// 会各自成功并生成不同新 key；调用方应在入口加分布式锁/互斥（库层不内置锁：低频
    /// 管理操作加全局锁反而引入竞争与死锁面）。old_key 不存在/已吊销返回 `InvalidToken`，
    /// 过期返回 `ExpiredToken`。
    pub async fn rotate(&self, old_key: &str) -> GarrisonResult<String> {
        // (1) 校验 old_key（管理操作，不受 allow_global_verify 开关约束）
        let info = self.verify_internal(old_key).await?;
        let now = current_ts()?;
        let remaining_ttl = info.expire_at - now;
        if remaining_ttl <= 0 {
            return Err(GarrisonError::ExpiredToken(
                "apikey-expired-cannot-rotate::".to_string(),
            ));
        }
        // (2) 先生成并持久化新 key（失败时原 key 仍有效，可安全重试）
        let new_key = self
            .generate_internal(
                info.login_id,
                &info.namespace,
                info.scopes,
                remaining_ttl,
                info.owner_id,
                info.rate_limit,
            )
            .await?;
        // (3) 再吊销原 key
        self.revoke(old_key).await?;
        // 广播 TokenRotate 事件
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            // CWE-916：事件持久化到审计日志，只广播公开 key_id 引用，绝不写入明文 secret。
            lm.broadcast(&GarrisonEvent::TokenRotate {
                old_key: public_key_ref(old_key),
                new_key: public_key_ref(&new_key),
                request_context: None,
            })
            .await;
        }
        Ok(new_key)
    }
}

/// 获取当前 Unix 时间戳（秒）。
fn current_ts() -> GarrisonResult<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| GarrisonError::Internal(format!("apikey-clock::{}", e)))
}

#[cfg(test)]
mod lost_revoke_tests {
    use super::super::mock::MockDao;
    use super::{ApiKeyHandler, ApiKeyInfo};
    use crate::dao::GarrisonDao;
    use crate::error::GarrisonError;
    use std::sync::Arc;

    /// 回归测试：并发 revoke 后，`maybe_touch_last_used` 用旧快照写回时必须 re-read
    /// 发现 `revoked` 并放弃，不得把已吊销状态回退（lost-revoke）。
    ///
    /// 整 JSON 覆盖（旧快照 revoked=false 覆盖并发 revoke 的 revoked=true）会让此
    /// 断言失败——已吊销 key 复活。
    #[tokio::test]
    async fn maybe_touch_does_not_resurrect_revoked_key() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao.clone()).with_last_used_tracking(true);

        let token = handler
            .generate("user1", vec!["read".to_string()], 3600)
            .await
            .unwrap();
        let (key_id, _) = token.split_once('.').unwrap();
        let dao_key = format!("garrison:apikey:default:{}", key_id);
        handler.revoke(&token).await.unwrap(); // DAO 中 revoked=true

        // 旧快照：取当前真实值后强制 revoked=false / last_used_at=None，
        // 模拟 verify 进入时读到的过期视图（last_used_at=None → stale，触发写回路径）
        let mut stale: ApiKeyInfo =
            serde_json::from_str(&dao.get(&dao_key).await.unwrap().unwrap()).unwrap();
        stale.revoked = false;
        stale.last_used_at = None;

        // 用旧快照调 maybe_touch，模拟 verify → revoke → touch 的并发交错
        handler.maybe_touch_last_used(&dao_key, &stale).await;

        let after: ApiKeyInfo =
            serde_json::from_str(&dao.get(&dao_key).await.unwrap().unwrap()).unwrap();
        assert!(
            after.revoked,
            "maybe_touch_last_used 不得复活已吊销的 key（lost-revoke）"
        );
    }

    /// `update_last_used` 对已吊销 key 返回 `InvalidToken`（与 verify 对称）。
    #[tokio::test]
    async fn update_last_used_rejects_revoked_key() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let handler = ApiKeyHandler::new(dao).with_last_used_tracking(true);
        let token = handler.generate("user1", vec![], 3600).await.unwrap();
        handler.revoke(&token).await.unwrap();

        let err = handler.update_last_used(&token).await.unwrap_err();
        assert!(
            matches!(err, GarrisonError::InvalidToken(_)),
            "revoked key 的 update_last_used 应返回 InvalidToken，got: {:?}",
            err
        );
    }
}
