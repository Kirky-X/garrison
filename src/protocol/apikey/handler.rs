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

/// `last_used_at` 节流写入阈值（秒）。
///
/// `verify` 成功后仅当距上次记录超过该阈值才写回，避免每请求写放大。
const LAST_USED_UPDATE_THROTTLE_SECS: i64 = 60;

/// `ApiKeyInfo::namespace` 的默认值：`"default"`。
///
/// 旧 JSON 数据不含 `namespace` 字段时，serde 用此函数填充默认值，保证向后兼容。
pub(crate) fn default_namespace() -> String {
    "default".to_string()
}

/// 计算 `sha256(input)` 的 hex 编码（64 字符小写）。
///
/// 用于将 `key_secret` 哈希后存储（CWE-916 修复）：明文 secret 永不落库。
fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        // LOW-3：write! 写入预分配 buffer，替代 format! 每字节一次 String 分配
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

/// E4: 构造 API Key 反向索引的存储 key。
///
/// 反向索引格式：`garrison:apikey:idx:<key_id>`，value 为对应的 dao_key
/// （`garrison:apikey:<namespace>:<key_id>`），使 `verify` / `revoke` 能以 O(1)
/// 查询替代 `keys("garrison:apikey:*:<key_id>")` 全表扫描。
///
/// # 设计说明
///
/// 索引 key 使用**公开的 `key_id`**（非机密的 `key_secret`），因此索引本身不泄露 secret。
/// `key_id` 为 32 字符随机 hex（UUID v4 simple），固定长度、高熵、URL 安全（仅 `[0-9a-f]`）。
///
/// # 参数
/// - `key_id`: API Key 的公开标识（32 字符 hex 字符串）；
///   兼容路径下也可传入旧格式的完整单 token（64 hex）。
pub(crate) fn idx_key_for(key_id: &str) -> String {
    format!("garrison:apikey:idx:{}", key_id)
}

/// 提取 API Key 的**可安全记录**公开引用（用于事件广播 / 审计日志）。
///
/// CWE-916 不变量「key_secret 永不落库」要求任何持久化路径（含审计日志）
/// 都不得写入明文 secret：
/// - 双段格式 `key_id.key_secret`：仅返回 `key_id`（公开标识，永不含 secret）；
/// - 旧格式单 token（无 `.`，token 本身即凭证）：截断为前 8 hex 字符 + `…`，
///   避免将完整凭证写入审计层（8/64 hex ≈ 32 bit，不足以暴力还原剩余 224 bit）。
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

    /// 设置作用域允许列表（opt-in，#6）。
    ///
    /// 设置后，`generate*` 会拒绝不在列表中的 scope（返回 `InvalidParam`），
    /// 防止拼写错误或越权 scope 写入。未设置时不校验（向后兼容）。
    ///
    /// 可用 [`super::ApiKeyScope`] 构建规范列表，如
    /// `vec![ApiKeyScope::Read.as_str().into(), ApiKeyScope::Write.as_str().into()]`。
    pub fn with_allowed_scopes(mut self, allowed: Vec<String>) -> Self {
        self.allowed_scopes = Some(allowed);
        self
    }

    /// 启用 `last_used_at` 追踪（opt-in，#7-b）。
    ///
    /// 启用后 `verify` / `verify_with_namespace` 成功时节流更新 `last_used_at`
    /// （距上次记录超过 `LAST_USED_UPDATE_THROTTLE_SECS` 秒才写回，避免写放大）。
    /// 默认关闭以保持 `verify` 只读语义。
    pub fn with_last_used_tracking(mut self, enabled: bool) -> Self {
        self.track_last_used = enabled;
        self
    }

    /// 生成 API Key。
    ///
    /// 返回 `key_id.key_secret` 双段格式（各 32 hex，`.` 分隔）。`key_secret` 不落库，
    /// 仅存储 `sha256(key_secret)`。存储于 `garrison:apikey:default:<key_id>`，TTL 为 `timeout` 秒。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（同时作为默认 `owner_id`）。
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
        self.generate_internal(login_id, &default_namespace(), scopes, timeout, None, None)
            .await
    }

    /// 生成带 namespace 的 API Key。
    ///
    /// 返回 `key_id.key_secret` 双段格式；存储于 `garrison:apikey:<namespace>:<key_id>`，
    /// value 为 JSON `ApiKeyInfo`（含 `secret_hash`），TTL 为 `timeout` 秒。
    /// 同步写入反向索引 `garrison:apikey:idx:<key_id> -> <dao_key>`（TTL 与主 key 一致），
    /// 使 `verify` / `revoke` 能以 O(1) 查询。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（同时作为默认 `owner_id`）。
    /// - `namespace`: 命名空间（1-64 字符，仅 `[a-zA-Z0-9_-]`）。
    /// - `scopes`: 作用域列表。
    /// - `timeout`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: timeout <= 0、namespace 非法或 scope 不在允许列表。
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

    /// 生成带完整选项的 API Key（显式 owner_id + 每 key rate_limit）。
    ///
    /// 用于需要将 key 归属到 `login_id` 以外主体（#3）、或设置每 key 速率上限（#7-b）的场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `namespace`: 命名空间。
    /// - `scopes`: 作用域列表。
    /// - `timeout`: 过期秒数（必须 > 0）。
    /// - `owner_id`: 归属主体（`None` 时默认等于 `login_id`）。
    /// - `rate_limit`: 每 key 速率上限（`None` 表示不限制）。
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
                "apikey-timeout-positive".to_string(),
            ));
        }
        validate_namespace(namespace)?;
        // #6: opt-in scope 校验
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
        };
        let value = serde_json::to_string(&info)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        let dao_key = format!("garrison:apikey:{}:{}", namespace, key_id);
        self.dao.set(&dao_key, &value, timeout as u64).await?;
        // 反向索引（TTL 与主 key 一致），O(1) verify/revoke
        let idx_key = idx_key_for(&key_id);
        self.dao.set(&idx_key, &dao_key, timeout as u64).await?;
        // 对外返回双段 token；key_secret 仅此一次可见
        Ok(format!("{}.{}", key_id, key_secret))
    }

    /// 校验 API Key。
    ///
    /// 校验逻辑（哈希 + 三级回退查找，最终都经 `decode_and_check` fail-closed 校验）：
    /// 1. **双段格式**：`token = key_id.key_secret` → O(1) 查 idx(`key_id`) → dao_key →
    ///    常量时间比较 `sha256(key_secret)` 与存储的 `secret_hash`。
    /// 2. **legacy v0.4.2**：单 token → 查 idx(`token`) → dao_key（`secret_hash` 空，被
    ///    `decode_and_check` fail-closed 拒绝，返回 `apikey-legacy-secret-required`）。
    /// 3. **legacy v0.4.1**：单 token → 查旧格式 `garrison:apikey:<token>`（同上，fail-closed 拒绝）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: key 不存在、secret 不匹配或已吊销。
    /// - `GarrisonError::ExpiredToken`: key 已过期。
    pub async fn verify(&self, key: &str) -> GarrisonResult<ApiKeyInfo> {
        let (dao_key, value, secret) = self.lookup(key).await?;
        let info = self.decode_and_check(&value, secret.as_deref())?;
        self.maybe_touch_last_used(&dao_key, &info).await;
        Ok(info)
    }

    /// 校验指定 namespace 下的 API Key。
    ///
    /// 严格匹配 `garrison:apikey:<namespace>:<key_id>`（双段格式）或
    /// `garrison:apikey:<namespace>:<token>`（legacy 单 token），不跨 namespace。
    /// 这是 IDOR 防护的核心：namespace A 的 key 无法在 namespace B 校验通过。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: namespace 非法。
    /// - `GarrisonError::InvalidToken`: key 不存在、secret 不匹配、已吊销或 namespace 不一致。
    /// - `GarrisonError::ExpiredToken`: key 已过期。
    pub async fn verify_with_namespace(
        &self,
        key: &str,
        namespace: &str,
    ) -> GarrisonResult<ApiKeyInfo> {
        validate_namespace(namespace)?;
        let (dao_key, value, secret) =
            match key.split_once('.') {
                Some((key_id, key_secret)) => {
                    let dao_key = format!("garrison:apikey:{}:{}", namespace, key_id);
                    let value = self.dao.get(&dao_key).await?.ok_or_else(|| {
                        GarrisonError::InvalidToken("apikey-not-found".to_string())
                    })?;
                    (dao_key, value, Some(key_secret.to_string()))
                },
                None => {
                    // legacy 单 token
                    let dao_key = format!("garrison:apikey:{}:{}", namespace, key);
                    let value = self.dao.get(&dao_key).await?.ok_or_else(|| {
                        GarrisonError::InvalidToken("apikey-not-found".to_string())
                    })?;
                    (dao_key, value, None)
                },
            };
        let info = self.decode_and_check(&value, secret.as_deref())?;
        // 二次校验：JSON 中 namespace 必须与请求 namespace 一致（防止存储错位 / 跨 namespace）
        if info.namespace != namespace {
            return Err(GarrisonError::InvalidToken(format!(
                "apikey-namespace-mismatch::{}::{}",
                namespace, info.namespace
            )));
        }
        self.maybe_touch_last_used(&dao_key, &info).await;
        Ok(info)
    }

    /// 内部：三级回退查找，返回 `(dao_key, value, provided_secret)`。
    ///
    /// `provided_secret` 为 `Some` 表示双段 token 提供了 secret（需哈希比较）；
    /// `None` 表示 legacy 单 token（最终被 `decode_and_check` fail-closed 拒绝，W8）。
    async fn lookup(&self, key: &str) -> GarrisonResult<(String, String, Option<String>)> {
        // 1. 双段格式：key_id.key_secret
        if let Some((key_id, key_secret)) = key.split_once('.') {
            let idx_key = idx_key_for(key_id);
            if let Some(dao_key) = self.dao.get(&idx_key).await? {
                if let Some(value) = self.dao.get(&dao_key).await? {
                    return Ok((dao_key, value, Some(key_secret.to_string())));
                }
            }
        }
        // 2. legacy v0.4.2：单 token 作为 idx key
        let idx_key = idx_key_for(key);
        if let Some(dao_key) = self.dao.get(&idx_key).await? {
            if let Some(value) = self.dao.get(&dao_key).await? {
                return Ok((dao_key, value, None));
            }
        }
        // 3. legacy v0.4.1：旧格式 garrison:apikey:<token>
        let old_dao_key = format!("garrison:apikey:{}", key);
        if let Some(value) = self.dao.get(&old_dao_key).await? {
            return Ok((old_dao_key, value, None));
        }
        Err(GarrisonError::InvalidToken("apikey-not-found".to_string()))
    }

    /// 解码 ApiKeyInfo 并校验 revoked / expire / secret（verify 内部复用）。
    ///
    /// - `secret_hash` 非空（新格式）：必须提供 `secret` 且常量时间比较通过。
    /// - `secret_hash` 空（legacy v0.4.1）：一律返回 `InvalidToken`
    ///   （`apikey-legacy-secret-required`），fail-closed 强制迁移到带 `secret_hash`
    ///   的新格式（W8，CWE-916 强化，消除"按存在性校验"弱点）。
    fn decode_and_check(&self, value: &str, secret: Option<&str>) -> GarrisonResult<ApiKeyInfo> {
        let info: ApiKeyInfo = serde_json::from_str(value)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        if info.revoked {
            return Err(GarrisonError::InvalidToken("apikey-revoked".to_string()));
        }
        let now = current_ts()?;
        if info.expire_at <= now {
            return Err(GarrisonError::ExpiredToken("apikey-expired".to_string()));
        }
        // CWE-916：新格式必须校验 secret 哈希（常量时间比较）
        if !info.secret_hash.is_empty() {
            let provided = secret
                .ok_or_else(|| GarrisonError::InvalidToken("apikey-secret-missing".to_string()))?;
            let computed = sha256_hex(provided);
            if !crate::secure::ct_eq::constant_time_eq(
                computed.as_bytes(),
                info.secret_hash.as_bytes(),
            ) {
                return Err(GarrisonError::InvalidToken(
                    "apikey-secret-mismatch".to_string(),
                ));
            }
        } else {
            // W8：空 secret_hash 的 legacy key fail-closed，强制迁移到带 secret_hash 的新格式。
            // 不提供 opt-in 兼容开关（遵循"禁止向后兼容"规则）。
            tracing::warn!(
                "apikey legacy empty-secret-hash rejected (login_id={}, namespace={}); \
                 migrate to v0.7.x dual-segment key format",
                info.login_id,
                info.namespace
            );
            return Err(GarrisonError::InvalidToken(
                "apikey-legacy-secret-required".to_string(),
            ));
        }
        Ok(info)
    }

    /// 节流更新 `last_used_at`（仅在启用追踪且距上次记录超过阈值时写回）。
    ///
    /// 写回失败**不影响校验结果**（元数据更新失败不应拒绝有效 key，availability 优先），
    /// 但会以 `warn` 级别记录，避免静默吞掉（Rule 12）。
    ///
    /// # lost-revoke 防护（MEDIUM-1）
    ///
    /// 不复用 `verify` 进入时读到的 `info`（可能已过期于并发 `revoke`），而是 **re-read
    /// 最新值**；若发现 `revoked == true` 则放弃写回，避免整 JSON 覆盖把已吊销状态回退
    /// 为 false。残留：re-read 与 `update` 之间仍有 micro-race 窗口，但 60s 节流 + revoke
    /// 优先 + revoked 前置检查将概率与影响降到可接受（`GarrisonDao` trait 无 CAS/字段级
    /// 更新，此为架构上限；如需强一致，调用方应在 rotate/revoke 入口加互斥）。
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
        // MEDIUM-1：re-read 最新值，绝不用 verify 进入时的旧 info 覆盖写
        let current = match self.dao.get(dao_key).await {
            Ok(Some(v)) => v,
            Ok(None) => return, // key 已删，放弃更新
            Err(e) => {
                tracing::warn!(dao_key = %dao_key, error = %e, "apikey last_used_at re-read 失败（不影响校验）");
                return;
            },
        };
        let mut updated: ApiKeyInfo = match serde_json::from_str(&current) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(error = %e, "apikey last_used_at 反序列化失败（不影响校验）");
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
                    tracing::warn!(dao_key = %dao_key, error = %e, "apikey last_used_at 更新失败（不影响校验）");
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "apikey last_used_at 序列化失败（不影响校验）");
            },
        }
    }

    /// 吊销 API Key。
    ///
    /// 通过三级回退查找定位 dao_key，将 `revoked` 设为 `true` 并写回（保留 TTL）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: key 不存在。
    pub async fn revoke(&self, key: &str) -> GarrisonResult<()> {
        let (dao_key, _value, _secret) = self.lookup(key).await?;
        self.revoke_at(&dao_key).await
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
    /// # 依赖
    /// 依赖 `GarrisonDao::keys`。`GarrisonDaoOxcache` 需启用 `dao-key-index` feature
    /// （由 `protocol-apikey` 传递启用），否则返回 `NotImplemented`。
    ///
    /// # 性能警告
    /// 大规模 key 场景下性能差（全量扫描 + 过滤），属管理面操作。
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

    /// 列出指定 namespace 下"陈旧"的未吊销 key（基于时间的轮换策略，#7-b）。
    ///
    /// "陈旧"定义：`last_used_at < cutoff_ts`，或从未使用（`last_used_at == None`）。
    /// 用于识别应轮换/回收的 key。
    ///
    /// # 参数
    /// - `namespace`: 命名空间。
    /// - `cutoff_ts`: 时间阈值（秒）；`last_used_at` 早于此值视为陈旧。
    ///
    /// # 错误
    /// - 同 [`list_by_namespace`](Self::list_by_namespace)。
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

    /// 显式更新 API Key 的 `last_used_at` 为当前时间（保留 TTL）。
    ///
    /// 供调用方在校验之外的场景（如异步审计）主动记录使用时间。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: key 不存在或已吊销。
    /// - `GarrisonError::ExpiredToken`: key 已过期。
    pub async fn update_last_used(&self, key: &str) -> GarrisonResult<()> {
        let (dao_key, value, _secret) = self.lookup(key).await?;
        let mut info: ApiKeyInfo = serde_json::from_str(&value)
            .map_err(|e| GarrisonError::Internal(format!("apikey-deserialize::{}", e)))?;
        // LOW-4：与 verify 对称，不对已吊销/过期的失效 key 写入使用时间
        if info.revoked {
            return Err(GarrisonError::InvalidToken("apikey-revoked".to_string()));
        }
        let now = current_ts()?;
        if info.expire_at <= now {
            return Err(GarrisonError::ExpiredToken("apikey-expired".to_string()));
        }
        info.last_used_at = Some(now);
        let new_value = serde_json::to_string(&info)
            .map_err(|e| GarrisonError::Internal(format!("apikey-serialize::{}", e)))?;
        self.dao.update(&dao_key, &new_value).await
    }

    /// 轮换 API Key。
    ///
    /// 轮换逻辑：(1) 校验 old_key 有效；(2) 吊销 old_key；(3) 生成新 key
    /// （保留 login_id/scopes/owner_id/rate_limit/剩余 TTL）；(4) 返回新 key（双段格式）。
    ///
    /// v0.4.2 扩展：成功时若注入了 `listener_manager`，广播 `GarrisonEvent::TokenRotate`
    ///
    /// # 并发警告（LOW-5）
    ///
    /// `rotate` 非原子（verify → revoke → generate 跨 await）。并发 rotate 同一 old_key
    /// 会各自成功并生成不同新 key（old_key 被吊销一次）。调用方应在 rotate 入口加
    /// 分布式锁/互斥，避免重复轮换。库层不内置锁（rotate 属低频管理操作，加全局锁
    /// 反而引入竞争与死锁面）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidToken`: old_key 不存在或已吊销。
    /// - `GarrisonError::ExpiredToken`: old_key 已过期。
    pub async fn rotate(&self, old_key: &str) -> GarrisonResult<String> {
        // (1) 校验 old_key
        let info = self.verify(old_key).await?;
        // (2) 吊销 old_key
        self.revoke(old_key).await?;
        // (3) 生成新 key（保留 login_id/scopes/owner_id/rate_limit/剩余 TTL）
        let now = current_ts()?;
        let remaining_ttl = info.expire_at - now;
        if remaining_ttl <= 0 {
            return Err(GarrisonError::ExpiredToken(
                "apikey-expired-cannot-rotate".to_string(),
            ));
        }
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

    /// MEDIUM-1 回归：并发 revoke 后，`maybe_touch_last_used` 用 verify 进入时的旧快照
    /// 写回时，必须 re-read 发现 `revoked` 并放弃，不得把已吊销状态回退（lost-revoke）。
    ///
    /// 修复前实现（`info.clone()` 整 JSON 覆盖）会让此断言失败：旧快照 revoked=false
    /// 覆盖了并发 revoke 写入的 revoked=true，导致已吊销 key 复活。
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

    /// LOW-4：`update_last_used` 对已吊销 key 返回 `InvalidToken`（与 verify 对称）。
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
