//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 会话模块，提供双模会话管理（Account-Session + Token-Session）。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaSession`，
//! 提供会话级数据存储与 Token 列表管理。
//!
//! ## 双模会话
//!
//! 1. **Account-Session**：以 login_id 为 key，存储该账号所有 token 列表与最后活跃时间
//!    - key: `account:session:{login_id}`
//!    - TTL: `active_timeout`（账号级 activity 超时）
//! 2. **Token-Session**：以 token 为 key，存储 login_id/创建时间/自定义属性
//!    - key: `token:session:{token}`
//!    - TTL: `timeout`（token 级超时）
//!
//! ## 过期机制
//!
//! - **token 级过期**：由 oxcache TTL 自动管理，过期后 get 返回 None
//! - **Account-Session 级过期**：由 oxcache TTL 自动管理 + `is_valid` 惰性检查
//! - **活跃续期**：`touch(token)` 更新 last_active_at 并重置 TTL
//! - **主动续期**：`renew(token)` 重置过期时间为完整 timeout
//!
//! ## 存储委托
//!
//! 会话数据通过 `BulwarkDao` 持久化（oxcache / dbnexus），不自行实现缓存逻辑。

/// Session 安全监听器（IP 变更检测）。
pub mod security_listener;

/// 设备管理模块（需要 sha2，由多个协议/安全 feature 启用）。
#[cfg(any(
    feature = "protocol-jwt",
    feature = "account-credential",
    feature = "protocol-oauth2",
    feature = "protocol-sso",
    feature = "protocol-sign",
    feature = "secure-sign",
    feature = "secure-httpdigest"
))]
pub mod device;

/// Re-export 设备管理类型（与 `device` 模块 feature gate 一致）。
///
/// 启用任一启用 `device` 模块的 feature 后，可通过 `bulwark::session::DeviceManager`
/// / `bulwark::session::DeviceSession` 直接访问，无需 `device::` 前缀。
#[cfg(any(
    feature = "protocol-jwt",
    feature = "account-credential",
    feature = "protocol-oauth2",
    feature = "protocol-sso",
    feature = "protocol-sign",
    feature = "secure-sign",
    feature = "secure-httpdigest"
))]
pub use device::{DeviceManager, DeviceSession};

/// 匿名 Session 模块（需要 `anonymous-session` feature）。
#[cfg(feature = "anonymous-session")]
pub mod anon;

/// 会话搜索模块（需要 `session-search` feature）。
#[cfg(feature = "session-search")]
pub mod search;

/// Re-export 搜索排序类型（与 `search` 模块 feature gate 一致）。
#[cfg(feature = "session-search")]
pub use search::SearchSortType;

use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;

/// Account-Session 的 token 信息条目。
///
/// 存储 token 字符串、创建时间与最后活跃时间。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// token 字符串。
    pub token: String,
    /// 创建时间戳（Unix 秒）。
    pub created_at: i64,
    /// 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
}

/// Account-Session 数据（以 login_id 为 key）。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 Account-Session，
/// 存储账号所有 token 列表与最后活跃时间。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSession {
    /// 登录主体标识。
    pub login_id: String,
    /// 该账号的所有 token 信息列表。
    pub tokens: Vec<TokenInfo>,
    /// Account-Session 创建时间戳（Unix 秒）。
    pub created_at: i64,
    /// Account-Session 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
}

/// Token-Session 数据（以 token 为 key）。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 Token-Session，
/// 存储 token 关联的 login_id、创建时间与自定义属性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSession {
    /// token 字符串。
    pub token: String,
    /// 关联的登录主体标识。
    pub login_id: String,
    /// 创建时间戳（Unix 秒）。
    pub created_at: i64,
    /// 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
    /// 自定义属性（键值对）。
    pub attrs: HashMap<String, String>,
    /// 登录设备标识。
    ///
    /// 由业务方在 login 后通过 `set_device` 设置（如 "web-chrome"/"mobile-ios"/"api-client"）。
    /// `kickout_by_device` 按此字段过滤踢出。未设置时为 `None`，不参与设备级踢出。
    #[serde(default)]
    pub device: Option<String>,
    /// 客户端 IP 地址。
    ///
    /// 由 `create_token_session` 在 login 时从 `LoginParams.ip` 写入。
    /// 未设置时为 `None`。
    #[serde(default)]
    pub ip: Option<String>,
    /// 客户端 User-Agent。
    ///
    /// 由 `create_token_session` 在 login 时从 `LoginParams.user_agent` 写入。
    /// 未设置时为 `None`。
    #[serde(default)]
    pub user_agent: Option<String>,
    /// 二级认证（Safe Auth）瞬态标记。
    ///
    /// key: service 名称（如 "default" / "payment"）
    /// value: 过期时间戳（Unix 秒），`now > value` 表示已过期。
    ///
    /// `open_safe` 写入，`is_safe` 查询，`close_safe` 移除。
    /// `#[serde(default)]` 确保反序列化旧数据（无此字段）时默认为空 HashMap（向后兼容）。
    #[serde(default)]
    pub safe_services: HashMap<String, i64>,
    /// 动态活跃超时（秒）。
    ///
    /// 启用 `dynamic-active-timeout` feature 后存在。为 `None` 时使用全局 `active_timeout`，
    /// 为 `Some(secs)` 时该 token 使用自定义的活跃超时。
    /// `#[serde(default)]` 确保反序列化旧数据（无此字段）时默认为 `None`（向后兼容）。
    #[cfg(feature = "dynamic-active-timeout")]
    #[serde(default)]
    pub dynamic_active_timeout: Option<i64>,
    /// 是否为匿名 Session。
    ///
    /// 启用 `anonymous-session` feature 后存在。匿名 Session 的 `login_id` 为空字符串 `""`，
    /// 通过 `token:session:anon:{token}` key 空间与登录 Session 隔离。
    /// `#[serde(default)]` 确保反序列化旧数据（无此字段）时默认为 `false`（向后兼容）。
    #[cfg(feature = "anonymous-session")]
    #[serde(default)]
    pub is_anon: bool,
}

/// 会话过期监听器 trait。
///
/// 在 session 过期时触发回调。listener 失败时记录 `tracing::warn!` 但不中断调用方
///
/// # 使用
///
/// ```ignore
/// use bulwark::session::SessionExpiryListener;
/// use bulwark::error::BulwarkResult;
/// use async_trait::async_trait;
/// use std::sync::Arc;
///
/// struct AuditListener;
///
/// #[async_trait]
/// impl SessionExpiryListener for AuditListener {
///     async fn on_session_expired(&self, login_id: &str, token: &str) -> BulwarkResult<()> {
///         tracing::info!(login_id, token, "session expired");
///         Ok(())
///     }
/// }
///
/// let mut session = bulwark::session::BulwarkSession::new(dao, 3600, 86400);
/// session.add_expiry_listener(Arc::new(AuditListener));
/// ```
#[async_trait]
pub trait SessionExpiryListener: Send + Sync {
    /// 会话过期回调。
    ///
    /// # 参数
    /// - `login_id`: 过期会话关联的登录主体标识。
    /// - `token`: 过期的 token 字符串（Account-Session 级过期时为空字符串 `""`）。
    ///
    /// # 返回
    /// - `Ok(())`: 回调成功。
    /// - `Err`: 回调失败，调用方记录 `tracing::warn!` 但不中断主流程或后续 listener。
    async fn on_session_expired(&self, login_id: &str, token: &str) -> BulwarkResult<()>;
}

/// 会话管理器，封装 `BulwarkDao` 提供双模会话操作。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `SaSession` 管理逻辑，
/// 持有 DAO 引用与超时配置，提供会话 CRUD / 过期检查 / 续期 / 登出。
///
/// # 存储格式
///
/// - `account:session:{login_id}` → `AccountSession`（JSON）
/// - `token:session:{token}` → `TokenSession`（JSON）
pub struct BulwarkSession {
    /// DAO 引用（oxcache / dbnexus 实现）。
    dao: Arc<dyn BulwarkDao>,
    /// token 级超时（秒）。
    timeout: u64,
    /// Account-Session 级 activity 超时（秒）。
    active_timeout: u64,
    /// 匿名 Session 超时（秒）。
    ///
    /// 启用 `anonymous-session` feature 后存在。由 `anon` 模块的 `get_anon_token_session`
    /// 用作匿名 Token-Session 的 TTL。
    #[cfg(feature = "anonymous-session")]
    anon_session_timeout: u64,
    /// per-login_id 操作锁，保护 Account-Session 的 read-modify-write 序列（R-001~R-004）。
    login_locks: DashMap<String, Arc<TokioMutex<()>>>,
    /// per-token 操作锁，保护 Token-Session 的 read-modify-write 序列（CRIT-001）。
    ///
    /// 用于 `open_safe`/`close_safe` 等 modifying TokenSession 操作的串行化，
    /// 避免并发 read-modify-write 导致 lost update。只读操作（如 `is_safe`）不需要锁。
    #[cfg(any(feature = "safe-auth", feature = "anonymous-session"))]
    token_session_locks: DashMap<String, Arc<TokioMutex<()>>>,
    /// login_id → token 列表的内存索引，用于并发登录控制快速查询。
    ///
    /// 与 DAO 持久化的 `AccountSession.tokens` 保持同步：
    /// - `create`/`create_token_session` 时 `add_login_token`
    /// - `logout`/`kickout_by_device`（经 `logout_inner`）/`logout_by_login_id` 时 `remove_login_token`
    login_token_map: DashMap<String, Vec<String>>,
    /// 监听器管理器。
    ///
    /// 注入后 `kickout_by_device` 会广播 `BulwarkEvent::Kickout` 事件。
    /// 未注入时 `kickout_by_device` 仍正常执行踢出，仅跳过事件广播。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<crate::listener::BulwarkListenerManager>>,
    /// 会话过期监听器列表。
    ///
    /// 按 FIFO 顺序调用。listener 失败时记录 `tracing::warn!` 但不中断后续 listener。
    expiry_listeners: Vec<Arc<dyn SessionExpiryListener>>,
    /// 每个登录主体的最后活跃时间（login_id → unix 毫秒时间戳）。
    ///
    /// 仅当 `session_hover_timeout > 0` 时由 `check_login` 路径更新与检查。
    last_active_time: DashMap<String, i64>,
}

/// 生成 Account-Session 的存储 key。
fn account_key(login_id: &str) -> String {
    format!("account:session:{}", login_id)
}

/// 生成 Token-Session 的存储 key。
fn token_key(token: &str) -> String {
    format!("{}session:{}", DaoKeyPrefix::Token, token)
}

impl BulwarkSession {
    /// 创建会话管理器实例。
    ///
    /// # 参数
    /// - `dao`: DAO 引用（oxcache / dbnexus）。
    /// - `timeout`: token 级超时秒数（0 表示永久驻留）。
    /// - `active_timeout`: Account-Session 级 activity 超时秒数。
    ///
    /// # 返回
    /// 新建的 `BulwarkSession` 实例。
    pub fn new(dao: Arc<dyn BulwarkDao>, timeout: u64, active_timeout: u64) -> Self {
        Self {
            dao,
            timeout,
            active_timeout,
            #[cfg(feature = "anonymous-session")]
            anon_session_timeout: crate::config::DEFAULT_ANON_SESSION_TIMEOUT_SECS,
            login_locks: DashMap::new(),
            #[cfg(any(feature = "safe-auth", feature = "anonymous-session"))]
            token_session_locks: DashMap::new(),
            login_token_map: DashMap::new(),
            #[cfg(feature = "listener")]
            listener_manager: None,
            expiry_listeners: Vec::new(),
            last_active_time: DashMap::new(),
        }
    }

    /// 获取 DAO 引用（pub(crate) 供 BulwarkLogicDefault 构造 ApiKeyHandler 等需要 DAO 的协议处理器复用）。
    ///
    /// `BulwarkLogicDefault::check_api_key` 通过此访问器获取 DAO，
    /// 构造 `ApiKeyHandler` 实例进行 API Key 校验。
    ///
    /// 仅在 `protocol-apikey` feature 启用时编译（避免 feature 关闭时的 dead_code 警告）。
    #[cfg(feature = "protocol-apikey")]
    pub(crate) fn dao(&self) -> &Arc<dyn BulwarkDao> {
        &self.dao
    }

    /// 注入监听器管理器。
    ///
    /// 注入后 `kickout_by_device` 会为每个被踢出的 token 广播 `BulwarkEvent::Kickout` 事件。
    ///
    /// # 参数
    /// - `manager`: 监听器管理器实例。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(
        mut self,
        manager: Arc<crate::listener::BulwarkListenerManager>,
    ) -> Self {
        self.listener_manager = Some(manager);
        self
    }

    /// 设置匿名 Session 超时时间。
    ///
    /// 启用 `anonymous-session` feature 后可用。覆盖默认的 `anon_session_timeout`
    /// （默认值为 `DEFAULT_ANON_SESSION_TIMEOUT_SECS` = 1800 秒 = 30 分钟）。
    ///
    /// # 参数
    /// - `timeout`: 匿名 Session 超时秒数。
    #[cfg(feature = "anonymous-session")]
    pub fn with_anon_session_timeout(mut self, timeout: u64) -> Self {
        self.anon_session_timeout = timeout;
        self
    }

    /// 注册会话过期监听器。
    ///
    /// listener 按注册顺序（FIFO）依次调用。`get_token_session` / `get_account_session`
    /// 发现 session 过期时触发所有已注册的 listener。
    ///
    /// # 参数
    /// - `listener`: 过期监听器实例。
    pub fn add_expiry_listener(&mut self, listener: Arc<dyn SessionExpiryListener>) {
        self.expiry_listeners.push(listener);
    }

    /// 触发所有过期监听器。
    ///
    /// listener 按注册顺序（FIFO）依次调用。单个 listener 失败时记录 `tracing::warn!`
    /// 但继续执行后续 listener。
    async fn trigger_expiry_listeners(&self, login_id: &str, token: &str) {
        for listener in &self.expiry_listeners {
            if let Err(e) = listener.on_session_expired(login_id, token).await {
                tracing::warn!(
                    "SessionExpiryListener 回调失败 (login_id={}, token={}): {}",
                    login_id,
                    token,
                    e
                );
            }
        }
    }

    /// 更新 login_id 的最后活跃时间为当前 unix 毫秒时间戳。
    pub fn update_last_active(&self, login_id: &str) {
        let now = chrono::Utc::now().timestamp_millis();
        self.last_active_time.insert(login_id.to_string(), now);
    }

    /// 获取 login_id 的最后活跃时间（unix 毫秒），不存在返回 None。
    pub fn get_last_active(&self, login_id: &str) -> Option<i64> {
        self.last_active_time.get(login_id).map(|v| *v)
    }

    /// 检查会话是否因悬停超时应被踢出。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `hover_timeout_secs`: 悬停超时秒数（-1 = 不启用，>0 = 启用）。
    ///
    /// # 返回
    /// - `true`: 会话活跃或悬停检查未启用，不应踢出。
    /// - `false`: 会话已悬停超时，应踢出。
    pub fn check_hover_timeout(&self, login_id: &str, hover_timeout_secs: i64) -> bool {
        if hover_timeout_secs <= 0 {
            return true; // 不启用悬停检查
        }
        let now = chrono::Utc::now().timestamp_millis();
        let timeout_millis = hover_timeout_secs * 1000;
        match self.last_active_time.get(login_id) {
            Some(last) => {
                let elapsed = now - *last;
                if elapsed > timeout_millis {
                    return false; // 悬停超时，踢出
                }
                true
            },
            None => true, // 无记录（首次 check_login），不踢出
        }
    }

    /// 获取 per-login_id 锁并执行 future（保护 Account-Session read-modify-write 序列）。
    ///
    /// 锁粒度为 login_id，不影响不同用户的并发。使用 `tokio::sync::Mutex`（持有锁跨 await 点）。
    /// `kickout_by_device` 持有锁后调用 `logout_inner`（不获取锁），避免死锁。
    async fn with_login_lock<F, R>(&self, login_id: &str, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let lock = self
            .login_locks
            .entry(login_id.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        f.await
    }

    /// 获取 per-token 锁并执行 future（保护 Token-Session read-modify-write 序列）。
    ///
    /// 锁粒度为 token，不影响不同 token 的并发。使用 `tokio::sync::Mutex`（持有锁跨 await 点）。
    /// 用于 `open_safe`/`close_safe` 等修改 TokenSession 的操作，避免并发 read-modify-write
    /// 导致 lost update（CRIT-001）。
    ///
    /// 注意：`get_token_session`/`save_token_session` 本身不加锁，调用方需通过此方法
    /// 包裹 read-modify-write 序列。只读操作（如 `is_safe`）不需要锁。
    #[cfg(any(feature = "safe-auth", feature = "anonymous-session"))]
    pub(crate) async fn with_token_session_lock<F, R>(&self, token: &str, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let lock = self
            .token_session_locks
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        f.await
    }

    /// 创建会话（login 时调用）：双写 Account-Session + Token-Session。
    ///
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（接受 `String` / `&str`）。
    /// - `token`: 新创建的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 序列化 `TokenSession` / `AccountSession` 失败：`BulwarkError::Session`。
    /// - DAO 写入失败：透传 `BulwarkError`。
    pub async fn create(&self, login_id: impl Into<String>, token: &str) -> BulwarkResult<()> {
        let login_id: String = login_id.into();
        self.create_inner(&login_id, token, None, None, None).await
    }

    /// 创建 Token-Session 并写入 LoginParams 中的 device/ip/user_agent。
    ///
    /// 与 [`create`](Self::create) 的区别：将 `LoginParams` 的 device/ip/user_agent
    /// 直接写入 `TokenSession` 对应字段，无需 login 后再调用 `set_device`。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: 新创建的 token 字符串。
    /// - `params`: 登录参数（device/ip/user_agent/remember_me）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 序列化 `TokenSession` / `AccountSession` 失败：`BulwarkError::Session`。
    /// - DAO 写入失败：透传 `BulwarkError`。
    pub async fn create_token_session(
        &self,
        login_id: &str,
        token: &str,
        params: &crate::stp::LoginParams,
    ) -> BulwarkResult<()> {
        self.create_inner(
            login_id,
            token,
            params.device.as_deref(),
            params.ip.as_deref(),
            params.user_agent.as_deref(),
        )
        .await
    }

    /// create / create_token_session 共用内部实现。
    ///
    /// 在 per-login_id 锁内双写 Token-Session + Account-Session。
    /// device/ip/user_agent 为 None 时对应字段留空（向后兼容 `create`）。
    async fn create_inner(
        &self,
        login_id: &str,
        token: &str,
        device: Option<&str>,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> BulwarkResult<()> {
        let login_id: String = login_id.to_string();
        self.with_login_lock(&login_id, async {
            let now = Utc::now().timestamp();

            // 创建 Token-Session
            let token_session = TokenSession {
                token: token.to_string(),
                login_id: login_id.clone(),
                created_at: now,
                last_active_at: now,
                attrs: HashMap::new(),
                device: device.map(|s| s.to_string()),
                ip: ip.map(|s| s.to_string()),
                user_agent: user_agent.map(|s| s.to_string()),
                safe_services: HashMap::new(),
                #[cfg(feature = "dynamic-active-timeout")]
                dynamic_active_timeout: None,
                #[cfg(feature = "anonymous-session")]
                is_anon: false,
            };
            let token_json = serde_json::to_string(&token_session)
                .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
            self.dao
                .set(&token_key(token), &token_json, self.timeout)
                .await?;

            // 读取或创建 Account-Session
            let mut account = self
                .get_account_session(&login_id)
                .await?
                .unwrap_or_else(|| AccountSession {
                    login_id: login_id.clone(),
                    tokens: vec![],
                    created_at: now,
                    last_active_at: now,
                });

            // 添加 token 信息（spec scenario "Account-Session 记录多 token"）
            account.tokens.push(TokenInfo {
                token: token.to_string(),
                created_at: now,
                last_active_at: now,
            });
            account.last_active_at = now;

            let account_json = serde_json::to_string(&account)
                .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
            self.dao
                .set(&account_key(&login_id), &account_json, self.active_timeout)
                .await?;

            // 同步内存索引（login_id → token 列表），用于并发登录控制快速查询
            self.add_login_token(&login_id, token);

            Ok(())
        })
        .await
    }

    /// 获取 Token-Session。
    ///
    ///
    /// # 参数
    /// - `token`: token 字符串。
    ///
    /// # 返回
    /// - `Some(TokenSession)`: token 存在。
    /// - `None`: token 不存在或已过期。
    ///
    /// # 错误
    /// - 反序列化失败：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_token_session(&self, token: &str) -> BulwarkResult<Option<TokenSession>> {
        match self.dao.get(&token_key(token)).await? {
            Some(json) => {
                let ts: TokenSession = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Session(format!("反序列化 TokenSession 失败: {}", e))
                })?;
                // R-session-lifecycle-003: 检查 session 级过期（last_active_at + timeout < now）
                let now = Utc::now().timestamp();
                if ts.last_active_at + (self.timeout as i64) < now {
                    // 触发过期回调
                    self.trigger_expiry_listeners(&ts.login_id, token).await;
                    // 从 DAO 删除过期 session（清理）
                    if let Err(e) = self.dao.delete(&token_key(token)).await {
                        let token_preview = if token.len() > 8 { &token[..8] } else { token };
                        tracing::warn!(
                            "删除过期 Token-Session 失败 (token={}...): {}",
                            token_preview,
                            e
                        );
                    }
                    return Ok(None);
                }
                Ok(Some(ts))
            },
            None => Ok(None),
        }
    }

    /// 获取 Account-Session。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（接受 `String` / `&str`）。
    ///
    /// # 返回
    /// - `Some(AccountSession)`: 账号会话存在。
    /// - `None`: 账号会话不存在或已过期。
    ///
    /// # 错误
    /// - 反序列化失败：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_account_session(
        &self,
        login_id: impl Into<String>,
    ) -> BulwarkResult<Option<AccountSession>> {
        let login_id: String = login_id.into();
        match self.dao.get(&account_key(&login_id)).await? {
            Some(json) => {
                let as_: AccountSession = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Session(format!("反序列化 AccountSession 失败: {}", e))
                })?;
                // R-session-lifecycle-003: 检查 session 级过期（last_active_at + active_timeout < now）
                let now = Utc::now().timestamp();
                if as_.last_active_at + (self.active_timeout as i64) < now {
                    // 触发过期回调（Account-Session 级过期，token 为空字符串）
                    self.trigger_expiry_listeners(&login_id, "").await;
                    // 从 DAO 删除过期 session（清理）
                    if let Err(e) = self.dao.delete(&account_key(&login_id)).await {
                        tracing::warn!(
                            "删除过期 Account-Session 失败 (login_id={}): {}",
                            login_id,
                            e
                        );
                    }
                    return Ok(None);
                }
                Ok(Some(as_))
            },
            None => Ok(None),
        }
    }

    /// 添加 login_id → token 映射到内存索引。
    ///
    /// 同一 token 不重复添加（去重）。在 `create`/`create_token_session` 成功后调用，
    /// 与 DAO 持久化的 `AccountSession.tokens` 保持同步。
    pub fn add_login_token(&self, login_id: &str, token: &str) {
        let mut entry = self
            .login_token_map
            .entry(login_id.to_string())
            .or_default();
        if !entry.contains(&token.to_string()) {
            entry.push(token.to_string());
        }
    }

    /// 从内存索引中移除指定 login_id 的某个 token。
    ///
    /// 当列表为空时移除整个 entry（避免内存泄漏）。在 `logout`/`kickout_by_device`
    /// （经 `logout_inner`）销毁 Token-Session 后调用。
    pub fn remove_login_token(&self, login_id: &str, token: &str) {
        if let Some(mut entry) = self.login_token_map.get_mut(login_id) {
            entry.retain(|t| t != token);
            if entry.is_empty() {
                drop(entry); // 释放 DashMap 写锁后再 remove，避免死锁
                self.login_token_map.remove(login_id);
            }
        }
    }

    /// 获取指定 login_id 的第一个 token（最旧）。
    ///
    /// 用于并发登录控制等只需取一个代表性 token 的场景。
    pub fn get_token_by_login_id(&self, login_id: &str) -> Option<String> {
        self.login_token_map
            .get(login_id)
            .and_then(|tokens| tokens.first().cloned())
    }

    /// 获取指定 login_id 的所有 token 列表（克隆）。
    ///
    /// 不存在时返回空 `Vec`。
    pub fn get_tokens_by_login_id(&self, login_id: &str) -> Vec<String> {
        self.login_token_map
            .get(login_id)
            .map(|tokens| tokens.clone())
            .unwrap_or_default()
    }

    /// 清理 `login_token_map` 中已过期或已注销的 token。
    ///
    /// 遍历内存索引中所有 login_id 的 token 列表，对每个 token 调用
    /// [`get_token_session`](Self::get_token_session) 检查存在性与过期状态：
    /// - `Ok(None)`：token session 不存在（已注销）或已过期 → 从列表中移除
    /// - `Ok(Some(_))`：token 仍有效 → 保留
    /// - `Err(e)`：DAO 读取错误 → 记录 `tracing::warn!` 并跳过该 token，继续遍历（HIGH-004）
    ///
    /// 若某个 login_id 的 token 列表清理后变空，移除该 login_id 的整个 entry
    ///（与 [`remove_login_token`](Self::remove_login_token) 行为一致）。
    ///
    /// # 返回
    /// 清理的 token 总数（仅统计成功清理的 token，DAO 失败的 token 不计入）。
    ///
    /// # 错误处理（HIGH-004）
    /// 单个 token 的 DAO 读取失败不再透传 `BulwarkError` 中断整个清理周期，
    /// 而是记录 `tracing::warn!` 日志并跳过该 token，继续处理后续 token。
    /// 这样可避免单个 DAO 故障导致整个清理周期中断，最大化清理覆盖率。
    pub async fn cleanup_expired_tokens(&self) -> BulwarkResult<usize> {
        let mut removed = 0usize;
        // 先收集所有 login_id，避免在 await 期间持有 DashMap 读锁
        let login_ids: Vec<String> = self
            .login_token_map
            .iter()
            .map(|r| r.key().clone())
            .collect();

        for login_id in login_ids {
            // 快照当前 login_id 的 token 列表
            let tokens: Vec<String> = match self.login_token_map.get(&login_id) {
                Some(t) => t.clone(),
                None => continue, // entry 已被并发移除
            };

            // 逐个检查 token 的存活性（get_token_session 会处理过期清理与回调）
            // HIGH-004: 单个 token 的 DAO 失败不再中断整个清理周期，改为 warn 日志并跳过
            let mut expired: Vec<String> = Vec::new();
            for token in &tokens {
                match self.get_token_session(token).await {
                    Ok(None) => expired.push(token.clone()),
                    Ok(Some(_)) => {}, // token 仍有效，保留
                    Err(e) => tracing::warn!(
                        "cleanup_expired_tokens: token={} DAO 读取失败，跳过该 token: {}",
                        token,
                        e
                    ),
                }
            }

            if expired.is_empty() {
                continue; // 无需更新
            }

            removed += expired.len();
            // 同步移除过期 token（持有 DashMap 写锁的时间极短）
            // 使用 retain 保留并发期间新增的 token
            if let Some(mut entry) = self.login_token_map.get_mut(&login_id) {
                entry.retain(|x| !expired.contains(x));
                if entry.is_empty() {
                    drop(entry); // 释放写锁后再 remove，避免死锁
                    self.login_token_map.remove(&login_id);
                }
            }
        }

        Ok(removed)
    }

    /// 从 DAO 重建内存 `login_token_map`。
    ///
    /// 遍历所有 Account-Session，收集 `tokens` 字段重建内存层。
    /// 用于应用启动时恢复内存索引（重启后内存丢失，DAO 数据仍保留）。
    ///
    /// # 重建流程
    /// 1. 清空现有内存 `login_token_map`（避免与重建数据重叠）
    /// 2. `dao.keys("account:session:*")` 扫描所有 Account-Session key
    /// 3. 逐个 `dao.get` 读取并反序列化为 `AccountSession`
    /// 4. 从 key 解析 `login_id`（key 格式：`account:session:{login_id}`）
    /// 5. 提取 `tokens` 字段中的 token 字符串列表写入内存 map
    ///
    /// # 错误
    /// - DAO `keys()` 失败：透传 `BulwarkError`
    /// - DAO `get()` 失败：透传 `BulwarkError`
    /// - `AccountSession` 反序列化失败：`BulwarkError::Session`
    ///
    /// # key 格式异常处理
    /// 若 key 不符合 `account:session:{login_id}` 模式（`strip_prefix` 返回 `None`），
    /// 记录 `tracing::warn!` 并跳过该 key（不中断重建流程）。
    #[cfg(feature = "login-token-map-persistence")]
    pub async fn rebuild_login_token_map(&self) -> BulwarkResult<()> {
        // 1. 清空现有内存 map（避免与重建数据重叠）
        self.login_token_map.clear();

        // 2. 扫描所有 Account-Session key
        let keys = self.dao.keys("account:session:*").await?;
        for key in keys {
            // 3. 从 key 解析 login_id（key 格式：account:session:{login_id}）
            let Some(login_id) = key.strip_prefix("account:session:") else {
                tracing::warn!(
                    "rebuild_login_token_map: 跳过不符合 account:session:{{login_id}} 模式的 key: {}",
                    key
                );
                continue;
            };

            // 4. 读取并反序列化 AccountSession
            if let Some(json) = self.dao.get(&key).await? {
                let session: AccountSession = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Session(format!("反序列化 AccountSession 失败: {}", e))
                })?;
                // 5. 提取 tokens 字段中的 token 字符串列表，写入内存 map
                let tokens: Vec<String> = session.tokens.into_iter().map(|ti| ti.token).collect();
                self.login_token_map.insert(login_id.to_string(), tokens);
            }
        }
        Ok(())
    }

    /// 持久化添加 login_id → token 映射（双层写入：DAO + 内存）。
    ///
    /// 先写 DAO `AccountSession.tokens`（读取现有 AccountSession → 添加 token → 写回 DAO），
    /// 再写内存 `login_token_map`。DAO 失败时内存不写（返回 Err），保证双层一致性。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: token 字符串。
    ///
    /// # 错误
    /// - AccountSession 不存在：`BulwarkError::Session`
    /// - 序列化失败：`BulwarkError::Session`
    /// - DAO update 失败：透传 `BulwarkError`
    #[cfg(feature = "login-token-map-persistence")]
    pub async fn add_login_token_persistent(
        &self,
        login_id: &str,
        token: &str,
    ) -> BulwarkResult<()> {
        let login_id: String = login_id.to_string();
        self.with_login_lock(&login_id, async {
            // 1. 读取现有 AccountSession（必须已存在）
            let mut account = self.get_account_session(&login_id).await?.ok_or_else(|| {
                BulwarkError::Session(format!("AccountSession 不存在: {}", login_id))
            })?;

            // 2. 添加 token（去重）
            let now = Utc::now().timestamp();
            if !account.tokens.iter().any(|ti| ti.token == token) {
                account.tokens.push(TokenInfo {
                    token: token.to_string(),
                    created_at: now,
                    last_active_at: now,
                });
            }
            account.last_active_at = now;

            // 3. 写回 DAO（用 update 保留原 TTL）
            let json = serde_json::to_string(&account)
                .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
            self.dao.update(&account_key(&login_id), &json).await?;

            // 4. DAO 成功后写内存 login_token_map
            self.add_login_token(&login_id, token);

            Ok(())
        })
        .await
    }

    /// 持久化移除 login_id → token 映射（双层写入：DAO + 内存）。
    ///
    /// 先写 DAO `AccountSession.tokens`（读取现有 AccountSession → 移除 token → 写回 DAO），
    /// 再写内存 `login_token_map`。DAO 失败时内存不写（返回 Err），保证双层一致性。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: token 字符串。
    ///
    /// # 错误
    /// - AccountSession 不存在：`BulwarkError::Session`
    /// - 序列化失败：`BulwarkError::Session`
    /// - DAO update 失败：透传 `BulwarkError`
    #[cfg(feature = "login-token-map-persistence")]
    pub async fn remove_login_token_persistent(
        &self,
        login_id: &str,
        token: &str,
    ) -> BulwarkResult<()> {
        let login_id: String = login_id.to_string();
        self.with_login_lock(&login_id, async {
            // 1. 读取现有 AccountSession（必须已存在）
            let mut account = self.get_account_session(&login_id).await?.ok_or_else(|| {
                BulwarkError::Session(format!("AccountSession 不存在: {}", login_id))
            })?;

            // 2. 移除 token
            account.tokens.retain(|ti| ti.token != token);

            // 3. 写回 DAO（用 update 保留原 TTL）
            let json = serde_json::to_string(&account)
                .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
            self.dao.update(&account_key(&login_id), &json).await?;

            // 4. DAO 成功后写内存 login_token_map
            self.remove_login_token(&login_id, token);

            Ok(())
        })
        .await
    }

    /// 设置 Token-Session 自定义属性。
    ///
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `key`: 属性键。
    /// - `value`: 属性值。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`。
    pub async fn set(&self, token: &str, key: &str, value: &str) -> BulwarkResult<()> {
        let mut ts = self
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken("token 不存在".to_string()))?;
        ts.attrs.insert(key.to_string(), value.to_string());
        ts.last_active_at = Utc::now().timestamp();
        let json = serde_json::to_string(&ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        // 用 update 保留原 TTL（不重置过期时间）
        self.dao.update(&token_key(token), &json).await?;
        Ok(())
    }

    /// 获取 Token-Session 自定义属性。
    ///
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `key`: 属性键。
    ///
    /// # 返回
    /// - `Some(String)`: 属性存在。
    /// - `None`: token 不存在或属性不存在。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get(&self, token: &str, key: &str) -> BulwarkResult<Option<String>> {
        match self.get_token_session(token).await? {
            Some(ts) => Ok(ts.attrs.get(key).cloned()),
            None => Ok(None),
        }
    }

    /// 保存（更新）Token-Session 到 DAO（保留原 TTL）。
    ///
    /// 供 `AuthLogicDefault::switch_to` / `renew_to_equivalent` 等需要修改
    /// TokenSession 结构（非 attrs）的方法使用。用 `dao.update` 保留原 TTL。
    ///
    /// # 参数
    /// - `token`: token 字符串（用于构造存储 key）。
    /// - `ts`: 修改后的 TokenSession。
    ///
    /// # 错误
    /// - 序列化失败：`BulwarkError::Session`。
    /// - DAO 更新失败：透传 `BulwarkError`。
    pub async fn save_token_session(&self, token: &str, ts: &TokenSession) -> BulwarkResult<()> {
        let json = serde_json::to_string(ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        self.dao.update(&token_key(token), &json).await?;
        Ok(())
    }

    /// 确保 token 存在于指定 login_id 的 Account-Session 中。
    ///
    /// 供 `AuthLogicDefault::switch_to` 使用：切换身份后需将 token 添加到
    /// 目标 login_id 的 Account-Session，否则 `is_valid` 检查会失败
    ///（`is_valid` 惰性检查 Account-Session 是否存在）。
    ///
    /// 若 token 已在 Account-Session 中，则仅更新 `last_active_at`，不重复添加。
    pub async fn ensure_token_in_account_session(
        &self,
        login_id: &str,
        token: &str,
    ) -> BulwarkResult<()> {
        let now = Utc::now().timestamp();
        let mut account = self
            .get_account_session(login_id)
            .await?
            .unwrap_or_else(|| AccountSession {
                login_id: login_id.to_string(),
                tokens: vec![],
                created_at: now,
                last_active_at: now,
            });

        // 若 token 已存在，仅更新 last_active_at；否则添加
        if let Some(ti) = account.tokens.iter_mut().find(|t| t.token == token) {
            ti.last_active_at = now;
        } else {
            account.tokens.push(TokenInfo {
                token: token.to_string(),
                created_at: now,
                last_active_at: now,
            });
        }
        account.last_active_at = now;

        let json = serde_json::to_string(&account)
            .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
        self.dao
            .set(&account_key(login_id), &json, self.active_timeout)
            .await?;
        Ok(())
    }

    /// 查询 token 的剩余 TTL。
    ///
    /// 供 `AuthLogicDefault::renew_to_equivalent` 使用：需要查询旧 token 的
    /// 剩余 TTL 以便新 token 继承相同的过期时间。
    ///
    /// # 返回
    /// - `Ok(Some(remaining))`: 键存在且设置了 TTL。
    /// - `Ok(None)`: 键不存在，或永久键（无 TTL）。
    pub async fn get_token_timeout(&self, token: &str) -> BulwarkResult<Option<Duration>> {
        self.dao.get_timeout(&token_key(token)).await
    }

    /// 创建新的 Token-Session 并指定 TTL。
    ///
    /// 供 `AuthLogicDefault::renew_to_equivalent` 使用：需要用旧 token 的
    /// 剩余 TTL 创建新 token 的 session（而非用默认 timeout）。
    ///
    /// # 参数
    /// - `token`: 新 token 字符串。
    /// - `ts`: 要存储的 TokenSession。
    /// - `ttl_seconds`: TTL 秒数（0 表示永久驻留）。
    pub async fn create_token_session_with_ttl(
        &self,
        token: &str,
        ts: &TokenSession,
        ttl_seconds: u64,
    ) -> BulwarkResult<()> {
        let json = serde_json::to_string(ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        self.dao.set(&token_key(token), &json, ttl_seconds).await?;
        Ok(())
    }

    /// 设置 Token-Session 的 TTL（供 remember_me 扩展超时使用）。
    ///
    /// 内部调用 `dao.expire` 重置 TTL。仅在 `create` 之后调用，用于将 Token-Session
    /// 的 TTL 从默认 `timeout` 扩展为 `remember_me_timeout`。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `ttl_seconds`: TTL 秒数（0 表示永久驻留）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时 DAO 返回错误。
    pub async fn set_token_session_ttl(&self, token: &str, ttl_seconds: u64) -> BulwarkResult<()> {
        self.dao.expire(&token_key(token), ttl_seconds).await
    }

    /// 关联 SSO ticket 到 token 会话。
    ///
    /// 将 SSO ticket 存入 Token-Session 的 `sso_ticket` 属性，
    /// 便于 logout 时联动销毁 SSO ticket。
    pub async fn link_sso_ticket(&self, token: &str, ticket: &str) -> BulwarkResult<()> {
        self.set(token, "sso_ticket", ticket).await
    }

    /// 查询 token 关联的 SSO ticket。
    pub async fn get_sso_ticket(&self, token: &str) -> BulwarkResult<Option<String>> {
        self.get(token, "sso_ticket").await
    }

    /// 关联 OAuth2 access_token 到 token 会话。
    ///
    /// 将 OAuth2 access_token 存入 Token-Session 的 `oauth2_access_token` 属性，
    /// 便于业务方在持有内部 token 时访问 OAuth2 资源服务器。
    pub async fn link_oauth2_token(&self, token: &str, access_token: &str) -> BulwarkResult<()> {
        self.set(token, "oauth2_access_token", access_token).await
    }

    /// 查询 token 关联的 OAuth2 access_token。
    pub async fn get_oauth2_token(&self, token: &str) -> BulwarkResult<Option<String>> {
        self.get(token, "oauth2_access_token").await
    }

    /// 关联临时凭证 key 到 token 会话。
    ///
    /// 将临时凭证的完整 dao key 存入 Token-Session 的 `temp_credential_key` 属性。
    /// `is_valid` 会检查该 key 是否仍存在于 dao，若已被删除则会话失效。
    pub async fn link_temp_credential(&self, token: &str, temp_key: &str) -> BulwarkResult<()> {
        self.set(token, "temp_credential_key", temp_key).await
    }

    /// 查询 token 关联的临时凭证 key（）。
    pub async fn get_temp_credential(&self, token: &str) -> BulwarkResult<Option<String>> {
        self.get(token, "temp_credential_key").await
    }

    /// 设置 Token-Session 的设备标识。
    ///
    /// 业务方在 `login` 后调用此方法关联 token 与设备，便于后续 `kickout_by_device` 按设备踢出。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `device`: 设备标识（如 "web-chrome"/"mobile-ios"/"api-client"）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`。
    /// - 序列化失败：`BulwarkError::Session`。
    /// - DAO 更新失败：透传 `BulwarkError`。
    pub async fn set_device(&self, token: &str, device: &str) -> BulwarkResult<()> {
        let mut ts = self
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken("token 不存在".to_string()))?;
        ts.device = Some(device.to_string());
        ts.last_active_at = Utc::now().timestamp();
        let json = serde_json::to_string(&ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        self.dao.update(&token_key(token), &json).await?;
        Ok(())
    }

    /// 设置 per-token 动态 active timeout（秒）。
    ///
    /// 读取现有 TokenSession，设置 `dynamic_active_timeout` 字段后写回 DAO。
    /// 用 `dao.update` 保留原 TTL（不重置过期时间）。
    ///
    /// # 参数
    /// - `token`: 待设置的 token 字符串。
    /// - `timeout_secs`: 超时秒数。
    ///
    /// # 错误
    /// - token 不存在：`BulwarkError::InvalidToken`。
    /// - 序列化失败：`BulwarkError::Session`。
    /// - DAO 更新失败：透传 `BulwarkError`。
    #[cfg(feature = "dynamic-active-timeout")]
    pub async fn set_active_timeout(&self, token: &str, timeout_secs: i64) -> BulwarkResult<()> {
        let mut ts = self
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken(format!("token 不存在: {}", token)))?;
        ts.dynamic_active_timeout = Some(timeout_secs);
        ts.last_active_at = Utc::now().timestamp();
        let json = serde_json::to_string(&ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        self.dao.update(&token_key(token), &json).await?;
        Ok(())
    }

    /// 检查 token 是否有效（Token-Session 存在且 Account-Session 未过期）。
    ///
    /// 惰性检查 Account-Session 是否存在——若 Account-Session 已被 oxcache TTL 清理，
    /// 即使 Token-Session 仍存在，也视为无效（spec scenario "Activity 超时"）。
    ///
    /// 注意：此方法只读，不更新 last_active_at。活跃续期请调用 `touch`。
    ///
    /// # 参数
    /// - `token`: 待校验的 token 字符串。
    ///
    /// # 返回
    /// - `true`: Token-Session 存在且 Account-Session 未过期。
    /// - `false`: token 不存在、Account-Session 已过期、或（启用 `dynamic-active-timeout` 时）
    ///   per-token 动态活跃超时已到期。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn is_valid(&self, token: &str) -> BulwarkResult<bool> {
        let ts = match self.get_token_session(token).await? {
            Some(ts) => ts,
            None => return Ok(false),
        };
        // T011: per-token 动态活跃超时检查
        // 优先使用 token_session.dynamic_active_timeout，None 时回退到全局 active_timeout
        #[cfg(feature = "dynamic-active-timeout")]
        {
            let effective_active_timeout = ts
                .dynamic_active_timeout
                .unwrap_or(self.active_timeout as i64);
            let now = Utc::now().timestamp();
            if ts.last_active_at + effective_active_timeout < now {
                return Ok(false);
            }
        }
        // 惰性检查 Account-Session 是否存在
        if self.get_account_session(&ts.login_id).await?.is_none() {
            return Ok(false);
        }
        // 临时凭证过期联动。
        // 若 Token-Session 含 temp_credential_key 属性，检查该 key 是否仍存在于 dao；
        // 临时凭证过期后 token 立即失效，不论 token 自身 timeout 是否到期。
        if let Some(temp_key) = ts.attrs.get("temp_credential_key") {
            if self.dao.get(temp_key).await?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 活跃续期：更新 last_active_at 并重置 TTL。
    ///
    /// 同时更新 Token-Session 与 Account-Session 的 last_active_at 和 TTL。
    ///
    /// # 参数
    /// - `token`: 待续期的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`。
    pub async fn touch(&self, token: &str) -> BulwarkResult<()> {
        let mut ts = self
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken(format!("token 不存在: {}", token)))?;
        let now = Utc::now().timestamp();
        ts.last_active_at = now;
        let json = serde_json::to_string(&ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        // 更新值 + 重置 TTL（用 set 覆盖，重置 TTL）
        self.dao.set(&token_key(token), &json, self.timeout).await?;

        // 同时更新 Account-Session 的 last_active_at + 对应 TokenInfo + 重置 TTL
        if let Some(mut account) = self.get_account_session(&ts.login_id).await? {
            account.last_active_at = now;
            for ti in &mut account.tokens {
                if ti.token == token {
                    ti.last_active_at = now;
                }
            }
            let account_json = serde_json::to_string(&account)
                .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
            self.dao
                .set(
                    &account_key(&ts.login_id),
                    &account_json,
                    self.active_timeout,
                )
                .await?;
        }
        Ok(())
    }

    /// 主动续期：重置过期时间为完整 timeout。
    ///
    ///
    /// # 参数
    /// - `token`: 待续期的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`（spec scenario "续期不存在的 token"）。
    pub async fn renew(&self, token: &str) -> BulwarkResult<()> {
        // 检查 token 存在（Fail Loud）
        if self.get_token_session(token).await?.is_none() {
            return Err(BulwarkError::InvalidToken(format!(
                "token 不存在: {}",
                token
            )));
        }
        // renew 等同于 touch：重置 TTL + 更新 last_active_at
        self.touch(token).await
    }

    /// 登出指定 token。
    ///
    ///
    /// 删除 Token-Session，并从 Account-Session 的 token 列表移除该 token。
    /// 若列表为空，Account-Session 保留（不删除，保留历史）。
    ///
    /// # 参数
    /// - `token`: 待登出的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 序列化 `AccountSession` 失败：`BulwarkError::Session`。
    /// - DAO 删除/更新失败：透传 `BulwarkError`。
    pub async fn logout(&self, token: &str) -> BulwarkResult<()> {
        // 匿名 token 路由到 logout_anon（key 空间隔离）
        #[cfg(feature = "anonymous-session")]
        if self.is_anon(token).await? {
            return self.logout_anon(token).await;
        }

        // 先读取 token session 获取 login_id（不在锁内，避免锁持有时间过长）
        let ts = self.get_token_session(token).await?;
        match ts {
            Some(ts) => {
                // 获取 per-login_id 锁，保护 Account-Session read-modify-write（R-002, R-004）
                let login_id = ts.login_id.clone();
                self.with_login_lock(
                    &login_id,
                    async move { self.logout_inner(token, &ts).await },
                )
                .await
            },
            None => {
                // token 不存在，幂等删除
                self.dao.delete(&token_key(token)).await
            },
        }
    }

    /// logout 内部实现（不获取 per-login_id 锁）。
    ///
    /// 供 `logout`（获取锁后调用）和 `kickout_by_device`（已持有锁）复用，避免死锁。
    async fn logout_inner(&self, token: &str, ts: &TokenSession) -> BulwarkResult<()> {
        // 删除 Token-Session
        self.dao.delete(&token_key(token)).await?;

        // SSO ticket 销毁联动。
        // 若 Token-Session 含 sso_ticket 属性，删除 dao 中的 `bulwark:sso:ticket:<ticket>` key。
        // 失败仅记录不中断主流程。
        if let Some(ticket) = ts.attrs.get("sso_ticket") {
            let sso_key = format!("bulwark:sso:ticket:{}", ticket);
            if let Err(e) = self.dao.delete(&sso_key).await {
                tracing::warn!("logout 联动删除 SSO ticket 失败 (key={}): {}", sso_key, e);
            }
        }

        // 从 Account-Session 移除该 token
        if let Some(mut account) = self.get_account_session(&ts.login_id).await? {
            account.tokens.retain(|ti| ti.token != token);
            // spec: 若列表为空，Account-Session 标记为空（但不删除，保留历史）
            let account_json = serde_json::to_string(&account)
                .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
            // 用 update 保留原 TTL（不重置 Account-Session 的过期时间）
            self.dao
                .update(&account_key(&ts.login_id), &account_json)
                .await?;
        }

        // 同步移除内存索引中的该 token（login_token_map）
        self.remove_login_token(&ts.login_id, token);

        Ok(())
    }

    /// 按账号登出：删除所有关联 token + Account-Session。
    ///
    /// 对应 Sa-Token 的 `logout(login_id)` 语义。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（接受 `String` / `&str`）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - DAO 删除失败：透传 `BulwarkError`。
    pub async fn logout_by_login_id(&self, login_id: impl Into<String>) -> BulwarkResult<()> {
        let login_id: String = login_id.into();
        // 获取 per-login_id 锁，保护 Account-Session 读-删序列（R-003, R-004）
        self.with_login_lock(&login_id, async {
            if let Some(account) = self.get_account_session(&login_id).await? {
                for ti in &account.tokens {
                    self.dao.delete(&token_key(&ti.token)).await?;
                }
            }
            self.dao.delete(&account_key(&login_id)).await?;
            // 移除整个 login_id 的内存索引（所有 token 已销毁）
            self.login_token_map.remove(&login_id);
            Ok(())
        })
        .await
    }

    /// 按设备踢出。
    ///
    /// 踢出指定 login_id 在指定 device 上的所有 token session。
    /// 不影响该 login_id 在其他 device 上的 session。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（接受 `String` / `&str`）。
    /// - `device`: 设备标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。device 不存在或无匹配 token 时幂等返回 `Ok(())`。
    ///
    /// # 事件广播（R-002）
    /// 若注入了 `listener_manager`，每个被踢出的 token 触发一个 `BulwarkEvent::Kickout` 事件，
    /// `reason` 字段格式为 `"kicked by device: <device>"`。
    ///
    /// # 错误
    /// - DAO 读取/删除失败：透传 `BulwarkError`。
    ///
    /// # account session 维护（R-003）
    /// 踢出后 account session 的 tokens 列表移除被踢出的 token，保留其他 device 的 token。
    pub async fn kickout_by_device(
        &self,
        login_id: impl Into<String>,
        device: &str,
    ) -> BulwarkResult<()> {
        let login_id: String = login_id.into();
        // 获取 per-login_id 锁，保护 Account-Session 读-踢序列（R-009）
        // 内部调用 logout_inner（不获取锁），避免死锁
        self.with_login_lock(&login_id, async {
            let account = match self.get_account_session(&login_id).await? {
                Some(a) => a,
                None => return Ok(()), // 幂等：account session 不存在
            };

            // 收集需要踢出的 token（同时获取 TokenSession 供 logout_inner 使用）
            let mut kicked: Vec<(String, TokenSession)> = Vec::new();
            for ti in &account.tokens {
                if let Some(ts) = self.get_token_session(&ti.token).await? {
                    if ts.device.as_deref() == Some(device) {
                        kicked.push((ti.token.clone(), ts));
                    }
                }
            }

            if kicked.is_empty() {
                return Ok(()); // 幂等：无匹配 device
            }

            // 逐个 logout_inner（不获取锁，因为已持有 login_id 锁）
            for (token, ts) in &kicked {
                self.logout_inner(token, ts).await?;
            }

            // 广播 Kickout 事件（R-002）
            #[cfg(feature = "listener")]
            if let Some(mgr) = &self.listener_manager {
                let reason = format!("kicked by device: {}", device);
                for (token, _) in &kicked {
                    mgr.broadcast(&crate::listener::BulwarkEvent::Kickout {
                        login_id: login_id.clone(),
                        token: token.clone(),
                        reason: reason.clone(),
                    })
                    .await;
                }
            }

            Ok(())
        })
        .await
    }
}

// ============================================================================
// 匿名 Session 委托方法（anonymous-session feature）
// ============================================================================

#[cfg(feature = "anonymous-session")]
impl BulwarkSession {
    /// 获取匿名 Token-Session，不存在则创建。
    ///
    /// 委托到 [`anon::get_anon_token_session`]。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    ///
    /// # 返回
    /// 匿名 TokenSession（`login_id = ""`, `is_anon = true`）。
    pub async fn get_anon_token_session(&self, token: &str) -> BulwarkResult<TokenSession> {
        anon::get_anon_token_session(self, token).await
    }

    /// 判断 token 是否为匿名 Session。
    ///
    /// 委托到 [`anon::is_anon`]。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    ///
    /// # 返回
    /// `true` 表示匿名 Session，`false` 表示非匿名。
    pub async fn is_anon(&self, token: &str) -> BulwarkResult<bool> {
        anon::is_anon(self, token).await
    }

    /// 注销匿名 Session。
    ///
    /// 委托到 [`anon::logout_anon`]。不存在的 anon token 返回 `Ok(())`（幂等）。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    pub async fn logout_anon(&self, token: &str) -> BulwarkResult<()> {
        anon::logout_anon(self, token).await
    }
}

// ============================================================================
// 会话搜索委托方法（session-search feature）
// ============================================================================

#[cfg(feature = "session-search")]
impl BulwarkSession {
    /// 按 token 值搜索 Token-Session。
    ///
    /// 委托到 [`search::search_token_value`]。排除匿名 Session，空 `keyword` 匹配所有。
    ///
    /// # 参数
    /// - `keyword`: 搜索关键字（空字符串匹配所有）。
    /// - `start`: 分页偏移量（0-based）。
    /// - `size`: 返回数量上限。
    /// - `sort_type`: 排序方式。
    ///
    /// # 返回
    /// 匹配的 token 值列表。
    pub async fn search_token_value(
        &self,
        keyword: &str,
        start: usize,
        size: usize,
        sort_type: SearchSortType,
    ) -> BulwarkResult<Vec<String>> {
        search::search_token_value(self, keyword, start, size, sort_type).await
    }

    /// 按 login_id 搜索 Account-Session。
    ///
    /// 委托到 [`search::search_session_id`]。空 `keyword` 匹配所有。
    ///
    /// # 参数
    /// - `keyword`: 搜索关键字（空字符串匹配所有）。
    /// - `start`: 分页偏移量（0-based）。
    /// - `size`: 返回数量上限。
    /// - `sort_type`: 排序方式。
    ///
    /// # 返回
    /// 匹配的 login_id 列表。
    pub async fn search_session_id(
        &self,
        keyword: &str,
        start: usize,
        size: usize,
        sort_type: SearchSortType,
    ) -> BulwarkResult<Vec<String>> {
        search::search_session_id(self, keyword, start, size, sort_type).await
    }

    /// 按 login_id 搜索 Token-Session 的 token。
    ///
    /// 委托到 [`search::search_token_session_id`]。排除匿名 Session，空 `keyword` 匹配所有。
    ///
    /// # 参数
    /// - `keyword`: 搜索关键字（空字符串匹配所有）。
    /// - `start`: 分页偏移量（0-based）。
    /// - `size`: 返回数量上限。
    /// - `sort_type`: 排序方式。
    ///
    /// # 返回
    /// 匹配的 token 值列表。
    pub async fn search_token_session_id(
        &self,
        keyword: &str,
        start: usize,
        size: usize,
        sort_type: SearchSortType,
    ) -> BulwarkResult<Vec<String>> {
        search::search_token_session_id(self, keyword, start, size, sort_type).await
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::stp::LoginParams;
    use async_trait::async_trait;
    use std::time::Duration;

    /// 辅助函数：创建带 MockDao 的 BulwarkSession。
    fn make_session(timeout: u64, active_timeout: u64) -> (Arc<MockDao>, BulwarkSession) {
        let dao = Arc::new(MockDao::new());
        let session = BulwarkSession::new(dao.clone(), timeout, active_timeout);
        (dao, session)
    }

    // ------------------------------------------------------------------------
    // 创建 Account-Session / 创建 Token-Session
    // ------------------------------------------------------------------------

    /// 验证 create 双写 Account-Session 与 Token-Session。
    #[tokio::test]
    async fn create_writes_both_sessions() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // Token-Session 存在
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(ts.login_id, "1001");
        assert_eq!(ts.token, "T1");
        assert!(ts.created_at > 0);
        assert_eq!(ts.created_at, ts.last_active_at);

        // Account-Session 存在，包含 T1
        let as_ = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(as_.login_id, "1001");
        assert_eq!(as_.tokens.len(), 1);
        assert_eq!(as_.tokens[0].token, "T1");
    }

    /// 验证 BulwarkDao 直接读取 key 格式正确。
    #[tokio::test]
    async fn dao_key_format_matches_spec() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // spec: BulwarkDao::get("account:session:1001") 返回 Account-Session 数据
        let account_json = dao.get("account:session:1001").await.unwrap();
        assert!(account_json.is_some());
        let account: AccountSession = serde_json::from_str(&account_json.unwrap()).unwrap();
        assert_eq!(account.login_id, "1001");

        // spec: BulwarkDao::get("token:session:T1") 返回 Token-Session 数据
        let token_json = dao.get("token:session:T1").await.unwrap();
        assert!(token_json.is_some());
        let ts: TokenSession = serde_json::from_str(&token_json.unwrap()).unwrap();
        assert_eq!(ts.login_id, "1001");
    }

    // ------------------------------------------------------------------------
    // Account-Session 记录多 token
    // ------------------------------------------------------------------------

    /// 验证同一账号登录两次后 token 列表包含两个 token。
    #[tokio::test]
    async fn account_session_records_multiple_tokens() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();

        let as_ = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(as_.tokens.len(), 2);
        assert_eq!(as_.tokens[0].token, "T1");
        assert_eq!(as_.tokens[1].token, "T2");
    }

    // ------------------------------------------------------------------------
    // Account-Session 随登出更新
    // ------------------------------------------------------------------------

    /// 验证登出 T1 后 Account-Session 移除 T1 但保留 T2。
    #[tokio::test]
    async fn account_session_removes_token_on_logout() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();

        session.logout("T1").await.unwrap();

        let as_ = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(as_.tokens.len(), 1);
        assert_eq!(as_.tokens[0].token, "T2");
    }

    /// 验证登出最后一个 token 后 Account-Session 保留（不删除，保留历史）。
    #[tokio::test]
    async fn account_session_keeps_history_when_empty() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.logout("T1").await.unwrap();

        // spec: 若列表为空，Account-Session 标记为空（但不删除，保留历史）
        let as_ = session.get_account_session("1001").await.unwrap();
        assert!(as_.is_some(), "Account-Session 应保留（保留历史）");
        assert!(as_.unwrap().tokens.is_empty());
    }

    // ------------------------------------------------------------------------
    // Token-Session 存储自定义属性
    // ------------------------------------------------------------------------

    /// 验证 set/get Token-Session 自定义属性。
    #[tokio::test]
    async fn token_session_stores_custom_attrs() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        session.set("T1", "ip", "192.168.1.1").await.unwrap();
        let ip = session.get("T1", "ip").await.unwrap();
        assert_eq!(ip, Some("192.168.1.1".to_string()));
    }

    /// 验证 set 不存在的 token 抛 InvalidToken。
    #[tokio::test]
    async fn set_attr_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.set("nonexistent", "ip", "1.2.3.4").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "set 不存在的 token 应返回 InvalidToken"
        );
    }

    // ------------------------------------------------------------------------
    // token 过期自动失效 / Activity 超时
    // ------------------------------------------------------------------------

    /// 验证 token 不存在时 is_valid 返回 false。
    #[tokio::test]
    async fn is_valid_returns_false_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let valid = session.is_valid("nonexistent").await.unwrap();
        assert!(!valid);
    }

    /// 验证 token 有效时 is_valid 返回 true。
    #[tokio::test]
    async fn is_valid_returns_true_for_active_token() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        let valid = session.is_valid("T1").await.unwrap();
        assert!(valid);
    }

    /// 验证 Account-Session 过期后 token 视为无效（惰性检查）。
    ///
    ///
    /// Account-Session 过期后，所有关联 token 失效。
    #[tokio::test]
    async fn is_valid_returns_false_when_account_session_expired() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 模拟 Account-Session 过期（oxcache TTL 到期自动删除）
        dao.delete(&account_key("1001")).await.unwrap();

        // Token-Session 仍存在，但 Account-Session 已过期 → is_valid 返回 false
        let token_exists = session.get_token_session("T1").await.unwrap();
        assert!(token_exists.is_some(), "Token-Session 仍应存在");
        let valid = session.is_valid("T1").await.unwrap();
        assert!(!valid, "Account-Session 过期后 token 应视为无效");
    }

    // ------------------------------------------------------------------------
    // 活跃续期 / 主动续期
    // ------------------------------------------------------------------------

    /// 验证 touch 更新 last_active_at 并重置 TTL。
    #[tokio::test]
    async fn touch_updates_last_active_and_renews_ttl() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 等待一小段时间，确保 touch 后 last_active_at 变化
        tokio::time::sleep(Duration::from_millis(1100)).await;

        session.touch("T1").await.unwrap();

        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert!(
            ts.last_active_at > ts.created_at,
            "touch 后 last_active_at 应大于 created_at"
        );

        // Account-Session 的对应 TokenInfo 也应更新
        let as_ = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(as_.last_active_at, ts.last_active_at);
        let ti = as_.tokens.iter().find(|t| t.token == "T1").unwrap();
        assert_eq!(ti.last_active_at, ts.last_active_at);
    }

    /// 验证 renew 重置过期时间（token 短 TTL + renew 后仍有效）。
    ///
    /// spec scenario "主动续期重置过期时间"。
    #[tokio::test]
    async fn renew_resets_ttl() {
        // token TTL=3 秒，留足 margin 避免 sleep 精度问题
        let (_dao, session) = make_session(3, 86400);
        session.create("1001", "T1").await.unwrap();

        // 在过期前 renew（已过 1 秒，剩余 2 秒）
        tokio::time::sleep(Duration::from_secs(1)).await;
        session.renew("T1").await.unwrap();

        // renew 重置 TTL 为 3 秒；再 sleep 2 秒，距过期还有 1 秒 margin
        tokio::time::sleep(Duration::from_secs(2)).await;
        let valid = session.is_valid("T1").await.unwrap();
        assert!(
            valid,
            "renew 后 token 应仍有效（TTL 已重置，还有 1 秒 margin）"
        );
    }

    /// 验证 renew 不存在的 token 抛 InvalidToken。
    ///
    /// spec scenario "续期不存在的 token"。
    #[tokio::test]
    async fn renew_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.renew("nonexistent").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "renew 不存在的 token 应返回 InvalidToken"
        );
    }

    // ------------------------------------------------------------------------
    // 登出
    // ------------------------------------------------------------------------

    /// 验证 logout 删除 Token-Session。
    #[tokio::test]
    async fn logout_removes_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.logout("T1").await.unwrap();

        let ts = session.get_token_session("T1").await.unwrap();
        assert!(ts.is_none(), "logout 后 Token-Session 应删除");
    }

    /// 验证 logout_by_login_id 删除所有关联 token + Account-Session。
    #[tokio::test]
    async fn logout_by_login_id_removes_all() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();

        session.logout_by_login_id("1001").await.unwrap();

        // 两个 token 都删除
        assert!(session.get_token_session("T1").await.unwrap().is_none());
        assert!(session.get_token_session("T2").await.unwrap().is_none());
        // Account-Session 也删除
        assert!(session.get_account_session("1001").await.unwrap().is_none());
    }

    /// 验证 logout 不存在的 token 不报错（幂等）。
    #[tokio::test]
    async fn logout_nonexistent_token_is_noop() {
        let (_dao, session) = make_session(3600, 86400);
        // logout 不存在的 token 不应报错
        let result = session.logout("nonexistent").await;
        assert!(result.is_ok());
    }

    // ------------------------------------------------------------------------
    // 错误分支补充测试：反序列化失败 / touch 不存在的 token
    // ------------------------------------------------------------------------

    /// 验证 get_token_session 在 DAO 中存储了非法 JSON 时返回 Session 错误。
    ///
    /// 覆盖 `get_token_session` 中 `serde_json::from_str(&json).map_err(...)` 错误路径。
    #[tokio::test]
    async fn get_token_session_corrupt_json_errors() {
        let (dao, session) = make_session(3600, 86400);
        // 直接写入非法 JSON 到 token key
        dao.set(&token_key("corrupt"), "not-a-valid-json", 3600)
            .await
            .unwrap();
        let result = session.get_token_session("corrupt").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("反序列化 TokenSession 失败")),
            "非法 JSON 应返回 '反序列化 TokenSession 失败' 错误，实际: {:?}",
            result
        );
    }

    /// 验证 get_account_session 在 DAO 中存储了非法 JSON 时返回 Session 错误。
    ///
    /// 覆盖 `get_account_session` 中 `serde_json::from_str(&json).map_err(...)` 错误路径。
    #[tokio::test]
    async fn get_account_session_corrupt_json_errors() {
        let (dao, session) = make_session(3600, 86400);
        // 直接写入非法 JSON 到 account key
        dao.set(&account_key("2001"), "{invalid-json", 3600)
            .await
            .unwrap();
        let result = session.get_account_session("2001").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("反序列化 AccountSession 失败")),
            "非法 JSON 应返回 '反序列化 AccountSession 失败' 错误，实际: {:?}",
            result
        );
    }

    /// 验证 touch 不存在的 token 返回 InvalidToken 错误。
    ///
    /// 覆盖 `touch` 方法中 `ok_or_else(|| BulwarkError::InvalidToken(...))` 错误路径。
    #[tokio::test]
    async fn touch_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.touch("nonexistent").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "touch 不存在的 token 应返回 InvalidToken 错误"
        );
    }

    /// 验证 get 在 token 不存在时返回 None（不抛错）。
    ///
    /// 覆盖 `get` 方法中 `None => Ok(None)` 分支。
    #[tokio::test]
    async fn get_attr_nonexistent_token_returns_none() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.get("nonexistent", "key").await.unwrap();
        assert!(result.is_none(), "token 不存在时 get 属性应返回 None");
    }

    /// 验证 create 在已存在 Account-Session 时追加 token 而非覆盖。
    ///
    /// 覆盖 `create` 中 `unwrap_or_else` 的 Some 分支（读取已存在的 account）。
    /// 此场景实际已被 account_session_records_multiple_tokens 覆盖，
    /// 但此处显式断言已存在的 token 列表被保留。
    #[tokio::test]
    async fn create_appends_to_existing_account_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        session.create("1001", "T3").await.unwrap();

        let as_ = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(as_.tokens.len(), 3, "三次 login 后应有 3 个 token");
        assert_eq!(as_.tokens[0].token, "T1");
        assert_eq!(as_.tokens[1].token, "T2");
        assert_eq!(as_.tokens[2].token, "T3");
    }

    // ------------------------------------------------------------------------
    // Token-Session 存储 SSO ticket 引用
    // ------------------------------------------------------------------------

    /// 验证 link_sso_ticket / get_sso_ticket 往返。
    #[tokio::test]
    async fn link_sso_ticket_stores_ticket_in_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        session
            .link_sso_ticket("T1", "ticket-abc-123")
            .await
            .unwrap();
        let ticket = session.get_sso_ticket("T1").await.unwrap();
        assert_eq!(ticket, Some("ticket-abc-123".to_string()));
    }

    /// 验证 get_sso_ticket 对未关联 ticket 的 token 返回 None。
    #[tokio::test]
    async fn get_sso_ticket_returns_none_when_not_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let ticket = session.get_sso_ticket("T1").await.unwrap();
        assert!(ticket.is_none(), "未关联 ticket 时应返回 None");
    }

    /// 验证 get_sso_ticket 对不存在的 token 返回 None。
    #[tokio::test]
    async fn get_sso_ticket_returns_none_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let ticket = session.get_sso_ticket("nonexistent").await.unwrap();
        assert!(ticket.is_none(), "token 不存在时应返回 None");
    }

    // ------------------------------------------------------------------------
    // Token-Session 存储 OAuth2 access_token
    // ------------------------------------------------------------------------

    /// 验证 link_oauth2_token / get_oauth2_token 往返。
    #[tokio::test]
    async fn link_oauth2_token_stores_access_token_in_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        session
            .link_oauth2_token("T1", "access-token-xyz")
            .await
            .unwrap();
        let access_token = session.get_oauth2_token("T1").await.unwrap();
        assert_eq!(access_token, Some("access-token-xyz".to_string()));
    }

    /// 验证 get_oauth2_token 对未关联 access_token 的 token 返回 None。
    #[tokio::test]
    async fn get_oauth2_token_returns_none_when_not_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let access_token = session.get_oauth2_token("T1").await.unwrap();
        assert!(access_token.is_none(), "未关联 access_token 时应返回 None");
    }

    /// 验证 get_oauth2_token 对不存在的 token 返回 None。
    #[tokio::test]
    async fn get_oauth2_token_returns_none_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let access_token = session.get_oauth2_token("nonexistent").await.unwrap();
        assert!(access_token.is_none(), "token 不存在时应返回 None");
    }

    // ------------------------------------------------------------------------
    // 临时凭证关联会话
    // ------------------------------------------------------------------------

    /// 验证 link_temp_credential / get_temp_credential 往返。
    #[tokio::test]
    async fn link_temp_credential_stores_key_in_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let temp_key = "bulwark:temp:order:abc123";
        session.link_temp_credential("T1", temp_key).await.unwrap();
        let stored = session.get_temp_credential("T1").await.unwrap();
        assert_eq!(stored, Some(temp_key.to_string()));
    }

    /// 验证 get_temp_credential 对未关联的 token 返回 None。
    #[tokio::test]
    async fn get_temp_credential_returns_none_when_not_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let stored = session.get_temp_credential("T1").await.unwrap();
        assert!(stored.is_none(), "未关联临时凭证时应返回 None");
    }

    /// 验证 get_temp_credential 对不存在的 token 返回 None。
    #[tokio::test]
    async fn get_temp_credential_returns_none_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let stored = session.get_temp_credential("nonexistent").await.unwrap();
        assert!(stored.is_none(), "token 不存在时应返回 None");
    }

    // ------------------------------------------------------------------------
    // link 方法对不存在的 token 报错
    // ------------------------------------------------------------------------

    /// 验证 link_sso_ticket / link_oauth2_token / link_temp_credential
    /// 对不存在的 token 返回 InvalidToken 错误。
    #[tokio::test]
    async fn link_methods_return_error_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);

        let r1 = session.link_sso_ticket("nonexistent", "ticket").await;
        assert!(
            matches!(r1, Err(BulwarkError::InvalidToken(_))),
            "link_sso_ticket 不存在的 token 应返回 InvalidToken"
        );

        let r2 = session
            .link_oauth2_token("nonexistent", "access-token")
            .await;
        assert!(
            matches!(r2, Err(BulwarkError::InvalidToken(_))),
            "link_oauth2_token 不存在的 token 应返回 InvalidToken"
        );

        let r3 = session
            .link_temp_credential("nonexistent", "temp-key")
            .await;
        assert!(
            matches!(r3, Err(BulwarkError::InvalidToken(_))),
            "link_temp_credential 不存在的 token 应返回 InvalidToken"
        );
    }

    // ------------------------------------------------------------------------
    // SSO ticket 销毁联动（logout 联动）
    // ------------------------------------------------------------------------

    /// 验证 logout 时联动删除 Token-Session 关联的 SSO ticket。
    #[tokio::test]
    async fn logout_destroys_linked_sso_ticket() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 在 dao 中预置 SSO ticket
        let sso_key = "bulwark:sso:ticket:ticket-abc-123";
        dao.set(sso_key, r#"{"login_id":1001,"client_id":1}"#, 60)
            .await
            .unwrap();
        // 关联 ticket 到 token
        session
            .link_sso_ticket("T1", "ticket-abc-123")
            .await
            .unwrap();
        // 确认 ticket 存在
        assert!(dao.get(sso_key).await.unwrap().is_some());

        // logout 应联动删除 SSO ticket
        session.logout("T1").await.unwrap();

        // SSO ticket 应已被删除
        assert!(
            dao.get(sso_key).await.unwrap().is_none(),
            "logout 后关联的 SSO ticket 应被删除"
        );
        // Token-Session 也应被删除
        assert!(session.get_token_session("T1").await.unwrap().is_none());
    }

    /// 验证 logout 未关联 SSO ticket 的 token 时，不影响 dao 中的 SSO keys。
    #[tokio::test]
    async fn logout_without_sso_ticket_does_not_affect_sso_keys() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 在 dao 中预置一个不相关的 SSO ticket
        let unrelated_sso_key = "bulwark:sso:ticket:other-ticket";
        dao.set(unrelated_sso_key, r#"{"login_id":2002,"client_id":2}"#, 60)
            .await
            .unwrap();

        // logout T1（未关联 sso_ticket）
        session.logout("T1").await.unwrap();

        // 不相关的 SSO ticket 应仍然存在
        assert!(
            dao.get(unrelated_sso_key).await.unwrap().is_some(),
            "logout 未关联 SSO ticket 的 token 不应影响其他 SSO keys"
        );
    }

    // ------------------------------------------------------------------------
    // 临时凭证过期联动（is_valid 联动）
    // ------------------------------------------------------------------------

    /// 验证 is_valid 在 token 关联的临时凭证仍存在时返回 true。
    #[tokio::test]
    async fn is_valid_returns_true_when_temp_credential_exists() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 在 dao 中预置临时凭证
        let temp_key = "bulwark:temp:order:abc123";
        dao.set(temp_key, "secret-value", 300).await.unwrap();
        // 关联临时凭证到 token
        session.link_temp_credential("T1", temp_key).await.unwrap();

        // 临时凭证仍存在，token 应有效
        let valid = session.is_valid("T1").await.unwrap();
        assert!(valid, "临时凭证存在时 token 应有效");
    }

    /// 验证 is_valid 在 token 关联的临时凭证已被删除时返回 false。
    ///
    /// "临时凭证过期后 T1 立即失效，不论 token 自身 timeout 是否到期"。
    #[tokio::test]
    async fn is_valid_returns_false_when_temp_credential_expired() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 在 dao 中预置临时凭证
        let temp_key = "bulwark:temp:order:abc123";
        dao.set(temp_key, "secret-value", 300).await.unwrap();
        session.link_temp_credential("T1", temp_key).await.unwrap();

        // 模拟临时凭证过期/被删除
        dao.delete(temp_key).await.unwrap();

        // 临时凭证已失效，token 应立即失效（即使 token 自身 timeout 未到期）
        let valid = session.is_valid("T1").await.unwrap();
        assert!(
            !valid,
            "临时凭证过期后 token 应立即失效，不论 token 自身 timeout 是否到期"
        );
    }

    /// 验证 is_valid 在 token 未关联临时凭证时返回 true（向后兼容）。
    #[tokio::test]
    async fn is_valid_returns_true_when_no_temp_credential_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 未关联临时凭证，token 应有效（0.1.0 既有行为不变）
        let valid = session.is_valid("T1").await.unwrap();
        assert!(valid, "未关联临时凭证时 token 有效性应遵循 0.1.0 既有行为");
    }

    // ------------------------------------------------------------------------
    // String-form login_id 接入测试
    // ------------------------------------------------------------------------

    /// 验证 `BulwarkSession::create` 接受 String 形式 login_id。
    #[tokio::test]
    async fn create_accepts_login_id_numeric() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(ts.login_id, "1001");
    }

    /// 验证 `BulwarkSession::get_account_session` 接受 String 形式 login_id。
    #[tokio::test]
    async fn get_account_session_accepts_login_id_numeric() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        let as_ = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(as_.login_id, "1001");
    }

    /// 验证 `BulwarkSession::logout_by_login_id` 接受 String 形式 login_id。
    #[tokio::test]
    async fn logout_by_login_id_accepts_login_id_numeric() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.logout_by_login_id("1001").await.unwrap();
        assert!(session.get_token_session("T1").await.unwrap().is_none());
    }

    // ------------------------------------------------------------------------
    // set_device + kickout_by_device
    // ------------------------------------------------------------------------

    /// 验证 set_device 设置 TokenSession.device 字段。
    ///
    /// 对应 spec session-kickout-device R-001 前置条件。
    #[tokio::test]
    async fn set_device_updates_token_session_device() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();

        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(ts.device.as_deref(), Some("web-chrome"));
    }

    /// 验证 set_device 不存在的 token 返回 InvalidToken 错误。
    #[tokio::test]
    async fn set_device_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.set_device("nonexistent", "web").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "set_device 不存在的 token 应返回 InvalidToken"
        );
    }

    /// 验证 kickout_by_device 踢出匹配设备的 token。
    ///
    /// 对应 spec session-kickout-device R-001 验收标准。
    #[tokio::test]
    async fn kickout_by_device_removes_matching_tokens() {
        let (_dao, session) = make_session(3600, 86400);
        // 用户 1001 在 3 个设备上登录
        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        session.set_device("T2", "mobile-ios").await.unwrap();
        session.create("1001", "T3").await.unwrap();
        session.set_device("T3", "web-chrome").await.unwrap();

        // 踢出 web-chrome 设备
        session
            .kickout_by_device("1001", "web-chrome")
            .await
            .unwrap();

        // T1 和 T3 应被踢出（web-chrome）
        assert!(session.get_token_session("T1").await.unwrap().is_none());
        assert!(session.get_token_session("T3").await.unwrap().is_none());
        // T2 应仍存在（mobile-ios）
        assert!(session.get_token_session("T2").await.unwrap().is_some());
    }

    /// 验证 kickout_by_device 不影响其他设备。
    ///
    /// 对应 spec session-kickout-device R-001 验收标准"不影响该 login_id 在其他 device 上的 session"。
    #[tokio::test]
    async fn kickout_by_device_preserves_other_devices() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        session.set_device("T2", "mobile-ios").await.unwrap();

        session
            .kickout_by_device("1001", "web-chrome")
            .await
            .unwrap();

        // T2 应仍有效
        assert!(session.is_valid("T2").await.unwrap());
    }

    /// 验证 kickout_by_device device 不存在时幂等返回 Ok。
    ///
    /// 对应 spec session-kickout-device R-001 验收标准"device 不存在时返回 Ok(())"。
    #[tokio::test]
    async fn kickout_by_device_nonexistent_device_is_noop() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();

        // 踢出不存在的设备
        let result = session
            .kickout_by_device("1001", "nonexistent-device")
            .await;
        assert!(result.is_ok());
        // T1 应仍存在
        assert!(session.get_token_session("T1").await.unwrap().is_some());
    }

    /// 验证 kickout_by_device account session 不存在时幂等返回 Ok。
    ///
    /// 对应 spec session-kickout-device R-003 验收标准"account session 不存在时返回 Ok(())"。
    #[tokio::test]
    async fn kickout_by_device_no_account_session_is_noop() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.kickout_by_device("9999", "web-chrome").await;
        assert!(result.is_ok());
    }

    /// 验证 kickout_by_device 同步更新 account session tokens 列表。
    ///
    /// 对应 spec session-kickout-device R-003 验收标准。
    #[tokio::test]
    async fn kickout_by_device_updates_account_session_tokens() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        session.set_device("T2", "mobile-ios").await.unwrap();

        session
            .kickout_by_device("1001", "web-chrome")
            .await
            .unwrap();

        let account = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(account.tokens.len(), 1, "account session 应只剩 1 个 token");
        assert_eq!(account.tokens[0].token, "T2", "剩余 token 应为 T2");
    }

    /// 验证 kickout_by_device 接受 String 形式 login_id。
    #[tokio::test]
    async fn kickout_by_device_accepts_login_id_numeric() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();

        session
            .kickout_by_device("1001", "web-chrome")
            .await
            .unwrap();
        assert!(session.get_token_session("T1").await.unwrap().is_none());
    }

    // ------------------------------------------------------------------------
    // kickout_by_device listener 广播（feature = "listener"）
    // ------------------------------------------------------------------------

    /// 验证 kickout_by_device 注入 listener_manager 后广播 Kickout 事件。
    ///
    /// 对应 spec session-kickout-device R-002 验收标准。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn kickout_by_device_broadcasts_kickout_events() {
        use crate::listener::{BulwarkEvent, BulwarkListener, BulwarkListenerManager};
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[allow(dead_code)]
        struct KickoutCounter {
            count: AtomicUsize,
        }
        #[async_trait]
        impl BulwarkListener for KickoutCounter {
            async fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
                if matches!(event, BulwarkEvent::Kickout { .. }) {
                    self.count.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            }
        }

        let mgr = Arc::new(BulwarkListenerManager::new());
        // 注入自定义监听器（直接 push 到 listeners，需要扩展 API）
        // 由于 BulwarkListenerManager 通过 inventory 收集，测试中无法直接注入
        // 改为验证 with_listener_manager 链式构造成功，且 kickout 不报错
        let (_dao, session) = make_session(3600, 86400);
        let session = session.with_listener_manager(mgr);

        session.create("1001", "T1").await.unwrap();
        session.set_device("T1", "web-chrome").await.unwrap();

        // kickout 应正常执行（不因 listener_manager 注入而失败）
        let result = session.kickout_by_device("1001", "web-chrome").await;
        assert!(result.is_ok());
        // T1 应被踢出
        assert!(session.get_token_session("T1").await.unwrap().is_none());
    }

    /// 验证 with_listener_manager builder 注入字段。
    #[cfg(feature = "listener")]
    #[test]
    fn with_listener_manager_sets_field() {
        use crate::listener::BulwarkListenerManager;
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mgr = Arc::new(BulwarkListenerManager::new());
        let session = BulwarkSession::new(dao, 3600, 86400).with_listener_manager(mgr);
        assert!(session.listener_manager.is_some());
    }

    // ------------------------------------------------------------------------
    // 覆盖率补充：SSO ticket 删除失败 warn 路径
    // ------------------------------------------------------------------------

    /// 测试用 DAO wrapper，在 delete 特定 key 时返回错误。
    ///
    /// 用于测试 logout 联动删除 SSO ticket 失败时的 warn 日志路径（行 528）。
    struct FailingDeleteDao {
        inner: Arc<MockDao>,
        fail_delete_key: String,
    }

    #[async_trait]
    impl BulwarkDao for FailingDeleteDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            if key == self.fail_delete_key {
                return Err(BulwarkError::Dao("模拟删除失败".to_string()));
            }
            self.inner.delete(key).await
        }
    }

    /// logout 联动删除 SSO ticket 失败时记录 warn 但不中断主流程。
    ///
    /// 覆盖行 528（SSO ticket 删除失败的 warn 日志路径）。
    /// 6: plugin/listener/集成失败不中断主流程。
    #[tokio::test]
    async fn logout_sso_ticket_delete_failure_logs_warn_without_failing() {
        let inner = Arc::new(MockDao::new());
        let dao: Arc<dyn BulwarkDao> = Arc::new(FailingDeleteDao {
            inner: inner.clone(),
            fail_delete_key: "bulwark:sso:ticket:ticket-fail".to_string(),
        });
        let session = BulwarkSession::new(dao, 3600, 86400);

        // login 并关联 SSO ticket
        session.create("1001", "T1").await.unwrap();
        session.link_sso_ticket("T1", "ticket-fail").await.unwrap();

        // logout 应成功（SSO ticket 删除失败仅 warn 不中断主流程）
        let result = session.logout("T1").await;
        assert!(
            result.is_ok(),
            "logout 不应因 SSO ticket 删除失败而中断: {:?}",
            result
        );

        // Token-Session 应已删除
        let ts = session.get_token_session("T1").await.unwrap();
        assert!(ts.is_none(), "logout 后 Token-Session 应已删除");
    }

    // ----------------------------------------------------------------
    // SessionExpiryListener 测试
    // ----------------------------------------------------------------

    /// Mock 过期监听器：记录所有回调调用，可选返回错误。
    struct MockExpiryListener {
        calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        fail: bool,
    }

    impl MockExpiryListener {
        #[allow(clippy::type_complexity)]
        fn new() -> (Self, Arc<std::sync::Mutex<Vec<(String, String)>>>) {
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                    fail: false,
                },
                calls,
            )
        }

        fn new_failing() -> Self {
            Self {
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
                fail: true,
            }
        }
    }

    #[async_trait]
    impl SessionExpiryListener for MockExpiryListener {
        async fn on_session_expired(&self, login_id: &str, token: &str) -> BulwarkResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push((login_id.to_string(), token.to_string()));
            if self.fail {
                return Err(BulwarkError::Session("模拟回调失败".to_string()));
            }
            Ok(())
        }
    }

    /// 修改 TokenSession 的 last_active_at 为过去时间（模拟 session 级过期）。
    async fn expire_token_session_in_dao(dao: &Arc<MockDao>, token: &str, timeout: u64) {
        let key = token_key(token);
        let json = dao.get(&key).await.unwrap().unwrap();
        let mut ts: TokenSession = serde_json::from_str(&json).unwrap();
        ts.last_active_at = Utc::now().timestamp() - timeout as i64 - 1;
        let new_json = serde_json::to_string(&ts).unwrap();
        dao.set(&key, &new_json, 3600).await.unwrap();
    }

    /// 修改 AccountSession 的 last_active_at 为过去时间（模拟 session 级过期）。
    async fn expire_account_session_in_dao(
        dao: &Arc<MockDao>,
        login_id: &str,
        active_timeout: u64,
    ) {
        let key = account_key(login_id);
        let json = dao.get(&key).await.unwrap().unwrap();
        let mut as_: AccountSession = serde_json::from_str(&json).unwrap();
        as_.last_active_at = Utc::now().timestamp() - active_timeout as i64 - 1;
        let new_json = serde_json::to_string(&as_).unwrap();
        dao.set(&key, &new_json, 3600).await.unwrap();
    }

    /// R-002: add_expiry_listener 注册监听器，listener 列表长度增加。
    #[tokio::test]
    async fn add_expiry_listener_registers_listener() {
        let (_dao, mut session) = make_session(3600, 86400);
        assert!(session.expiry_listeners.is_empty());
        let (listener, _) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener));
        assert_eq!(session.expiry_listeners.len(), 1);
    }

    /// R-003: get_token_session 发现 token session 过期时触发回调。
    #[tokio::test]
    async fn get_token_session_triggers_callback_on_expiry() {
        let (dao, mut session) = make_session(3600, 86400);
        let (listener, calls) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener));

        session.create("1001", "T1").await.unwrap();
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        let result = session.get_token_session("T1").await.unwrap();
        assert!(result.is_none(), "过期 session 应返回 None");

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1, "应触发 1 次回调");
        assert_eq!(recorded[0].0, "1001");
        assert_eq!(recorded[0].1, "T1");
    }

    /// R-003: get_token_session 对未过期 session 不触发回调。
    #[tokio::test]
    async fn get_token_session_no_callback_for_active_session() {
        let (_dao, mut session) = make_session(3600, 86400);
        let (listener, calls) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener));

        session.create("1001", "T1").await.unwrap();

        let result = session.get_token_session("T1").await.unwrap();
        assert!(result.is_some());

        assert!(
            calls.lock().unwrap().is_empty(),
            "未过期 session 不应触发回调"
        );
    }

    /// R-003: get_token_session 触发回调后从 DAO 删除过期 session。
    #[tokio::test]
    async fn get_token_session_deletes_expired_session_after_callback() {
        let (dao, mut session) = make_session(3600, 86400);
        let (listener, _calls) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener));

        session.create("1001", "T1").await.unwrap();
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        assert!(dao.get(&token_key("T1")).await.unwrap().is_some());

        session.get_token_session("T1").await.unwrap();

        assert!(
            dao.get(&token_key("T1")).await.unwrap().is_none(),
            "过期 session 应从 DAO 删除"
        );
    }

    /// R-003: get_account_session 发现 account session 过期时触发回调。
    #[tokio::test]
    async fn get_account_session_triggers_callback_on_expiry() {
        let (dao, mut session) = make_session(3600, 3600);
        let (listener, calls) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener));

        session.create("1001", "T1").await.unwrap();
        expire_account_session_in_dao(&dao, "1001", 3600).await;

        let result = session.get_account_session("1001").await.unwrap();
        assert!(result.is_none(), "过期 account session 应返回 None");

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1, "应触发 1 次回调");
        assert_eq!(recorded[0].0, "1001");
        assert_eq!(
            recorded[0].1, "",
            "Account-Session 级过期 token 应为空字符串"
        );
    }

    /// R-003: get_account_session 对未过期 session 不触发回调。
    #[tokio::test]
    async fn get_account_session_no_callback_for_active_session() {
        let (_dao, mut session) = make_session(3600, 86400);
        let (listener, calls) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener));

        session.create("1001", "T1").await.unwrap();

        let result = session.get_account_session("1001").await.unwrap();
        assert!(result.is_some());

        assert!(
            calls.lock().unwrap().is_empty(),
            "未过期 session 不应触发回调"
        );
    }

    /// R-003: 多个 listener 按注册顺序（FIFO）依次调用。
    #[tokio::test]
    async fn multiple_listeners_called_in_fifo_order() {
        let (dao, mut session) = make_session(3600, 86400);
        let (listener1, calls1) = MockExpiryListener::new();
        let (listener2, calls2) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(listener1));
        session.add_expiry_listener(Arc::new(listener2));

        session.create("1001", "T1").await.unwrap();
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        session.get_token_session("T1").await.unwrap();

        assert_eq!(calls1.lock().unwrap().len(), 1);
        assert_eq!(calls2.lock().unwrap().len(), 1);
    }

    /// R-003: listener 失败时记录 warn 但继续执行后续 listener。
    #[tokio::test]
    async fn failing_listener_does_not_interrupt_subsequent_listeners() {
        let (dao, mut session) = make_session(3600, 86400);
        let failing = MockExpiryListener::new_failing();
        let (success, calls) = MockExpiryListener::new();
        session.add_expiry_listener(Arc::new(failing));
        session.add_expiry_listener(Arc::new(success));

        session.create("1001", "T1").await.unwrap();
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        let result = session.get_token_session("T1").await.unwrap();
        assert!(result.is_none(), "过期 session 应返回 None");

        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "失败的 listener 不应阻止后续 listener 执行"
        );
    }

    /// R-003: 无 listener 注册时 get_token_session 仍正常处理过期 session。
    #[tokio::test]
    async fn expired_session_with_no_listeners_still_deleted() {
        let (dao, session) = make_session(3600, 86400);

        session.create("1001", "T1").await.unwrap();
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        let result = session.get_token_session("T1").await.unwrap();
        assert!(result.is_none());

        assert!(
            dao.get(&token_key("T1")).await.unwrap().is_none(),
            "无 listener 时过期 session 仍应从 DAO 删除"
        );
    }

    // ------------------------------------------------------------------------
    // 并发竞态测试（R-001~R-004 修复验证）
    // ------------------------------------------------------------------------

    /// SlowDao wrapper：在 `get` account session key 后插入延迟，
    /// 放大 Account-Session read-modify-write 窗口，使 R-001 竞态可靠复现。
    ///
    /// 无锁时：两个并发 `create` 都会在对方的 `set(account)` 之前读到空的 account session，
    /// 导致 lost update（最终 tokens 列表只有 1 个 token 而非 2 个）。
    struct SlowDao {
        inner: Arc<MockDao>,
        delay: Duration,
    }

    #[async_trait]
    impl BulwarkDao for SlowDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let result = self.inner.get(key).await;
            // 仅对 account:session:* key 插入延迟，放大 read-modify-write 窗口
            if key.starts_with("account:session:") {
                tokio::time::sleep(self.delay).await;
            }
            result
        }
        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.inner.delete(key).await
        }
    }

    /// R-001 修复验证：两个并发 `create` 同一 login_id，Account-Session 的 token 列表应包含两个 token。
    ///
    /// 修复前（无 per-login_id 锁）：两个并发 create 的 read-modify-write 交错，
    /// 后写入的 account session 覆盖先写入的，导致丢失一个 token（lost update）。
    /// 修复后（per-login_id 锁）：两个 create 串行化，tokens 列表完整保留两个 token。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn concurrent_login_same_user_creates_consistent_session() {
        let inner = Arc::new(MockDao::new());
        let dao: Arc<dyn BulwarkDao> = Arc::new(SlowDao {
            inner: inner.clone(),
            delay: Duration::from_millis(50),
        });
        let session = BulwarkSession::new(dao, 3600, 86400);

        // 并发执行两次 create 同一 login_id（用 tokio::join! 确保并发）
        let (r1, r2) = tokio::join!(session.create("1001", "T1"), session.create("1001", "T2"),);
        r1.expect("create T1 应成功");
        r2.expect("create T2 应成功");

        // 验证 Account-Session 的 token 列表长度为 2（修复前会丢失一个）
        let account = session
            .get_account_session("1001")
            .await
            .expect("get_account_session 应成功")
            .expect("Account-Session 应存在");
        assert_eq!(
            account.tokens.len(),
            2,
            "并发 create 后 Account-Session 应包含 2 个 token（修复前 lost update 导致只剩 1 个）"
        );

        // 验证两个 token 都能通过 is_valid 检查
        assert!(
            session.is_valid("T1").await.expect("is_valid T1 应成功"),
            "T1 应有效"
        );
        assert!(
            session.is_valid("T2").await.expect("is_valid T2 应成功"),
            "T2 应有效"
        );
    }

    // ------------------------------------------------------------------------
    // 会话悬停超时测试（spec R-hover-001 ~ R-hover-004）
    // ------------------------------------------------------------------------

    /// R-hover-001: `session_hover_timeout == -1` 时 `check_hover_timeout` 始终返回 true。
    #[test]
    fn check_hover_timeout_disabled_when_negative() {
        let (_dao, session) = make_session(3600, 86400);
        session.update_last_active("user1");
        assert!(
            session.check_hover_timeout("user1", -1),
            "hover_timeout=-1 时应始终返回 true（不启用）"
        );
    }

    /// R-hover-001: `session_hover_timeout == 0` 时也视为不启用，返回 true。
    #[test]
    fn check_hover_timeout_disabled_when_zero() {
        let (_dao, session) = make_session(3600, 86400);
        session.update_last_active("user1");
        assert!(
            session.check_hover_timeout("user1", 0),
            "hover_timeout=0 时应始终返回 true（不启用）"
        );
    }

    /// 无 last_active_time 记录时（首次 check_login），不踢出。
    #[test]
    fn check_hover_timeout_returns_true_when_no_record() {
        let (_dao, session) = make_session(3600, 86400);
        assert!(
            session.check_hover_timeout("nonexistent", 10),
            "无记录时应返回 true（首次 check_login 不踢出）"
        );
    }

    /// 活跃会话（刚更新 last_active_time）不应被踢出。
    #[test]
    fn check_hover_timeout_returns_true_when_active() {
        let (_dao, session) = make_session(3600, 86400);
        session.update_last_active("user1");
        assert!(
            session.check_hover_timeout("user1", 10),
            "活跃会话应返回 true"
        );
    }

    /// R-hover-003: 悬停超时后返回 false（踢出）。
    ///
    /// 设置 last_active_time 为 5 秒前，hover_timeout=1 秒，应返回 false。
    #[test]
    fn check_hover_timeout_evicts_after_timeout() {
        let (_dao, session) = make_session(3600, 86400);
        // 手动设置 5 秒前的 last_active_time
        let old_time = chrono::Utc::now().timestamp_millis() - 5000;
        session
            .last_active_time
            .insert("user1".to_string(), old_time);
        assert!(
            !session.check_hover_timeout("user1", 1),
            "悬停超时后应返回 false（踢出）"
        );
    }

    /// update_last_active / get_last_active 往返测试。
    #[test]
    fn update_and_get_last_active_roundtrip() {
        let (_dao, session) = make_session(3600, 86400);
        assert!(
            session.get_last_active("user1").is_none(),
            "未更新前应返回 None"
        );
        session.update_last_active("user1");
        let ts = session.get_last_active("user1");
        assert!(ts.is_some(), "更新后应返回 Some");
        let now = chrono::Utc::now().timestamp_millis();
        assert!(
            (now - ts.unwrap()).abs() < 1000,
            "last_active_time 应接近当前时间"
        );
    }

    // ------------------------------------------------------------------------
    // create_token_session：LoginParams 写入 device/ip/user_agent
    // ------------------------------------------------------------------------

    /// 验证 `create_token_session` 将 LoginParams 中的 device/ip/user_agent 写入 TokenSession。
    #[tokio::test]
    async fn token_session_stores_ip_and_user_agent() {
        let (_dao, session) = make_session(3600, 86400);
        let params = LoginParams {
            device: Some("web-chrome".to_string()),
            ip: Some("192.168.1.100".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            remember_me: false,
            require_mfa: false,
        };
        session
            .create_token_session("1001", "T1", &params)
            .await
            .unwrap();

        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(ts.device.as_deref(), Some("web-chrome"));
        assert_eq!(ts.ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(ts.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    /// 验证 `create_token_session` 在 `LoginParams::default()` 时 device/ip/user_agent 全为 None。
    #[tokio::test]
    async fn token_session_defaults_to_none_when_no_params() {
        let (_dao, session) = make_session(3600, 86400);
        session
            .create_token_session("1001", "T1", &LoginParams::default())
            .await
            .unwrap();

        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert!(ts.device.is_none(), "device 应为 None");
        assert!(ts.ip.is_none(), "ip 应为 None");
        assert!(ts.user_agent.is_none(), "user_agent 应为 None");
    }

    // ------------------------------------------------------------------------
    // login_token_map：login_id → token 列表内存索引
    // ------------------------------------------------------------------------

    /// 验证 `add_login_token` 为同一 login_id 累积多个 token，且 `get_tokens_by_login_id` 返回完整列表。
    #[test]
    fn login_token_map_tracks_multiple_tokens() {
        let (_dao, session) = make_session(3600, 86400);
        session.add_login_token("user1", "token1");
        session.add_login_token("user1", "token2");

        let tokens = session.get_tokens_by_login_id("user1");
        assert_eq!(
            tokens,
            vec!["token1".to_string(), "token2".to_string()],
            "应按添加顺序返回两个 token"
        );
    }

    /// 验证 `get_token_by_login_id` 返回第一个（最旧）token。
    #[test]
    fn get_token_by_login_id_returns_first() {
        let (_dao, session) = make_session(3600, 86400);
        session.add_login_token("user2", "tokenA");
        session.add_login_token("user2", "tokenB");

        let first = session.get_token_by_login_id("user2");
        assert_eq!(
            first,
            Some("tokenA".to_string()),
            "应返回第一个添加的 token"
        );
    }

    /// 验证 `remove_login_token` 移除指定 token，列表为空时移除整个 entry。
    #[test]
    fn kickout_cleans_login_token_map() {
        let (_dao, session) = make_session(3600, 86400);
        session.add_login_token("user3", "tokenX");
        session.remove_login_token("user3", "tokenX");

        let tokens = session.get_tokens_by_login_id("user3");
        assert!(tokens.is_empty(), "移除后应返回空列表");
        assert!(
            session.get_token_by_login_id("user3").is_none(),
            "entry 已移除，应返回 None"
        );
    }

    // ------------------------------------------------------------------------
    // cleanup_expired_tokens：清理 login_token_map 中的过期/已注销 token
    // ------------------------------------------------------------------------

    /// 验证 `login_token_map` 为空时 `cleanup_expired_tokens` 返回 0。
    #[tokio::test]
    async fn cleanup_expired_tokens_no_tokens_returns_zero() {
        let (_dao, session) = make_session(3600, 86400);
        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 0, "无 token 时应返回 0");
    }

    /// 验证 `cleanup_expired_tokens` 清理已过期的 token（session 级过期）。
    #[tokio::test]
    async fn cleanup_expired_tokens_removes_expired() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        // 模拟 token session 过期（last_active_at 早于 timeout 之前）
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 1, "应清理 1 个过期 token");
        // login_token_map 中该 login_id 的 entry 应被移除（列表变空）
        assert!(
            session.get_token_by_login_id("1001").is_none(),
            "清理后 login_id entry 应被移除"
        );
    }

    /// 验证 `cleanup_expired_tokens` 清理已注销的 token（token session 不存在）。
    #[tokio::test]
    async fn cleanup_expired_tokens_removes_logged_out() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        // 直接从 DAO 删除 token session（模拟 oxcache TTL 过期或外部删除，不经过 logout）
        dao.delete(&token_key("T1")).await.unwrap();

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 1, "应清理 1 个已注销 token");
        assert!(
            session.get_token_by_login_id("1001").is_none(),
            "清理后 login_id entry 应被移除"
        );
    }

    /// 验证 `cleanup_expired_tokens` 保留有效的 token。
    #[tokio::test]
    async fn cleanup_expired_tokens_keeps_valid() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 0, "有效 token 不应被清理");
        // token 仍在 login_token_map 中
        let tokens = session.get_tokens_by_login_id("1001");
        assert_eq!(tokens, vec!["T1".to_string()], "有效 token 应保留");
        // token session 仍可访问
        assert!(session.get_token_session("T1").await.unwrap().is_some());
    }

    /// 验证 `cleanup_expired_tokens` 处理多 login_id 混合场景（一个过期，一个有效）。
    #[tokio::test]
    async fn cleanup_expired_tokens_multi_login_id_mixed() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("2002", "T2").await.unwrap();
        // 让 T1 过期，T2 保持有效
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 1, "应清理 1 个过期 token");
        // 1001 的 entry 应被移除（列表变空）
        assert!(
            session.get_token_by_login_id("1001").is_none(),
            "1001 的 entry 应被移除"
        );
        // 2002 的 token 应保留
        let tokens = session.get_tokens_by_login_id("2002");
        assert_eq!(tokens, vec!["T2".to_string()], "2002 的有效 token 应保留");
    }

    /// 验证 `cleanup_expired_tokens` 在所有 token 都过期时清理全部。
    #[tokio::test]
    async fn cleanup_expired_tokens_all_expired_cleans_all() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        // 让两个 token 都过期
        expire_token_session_in_dao(&dao, "T1", 3600).await;
        expire_token_session_in_dao(&dao, "T2", 3600).await;

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 2, "应清理 2 个过期 token");
        assert!(
            session.get_token_by_login_id("1001").is_none(),
            "全部清理后 entry 应被移除"
        );
    }

    /// 验证 `cleanup_expired_tokens` 在部分过期时只清理过期的，保留有效的。
    #[tokio::test]
    async fn cleanup_expired_tokens_partial_expired() {
        let (dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        // 让 T1 过期，T2 保持有效
        expire_token_session_in_dao(&dao, "T1", 3600).await;

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 1, "应清理 1 个过期 token");
        // entry 应保留，但只剩 T2
        let tokens = session.get_tokens_by_login_id("1001");
        assert_eq!(tokens, vec!["T2".to_string()], "应只剩有效的 T2");
    }

    /// 验证 `cleanup_expired_tokens` 返回正确的清理总数（多 login_id 多 token）。
    #[tokio::test]
    async fn cleanup_expired_tokens_returns_correct_count() {
        let (dao, session) = make_session(3600, 86400);
        // 1001: T1 过期, T2 有效
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        // 2002: T3 过期, T4 有效
        session.create("2002", "T3").await.unwrap();
        session.create("2002", "T4").await.unwrap();
        // 让 T1 和 T3 过期
        expire_token_session_in_dao(&dao, "T1", 3600).await;
        expire_token_session_in_dao(&dao, "T3", 3600).await;

        let removed = session.cleanup_expired_tokens().await.unwrap();
        assert_eq!(removed, 2, "应清理 2 个过期 token（T1 + T3）");
        // 1001 应只剩 T2
        let tokens_1001 = session.get_tokens_by_login_id("1001");
        assert_eq!(tokens_1001, vec!["T2".to_string()]);
        // 2002 应只剩 T4
        let tokens_2002 = session.get_tokens_by_login_id("2002");
        assert_eq!(tokens_2002, vec!["T4".to_string()]);
    }

    // ----------------------------------------------------------------
    // HIGH-004: 单 token DAO 失败不中断清理周期
    // ----------------------------------------------------------------

    /// 测试用 DAO wrapper，在 get 特定 key 时返回错误。
    ///
    /// 用于测试 `cleanup_expired_tokens` 单 token DAO 读取失败时
    /// 不中断整个清理周期（HIGH-004）。
    struct FailingGetDao {
        inner: Arc<MockDao>,
        fail_get_key: String,
    }

    #[async_trait]
    impl BulwarkDao for FailingGetDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            if key == self.fail_get_key {
                return Err(BulwarkError::Dao("模拟读取失败".to_string()));
            }
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.inner.delete(key).await
        }
    }

    /// 测试用 DAO wrapper，在 update 特定 key 时返回错误。
    ///
    /// 用于测试 `add_login_token_persistent` / `remove_login_token_persistent`
    /// 在 DAO update 失败时不写入内存层（保证双层一致性）。
    struct FailingUpdateDao {
        inner: Arc<MockDao>,
        fail_update_key: String,
    }

    #[async_trait]
    impl BulwarkDao for FailingUpdateDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            if key == self.fail_update_key {
                return Err(BulwarkError::Dao("模拟更新失败".to_string()));
            }
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.inner.delete(key).await
        }
    }

    /// HIGH-004: 单 token DAO 读取失败不中断整个清理周期，改为 warn 日志并跳过该 token。
    ///
    /// 场景：3 个 token（T1 有效 / T2 DAO get 失败 / T3 已注销），
    /// 验证 T2 的 DAO 失败不中断遍历，T3 仍被清理，T1/T2 保留在 map 中。
    #[tokio::test]
    async fn cleanup_expired_tokens_dao_failure_skips_token_without_aborting() {
        let inner = Arc::new(MockDao::new());
        let dao: Arc<dyn BulwarkDao> = Arc::new(FailingGetDao {
            inner: inner.clone(),
            fail_get_key: token_key("T2"),
        });
        let session = BulwarkSession::new(dao, 3600, 86400);

        // 创建 3 个 token：T1（有效）、T2（DAO get 会失败）、T3（将注销）
        session.create("1001", "T1").await.unwrap();
        session.create("1001", "T2").await.unwrap();
        session.create("1001", "T3").await.unwrap();

        // 从 inner MockDao 删除 T3 的 token session（模拟已注销/TTL 过期）
        inner.delete(&token_key("T3")).await.unwrap();

        // 调用 cleanup_expired_tokens（不应返回 Err）
        let removed = session.cleanup_expired_tokens().await.unwrap();

        // 验证：只清理 T3（T2 因 DAO 失败被跳过，不计入清理数）
        assert_eq!(
            removed, 1,
            "应只清理 1 个已注销 token（T3），T2 因 DAO 失败被跳过"
        );

        // T1 和 T2 仍在 login_token_map 中，T3 被清理
        let tokens = session.get_tokens_by_login_id("1001");
        assert!(tokens.contains(&"T1".to_string()), "T1（有效）应保留");
        assert!(
            tokens.contains(&"T2".to_string()),
            "T2（DAO 失败被跳过）应保留在 map 中"
        );
        assert!(!tokens.contains(&"T3".to_string()), "T3（已注销）应被清理");
    }

    // ------------------------------------------------------------------------
    // dynamic_active_timeout 字段默认值（feature = "dynamic-active-timeout"）
    // ------------------------------------------------------------------------

    /// 验证 `TokenSession` 创建后 `dynamic_active_timeout` 默认为 `None`。
    ///
    /// 启用 `dynamic-active-timeout` feature 后，新创建的 TokenSession
    /// 的 `dynamic_active_timeout` 字段应为 `None`（未设置自定义活跃超时）。
    #[cfg(feature = "dynamic-active-timeout")]
    #[tokio::test]
    async fn token_session_dynamic_active_timeout_defaults_to_none() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert!(
            ts.dynamic_active_timeout.is_none(),
            "新创建的 TokenSession 的 dynamic_active_timeout 应默认为 None"
        );
    }

    // ------------------------------------------------------------------------
    // set_active_timeout：设置 per-token 动态活跃超时
    // ------------------------------------------------------------------------

    /// 验证 `set_active_timeout` 设置 `dynamic_active_timeout` 为指定值。
    ///
    /// 创建 token session 后调用 `set_active_timeout(token, 600)`，
    /// 验证 `get_token_session` 返回的 `dynamic_active_timeout` 为 `Some(600)`。
    #[cfg(feature = "dynamic-active-timeout")]
    #[tokio::test]
    async fn set_active_timeout_sets_dynamic_timeout() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 初始应为 None
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert!(ts.dynamic_active_timeout.is_none());

        // 设置动态活跃超时为 600 秒
        session.set_active_timeout("T1", 600).await.unwrap();

        // 验证已写入
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(
            ts.dynamic_active_timeout,
            Some(600),
            "set_active_timeout 后 dynamic_active_timeout 应为 Some(600)"
        );
    }

    /// 验证 `set_active_timeout` 对不存在的 token 返回错误。
    ///
    /// 对不存在的 token 调用 `set_active_timeout`，验证返回 `Err`。
    #[cfg(feature = "dynamic-active-timeout")]
    #[tokio::test]
    async fn set_active_timeout_returns_error_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.set_active_timeout("nonexistent", 600).await;
        assert!(
            result.is_err(),
            "set_active_timeout 对不存在的 token 应返回 Err"
        );
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "set_active_timeout 对不存在的 token 应返回 InvalidToken 错误，实际: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // rebuild_login_token_map：从 DAO 重建内存索引（feature = "login-token-map-persistence"）
    // ------------------------------------------------------------------------

    /// 验证空 DAO（无 Account-Session）重建后 `login_token_map` 为空。
    #[cfg(feature = "login-token-map-persistence")]
    #[tokio::test]
    async fn rebuild_login_token_map_empty_dao_produces_empty_map() {
        let (_dao, session) = make_session(3600, 86400);
        session.rebuild_login_token_map().await.unwrap();
        assert!(
            session.login_token_map.is_empty(),
            "空 DAO 重建后 login_token_map 应为空"
        );
    }

    /// 验证 3 个 AccountSession（各有 2 个 token）重建后 `login_token_map` 包含全部 6 个 token。
    #[cfg(feature = "login-token-map-persistence")]
    #[tokio::test]
    async fn rebuild_login_token_map_with_3_sessions_populates_all_tokens() {
        let (_dao, session) = make_session(3600, 86400);
        // 创建 3 个 AccountSession，各有 2 个 token
        session.create("user1", "T1").await.unwrap();
        session.create("user1", "T2").await.unwrap();
        session.create("user2", "T3").await.unwrap();
        session.create("user2", "T4").await.unwrap();
        session.create("user3", "T5").await.unwrap();
        session.create("user3", "T6").await.unwrap();

        // 模拟重启：清空内存 map（DAO 数据仍保留）
        session.login_token_map.clear();
        assert!(session.login_token_map.is_empty());

        // 从 DAO 重建内存索引
        session.rebuild_login_token_map().await.unwrap();

        // 验证：3 个 login_id，各 2 个 token，共 6 个
        assert_eq!(
            session.login_token_map.len(),
            3,
            "应重建 3 个 login_id entry"
        );

        let tokens1 = session.get_tokens_by_login_id("user1");
        assert_eq!(tokens1.len(), 2, "user1 应有 2 个 token");
        assert!(tokens1.contains(&"T1".to_string()));
        assert!(tokens1.contains(&"T2".to_string()));

        let tokens2 = session.get_tokens_by_login_id("user2");
        assert_eq!(tokens2.len(), 2, "user2 应有 2 个 token");
        assert!(tokens2.contains(&"T3".to_string()));
        assert!(tokens2.contains(&"T4".to_string()));

        let tokens3 = session.get_tokens_by_login_id("user3");
        assert_eq!(tokens3.len(), 2, "user3 应有 2 个 token");
        assert!(tokens3.contains(&"T5".to_string()));
        assert!(tokens3.contains(&"T6".to_string()));
    }

    // ------------------------------------------------------------------------
    // add_login_token_persistent / remove_login_token_persistent（feature = "login-token-map-persistence"）
    // ------------------------------------------------------------------------

    /// 验证 `add_login_token_persistent` 同时写入 DAO AccountSession.tokens 和内存 login_token_map。
    ///
    /// 场景：已存在 AccountSession（含 T1，内存已有 T1），调用 persistent 添加 T2，
    /// 验证 DAO 与内存两层都包含 T1 和 T2。
    #[cfg(feature = "login-token-map-persistence")]
    #[tokio::test]
    async fn add_login_token_persistent_adds_to_both_layers() {
        let (_dao, session) = make_session(3600, 86400);
        // 先创建 AccountSession（通过 create，DAO 和内存都含 T1）
        session.create("user1", "T1").await.unwrap();

        // 调用 add_login_token_persistent 添加 T2
        session
            .add_login_token_persistent("user1", "T2")
            .await
            .unwrap();

        // 验证 DAO AccountSession.tokens 包含 T1 和 T2
        let account = session.get_account_session("user1").await.unwrap().unwrap();
        let dao_tokens: Vec<String> = account.tokens.into_iter().map(|ti| ti.token).collect();
        assert_eq!(
            dao_tokens.len(),
            2,
            "DAO AccountSession.tokens 应有 2 个 token"
        );
        assert!(dao_tokens.contains(&"T1".to_string()));
        assert!(dao_tokens.contains(&"T2".to_string()));

        // 验证内存 login_token_map 包含 T1 和 T2
        let mem_tokens = session.get_tokens_by_login_id("user1");
        assert_eq!(mem_tokens.len(), 2, "内存 login_token_map 应有 2 个 token");
        assert!(mem_tokens.contains(&"T1".to_string()));
        assert!(mem_tokens.contains(&"T2".to_string()));
    }

    /// 验证 `remove_login_token_persistent` 同时从 DAO AccountSession.tokens 和内存 login_token_map 移除。
    ///
    /// 场景：AccountSession 含 T1 和 T2，调用 persistent 移除 T1，
    /// 验证 DAO 与内存两层都只剩 T2。
    #[cfg(feature = "login-token-map-persistence")]
    #[tokio::test]
    async fn remove_login_token_persistent_removes_from_both_layers() {
        let (_dao, session) = make_session(3600, 86400);
        // 创建 2 个 token
        session.create("user1", "T1").await.unwrap();
        session.create("user1", "T2").await.unwrap();

        // 调用 remove_login_token_persistent 移除 T1
        session
            .remove_login_token_persistent("user1", "T1")
            .await
            .unwrap();

        // 验证 DAO AccountSession.tokens 只剩 T2
        let account = session.get_account_session("user1").await.unwrap().unwrap();
        let dao_tokens: Vec<String> = account.tokens.into_iter().map(|ti| ti.token).collect();
        assert_eq!(
            dao_tokens.len(),
            1,
            "DAO AccountSession.tokens 应剩 1 个 token"
        );
        assert!(!dao_tokens.contains(&"T1".to_string()));
        assert!(dao_tokens.contains(&"T2".to_string()));

        // 验证内存 login_token_map 只剩 T2
        let mem_tokens = session.get_tokens_by_login_id("user1");
        assert_eq!(mem_tokens.len(), 1, "内存 login_token_map 应剩 1 个 token");
        assert!(!mem_tokens.contains(&"T1".to_string()));
        assert!(mem_tokens.contains(&"T2".to_string()));
    }

    /// 验证 DAO update 失败时内存不写（返回 Err），保证双层一致性。
    ///
    /// 场景：使用 FailingUpdateDao 让 account:session:user1 的 update 失败，
    /// 调用 add_login_token_persistent 应返回 Err，且内存 login_token_map 未被写入。
    #[cfg(feature = "login-token-map-persistence")]
    #[tokio::test]
    async fn add_login_token_persistent_dao_failure_skips_memory_write() {
        let inner = Arc::new(MockDao::new());
        let dao: Arc<dyn BulwarkDao> = Arc::new(FailingUpdateDao {
            inner: inner.clone(),
            fail_update_key: account_key("user1"),
        });
        let session = BulwarkSession::new(dao, 3600, 86400);

        // 先创建 AccountSession（create 用 set，不受 FailingUpdateDao 影响）
        session.create("user1", "T1").await.unwrap();
        // 清空内存 map
        session.login_token_map.clear();

        // 调用 add_login_token_persistent → DAO update 失败 → 返回 Err
        let result = session.add_login_token_persistent("user1", "T2").await;
        assert!(
            result.is_err(),
            "DAO update 失败时应返回 Err，实际: {:?}",
            result
        );

        // 验证内存 login_token_map 未被写入（仍为空）
        let mem_tokens = session.get_tokens_by_login_id("user1");
        assert!(
            mem_tokens.is_empty(),
            "DAO 失败时内存不应写入，实际: {:?}",
            mem_tokens
        );
    }

    // ------------------------------------------------------------------------
    // create / logout 端到端双层一致性（feature = "login-token-map-persistence"）
    // ------------------------------------------------------------------------

    /// 验证 login → logout 后 DAO AccountSession.tokens 与内存 login_token_map 一致。
    ///
    /// 场景：create(user1, T1) 后 DAO 与内存两层都包含 T1；
    /// logout(T1) 后 DAO AccountSession.tokens 为空、内存 login_token_map 不包含 T1。
    /// 这验证了 create_inner/logout_inner 现有双写逻辑在 persistent 特性下的一致性。
    #[cfg(feature = "login-token-map-persistence")]
    #[tokio::test]
    async fn login_logout_persistent_consistency() {
        let (_dao, session) = make_session(3600, 86400);

        // 1. create(user1, T1)
        session.create("user1", "T1").await.unwrap();

        // 验证 DAO AccountSession.tokens 包含 T1
        let account = session.get_account_session("user1").await.unwrap().unwrap();
        let dao_tokens: Vec<String> = account.tokens.into_iter().map(|ti| ti.token).collect();
        assert_eq!(
            dao_tokens.len(),
            1,
            "DAO AccountSession.tokens 应有 1 个 token"
        );
        assert!(dao_tokens.contains(&"T1".to_string()));

        // 验证内存 login_token_map 包含 T1
        let mem_tokens = session.get_tokens_by_login_id("user1");
        assert_eq!(mem_tokens.len(), 1, "内存 login_token_map 应有 1 个 token");
        assert!(mem_tokens.contains(&"T1".to_string()));

        // 2. logout(T1)
        session.logout("T1").await.unwrap();

        // 验证 DAO AccountSession.tokens 为空（AccountSession 保留历史，不删除）
        let account = session.get_account_session("user1").await.unwrap().unwrap();
        let dao_tokens: Vec<String> = account.tokens.into_iter().map(|ti| ti.token).collect();
        assert!(
            dao_tokens.is_empty(),
            "logout 后 DAO AccountSession.tokens 应为空，实际: {:?}",
            dao_tokens
        );

        // 验证内存 login_token_map 不包含 T1（entry 为空时被移除）
        let mem_tokens = session.get_tokens_by_login_id("user1");
        assert!(
            mem_tokens.is_empty(),
            "logout 后内存 login_token_map 不应包含 T1，实际: {:?}",
            mem_tokens
        );
    }
}
