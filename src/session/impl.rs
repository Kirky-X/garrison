//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkSession 实现块（从 mod.rs 迁移）。

use super::*;

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

    /// 更新 login_id 的最后活跃时间为指定时间戳（用于可注入时钟）。
    ///
    /// 与 `update_last_active` 的区别：接受外部传入的时间戳，
    /// 支持 `MockClock` 注入测试场景。
    pub fn update_last_active_at(&self, login_id: &str, timestamp_millis: i64) {
        self.last_active_time
            .insert(login_id.to_string(), timestamp_millis);
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
    ///
    /// # 反序列化失败处理
    /// 若某个 `AccountSession` 反序列化失败，记录 `tracing::warn!` 并跳过该条目
    /// （不中断重建流程），与 key 格式异常处理一致。
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
                let session: AccountSession = match serde_json::from_str(&json) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            key = %key,
                            error = %e,
                            "rebuild_login_token_map: 跳过反序列化失败的 AccountSession"
                        );
                        continue;
                    },
                };
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
    /// - `timeout_secs`: 超时秒数。`-1` 表示永不过期，`0` 非法。
    ///
    /// # 错误
    /// - `timeout_secs=0`：`BulwarkError::InvalidParam`。
    /// - token 不存在：`BulwarkError::InvalidToken`。
    /// - 序列化失败：`BulwarkError::Session`。
    /// - DAO 更新失败：透传 `BulwarkError`。
    #[cfg(feature = "dynamic-active-timeout")]
    pub async fn set_active_timeout(&self, token: &str, timeout_secs: i64) -> BulwarkResult<()> {
        if timeout_secs == 0 {
            return Err(BulwarkError::InvalidParam(
                "timeout_secs 必须为 -1 或 >0".to_string(),
            ));
        }
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
            // -1 表示永不过期（与全局 active_timeout 语义一致），负值跳过活跃超时检查
            let now = Utc::now().timestamp();
            if effective_active_timeout >= 0 && ts.last_active_at + effective_active_timeout < now {
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
        // InvalidParam（空 token / 超长 token）降级为非匿名，保持 logout 幂等契约
        #[cfg(feature = "anonymous-session")]
        {
            let is_anon = match self.is_anon(token).await {
                Ok(v) => v,
                Err(BulwarkError::InvalidParam(_)) => false,
                Err(e) => return Err(e),
            };
            if is_anon {
                return self.logout_anon(token).await;
            }
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
                        request_context: None,
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
// 单元测试：覆盖 impl.rs 中尚未被 session::tests 覆盖的路径
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// 辅助函数：创建带 MockDao 的 BulwarkSession（与 session::tests 中保持一致）。
    fn make_session(timeout: u64, active_timeout: u64) -> (Arc<MockDao>, BulwarkSession) {
        let dao = Arc::new(MockDao::new());
        let session = BulwarkSession::new(dao.clone(), timeout, active_timeout);
        (dao, session)
    }

    // ----------------------------------------------------------------
    // update_last_active_at：与 update_last_active 的差异（接受外部时间戳）
    // ----------------------------------------------------------------

    /// 验证 `update_last_active_at` 写入指定时间戳，而非当前时间。
    ///
    /// 覆盖与 `update_last_active` 的差异点：支持可注入时钟（MockClock）。
    #[test]
    fn update_last_active_at_sets_specified_timestamp() {
        let (_dao, session) = make_session(3600, 86400);
        // 固定时间戳，与当前时间无关
        let specified_ts: i64 = 1_700_000_000_000;
        session.update_last_active_at("user_injected", specified_ts);

        let stored = session.get_last_active("user_injected");
        assert_eq!(
            stored,
            Some(specified_ts),
            "update_last_active_at 应写入指定时间戳而非当前时间"
        );
    }

    // ----------------------------------------------------------------
    // add_login_token：去重逻辑
    // ----------------------------------------------------------------

    /// 验证 `add_login_token` 重复添加同一 token 不会复制条目。
    ///
    /// 覆盖 `if !entry.contains(...)` 分支为 false 时的跳过路径。
    #[test]
    fn add_login_token_deduplicates_existing_token() {
        let (_dao, session) = make_session(3600, 86400);
        session.add_login_token("user1", "token1");
        session.add_login_token("user1", "token1"); // 重复
        session.add_login_token("user1", "token2");

        let tokens = session.get_tokens_by_login_id("user1");
        assert_eq!(
            tokens,
            vec!["token1".to_string(), "token2".to_string()],
            "重复 token 不应重复计入列表"
        );
    }

    // ----------------------------------------------------------------
    // ensure_token_in_account_session：token 已存在仅更新 last_active_at
    // ----------------------------------------------------------------

    /// 验证 `ensure_token_in_account_session` 在 token 已存在时不重复添加，
    /// 仅更新对应 TokenInfo 与 AccountSession 的 last_active_at。
    ///
    /// 覆盖 `if let Some(ti) = account.tokens.iter_mut().find(...)` 分支。
    #[tokio::test]
    async fn ensure_token_in_account_session_updates_last_active_for_existing_token() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        let original = session.get_account_session("1001").await.unwrap().unwrap();
        let original_active = original.last_active_at;

        // 跨秒等待，确保 last_active_at（秒级精度）有可测差异
        tokio::time::sleep(Duration::from_secs(2)).await;

        session
            .ensure_token_in_account_session("1001", "T1")
            .await
            .unwrap();

        let after = session.get_account_session("1001").await.unwrap().unwrap();
        assert_eq!(
            after.tokens.len(),
            1,
            "token 已存在时不应重复添加到 tokens 列表"
        );
        assert!(
            after.last_active_at > original_active,
            "ensure 已存在的 token 应更新 last_active_at（原={}, 新={})",
            original_active,
            after.last_active_at
        );
        // 对应 TokenInfo 的 last_active_at 也应更新
        let ti = after.tokens.iter().find(|t| t.token == "T1").unwrap();
        assert!(
            ti.last_active_at > original_active,
            "TokenInfo.last_active_at 也应被更新"
        );
    }

    // ----------------------------------------------------------------
    // ensure_token_in_account_session：Account-Session 不存在时创建
    // ----------------------------------------------------------------

    /// 验证 `ensure_token_in_account_session` 在 Account-Session 不存在时
    /// 通过 `unwrap_or_else` 创建新的 AccountSession 并添加 token。
    ///
    /// 覆盖 `unwrap_or_else` 的 None 分支。
    #[tokio::test]
    async fn ensure_token_in_account_session_creates_account_when_missing() {
        let (_dao, session) = make_session(3600, 86400);
        // 直接调用 ensure，不预先 create
        session
            .ensure_token_in_account_session("2002", "T1")
            .await
            .unwrap();

        let account = session.get_account_session("2002").await.unwrap().unwrap();
        assert_eq!(account.login_id, "2002");
        assert_eq!(
            account.tokens.len(),
            1,
            "应创建包含 1 个 token 的 Account-Session"
        );
        assert_eq!(account.tokens[0].token, "T1");
    }

    // ----------------------------------------------------------------
    // save_token_session：保留原 TTL 持久化修改
    // ----------------------------------------------------------------

    /// 验证 `save_token_session` 通过 `dao.update` 持久化修改后的 TokenSession，
    /// 保留原 TTL（不重置过期时间）。
    ///
    /// 覆盖 `save_token_session` 调用路径。
    #[tokio::test]
    async fn save_token_session_persists_modified_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 读取并修改 TokenSession
        let mut ts = session.get_token_session("T1").await.unwrap().unwrap();
        ts.attrs
            .insert("custom_key".to_string(), "custom_value".to_string());

        // save_token_session 用 update（保留原 TTL）
        session.save_token_session("T1", &ts).await.unwrap();

        // 验证修改已持久化
        let reloaded = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(
            reloaded.attrs.get("custom_key").map(|s| s.as_str()),
            Some("custom_value"),
            "save_token_session 后自定义属性应持久化"
        );
    }

    // ----------------------------------------------------------------
    // create_token_session_with_ttl + get_token_timeout + set_token_session_ttl
    // ----------------------------------------------------------------

    /// 验证 TTL 相关三个方法的往返：
    /// - `create_token_session_with_ttl`：用指定 TTL 创建 TokenSession
    /// - `get_token_timeout`：查询剩余 TTL
    /// - `set_token_session_ttl`：重置 TTL
    ///
    /// 覆盖这三个方法未被现有测试覆盖的调用路径。
    #[tokio::test]
    async fn ttl_methods_roundtrip() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("1001", "T1").await.unwrap();

        // 用指定 TTL=600 创建新 TokenSession（构造最小可用 TokenSession）
        let new_ts = TokenSession {
            token: "T2".to_string(),
            login_id: "1001".to_string(),
            created_at: Utc::now().timestamp(),
            last_active_at: Utc::now().timestamp(),
            attrs: HashMap::new(),
            device: None,
            ip: None,
            user_agent: None,
            safe_services: HashMap::new(),
            #[cfg(feature = "dynamic-active-timeout")]
            dynamic_active_timeout: None,
            #[cfg(feature = "anonymous-session")]
            is_anon: false,
        };
        session
            .create_token_session_with_ttl("T2", &new_ts, 600)
            .await
            .unwrap();

        // get_token_timeout 应返回 Some（键存在且设置了 TTL）
        let ttl = session.get_token_timeout("T2").await.unwrap();
        assert!(
            ttl.is_some(),
            "create_token_session_with_ttl 设置了 TTL=600，应返回 Some"
        );
        let ttl_secs = ttl.unwrap().as_secs();
        // 容差：执行时间内可能消耗少量秒，应仍在 590~600 之间
        assert!(
            (590..=600).contains(&ttl_secs),
            "TTL 应接近 600 秒，实际: {}",
            ttl_secs
        );

        // set_token_session_ttl 重置为 1200 秒
        session.set_token_session_ttl("T2", 1200).await.unwrap();
        let ttl_after = session
            .get_token_timeout("T2")
            .await
            .unwrap()
            .expect("set_token_session_ttl 后应仍返回 Some");
        let ttl_after_secs = ttl_after.as_secs();
        assert!(
            (1190..=1200).contains(&ttl_after_secs),
            "set_token_session_ttl 后 TTL 应接近 1200 秒，实际: {}",
            ttl_after_secs
        );
    }

    // ----------------------------------------------------------------
    // with_anon_session_timeout builder（anonymous-session feature）
    // ----------------------------------------------------------------

    /// 验证 `with_anon_session_timeout` builder 设置 `anon_session_timeout` 字段，
    /// 且 `new` 默认使用 `DEFAULT_ANON_SESSION_TIMEOUT_SECS`。
    ///
    /// 覆盖 anonymous-session feature 下的 builder 方法与默认值。
    #[cfg(feature = "anonymous-session")]
    #[test]
    fn with_anon_session_timeout_sets_field() {
        use crate::config::DEFAULT_ANON_SESSION_TIMEOUT_SECS;

        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // 默认值应为 DEFAULT_ANON_SESSION_TIMEOUT_SECS（1800 秒 = 30 分钟）
        let default_session = BulwarkSession::new(dao.clone(), 3600, 86400);
        assert_eq!(
            default_session.anon_session_timeout, DEFAULT_ANON_SESSION_TIMEOUT_SECS,
            "new 默认应使用 DEFAULT_ANON_SESSION_TIMEOUT_SECS"
        );

        // builder 覆盖默认值
        let session = BulwarkSession::new(dao, 3600, 86400).with_anon_session_timeout(99);
        assert_eq!(
            session.anon_session_timeout, 99,
            "with_anon_session_timeout 应设置字段为指定值"
        );
    }

    // ----------------------------------------------------------------
    // with_token_session_lock：per-token 锁（safe-auth / anonymous-session feature）
    // ----------------------------------------------------------------

    /// 验证 `with_token_session_lock` 串行化同一 token 的并发操作。
    ///
    /// 两个并发任务对同一 token 调用 `with_token_session_lock`，应串行执行
    ///（第二个任务在第一个释放锁后才开始），通过共享计数器验证顺序。
    #[cfg(any(feature = "safe-auth", feature = "anonymous-session"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn with_token_session_lock_serializes_same_token() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_dao, session) = make_session(3600, 86400);
        let session = Arc::new(session);
        let counter = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let counter_a = counter.clone();
        let max_a = max_concurrent.clone();
        let session_a = session.clone();
        let h1 = tokio::spawn(async move {
            session_a
                .with_token_session_lock("T1", async {
                    let cur = counter_a.fetch_add(1, Ordering::SeqCst) + 1;
                    max_a.fetch_max(cur, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    counter_a.fetch_sub(1, Ordering::SeqCst);
                })
                .await
        });

        let counter_b = counter.clone();
        let max_b = max_concurrent.clone();
        let session_b = session.clone();
        let h2 = tokio::spawn(async move {
            session_b
                .with_token_session_lock("T1", async {
                    let cur = counter_b.fetch_add(1, Ordering::SeqCst) + 1;
                    max_b.fetch_max(cur, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    counter_b.fetch_sub(1, Ordering::SeqCst);
                })
                .await
        });

        h1.await.unwrap();
        h2.await.unwrap();

        // 串行执行时，counter 最大值为 1（不会有两个任务同时进入临界区）
        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            1,
            "with_token_session_lock 应串行化同一 token 的并发操作"
        );
    }
}
