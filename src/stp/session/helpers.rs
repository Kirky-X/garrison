// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SessionLogic 私有 helper：`GarrisonLogicDefault` 私有 impl 块，供 trait 实现内部调用，经 `pub(super)` 对父模块可见。

use super::*;

// 私有 helper 方法（供 SessionLogic impl 调用）

impl GarrisonLogicDefault {
    /// login_id 输入不变量校验（login 签发源头 fail-closed）：trim 后非空、不含 `\x1f`（token body 分隔符，内嵌会造成 verify 身份切分歧义）与其他控制字符、字节长度 ≤ `config.login_id_max_len`（`0` 不限，默认 255 封住超大 login_id 灌入会话存储）。
    /// 与 [`crate::core::token::SimpleTokenStyle::generate`] 校验语义对齐；只拒绝明显非法值，错误信息不回显输入内容。
    pub(super) fn validate_login_id(&self, login_id: &str) -> GarrisonResult<()> {
        if login_id.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "stp-login-id-empty::".to_string(),
            ));
        }
        if login_id.trim().is_empty() {
            return Err(GarrisonError::InvalidParam(
                "stp-login-id-whitespace::".to_string(),
            ));
        }
        if login_id.contains('\x1f') {
            return Err(GarrisonError::InvalidParam(
                "stp-login-id-sep::".to_string(),
            ));
        }
        if login_id.chars().any(|c| c.is_control()) {
            return Err(GarrisonError::InvalidParam(
                "stp-login-id-control-char::".to_string(),
            ));
        }
        let max_len = self.config.login_id_max_len;
        if max_len > 0 && login_id.len() > max_len as usize {
            // 只回显长度，不回显内容（超长输入不得进入日志/错误通道）
            return Err(GarrisonError::InvalidParam(format!(
                "stp-login-id-too-long::{}::{}",
                login_id.len(),
                max_len
            )));
        }
        Ok(())
    }

    /// login 实际逻辑（供 `login` 在 metrics 包装内调用）：先经 [`Self::validate_login_id`] 校验，非法值一律 fail-closed 不签发会话。
    /// `create_token_session_inner` + `enforce_max_login_count_inner` 在同一 `with_login_lock` 临界区执行，持锁约 3-25ms（DAO 调用数随 max_login_count 与踢出数增长），期间阻塞同 `login_id` 的 login/logout/kickout，不同 login_id 不受影响（DashMap 分片锁）。
    pub(super) async fn login_inner(
        &self,
        login_id: &str,
        params: &LoginParams,
    ) -> GarrisonResult<String> {
        // 0. login_id 输入不变量（fail-closed，先于防火墙钩子，避免非法值消耗限流/爆破计数）
        self.validate_login_id(login_id)?;

        // 1. 登录前防火墙安全钩子检查
        #[cfg(any(
            feature = "sms-rate-limit",
            feature = "firewall-ratelimit",
            feature = "firewall-bruteforce",
            feature = "firewall-ddos",
            feature = "firewall",
            feature = "oauth2-server"
        ))]
        {
            let ctx = FirewallLoginContext::new(login_id);
            self.firewall.check_login_hooks(login_id, &ctx).await?;
        }

        // 2. is_share=true: 复用现有有效 token
        if let Some(token) = self.try_reuse_session(login_id).await? {
            return Ok(token);
        }

        let params = self.prepare_device_fingerprint(params);

        self.check_device_binding(login_id, &params).await?;

        // 5. 创建会话 + 强制最大登录数（含并发策略，同一 login 锁区内，消除 TOCTOU）
        let token = self.generate_token(login_id)?;
        let params_owned = params.clone();
        self.create_session_with_quota(
            login_id,
            &token,
            params_owned.device.as_deref(),
            params_owned.ip.as_deref(),
            params_owned.user_agent.as_deref(),
            params_owned.remember_me,
        )
        .await?;

        // 5.5 角色层级 TC 预计算 + 权限并集缓存（见 `cache_role_union_on_login`；fail-open，不阻断登录）
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        self.cache_role_union_on_login(login_id).await;

        // 6. 事件通知（锁外执行，避免持锁跨 broadcast）
        self.notify_login_event(login_id, &token, &params).await;
        Ok(token)
    }

    /// 登录时角色层级 TC 预计算 + 权限并集缓存：经 `RoleHierarchyService` 计算「直接角色 ∪ 间接祖先」并写入 `role:cache:{login_id}`（TTL 3600s，与 `tenant:{tid}:role_closure` 闭包缓存一致），避免每次角色校验做 DFS。
    /// fail-open：角色列表为空、DAO 无 SQL 后端（`NotImplemented`，如 MockDao / oxcache-only 部署）或查询失败均只记日志跳过，不阻断登录；仅接在 `login_inner` 新建路径（复用/外部 token 导入路径不触发）；依赖 SQL 查询，门控 `any(db-sqlite, db-postgres, db-mysql)`。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    pub(super) async fn cache_role_union_on_login(&self, login_id: &str) {
        // 1. 直接角色列表（fail-open：取角色失败跳过预热，不影响登录）
        let roles = match self.firewall.get_role_list(login_id).await {
            Ok(roles) => roles,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    login_id = %login_id,
                    "{}", crate::i18n::translate_detail("logs-stp-role-union-get-role-list-failed", &[])
                );
                return;
            },
        };
        if roles.is_empty() {
            return;
        }

        // 2. 租户维度（与 permission.rs firewall 回退路径同口径：无上下文视为租户 0）
        let tenant_id = crate::context::tenant::TENANT
            .try_get()
            .map(|ctx| ctx.tenant_id)
            .unwrap_or(0);

        // 3. TC 预计算：get_ancestors 未命中时 compute_closure 并缓存租户闭包
        let service = crate::dao::repository::role_hierarchy::RoleHierarchyService::new(
            self.session.dao().clone(),
        );
        let mut union: std::collections::HashSet<String> = roles.iter().cloned().collect();
        for role in &roles {
            match service.get_ancestors(role, tenant_id).await {
                Ok(ancestors) => union.extend(ancestors),
                Err(GarrisonError::NotImplemented(_)) => {
                    // DAO 无 SQL 后端：常规能力缺失而非故障，debug 跳过避免 warn 刷屏
                    tracing::debug!(
                        login_id = %login_id,
                        "{}", crate::i18n::translate_detail("logs-stp-role-union-no-sql-backend", &[])
                    );
                    return;
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        login_id = %login_id,
                        "{}", crate::i18n::translate_detail("logs-stp-role-union-precompute-failed", &[])
                    );
                    return;
                },
            }
        }

        // 4. 缓存权限并集（直接角色 ∪ TC 祖先），TTL 与闭包缓存一致 3600 秒
        let key = crate::constants::DaoKeyPrefix::RoleCache.build_key(login_id);
        match serde_json::to_string(&union) {
            Ok(json) => {
                if let Err(e) = self.session.dao().set(&key, &json, 3600).await {
                    tracing::warn!(
                        error = %e,
                        login_id = %login_id,
                        "{}", crate::i18n::translate_detail("logs-stp-role-union-write-failed", &[])
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    login_id = %login_id,
                    "{}", crate::i18n::translate_detail("logs-stp-role-union-serialize-failed", &[])
                );
            },
        }
    }

    /// 锁内公共序列：并发策略检查 + 创建会话 + 强制最大登录数；`create` 与 `enforce_max_login_count` 同一 `with_login_lock` 临界区执行消除 TOCTOU，enforce 失败回滚新建会话。
    /// 本方法为调用链唯一收口：`remember_me_enabled=false` 时客户端 `remember_me=true` 一律降级（effective_timeout 不写 90 天，仅记 debug）；`seed_primary_amr=false` 时向 `create_token_session_inner` 传不播种标记，不为未密码校验的 login 断言 `pwd` / AAL 1。
    pub(super) async fn create_session_with_quota(
        &self,
        login_id: &str,
        token: &str,
        device: Option<&str>,
        ip: Option<&str>,
        user_agent: Option<&str>,
        remember_me: bool,
    ) -> GarrisonResult<()> {
        // 1. 并发策略（is_concurrent=false）。必须在 login 锁外：OldDevice 模式下 `check_concurrent_policy` 会调 `kickout` 再次获取 per-login_id 锁，与下方 `with_login_lock` 临界区嵌套会重入死锁。
        self.check_concurrent_policy(login_id).await?;

        // remember_me_enabled=false：请求的 remember_me 降级为 false（effective_timeout 不写 90 天）
        let effective_remember_me = remember_me && self.config.remember_me_enabled;
        if remember_me && !effective_remember_me {
            tracing::debug!(
                login_id,
                "{}",
                crate::i18n::translate_detail("logs-stp-remember-me-disabled", &[])
            );
        }

        // 2. 创建 + enforce 最大登录数（同一 login 锁区内）
        let login_id_owned = login_id.to_string();
        let token_owned = token.to_string();
        let seed_primary_amr = self.config.seed_primary_amr;
        self.session
            .with_login_lock(&login_id_owned, async {
                self.session
                    .create_token_session_inner(
                        &login_id_owned,
                        &token_owned,
                        device,
                        ip,
                        user_agent,
                        Some(effective_remember_me),
                        seed_primary_amr,
                    )
                    .await?;
                if self.config.max_login_count > 0 {
                    if let Err(e) = self
                        .enforce_max_login_count_inner(&login_id_owned, self.config.max_login_count)
                        .await
                    {
                        tracing::error!(
                            error = %e,
                            "enforce_max_login_count failed, rolling back newly created session"
                        );
                        match self.session.get_token_session(&token_owned).await {
                            Ok(Some(ts)) => {
                                if let Err(logout_err) =
                                    self.session.logout_inner(&token_owned, &ts).await
                                {
                                    tracing::error!(
                                        error = %logout_err,
                                        "rollback logout_inner failed, may produce orphan session (token still in DAO but login returned Err)"
                                    );
                                }
                            },
                            Ok(None) => {
                                tracing::warn!(
                                    "token session no longer exists during rollback, skipping logout_inner"
                                );
                            },
                            Err(get_err) => {
                                tracing::error!(
                                    error = %get_err,
                                    "rollback get_token_session failed, token may remain as orphan session"
                                );
                            },
                        }
                        return Err(e);
                    }
                }
                Ok(())
            })
            .await
    }

    /// is_share=true 时复用现有有效 token；`Ok(Some(token))` 表示复用成功，`Ok(None)` 表示无可复用会话。
    pub(super) async fn try_reuse_session(&self, login_id: &str) -> GarrisonResult<Option<String>> {
        if !self.config.is_share {
            return Ok(None);
        }
        if let Some(existing_token) = self.session.get_token_by_login_id(login_id) {
            if let Ok(Some(_ts)) = self.session.get_token_session(&existing_token).await {
                self.session.touch(&existing_token).await?;
                return Ok(Some(existing_token));
            }
            self.session.remove_login_token(login_id, &existing_token);
        }
        Ok(None)
    }

    /// is_concurrent=false 时根据 replaced_login_exit_mode 处理并发登录策略。
    pub(super) async fn check_concurrent_policy(&self, login_id: &str) -> GarrisonResult<()> {
        if self.config.is_concurrent {
            return Ok(());
        }
        match self.config.replaced_login_exit_mode {
            ReplacedLoginExitMode::OldDevice => {
                self.kickout(login_id).await?;
            },
            ReplacedLoginExitMode::NewDevice => {
                if let Some(existing_token) = self.session.get_token_by_login_id(login_id) {
                    if let Ok(Some(_)) = self.session.get_token_session(&existing_token).await {
                        tracing::warn!(
                            login_id,
                            mode = "new_device",
                            "new device login rejected: currently in NewDevice mode, valid existing session exists"
                        );
                        return Err(GarrisonError::NotLogin(
                            "stp-new-device-login-rejected-not-allowed::".to_string(),
                        ));
                    }
                }
            },
        }
        Ok(())
    }

    /// `LoginParams.device` 为 None 且 `user_agent` + `ip` 有值时，用 `device_fingerprint_rich` 生成 SHA-256 指纹。
    #[cfg_attr(
        not(any(
            feature = "protocol-jwt",
            feature = "account-credential",
            feature = "protocol-oauth2",
            feature = "protocol-sso",
            feature = "protocol-sign",
            feature = "secure-sign",
            feature = "protocol-httpdigest"
        )),
        allow(unused_mut)
    )]
    pub(super) fn prepare_device_fingerprint(&self, params: &LoginParams) -> LoginParams {
        let mut params = params.clone();
        #[cfg(any(
            feature = "protocol-jwt",
            feature = "account-credential",
            feature = "protocol-oauth2",
            feature = "protocol-sso",
            feature = "protocol-sign",
            feature = "secure-sign",
            feature = "protocol-httpdigest"
        ))]
        if params.device.is_none() {
            if let (Some(ua), Some(ip)) = (&params.user_agent, &params.ip) {
                let fp_input = crate::session::device::DeviceFingerprintInput::from_ua_ip(ua, ip);
                params.device = Some(crate::session::device::device_fingerprint_rich(&fp_input));
            }
        }
        params
    }

    /// 设备绑定策略检测（device-binding feature）：新设备且策略要求二次认证时硬阻断登录。
    pub(super) async fn check_device_binding(
        &self,
        login_id: &str,
        params: &LoginParams,
    ) -> GarrisonResult<()> {
        #[cfg(feature = "device-binding")]
        if let Some(policy) = &self.device_binding_policy {
            let device_id = params.device.as_deref().unwrap_or("");
            if !device_id.is_empty() {
                match policy.is_new_device(login_id, device_id).await {
                    Ok(true) => match policy.require_secondary_auth(login_id, device_id).await {
                        Ok(true) => {
                            tracing::info!(
                                login_id,
                                device_id,
                                "device binding policy triggered secondary auth block (hard block)"
                            );
                            return Err(GarrisonError::NotPermission(
                                "secondary auth required".to_string(),
                            ));
                        },
                        Ok(false) => {},
                        Err(e) => tracing::warn!(
                            error = %e,
                            "DeviceBindingPolicy::require_secondary_auth failed"
                        ),
                    },
                    Ok(false) => {},
                    Err(e) => tracing::warn!(
                        error = %e,
                        "DeviceBindingPolicy::is_new_device failed"
                    ),
                }
            }
        }
        let _ = (login_id, params);
        Ok(())
    }

    /// 登录事件通知：plugin on_login + listener broadcast + 异常检测；锁外执行，避免持锁跨 broadcast。
    pub(super) async fn notify_login_event(
        &self,
        login_id: &str,
        token: &str,
        params: &LoginParams,
    ) {
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            // CWE-532: 事件载荷统一携掩码 token，listener 打日志不泄露活动会话 token
            lm.broadcast(&GarrisonEvent::Login {
                login_id: login_id.to_string(),
                token: crate::listener::mask_token_for_event(token),
                device: params.device.clone(),
                request_context: None,
            })
            .await;
        }
        #[cfg(feature = "security-extra")]
        self.run_anomaly_check_on_login(login_id, params).await;
        let _ = params; // suppress unused warning when listener/security-alert features are disabled
    }

    /// 强制最大登录数量：按 `last_active_at` 升序踢出最旧会话直到数量 ≤ max（`max=0` 不操作）；踢出按 `OverflowLogoutMode` 广播 Logout / Kickout / Replaced 事件（需 listener feature 且注入 listener_manager）。
    /// **独立获取 `with_login_lock`**，调用方不得预先持锁（`tokio::sync::Mutex` 不可重入，已持锁再调用会死锁）；需与 create 组成原子序列时改调 `Self::enforce_max_login_count_inner`。
    /// 持锁期间执行 1 次 `get_account_session` + 至多 4N 次 DAO 调用（N = 踢出数），调用方需评估对同 `login_id` 并发请求的阻塞。
    pub async fn enforce_max_login_count(&self, login_id: &str, max: u32) -> GarrisonResult<()> {
        // 独立获取 with_login_lock：login_inner 已持锁时改调 enforce_max_login_count_inner，避免重入死锁。
        // login_id shadowing 到 String，供 async block 内 'static 借用（与 ensure_token_in_account_session 同模式）。
        let login_id: String = login_id.to_string();
        self.session
            .with_login_lock(&login_id, async {
                Self::enforce_max_login_count_inner(self, &login_id, max).await
            })
            .await
    }

    /// enforce_max_login_count 内部实现：调用方必须已持 `with_login_lock`；供 `login_inner` 与 `create_token_session_inner` 组合成原子序列，消除 create 返回后重新取锁之间的 TOCTOU 窗口。
    /// 已知冗余：超限分支再次 `get_account_session`（1 次冗余 DAO get）；让 `create_token_session_inner` 返回 AccountSession 会改变签名并影响独立调用路径，且该分支低频（1-5ms），维持现状（简洁与 fail-safe 重新读取优先）。
    pub(crate) async fn enforce_max_login_count_inner(
        &self,
        login_id: &str,
        max: u32,
    ) -> GarrisonResult<()> {
        if max == 0 {
            return Ok(());
        }

        // 闸门读 DAO AccountSession.tokens（权威源）：本地 login_token_map 是多节点互不可见的进程内索引（节点 A 登满后节点 B 直接放行），会让 max_login_count 形同虚设；登录非热路径，1 次 DAO get 可承受。
        let account = match self.session.get_account_session(login_id).await? {
            Some(a) => a,
            None => return Ok(()),
        };
        if account.tokens.len() <= max as usize {
            return Ok(());
        }

        // 按 last_active_at 升序排序（最旧排前面）
        let mut token_times: Vec<(String, i64)> = account
            .tokens
            .iter()
            .map(|ti| (ti.token.clone(), ti.last_active_at))
            .collect();
        token_times.sort_by_key(|(_, t)| *t);

        // 踢出最旧的 (count - max) 个，按 overflow_logout_mode 广播事件
        let to_evict = token_times.len().saturating_sub(max as usize);
        for (token, _) in token_times.iter().take(to_evict) {
            // 锁内用 logout_inner（不重入 with_login_lock）；token 不存在时跳过（幂等，与其他 logout 调用一致）。
            match self.session.get_token_session(token).await? {
                Some(ts) => self.session.logout_inner(token, &ts).await?,
                None => {
                    // 脱敏只打印 token 前 8 字符；用 get(..8) 而非 &token[..8]（字节 8 落在多字节 UTF-8 字符中间会 panic = DoS）。
                    let token_preview = token.get(..8).unwrap_or(token);
                    tracing::warn!(
                        token = %token_preview,
                        "enforce_max_login_count: token not found, skipping logout_inner"
                    );
                },
            }
            // 根据 overflow_logout_mode 广播对应事件
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                match self.config.overflow_logout_mode {
                    OverflowLogoutMode::Logout => {
                        // CWE-532: 事件载荷统一携掩码 token
                        lm.broadcast(&GarrisonEvent::Logout {
                            login_id: login_id.to_string(),
                            token: crate::listener::mask_token_for_event(token),
                            request_context: None,
                        })
                        .await;
                    },
                    OverflowLogoutMode::Kickout => {
                        lm.broadcast(&GarrisonEvent::Kickout {
                            login_id: login_id.to_string(),
                            token: crate::listener::mask_token_for_event(token),
                            reason: loc!("session-overflow-kickout", ""),
                            request_context: None,
                        })
                        .await;
                    },
                    OverflowLogoutMode::Replaced => {
                        lm.broadcast(&GarrisonEvent::Replaced {
                            login_id: login_id.to_string(),
                            token: crate::listener::mask_token_for_event(token),
                            reason: loc!("session-overflow-replaced", ""),
                            request_context: None,
                        })
                        .await;
                    },
                }
            }
        }

        Ok(())
    }

    /// 按 `config.token_style` 生成 token：uuid / random_64 / simple（simple UUID，32 字符）/ jwt（需 `protocol-jwt`，委托 `JwtHandler::sign`）。
    pub(super) fn generate_token(&self, login_id: &str) -> GarrisonResult<String> {
        match self.config.token_style.as_str() {
            "uuid" => Ok(uuid::Uuid::new_v4().to_string()),
            "random_64" => Ok(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            "simple" => {
                // 复用 `SimpleTokenStyle`（HMAC-SHA256 签名），消除裸 UUID 随机 token 与 verify 路径的格式不一致；feature 未启用时 fail-closed 返回 Config，与 TokenStyleFactory 一致。
                #[cfg(feature = "secure-simple-token")]
                {
                    let style = crate::core::token::SimpleTokenStyle::new(
                        self.config.jwt_secret.as_str().to_string(),
                    );
                    style.generate(login_id, self.config.timeout)
                }
                #[cfg(not(feature = "secure-simple-token"))]
                {
                    Err(GarrisonError::Config(
                        "stp-simple-token-style-requires-secure-simple-token-feature::".to_string(),
                    ))
                }
            },
            "jwt" => {
                #[cfg(feature = "protocol-jwt")]
                {
                    // 主登录即密码认证：amr / auth_time 取统一口径 `primary_issuance_claims`；`seed_primary_amr=false` 时零断言签发。
                    let now = chrono::Utc::now().timestamp();
                    let (amr, auth_time) = if self.config.seed_primary_amr {
                        crate::stp::mfa::primary_issuance_claims(now)
                    } else {
                        (Vec::new(), None)
                    };
                    // 有租户上下文时经 `with_tid` 签发 `tid` 绑定 claim（租户隔离的 Stateless 补口，`check_login_stateless` 从首次验签 claims 直读 tid）；无上下文不接 tid，payload 与既有格式逐字节一致。
                    let tenant_id = crate::context::tenant::TENANT
                        .try_get()
                        .ok()
                        .map(|ctx| ctx.tenant_id);
                    let handler =
                        crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
                    match tenant_id {
                        Some(tid) => handler.with_tid(tid).sign_with_amr(
                            login_id,
                            self.config.timeout,
                            &amr,
                            auth_time,
                        ),
                        None => {
                            handler.sign_with_amr(login_id, self.config.timeout, &amr, auth_time)
                        },
                    }
                }
                #[cfg(not(feature = "protocol-jwt"))]
                {
                    let _ = login_id;
                    Err(GarrisonError::Config(
                        "stp-jwt-token-style-requires-protocol-jwt::".to_string(),
                    ))
                }
            },
            other => Err(GarrisonError::Config(format!(
                "stp-unknown-token-style::{}",
                other
            ))),
        }
    }

    /// Stateless 模式：仅 JWT verify，不查询 session（需 `protocol-jwt` + `token_style=jwt`，否则 Config 错误）；verify 失败透传 `InvalidToken`/`ExpiredToken`，`enable_jwt_revocation=true` 时校验 jti 黑名单。
    /// 租户绑定：从首次验签 claims 读 `tid`，与请求租户不一致即拒——否则客户端换 `X-Tenant-Id` 头可让 jti 黑名单随请求租户命名空间错位，形成吊销逃逸；无 `tid` 默认放行，`require_tenant_bound_jwt=true` 时显性拒绝（`stp-check-login-tenant-unbound`）。
    pub(super) async fn check_login_stateless(
        &self,
        token: &str,
    ) -> GarrisonResult<(bool, Option<String>)> {
        #[cfg(feature = "protocol-jwt")]
        {
            // fail-closed 启动期互斥校验：jwt + Stateless 且未启用撤销 = 不可吊销的永久凭证（高危），拒绝并给出三选一指引（开启撤销 / 改 Mixin / 显式风险接受）。
            if self.config.token_style == "jwt"
                && !self.config.enable_jwt_revocation
                && !self.config.allow_stateless_jwt_no_revocation
            {
                return Err(GarrisonError::Config(
                    "stp-stateless-jwt-requires-revocation::".to_string(),
                ));
            }
            if self.config.token_style != "jwt" {
                return Err(GarrisonError::Config(
                    "stp-stateless-requires-jwt-token-style::".to_string(),
                ));
            }
            let handler = crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
            // 无效签名返回 InvalidToken，过期返回 ExpiredToken（透传 verify 错误）
            let claims = handler.verify(token)?;
            // 租户绑定校验（verify 成功后、黑名单检查前）：签发租户 ≠ 请求租户即拒绝，错误码与会话模式的跨租户拒绝一致
            if let Ok(ctx) = crate::context::tenant::TENANT.try_get() {
                match claims.tid {
                    Some(tid) if tid != ctx.tenant_id => {
                        return Err(GarrisonError::Session(
                            "stp-check-login-tenant-mismatch::".to_string(),
                        ));
                    },
                    // 严格收口开关：存量无 tid token 在租户上下文内显性拒绝（默认 false 向后兼容；开启后需等存量 token 自然过期轮替）
                    None if self.config.require_tenant_bound_jwt => {
                        return Err(GarrisonError::Session(
                            "stp-check-login-tenant-unbound::".to_string(),
                        ));
                    },
                    _ => {},
                }
            }
            // JWT 撤销黑名单检查（verify 成功后、返回 Ok 前）
            if self.config.enable_jwt_revocation {
                if let Some(jti) = &claims.jti {
                    let key = format!("jwt:blacklist:{}", jti);
                    if self.dao().get(&key).await?.is_some() {
                        return Err(GarrisonError::TokenRevoked(format!(
                            "jwt-revoked::jti={}",
                            &jti[..jti.len().min(16)]
                        )));
                    }
                }
            }
            // stateless 无 session，login_id 直接取自 claims（零额外读取）
            Ok((true, Some(claims.login_id)))
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            let _ = token;
            Err(GarrisonError::Config(
                "stp-stateless-requires-protocol-jwt::".to_string(),
            ))
        }
    }

    /// Mixin 模式：`protocol-jwt` + `token_style=jwt` 时先 JWT verify（失败直接返回，不查 session）再查 session，否则仅查 session。
    /// 返回值第二元为 Token-Session 快照，供请求内复用（租户绑定、hover 检查与登录身份缓存共享，消除重复 DAO 读）。
    pub(super) async fn check_login_mixin(
        &self,
        token: &str,
    ) -> (
        GarrisonResult<(bool, Option<String>)>,
        Option<crate::session::TokenSession>,
    ) {
        #[cfg(feature = "protocol-jwt")]
        {
            if self.config.token_style == "jwt" {
                let handler =
                    crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
                // JWT 签名无效直接返回错误（不查询 session）
                if let Err(e) = handler.verify(token) {
                    return (Err(e), None);
                }
            }
        }
        // is_valid_with_session 返回的快照供 hover 与登录身份缓存复用，消除同一请求内的重复 DAO 读
        let ts_opt = match self.session.is_valid_with_session(token).await {
            Ok(ts) => ts,
            Err(e) => return (Err(e), None),
        };
        let valid = ts_opt.is_some();
        let login_id = ts_opt.as_ref().map(|ts| ts.login_id.clone());
        if !valid {
            // 无效时广播 SessionTimeout：token session 仍存在（account session 过期）才有 login_id 可播，完全不存在则跳过。
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                if let Ok(Some(ts)) = self.session.get_token_session(token).await {
                    lm.broadcast(&GarrisonEvent::SessionTimeout {
                        login_id: ts.login_id,
                        token: token.to_string(),
                        request_context: None,
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return (
                    Err(GarrisonError::Session("stp-not-login::".to_string())),
                    None,
                );
            }
        }
        // 悬停检查（仅 valid 时）
        if valid {
            let hover_ok = match self.check_and_update_hover(token, ts_opt.as_ref()).await {
                Ok(ok) => ok,
                Err(e) => return (Err(e), None),
            };
            if !hover_ok {
                return (Ok((false, None)), ts_opt);
            }
            // Token 自动续签（若启用且剩余 TTL 低于阈值）
            if let Err(e) = self.check_and_renew(token).await {
                tracing::warn!(error = %e, "Token auto-renewal failed, old Token still in use");
            }
            return (Ok((true, login_id)), ts_opt);
        }
        (Ok((false, None)), ts_opt)
    }

    /// 检查悬停超时并更新最后活跃时间（仅会话有效时调用，Token-Session 快照由调用方传入复用）：超时执行 `logout` 并广播 `SessionTimeout`，按 `throw_on_not_login` 返回 `Err(Session)` 或 `Ok(false)`；未超时更新 `last_active` 返回 `Ok(true)`；快照为 `None` 视为有效（与原逻辑一致）。
    /// `logout` 失败只记 `warn`，不静默吞掉。
    pub(super) async fn check_and_update_hover(
        &self,
        token: &str,
        ts_opt: Option<&crate::session::TokenSession>,
    ) -> GarrisonResult<bool> {
        if let Some(ts) = ts_opt {
            let now_millis = self.clock.now().timestamp_millis();
            let should_evict = self.config.session_hover_timeout > 0 && {
                let timeout_millis = self.config.session_hover_timeout * 1000;
                match self.session.get_last_active(&ts.login_id) {
                    Some(last) => now_millis - last > timeout_millis,
                    None => false,
                }
            };
            if should_evict {
                if let Err(e) = self.session.logout(token).await {
                    tracing::warn!(error = %e, "hover timeout logout failed");
                }
                #[cfg(feature = "listener")]
                if let Some(lm) = &self.listener_manager {
                    lm.broadcast(&GarrisonEvent::SessionTimeout {
                        login_id: ts.login_id.clone(),
                        token: token.to_string(),
                        request_context: None,
                    })
                    .await;
                }
                if self.config.throw_on_not_login {
                    return Err(GarrisonError::Session("stp-session-timeout::".to_string()));
                }
                return Ok(false);
            }
            self.session.update_last_active_at(&ts.login_id, now_millis);
        }
        Ok(true)
    }

    /// Simple 模式：仅 session 校验，不验证 JWT 签名；session 不存在时按 `throw_on_not_login` 返回 `Ok(false)` 或 `Session` 错误。
    /// 返回值第二元为 Token-Session 快照，供请求内复用（租户绑定、hover 检查与登录身份缓存共享，消除重复 DAO 读）。
    pub(super) async fn check_login_simple(
        &self,
        token: &str,
    ) -> (
        GarrisonResult<(bool, Option<String>)>,
        Option<crate::session::TokenSession>,
    ) {
        // is_valid_with_session 返回的快照供 hover 与登录身份缓存复用，消除同一请求内的重复 DAO 读
        let ts_opt = match self.session.is_valid_with_session(token).await {
            Ok(ts) => ts,
            Err(e) => return (Err(e), None),
        };
        let valid = ts_opt.is_some();
        let login_id = ts_opt.as_ref().map(|ts| ts.login_id.clone());
        if !valid {
            // 无效时广播 SessionTimeout：token session 仍存在（account session 过期）才有 login_id 可播，完全不存在则跳过。
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                if let Ok(Some(ts)) = self.session.get_token_session(token).await {
                    lm.broadcast(&GarrisonEvent::SessionTimeout {
                        login_id: ts.login_id,
                        token: token.to_string(),
                        request_context: None,
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return (
                    Err(GarrisonError::Session("stp-not-login::".to_string())),
                    None,
                );
            }
        }
        // 悬停检查（仅 valid 时）
        if valid {
            let hover_ok = match self.check_and_update_hover(token, ts_opt.as_ref()).await {
                Ok(ok) => ok,
                Err(e) => return (Err(e), None),
            };
            if !hover_ok {
                return (Ok((false, None)), ts_opt);
            }
            // Token 自动续签（若启用且剩余 TTL 低于阈值）
            if let Err(e) = self.check_and_renew(token).await {
                tracing::warn!(error = %e, "Token auto-renewal failed, old Token still in use");
            }
            return (Ok((true, login_id)), ts_opt);
        }
        (Ok((false, None)), ts_opt)
    }
}

// GarrisonLogicDefault 私有方法：JWT 撤销黑名单

impl GarrisonLogicDefault {
    /// 黑名单写入 `login_id` 当前全部会话 token 的 jti（批量入口）；**调用方必须已持 `with_login_lock`**，与 `logout_by_login_id_inner` 的会话删除同临界区，闭合「锁外快照 → 并发 login 插入 → jti 未拉黑」的 TOCTOU 窗口。
    /// 快照取自 DAO AccountSession.tokens（非可能滞后的 login_token_map）；读取失败只 warn 并继续，删除照常执行（日志供部署侧监控覆盖缺口）。
    #[cfg(feature = "protocol-jwt")]
    pub(crate) async fn blacklist_all_jwt_jti_locked(&self, login_id: &str) {
        if !self.config.enable_jwt_revocation || self.config.token_style != "jwt" {
            return;
        }
        let tokens: Vec<String> = match self.session.get_account_session(login_id).await {
            Ok(Some(account)) => account.tokens.into_iter().map(|ti| ti.token).collect(),
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    login_id,
                    "{}", crate::i18n::translate_detail("logs-stp-jti-blacklist-snapshot-read-failed", &[])
                );
                return;
            },
        };
        for token in &tokens {
            self.blacklist_jwt_jti(token).await;
        }
    }

    /// 将 JWT 的 `jti` 写入 DAO 黑名单 `jwt:blacklist:{jti}` = "1"（TTL = 剩余有效期秒数）；无 jti / 已过期 / DAO 失败只记日志，不中断主流程。
    /// 键不带租户段：tenant-isolation 下 DAO 按请求租户加物理前缀，键内拼租户段无法跨越写读两侧错位；跨租户吊销逃逸由签发侧 `tid` 绑定 + [`Self::check_login_stateless`] 绑定校验闭合。
    #[cfg(feature = "protocol-jwt")]
    pub(crate) async fn blacklist_jwt_jti(&self, token: &str) {
        if !self.config.enable_jwt_revocation || self.config.token_style != "jwt" {
            return;
        }
        let handler = crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
        let claims = match handler.verify(token) {
            Ok(c) => c,
            Err(_) => return, // token 已过期或无效，无需加入黑名单
        };
        let jti = match claims.jti {
            Some(j) => j,
            None => return, // 旧 token 无 jti，跳过
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let ttl_secs = claims.exp - now_unix;
        if ttl_secs <= 0 {
            return; // 已过期，无需加入黑名单
        }
        let key = format!("jwt:blacklist:{}", jti);
        // 写失败有界重试（退避 100/300ms，共 3 次）：撤销写失败若只 warn，被吊销 token 在全部节点继续有效至自然过期；重试消化瞬时抖动，最终失败升级 error 供告警，对外仍保持幂等成功（登出不因撤销存储故障而报错）。
        const RETRY_ATTEMPTS: u32 = 3; // 1 首次 + 2 重试
        let mut result = self.dao().set(&key, "1", ttl_secs as u64).await;
        for attempt in 1..RETRY_ATTEMPTS {
            if result.is_ok() {
                break;
            }
            tokio::time::sleep(jwt_blacklist_retry_delay(attempt)).await;
            result = self.dao().set(&key, "1", ttl_secs as u64).await;
        }
        if let Err(e) = result {
            tracing::error!(
                error = %e,
                jti = &jti[..jti.len().min(16)],
                attempts = RETRY_ATTEMPTS,
                "JWT blacklist write failed after retries; \
                 revoked token may remain valid until natural expiry"
            );
        }
    }
}

/// JWT 黑名单写入重试退避（attempt 从 1 起）：委托 limiteron `retry::delay_for_attempt`（initial=100ms、factor=3.0、max_delay=300ms、jitter=0 保持确定性）；即第 1 次重试前等 100ms、第 2 次前等 300ms。
#[cfg(feature = "protocol-jwt")]
pub(super) fn jwt_blacklist_retry_delay(attempt: u32) -> std::time::Duration {
    limiteron::retry::delay_for_attempt(
        attempt,
        std::time::Duration::from_millis(100),
        3.0,
        std::time::Duration::from_millis(300),
        0.0,
    )
}

// GarrisonLogicDefault 私有方法：异常检测集成（security-alert feature）

#[cfg(feature = "security-extra")]
impl GarrisonLogicDefault {
    /// login 路径异常检测：遍历所有检测器，广播事件，失败只 warn。
    pub(super) async fn run_anomaly_check_on_login(&self, login_id: &str, params: &LoginParams) {
        let Some(detectors) = &self.anomaly_detectors else {
            return;
        };
        let device_id = params.device.as_deref().unwrap_or("");
        let ip = params.ip.as_deref();
        for detector in detectors {
            match detector.check_on_login(login_id, device_id, ip).await {
                Ok(events) => self.broadcast_anomaly_events(events).await,
                Err(e) => tracing::warn!(error = %e, "AnomalyDetector::check_on_login failed"),
            }
        }
    }

    /// check_login 路径异常检测：遍历所有检测器，广播事件，失败只 warn。
    pub(super) async fn run_anomaly_check_on_check_login(&self, login_id: &str, token: &str) {
        let Some(detectors) = &self.anomaly_detectors else {
            return;
        };
        for detector in detectors {
            match detector.check_on_check_login(login_id, token).await {
                Ok(events) => self.broadcast_anomaly_events(events).await,
                Err(e) => {
                    tracing::warn!(error = %e, "AnomalyDetector::check_on_check_login failed")
                },
            }
        }
    }

    /// 广播告警事件到 `AlertListenerManager`；未注入 manager 时为 no-op（事件被丢弃）。
    pub(super) async fn broadcast_anomaly_events(
        &self,
        events: Vec<crate::strategy::alert::SecurityAlertEvent>,
    ) {
        let Some(manager) = &self.alert_listener_manager else {
            return;
        };
        for event in events {
            manager.broadcast_alert(&event).await;
        }
    }
}

// GarrisonLogicDefault 私有方法：Token 自动续签

impl GarrisonLogicDefault {
    /// 检查并续签 Token（`auto_renewal_threshold > 0` 且剩余 TTL 百分比低于阈值时），成功后经 `CURRENT_RENEWED_TOKEN` task_local 传递新 Token。
    /// 并发防护：续签前取 per-login_id 锁并在锁内二次检查 TTL，避免两个并发 `check_login` 各自续签导致旧 token 已失效却返回 `Ok(true)`（会话假活）。
    /// `Ok(None)` = 未启用续签 / TTL 充足 / 永久键 / 已被并发调用续签；`Err` = 续签失败（auth_logic 未配置 / renew 调用失败）。
    pub(crate) async fn check_and_renew(&self, token: &str) -> GarrisonResult<Option<String>> {
        let threshold = self.config.auto_renewal_threshold;
        if threshold <= 0 {
            return Ok(None);
        }
        // 快速路径：无锁检查 TTL，充足则直接返回
        let remaining = match self.session.get_token_timeout(token).await? {
            Some(d) => d,
            None => return Ok(None),
        };
        let total = self.config.timeout;
        if total <= 0 || remaining.is_zero() {
            return Ok(None);
        }
        // 毫秒精度避免 as_secs() 截断（如 999ms → 0s）导致误判
        let remaining_pct = (remaining.as_millis() as i64 * 100) / (total * 1000);
        if remaining_pct >= threshold {
            return Ok(None);
        }

        // 获取 login_id 用于 per-login_id 续签锁
        let login_id = match self.session.get_token_session(token).await? {
            Some(ts) => ts.login_id,
            None => return Ok(None),
        };

        // 持 per-login_id 续签锁（独立于 GarrisonSession::login_locks）：不能用 login_locks，`renew_to_equivalent` 内部 logout 会再次获取它而重入死锁。
        // 安全点用 `remove_if(strong_count==1)` 移除无等待者条目，防 renewal_locks 随 login_id 数量无界增长（OOM / CWE-770），并覆盖取消时的条目清理。
        let lock = self
            .renewal_locks
            .entry(login_id.clone())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        // 续签流程（在锁内执行，保证二次检查与续签的原子性）
        let renew_flow = async {
            // 二次检查 TTL：可能已被另一并发调用续签
            let remaining = match self.session.get_token_timeout(token).await? {
                Some(d) => d,
                None => return Ok(None),
            };
            if remaining.is_zero() {
                return Ok(None);
            }
            let remaining_pct = (remaining.as_millis() as i64 * 100) / (total * 1000);
            if remaining_pct >= threshold {
                return Ok(None);
            }

            // 续签：非 JWT 用 renew_to_equivalent，JWT 用 refresh_token
            #[cfg(feature = "protocol-jwt")]
            {
                let new_token = if self.config.token_style == "jwt" {
                    self.refresh_token(token).await?
                } else {
                    let auth = self.auth_logic.as_ref().ok_or_else(|| {
                        GarrisonError::Config("stp-auto-renewal-no-auth-logic::".to_string())
                    })?;
                    auth.renew_to_equivalent(token).await?
                };
                set_renewed_token(new_token.clone());
                Ok(Some(new_token))
            }
            #[cfg(not(feature = "protocol-jwt"))]
            {
                if self.config.token_style == "jwt" {
                    return Err(GarrisonError::Config(
                        "stp-auto-renewal-jwt-requires-protocol-jwt::".to_string(),
                    ));
                }
                let auth = self.auth_logic.as_ref().ok_or_else(|| {
                    GarrisonError::Config("stp-auto-renewal-no-auth-logic::".to_string())
                })?;
                let new_token = auth.renew_to_equivalent(token).await?;
                set_renewed_token(new_token.clone());
                Ok(Some(new_token))
            }
        };
        let result = renew_flow.await;

        // 安全点清理（与 GarrisonSession::with_token_session_lock 同模式）：先 drop guard 再 drop 本地 Arc clone，使 strong_count 降到 1（仅剩 DashMap entry）remove_if 才真正移除；仍有等待者（≥2）则由最后一个使用者清理。
        drop(_guard);
        drop(lock);
        self.renewal_locks
            .remove_if(&login_id, |_, l| Arc::strong_count(l) == 1);
        result
    }
}
