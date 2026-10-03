// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SessionLogic 私有 helper 方法。
//!
//! 从 `session/mod.rs` 拆分出的 `GarrisonLogicDefault` 私有 impl 块，
//! 供 trait 实现方法内部调用。通过 `pub(super)` 对父模块可见。

use super::*;

// ============================================================================
// 租户绑定 JWT claims（渗透-租户隔离-会话绑定-1 的 Stateless 补口）
// ============================================================================

/// Stateless JWT 的租户绑定签发载荷：[`crate::protocol::jwt::GarrisonJwtClaims`]
/// 全字段 + `tid`（签发租户绑定）。
///
/// JwtHandler 固定签发 `GarrisonJwtClaims`（无租户 claim 参数，protocol 层
/// 不感知租户语义），租户上下文存在时经 `sign_custom` 以本结构签发，
/// payload 为既有格式 + `tid` claim；无租户上下文仍走 `sign_with_amr`
/// 既有路径，签发格式不变。字段与 serde 跳过属性必须与
/// `GarrisonJwtClaims` 保持一致——`GarrisonJwtClaims::verify`（serde 忽略
/// 未知字段）解析本结构签发的 token 时行为与既有 token 完全一致，
/// `jwt_tenant_claims_parity_tests::tenant_bound_claims_parse_as_garrison_jwt_claims`
/// 测试守护该契约防字段漂移。
#[cfg(feature = "protocol-jwt")]
#[derive(Debug, serde::Serialize)]
pub(super) struct TenantBoundJwtClaims {
    /// 主体标识（与 login_id 一致）。
    pub(super) sub: String,
    /// 签发时间（Unix 秒）。
    pub(super) iat: i64,
    /// 过期时间（Unix 秒）。
    pub(super) exp: i64,
    /// Garrison 登录标识。
    pub(super) login_id: String,
    /// 可选设备标识（stp 签发路径恒为 None，序列化为 null，与既有格式一致）。
    pub(super) device: Option<String>,
    /// JWT 唯一标识（签发时生成 UUID v4）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) jti: Option<String>,
    /// Not Before（签发时刻）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) nbf: Option<i64>,
    /// RFC 8176 amr claim（账本映射；None 时跳过序列化）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) amr: Option<Vec<String>>,
    /// OIDC auth_time claim（None 时跳过序列化）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) auth_time: Option<i64>,
    /// 签发租户绑定（`TENANT` 上下文存在时写入；十进制 i64）。
    pub(super) tid: i64,
}

#[cfg(feature = "protocol-jwt")]
impl TenantBoundJwtClaims {
    /// 按既有 `sign_with_kid` 同一口径构造（iat/nbf/exp/jti 生成逻辑一致）。
    pub(super) fn new(
        login_id: &str,
        timeout: i64,
        amr: &[String],
        auth_time: Option<i64>,
        tid: i64,
    ) -> GarrisonResult<Self> {
        if timeout < 0 {
            return Err(GarrisonError::Config(format!(
                "jwt-timeout-negative::{}",
                timeout
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("system-clock-error::{}", e)))?
            .as_secs() as i64;
        let exp = now.checked_add(timeout).ok_or_else(|| {
            GarrisonError::InvalidParam(format!("jwt-timeout-overflow::{}", timeout))
        })?;
        Ok(Self {
            sub: login_id.to_string(),
            iat: now,
            exp,
            login_id: login_id.to_string(),
            device: None,
            jti: Some(uuid::Uuid::new_v4().to_string()),
            nbf: Some(now),
            amr: if amr.is_empty() {
                None
            } else {
                Some(amr.to_vec())
            },
            auth_time,
            tid,
        })
    }
}

/// check 侧 `tid` 探针：只反序列化租户绑定 claim（未知字段忽略，缺失为 None）。
#[cfg(feature = "protocol-jwt")]
#[derive(serde::Deserialize)]
struct JwtTenantProbe {
    #[serde(default)]
    tid: Option<i64>,
}

// ============================================================================
// 私有 helper 方法（从 mod.rs 搬移，供 SessionLogic impl 调用）
// ============================================================================

impl GarrisonLogicDefault {
    /// login_id 输入不变量校验（渗透-会话与令牌-2 / 限流与爆破-1 /
    /// 注入-login_id 无长度上限-2：login 签发源头的 fail-closed 收口）。
    ///
    /// 与 [`crate::core::token::SimpleTokenStyle::generate`] 的校验语义对齐
    /// （错误码同源命名）：
    /// - trim 后非空（空串 / 纯空白拒绝：空主体低于任何业务契约）
    /// - 不含 `\x1f`（token body 字段分隔符，内嵌会造成 verify 身份切分歧义）
    /// - 不含其他控制字符（CRLF / 日志污染 / 键拼接歧义）
    /// - 字节长度 ≤ `config.login_id_max_len`（`0` = 不限制；默认 255，
    ///   封住未认证超大 login_id 灌入会话存储的内存增长向量）
    ///
    /// 仅拒绝明显非法值，正常标识不受影响；错误信息不含输入内容回显。
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

    /// login 实际逻辑（供 `login` 方法在 metrics 包装内调用）。
    ///
    /// 抽取此私有方法以保持 `login` trait 方法的 metrics 包装简洁。
    ///
    /// # login_id 不变量
    ///
    /// 进入防火墙钩子前先做输入校验（[`Self::validate_login_id`]），
    /// 空串 / 空白 / 控制字符 / 超长 login_id 一律 fail-closed，
    /// 不签发会话（对齐 SimpleTokenStyle 的生成期校验语义）。
    ///
    /// # 持锁时间
    ///
    /// `create_token_session_inner` + `enforce_max_login_count_inner`
    /// 在同一 `with_login_lock` 临界区内执行。持锁时间估算：
    /// - `max_login_count == 0`（不限制）：3 次 DAO 调用（create_inner 的 set×2 + get×1），典型 3-10ms
    /// - `max_login_count > 0` 且未超限：4 次 DAO 调用（+ enforce 的 get_account_session），典型 5-15ms
    /// - `max_login_count > 0` 且超限踢出：4 + 4N 次 DAO 调用（N = 踢出数），典型 5-25ms+
    ///
    /// 持锁期间阻塞同 `login_id` 的其他 `login`/`logout`/`kickout` 请求（per-login_id 锁粒度）。
    /// 不同 `login_id` 的请求不受影响（DashMap 分片锁）。
    pub(super) async fn login_inner(
        &self,
        login_id: &str,
        params: &LoginParams,
    ) -> GarrisonResult<String> {
        // 0. login_id 输入不变量（fail-closed，先于防火墙钩子，避免非法值
        // 消耗限流/爆破计数等校验资源）
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

        // 5.5 角色层级 TC 预计算 + 权限并集缓存（0.5.0 `role_hierarchy` 表接线，
        //     见 `cache_role_union_on_login`；fail-open，不阻断登录）
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        self.cache_role_union_on_login(login_id).await;

        // 6. 事件通知（锁外执行，避免持锁跨 broadcast）
        self.notify_login_event(login_id, &token, &params).await;
        Ok(token)
    }

    /// 登录时角色层级 TC 预计算 + 权限并集缓存（0.5.0 `role_hierarchy` 表接线）。
    ///
    /// 文档意图（mdbook/src/permission-rbac.md「角色层级 hierarchy」、
    /// docs/ROADMAP.md H6、docs/CHANGELOG.md 0.5.0「角色层级」、
    /// `role_hierarchy.rs` 模块注释）：登录时经 `RoleHierarchyService` 预计算
    /// `role_hierarchy` 表的传递闭包（TC）并缓存，得到「直接角色 ∪ 间接祖先」
    /// 的权限并集，避免每次角色校验都做 DFS。
    ///
    /// # 流程（`login_inner` 会话创建成功后调用）
    ///
    /// 1. 经 firewall 策略取直接角色列表（最终来自 `GarrisonInterface::get_role_list`）
    /// 2. 租户维度取 `TENANT` task_local（无上下文时租户 0 = 单租户默认）
    /// 3. 逐角色 `RoleHierarchyService::get_ancestors`——未命中时 `compute_closure`
    ///    并缓存整个租户闭包到 `tenant:{tid}:role_closure`（TTL 3600 秒）
    /// 4. 并集写缓存 `role:cache:{login_id}`（`DaoKeyPrefix::RoleCache`，
    ///    TTL 3600 秒，与闭包缓存一致；`dao/warmup` 的 `role:*` 预热可复用）
    ///
    /// # fail-open 语义
    ///
    /// 本步骤是缓存预热，任何失败都不阻断登录、不影响返回的 token：
    /// - 角色列表为空：无事可做，直接返回（不触发 TC 查询、不写缓存）
    /// - DAO 无 SQL 后端（`query_role_hierarchy_edges` trait 默认
    ///   `NotImplemented`，如 MockDao / oxcache-only 部署）：debug 日志跳过
    /// - 其他错误（SQL 查询 / 缓存读写失败）：warn 日志跳过
    ///
    /// # 调用位置
    ///
    /// 仅接在 `login_inner`（会话新建路径）；`login_with_token`（外部 token
    /// 导入）与 `try_reuse_session` 复用路径不触发——复用路径下首次登录已
    /// 写入缓存。运行时角色校验（`GarrisonPermissionStrategyDefault::expand_roles`）
    /// 仍走 builder 注入的 `role_hierarchy` 映射，与本缓存互补、互不依赖。
    ///
    /// # Feature gate
    ///
    /// `RoleHierarchyService` 依赖 SQL 查询，门控
    /// `any(db-sqlite, db-postgres, db-mysql)`，与本方法一致。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    pub(super) async fn cache_role_union_on_login(&self, login_id: &str) {
        // 1. 直接角色列表（fail-open：取角色失败跳过预热，不影响登录）
        let roles = match self.firewall.get_role_list(login_id).await {
            Ok(roles) => roles,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    login_id = %login_id,
                    "role union cache: get_role_list failed, skip (fail-open)"
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
                    // DAO 无 SQL 后端（MockDao / oxcache-only 部署）：
                    // 常规能力缺失而非故障，debug 级跳过，避免每次登录 warn 刷屏
                    tracing::debug!(
                        login_id = %login_id,
                        "role union cache: dao has no SQL backend, skip"
                    );
                    return;
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        login_id = %login_id,
                        "role union cache precompute failed, skip (fail-open)"
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
                        "role union cache write failed (fail-open)"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    login_id = %login_id,
                    "role union cache serialize failed (fail-open)"
                );
            },
        }
    }

    /// 锁内公共序列：并发策略检查 + 创建会话 + 强制最大登录数。
    ///
    /// 抽取自 `login_inner` 与 `login_with_token` 的公共逻辑，统一会话创建配额行为，
    /// 保证 `create` 与 `enforce_max_login_count` 在同一 `with_login_lock` 临界区内执行，
    /// 消除 TOCTOU 竞态。`enforce_max_login_count` 失败时对新建会话做回滚。
    ///
    /// # 参数
    /// - `login_id` / `token`：会话主体与 token
    /// - `device` / `ip` / `user_agent`：设备上下文（来自 `LoginParams`，`login_with_token` 传 `None`）
    /// - `remember_me`：记住我
    ///
    /// # remember_me_enabled 开关（渗透-会话与令牌-1）
    ///
    /// 本方法是 stp login 调用链的唯一收口：`config.remember_me_enabled = false`
    /// 时客户端提交的 `remember_me=true` 在此处一律降级为 `false`
    /// （`effective_timeout` 不写 90 天，按全局 `timeout` 签发），使「禁用长会话」
    /// 的配置在 HTTP login 实际调用链真实生效。降级仅记 debug 日志，不报错
    /// （开关语义为忽略请求，非拒绝登录）。
    ///
    /// # amr 播种开关（渗透-认证绕过-3 / 会话与令牌-5）
    ///
    /// `config.seed_primary_amr = false` 时向 `create_token_session_inner`
    /// 传递不播种标记：会话 `amr_ledger` 为空、`auth_time` 为 `None`，
    /// 不为未经密码校验的 login 断言 `pwd` / AAL 1 认证事实。
    pub(super) async fn create_session_with_quota(
        &self,
        login_id: &str,
        token: &str,
        device: Option<&str>,
        ip: Option<&str>,
        user_agent: Option<&str>,
        remember_me: bool,
    ) -> GarrisonResult<()> {
        // 1. 并发策略（is_concurrent=false）。注意：必须在 login 锁外执行，
        // 因为 `check_concurrent_policy` 在 OldDevice 模式下会调用 `kickout`
        // （内部再次获取 per-login_id 锁），与下方 `with_login_lock` 临界区不能嵌套，
        // 否则会重入死锁。
        self.check_concurrent_policy(login_id).await?;

        // remember_me_enabled=false：客户端请求的 remember_me 降级为 false
        // （渗透-会话与令牌-1：开关在调用链真实生效，effective_timeout 不写 90 天）
        let effective_remember_me = remember_me && self.config.remember_me_enabled;
        if remember_me && !effective_remember_me {
            tracing::debug!(
                login_id,
                "remember_me requested but disabled by config, using default timeout"
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

    /// is_share=true 时尝试复用现有有效 token。
    ///
    /// 返回 `Ok(Some(token))` 表示复用成功，`Ok(None)` 表示无可复用会话。
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

    /// 自动生成设备指纹（强化：使用 `device_fingerprint_rich`）。
    ///
    /// `LoginParams.device` 为 None 但 `user_agent` + `ip` 有值时生成 SHA-256 指纹。
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

    /// 设备绑定策略检测（device-binding feature，强化：hard block）。
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

    /// 触发登录事件通知：plugin on_login + listener broadcast + 异常检测。
    ///
    /// 在锁外执行，避免持锁跨 broadcast。
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

    /// 强制最大登录数量：踢出最旧的会话直到数量 <= max。
    ///
    /// 按 `last_active_at` 升序排序（最旧排前面），踢出最早的 (count - max) 个 token。
    /// `max=0` 时不做任何操作（0 表示不限制，由调用方判断）。
    ///
    /// 踢出后根据 [`crate::config::OverflowLogoutMode`] 广播对应事件：
    /// - `Logout`：广播 `GarrisonEvent::Logout`（默认）
    /// - `Kickout`：广播 `GarrisonEvent::Kickout`（reason: "超过最大登录数限制"）
    /// - `Replaced`：广播 `GarrisonEvent::RevokeToken`
    ///
    /// 事件广播需启用 `listener` feature 且注入 `listener_manager`，否则跳过。
    ///
    /// # 并发安全
    ///
    /// 整个函数体在 `with_login_lock(login_id)` 保护下执行，保证 enforce 内部
    /// Account-Session read-modify-write 序列的并发安全。内部 `logout` 改为
    /// `logout_inner`（不重入 `with_login_lock`），避免死锁。
    ///
    /// # 与 `login_inner` 的关系
    ///
    /// 本方法**独立获取 `with_login_lock`**，调用方**无需也不能**预先持锁——
    /// `tokio::sync::Mutex` 不可重入，已持锁的调用方再调用本方法会直接死锁。
    ///
    /// `login_inner` 需要将 create + enforce 组合成真正的原子序列时，应直接调用
    /// `enforce_max_login_count_inner`（无锁版本，`pub(crate)` 不出现在公开文档），
    /// 而非本方法。本方法仅供独立调用场景（如外部 API 主动触发踢出、测试代码）使用。
    ///
    /// # 持锁时间
    ///
    /// 持锁期间执行 1 次 `get_account_session` + 至多 4N 次 DAO 调用
    /// （N = 待踢出 token 数：`get_token_session` + `logout_inner` 内的
    /// `delete` + `get_account_session` + `update`）。典型场景（max=5，
    /// 踢出 1 个）持锁 5-25ms，调用方需评估对同 `login_id` 并发请求的阻塞影响。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `max`: 最大允许同时登录数。
    ///
    /// # 错误
    /// - DAO 查询失败：透传 `GarrisonError`。
    pub async fn enforce_max_login_count(&self, login_id: &str, max: u32) -> GarrisonResult<()> {
        // 独立获取 with_login_lock（与 login_inner 的 create+enforce 原子序列无关）。
        // login_inner 已持锁时直接调用 enforce_max_login_count_inner，避免重入死锁。
        // login_id 所有权 shadowing 到 String，供 async block 内 'static 借用（与 ensure_token_in_account_session 模式一致）。
        let login_id: String = login_id.to_string();
        self.session
            .with_login_lock(&login_id, async {
                Self::enforce_max_login_count_inner(self, &login_id, max).await
            })
            .await
    }

    /// enforce_max_login_count 内部实现（已在 with_login_lock 内，调用方必须已持锁）。
    ///
    /// 改为 `pub(crate)` 以供
    /// `login_inner` 在已持 `with_login_lock` 的临界区内直接调用，与
    /// `create_token_session_inner` 组合成真正的原子序列，消除
    /// `create_token_session` 返回时锁释放 → plugin/listener 跨 await →
    /// `enforce_max_login_count` 重新获取锁之间的 TOCTOU 竞态窗口。
    ///
    /// # 已知优化机会（暂不修复）
    ///
    /// `login_inner` 调用链中，`create_token_session_inner` 已读取并修改
    /// `AccountSession`，本方法在超限踢出分支会再次 `get_account_session`
    /// 重新读取同一份数据（1 次冗余 DAO get）。修复方案（让 `create_token_session_inner`
    /// 返回 `AccountSession` 供本方法复用）会改变签名，影响 `enforce_max_login_count`
    /// 独立调用路径，增加代码复杂度。当前选择不修复的理由（简洁优先）：
    /// - 冗余读取仅在 `max_login_count > 0` 且超限踢出时发生（低频场景）
    /// - 1 次 DAO get 约 1-5ms，对用户体验无感知
    /// - enforce 独立可用性（fail-safe 重新读取）比微优化更重要
    pub(crate) async fn enforce_max_login_count_inner(
        &self,
        login_id: &str,
        max: u32,
    ) -> GarrisonResult<()> {
        if max == 0 {
            return Ok(());
        }

        // 闸门改读 DAO AccountSession——本地 login_token_map 是进程内索引，
        // 多节点共享存储部署时各节点本地计数互不可见（节点 A 登满 max 个后，
        // 节点 B 本地 map 为空直接放行），max_login_count 形同虚设。
        // AccountSession.tokens 为权威数据源；登录路径非热路径，1 次 DAO get 可承受。
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
            // 已在 with_login_lock 内，用 logout_inner 避免重入 with_login_lock 死锁。
            // 需先 get_token_session 获取 ts（logout_inner 的参数）。
            // token 不存在时跳过（幂等，与其他 logout 调用一致）。
            match self.session.get_token_session(token).await? {
                Some(ts) => self.session.logout_inner(token, &ts).await?,
                None => {
                    // 脱敏：只打印 token 前 8 字符，避免完整 token 泄露到日志。
                    // 用 get(..8) 字符安全截取：&token[..8] 在字节 8 落于多字节
                    // UTF-8 字符中间时会 panic（token 不强制 ASCII，warn 路径 panic = DoS）
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

    /// 根据 `config.token_style` 生成 token。
    ///
    /// - `uuid`: UUID v4（36 字符，含连字符）
    /// - `random_64`: 两个 simple UUID 拼接（64 字符）
    /// - `simple`: simple UUID（32 字符）
    /// - `jwt`: 需启用 `protocol-jwt` feature，委托 `JwtHandler::sign`（）
    pub(super) fn generate_token(&self, login_id: &str) -> GarrisonResult<String> {
        match self.config.token_style.as_str() {
            "uuid" => Ok(uuid::Uuid::new_v4().to_string()),
            "random_64" => Ok(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            "simple" => {
                // 复用 `SimpleTokenStyle`（HMAC-SHA256 签名），
                // 消除裸 UUID 随机 token 与 verify 路径的格式不一致（单点真相）。
                // `secure-simple-token` 未启用时 fail-closed 返回 Config 错误，与 TokenStyleFactory 一致。
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
                // 委托 JwtHandler::sign
                #[cfg(feature = "protocol-jwt")]
                {
                    // 主登录即密码认证：claim 映射取统一口径（与会话账本播种
                    // 同源），不经各签发点自行硬编码；seed_primary_amr=false
                    // 时零断言签发（渗透-认证绕过-3 / 会话与令牌-5）。
                    let now = chrono::Utc::now().timestamp();
                    let (amr, auth_time) = if self.config.seed_primary_amr {
                        crate::stp::mfa::primary_issuance_claims(now)
                    } else {
                        (Vec::new(), None)
                    };
                    // 租户上下文存在时签发携带 `tid` 绑定 claim（渗透-租户隔离-
                    // 会话绑定-1 的 Stateless 补口）：check_login_stateless 据此
                    // 拒绝跨租户复用，换 X-Tenant-Id 头不得逃逸吊销。无租户
                    // 上下文走 `sign_with_amr`，payload 与既有格式逐字节一致。
                    let tenant_id = crate::context::tenant::TENANT
                        .try_get()
                        .ok()
                        .map(|ctx| ctx.tenant_id);
                    match tenant_id {
                        Some(tid) => {
                            let handler = crate::protocol::jwt::JwtHandler::new(
                                self.config.jwt_secret.as_str(),
                            );
                            let claims = TenantBoundJwtClaims::new(
                                login_id,
                                self.config.timeout,
                                &amr,
                                auth_time,
                                tid,
                            )?;
                            handler.sign_custom(&claims)
                        },
                        None => {
                            crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str())
                                .sign_with_amr(login_id, self.config.timeout, &amr, auth_time)
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

    /// Stateless 模式：仅 JWT verify，不查询 session。
    ///
    /// 要求启用 `protocol-jwt` feature 且 `token_style=jwt`，否则返回 `Config` 错误。
    /// JWT verify 失败时透传 `InvalidToken`/`ExpiredToken`（不查询 session）。
    /// `enable_jwt_revocation=true` 时，verify 成功后检查 jti 黑名单。
    ///
    /// # 租户绑定校验（渗透-租户隔离-会话绑定-1 的 Stateless 补口）
    ///
    /// 租户上下文存在且 token 携带 `tid` 绑定 claim（登录时租户上下文内签发）
    /// 时，绑定租户 ≠ 请求租户即拒绝——客户端可控的 `X-Tenant-Id` 头不得携
    /// 他租户签发的 JWT 跨租户复用（否则 jti 黑名单经 DAO 租户前缀错位后
    /// 形成吊销逃逸：黑名单写读各随请求租户命名空间，换头即 miss）。
    /// token 无 `tid`（无租户上下文签发的存量/兼容 token）或无租户上下文时
    /// 行为不变。黑名单键仍为 `jwt:blacklist:{jti}`：键构造无法跨越 DAO 的
    /// 请求租户物理命名空间（写读两侧前缀各随当时的请求租户），同租户内
    /// 命中语义不变，跨租户逃逸由本绑定校验闭合。
    pub(super) async fn check_login_stateless(
        &self,
        token: &str,
    ) -> GarrisonResult<(bool, Option<String>)> {
        #[cfg(feature = "protocol-jwt")]
        {
            // R-sessiontokenconsistency / ：stateless JWT 但未启用撤销 = 不可吊销的永久凭证（高危）。
            // 启动期互斥校验：token_style=jwt 且 jwt_mode=Stateless 且 enable_jwt_revocation=false 时拒绝，
            // 给出三选一指引（开启撤销 / 改 Mixin / 显式风险接受）。fail-closed，不依赖 token 合法性。
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
            // 租户绑定校验（verify 成功后、黑名单检查前）：签发租户 ≠ 请求租户
            // 即拒绝，错误码与会话模式的跨租户拒绝一致
            if let Ok(ctx) = crate::context::tenant::TENANT.try_get() {
                let probe = handler.verify_custom::<JwtTenantProbe>(token)?;
                if probe.tid.is_some_and(|tid| tid != ctx.tenant_id) {
                    return Err(GarrisonError::Session(
                        "stp-check-login-tenant-mismatch::".to_string(),
                    ));
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

    /// Mixin 模式：JWT verify + session 二级校验。
    ///
    /// 启用 `protocol-jwt` feature 且 `token_style=jwt` 时先 JWT verify 再查 session
    /// （JWT verify 失败直接返回错误，不查询 session）。否则仅查 session
    /// （无 protocol-jwt feature 或 token_style != jwt 时）。
    pub(super) async fn check_login_mixin(
        &self,
        token: &str,
    ) -> GarrisonResult<(bool, Option<String>)> {
        #[cfg(feature = "protocol-jwt")]
        {
            if self.config.token_style == "jwt" {
                let handler =
                    crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
                // JWT 签名无效直接返回错误（不查询 session）
                handler.verify(token)?;
            }
        }
        // is_valid_with_session 返回 Token-Session 快照——hover 检查与
        // 登录身份缓存复用同一快照，消除同一请求内的重复 DAO 读取
        let ts_opt = self.session.is_valid_with_session(token).await?;
        let valid = ts_opt.is_some();
        let login_id = ts_opt.as_ref().map(|ts| ts.login_id.clone());
        if !valid {
            // token 无效时广播 SessionTimeout 事件
            // 若 token session 仍存在（account session 过期），可获取 login_id 并广播；
            // token session 完全不存在时跳过广播（无法获取 login_id）。
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
                return Err(GarrisonError::Session("stp-not-login::".to_string()));
            }
        }
        // 悬停检查（仅 valid 时）
        if valid {
            let hover_ok = self.check_and_update_hover(token, ts_opt).await?;
            if !hover_ok {
                return Ok((false, None));
            }
            // Token 自动续签（若启用且剩余 TTL 低于阈值）
            if let Err(e) = self.check_and_renew(token).await {
                tracing::warn!(error = %e, "Token auto-renewal failed, old Token still in use");
            }
            return Ok((true, login_id));
        }
        Ok((false, None))
    }

    /// 检查悬停超时并更新最后活跃时间。
    ///
    /// 仅在会话有效时调用。Token-Session 快照由调用方传入（请求内复用，
    /// 不再重复读取）：
    /// - 悬停未超时：更新 `last_active`，返回 `Ok(true)`。
    /// - 悬停超时：执行 `logout` 并广播 `SessionTimeout` 事件。
    /// - `throw_on_not_login=true`：返回 `Err(Session)`。
    /// - `throw_on_not_login=false`：返回 `Ok(false)`。
    /// - 快照为 `None`（无法检查悬停）：返回 `Ok(true)`（视为有效，与原逻辑一致）。
    ///
    /// logout 失败时记录 `warn` 日志而非静默吞掉。
    pub(super) async fn check_and_update_hover(
        &self,
        token: &str,
        ts_opt: Option<crate::session::TokenSession>,
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

    /// Simple 模式：仅 session 校验，不验证 JWT 签名。
    ///
    /// session 不存在时按 `throw_on_not_login` 决定返回 `Ok(false)` 或 `Session` 错误。
    pub(super) async fn check_login_simple(
        &self,
        token: &str,
    ) -> GarrisonResult<(bool, Option<String>)> {
        // is_valid_with_session 返回 Token-Session 快照——hover 检查与
        // 登录身份缓存复用同一快照，消除同一请求内的重复 DAO 读取
        let ts_opt = self.session.is_valid_with_session(token).await?;
        let valid = ts_opt.is_some();
        let login_id = ts_opt.as_ref().map(|ts| ts.login_id.clone());
        if !valid {
            // token 无效时广播 SessionTimeout 事件
            // 若 token session 仍存在（account session 过期），可获取 login_id 并广播；
            // token session 完全不存在时跳过广播（无法获取 login_id）。
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
                return Err(GarrisonError::Session("stp-not-login::".to_string()));
            }
        }
        // 悬停检查（仅 valid 时）
        if valid {
            let hover_ok = self.check_and_update_hover(token, ts_opt).await?;
            if !hover_ok {
                return Ok((false, None));
            }
            // Token 自动续签（若启用且剩余 TTL 低于阈值）
            if let Err(e) = self.check_and_renew(token).await {
                tracing::warn!(error = %e, "Token auto-renewal failed, old Token still in use");
            }
            return Ok((true, login_id));
        }
        Ok((false, None))
    }
}

// ============================================================================
// GarrisonLogicDefault 私有方法：JWT 撤销黑名单
// ============================================================================

impl GarrisonLogicDefault {
    /// 黑名单写入 `login_id` 当前全部会话 token 的 jti（批量入口）。
    ///
    /// **调用方必须已持有 `with_login_lock(login_id)`**：与 `logout_by_login_id_inner`
    /// 的会话删除同临界区执行，闭合「锁外快照 → 并发 login 插入新 token →
    /// 锁内删除新 session 但 jti 未拉黑」的 TOCTOU 窗口（渗透-竞态-踢出黑名单-1）。
    /// 锁内快照与删除同源（DAO AccountSession.tokens，而非 login_token_map
    /// 内存索引——后者在 login-token-map-persistence 间隔写入下可能滞后）。
    ///
    /// 快照读取失败仅 warn 并继续（与 [`Self::blacklist_jwt_jti`] 的幂等成功
    /// 语义一致，删除照常执行；warn 供部署侧监控黑名单覆盖缺口）。
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
                    "jti blacklist snapshot read failed; revoked tokens may remain valid until natural expiry"
                );
                return;
            },
        };
        for token in &tokens {
            self.blacklist_jwt_jti(token).await;
        }
    }

    /// 将 JWT 的 `jti` 写入 DAO 黑名单。
    ///
    /// 解析 token 获取 claims，若 `jti` 为 Some 且 TTL > 0，
    /// 则写入 `jwt:blacklist:{jti}` = "1"（TTL = 剩余有效期秒数）。
    /// DAO 失败时 warn 日志不中断主流程。
    ///
    /// # 键命名空间与租户
    ///
    /// 键不带显式租户段：tenant-isolation 下 DAO 按**请求租户**为所有键加
    /// 物理前缀，键内拼接租户段无法跨越写读两侧的请求租户错位（黑名单写入
    /// 与校验各随当次请求的租户命名空间）。跨租户吊销逃逸由签发侧 `tid`
    /// 绑定 claim + `check_login_stateless` 的绑定校验闭合（换 X-Tenant-Id
    /// 头在黑名单检查前即被拒绝）；同租户内 kickout 与 check 的请求租户
    /// 一致，键命中语义不变。非租户上下文（单租户部署）无前缀，行为不变。
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
        // 写失败有界重试（退避 100/300ms，共 3 次尝试）。
        // 撤销写失败若只 warn 放行，被吊销 token 在全部节点继续有效至自然过期
        // （撤销传播延迟上界 = 剩余有效期）；重试消化瞬时抖动，最终失败升级为
        // error 日志供部署侧告警监控该窗口。对外仍保持幂等成功（logout 不因
        // 撤销存储故障而报错——用户以为登出失败比实际未撤销更危险）。
        const RETRY_DELAYS_MS: [u64; 2] = [100, 300];
        let mut result = self.dao().set(&key, "1", ttl_secs as u64).await;
        for delay_ms in RETRY_DELAYS_MS {
            if result.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            result = self.dao().set(&key, "1", ttl_secs as u64).await;
        }
        if let Err(e) = result {
            tracing::error!(
                error = %e,
                jti = &jti[..jti.len().min(16)],
                attempts = RETRY_DELAYS_MS.len() + 1,
                "JWT blacklist write failed after retries; \
                 revoked token may remain valid until natural expiry"
            );
        }
    }
}

// ============================================================================
// GarrisonLogicDefault 私有方法：异常检测集成（security-alert feature）
// ============================================================================

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

    /// 广播告警事件列表到 `AlertListenerManager`。
    /// 未注入 manager 时为 no-op（事件被丢弃）。
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

// ============================================================================
// GarrisonLogicDefault 私有方法：Token 自动续签
// ============================================================================

impl GarrisonLogicDefault {
    /// 检查并续签 Token（若剩余 TTL 低于阈值）。
    ///
    /// 在 `check_login` 路径中调用：当 `auto_renewal_threshold > 0` 时，
    /// 检查 Token 剩余 TTL 百分比，低于阈值则触发续签。
    /// 续签成功后通过 `CURRENT_RENEWED_TOKEN` task_local 传递新 Token。
    ///
    /// # 并发续签竞态防护
    ///
    /// 两个并发 `check_login` 可能同时通过 TTL 检查并各自触发续签。
    /// Call A 续签成功（旧 token 删除），Call B 的续签失败（token 已不存在），
    /// 错误被 `tracing::warn!` 吞掉，Call B 返回 `Ok(true)` 但旧 token 已失效 → "会话假活"。
    ///
    /// 在续签前获取 per-login_id 锁，进入锁后**二次检查** TTL。
    /// 若另一并发调用已完成续签，当前调用的 TTL 已被重置 → 返回 `None`（无需续签）。
    ///
    /// # 参数
    /// - `token`: 待检查的 Token 字符串。
    ///
    /// # 返回
    /// - `Ok(None)`: 未启用续签 / TTL 充足 / 永久键 / 已被并发调用续签。
    /// - `Ok(Some(new_token))`: 续签成功，返回新 Token。
    /// - `Err(...)`: 续签失败（如 auth_logic 未配置 / renew 调用失败）。
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

        // 持有 per-login_id **续签锁**（独立于 GarrisonSession::login_locks）执行续签。
        // 不能用 login_locks：renew_to_equivalent 内部调用 logout 会再次获取 login_locks → 死锁。
        //
        // 已知问题修复：
        // 1. 条目泄漏——续签完成后在安全点（guard 与本地 Arc clone 均已 drop）用
        // remove_if(strong_count==1) 移除无等待者的条目，防止 renewal_locks 随
        // 唯一 login_id 数量无界增长（OOM / CWE-770）；
        // 2. 取消安全——TokioMutex guard 取消时自动释放，但条目此前永不移除；
        // 续签流程收敛进内部 async block，所有提前返回路径都经过统一清理。
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

        // 安全点清理（与 GarrisonSession::with_token_session_lock 同模式）：
        // 先 drop guard 再 drop 本地 Arc clone，使 strong_count 降到 1
        //（仅剩 DashMap entry），remove_if 才会真正移除。
        // 若仍有等待者（strong_count >= 2）则保留条目，由最后一个使用者清理。
        drop(_guard);
        drop(lock);
        self.renewal_locks
            .remove_if(&login_id, |_, l| Arc::strong_count(l) == 1);
        result
    }
}
