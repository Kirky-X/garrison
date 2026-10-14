// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SessionLogic trait：会话生命周期契约（登录/登出/踢出/校验），super-trait 为 [`GarrisonCore`]。
//! `login_id` 统一为 `&str`（对象安全，可作 `dyn`）；`GarrisonUtil` 保留 `impl Into<String>` 入口，`get_login_id` 返回 `Option<String>`。

use super::context::set_renewed_token;
use super::current_token;
use super::GarrisonLogicDefault;
use super::JwtMode;
use super::LoginParams;
#[cfg(feature = "listener")]
use crate::config::OverflowLogoutMode;
use crate::config::ReplacedLoginExitMode;
#[cfg(feature = "secure-simple-token")]
use crate::core::token::Token;
use crate::error::{GarrisonError, GarrisonResult};
#[cfg(feature = "listener")]
use crate::listener::GarrisonEvent;
#[cfg(feature = "listener")]
use crate::loc;
use crate::stp::core::GarrisonCore;
use crate::stp::token::TokenLogic;
// FirewallLoginContext 来自 hooks 模块，依赖 limiteron（匹配 lib.rs 的 limiteron cfg）
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
use crate::strategy::FirewallLoginContext;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

/// 会话逻辑 trait：登录 / 登出 / 踢出 / 吊销 / 校验 / 刷新完整契约（`login_by_token` 与 `refresh_access_token` 默认返回 `NotImplemented`）。
/// 方法参数均为具体类型（`&str`），无泛型，trait 对象安全，可作 `dyn SessionLogic` 使用。
#[async_trait]
pub trait SessionLogic: GarrisonCore {
    /// 执行登录：生成 token + 创建会话。
    /// 返回 `Ok(token)` 时 DAO 层会话已完全建立（Token-Session + Account-Session 写入、enforce_max_login_count 已执行），但 plugin `on_login` 与 listener `Login` 事件在返回后异步触发，调用方不应假设其已完成（避免持锁跨 broadcast 与"幽灵登录"）；需强一致事件序应在 listener 内做去重/序号化。
    /// 错误：token 生成失败（如 `token_style` 非法）返回 `Config`，会话创建失败透传 `GarrisonError`。
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String>;

    /// 执行登录（自定义 token）：用指定 token 创建会话，用于 token 转发、自定义 token 生成等场景。
    async fn login_with_token(&self, login_id: &str, token: &str) -> GarrisonResult<()>;

    /// 执行登出：从 task_local 取当前 token 并销毁；未登录时幂等返回 `Ok(())`。
    async fn logout(&self) -> GarrisonResult<()>;

    /// 按账号登出：销毁指定 `login_id` 的所有会话。
    async fn logout_by_login_id(&self, login_id: &str) -> GarrisonResult<()>;

    /// 踢出用户：按账号踢出，语义等同 [`logout_by_login_id`](Self::logout_by_login_id)。
    async fn kickout(&self, login_id: &str) -> GarrisonResult<()>;

    /// 踢出会话：按 token 踢出，语义等同 `logout(token)`。
    async fn kickout_by_token(&self, token: &str) -> GarrisonResult<()>;

    /// 主动吊销 token：销毁会话并广播 `RevokeToken`；与 [`logout`](Self::logout) 的区别是接收显式 token 参数（管理员/系统吊销语义），token 不存在时幂等返回 `Ok(())`。
    async fn revoke_token(&self, token: &str) -> GarrisonResult<()>;

    /// 批量终止指定用户的所有会话，返回被终止的会话数量；遍历其所有 token 逐个吊销并广播 `RevokeToken`，单个失败记 warn 继续（best-effort）。
    async fn revoke_all_sessions(&self, login_id: &str) -> GarrisonResult<usize> {
        let _ = login_id;
        Err(GarrisonError::NotImplemented(
            "stp-revoke-all-sessions-not-implemented::".to_string(),
        ))
    }

    /// 查询指定用户当前活跃的 token 列表（空 Vec 表示无活跃会话）。
    async fn get_active_sessions(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        let _ = login_id;
        Err(GarrisonError::NotImplemented(
            "stp-get-active-sessions-not-implemented::".to_string(),
        ))
    }

    /// 检查登录状态：从 task_local 取 token 验证有效性；`Ok(true)` = token 有效且 Account-Session 未过期，`Ok(false)` = 无效或未登录（`throw_on_not_login=false`），未登录且 `throw_on_not_login=true` 抛 `Session`。
    async fn check_login(&self) -> GarrisonResult<bool>;

    /// 获取当前登录 ID：token 有效返回 `Some(login_id)`，未登录或 token 无效返回 `None`。
    async fn get_login_id(&self) -> GarrisonResult<Option<String>>;

    /// 通过外部 token 反向建立会话（OAuth2/SSO 场景：外部 token 经协议层校验后建立内部会话）；默认实现返回 `NotImplemented`。
    async fn login_by_token(&self, _token: &str) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(
            "stp-login-by-token-feature-required::".to_string(),
        ))
    }

    /// 刷新 access token：用 refresh_token 换新的 (access_token, refresh_token) 对；默认 `NotImplemented`，启用 `db-sqlite` 且注入 `RefreshTokenRotation` 后委托其 rotate（已撤销/重用返回 `InvalidToken` 或 `TokenRevoked`）。
    async fn refresh_access_token(&self, _refresh_token: &str) -> GarrisonResult<(String, String)> {
        Err(GarrisonError::NotImplemented(
            "stp-refresh-access-token-not-implemented-db::".to_string(),
        ))
    }
}

// GarrisonLogicDefault impl

/// `login_with_token` 入口校验（锁外执行，避免无谓持锁），阻断会话固定/劫持：token 非空、长度 8..=256（过短易碰撞/伪造，过长 DoS）、不含控制字符（CRLF 注入 / header smuggling / 日志污染）。
/// `login_id` 不变量由 [`GarrisonLogicDefault::validate_login_id`](crate::stp::GarrisonLogicDefault) 统一承载（与 `login` / `login_by_token` 共用校验与错误码）；失败返回 `InvalidParam`，消息含失败原因不含敏感数据。
fn validate_login_with_token_inputs(token: &str) -> GarrisonResult<()> {
    if token.is_empty() {
        return Err(GarrisonError::InvalidParam("stp-token-empty::".to_string()));
    }
    // 长度校验（字节长度，与 DAO 存储开销一致）
    let len = token.len();
    if len < 8 {
        return Err(GarrisonError::InvalidParam(format!(
            "stp-token-length-too-short::{}",
            len
        )));
    }
    if len > 256 {
        return Err(GarrisonError::InvalidParam(format!(
            "stp-token-length-too-long::{}",
            len
        )));
    }
    // 控制字符校验：阻断 CRLF 注入 / header smuggling / 日志污染
    if token.chars().any(|c| c.is_control()) {
        return Err(GarrisonError::InvalidParam(
            "stp-token-control-char::".to_string(),
        ));
    }
    Ok(())
}

#[async_trait]
impl SessionLogic for GarrisonLogicDefault {
    #[tracing::instrument(skip_all, fields(login_id = %login_id))]
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String> {
        // emit metrics：登录尝试（成功/失败均记录）
        #[cfg(feature = "metrics-prometheus")]
        let start = std::time::Instant::now();

        // 暴力破解防护：已封禁 IP 前置短路拒绝（不消耗校验资源）。
        #[cfg(feature = "firewall-bruteforce")]
        if let Some(ip) = crate::stp::current_ip() {
            use crate::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
            use crate::strategy::firewall::FirewallContext;
            let strategy = BruteForceStrategy::new(BruteForceConfig::default(), self.dao().clone());
            let fw_ctx = FirewallContext::new(&ip);
            if strategy.is_blocked(&fw_ctx).await? {
                return Err(GarrisonError::FirewallBlocked(format!(
                    "stp-login-ip-blocked::{}",
                    ip
                )));
            }
        }

        let result = self.login_inner(login_id, params).await;

        // 失败计数（仅失败路径）；成功路径清零失败计数。
        #[cfg(feature = "firewall-bruteforce")]
        if let Some(ip) = crate::stp::current_ip() {
            use crate::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
            use crate::strategy::firewall::FirewallContext;
            let strategy = BruteForceStrategy::new(BruteForceConfig::default(), self.dao().clone());
            let fw_ctx = FirewallContext::new(&ip);
            match &result {
                Ok(_) => {
                    let count_key =
                        format!("{}{}:count", crate::constants::DaoKeyPrefix::BruteForce, ip);
                    if let Err(e) = self.dao().delete(&count_key).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %e,
                            "brute force reset-on-success failed (does not affect the login result)"
                        );
                    }
                },
                Err(_) => {
                    if let Err(record_err) = strategy.record_failure(&fw_ctx).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %record_err,
                            "brute force record_failure failed (does not affect the login result)"
                        );
                    }
                },
            }
        }

        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_login(result.is_ok());
            m.observe_token_validation(start.elapsed());
        }
        result
    }

    async fn login_with_token(&self, login_id: &str, token: &str) -> GarrisonResult<()> {
        // 入口校验（锁外执行，避免无谓持锁）：login_id 走 validate_login_id 收口，token 规则见 validate_login_with_token_inputs。
        self.validate_login_id(login_id)?;
        validate_login_with_token_inputs(token)?;

        // 防 token dual-mapping（同 token 映射两个 login_id 构成会话劫持）：`with_token_session_lock` 包裹 check + create 原子序列，同一 token 并发调用串行执行，避免 TOCTOU 绕过防护。
        let session = &self.session;
        session
            .with_token_session_lock(token, async {
                // check: token 是否已关联其他 login_id
                if let Some(existing_ts) = session.get_token_session(token).await? {
                    if existing_ts.login_id != login_id {
                        return Err(GarrisonError::InvalidToken(format!(
                            "stp-token-login-id-bound::{}",
                            existing_ts.login_id
                        )));
                    }
                }
                // create: 含并发策略 + 最大登录数配额（同一 login 锁区内）
                self.create_session_with_quota(login_id, token, None, None, None, false)
                    .await
            })
            .await
    }

    #[tracing::instrument(skip_all)]
    async fn logout(&self) -> GarrisonResult<()> {
        // 未登录时幂等返回 Ok（不抛错）
        match current_token() {
            Ok(token) => {
                // 获取 login_id（用于 plugin/listener 回调），注销前查询
                let login_id = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .map(|ts| ts.login_id);
                // JWT 撤销黑名单（注销前写入，确保 jti 在 TTL 内被拒绝）
                #[cfg(feature = "protocol-jwt")]
                self.blacklist_jwt_jti(&token).await;
                self.session.logout(&token).await?;
                // 登出后立即失效请求内登录身份缓存（同请求内 get_login_id 回退 DAO）
                crate::stp::context::invalidate_login_identity_by_token(&token);
                // auto-wire: 触发 plugin on_logout + listener Logout 事件
                if let (Some(pm), Some(id)) = (&self.plugin_manager, login_id.as_ref()) {
                    pm.on_logout(id, &token);
                }
                #[cfg(feature = "listener")]
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id.as_ref()) {
                    // CWE-532: 事件载荷统一携掩码 token。
                    // Back-Channel Logout 入队：本路径为 auto-commit 会话写、无事务上下文，Logout 事件按 Immediately 档广播（广播时点消费，会话写已持久）；事务内登出的调用方应改经 GarrisonEventTx::on_commit 缓冲，同一登出禁止既 broadcast 又 on_commit（双重入队）。
                    lm.broadcast(&GarrisonEvent::Logout {
                        login_id: id.clone(),
                        token: crate::listener::mask_token_for_event(&token),
                        request_context: None,
                    })
                    .await;
                }
                // three-tier-cache: 失效用户三层缓存（权限/角色/用户）
                #[cfg(feature = "three-tier-cache")]
                if let (Some(ucs), Some(id)) = (&self.user_cache_service, login_id.as_ref()) {
                    if let Err(e) = ucs.invalidate(id).await {
                        tracing::warn!(error = %e, login_id = id, "logout invalidate user cache failed");
                    }
                }
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: &str) -> GarrisonResult<()> {
        // 权限判定缓存联动失效（回收角色/权限后 + 登出，旧 Allow 不得存续；锁外执行，失败不影响登出结果）
        if let Err(e) = self.firewall.invalidate_login_cache(login_id).await {
            tracing::warn!(error = %e, login_id, "{}", crate::i18n::translate_detail("logs-stp-invalidate-login-cache-logout-failed", &[]));
        }
        // 「token 快照 → jti 黑名单 → 会话删除」同一 per-login_id 临界区，闭合「锁外快照被并发 login 插队、新 token 的 jti 未入黑名单」的 TOCTOU 窗口（Stateless 下该 token 会存活至自然过期；锁序见 `GarrisonSession::logout_by_login_id_inner`）。
        self.session
            .with_login_lock(login_id, async {
                #[cfg(feature = "protocol-jwt")]
                self.blacklist_all_jwt_jti_locked(login_id).await;
                self.session.logout_by_login_id_inner(login_id).await
            })
            .await?;
        // 按主体失效请求内登录身份缓存
        crate::stp::context::invalidate_login_identity_by_login_id(login_id);
        // three-tier-cache: 失效用户三层缓存（权限/角色/用户）
        #[cfg(feature = "three-tier-cache")]
        if let Some(ucs) = &self.user_cache_service {
            if let Err(e) = ucs.invalidate(login_id).await {
                tracing::warn!(error = %e, login_id, "logout_by_login_id invalidate user cache failed");
            }
        }
        Ok(())
    }

    async fn kickout(&self, login_id: &str) -> GarrisonResult<()> {
        // 权限判定缓存联动失效（锁外执行，失败不影响踢出结果）
        if let Err(e) = self.firewall.invalidate_login_cache(login_id).await {
            tracing::warn!(error = %e, login_id, "{}", crate::i18n::translate_detail("logs-stp-invalidate-login-cache-kickout-failed", &[]));
        }
        // 语义等同 logout_by_login_id：快照 + jti 黑名单 + 会话删除同一 per-login_id 临界区（并发 login 在同一锁内串行，不会漏掉随后被删除的 token）。
        self.session
            .with_login_lock(login_id, async {
                #[cfg(feature = "protocol-jwt")]
                self.blacklist_all_jwt_jti_locked(login_id).await;
                self.session.logout_by_login_id_inner(login_id).await
            })
            .await?;
        // 按主体失效请求内登录身份缓存
        crate::stp::context::invalidate_login_identity_by_login_id(login_id);
        // auto-wire: 触发 listener Kickout 事件（plugin 无 kickout 钩子）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&GarrisonEvent::Kickout {
                login_id: login_id.to_string(),
                token: String::new(),
                reason: loc!("session-kickout-admin", ""),
                request_context: None,
            })
            .await;
        }
        Ok(())
    }

    async fn kickout_by_token(&self, token: &str) -> GarrisonResult<()> {
        // JWT 撤销黑名单
        #[cfg(feature = "protocol-jwt")]
        self.blacklist_jwt_jti(token).await;
        // kickout_by_token 语义等同 logout(token)
        let result = self.session.logout(token).await;
        if result.is_ok() {
            // 登出后立即失效请求内登录身份缓存
            crate::stp::context::invalidate_login_identity_by_token(token);
        }
        result
    }

    async fn revoke_token(&self, token: &str) -> GarrisonResult<()> {
        // JWT 撤销黑名单：Stateless 模式下销毁 session 不足以废止 JWT
        #[cfg(feature = "protocol-jwt")]
        self.blacklist_jwt_jti(token).await;
        // 销毁 Token-Session（幂等：token 不存在也返回 Ok）
        self.session.logout(token).await?;
        // 吊销后立即失效请求内登录身份缓存
        crate::stp::context::invalidate_login_identity_by_token(token);
        // 广播 RevokeToken 事件
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&GarrisonEvent::RevokeToken {
                token: token.to_string(),
                request_context: None,
            })
            .await;
        }
        Ok(())
    }

    async fn revoke_all_sessions(&self, login_id: &str) -> GarrisonResult<usize> {
        let tokens = self.session.get_tokens_by_login_id(login_id);
        let mut count = 0usize;
        for token in tokens {
            match self.revoke_token(&token).await {
                Ok(()) => count += 1,
                Err(e) => {
                    // 脱敏：只打印 token 前 8 字符，避免完整 token 泄露到日志
                    let token_preview = if token.len() > 8 { &token[..8] } else { &token };
                    tracing::warn!(
                        error = %e,
                        login_id,
                        token = %token_preview,
                        "revoke_all_sessions: single token revoke failed, continuing"
                    );
                },
            }
        }
        // revoke_token 只删 Token-Session 并从 Account-Session 移除该 token，保留空 Account-Session；这里补调 logout_by_login_id 彻底清除 Account-Session + login_token_map + 三层缓存。
        if let Err(e) = self.logout_by_login_id(login_id).await {
            tracing::warn!(
                error = %e,
                login_id,
                "revoke_all_sessions: Account-Session cleanup failed"
            );
        }
        Ok(count)
    }

    async fn get_active_sessions(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        let tokens = self.session.get_tokens_by_login_id(login_id);
        let mut active = Vec::with_capacity(tokens.len());
        for token in tokens {
            if self.session.get_token_session(&token).await?.is_some() {
                active.push(token);
            }
        }
        Ok(active)
    }

    #[tracing::instrument(skip_all)]
    async fn check_login(&self) -> GarrisonResult<bool> {
        // 暴力破解防护：已封禁 IP 前置短路拒绝。
        #[cfg(feature = "firewall-bruteforce")]
        if let Some(ip) = crate::stp::current_ip() {
            use crate::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
            use crate::strategy::firewall::FirewallContext;
            let strategy = BruteForceStrategy::new(BruteForceConfig::default(), self.dao().clone());
            let fw_ctx = FirewallContext::new(&ip);
            if strategy.is_blocked(&fw_ctx).await? {
                return Err(GarrisonError::FirewallBlocked(format!(
                    "stp-check-login-ip-blocked::{}",
                    ip
                )));
            }
        }

        let token = match current_token() {
            Ok(t) => t,
            Err(_) => {
                // 未设置 token = 未登录（保持现有 throw_on_not_login 语义）
                if self.config.throw_on_not_login {
                    return Err(GarrisonError::Session("stp-not-login::".to_string()));
                }
                return Ok(false);
            },
        };

        // 登录身份缓存：check_login 校验成功写入 (token, login_id)，同请求内 get_login_id/check_permission 命中缓存免 DAO 读；作用域由 Web middleware 的 `with_login_id_scope` 创建，未在作用域内写入为 no-op（回退 DAO，语义不变）。
        // 会话-租户一致性：仅判定有效时执行——有租户上下文且会话已绑定租户时，绑定 ≠ 请求租户即拒绝（客户端可控 X-Tenant-Id 不得跨租户复用会话）；无绑定或无上下文行为不变；simple/mixin 模式透传 `is_valid_with_session` 快照供校验复用。
        let (result, snapshot) = match self.jwt_mode {
            JwtMode::Stateless => (self.check_login_stateless(&token).await, None),
            JwtMode::Mixin => self.check_login_mixin(&token).await,
            JwtMode::Simple => self.check_login_simple(&token).await,
        };
        let result = self
            .validate_session_tenant_binding(&token, result, snapshot.as_ref())
            .await;
        // 异常检测（仅 valid 时，检测失败不中断主流程）
        #[cfg(feature = "security-extra")]
        if let Ok((true, Some(ref login_id))) = result {
            self.run_anomaly_check_on_check_login(login_id, &token)
                .await;
        }

        // 认证失败计数（仅 Ok(false) 计入撞库尝试），成功路径清零。
        #[cfg(feature = "firewall-bruteforce")]
        if let Some(ip) = crate::stp::current_ip() {
            use crate::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
            use crate::strategy::firewall::FirewallContext;
            let strategy = BruteForceStrategy::new(BruteForceConfig::default(), self.dao().clone());
            let fw_ctx = FirewallContext::new(&ip);
            match &result {
                Ok((true, _)) => {
                    let count_key =
                        format!("{}{}:count", crate::constants::DaoKeyPrefix::BruteForce, ip);
                    if let Err(e) = self.dao().delete(&count_key).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %e,
                            "brute force reset-on-success failed (does not affect the verification result)"
                        );
                    }
                },
                Ok((false, _)) => {
                    if let Err(record_err) = strategy.record_failure(&fw_ctx).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %record_err,
                            "brute force record_failure failed (does not affect the verification result)"
                        );
                    }
                },
                Err(_) => {
                    // 状态/配置错误（如未登录异常），非撞库尝试，不计入。
                },
            }
        }
        // 校验通过 → 缓存登录身份（get_login_id 按 token 匹配复用，登出即失效）
        if let Ok((true, Some(ref login_id))) = result {
            crate::stp::context::cache_login_identity(&token, login_id);
        }
        result.map(|(valid, _)| valid)
    }

    async fn get_login_id(&self) -> GarrisonResult<Option<String>> {
        match current_token() {
            Ok(token) => {
                // 请求内缓存命中（check_login 已校验该 token）直接复用，免一次 TokenSession DAO 读；token 不匹配或未在缓存作用域内回退 DAO（语义不变）。
                if let Some(login_id) = crate::stp::context::cached_login_id_for(&token) {
                    return Ok(Some(login_id));
                }
                match self.session.get_token_session(&token).await? {
                    Some(ts) => Ok(Some(ts.login_id)),
                    None => Ok(None),
                }
            },
            Err(_) => Ok(None),
        }
    }

    async fn login_by_token(&self, token: &str) -> GarrisonResult<()> {
        // 获取 login_id：优先委托 auth_logic，否则使用 verify_token（TokenStyleFactory）
        let login_id = if let Some(auth) = &self.auth_logic {
            auth.verify_token(token).await?
        } else {
            self.verify_token(token).await?
        };
        // 同族收口：外部 token 解析出的 login_id 同样过输入不变量（防上游数据源空串/控制字符/超长标识直通建会话）
        self.validate_login_id(&login_id)?;
        // 建立内部会话（使用同一 token）
        self.session.create(&login_id, token).await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(&login_id, token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&GarrisonEvent::Login {
                login_id,
                token: token.to_string(),
                device: None,
                request_context: None,
            })
            .await;
        }
        Ok(())
    }

    #[tracing::instrument(level = "info", skip(self, refresh_token))]
    async fn refresh_access_token(&self, refresh_token: &str) -> GarrisonResult<(String, String)> {
        #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
        {
            if let Some(rtr) = &self.refresh_token_rotation {
                return rtr.rotate(refresh_token).await;
            }
            return Err(GarrisonError::NotImplemented(
                "stp-refresh-access-token-no-rotation::".to_string(),
            ));
        }
        #[cfg(not(all(feature = "protocol-jwt", feature = "db-sqlite")))]
        {
            let _ = refresh_token;
            Err(GarrisonError::NotImplemented(
                "stp-refresh-access-token-feature-required::".to_string(),
            ))
        }
    }
}

impl GarrisonLogicDefault {
    /// 会话-租户绑定一致性校验（check_login 专用）：判定无效、无租户上下文或会话无绑定（旧会话/单租户部署）时原样放行。
    /// 已绑定时绑定租户 ≠ 请求租户即拒绝（`stp-check-login-tenant-mismatch`）；`require_session_tenant_binding=true` 时无绑定也显性拒绝（`stp-check-login-session-tenant-unbound`，开启前应确认存量无绑定会话已轮替，`remember_me` 最长 90 天）。
    /// Stateless 无 session 存储（本读恒 None），其租户强制由 `require_tenant_bound_jwt` 承担，本机制与严格档均不适用（否则 Stateless 开开关后会全量报错）。
    /// 快照复用：`snapshot`（simple/mixin 经 `is_valid_with_session` 已取）可达时直读 attrs 不追加 DAO 读，None 时回退 `session.get`；绑定 attr 仅在创建时写入，快照与整读等价；DAO 故障透传 Err。
    async fn validate_session_tenant_binding(
        &self,
        token: &str,
        result: GarrisonResult<(bool, Option<String>)>,
        snapshot: Option<&crate::session::TokenSession>,
    ) -> GarrisonResult<(bool, Option<String>)> {
        // 仅有效判定需要校验（无效判定本就不放行）
        if !matches!(result, Ok((true, _))) {
            return result;
        }
        let ctx = match crate::context::tenant::TENANT.try_get() {
            Ok(ctx) => ctx,
            Err(_) => return result, // 无租户上下文：行为不变
        };
        let bound = match snapshot {
            Some(ts) => ts
                .attrs
                .get(crate::context::tenant::SESSION_TENANT_ATTR_KEY)
                .cloned(),
            // 快照不可达（Stateless 无会话存储）：保持原整读路径
            None => {
                self.session
                    .get(token, crate::context::tenant::SESSION_TENANT_ATTR_KEY)
                    .await?
            },
        };
        match bound {
            // 已绑定：规范十进制字符串比较（绑定写入恒为 i64::to_string）
            Some(bound) if bound == ctx.tenant_id.to_string() => result,
            Some(_) => Err(GarrisonError::Session(
                "stp-check-login-tenant-mismatch::".to_string(),
            )),
            // 无绑定（旧会话/单租户部署创建）：严格档显性拒绝，缺省放行；不做惰性补绑（X-Tenant-Id 客户端可控，补绑等于把豁免面换成钉定型 DoS）。
            // Stateless 不纳入：无会话存储时本读恒 None，一并拦下会让开了开关的 Stateless 部署全量报错（其租户强制由 `require_tenant_bound_jwt` 覆盖）。
            None if self.config.require_session_tenant_binding
                && self.jwt_mode != JwtMode::Stateless =>
            {
                Err(GarrisonError::Session(
                    "stp-check-login-session-tenant-unbound::".to_string(),
                ))
            },
            None => result,
        }
    }
}

// 私有 helper 方法拆分到独立文件。
mod helpers;

#[cfg(test)]
mod tests;

/// 角色层级 TC 预计算 + 权限并集缓存接线测试（需 db-sqlite 跑内存库迁移）。
#[cfg(all(test, feature = "db-sqlite"))]
mod role_union_tests;
