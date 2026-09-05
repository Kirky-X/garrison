//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SessionLogic trait — 会话生命周期管理契约（登录/登出/踢出/校验）。
//! 从 v0.5.2 起，原 `GarrisonLogic` 上帝 trait 拆分为 6 个细粒度 trait；
//! 本 trait 承接会话生命周期相关 10 个方法，super-trait 为 [`GarrisonCore`]。
//!
//! # LoginId 迁移（v0.5.2）
//!
//! 所有 `login_id: i64` 签名迁移为 `login_id: &str`（对象安全，可作 `dyn`）。
//! `GarrisonUtil` 保留 `impl Into<String>` ergonomic 入口，自动 `.into()` 后传引用。
//! `get_login_id()` 返回类型从 `Option<i64>` 迁移为 `Option<String>`。

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

/// 会话逻辑 trait，定义登录/登出/踢出/校验完整契约。
///
/// 对应 `StpLogic` 的会话生命周期部分。
///
/// # 方法分组
///
/// - 登录：[`login`](Self::login) / [`login_with_token`](Self::login_with_token) /
///   [`login_by_token`](Self::login_by_token)（默认返回 `NotImplemented`）
/// - 登出：[`logout`](Self::logout) / [`logout_by_login_id`](Self::logout_by_login_id)
/// - 踢出：[`kickout`](Self::kickout) / [`kickout_by_token`](Self::kickout_by_token)
/// - 吊销：[`revoke_token`](Self::revoke_token)
/// - 校验：[`check_login`](Self::check_login) / [`get_login_id`](Self::get_login_id)
/// - 刷新：[`refresh_access_token`](Self::refresh_access_token)（默认返回 `NotImplemented`）
///
/// # 对象安全
///
/// 所有方法参数均为具体类型（`&str`），无泛型参数，trait 对象安全，
/// 可作 `dyn SessionLogic` 使用。`GarrisonManager` 返回 `Arc<GarrisonLogicDefault>`
/// 后，可通过 trait 方法解析调用本 trait 方法（需 `use crate::stp::SessionLogic`）。
#[async_trait]
pub trait SessionLogic: GarrisonCore {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用（字符串形式，如 "42" / "alice" / UUID）。
    /// - `params`: 登录参数（设备/IP/UserAgent/remember_me），传 `&LoginParams::default()` 表示无附加元数据。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - token 生成失败（如 `token_style` 非法）：`GarrisonError::Config`。
    /// - 会话创建失败：透传 `GarrisonError`。
    ///
    /// # 时序契约（架构审查 MEDIUM-1，fix-refresh-race-and-test-contracts）
    ///
    /// `login` 返回 `Ok(token)` 时，DAO 层面的会话已完全建立（Token-Session +
    /// Account-Session 已写入，`enforce_max_login_count` 已执行）。但 **plugin
    /// `on_login` 回调与 listener `Login` 事件广播在 `login` 返回后异步触发**，
    /// 调用方**不应假设** `login` 返回时 plugin/listener 已执行完成。
    ///
    /// 该设计权衡（HIGH-1 修复）：
    /// - 避免持锁跨 `listener.broadcast().await`（broadcast 串行调用 listener，
    ///   阻塞同 `login_id` 的其他请求 5-25ms）
    /// - 避免"幽灵登录"（enforce 失败回滚后 Login 事件已广播）
    ///
    /// 调用方若需强一致事件序，应在 listener 内做事件去重/序号化，而非依赖
    /// `login` 返回时的事件时序。
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String>;

    /// 执行登录（自定义 token）：用指定 token 创建会话。
    ///
    /// 用于 token 转发、自定义 token 生成等场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    /// - `token`: 自定义 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话创建失败：透传 `GarrisonError`。
    async fn login_with_token(&self, login_id: &str, token: &str) -> GarrisonResult<()>;

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// 未登录时调用幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `GarrisonError`。
    async fn logout(&self) -> GarrisonResult<()>;

    /// 按账号登出：销毁指定 `login_id` 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `GarrisonError`。
    async fn logout_by_login_id(&self, login_id: &str) -> GarrisonResult<()>;

    /// 踢出用户：按账号踢出（语义等同 [`logout_by_login_id`](Self::logout_by_login_id)）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `GarrisonError`。
    async fn kickout(&self, login_id: &str) -> GarrisonResult<()>;

    /// 踢出会话：按 token 踢出（语义等同 `logout(token)`）。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `GarrisonError`。
    async fn kickout_by_token(&self, token: &str) -> GarrisonResult<()>;

    /// 主动吊销 token：销毁指定 token 的会话并广播 `RevokeToken` 事件
    ///
    /// 与 [`logout`](Self::logout) 的区别：`logout` 从 task_local 读取当前 token
    /// （用户主动登出语义）；`revoke_token` 接收显式 token 参数（管理员/系统吊销语义）。
    ///
    /// # 参数
    /// - `token`: 待吊销的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `GarrisonError`。
    async fn revoke_token(&self, token: &str) -> GarrisonResult<()>;

    /// 批量终止指定用户的所有会话。
    ///
    /// 遍历 `login_id` 的所有 token，逐个吊销并广播 `RevokeToken` 事件。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 返回
    /// 被终止的会话数量。
    ///
    /// # 错误
    /// - 单个 token 吊销失败时记录 warn 并继续（best-effort），不中断批量操作。
    async fn revoke_all_sessions(&self, login_id: &str) -> GarrisonResult<usize> {
        let _ = login_id;
        Err(GarrisonError::NotImplemented(
            "stp-revoke-all-sessions-not-implemented::".to_string(),
        ))
    }

    /// 查询指定用户当前活跃的 token 列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 返回
    /// 活跃 token 字符串列表（空 Vec 表示无活跃会话）。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `GarrisonError`。
    async fn get_active_sessions(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        let _ = login_id;
        Err(GarrisonError::NotImplemented(
            "stp-get-active-sessions-not-implemented::".to_string(),
        ))
    }

    /// 检查登录状态：从 task_local 获取 token 验证有效性。
    ///
    /// # 返回
    /// - `Ok(true)`: token 有效且 Account-Session 未过期。
    /// - `Ok(false)`: token 无效或未登录（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：抛 `GarrisonError::Session`。
    /// - DAO 读取失败：透传 `GarrisonError`。
    async fn check_login(&self) -> GarrisonResult<bool>;

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的 `login_id`（字符串形式）。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `GarrisonError`。
    async fn get_login_id(&self) -> GarrisonResult<Option<String>>;

    /// 通过外部 token 反向建立会话。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串（如 OAuth2 access_token / SSO ticket）。
    ///
    /// # 错误
    /// - 默认实现：`GarrisonError::NotImplemented`（未启用 protocol-oauth2/protocol-sso）。
    async fn login_by_token(&self, _token: &str) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(
            "stp-login-by-token-feature-required::".to_string(),
        ))
    }

    /// 刷新 access token：用 refresh_token 换取新的 (access_token, refresh_token) 对。
    ///
    /// 默认返回 `NotImplemented`。启用 `db-sqlite` feature 且注入 `RefreshTokenRotation` 后
    /// 委托 `RefreshTokenRotation::rotate` 实现轮换。
    ///
    /// # 参数
    /// - `refresh_token`: 旧的 refresh token 字符串。
    ///
    /// # 返回
    /// - `Ok((access_token, refresh_token))`: 轮换成功，返回新的 token 对。
    ///
    /// # 错误
    /// - 未启用 `db-sqlite` 或未注入 `RefreshTokenRotation`：`GarrisonError::NotImplemented`。
    /// - refresh token 已撤销/重用：`GarrisonError::InvalidToken` 或 `GarrisonError::TokenRevoked`。
    async fn refresh_access_token(&self, _refresh_token: &str) -> GarrisonResult<(String, String)> {
        Err(GarrisonError::NotImplemented(
            "stp-refresh-access-token-not-implemented-db::".to_string(),
        ))
    }
}

// ============================================================================
// GarrisonLogicDefault impl
// ============================================================================

/// A8: `login_with_token` 入口校验 — 阻断会话固定/劫持的常见攻击向量。
///
/// 在 `with_token_session_lock` 之前执行纯输入校验，避免无谓持锁。
///
/// # 校验规则
///
/// - `login_id` 非空：防止空标识创建无主会话（攻击者可借此构造游离会话）
/// - `token` 非空：空 token 无法标识会话，且可能在下游 DAO 层产生异常键
/// - `token` 长度 `8..=256`：
///   - 下限 8：拒绝过短 token（易碰撞/伪造，如 "0"/"1" 等单字符 token）
///   - 上限 256：拒绝超长 token（DoS 防护，避免 DAO 存储与序列化开销过大）
/// - `token` 不含控制字符（U+0000..=U+001F / U+007F..=U+009F）：
///   阻断 CRLF 注入、HTTP header smuggling、日志污染等攻击
///
/// # 错误
///
/// - `GarrisonError::InvalidParam`：任一校验失败时返回，消息含失败原因（不含敏感数据）。
fn validate_login_with_token_inputs(login_id: &str, token: &str) -> GarrisonResult<()> {
    if login_id.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "stp-login-id-empty::".to_string(),
        ));
    }
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

        // CRIT-010: 暴力破解防护（firewall-bruteforce 启用时）。
        // 前置短路：已封禁 IP 直接拒绝（不消耗校验资源）。
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

        // CRIT-010: 失败计数（仅失败路径）；成功路径清零失败计数。
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
                            "brute force reset-on-success 失败（不影响登录结果）"
                        );
                    }
                },
                Err(_) => {
                    if let Err(record_err) = strategy.record_failure(&fw_ctx).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %record_err,
                            "brute force record_failure 失败（不影响登录结果）"
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
        // A8: 入口校验 — 阻断会话固定/劫持的常见攻击向量。
        // 校验在锁外执行：纯输入校验无需临界区保护，避免无谓持锁。
        //
        // - login_id 非空：防止空标识创建无主会话
        // - token 非空 + 长度 8..=256：拒绝过短（易碰撞/伪造）/过长（DoS）的 token
        // - token 不含控制字符：阻断 CRLF 注入、HTTP header smuggling、日志污染
        validate_login_with_token_inputs(login_id, token)?;

        // 检查 token 是否已关联其他 login_id，避免同一 token 同时映射到两个
        // login_id（dual-mapping）构成会话劫持风险。
        // 用 `with_token_session_lock` 包裹 check + create 原子序列，
        // 保证同一 token 的并发调用串行执行，避免 TOCTOU 竞态绕过 dual-mapping 防护。
        let session = &self.session;
        session
            .with_token_session_lock(token, async {
                // check: token 是否已关联其他 login_id
                if let Some(existing_ts) = session.get_token_session(token).await? {
                    if existing_ts.login_id != login_id {
                        return Err(GarrisonError::InvalidToken(format!(
                            "token already associated with login_id: {}",
                            existing_ts.login_id
                        )));
                    }
                }
                // create: 原子序列的 Step 2（含并发策略 + 最大登录数配额，同一 login 锁区内）
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
                // H-14: JWT 撤销黑名单（注销前写入，确保 jti 在 TTL 内被拒绝）
                #[cfg(feature = "protocol-jwt")]
                self.blacklist_jwt_jti(&token).await;
                self.session.logout(&token).await?;
                // auto-wire: 触发 plugin on_logout + listener Logout 事件
                if let (Some(pm), Some(id)) = (&self.plugin_manager, login_id.as_ref()) {
                    pm.on_logout(id, &token);
                }
                #[cfg(feature = "listener")]
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id.as_ref()) {
                    lm.broadcast(&GarrisonEvent::Logout {
                        login_id: id.clone(),
                        token: token.clone(),
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
        self.session.logout_by_login_id(login_id).await?;
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
        // H-14: JWT 撤销黑名单（踢出前将所有 token 的 jti 写入黑名单）
        #[cfg(feature = "protocol-jwt")]
        {
            let tokens = self.session.get_tokens_by_login_id(login_id);
            for token in &tokens {
                self.blacklist_jwt_jti(token).await;
            }
        }
        // kickout 语义等同 logout_by_login_id
        self.session.logout_by_login_id(login_id).await?;
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
        // H-14: JWT 撤销黑名单
        #[cfg(feature = "protocol-jwt")]
        self.blacklist_jwt_jti(token).await;
        // kickout_by_token 语义等同 logout(token)
        self.session.logout(token).await
    }

    async fn revoke_token(&self, token: &str) -> GarrisonResult<()> {
        // 销毁 Token-Session（幂等：token 不存在也返回 Ok）
        self.session.logout(token).await?;
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
        // 清理 Account-Session + 失效三层缓存（与 logout_by_login_id 语义对齐）。
        // revoke_token 仅删除 Token-Session 并从 Account-Session 移除该 token，
        // 但保留空的 Account-Session（logout_inner L1106 设计），需额外调用
        // logout_by_login_id 彻底清除 Account-Session + login_token_map + 三层缓存。
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
        // CRIT-010: 暴力破解防护前置短路（已封禁 IP 直接拒绝）。
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

        let result = match self.jwt_mode {
            JwtMode::Stateless => self.check_login_stateless(&token).await,
            JwtMode::Mixin => self.check_login_mixin(&token).await,
            JwtMode::Simple => self.check_login_simple(&token).await,
        };
        // T006: 异常检测（仅 valid 时，检测失败不中断主流程）
        #[cfg(feature = "security-extra")]
        if let Ok(true) = &result {
            if let Ok(Some(ts)) = self.session.get_token_session(&token).await {
                self.run_anomaly_check_on_check_login(&ts.login_id, &token)
                    .await;
            }
        }

        // CRIT-010: 认证失败计数（仅 Ok(false) 计入撞库尝试），成功路径清零。
        #[cfg(feature = "firewall-bruteforce")]
        if let Some(ip) = crate::stp::current_ip() {
            use crate::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
            use crate::strategy::firewall::FirewallContext;
            let strategy = BruteForceStrategy::new(BruteForceConfig::default(), self.dao().clone());
            let fw_ctx = FirewallContext::new(&ip);
            match &result {
                Ok(true) => {
                    let count_key =
                        format!("{}{}:count", crate::constants::DaoKeyPrefix::BruteForce, ip);
                    if let Err(e) = self.dao().delete(&count_key).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %e,
                            "brute force reset-on-success 失败（不影响校验结果）"
                        );
                    }
                },
                Ok(false) => {
                    if let Err(record_err) = strategy.record_failure(&fw_ctx).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %record_err,
                            "brute force record_failure 失败（不影响校验结果）"
                        );
                    }
                },
                Err(_) => {
                    // 状态/配置错误（如未登录异常），非撞库尝试，不计入。
                },
            }
        }
        result
    }

    async fn get_login_id(&self) -> GarrisonResult<Option<String>> {
        match current_token() {
            Ok(token) => match self.session.get_token_session(&token).await? {
                Some(ts) => Ok(Some(ts.login_id)),
                None => Ok(None),
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

// 私有 helper 方法拆分到独立文件（大文件拆分，fix-codebase-review-violations T015）。
mod helpers;

#[cfg(test)]
mod tests;
