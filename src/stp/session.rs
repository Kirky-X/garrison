//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SessionLogic trait — 会话生命周期管理契约（登录/登出/踢出/校验）。
//! 从 v0.5.2 起，原 `BulwarkLogic` 上帝 trait 拆分为 6 个细粒度 trait；
//! 本 trait 承接会话生命周期相关 10 个方法，super-trait 为 [`BulwarkCore`]。
//!
//! # LoginId 迁移（v0.5.2）
//!
//! 所有 `login_id: i64` 签名迁移为 `login_id: &str`（对象安全，可作 `dyn`）。
//! `BulwarkUtil` 保留 `impl Into<String>` ergonomic 入口，自动 `.into()` 后传引用。
//! `get_login_id()` 返回类型从 `Option<i64>` 迁移为 `Option<String>`。

use super::context::set_renewed_token;
use super::current_token;
use super::BulwarkLogicDefault;
use super::JwtMode;
use super::LoginParams;
#[cfg(feature = "listener")]
use crate::config::OverflowLogoutMode;
use crate::config::ReplacedLoginExitMode;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkEvent;
use crate::stp::core::BulwarkCore;
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
/// 可作 `dyn SessionLogic` 使用。`BulwarkManager` 返回 `Arc<BulwarkLogicDefault>`
/// 后，可通过 trait 方法解析调用本 trait 方法（需 `use crate::stp::SessionLogic`）。
#[async_trait]
pub trait SessionLogic: BulwarkCore {
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
    /// - token 生成失败（如 `token_style` 非法）：`BulwarkError::Config`。
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login(&self, login_id: &str, params: &LoginParams) -> BulwarkResult<String>;

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
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login_with_token(&self, login_id: &str, token: &str) -> BulwarkResult<()>;

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// 未登录时调用幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout(&self) -> BulwarkResult<()>;

    /// 按账号登出：销毁指定 `login_id` 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout_by_login_id(&self, login_id: &str) -> BulwarkResult<()>;

    /// 踢出用户：按账号踢出（语义等同 [`logout_by_login_id`](Self::logout_by_login_id)）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout(&self, login_id: &str) -> BulwarkResult<()>;

    /// 踢出会话：按 token 踢出（语义等同 `logout(token)`）。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()>;

    /// 主动吊销 token：销毁指定 token 的会话并广播 `RevokeToken` 事件
    /// 。
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
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn revoke_token(&self, token: &str) -> BulwarkResult<()>;

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
    async fn revoke_all_sessions(&self, login_id: &str) -> BulwarkResult<usize> {
        let _ = login_id;
        Err(BulwarkError::NotImplemented(
            "revoke_all_sessions 需 BulwarkLogicDefault 实现".to_string(),
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
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn get_active_sessions(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        let _ = login_id;
        Err(BulwarkError::NotImplemented(
            "get_active_sessions 需 BulwarkLogicDefault 实现".to_string(),
        ))
    }

    /// 检查登录状态：从 task_local 获取 token 验证有效性。
    ///
    /// # 返回
    /// - `Ok(true)`: token 有效且 Account-Session 未过期。
    /// - `Ok(false)`: token 无效或未登录（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：抛 `BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn check_login(&self) -> BulwarkResult<bool>;

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的 `login_id`（字符串形式）。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn get_login_id(&self) -> BulwarkResult<Option<String>>;

    /// 通过外部 token 反向建立会话。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串（如 OAuth2 access_token / SSO ticket）。
    ///
    /// # 错误
    /// - 默认实现：`BulwarkError::NotImplemented`（未启用 protocol-oauth2/protocol-sso）。
    async fn login_by_token(&self, _token: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "login_by_token 需启用 protocol-oauth2 或 protocol-sso feature".to_string(),
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
    /// - 未启用 `db-sqlite` 或未注入 `RefreshTokenRotation`：`BulwarkError::NotImplemented`。
    /// - refresh token 已撤销/重用：`BulwarkError::InvalidToken` 或 `BulwarkError::TokenRevoked`。
    async fn refresh_access_token(&self, _refresh_token: &str) -> BulwarkResult<(String, String)> {
        Err(BulwarkError::NotImplemented(
            "refresh_access_token 未实现：需启用 db-sqlite feature 并注入 RefreshTokenRotation"
                .to_string(),
        ))
    }
}

// ============================================================================
// BulwarkLogicDefault impl
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
/// - `BulwarkError::InvalidParam`：任一校验失败时返回，消息含失败原因（不含敏感数据）。
fn validate_login_with_token_inputs(login_id: &str, token: &str) -> BulwarkResult<()> {
    if login_id.is_empty() {
        return Err(BulwarkError::InvalidParam(
            "stp-login-id-empty::".to_string(),
        ));
    }
    if token.is_empty() {
        return Err(BulwarkError::InvalidParam("stp-token-empty::".to_string()));
    }
    // 长度校验（字节长度，与 DAO 存储开销一致）
    let len = token.len();
    if len < 8 {
        return Err(BulwarkError::InvalidParam(format!(
            "token 长度不足：{} < 8",
            len
        )));
    }
    if len > 256 {
        return Err(BulwarkError::InvalidParam(format!(
            "token 长度超限：{} > 256",
            len
        )));
    }
    // 控制字符校验：阻断 CRLF 注入 / header smuggling / 日志污染
    if token.chars().any(|c| c.is_control()) {
        return Err(BulwarkError::InvalidParam(
            "stp-token-control-char::".to_string(),
        ));
    }
    Ok(())
}

#[async_trait]
impl SessionLogic for BulwarkLogicDefault {
    #[tracing::instrument(skip_all, fields(login_id = %login_id))]
    async fn login(&self, login_id: &str, params: &LoginParams) -> BulwarkResult<String> {
        // emit metrics：登录尝试（成功/失败均记录）
        #[cfg(feature = "metrics-prometheus")]
        let start = std::time::Instant::now();
        let result = self.login_inner(login_id, params).await;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_login(result.is_ok());
            m.observe_token_validation(start.elapsed());
        }
        result
    }

    async fn login_with_token(&self, login_id: &str, token: &str) -> BulwarkResult<()> {
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
                        return Err(BulwarkError::InvalidToken(format!(
                            "token already associated with login_id: {}",
                            existing_ts.login_id
                        )));
                    }
                }
                // create: 原子序列的 Step 2
                session.create(login_id, token).await
            })
            .await
    }

    #[tracing::instrument(skip_all)]
    async fn logout(&self) -> BulwarkResult<()> {
        // 未登录时幂等返回 Ok（不抛错）
        match current_token() {
            Ok(token) => {
                // 获取 login_id（用于 plugin/listener 回调），注销前查询
                let login_id = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .map(|ts| ts.login_id);
                self.session.logout(&token).await?;
                // auto-wire: 触发 plugin on_logout + listener Logout 事件
                if let (Some(pm), Some(id)) = (&self.plugin_manager, login_id.as_ref()) {
                    pm.on_logout(id, &token);
                }
                #[cfg(feature = "listener")]
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id.as_ref()) {
                    lm.broadcast(&BulwarkEvent::Logout {
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
                        tracing::warn!(error = %e, login_id = id, "logout 失效用户缓存失败");
                    }
                }
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: &str) -> BulwarkResult<()> {
        self.session.logout_by_login_id(login_id).await?;
        // three-tier-cache: 失效用户三层缓存（权限/角色/用户）
        #[cfg(feature = "three-tier-cache")]
        if let Some(ucs) = &self.user_cache_service {
            if let Err(e) = ucs.invalidate(login_id).await {
                tracing::warn!(error = %e, login_id, "logout_by_login_id 失效用户缓存失败");
            }
        }
        Ok(())
    }

    async fn kickout(&self, login_id: &str) -> BulwarkResult<()> {
        // kickout 语义等同 logout_by_login_id
        self.session.logout_by_login_id(login_id).await?;
        // auto-wire: 触发 listener Kickout 事件（plugin 无 kickout 钩子）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Kickout {
                login_id: login_id.to_string(),
                token: String::new(),
                reason: "管理员强制下线".to_string(),
                request_context: None,
            })
            .await;
        }
        Ok(())
    }

    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()> {
        // kickout_by_token 语义等同 logout(token)
        self.session.logout(token).await
    }

    async fn revoke_token(&self, token: &str) -> BulwarkResult<()> {
        // 销毁 Token-Session（幂等：token 不存在也返回 Ok）
        self.session.logout(token).await?;
        // 广播 RevokeToken 事件
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::RevokeToken {
                token: token.to_string(),
                request_context: None,
            })
            .await;
        }
        Ok(())
    }

    async fn revoke_all_sessions(&self, login_id: &str) -> BulwarkResult<usize> {
        let tokens = self.session.get_tokens_by_login_id(login_id);
        let mut count = 0usize;
        for token in tokens {
            match self.revoke_token(&token).await {
                Ok(()) => count += 1,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        login_id,
                        token = %token,
                        "revoke_all_sessions: 单个 token 吊销失败，继续处理"
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
                "revoke_all_sessions: Account-Session 清理失败"
            );
        }
        Ok(count)
    }

    async fn get_active_sessions(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
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
    async fn check_login(&self) -> BulwarkResult<bool> {
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => {
                // 未设置 token = 未登录（保持现有 throw_on_not_login 语义）
                if self.config.throw_on_not_login {
                    return Err(BulwarkError::Session("stp-not-login::".to_string()));
                }
                return Ok(false);
            },
        };

        let result = match self.jwt_mode {
            JwtMode::Stateless => self.check_login_stateless(&token),
            JwtMode::Mixin => self.check_login_mixin(&token).await,
            JwtMode::Simple => self.check_login_simple(&token).await,
        };
        // T006: 异常检测（仅 valid 时，检测失败不中断主流程）
        #[cfg(feature = "security-alert")]
        if let Ok(true) = &result {
            if let Ok(Some(ts)) = self.session.get_token_session(&token).await {
                self.run_anomaly_check_on_check_login(&ts.login_id, &token)
                    .await;
            }
        }
        result
    }

    async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
        match current_token() {
            Ok(token) => match self.session.get_token_session(&token).await? {
                Some(ts) => Ok(Some(ts.login_id)),
                None => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }

    async fn login_by_token(&self, token: &str) -> BulwarkResult<()> {
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
            lm.broadcast(&BulwarkEvent::Login {
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
    async fn refresh_access_token(&self, refresh_token: &str) -> BulwarkResult<(String, String)> {
        #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
        {
            if let Some(rtr) = &self.refresh_token_rotation {
                return rtr.rotate(refresh_token).await;
            }
            return Err(BulwarkError::NotImplemented(
                "refresh_access_token 未注入 RefreshTokenRotation".to_string(),
            ));
        }
        #[cfg(not(all(feature = "protocol-jwt", feature = "db-sqlite")))]
        {
            let _ = refresh_token;
            Err(BulwarkError::NotImplemented(
                "refresh_access_token 需启用 protocol-jwt + db-sqlite feature".to_string(),
            ))
        }
    }
}

// ============================================================================
// 私有 helper 方法（从 mod.rs 搬移，供 SessionLogic impl 调用）
// ============================================================================

impl BulwarkLogicDefault {
    /// login 实际逻辑（供 `login` 方法在 metrics 包装内调用）。
    ///
    /// 0.3.0 抽取此私有方法以保持 `login` trait 方法的 metrics 包装简洁。
    async fn login_inner(&self, login_id: &str, params: &LoginParams) -> BulwarkResult<String> {
        // 登录前防火墙安全钩子检查
        // 任一 hook Err 阻断登录；未注入 hook 时为 no-op（向后兼容 0.2.x）
        // hooks 模块依赖 limiteron，仅在 limiteron 启用时编译（匹配 lib.rs 的 limiteron cfg）
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

        // is_share=true: 复用现有有效 token，不创建新会话
        if self.config.is_share {
            if let Some(existing_token) = self.session.get_token_by_login_id(login_id) {
                // 验证 token 仍然有效（DAO 中存在且未过期）
                if let Ok(Some(_ts)) = self.session.get_token_session(&existing_token).await {
                    // touch 刷新活跃时间 + TTL
                    self.session.touch(&existing_token).await?;
                    return Ok(existing_token);
                }
                // token 已失效（DAO 中已过期/删除），清理 login_token_map 陈旧条目
                self.session.remove_login_token(login_id, &existing_token);
            }
        }

        // is_concurrent=false: 根据 replaced_login_exit_mode 决定行为
        // - OldDevice：踢出旧设备的所有会话（默认，对应 既有语义）
        // - NewDevice：若存在有效旧会话则拒绝新登录，保留旧设备
        // 注：is_share=true 时 is_concurrent 必为 true（T006 validate 保证），两分支互斥
        if !self.config.is_concurrent {
            match self.config.replaced_login_exit_mode {
                ReplacedLoginExitMode::OldDevice => {
                    self.kickout(login_id).await?;
                },
                ReplacedLoginExitMode::NewDevice => {
                    // 检查是否存在有效旧会话（与 is_share 块一致的校验模式）
                    if let Some(existing_token) = self.session.get_token_by_login_id(login_id) {
                        if let Ok(Some(_)) = self.session.get_token_session(&existing_token).await {
                            tracing::warn!(
                                login_id,
                                mode = "new_device",
                                "新设备登录被拒绝：当前为 NewDevice 模式，已有有效旧会话"
                            );
                            return Err(BulwarkError::NotLogin(
                                "新设备登录被拒绝：当前为 NewDevice 模式，不允许新设备登录"
                                    .to_string(),
                            ));
                        }
                    }
                    // 无有效旧会话，允许新登录
                },
            }
        }

        // T020: 自动生成设备指纹（A10 强化：使用 `device_fingerprint_rich`）。
        // `LoginParams.device` 为 None 但 `user_agent` + `ip` 有值时，
        // 调用 `device_fingerprint_rich` 生成 SHA-256 多维度指纹写入 device。
        // 当前 LoginParams 仅含 ua/ip 两个维度，其余维度为 None（API 已就绪，
        // 未来扩展 LoginParams 后可直接传入 Accept-Language / sec-ch-ua 等 header）。
        // 仅在 device 模块可用时执行（feature gate 与 device 模块一致）；
        // 未启用时 device 保持 None，不影响登录主流程。
        // `cfg_attr` 抑制未启用 device feature 时的 `unused_mut` 警告。
        #[cfg_attr(
            not(any(
                feature = "protocol-jwt",
                feature = "account-credential",
                feature = "protocol-oauth2",
                feature = "protocol-sso",
                feature = "protocol-sign",
                feature = "secure-sign",
                feature = "secure-httpdigest",
                feature = "device-binding"
            )),
            allow(unused_mut)
        )]
        let mut params = params.clone();
        #[cfg(any(
            feature = "protocol-jwt",
            feature = "account-credential",
            feature = "protocol-oauth2",
            feature = "protocol-sso",
            feature = "protocol-sign",
            feature = "secure-sign",
            feature = "secure-httpdigest"
        ))]
        if params.device.is_none() {
            if let (Some(ua), Some(ip)) = (&params.user_agent, &params.ip) {
                let fp_input = crate::session::device::DeviceFingerprintInput::from_ua_ip(ua, ip);
                params.device = Some(crate::session::device::device_fingerprint_rich(&fp_input));
            }
        }

        // T013: 设备绑定策略检测（device-binding feature，A10 强化：hard block）。
        // 创建 session 前调用 `DeviceBindingPolicy::is_new_device`，若为新设备
        // 且 `require_secondary_auth` 返回 true，直接返回 `Err(NotPermission)` 阻断登录
        // （A10 修复：原仅设置 `params.require_mfa = true` 软提示，未真正阻断）。
        // 未注入 policy 时跳过（向后兼容）；检测失败只 warn 不中断 login。
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
                                "设备绑定策略触发二级认证阻断（hard block）"
                            );
                            return Err(BulwarkError::NotPermission(
                                "secondary auth required".to_string(),
                            ));
                        },
                        Ok(false) => {},
                        Err(e) => tracing::warn!(
                            error = %e,
                            "DeviceBindingPolicy::require_secondary_auth 失败"
                        ),
                    },
                    Ok(false) => {},
                    Err(e) => tracing::warn!(
                        error = %e,
                        "DeviceBindingPolicy::is_new_device 失败"
                    ),
                }
            }
        }

        let token = self.generate_token(login_id)?;
        self.session
            .create_token_session(login_id, &token, &params)
            .await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, &token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id: login_id.to_string(),
                token: token.clone(),
                device: params.device.clone(),
                request_context: None,
            })
            .await;
        }
        // max_login_count > 0 时，强制最大登录数量（踢出最旧会话）
        // enforce 失败时回滚（登出新创建的 token），避免孤儿会话泄漏
        if self.config.max_login_count > 0 {
            if let Err(e) = self
                .enforce_max_login_count(login_id, self.config.max_login_count)
                .await
            {
                tracing::error!(
                    error = %e,
                    "enforce_max_login_count 失败，回滚新创建的会话"
                );
                if let Err(logout_err) = self.session.logout(&token).await {
                    tracing::error!(
                        error = %logout_err,
                        "回滚 logout 失败，可能产生孤儿会话（token 仍在 DAO 但 login 返回 Err）"
                    );
                }
                return Err(e);
            }
        }
        // T006: 异常检测（security-alert feature，检测失败只 warn 不中断 login）
        #[cfg(feature = "security-alert")]
        self.run_anomaly_check_on_login(login_id, &params).await;
        Ok(token)
    }

    /// 强制最大登录数量：踢出最旧的会话直到数量 <= max。
    ///
    /// 按 `last_active_at` 升序排序（最旧排前面），踢出最早的 (count - max) 个 token。
    /// `max=0` 时不做任何操作（0 表示不限制，由调用方判断）。
    ///
    /// 踢出后根据 [`OverflowLogoutMode`] 广播对应事件：
    /// - `Logout`：广播 `BulwarkEvent::Logout`（默认，向后兼容）
    /// - `Kickout`：广播 `BulwarkEvent::Kickout`（reason: "超过最大登录数限制"）
    /// - `Replaced`：广播 `BulwarkEvent::RevokeToken`
    ///
    /// 事件广播需启用 `listener` feature 且注入 `listener_manager`，否则跳过。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `max`: 最大允许同时登录数。
    ///
    /// # 错误
    /// - DAO 查询失败：透传 `BulwarkError`。
    pub async fn enforce_max_login_count(&self, login_id: &str, max: u32) -> BulwarkResult<()> {
        if max == 0 {
            return Ok(());
        }

        let tokens = self.session.get_tokens_by_login_id(login_id);
        if tokens.len() <= max as usize {
            return Ok(());
        }

        // 从 AccountSession 获取每个 token 的 last_active_at（单次 DAO 查询）
        let account = match self.session.get_account_session(login_id).await? {
            Some(a) => a,
            None => return Ok(()),
        };

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
            self.session.logout(token).await?;
            // 根据 overflow_logout_mode 广播对应事件
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                match self.config.overflow_logout_mode {
                    OverflowLogoutMode::Logout => {
                        lm.broadcast(&BulwarkEvent::Logout {
                            login_id: login_id.to_string(),
                            token: token.clone(),
                            request_context: None,
                        })
                        .await;
                    },
                    OverflowLogoutMode::Kickout => {
                        lm.broadcast(&BulwarkEvent::Kickout {
                            login_id: login_id.to_string(),
                            token: token.clone(),
                            reason: "超过最大登录数限制".to_string(),
                            request_context: None,
                        })
                        .await;
                    },
                    OverflowLogoutMode::Replaced => {
                        lm.broadcast(&BulwarkEvent::Replaced {
                            login_id: login_id.to_string(),
                            token: token.clone(),
                            reason: "超过最大登录数限制，被新会话顶替".to_string(),
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
    fn generate_token(&self, login_id: &str) -> BulwarkResult<String> {
        match self.config.token_style.as_str() {
            "uuid" => Ok(uuid::Uuid::new_v4().to_string()),
            "random_64" => Ok(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            "simple" => Ok(uuid::Uuid::new_v4().simple().to_string()),
            "jwt" => {
                // 委托 JwtHandler::sign
                #[cfg(feature = "protocol-jwt")]
                {
                    let handler =
                        crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
                    handler.sign(login_id, self.config.timeout)
                }
                #[cfg(not(feature = "protocol-jwt"))]
                {
                    let _ = login_id;
                    Err(BulwarkError::Config(
                        "jwt token_style 需启用 protocol-jwt feature".to_string(),
                    ))
                }
            },
            other => Err(BulwarkError::Config(format!(
                "unknown token_style: {}",
                other
            ))),
        }
    }

    /// Stateless 模式：仅 JWT verify，不查询 session。
    ///
    /// 要求启用 `protocol-jwt` feature 且 `token_style=jwt`，否则返回 `Config` 错误。
    /// JWT verify 失败时透传 `InvalidToken`/`ExpiredToken`（不查询 session）。
    fn check_login_stateless(&self, token: &str) -> BulwarkResult<bool> {
        #[cfg(feature = "protocol-jwt")]
        {
            if self.config.token_style != "jwt" {
                return Err(BulwarkError::Config(
                    "Stateless 模式要求 token_style=jwt".to_string(),
                ));
            }
            let handler = crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
            // spec R-002: 无效签名返回 InvalidToken，过期返回 ExpiredToken（透传 verify 错误）
            handler.verify(token)?;
            Ok(true)
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            let _ = token;
            Err(BulwarkError::Config(
                "Stateless 模式要求启用 protocol-jwt feature".to_string(),
            ))
        }
    }

    /// Mixin 模式：JWT verify + session 二级校验。
    ///
    /// 启用 `protocol-jwt` feature 且 `token_style=jwt` 时先 JWT verify 再查 session
    /// （JWT verify 失败直接返回错误，不查询 session）。否则仅查 session
    /// （向后兼容 0.4.1 行为：无 protocol-jwt 或 token_style != jwt）。
    async fn check_login_mixin(&self, token: &str) -> BulwarkResult<bool> {
        #[cfg(feature = "protocol-jwt")]
        {
            if self.config.token_style == "jwt" {
                let handler =
                    crate::protocol::jwt::JwtHandler::new(self.config.jwt_secret.as_str());
                // spec R-003: JWT 签名无效直接返回错误（不查询 session）
                handler.verify(token)?;
            }
        }
        let valid = self.session.is_valid(token).await?;
        if !valid {
            // token 无效时广播 SessionTimeout 事件
            // 若 token session 仍存在（account session 过期），可获取 login_id 并广播；
            // token session 完全不存在时跳过广播（无法获取 login_id）。
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                if let Ok(Some(ts)) = self.session.get_token_session(token).await {
                    lm.broadcast(&BulwarkEvent::SessionTimeout {
                        login_id: ts.login_id,
                        token: token.to_string(),
                        request_context: None,
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return Err(BulwarkError::Session("stp-not-login::".to_string()));
            }
        }
        // 悬停检查（仅 valid 时）
        if valid {
            let hover_ok = self.check_and_update_hover(token).await?;
            if !hover_ok {
                return Ok(false);
            }
            // Token 自动续签（若启用且剩余 TTL 低于阈值）
            if let Err(e) = self.check_and_renew(token).await {
                tracing::warn!(error = %e, "Token 自动续签失败，旧 Token 继续使用");
            }
            return Ok(true);
        }
        Ok(valid)
    }

    /// 检查悬停超时并更新最后活跃时间。
    ///
    /// 仅在会话有效时调用。获取 token session 后检查悬停超时：
    /// - 悬停未超时：更新 `last_active`，返回 `Ok(true)`。
    /// - 悬停超时：执行 `logout` 并广播 `SessionTimeout` 事件。
    ///   - `throw_on_not_login=true`：返回 `Err(Session)`。
    ///   - `throw_on_not_login=false`：返回 `Ok(false)`。
    /// - 无 token session（`get_token_session` 返回 `None` 或 `Err`）：返回 `Ok(true)`
    ///   （无法检查悬停，视为有效，与原逻辑一致）。
    ///
    /// logout 失败时记录 `warn` 日志而非静默吞掉（Fix M-4）。
    async fn check_and_update_hover(&self, token: &str) -> BulwarkResult<bool> {
        if let Ok(Some(ts)) = self.session.get_token_session(token).await {
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
                    tracing::warn!(error = %e, "悬停超时 logout 失败");
                }
                #[cfg(feature = "listener")]
                if let Some(lm) = &self.listener_manager {
                    lm.broadcast(&BulwarkEvent::SessionTimeout {
                        login_id: ts.login_id.clone(),
                        token: token.to_string(),
                        request_context: None,
                    })
                    .await;
                }
                if self.config.throw_on_not_login {
                    return Err(BulwarkError::Session("stp-session-timeout::".to_string()));
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
    async fn check_login_simple(&self, token: &str) -> BulwarkResult<bool> {
        let valid = self.session.is_valid(token).await?;
        if !valid {
            // token 无效时广播 SessionTimeout 事件
            // 若 token session 仍存在（account session 过期），可获取 login_id 并广播；
            // token session 完全不存在时跳过广播（无法获取 login_id）。
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                if let Ok(Some(ts)) = self.session.get_token_session(token).await {
                    lm.broadcast(&BulwarkEvent::SessionTimeout {
                        login_id: ts.login_id,
                        token: token.to_string(),
                        request_context: None,
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return Err(BulwarkError::Session("stp-not-login::".to_string()));
            }
        }
        // 悬停检查（仅 valid 时）
        if valid {
            let hover_ok = self.check_and_update_hover(token).await?;
            if !hover_ok {
                return Ok(false);
            }
            // Token 自动续签（若启用且剩余 TTL 低于阈值）
            if let Err(e) = self.check_and_renew(token).await {
                tracing::warn!(error = %e, "Token 自动续签失败，旧 Token 继续使用");
            }
            return Ok(true);
        }
        Ok(valid)
    }
}

// ============================================================================
// BulwarkLogicDefault 私有方法：异常检测集成（security-alert feature）
// ============================================================================

#[cfg(feature = "security-alert")]
impl BulwarkLogicDefault {
    /// login 路径异常检测：遍历所有检测器，广播事件，失败只 warn。
    async fn run_anomaly_check_on_login(&self, login_id: &str, params: &LoginParams) {
        let Some(detectors) = &self.anomaly_detectors else {
            return;
        };
        let device_id = params.device.as_deref().unwrap_or("");
        let ip = params.ip.as_deref();
        for detector in detectors {
            match detector.check_on_login(login_id, device_id, ip).await {
                Ok(events) => self.broadcast_anomaly_events(events).await,
                Err(e) => tracing::warn!(error = %e, "AnomalyDetector::check_on_login 失败"),
            }
        }
    }

    /// check_login 路径异常检测：遍历所有检测器，广播事件，失败只 warn。
    async fn run_anomaly_check_on_check_login(&self, login_id: &str, token: &str) {
        let Some(detectors) = &self.anomaly_detectors else {
            return;
        };
        for detector in detectors {
            match detector.check_on_check_login(login_id, token).await {
                Ok(events) => self.broadcast_anomaly_events(events).await,
                Err(e) => tracing::warn!(error = %e, "AnomalyDetector::check_on_check_login 失败"),
            }
        }
    }

    /// 广播告警事件列表到 `AlertListenerManager`。
    /// 未注入 manager 时为 no-op（事件被丢弃）。
    async fn broadcast_anomaly_events(
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
// BulwarkLogicDefault 私有方法：Token 自动续签
// ============================================================================

impl BulwarkLogicDefault {
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
    pub(crate) async fn check_and_renew(&self, token: &str) -> BulwarkResult<Option<String>> {
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

        // 持有 per-login_id **续签锁**（独立于 BulwarkSession::login_locks）执行续签。
        // 不能用 login_locks：renew_to_equivalent 内部调用 logout 会再次获取 login_locks → 死锁。
        let lock = self
            .renewal_locks
            .entry(login_id.clone())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();
        let _guard = lock.lock().await;

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
                    BulwarkError::Config(
                        "auto_renewal_threshold 启用但 auth_logic 未注入，无法续签".to_string(),
                    )
                })?;
                auth.renew_to_equivalent(token).await?
            };
            set_renewed_token(new_token.clone());
            Ok(Some(new_token))
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            if self.config.token_style == "jwt" {
                return Err(BulwarkError::Config(
                    "auto_renewal_threshold 启用且 token_style=jwt，但未启用 protocol-jwt feature"
                        .to_string(),
                ));
            }
            let auth = self.auth_logic.as_ref().ok_or_else(|| {
                BulwarkError::Config(
                    "auto_renewal_threshold 启用但 auth_logic 未注入，无法续签".to_string(),
                )
            })?;
            let new_token = auth.renew_to_equivalent(token).await?;
            set_renewed_token(new_token.clone());
            Ok(Some(new_token))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + 9 个必需 `SessionLogic` 方法
    /// （`login_by_token` 有默认实现，无需覆写）。
    struct MockSession {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockSession {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockSession {
        async fn login(&self, _login_id: &str, _params: &LoginParams) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    /// 验证 `login` 接受 `&str`（Numeric 与 String 形式）。
    /// 调用方通过 `BulwarkUtil::login("42")` 或 `BulwarkUtil::login(42i64.to_string())`。
    #[tokio::test]
    async fn login_accepts_str_ref() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let t1 = mock.login("42", &LoginParams::default()).await.unwrap();
        let t2 = mock.login("alice", &LoginParams::default()).await.unwrap();
        assert_eq!(t1, "mock-token");
        assert_eq!(t2, "mock-token");
    }

    /// 验证 `login_with_token` 接受 `&str`。
    #[tokio::test]
    async fn login_with_token_accepts_str_ref() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.login_with_token("user-uuid", "tok").await.unwrap();
    }

    /// 验证 `get_login_id` 返回 `String`（v0.5.2 返回类型迁移）。
    #[tokio::test]
    async fn get_login_id_returns_string() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let id = mock.get_login_id().await.unwrap().unwrap();
        assert_eq!(id, "42");
    }

    /// 验证 `login_by_token` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn login_by_token_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let result = mock.login_by_token("external").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// 验证 `revoke_all_sessions` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn revoke_all_sessions_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let result = mock.revoke_all_sessions("1001").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// 验证 `get_active_sessions` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn get_active_sessions_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let result = mock.get_active_sessions("1001").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // T006: AnomalyDetector 集成测试（security-alert feature）
    // ========================================================================

    #[cfg(feature = "security-alert")]
    mod anomaly_integration {
        use super::*;
        use crate::dao::BulwarkDao;
        use crate::session::BulwarkSession;
        use crate::stp::with_current_token;
        use crate::strategy::alert::{
            AlertListener, AlertListenerManager, AnomalyDetector, AnomalyType, SecurityAlertEvent,
        };
        use crate::strategy::BulwarkPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // --------------------------------------------------------------------
        // MockDao：HashMap + Instant 模拟 TTL（与 stp/tests.rs 同模式）
        // --------------------------------------------------------------------

        struct MockDao {
            store: Mutex<HashMap<String, (String, Option<Instant>)>>,
        }

        impl MockDao {
            fn new() -> Self {
                Self {
                    store: Mutex::new(HashMap::new()),
                }
            }
        }

        #[async_trait]
        impl BulwarkDao for MockDao {
            async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
                let mut store = self.store.lock();
                match store.get(key) {
                    Some((value, expire_at)) => {
                        if let Some(deadline) = expire_at {
                            if Instant::now() >= *deadline {
                                store.remove(key);
                                return Ok(None);
                            }
                        }
                        Ok(Some(value.clone()))
                    },
                    None => Ok(None),
                }
            }
            async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
                let expire_at = if ttl_seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(ttl_seconds))
                };
                self.store
                    .lock()
                    .insert(key.to_string(), (value.to_string(), expire_at));
                Ok(())
            }
            async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((existing, _)) => {
                        *existing = value.to_string();
                        Ok(())
                    },
                    None => Err(BulwarkError::Dao(format!("stp-dao-find-by-id::{}", key))),
                }
            }
            async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((_, expire_at)) => {
                        *expire_at = if seconds == 0 {
                            None
                        } else {
                            Some(Instant::now() + Duration::from_secs(seconds))
                        };
                        Ok(())
                    },
                    None => Err(BulwarkError::Dao(format!("stp-dao-find-by-id::{}", key))),
                }
            }
            async fn delete(&self, key: &str) -> BulwarkResult<()> {
                self.store.lock().remove(key);
                Ok(())
            }
        }

        // --------------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // --------------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl BulwarkPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
        }

        // --------------------------------------------------------------------
        // MockAnomalyDetector：记录调用，可配置返回事件或错误
        // --------------------------------------------------------------------

        struct MockAnomalyDetector {
            login_call_count: AtomicUsize,
            check_login_call_count: AtomicUsize,
            login_events: Mutex<Vec<SecurityAlertEvent>>,
            check_login_events: Mutex<Vec<SecurityAlertEvent>>,
            fail_on_login: bool,
            fail_on_check_login: bool,
        }

        impl MockAnomalyDetector {
            fn new() -> Self {
                Self {
                    login_call_count: AtomicUsize::new(0),
                    check_login_call_count: AtomicUsize::new(0),
                    login_events: Mutex::new(Vec::new()),
                    check_login_events: Mutex::new(Vec::new()),
                    fail_on_login: false,
                    fail_on_check_login: false,
                }
            }

            fn with_login_event(event: SecurityAlertEvent) -> Self {
                let det = Self::new();
                det.login_events.lock().push(event);
                det
            }

            fn with_check_login_event(event: SecurityAlertEvent) -> Self {
                let det = Self::new();
                det.check_login_events.lock().push(event);
                det
            }

            fn failing_on_login() -> Self {
                let mut det = Self::new();
                det.fail_on_login = true;
                det
            }

            fn failing_on_check_login() -> Self {
                let mut det = Self::new();
                det.fail_on_check_login = true;
                det
            }

            fn login_calls(&self) -> usize {
                self.login_call_count.load(Ordering::SeqCst)
            }

            fn check_login_calls(&self) -> usize {
                self.check_login_call_count.load(Ordering::SeqCst)
            }
        }

        #[async_trait]
        impl AnomalyDetector for MockAnomalyDetector {
            async fn check_on_login(
                &self,
                _login_id: &str,
                _device_id: &str,
                _ip: Option<&str>,
            ) -> BulwarkResult<Vec<SecurityAlertEvent>> {
                self.login_call_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_on_login {
                    return Err(BulwarkError::Internal(
                        "mock login detection 失败".to_string(),
                    ));
                }
                Ok(self.login_events.lock().clone())
            }

            async fn check_on_check_login(
                &self,
                _login_id: &str,
                _token: &str,
            ) -> BulwarkResult<Vec<SecurityAlertEvent>> {
                self.check_login_call_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_on_check_login {
                    return Err(BulwarkError::Internal(
                        "mock check_login detection 失败".to_string(),
                    ));
                }
                Ok(self.check_login_events.lock().clone())
            }
        }

        // --------------------------------------------------------------------
        // CountingAlertListener：记录接收到的告警事件
        // --------------------------------------------------------------------

        struct CountingAlertListener {
            received: Mutex<Vec<SecurityAlertEvent>>,
        }

        impl CountingAlertListener {
            fn new() -> Self {
                Self {
                    received: Mutex::new(Vec::new()),
                }
            }

            fn count(&self) -> usize {
                self.received.lock().len()
            }

            fn events(&self) -> Vec<SecurityAlertEvent> {
                self.received.lock().clone()
            }
        }

        #[async_trait]
        impl AlertListener for CountingAlertListener {
            async fn on_alert(&self, event: &SecurityAlertEvent) -> BulwarkResult<()> {
                self.received.lock().push(event.clone());
                Ok(())
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建带异常检测器的 BulwarkLogicDefault。
        fn make_logic_with_anomaly(
            detector: Arc<dyn AnomalyDetector>,
            listener_manager: Arc<AlertListenerManager>,
        ) -> BulwarkLogicDefault {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_anomaly_detector(detector)
                .with_alert_listener_manager(listener_manager)
        }

        /// 创建不带检测器的 BulwarkLogicDefault（向后兼容测试用）。
        fn make_logic_without_anomaly() -> BulwarkLogicDefault {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
        }

        fn sample_anomaly_event(login_id: &str) -> SecurityAlertEvent {
            SecurityAlertEvent::AnomalyLogin {
                login_id: login_id.to_string(),
                anomaly_type: AnomalyType::IpChanged,
                detail: "IP 变化检测".to_string(),
                trace_id: "trace-t006".to_string(),
            }
        }

        // --------------------------------------------------------------------
        // 6 个集成测试
        // --------------------------------------------------------------------

        /// login 时 detector 返回告警事件，验证 broadcast 被调用。
        #[tokio::test]
        async fn test_login_triggers_anomaly_alert() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::with_login_event(sample_anomaly_event(
                "1001",
            )));
            let logic = make_logic_with_anomaly(detector.clone(), manager);

            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("login 应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            assert_eq!(detector.login_calls(), 1, "check_on_login 应被调用 1 次");
            assert_eq!(listener.count(), 1, "应广播 1 个告警事件");
            let events = listener.events();
            assert!(
                matches!(&events[0], SecurityAlertEvent::AnomalyLogin { login_id, .. } if login_id == "1001"),
                "广播的事件应为 AnomalyLogin(login_id=1001)"
            );
        }

        /// check_login 时 detector 返回告警事件，验证 broadcast 被调用。
        #[tokio::test]
        async fn test_check_login_triggers_anomaly_alert() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::with_check_login_event(
                sample_anomaly_event("1001"),
            ));
            let logic = Arc::new(make_logic_with_anomaly(detector.clone(), manager));

            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let valid =
                with_current_token(token, async { logic.check_login().await.unwrap() }).await;

            assert!(valid, "check_login 应返回 true（有效 token）");
            assert_eq!(
                detector.check_login_calls(),
                1,
                "check_on_check_login 应被调用 1 次"
            );
            assert_eq!(listener.count(), 1, "应广播 1 个告警事件");
        }

        /// detector 返回 Err，login 仍成功返回 token。
        #[tokio::test]
        async fn test_login_detection_failure_does_not_interrupt() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::failing_on_login());
            let logic = make_logic_with_anomaly(detector.clone(), manager);

            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("检测失败时 login 仍应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            assert_eq!(detector.login_calls(), 1, "check_on_login 应被调用 1 次");
            assert_eq!(listener.count(), 0, "检测失败时不应广播事件");
        }

        /// detector 返回 Err，check_login 仍返回原结果。
        #[tokio::test]
        async fn test_check_login_detection_failure_does_not_interrupt() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::failing_on_check_login());
            let logic = Arc::new(make_logic_with_anomaly(detector.clone(), manager));

            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let valid =
                with_current_token(token, async { logic.check_login().await.unwrap() }).await;

            assert!(valid, "检测失败时 check_login 仍应返回 true");
            assert_eq!(
                detector.check_login_calls(),
                1,
                "check_on_check_login 应被调用 1 次"
            );
            assert_eq!(listener.count(), 0, "检测失败时不应广播事件");
        }

        /// 未注入 detector 时 login 正常工作（向后兼容）。
        #[tokio::test]
        async fn test_login_without_detector_backward_compatible() {
            let logic = make_logic_without_anomaly();
            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("未注入 detector 时 login 应正常工作");
            assert!(!token.is_empty(), "login 应返回非空 token");

            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
        }

        /// 未注入 detector 时 check_login 正常工作（向后兼容）。
        #[tokio::test]
        async fn test_check_login_without_detector_backward_compatible() {
            let logic = Arc::new(make_logic_without_anomaly());
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let valid =
                with_current_token(token, async { logic.check_login().await.unwrap() }).await;

            assert!(valid, "未注入 detector 时 check_login 应返回 true");
        }
    }

    // ========================================================================
    // T013: DeviceBindingPolicy 集成测试（device-binding feature）
    // ========================================================================

    #[cfg(feature = "device-binding")]
    mod device_binding_integration {
        use super::*;
        use crate::config::BulwarkConfig;
        use crate::dao::tests::MockDao;
        use crate::session::BulwarkSession;
        use crate::strategy::alert::{AlertListener, AlertListenerManager, SecurityAlertEvent};
        use crate::strategy::device_binding::{Disabled, LooseBinding, StrictBinding};
        use crate::strategy::BulwarkPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::sync::Arc;

        // --------------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // --------------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl BulwarkPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
        }

        // --------------------------------------------------------------------
        // CountingAlertListener：记录接收到的告警事件
        // --------------------------------------------------------------------

        struct CountingAlertListener {
            received: Mutex<Vec<SecurityAlertEvent>>,
        }

        impl CountingAlertListener {
            fn new() -> Self {
                Self {
                    received: Mutex::new(Vec::new()),
                }
            }

            fn count(&self) -> usize {
                self.received.lock().len()
            }

            fn events(&self) -> Vec<SecurityAlertEvent> {
                self.received.lock().clone()
            }
        }

        #[async_trait]
        impl AlertListener for CountingAlertListener {
            async fn on_alert(&self, event: &SecurityAlertEvent) -> BulwarkResult<()> {
                self.received.lock().push(event.clone());
                Ok(())
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建带 MockDao 的 BulwarkLogicDefault（无设备绑定策略，供测试自定义注入）。
        fn make_logic_base() -> BulwarkLogicDefault {
            let dao: Arc<MockDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
        }

        // --------------------------------------------------------------------
        // 7 个集成测试（A10 新增 hard block 验证）
        // --------------------------------------------------------------------

        /// A10 修复：strict 模式下新设备 login 被 hard block（require_secondary_auth=true
        /// → 返回 `Err(NotPermission)`），login 失败且不创建 session。
        #[tokio::test]
        async fn test_strict_mode_new_device_triggers_mfa() {
            let logic = make_logic_base();
            // 注入 StrictBinding（共享 logic.session，检测历史 session）
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            // 无历史 session → is_new_device=true → require_secondary_auth=true → hard block
            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let result = logic.login("1001", &params).await;

            // A10: login 应返回 Err(NotPermission) 而非成功
            assert!(
                result.is_err(),
                "strict 模式新设备 login 应被 hard block 阻断（A10 修复）"
            );
            match result {
                Err(BulwarkError::NotPermission(msg)) => {
                    assert_eq!(
                        msg, "secondary auth required",
                        "错误消息应为 'secondary auth required'"
                    );
                },
                Err(other) => panic!("期望 NotPermission 错误，实际: {:?}", other),
                Ok(_) => panic!("strict 模式新设备 login 不应成功（A10 hard block）"),
            }
        }

        /// A10 修复：strict 模式新设备 login 被阻断后不创建 session（无孤儿会话泄漏）。
        #[tokio::test]
        async fn test_strict_mode_new_device_block_creates_no_session() {
            let logic = make_logic_base();
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            // login 被阻断
            let _ = logic.login("1001", &params).await;

            // 验证无 session 被创建
            let tokens = logic.session.get_tokens_by_login_id("1001");
            assert!(
                tokens.is_empty(),
                "hard block 后不应创建任何 session（无孤儿会话）"
            );
        }

        /// strict 模式下旧设备 login 不触发 MFA（policy.is_new_device=false →
        /// require_secondary_auth 不调用 → params.require_mfa=false）。
        #[tokio::test]
        async fn test_strict_mode_old_device_no_mfa() {
            let logic = make_logic_base();
            // 预创建带 device="web-chrome" 的历史 session
            let pre_params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            logic
                .session
                .create_token_session("1001", "pre-token-T2", &pre_params)
                .await
                .unwrap();

            // 注入 StrictBinding
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            // 用同一 device 登录 → is_new_device=false → require_mfa 不触发
            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("strict 模式旧设备 login 应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            assert_ne!(token, "pre-token-T2", "应创建新 token（is_share=false）");
            // 验证新 session 已创建
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("新会话应已创建");
            assert_eq!(ts.device.as_deref(), Some("web-chrome"));
        }

        /// loose 模式下新设备 login 广播告警但不阻断（require_secondary_auth=false →
        /// params.require_mfa=false），AlertListener 收到 NewDeviceLogin 事件。
        #[tokio::test]
        async fn test_loose_mode_new_device_alerts_no_block() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);

            let logic = make_logic_base();
            // 注入 LooseBinding（带告警管理器）
            let policy = Arc::new(LooseBinding::with_alert_manager(
                logic.session.clone(),
                manager,
            ));
            let logic = logic.with_device_binding_policy(policy);

            // 无历史 session → is_new_device=true → require_secondary_auth 广播告警 + 返回 false
            let params = LoginParams {
                device: Some("mobile-ios".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("loose 模式新设备 login 应成功（不阻断）");

            assert!(!token.is_empty(), "login 应返回非空 token");
            // 验证告警已广播
            assert_eq!(
                listener.count(),
                1,
                "loose 模式新设备应广播 1 次 NewDeviceLogin 告警"
            );
            let events = listener.events();
            match &events[0] {
                SecurityAlertEvent::NewDeviceLogin {
                    login_id,
                    device_id,
                    ..
                } => {
                    assert_eq!(login_id, "1001");
                    assert_eq!(device_id, "mobile-ios");
                },
                other => panic!("期望 NewDeviceLogin 事件，实际: {:?}", other),
            }
        }

        /// disabled 模式下任何设备 login 不受影响（is_new_device=false →
        /// require_secondary_auth 不调用 → params.require_mfa=false）。
        #[tokio::test]
        async fn test_disabled_mode_no_impact() {
            let logic = make_logic_base();
            let policy = Arc::new(Disabled);
            let logic = logic.with_device_binding_policy(policy);

            let params = LoginParams {
                device: Some("any-device".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("disabled 模式 login 应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
        }

        /// 未注入 policy 时 login 正常工作（向后兼容），params.require_mfa=false。
        #[tokio::test]
        async fn test_no_policy_backward_compatible() {
            let logic = make_logic_base();
            // 不注入 device_binding_policy

            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("未注入 policy 时 login 应正常工作");

            assert!(!token.is_empty(), "login 应返回非空 token");
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
        }

        /// LoginParams::default().require_mfa 默认为 false。
        #[test]
        fn test_require_mfa_default_false() {
            let params = LoginParams::default();
            assert!(
                !params.require_mfa,
                "LoginParams::default().require_mfa 应为 false"
            );
        }
    }

    // ========================================================================
    // T014: three-tier-cache 集成测试（three-tier-cache feature）
    // 验证 R-three-tier-cache-005: logout/logout_by_login_id 调用 invalidate
    // ========================================================================

    #[cfg(feature = "three-tier-cache")]
    mod three_tier_cache_integration {
        use super::*;
        use crate::cache::UserCacheService;
        use crate::dao::BulwarkDao;
        use crate::session::BulwarkSession;
        use crate::stp::with_current_token;
        use crate::strategy::BulwarkPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        /// 计数 DAO：记录 delete 调用次数与 key 列表。
        struct CountingDao {
            store: Mutex<HashMap<String, (String, Option<Instant>)>>,
            delete_count: AtomicU32,
            delete_keys: Mutex<Vec<String>>,
        }

        impl CountingDao {
            fn new() -> Self {
                Self {
                    store: Mutex::new(HashMap::new()),
                    delete_count: AtomicU32::new(0),
                    delete_keys: Mutex::new(Vec::new()),
                }
            }

            fn delete_count(&self) -> u32 {
                self.delete_count.load(Ordering::SeqCst)
            }

            fn delete_keys(&self) -> Vec<String> {
                self.delete_keys.lock().clone()
            }

            /// 直接插入（绕过 TTL 逻辑，测试预备数据用）。
            fn insert_direct(&self, key: &str, value: &str) {
                self.store
                    .lock()
                    .insert(key.to_string(), (value.to_string(), None));
            }
        }

        #[async_trait]
        impl BulwarkDao for CountingDao {
            async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
                let mut store = self.store.lock();
                match store.get(key) {
                    Some((value, expire_at)) => {
                        if let Some(deadline) = expire_at {
                            if Instant::now() >= *deadline {
                                store.remove(key);
                                return Ok(None);
                            }
                        }
                        Ok(Some(value.clone()))
                    },
                    None => Ok(None),
                }
            }

            async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
                let expire_at = if ttl_seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(ttl_seconds))
                };
                self.store
                    .lock()
                    .insert(key.to_string(), (value.to_string(), expire_at));
                Ok(())
            }

            async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((existing, _)) => {
                        *existing = value.to_string();
                        Ok(())
                    },
                    None => Err(BulwarkError::Dao(format!("stp-dao-find-by-id::{}", key))),
                }
            }

            async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((_, expire_at)) => {
                        *expire_at = if seconds == 0 {
                            None
                        } else {
                            Some(Instant::now() + Duration::from_secs(seconds))
                        };
                        Ok(())
                    },
                    None => Err(BulwarkError::Dao(format!("stp-dao-find-by-id::{}", key))),
                }
            }

            async fn delete(&self, key: &str) -> BulwarkResult<()> {
                self.delete_count.fetch_add(1, Ordering::SeqCst);
                self.delete_keys.lock().push(key.to_string());
                self.store.lock().remove(key);
                Ok(())
            }
        }

        /// 最小 firewall mock（提供 L3 回调数据源）。
        struct MockFirewall;

        #[async_trait]
        impl BulwarkPermissionStrategy for MockFirewall {
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> BulwarkResult<bool> {
                Ok(true)
            }

            async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
                Ok(true)
            }

            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }

            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }

            async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec!["user:read".to_string()])
            }

            async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec!["admin".to_string()])
            }

            async fn get_user_info(&self, _login_id: &str) -> BulwarkResult<Option<String>> {
                Ok(Some("user-info".to_string()))
            }
        }

        /// 构造带 UserCacheService 的 BulwarkLogicDefault。
        fn make_logic_with_cache(dao: Arc<CountingDao>) -> BulwarkLogicDefault {
            let session = Arc::new(BulwarkSession::new(dao.clone(), 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            let cache_service = Arc::new(
                UserCacheService::new(
                    dao.clone() as Arc<dyn BulwarkDao>,
                    firewall.clone(),
                    30,
                    300,
                    10_000,
                )
                .expect("UserCacheService::new 应成功"),
            );
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_user_cache_service(cache_service)
        }

        /// logout() 注入 cache service 时应调用 invalidate（删除 perm/role/user 3 个缓存 key）。
        #[tokio::test]
        async fn logout_invalidates_user_cache() {
            let dao = Arc::new(CountingDao::new());
            let logic = Arc::new(make_logic_with_cache(dao.clone()));

            // 登录用户
            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("login 应成功");

            // 预填充缓存（模拟 get_permissions 已调用过）
            dao.insert_direct("perm:cache:1001", r#"["user:read"]"#);
            dao.insert_direct("role:cache:1001", r#"["admin"]"#);
            dao.insert_direct("user:cache:1001", r#""user-info""#);
            assert_eq!(dao.delete_count(), 0, "预填充后 delete 次数应为 0");

            // 调用 logout（需设置 current_token task-local）
            with_current_token(token, async {
                logic.logout().await.expect("logout 应成功");
            })
            .await;

            // 验证 invalidate 被调用：perm/role/user 3 个缓存 key 在删除列表中
            // （总 delete 次数可能包含 session.logout 销毁 token-session 的 delete）
            let deleted = dao.delete_keys();
            assert!(
                deleted.contains(&"perm:cache:1001".to_string()),
                "logout 应删除 perm:cache:1001，实际删除: {:?}",
                deleted
            );
            assert!(
                deleted.contains(&"role:cache:1001".to_string()),
                "logout 应删除 role:cache:1001"
            );
            assert!(
                deleted.contains(&"user:cache:1001".to_string()),
                "logout 应删除 user:cache:1001"
            );
        }

        /// logout_by_login_id() 注入 cache service 时应调用 invalidate。
        #[tokio::test]
        async fn logout_by_login_id_invalidates_user_cache() {
            let dao = Arc::new(CountingDao::new());
            let logic = Arc::new(make_logic_with_cache(dao.clone()));

            // 登录用户
            let _token = logic
                .login("2002", &LoginParams::default())
                .await
                .expect("login 应成功");

            // 预填充缓存
            dao.insert_direct("perm:cache:2002", r#"["user:read"]"#);
            dao.insert_direct("role:cache:2002", r#"["admin"]"#);
            dao.insert_direct("user:cache:2002", r#""user-info""#);

            // 调用 logout_by_login_id
            logic
                .logout_by_login_id("2002")
                .await
                .expect("logout_by_login_id 应成功");

            // 验证 perm/role/user 3 个缓存 key 被删除
            let deleted = dao.delete_keys();
            assert!(deleted.contains(&"perm:cache:2002".to_string()));
            assert!(deleted.contains(&"role:cache:2002".to_string()));
            assert!(deleted.contains(&"user:cache:2002".to_string()));
        }

        /// 未注入 cache service 时 logout 不 panic（向后兼容）。
        #[tokio::test]
        async fn logout_without_cache_service_backward_compatible() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(CountingDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            // 不注入 user_cache_service
            let logic = Arc::new(BulwarkLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
            ));

            let token = logic
                .login("3003", &LoginParams::default())
                .await
                .expect("login 应成功");

            with_current_token(token, async {
                logic.logout().await.expect("logout 应成功（无缓存服务）");
            })
            .await;
        }
    }

    // ========================================================================
    // 覆盖率补充测试：覆盖 check_login 三种模式、auto_renewal、错误路径等
    // 使用 `BulwarkLogicDefault` + `crate::stp::mock::{MockDao, MockFirewall}`
    // ========================================================================

    mod session_coverage_tests {
        use super::*;
        use crate::dao::BulwarkDao;
        use crate::session::BulwarkSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::stp::with_current_token;
        use crate::strategy::BulwarkPermissionStrategy;
        use std::sync::Arc;

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建基础 BulwarkLogicDefault（uuid token_style，throw 可配置）。
        fn make_logic(throw_on_not_login: bool) -> BulwarkLogicDefault {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = throw_on_not_login;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
        }

        /// 创建 JWT 模式 BulwarkLogicDefault（token_style=jwt + 自定义 jwt_secret + jwt_mode）。
        #[cfg(feature = "protocol-jwt")]
        fn make_jwt_logic(
            throw_on_not_login: bool,
            jwt_mode: JwtMode,
            secret: &str,
        ) -> BulwarkLogicDefault {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = throw_on_not_login;
            config.token_style = "jwt".to_string();
            config.jwt_secret = secret.to_string().into();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            BulwarkLogicDefault::new(session, Arc::new(config), firewall).with_jwt_mode(jwt_mode)
        }

        // --------------------------------------------------------------------
        // check_login：无 token 路径
        // --------------------------------------------------------------------

        /// 无 current_token + throw_on_not_login=true → Err Session("未登录")。
        #[tokio::test]
        async fn check_login_no_token_throws_when_configured() {
            let logic = make_logic(true);
            let result = logic.check_login().await;
            assert!(
                matches!(result, Err(BulwarkError::Session(ref msg)) if msg == "stp-not-login::"),
                "无 token + throw_on_not_login=true 应返回 Err(Session(\"stp-not-login::\"))，实际: {:?}",
                result
            );
        }

        /// 无 current_token + throw_on_not_login=false → Ok(false)。
        #[tokio::test]
        async fn check_login_no_token_returns_false_when_not_throwing() {
            let logic = make_logic(false);
            let result = logic.check_login().await;
            assert!(
                result.is_ok(),
                "无 token + throw_on_not_login=false 应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "无 token + throw_on_not_login=false 应返回 false"
            );
        }

        // --------------------------------------------------------------------
        // check_login_stateless 测试（需 protocol-jwt feature）
        // --------------------------------------------------------------------

        /// Stateless 模式 + 有效 JWT → Ok(true)。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_login_stateless_valid_jwt_returns_true() {
            let secret = "coverage-secret-stateless-valid";
            let logic = make_jwt_logic(false, JwtMode::Stateless, secret);
            let handler = crate::protocol::jwt::JwtHandler::new(secret);
            let jwt_token = handler
                .sign("stateless-user-001", 3600)
                .expect("JWT 签发应成功");

            let result = with_current_token(jwt_token, async { logic.check_login().await }).await;
            assert!(
                result.is_ok(),
                "Stateless + 有效 JWT 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap(), "Stateless + 有效 JWT 应返回 true");
        }

        /// Stateless 模式 + 无效 JWT → Err InvalidToken。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_login_stateless_invalid_token_returns_error() {
            let logic = make_jwt_logic(false, JwtMode::Stateless, "coverage-secret-stateless");
            let result = with_current_token("invalid.jwt.token".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidToken(_))),
                "Stateless + 无效 JWT 应返回 Err(InvalidToken)，实际: {:?}",
                result
            );
        }

        /// Stateless 模式 + token_style != jwt → Err Config。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_login_stateless_wrong_token_style_returns_config_error() {
            // token_style=uuid 但 jwt_mode=Stateless
            let logic = make_logic(false).with_jwt_mode(JwtMode::Stateless);
            let result =
                with_current_token("any-token".to_string(), async { logic.check_login().await })
                    .await;
            assert!(
                matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("Stateless")),
                "Stateless + token_style=uuid 应返回 Err(Config(...Stateless...))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // check_login_simple 测试
        // --------------------------------------------------------------------

        /// Simple 模式 + 无效 token + throw_on_not_login=false → Ok(false)。
        #[tokio::test]
        async fn check_login_simple_invalid_token_returns_false() {
            let logic = make_logic(false).with_jwt_mode(JwtMode::Simple);
            let result = with_current_token("nonexistent-token".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                result.is_ok(),
                "Simple + 无效 token + throw=false 应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "Simple + 无效 token + throw=false 应返回 false"
            );
        }

        // --------------------------------------------------------------------
        // check_login_mixin 测试（默认模式，无效 token 路径）
        // --------------------------------------------------------------------

        /// Mixin 模式 + 无效 token + throw_on_not_login=true → Err Session。
        #[tokio::test]
        async fn check_login_mixin_invalid_token_throws() {
            let logic = make_logic(true).with_jwt_mode(JwtMode::Mixin);
            let result = with_current_token("nonexistent-token".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                matches!(result, Err(BulwarkError::Session(ref msg)) if msg == "stp-not-login::"),
                "Mixin + 无效 token + throw=true 应返回 Err(Session(\"stp-not-login::\"))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // check_and_renew 测试（auto_renewal_threshold 路径）
        // --------------------------------------------------------------------

        /// threshold <= 0 → Ok(None)（未启用续签）。
        #[tokio::test]
        async fn check_and_renew_threshold_zero_returns_none() {
            let logic = make_logic(false);
            let result = logic.check_and_renew("any-token").await;
            assert!(
                result.is_ok(),
                "threshold <= 0 应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                result.unwrap().is_none(),
                "threshold <= 0 应返回 None（未启用续签）"
            );
        }

        /// threshold > 0 + TTL 充足 → Ok(None)（无需续签）。
        #[tokio::test]
        async fn check_and_renew_ttl_sufficient_returns_none() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            // session timeout=3600s，与 config.timeout 对齐以避免百分比计算偏差
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            config.auto_renewal_threshold = 50;
            config.timeout = 3600;
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("renew-user-001", &LoginParams::default())
                .await
                .unwrap();
            let result = logic.check_and_renew(&token).await;
            assert!(result.is_ok(), "TTL 充足应返回 Ok，实际: {:?}", result);
            assert!(result.unwrap().is_none(), "TTL 充足应返回 None（无需续签）");
        }

        /// threshold > 0 + TTL 低于阈值 + 无 auth_logic → Err Config（非 JWT 路径）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_and_renew_no_auth_logic_returns_config_error() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            // session timeout=5s，与 config.timeout 对齐
            let session = Arc::new(BulwarkSession::new(dao, 5, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            config.auto_renewal_threshold = 95;
            config.timeout = 5;
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("renew-user-002", &LoginParams::default())
                .await
                .unwrap();
            // 等待 TTL 衰减至阈值以下（5s * 5% = 250ms 后即低于 95%）
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            let result = logic.check_and_renew(&token).await;
            assert!(
                matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("auth_logic")),
                "TTL 低 + 无 auth_logic 应返回 Err(Config(...auth_logic...))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // generate_token 错误路径
        // --------------------------------------------------------------------

        /// 未知 token_style → Err Config("unknown token_style")。
        #[tokio::test]
        async fn generate_token_unknown_style_returns_config_error() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "unknown-style".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let result = logic.login("test-user", &LoginParams::default()).await;
            assert!(
                matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("unknown token_style")),
                "未知 token_style 应返回 Err(Config(...unknown token_style...))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // refresh_access_token 错误路径
        // --------------------------------------------------------------------

        /// 未注入 RefreshTokenRotation → Err NotImplemented。
        #[tokio::test]
        async fn refresh_access_token_returns_not_implemented() {
            let logic = make_logic(false);
            let result = logic.refresh_access_token("any-refresh-token").await;
            assert!(
                matches!(result, Err(BulwarkError::NotImplemented(_))),
                "未注入 RefreshTokenRotation 应返回 Err(NotImplemented)，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // revoke_all_sessions 测试
        // --------------------------------------------------------------------

        /// 无 token 时返回 0。
        #[tokio::test]
        async fn revoke_all_sessions_returns_zero_for_no_tokens() {
            let logic = make_logic(false);
            let count = logic.revoke_all_sessions("no-sessions-user").await.unwrap();
            assert_eq!(count, 0, "无 token 时应返回 0，实际: {}", count);
        }

        /// 有 token 时全部吊销并返回 count。
        #[tokio::test]
        async fn revoke_all_sessions_revokes_all_tokens() {
            let logic = make_logic(false);
            let t1 = logic
                .login("revoke-user-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("revoke-user-001", &LoginParams::default())
                .await
                .unwrap();
            let t3 = logic
                .login("revoke-user-001", &LoginParams::default())
                .await
                .unwrap();

            let count = logic.revoke_all_sessions("revoke-user-001").await.unwrap();
            assert_eq!(count, 3, "应吊销 3 个会话，实际: {}", count);

            // 验证所有 token 已被吊销
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_none(),
                "t1 应被吊销"
            );
            assert!(
                logic
                    .session
                    .get_token_session(&t2)
                    .await
                    .unwrap()
                    .is_none(),
                "t2 应被吊销"
            );
            assert!(
                logic
                    .session
                    .get_token_session(&t3)
                    .await
                    .unwrap()
                    .is_none(),
                "t3 应被吊销"
            );
        }

        // --------------------------------------------------------------------
        // get_active_sessions 测试
        // --------------------------------------------------------------------

        /// get_active_sessions 过滤掉失效 token。
        #[tokio::test]
        async fn get_active_sessions_filters_invalid_tokens() {
            let logic = make_logic(false);
            let t1 = logic
                .login("active-user-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("active-user-001", &LoginParams::default())
                .await
                .unwrap();
            // 手动吊销 t1（模拟 token 失效）
            logic.session.logout(&t1).await.unwrap();

            let active = logic.get_active_sessions("active-user-001").await.unwrap();
            assert_eq!(
                active.len(),
                1,
                "应只有 1 个活跃会话（t2），实际: {}",
                active.len()
            );
            assert_eq!(active[0], t2, "活跃会话应为 t2，实际: {:?}", active);
        }

        // --------------------------------------------------------------------
        // get_login_id 测试
        // --------------------------------------------------------------------

        /// 无 current_token → Ok(None)。
        #[tokio::test]
        async fn get_login_id_no_current_token_returns_none() {
            let logic = make_logic(false);
            let result = logic.get_login_id().await;
            assert!(
                result.is_ok(),
                "无 current_token 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap().is_none(), "无 current_token 应返回 None");
        }

        // --------------------------------------------------------------------
        // login_inner: is_share 路径
        // --------------------------------------------------------------------

        /// is_share=true 时复用现有有效 token。
        #[tokio::test]
        async fn login_with_is_share_reuses_existing_token() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_share = true;

            let t1 = logic
                .login("share-valid-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("share-valid-001", &LoginParams::default())
                .await
                .unwrap();
            assert_eq!(t1, t2, "is_share=true 应复用现有有效 token");
        }

        /// is_share=true + token 已失效 → 清理后创建新会话。
        #[tokio::test]
        async fn login_with_is_share_creates_new_when_existing_invalid() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_share = true;

            let t1 = logic
                .login("share-invalid-001", &LoginParams::default())
                .await
                .unwrap();
            // 手动吊销 t1（模拟 token 失效）
            logic.session.logout(&t1).await.unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_none(),
                "t1 应已失效"
            );

            // 第二次登录：is_share=true 但旧 token 失效，应创建新 token
            let t2 = logic
                .login("share-invalid-001", &LoginParams::default())
                .await
                .unwrap();
            assert_ne!(t1, t2, "is_share=true 但旧 token 失效时应创建新 token");
            assert!(
                logic
                    .session
                    .get_token_session(&t2)
                    .await
                    .unwrap()
                    .is_some(),
                "新 token 应有对应 session"
            );
        }

        // --------------------------------------------------------------------
        // login_inner: NewDevice 模式（is_concurrent=false）允许首次登录
        // --------------------------------------------------------------------

        /// NewDevice 模式 + 无旧会话 → 允许登录。
        #[tokio::test]
        async fn login_new_device_mode_allows_first_login() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_concurrent = false;
            Arc::make_mut(&mut logic.config).replaced_login_exit_mode =
                ReplacedLoginExitMode::NewDevice;

            let token = logic
                .login("new-device-first-001", &LoginParams::default())
                .await;
            assert!(
                token.is_ok(),
                "NewDevice 模式 + 无旧会话应允许登录，实际: {:?}",
                token
            );
            assert!(!token.unwrap().is_empty(), "应返回非空 token");
        }

        // ==================================================================
        // Listener 广播测试：logout / kickout / revoke_token
        // ==================================================================

        #[cfg(feature = "listener")]
        mod listener_tests {
            use super::*;
            use crate::config::OverflowLogoutMode;
            use crate::listener::{BulwarkEvent, BulwarkListener, BulwarkListenerManager};
            use crate::stp::{Clock, MockClock};
            use parking_lot::Mutex;

            /// 记录事件监听器，捕获广播的 BulwarkEvent 用于断言。
            struct RecordingListener {
                events: Mutex<Vec<BulwarkEvent>>,
            }

            impl RecordingListener {
                fn new() -> Self {
                    Self {
                        events: Mutex::new(Vec::new()),
                    }
                }

                fn captured(&self) -> Vec<BulwarkEvent> {
                    self.events.lock().clone()
                }
            }

            #[async_trait]
            impl BulwarkListener for RecordingListener {
                async fn on_event(&self, event: &BulwarkEvent) -> crate::error::BulwarkResult<()> {
                    self.events.lock().push(event.clone());
                    Ok(())
                }
            }

            /// 创建带 listener_manager 的 BulwarkLogicDefault，返回 (logic, recorder)。
            fn make_logic_with_listener(
                throw_on_not_login: bool,
            ) -> (BulwarkLogicDefault, Arc<RecordingListener>) {
                let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
                let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
                let mut config = BulwarkConfig::default_config();
                config.throw_on_not_login = throw_on_not_login;
                config.token_style = "uuid".to_string();
                let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let recorder = Arc::new(RecordingListener::new());
                let lm = Arc::new(BulwarkListenerManager::new());
                lm.register(recorder.clone() as Arc<dyn BulwarkListener>);
                let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                    .with_listener_manager(lm);
                (logic, recorder)
            }

            /// logout 广播 Logout 事件。
            ///
            /// 覆盖 lines 251-286：current_token 存在 → session.logout → broadcast Logout。
            #[tokio::test]
            async fn logout_broadcasts_logout_event() {
                let (logic, recorder) = make_logic_with_listener(false);
                let token = logic
                    .login("logout-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result =
                    with_current_token(token.clone(), async { logic.logout().await }).await;
                assert!(result.is_ok(), "logout 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::Logout {
                            login_id,
                            token: t,
                            ..
                        } if login_id == "logout-user-001" && t == &token
                    )),
                    "应广播 Logout 事件 (login_id=logout-user-001)，实际事件: {:?}",
                    events
                );
            }

            /// kickout 广播 Kickout 事件。
            ///
            /// 覆盖 lines 300-315：logout_by_login_id → broadcast Kickout。
            #[tokio::test]
            async fn kickout_broadcasts_kickout_event() {
                let (logic, recorder) = make_logic_with_listener(false);
                logic
                    .login("kickout-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.kickout("kickout-user-001").await;
                assert!(result.is_ok(), "kickout 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::Kickout {
                            login_id,
                            reason,
                            ..
                        } if login_id == "kickout-user-001" && reason == "管理员强制下线"
                    )),
                    "应广播 Kickout 事件 (login_id=kickout-user-001)，实际事件: {:?}",
                    events
                );
            }

            /// revoke_token 广播 RevokeToken 事件。
            ///
            /// 覆盖 lines 322-335：session.logout → broadcast RevokeToken。
            #[tokio::test]
            async fn revoke_token_broadcasts_revoke_event() {
                let (logic, recorder) = make_logic_with_listener(false);
                let token = logic
                    .login("revoke-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.revoke_token(&token).await;
                assert!(result.is_ok(), "revoke_token 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::RevokeToken { token: t, .. } if t == &token
                    )),
                    "应广播 RevokeToken 事件 (token={})，实际事件: {:?}",
                    token,
                    events
                );
            }

            // ==================================================================
            // enforce_max_login_count 测试
            // ==================================================================

            /// max=0 时不做任何操作（no-op）。
            ///
            /// 覆盖 lines 647-649：max == 0 → return Ok(())。
            #[tokio::test]
            async fn enforce_max_login_count_zero_is_noop() {
                let logic = make_logic(false);
                let token = logic
                    .login("max-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-user-001", 0).await;
                assert!(result.is_ok(), "max=0 应返回 Ok，实际: {:?}", result);
                assert!(
                    logic
                        .session
                        .get_token_session(&token)
                        .await
                        .unwrap()
                        .is_some(),
                    "max=0 时 session 应仍然存在"
                );
            }

            /// 超过 max_login_count 时踢出最旧会话，OverflowLogoutMode::Logout 广播 Logout 事件。
            ///
            /// 覆盖 lines 651-709（Logout 模式分支 lines 678-685）。
            #[tokio::test]
            async fn enforce_max_login_count_evicts_oldest_with_logout_mode() {
                let (logic, recorder) = make_logic_with_listener(false);
                let t1 = logic
                    .login("max-logout-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t2 = logic
                    .login("max-logout-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t3 = logic
                    .login("max-logout-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-logout-001", 1).await;
                assert!(result.is_ok(), "enforce 应返回 Ok，实际: {:?}", result);
                // t1 是最旧的，应被踢出
                assert!(
                    logic
                        .session
                        .get_token_session(&t1)
                        .await
                        .unwrap()
                        .is_none(),
                    "最旧 token 应已被踢出"
                );

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::Logout { login_id, token, .. } if login_id == "max-logout-001"
                            && token == &t1
                    )),
                    "应广播 Logout 事件 (最旧 token 被踢出)，实际事件: {:?}",
                    events
                );
            }

            /// OverflowLogoutMode::Kickout 广播 Kickout 事件。
            ///
            /// 覆盖 lines 686-694（Kickout 模式分支）。
            #[tokio::test]
            async fn enforce_max_login_count_evicts_oldest_with_kickout_mode() {
                let (mut logic, recorder) = make_logic_with_listener(false);
                Arc::make_mut(&mut logic.config).overflow_logout_mode = OverflowLogoutMode::Kickout;
                let t1 = logic
                    .login("max-kickout-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t2 = logic
                    .login("max-kickout-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-kickout-001", 1).await;
                assert!(result.is_ok(), "enforce 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::Kickout {
                            login_id,
                            token,
                            reason,
                            ..
                        } if login_id == "max-kickout-001"
                            && token == &t1
                            && reason == "超过最大登录数限制"
                    )),
                    "应广播 Kickout 事件 (reason=超过最大登录数限制)，实际事件: {:?}",
                    events
                );
            }

            /// OverflowLogoutMode::Replaced 广播 Replaced 事件。
            ///
            /// 覆盖 lines 695-704（Replaced 模式分支）。
            #[tokio::test]
            async fn enforce_max_login_count_evicts_oldest_with_replaced_mode() {
                let (mut logic, recorder) = make_logic_with_listener(false);
                Arc::make_mut(&mut logic.config).overflow_logout_mode =
                    OverflowLogoutMode::Replaced;
                let t1 = logic
                    .login("max-replaced-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t2 = logic
                    .login("max-replaced-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-replaced-001", 1).await;
                assert!(result.is_ok(), "enforce 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::Replaced {
                            login_id,
                            token,
                            reason,
                            ..
                        } if login_id == "max-replaced-001" && token == &t1
                    )),
                    "应广播 Replaced 事件，实际事件: {:?}",
                    events
                );
            }

            // ==================================================================
            // login_by_token 测试（token_style=simple，verify_token 路径）
            // ==================================================================

            /// login_by_token 通过 verify_token 解析 login_id 并创建会话，广播 Login 事件。
            ///
            /// 覆盖 lines 416-440：无 auth_logic → self.verify_token → session.create → broadcast Login。
            #[tokio::test]
            async fn login_by_token_creates_session_and_broadcasts_login() {
                let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
                let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
                let mut config = BulwarkConfig::default_config();
                config.throw_on_not_login = false;
                config.token_style = "simple".to_string();
                let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let recorder = Arc::new(RecordingListener::new());
                let lm = Arc::new(BulwarkListenerManager::new());
                lm.register(recorder.clone() as Arc<dyn BulwarkListener>);
                let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                    .with_listener_manager(lm);

                // simple 格式 token: <login_id>-<uuid>（login_id 不能含 '-'，因 split_once 分割）
                let external_token = format!("externaluser001-{}", uuid::Uuid::new_v4());
                let result = logic.login_by_token(&external_token).await;
                assert!(
                    result.is_ok(),
                    "login_by_token 应返回 Ok，实际: {:?}",
                    result
                );

                // 验证会话已创建
                assert!(
                    logic
                        .session
                        .get_token_session(&external_token)
                        .await
                        .unwrap()
                        .is_some(),
                    "login_by_token 后应存在 Token-Session"
                );

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::Login {
                            login_id,
                            token,
                            ..
                        } if login_id == "externaluser001" && token == &external_token
                    )),
                    "应广播 Login 事件 (login_id=externaluser001)，实际事件: {:?}",
                    events
                );
            }

            // ==================================================================
            // check_and_update_hover 测试（session_hover_timeout + MockClock）
            // ==================================================================

            /// 悬停超时后 check_login 返回 false 并广播 SessionTimeout 事件。
            ///
            /// 覆盖 lines 834-865：session_hover_timeout > 0 + last_active 过期 → logout + broadcast。
            #[tokio::test]
            async fn check_and_update_hover_evicts_on_timeout() {
                let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
                let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
                let mut config = BulwarkConfig::default_config();
                config.throw_on_not_login = false;
                config.token_style = "uuid".to_string();
                config.session_hover_timeout = 1; // 1 second
                let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let clock = Arc::new(MockClock::new(chrono::Utc::now()));
                let recorder = Arc::new(RecordingListener::new());
                let lm = Arc::new(BulwarkListenerManager::new());
                lm.register(recorder.clone() as Arc<dyn BulwarkListener>);
                let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                    .with_listener_manager(lm)
                    .with_clock(clock.clone() as Arc<dyn Clock>);

                let token = logic
                    .login("hover-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                // 手动设置 last_active_at 为当前 MockClock 时间
                let now_millis = clock.now().timestamp_millis();
                logic
                    .session
                    .update_last_active_at("hover-user-001", now_millis);

                // 推进 MockClock 2 秒（超过 1 秒悬停超时）
                clock.advance(chrono::Duration::seconds(2));

                let result =
                    with_current_token(token.clone(), async { logic.check_login().await }).await;
                assert!(
                    result.is_ok(),
                    "悬停超时 + throw=false 时 check_login 应返回 Ok，实际: {:?}",
                    result
                );
                assert!(!result.unwrap(), "悬停超时后 check_login 应返回 false");

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        BulwarkEvent::SessionTimeout {
                            login_id,
                            token: t,
                            ..
                        } if login_id == "hover-user-001" && t == &token
                    )),
                    "应广播 SessionTimeout 事件，实际事件: {:?}",
                    events
                );
            }

            /// 悬停超时 + throw_on_not_login=true → Err(Session("会话悬停超时"))。
            ///
            /// 覆盖 lines 857-859：throw_on_not_login=true → return Err。
            #[tokio::test]
            async fn check_and_update_hover_evicts_on_timeout_throws() {
                let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
                let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
                let mut config = BulwarkConfig::default_config();
                config.throw_on_not_login = true;
                config.token_style = "uuid".to_string();
                config.session_hover_timeout = 1;
                let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let clock = Arc::new(MockClock::new(chrono::Utc::now()));
                let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                    .with_clock(clock.clone() as Arc<dyn Clock>);

                let token = logic
                    .login("hover-user-002", &LoginParams::default())
                    .await
                    .unwrap();
                let now_millis = clock.now().timestamp_millis();
                logic
                    .session
                    .update_last_active_at("hover-user-002", now_millis);
                clock.advance(chrono::Duration::seconds(2));

                let result = with_current_token(token, async { logic.check_login().await }).await;
                assert!(
                    matches!(result, Err(BulwarkError::Session(ref msg)) if msg == "stp-session-timeout::"),
                    "悬停超时 + throw=true 应返回 Err(Session(\"会话悬停超时\"))，实际: {:?}",
                    result
                );
            }
        } // end listener_tests

        // ==================================================================
        // login_with_token / kickout_by_token / logout 无 token 路径
        // ==================================================================

        /// login_with_token 创建会话后，check_login 返回 true。
        ///
        /// 覆盖 lines 247-249：`self.session.create(login_id, token)` 路径。
        #[tokio::test]
        async fn login_with_token_creates_session() {
            let logic = make_logic(false);
            logic
                .login_with_token("lwt-user-001", "custom-token-001")
                .await
                .unwrap();
            // 验证会话已创建
            let ts = logic
                .session
                .get_token_session("custom-token-001")
                .await
                .unwrap()
                .expect("login_with_token 后应存在 Token-Session");
            assert_eq!(ts.login_id, "lwt-user-001");
        }

        /// token 已关联其他 login_id 时 `login_with_token` 应返回 Err。
        ///
        /// 模拟攻击者拿到 alice 的 token 后，调用 `login_with_token("attacker", T1)`
        /// 试图在 attacker 名下创建会话以实现会话劫持。应拒绝，避免同一 token
        /// 同时映射到两个 login_id（dual-mapping）。
        ///
        /// 覆盖 `login_with_token` 中新增的 token 唯一性检查分支。
        #[tokio::test]
        async fn login_with_token_returns_error_when_token_already_associated() {
            let logic = make_logic(false);
            // alice 先用 T1 登录（合法占有 T1）
            logic
                .login_with_token("alice-001", "shared-token-T1")
                .await
                .expect("alice 首次登录应成功");

            // 攻击者尝试用同一 token 在自己名下创建会话
            let result = logic
                .login_with_token("attacker-002", "shared-token-T1")
                .await;
            assert!(
                result.is_err(),
                "token 已关联 alice 时，attacker 重复关联应返回 Err，避免 dual-mapping。实际: {:?}",
                result
            );

            // 验证 token 仍归属 alice（未被覆盖）
            let ts = logic
                .session
                .get_token_session("shared-token-T1")
                .await
                .unwrap()
                .expect("T1 的 Token-Session 应保留");
            assert_eq!(
                ts.login_id, "alice-001",
                "token 应仍归属原 login_id（alice），未被 attacker 抢占"
            );
        }

        // ==================================================================
        // A8: login_with_token 入口校验（会话固定/劫持防护）
        // ==================================================================

        /// A8: 空 `login_id` 应被拒绝。
        ///
        /// 攻击场景：攻击者尝试用空 login_id 创建无主会话，绕过账号绑定。
        /// 期望返回 `InvalidParam`，且不创建任何会话。
        #[tokio::test]
        async fn a8_login_with_token_rejects_empty_login_id() {
            let logic = make_logic(false);
            let result = logic.login_with_token("", "valid-token-001").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(_))),
                "空 login_id 应返回 InvalidParam，实际: {:?}",
                result
            );
            // 验证未创建会话（fail-closed）
            assert!(
                logic
                    .session
                    .get_token_session("valid-token-001")
                    .await
                    .unwrap()
                    .is_none(),
                "校验失败时不应创建会话"
            );
        }

        /// A8: 空 `token` 应被拒绝。
        ///
        /// 攻击场景：空 token 无法标识会话，且可能在下游 DAO 层产生异常键。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_empty_token() {
            let logic = make_logic(false);
            let result = logic.login_with_token("user-001", "").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(_))),
                "空 token 应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// A8: 过短 token（< 8 字节）应被拒绝。
        ///
        /// 攻击场景：过短 token 易碰撞/伪造（如 "0"/"1"/"abc"），
        /// 攻击者可枚举短 token 劫持他人会话。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_too_short_token() {
            let logic = make_logic(false);
            // 7 字节 token（< 8 下限）
            let result = logic.login_with_token("user-001", "short12").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(_))),
                "过短 token 应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// A8: 超长 token（> 256 字节）应被拒绝。
        ///
        /// 攻击场景：超长 token 可触发 DAO 存储放大 / 序列化开销过大（DoS）。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_too_long_token() {
            let logic = make_logic(false);
            // 257 字节 token（> 256 上限）
            let long_token = "a".repeat(257);
            let result = logic.login_with_token("user-001", &long_token).await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(_))),
                "超长 token 应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// A8: 含控制字符的 token 应被拒绝。
        ///
        /// 攻击场景：控制字符（如 `\r\n`）可触发 CRLF 注入 / HTTP header
        /// smuggling / 日志污染。例如 token="valid\r\nX-Evil: 1" 可在日志
        /// 或下游 HTTP 客户端注入伪造 header。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_token_with_control_chars() {
            let logic = make_logic(false);
            // 含 \r\n 的 token（CRLF 注入向量）
            let result = logic
                .login_with_token("user-001", "valid-token\r\nX-Evil: 1")
                .await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(_))),
                "含控制字符的 token 应返回 InvalidParam，实际: {:?}",
                result
            );
            // 含 NUL 字节的 token（二进制注入向量）
            let result2 = logic.login_with_token("user-001", "valid\0token").await;
            assert!(
                matches!(result2, Err(BulwarkError::InvalidParam(_))),
                "含 NUL 字节的 token 应返回 InvalidParam，实际: {:?}",
                result2
            );
        }

        /// A8: 边界值 — 8 字节 token 应通过校验（下限包含）。
        ///
        /// 验证 `8..=256` 区间为闭区间，避免 off-by-one 错误。
        #[tokio::test]
        async fn a8_login_with_token_accepts_min_length_token() {
            let logic = make_logic(false);
            // 恰好 8 字节 token（下限包含）
            logic
                .login_with_token("user-001", "12345678")
                .await
                .expect("8 字节 token 应通过校验");
            // 验证会话已创建
            let ts = logic
                .session
                .get_token_session("12345678")
                .await
                .unwrap()
                .expect("8 字节 token 应已创建会话");
            assert_eq!(ts.login_id, "user-001");
        }

        /// A8: 边界值 — 256 字节 token 应通过校验（上限包含）。
        ///
        /// 验证 `8..=256` 区间为闭区间，避免 off-by-one 错误。
        #[tokio::test]
        async fn a8_login_with_token_accepts_max_length_token() {
            let logic = make_logic(false);
            // 恰好 256 字节 token（上限包含）
            let max_token = "a".repeat(256);
            logic
                .login_with_token("user-001", &max_token)
                .await
                .expect("256 字节 token 应通过校验");
            // 验证会话已创建
            let ts = logic
                .session
                .get_token_session(&max_token)
                .await
                .unwrap()
                .expect("256 字节 token 应已创建会话");
            assert_eq!(ts.login_id, "user-001");
        }

        /// kickout_by_token 销毁指定 token 的会话。
        ///
        /// 覆盖 lines 317-320：`self.session.logout(token)` 路径。
        #[tokio::test]
        async fn kickout_by_token_destroys_session() {
            let logic = make_logic(false);
            let token = logic
                .login("kbt-user-001", &LoginParams::default())
                .await
                .unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&token)
                    .await
                    .unwrap()
                    .is_some(),
                "login 后应存在 session"
            );
            logic.kickout_by_token(&token).await.unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&token)
                    .await
                    .unwrap()
                    .is_none(),
                "kickout_by_token 后 session 应被销毁"
            );
        }

        /// logout 无 current_token 时幂等返回 Ok。
        ///
        /// 覆盖 lines 283-285：`Err(_) => Ok(())` 分支。
        #[tokio::test]
        async fn logout_without_token_returns_ok() {
            let logic = make_logic(false);
            // 不设置 current_token，直接调用 logout
            let result = logic.logout().await;
            assert!(
                result.is_ok(),
                "无 current_token 时 logout 应幂等返回 Ok，实际: {:?}",
                result
            );
        }

        // ==================================================================
        // generate_token 不同 token_style 测试
        // ==================================================================

        /// token_style=random_64 生成 64 字符 token。
        ///
        /// 覆盖 lines 720-724：`random_64` 分支（两个 simple UUID 拼接）。
        #[tokio::test]
        async fn generate_token_random_64_style() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "random_64".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("r64-user-001", &LoginParams::default())
                .await
                .unwrap();
            // random_64 = 两个 simple UUID 拼接 = 32 + 32 = 64 字符
            assert_eq!(
                token.len(),
                64,
                "random_64 token 应为 64 字符，实际: {} 字符",
                token.len()
            );
            // 验证全部为十六进制字符
            assert!(
                token.chars().all(|c| c.is_ascii_hexdigit()),
                "random_64 token 应全部为十六进制字符"
            );
        }

        /// token_style=simple 生成 32 字符 token。
        ///
        /// 覆盖 line 725：`simple` 分支（simple UUID，32 字符无连字符）。
        #[tokio::test]
        async fn generate_token_simple_style() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "simple".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("simple-user-001", &LoginParams::default())
                .await
                .unwrap();
            // simple UUID = 32 字符无连字符
            assert_eq!(
                token.len(),
                32,
                "simple token 应为 32 字符，实际: {} 字符",
                token.len()
            );
            assert!(!token.contains('-'), "simple token 不应包含连字符");
        }

        /// token_style=jwt 生成 JWT token。
        ///
        /// 覆盖 lines 726-739：`jwt` 分支（委托 JwtHandler::sign）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn generate_token_jwt_style() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "gen-jwt-secret".to_string().into();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("jwt-user-001", &LoginParams::default())
                .await
                .unwrap();
            // JWT token 包含两个点（header.payload.signature）
            assert_eq!(
                token.matches('.').count(),
                2,
                "JWT token 应包含 2 个点，实际: {} 个",
                token.matches('.').count()
            );
        }

        // ==================================================================
        // check_login_mixin + 有效 token 路径
        // ==================================================================

        /// Mixin 模式 + 有效 token → Ok(true)。
        ///
        /// 覆盖 lines 808-821：valid=true → check_and_update_hover → check_and_renew → Ok(true)。
        #[tokio::test]
        async fn check_login_mixin_valid_token_returns_true() {
            let logic = make_logic(false).with_jwt_mode(JwtMode::Mixin);
            let token = logic
                .login("mixin-user-001", &LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async { logic.check_login().await }).await;
            assert!(
                result.is_ok(),
                "Mixin + 有效 token 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap(), "Mixin + 有效 token 应返回 true");
        }

        /// Simple 模式 + 有效 token → Ok(true)。
        ///
        /// 覆盖 lines 891-903：valid=true → check_and_update_hover → check_and_renew → Ok(true)。
        #[tokio::test]
        async fn check_login_simple_valid_token_returns_true() {
            let logic = make_logic(false).with_jwt_mode(JwtMode::Simple);
            let token = logic
                .login("simple-check-user-001", &LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async { logic.check_login().await }).await;
            assert!(
                result.is_ok(),
                "Simple + 有效 token 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap(), "Simple + 有效 token 应返回 true");
        }

        // ==================================================================
        // refresh_access_token 错误路径（protocol-jwt + db-sqlite）
        // ==================================================================

        /// 启用 protocol-jwt + db-sqlite 但未注入 RefreshTokenRotation → NotImplemented。
        ///
        /// 覆盖 lines 444-452：`#[cfg(all(protocol-jwt, db-sqlite))]` 分支
        /// 中 `refresh_token_rotation` 未注入返回 NotImplemented。
        #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
        #[tokio::test]
        async fn refresh_access_token_with_jwt_no_rotation_returns_not_implemented() {
            let logic = make_logic(false);
            let result = logic.refresh_access_token("any-refresh").await;
            assert!(
                matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("RefreshTokenRotation")),
                "未注入 RefreshTokenRotation 应返回 NotImplemented 包含 'RefreshTokenRotation'，实际: {:?}",
                result
            );
        }

        // ==================================================================
        // NewDevice 模式拒绝登录路径
        // ==================================================================

        /// NewDevice 模式 + 已有有效旧会话 → 拒绝新登录。
        ///
        /// 覆盖 lines 500-514：`NewDevice` 分支中存在有效旧会话时返回 NotLogin。
        #[tokio::test]
        async fn login_new_device_mode_rejects_when_existing_session() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_concurrent = false;
            Arc::make_mut(&mut logic.config).replaced_login_exit_mode =
                ReplacedLoginExitMode::NewDevice;

            // 首次登录成功
            let _t1 = logic
                .login("new-device-reject-001", &LoginParams::default())
                .await
                .unwrap();

            // 第二次登录应被拒绝（NewDevice 模式 + 已有有效旧会话）
            let result = logic
                .login("new-device-reject-001", &LoginParams::default())
                .await;
            assert!(
                matches!(result, Err(BulwarkError::NotLogin(ref msg)) if msg.contains("NewDevice")),
                "NewDevice 模式 + 已有旧会话应返回 NotLogin 包含 'NewDevice'，实际: {:?}",
                result
            );
        }

        // ==================================================================
        // OldDevice 模式踢出旧会话
        // ==================================================================

        /// OldDevice 模式 + is_concurrent=false → 踢出旧会话后创建新会话。
        ///
        /// 覆盖 lines 496-499：`OldDevice` 分支调用 kickout。
        #[tokio::test]
        async fn login_old_device_mode_kickouts_old_session() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_concurrent = false;
            Arc::make_mut(&mut logic.config).replaced_login_exit_mode =
                ReplacedLoginExitMode::OldDevice;

            let t1 = logic
                .login("old-device-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("old-device-001", &LoginParams::default())
                .await
                .unwrap();
            // 旧 token 应被踢出
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_none(),
                "OldDevice 模式下旧 token 应被踢出"
            );
            // 新 token 应有效
            assert!(
                logic
                    .session
                    .get_token_session(&t2)
                    .await
                    .unwrap()
                    .is_some(),
                "新 token 应有效"
            );
            assert_ne!(t1, t2, "新旧 token 应不同");
        }

        // ==================================================================
        // enforce_max_login_count：tokens <= max 不操作
        // ==================================================================

        /// tokens 数量 <= max 时不踢出任何会话。
        ///
        /// 覆盖 lines 651-654：`tokens.len() <= max → return Ok(())`。
        #[tokio::test]
        async fn enforce_max_login_count_within_limit_no_op() {
            let logic = make_logic(false);
            let t1 = logic
                .login("max-nop-001", &LoginParams::default())
                .await
                .unwrap();
            let _t2 = logic
                .login("max-nop-001", &LoginParams::default())
                .await
                .unwrap();

            // max=5，tokens=2，不踢出
            logic
                .enforce_max_login_count("max-nop-001", 5)
                .await
                .unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_some(),
                "tokens <= max 时 t1 应仍存在"
            );
        }

        // ==================================================================
        // get_login_id + current_token 但无 session
        // ==================================================================

        /// get_login_id + current_token 存在但 session 不存在 → Ok(None)。
        ///
        /// 覆盖 lines 407-413：`current_token → get_token_session → None → Ok(None)` 路径。
        #[tokio::test]
        async fn get_login_id_token_without_session_returns_none() {
            let logic = make_logic(false);
            let result = with_current_token("nonexistent-token".to_string(), async {
                logic.get_login_id().await
            })
            .await;
            assert!(
                result.is_ok(),
                "token 无对应 session 时应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                result.unwrap().is_none(),
                "token 无对应 session 时应返回 None"
            );
        }
    }
}
