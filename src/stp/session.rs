//! SessionLogic trait — 会话生命周期管理契约（登录/登出/踢出/校验）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
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
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkEvent;
use crate::stp::core::BulwarkCore;
use crate::stp::token::TokenLogic;
use crate::strategy::FirewallLoginContext;
use async_trait::async_trait;

/// 会话逻辑 trait，定义登录/登出/踢出/校验完整契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 的会话生命周期部分。
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

#[async_trait]
impl SessionLogic for BulwarkLogicDefault {
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
        self.session.create(login_id, token).await
    }

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
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id) {
                    lm.broadcast(&BulwarkEvent::Logout {
                        login_id: id,
                        token: token.clone(),
                    })
                    .await;
                }
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: &str) -> BulwarkResult<()> {
        self.session.logout_by_login_id(login_id).await
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
            })
            .await;
        }
        Ok(())
    }

    async fn check_login(&self) -> BulwarkResult<bool> {
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => {
                // 未设置 token = 未登录（保持现有 throw_on_not_login 语义）
                if self.config.throw_on_not_login {
                    return Err(BulwarkError::Session("未登录".to_string()));
                }
                return Ok(false);
            },
        };

        match self.jwt_mode {
            JwtMode::Stateless => self.check_login_stateless(&token),
            JwtMode::Mixin => self.check_login_mixin(&token).await,
            JwtMode::Simple => self.check_login_simple(&token).await,
        }
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
            })
            .await;
        }
        Ok(())
    }

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
        let ctx = FirewallLoginContext::new(login_id);
        self.firewall.check_login_hooks(login_id, &ctx).await?;

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

        // is_concurrent=false: 登录前踢出所有现有会话（fail-closed，kickout 失败则不创建新会话）
        // 注：is_share=true 时 is_concurrent 必为 true（T006 validate 保证），两分支互斥
        if !self.config.is_concurrent {
            self.kickout(login_id).await?;
        }

        // T020: 自动生成设备指纹。
        // `LoginParams.device` 为 None 但 `user_agent` + `ip` 有值时，
        // 调用 `device_fingerprint` 生成 SHA-256(UA+IP) 前 16 字节 hex 指纹写入 device。
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
                feature = "secure-httpdigest"
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
                params.device = Some(crate::session::device::device_fingerprint(ua, ip));
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
            })
            .await;
        }
        // max_login_count > 0 时，强制最大登录数量（踢出最旧会话）
        if self.config.max_login_count > 0 {
            self.enforce_max_login_count(login_id, self.config.max_login_count)
                .await?;
        }
        Ok(token)
    }

    /// 强制最大登录数量：踢出最旧的会话直到数量 <= max。
    ///
    /// 按 `last_active_at` 升序排序（最旧排前面），踢出最早的 (count - max) 个 token。
    /// `max=0` 时不做任何操作（0 表示不限制，由调用方判断）。
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

        // 踢出最旧的 (count - max) 个
        let to_evict = token_times.len().saturating_sub(max as usize);
        for (token, _) in token_times.iter().take(to_evict) {
            self.session.logout(token).await?;
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
                    let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
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
            let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
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
                let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
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
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return Err(BulwarkError::Session("未登录".to_string()));
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
            if !self
                .session
                .check_hover_timeout(&ts.login_id, self.config.session_hover_timeout)
            {
                if let Err(e) = self.session.logout(token).await {
                    tracing::warn!(error = %e, "悬停超时 logout 失败");
                }
                #[cfg(feature = "listener")]
                if let Some(lm) = &self.listener_manager {
                    lm.broadcast(&BulwarkEvent::SessionTimeout {
                        login_id: ts.login_id.clone(),
                        token: token.to_string(),
                    })
                    .await;
                }
                if self.config.throw_on_not_login {
                    return Err(BulwarkError::Session("会话悬停超时".to_string()));
                }
                return Ok(false);
            }
            self.session.update_last_active(&ts.login_id);
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
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return Err(BulwarkError::Session("未登录".to_string()));
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
// BulwarkLogicDefault 私有方法：Token 自动续签
// ============================================================================

impl BulwarkLogicDefault {
    /// 检查并续签 Token（若剩余 TTL 低于阈值）。
    ///
    /// 在 `check_login` 路径中调用：当 `auto_renewal_threshold > 0` 时，
    /// 检查 Token 剩余 TTL 百分比，低于阈值则触发续签。
    /// 续签成功后通过 `CURRENT_RENEWED_TOKEN` task_local 传递新 Token。
    ///
    /// # 参数
    /// - `token`: 待检查的 Token 字符串。
    ///
    /// # 返回
    /// - `Ok(None)`: 未启用续签 / TTL 充足 / 永久键。
    /// - `Ok(Some(new_token))`: 续签成功，返回新 Token。
    /// - `Err(...)`: 续签失败（如 auth_logic 未配置 / renew 调用失败）。
    pub(crate) async fn check_and_renew(&self, token: &str) -> BulwarkResult<Option<String>> {
        let threshold = self.config.auto_renewal_threshold;
        if threshold <= 0 {
            return Ok(None);
        }
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
}
