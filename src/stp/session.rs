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
use crate::strategy::FirewallLoginContext;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

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
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id.as_ref()) {
                    lm.broadcast(&BulwarkEvent::Logout {
                        login_id: id.clone(),
                        token: token.clone(),
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

        // is_concurrent=false: 根据 replaced_login_exit_mode 决定行为
        // - OldDevice：踢出旧设备的所有会话（默认，对应 Sa-Token 语义）
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
                params.device = Some(crate::session::device::device_fingerprint(ua, ip));
            }
        }

        // T013: 设备绑定策略检测（device-binding feature）。
        // 创建 session 前调用 `DeviceBindingPolicy::is_new_device`，若为新设备
        // 且 `require_secondary_auth` 返回 true，设置 `params.require_mfa = true`。
        // 未注入 policy 时跳过（向后兼容）；检测失败只 warn 不中断 login。
        #[cfg(feature = "device-binding")]
        if let Some(policy) = &self.device_binding_policy {
            let device_id = params.device.as_deref().unwrap_or("");
            if !device_id.is_empty() {
                match policy.is_new_device(login_id, device_id).await {
                    Ok(true) => match policy.require_secondary_auth(login_id, device_id).await {
                        Ok(true) => {
                            tracing::info!(login_id, device_id, "设备绑定策略触发二级认证要求");
                            params.require_mfa = true;
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
            })
            .await;
        }
        // max_login_count > 0 时，强制最大登录数量（踢出最旧会话）
        // HIGH-002 修复：enforce 失败时回滚（登出新创建的 token），避免孤儿会话泄漏
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
                        })
                        .await;
                    },
                    OverflowLogoutMode::Kickout => {
                        lm.broadcast(&BulwarkEvent::Kickout {
                            login_id: login_id.to_string(),
                            token: token.clone(),
                            reason: "超过最大登录数限制".to_string(),
                        })
                        .await;
                    },
                    OverflowLogoutMode::Replaced => {
                        lm.broadcast(&BulwarkEvent::Replaced {
                            login_id: login_id.to_string(),
                            token: token.clone(),
                            reason: "超过最大登录数限制，被新会话顶替".to_string(),
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
    /// # HIGH-001 修复：并发续签竞态防护
    ///
    /// 两个并发 `check_login` 可能同时通过 TTL 检查并各自触发续签。
    /// Call A 续签成功（旧 token 删除），Call B 的续签失败（token 已不存在），
    /// 错误被 `tracing::warn!` 吞掉，Call B 返回 `Ok(true)` 但旧 token 已失效 → "会话假活"。
    ///
    /// 修复：在续签前获取 per-login_id 锁，进入锁后**二次检查** TTL。
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

        // HIGH-001 修复：获取 login_id 用于 per-login_id 续签锁
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
                    None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
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
                    None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
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
        // 6 个集成测试
        // --------------------------------------------------------------------

        /// strict 模式下新设备 login 触发 MFA 标记（policy.is_new_device=true +
        /// require_secondary_auth=true → params.require_mfa=true），login 仍成功。
        #[tokio::test]
        async fn test_strict_mode_new_device_triggers_mfa() {
            let logic = make_logic_base();
            // 注入 StrictBinding（共享 logic.session，检测历史 session）
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            // 无历史 session → is_new_device=true → require_secondary_auth=true
            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("strict 模式新设备 login 应成功（设置 require_mfa 标记但不阻断）");

            assert!(!token.is_empty(), "login 应返回非空 token");
            // 验证 session 已创建
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
            assert_eq!(ts.device.as_deref(), Some("web-chrome"));
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
                    None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
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
                    None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
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
}
