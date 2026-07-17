//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `AuthLogicDefault` 的具体实现（builder 方法 + `AuthLogic` trait 实现 + 回滚辅助）。
//!
//! 依据 rule 25（mod 接口隔离），从 `mod.rs` 拆分而来；`mod.rs` 仅保留 trait 定义
//! 与 struct 声明，具体实现函数集中在本文件。

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;

use crate::core::token::Token;
use crate::error::{BulwarkError, BulwarkResult};
use crate::session::{BulwarkSession, TokenSession};

use super::*;

impl AuthLogicDefault {
    /// 创建新的 `AuthLogicDefault` 实例。
    ///
    /// remember_me 默认禁用。使用 `with_remember_me` 启用扩展超时。
    ///
    /// # 安全默认（L4 修复）
    ///
    /// `switch_to_guard` 默认为 `DenyAllSwitchToGuard`（拒绝所有切换）。
    /// 调用方必须通过 [`with_switch_to_guard`](Self::with_switch_to_guard)
    /// 注入自定义 guard 才能启用 `switch_to` 功能。
    ///
    /// # 参数
    /// - `session`: 会话管理器。
    /// - `token_handler`: Token 生成与校验处理器。
    /// - `timeout`: 默认 token 有效期（秒）。
    pub fn new(session: Arc<BulwarkSession>, token_handler: Arc<dyn Token>, timeout: i64) -> Self {
        Self {
            session,
            token_handler,
            timeout,
            remember_me_enabled: false,
            remember_me_timeout: 7_776_000,
            switch_to_guard: Arc::new(DenyAllSwitchToGuard),
        }
    }

    /// 配置 remember_me 扩展超时。
    ///
    /// 启用后，`login` 时 params 含 `remember_me=true` 将使用 `remember_me_timeout` 作为
    /// Token-Session 的 TTL，否则使用默认 `timeout`。
    ///
    /// # 参数
    /// - `enabled`: 是否启用 remember_me。
    /// - `timeout`: remember_me 扩展超时秒数（应大于 `timeout`）。
    pub fn with_remember_me(mut self, enabled: bool, timeout: i64) -> Self {
        self.remember_me_enabled = enabled;
        self.remember_me_timeout = timeout;
        self
    }

    /// 注入身份切换权限校验 guard（L4 修复，依据安全审计 L4）。
    ///
    /// 默认为 `DenyAllSwitchToGuard`（拒绝所有切换）。调用方必须注入自定义 guard
    /// 才能启用 `switch_to` 功能。
    ///
    /// # 参数
    /// - `guard`: 实现 [`SwitchToGuard`] trait 的权限校验实例。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use bulwark::core::auth::{AuthLogicDefault, SwitchToGuard};
    /// use bulwark::error::{BulwarkError, BulwarkResult};
    ///
    /// struct AdminOnlyGuard;
    /// #[async_trait::async_trait]
    /// impl SwitchToGuard for AdminOnlyGuard {
    ///     async fn check(&self, original: &str, target: &str) -> BulwarkResult<()> {
    ///         if original.starts_with("admin:") {
    ///             Ok(())
    ///         } else {
    ///             Err(BulwarkError::NotPermission(format!("{} 无权切换", original)))
    ///         }
    ///     }
    /// }
    ///
    /// let auth = AuthLogicDefault::new(session, token_handler, 3600)
    ///     .with_switch_to_guard(Arc::new(AdminOnlyGuard));
    /// ```
    pub fn with_switch_to_guard(mut self, guard: Arc<dyn SwitchToGuard>) -> Self {
        self.switch_to_guard = guard;
        self
    }
}

/// 解析 params 中的 remember_me 参数。
///
/// params 格式为 URL query string（`key=value&key2=value2`）。
/// 仅当存在 `remember_me=true` 时返回 `true`，其他值或格式错误时静默返回 `false`（容错）。
pub fn parse_remember_me_param(params: Option<&str>) -> bool {
    match params {
        Some(p) if !p.is_empty() => {
            for pair in p.split('&') {
                let mut kv = pair.splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    if k.trim() == "remember_me" && v.trim() == "true" {
                        return true;
                    }
                }
            }
            false
        },
        _ => false,
    }
}

#[async_trait]
impl AuthLogic for AuthLogicDefault {
    async fn login(&self, id: &str, params: Option<&str>) -> BulwarkResult<String> {
        // R-session-lifecycle-005: 解析 remember_me 参数
        let remember_me = parse_remember_me_param(params);
        let effective_timeout = if remember_me && self.remember_me_enabled {
            self.remember_me_timeout
        } else {
            self.timeout
        };
        let token = self.token_handler.generate(id, effective_timeout)?;
        self.session.create(id, &token).await?;
        // R-session-lifecycle-005: remember_me 扩展 Token-Session TTL
        if effective_timeout != self.timeout {
            self.session
                .set_token_session_ttl(&token, effective_timeout as u64)
                .await?;
        }
        Ok(token)
    }

    async fn logout(&self, token: &str) -> BulwarkResult<()> {
        // 幂等处理：logout 不存在的 token 返回 Ok(())
        // session.logout 内部对不存在的 token 返回 Ok(())，直接委托
        self.session.logout(token).await
    }

    async fn is_login(&self, token: &str) -> BulwarkResult<bool> {
        self.session.is_valid(token).await
    }

    async fn get_login_id(&self, token: &str) -> BulwarkResult<Option<String>> {
        match self.session.get_token_session(token).await? {
            Some(ts) => Ok(Some(ts.login_id)),
            None => Ok(None),
        }
    }

    async fn verify_token(&self, token: &str) -> BulwarkResult<String> {
        match self.get_login_id(token).await? {
            Some(id) => Ok(id),
            None => Err(BulwarkError::InvalidToken("token 无效或已过期".to_string())),
        }
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> BulwarkResult<()> {
        // 验证 target_login_id 非空
        if target_login_id.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "target_login_id 不能为空".to_string(),
            ));
        }

        // 获取当前 TokenSession
        let mut ts = self
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::NotLogin("token 无效或已过期".to_string()))?;

        // A6: 校验目标 Account-Session 存在（纵深防御层）。
        // 在 guard 检查前校验，原因有二：
        // 1. 防止 switch_to 切到不存在的 login_id（ensure_token_in_account_session 已 fail-closed，
        //    此层提前拒绝，避免执行到后续步骤）
        // 2. guard 可能依赖 target 的属性，target 不存在时 guard 行为未定义
        // 安全权衡：此校验会泄露 login_id 存在性，但 switch_to 本身是高危操作，
        // 调用方通常已通过 login 流程知道 target 存在，泄露风险可接受。
        if self
            .session
            .get_account_session(target_login_id)
            .await?
            .is_none()
        {
            return Err(BulwarkError::InvalidParam(format!(
                "target login_id 不存在: {}",
                target_login_id
            )));
        }

        // 执行权限校验（guard 默认 DenyAllSwitchToGuard，fail-closed）
        // 在修改 session 前校验，确保无权限时不产生任何副作用
        let original_login_id = ts.login_id.clone();
        self.switch_to_guard
            .check(&original_login_id, target_login_id)
            .await?;

        // 存储原始 login_id 到 attrs["switched_from"]
        ts.attrs
            .insert("switched_from".to_string(), original_login_id.clone());

        // 更新 login_id 为 target_login_id
        ts.login_id = target_login_id.to_string();
        ts.last_active_at = Utc::now().timestamp();

        // 保存更新后的 session 到 DAO（保留原 TTL）
        self.session.save_token_session(token, &ts).await?;

        // 确保 token 存在于目标 login_id 的 Account-Session 中
        //（否则 is_valid 检查会因 Account-Session 不存在而返回 false）
        self.session
            .ensure_token_in_account_session(target_login_id, token)
            .await?;

        // 审计日志
        // token 脱敏：仅记录前 8 字符
        let token_prefix = if token.len() >= 8 { &token[..8] } else { token };
        tracing::info!(
            original_login_id = %original_login_id,
            target_login_id = %target_login_id,
            token_prefix = %token_prefix,
            "身份切换: {} -> {}",
            original_login_id,
            target_login_id
        );

        Ok(())
    }

    async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
        // A9: 调整顺序为"先创建新 token session，再失效旧 token"，消除续期窗口漏洞
        // （vuln-0003 / CWE-362 / CVSS 7.5）。
        //
        // 原实现"先失效旧 token，再创建新 token"在步骤 2（logout old）与步骤 5
        // （create new）之间存在 DoS gap window：用户在此窗口内无任何有效 token，
        // 若新 token 创建失败且回滚也失败，用户将彻底失去会话。
        //
        // 新顺序的权衡（rule 7 暴露冲突）：
        // - 旧设计（VULN-0020）：delete first → 无双 token 窗口，但有 DoS gap（HIGH 风险）
        // - 新设计（A9 / vuln-0003 修复）：create first → 无 DoS gap，但有短暂双 token 窗口
        //
        // 决策依据：strix vuln-0003 明确指出 DoS gap 为 HIGH 风险（CVSS 7.5），
        // 而双 token 窗口仅持续毫秒级（create 与 delete 之间），且旧 token 在 delete
        // 成功后立即失效，攻击窗口极小。可用性 > 短暂安全窗口，故采用 create first。
        //
        // 新顺序：
        // 1. 获取旧 TokenSession + 剩余 TTL
        // 2. 生成新 token + 构建新 TokenSession
        // 3. 保存新 Token-Session with TTL
        //    若失败，旧 token 仍有效 → 直接返回错误（无需回滚）
        // 4. 添加新 token 到 Account-Session
        //    若失败，删除新 token session → 旧 token 仍有效 → 返回错误
        // 5. 失效旧 token（logout 同时删除 Token-Session 与 Account-Session 条目）
        //    若失败，记录 warn 但返回 Ok(new_token) — 用户已持有新 token，
        //    旧 token 残留属安全风险但非 DoS，需运维介入清理

        // 1. 获取旧 TokenSession + 剩余 TTL（性能优化：单次 DAO 调用）
        //    None 表示永久键（无 TTL），用 0 表示永久驻留
        let (old_ts, remaining_ttl) = self
            .session
            .get_token_session_with_ttl(token)
            .await?
            .ok_or_else(|| BulwarkError::NotLogin("token 无效或已过期".to_string()))?;
        let ttl_secs = remaining_ttl.map(|d| d.as_secs()).unwrap_or(0);

        // 2. 生成新 token（同 token_style + 同 login_id）
        let new_token = self
            .token_handler
            .generate(&old_ts.login_id, self.timeout)?;

        // 3. 构建新 TokenSession（复制 attrs + device + ip + user_agent + safe_services）
        let now = Utc::now().timestamp();
        let new_ts = TokenSession {
            token: new_token.clone(),
            login_id: old_ts.login_id.clone(),
            created_at: now,
            last_active_at: now,
            attrs: old_ts.attrs.clone(),
            device: old_ts.device.clone(),
            ip: old_ts.ip.clone(),
            user_agent: old_ts.user_agent.clone(),
            safe_services: old_ts.safe_services.clone(),
            #[cfg(feature = "dynamic-active-timeout")]
            dynamic_active_timeout: old_ts.dynamic_active_timeout,
            // 匿名 token 不可达此路径（get_token_session 读 token:session:{token}，
            // 匿名 session 在 token:session:anon:{token}，入口即返回 NotLogin）
            #[cfg(feature = "anonymous-session")]
            is_anon: false,
        };

        // 4. 保存新 Token-Session with remaining TTL
        //    若失败，旧 token 仍有效（未触碰），直接返回错误 — 无 DoS
        if let Err(e) = self
            .session
            .create_token_session_with_ttl(&new_token, &new_ts, ttl_secs)
            .await
        {
            let new_prefix = if new_token.len() >= 8 {
                &new_token[..8]
            } else {
                &new_token
            };
            tracing::error!(
                error = %e,
                new_token_prefix = %new_prefix,
                "renew_to_equivalent 创建新 token session 失败，旧 token 仍有效（A9 无 DoS）"
            );
            return Err(BulwarkError::Internal(
                "token 置换失败：创建新 token session 出错（old token 仍有效）".to_string(),
            ));
        }

        // 5. 添加新 token 到 Account-Session
        //    若失败，删除新 token session → 旧 token 仍有效 → 返回错误 — 无 DoS
        if let Err(e) = self
            .session
            .ensure_token_in_account_session(&old_ts.login_id, &new_token)
            .await
        {
            let new_prefix = if new_token.len() >= 8 {
                &new_token[..8]
            } else {
                &new_token
            };
            tracing::error!(
                error = %e,
                new_token_prefix = %new_prefix,
                "renew_to_equivalent 添加新 token 到 Account-Session 失败，清理新 token"
            );
            // 清理刚创建的新 token session（best-effort）
            if let Err(rb_err) = self.session.logout(&new_token).await {
                tracing::error!(
                    rollback_error = %rb_err,
                    new_token_prefix = %new_prefix,
                    "renew_to_equivalent 清理新 token session 失败，新 token 可能残留"
                );
            }
            // rule 12：失败显性化 — 旧 token 仍有效，用户可用旧 token 重试
            return Err(BulwarkError::Internal(
                "token 置换失败：添加新 token 到 Account-Session 出错（old token 仍有效）"
                    .to_string(),
            ));
        }

        // 6. 失效旧 token（logout 同时删除 Token-Session 与 Account-Session 条目）
        //    A9 关键变化：此步在"新 token 已完全建立"之后执行。
        //    若此步失败，用户已持有新 token（无 DoS），但旧 token 残留（安全风险）。
        //    决策：返回 Ok(new_token) 让用户继续操作，旧 token 残留由运维介入清理。
        //    理由：若因 delete 失败而返回 Err，用户将丢失新 token（已建立），
        //    反而制造新的 DoS — 与 A9 修复目标相悖。
        if let Err(e) = self.session.logout(token).await {
            let old_prefix = if token.len() >= 8 { &token[..8] } else { token };
            tracing::warn!(
                error = %e,
                old_token_prefix = %old_prefix,
                new_token_prefix = %&new_token[..new_token.len().min(8)],
                "renew_to_equivalent 失效旧 token 失败，旧 token 可能残留（安全风险），\
                 但新 token 已建立，用户可用新 token 继续 — 需运维清理旧 token"
            );
        }

        Ok(new_token)
    }
}
