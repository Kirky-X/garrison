// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `AuthLogicDefault` 的具体实现（builder 方法 + `AuthLogic` trait 实现 + 回滚辅助）；
//! `mod.rs` 仅保留 trait 定义与 struct 声明。

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;

use crate::core::token::Token;
use crate::error::{GarrisonError, GarrisonResult};
use crate::session::{GarrisonSession, TokenSession};

use super::*;

/// 默认 token 有效期（秒）。构造器收到非正数 timeout 时的回退值。
const DEFAULT_TOKEN_TIMEOUT_SECS: i64 = 3_600;

/// remember_me 默认扩展超时（秒，90 天）。`with_remember_me` 收到非正数 timeout 时的回退值。
const DEFAULT_REMEMBER_ME_TIMEOUT_SECS: i64 = 7_776_000;

impl AuthLogicDefault {
    /// 创建新的 `AuthLogicDefault` 实例：remember_me 默认禁用（经 `with_remember_me` 启用），
    /// `switch_to_guard` 默认 `DenyAllSwitchToGuard`（调用方必须注入自定义 guard 才能启用
    /// `switch_to`）；`timeout` 非正数时回退 3600 秒并 warn（负值经 `as u64` 会回绕成事实上的永久会话）。
    pub fn new(session: Arc<GarrisonSession>, token_handler: Arc<dyn Token>, timeout: i64) -> Self {
        let timeout = if timeout > 0 {
            timeout
        } else {
            tracing::warn!(
                timeout,
                "core-auth: non-positive timeout rejected, falling back to \
                 default 3600s (issue 2408/2664: negative i64 would wrap via `as u64`)"
            );
            DEFAULT_TOKEN_TIMEOUT_SECS
        };
        Self {
            session,
            token_handler,
            timeout,
            remember_me_enabled: false,
            remember_me_timeout: DEFAULT_REMEMBER_ME_TIMEOUT_SECS,
            seed_primary_amr: true,
            switch_to_guard: Arc::new(DenyAllSwitchToGuard),
            renew_locks: Arc::new(DashMap::new()),
        }
    }

    /// 配置 remember_me 扩展超时：启用后 login 的 params 含 `remember_me=true` 时用
    /// `remember_me_timeout` 作 TTL，否则用默认 `timeout`；非正数回退 7776000 秒（90 天）并 warn。
    pub fn with_remember_me(mut self, enabled: bool, timeout: i64) -> Self {
        self.remember_me_enabled = enabled;
        self.remember_me_timeout = if timeout > 0 {
            timeout
        } else {
            tracing::warn!(
                timeout,
                "core-auth: non-positive remember_me_timeout rejected, falling back to \
                 default 7776000s (issue 2664)"
            );
            DEFAULT_REMEMBER_ME_TIMEOUT_SECS
        };
        self
    }

    /// 配置登录时是否播种主认证因子（amr=["pwd"] / aal:1 / auth_time），默认 `true`。
    ///
    /// 凭证委托 / 零凭证 login 未发生密码校验的部署应显式关闭：关闭后签发的 token 不携带
    /// `amr` / `auth_time` claim、会话账本为空，下游 step-up 判定（`assert_freshness` /
    /// `ledger_max_aal`）不再被未经发生的 `pwd` 断言误导；step-up 追加
    /// （`append_amr_entry`）不受影响。与 `config.seed_primary_amr` 同语义：管理器装配经
    /// `GarrisonManagerBuilder` 桥接配置，本 builder 供直连构造时覆盖默认值。
    pub fn with_seed_primary_amr(mut self, enabled: bool) -> Self {
        self.seed_primary_amr = enabled;
        self
    }

    /// 注入身份切换权限校验 guard；默认 `DenyAllSwitchToGuard` 拒绝所有切换，
    /// 必须注入自定义 guard 才能启用 `switch_to`。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use garrison::core::auth::{AuthLogicDefault, SwitchToGuard};
    /// use garrison::error::{GarrisonError, GarrisonResult};
    ///
    /// struct AdminOnlyGuard;
    /// #[async_trait::async_trait]
    /// impl SwitchToGuard for AdminOnlyGuard {
    /// async fn check(&self, original: &str, target: &str) -> GarrisonResult<()> {
    /// if original.starts_with("admin:") {
    /// Ok(())
    /// } else {
    /// Err(GarrisonError::NotPermission(format!("{} 无权切换", original)))
    /// }
    /// }
    /// }
    ///
    /// let auth = AuthLogicDefault::new(session, token_handler, 3600)
    /// .with_switch_to_guard(Arc::new(AdminOnlyGuard));
    /// ```
    pub fn with_switch_to_guard(mut self, guard: Arc<dyn SwitchToGuard>) -> Self {
        self.switch_to_guard = guard;
        self
    }
}

/// 解析 params 中的 remember_me：params 为 URL query string（`key=value&key2=value2`），
/// 仅 `remember_me=true` 返回 `true`，其他值或格式错误静默返回 `false`（容错）。
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
    async fn login(&self, id: &str, params: Option<&str>) -> GarrisonResult<String> {
        let remember_me = parse_remember_me_param(params);
        let effective_timeout = if remember_me && self.remember_me_enabled {
            self.remember_me_timeout
        } else {
            self.timeout
        };
        // 签发 claim 与会话账本播种统一口径：seed_primary_amr=false 时零断言签发（不携带 amr/auth_time）。
        let now = Utc::now().timestamp();
        let (amr, auth_time) = if self.seed_primary_amr {
            crate::stp::mfa::primary_issuance_claims(now)
        } else {
            (Vec::new(), None)
        };
        let token = self
            .token_handler
            .generate_with_amr(id, effective_timeout, &amr, auth_time)?;
        // 会话账本播种随同一开关，与签发 claim 的零断言语义一致。
        self.session
            .create_with_seed_primary_amr(id, &token, self.seed_primary_amr)
            .await?;
        if effective_timeout != self.timeout {
            // 构造器已保证正数，此处 try_from 防御性校验：负值绝不允许经 `as u64` 回绕为巨大 TTL。
            let ttl_secs = match u64::try_from(effective_timeout) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        effective_timeout,
                        "core-auth-login: non-positive effective_timeout, \
                         falling back to default 3600s TTL (issue 2408)"
                    );
                    DEFAULT_TOKEN_TIMEOUT_SECS as u64
                },
            };
            self.session.set_token_session_ttl(&token, ttl_secs).await?;
        }
        Ok(token)
    }

    async fn logout(&self, token: &str) -> GarrisonResult<()> {
        // 幂等：session.logout 内部对不存在的 token 返回 Ok(())，直接委托。
        self.session.logout(token).await
    }

    async fn is_login(&self, token: &str) -> GarrisonResult<bool> {
        self.session.is_valid(token).await
    }

    async fn get_login_id(&self, token: &str) -> GarrisonResult<Option<String>> {
        match self.session.get_token_session(token).await? {
            Some(ts) => Ok(Some(ts.login_id)),
            None => Ok(None),
        }
    }

    async fn verify_token(&self, token: &str) -> GarrisonResult<String> {
        match self.get_login_id(token).await? {
            Some(id) => Ok(id),
            None => Err(GarrisonError::InvalidToken(
                "core-auth-token-invalid-or-expired".to_string(),
            )),
        }
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()> {
        if target_login_id.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "core-auth-target-login-id-empty".to_string(),
            ));
        }

        let mut ts = self
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| {
                GarrisonError::NotLogin("core-auth-token-invalid-or-expired".to_string())
            })?;

        // 目标存在性校验（纵深防御，置于 guard 前：target 不存在时 guard 行为未定义，且
        // ensure_* 已 fail-closed）；与权限拒绝统一返回模糊错误 NotPermission("core-auth-switch-to-denied")，
        // 使「target 不存在」与「无权切换」在外部不可区分，防 login_id 枚举。
        if self
            .session
            .get_account_session(target_login_id)
            .await?
            .is_none()
        {
            return Err(GarrisonError::NotPermission(
                "core-auth-switch-to-denied".to_string(),
            ));
        }

        // 修改 session 前执行 guard（默认 DenyAllSwitchToGuard fail-closed），无权限时零副作用。
        let original_login_id = ts.login_id.clone();
        self.switch_to_guard
            .check(&original_login_id, target_login_id)
            .await?;

        // 迁移前快照，供两阶段 Account-Session 失败路径回滚。
        let ts_original = ts.clone();

        ts.attrs
            .insert("switched_from".to_string(), original_login_id.clone());

        ts.login_id = target_login_id.to_string();
        ts.last_active_at = Utc::now().timestamp();
        // 切换后认证事实归零（fail-closed）：原主体的 step-up 成果不得让目标身份免认证通过
        // MFA gate，置空后 freshness 判 Stale，目标身份须重新完成自己的 step-up。
        ts.amr_ledger.clear();
        ts.auth_time = None;

        self.session.save_token_session(token, &ts).await?;

        // 顺序：先 remove original 再 ensure target——否则 list_devices(original) 会误返回已切换
        // token，logout_by_login_id(original) 会越权踢出已切到 target 的 token，
        // enforce_max_login_count(original) 会误算。
        //
        // 孤儿防护：save_token_session 后任一 Account-Session 操作失败须 best-effort 回滚到迁移前
        // 快照（ensure 失败时还需把 token 挂回 original）；回滚成功透传原错误，回滚也失败则升级为
        // Internal 聚合错误（禁止静默残留）。remove/ensure 内部经 `with_login_lock` 串行化，避免与
        // login/logout 竞态。
        if let Err(remove_err) = self
            .session
            .remove_token_from_account_session(&original_login_id, token)
            .await
        {
            // 回滚：恢复原始 TokenSession，与「token 仍在 original Account-Session」重新一致。
            if let Err(rb_err) = self.session.save_token_session(token, &ts_original).await {
                let token_prefix = &token[..token.len().min(8)];
                tracing::error!(
                    error = %remove_err,
                    rollback_error = %rb_err,
                    token_prefix = %token_prefix,
                    "switch_to: remove from original Account-Session failed and rollback failed; \
                     token session may be inconsistent (issue 6429)"
                );
                return Err(GarrisonError::Internal(
                    "core-auth-switch-to-inconsistent".to_string(),
                ));
            }
            return Err(remove_err);
        }

        // 确保 token 在目标 Account-Session 中，否则 is_valid 会因 Account-Session 不存在返回 false。
        if let Err(ensure_err) = self
            .session
            .ensure_token_in_account_session(target_login_id, token)
            .await
        {
            // 回滚：token 已从 original 移除，先挂回 original，再恢复原始 TokenSession。
            let reattach_ok = self
                .session
                .ensure_token_in_account_session(&original_login_id, token)
                .await;
            let restore_ok = self.session.save_token_session(token, &ts_original).await;
            if let (Err(rb1), Err(rb2)) = (&reattach_ok, &restore_ok) {
                let token_prefix = &token[..token.len().min(8)];
                tracing::error!(
                    error = %ensure_err,
                    rollback_error_1 = %rb1,
                    rollback_error_2 = %rb2,
                    token_prefix = %token_prefix,
                    "switch_to: ensure target Account-Session failed and rollback failed; \
                     token orphaned from both Account-Sessions (issue 6641/6642)"
                );
                return Err(GarrisonError::Internal(
                    "core-auth-switch-to-inconsistent".to_string(),
                ));
            }
            // 回滚成功或部分成功：透传原始错误并显性化单边失败，避免静默孤儿。
            if reattach_ok.is_err() || restore_ok.is_err() {
                let token_prefix = &token[..token.len().min(8)];
                tracing::error!(
                    error = %ensure_err,
                    reattach_ok = reattach_ok.is_ok(),
                    restore_ok = restore_ok.is_ok(),
                    token_prefix = %token_prefix,
                    "switch_to: rollback partially failed, token state may need operator cleanup \
                     (issue 6641/6642)"
                );
            }
            return Err(ensure_err);
        }

        // 日志脱敏：仅记录前 8 字符。
        let token_prefix = if token.len() >= 8 { &token[..8] } else { token };
        tracing::info!(
            original_login_id = %original_login_id,
            target_login_id = %target_login_id,
            token_prefix = %token_prefix,
            "identity switch: {} -> {}",
            original_login_id,
            target_login_id
        );

        Ok(())
    }

    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
        // per-token 串行化整个 renew 流程（修复 CWE-362 TOCTOU）：并发 renew 同一 token 时只有
        // 第 1 个成功，其余等锁后读到已失效旧 session → NotLogin，即"恰好 1 个成功"。锁为
        // `tokio::sync::Mutex`（可跨 `.await` 持有），粒度 per-token（不同 token 仍可并行）。
        //
        // 清理：renew 结束（无论成功/失败）且锁释放后 `remove_if` 检查 `Arc::strong_count == 1`
        // 则移除 entry，防随机 token 灌满 DashMap 导致 OOM（CWE-770）；用 inner async block 包裹
        // 流程，使所有 `?` 提前返回路径统一经过外层清理。
        let renew_lock = self
            .renew_locks
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _renew_guard = renew_lock.lock().await;

        // inner async block：所有 `?` 提前返回路径统一收敛到外层 drop + remove_if 清理
        //（否则失败 renew 残留 entry 累积，CWE-770 OOM）；代价仅多一层编译期状态机包装。
        let result: GarrisonResult<String> = async {
            // 顺序：先创建新 session 再失效旧 token——delete-first 在旧 token 失效与新 token 创建
            // 之间产生 DoS gap（用户无任何有效 token，创建失败即失会话，CWE-362 / CVSS 7.5），
            // 代价是毫秒级双 token 窗口，可用性优先。步骤：1 读旧 session + 剩余 TTL（None = 永久键）；
            // 2 生成同 style/login_id 的新 token（账本延续）；3 保存新 session（失败则旧 token 仍有效，
            // 无需回滚）；4 挂到 Account-Session（失败则清理新 token session）；5 失效旧 token
            //（失败记录 error 但返回 Ok(new_token)，旧 token 残留由运维按 error_code 清理）。

            // 读旧 TokenSession + 剩余 TTL（单次 DAO 调用；None 表永久键，用 0 表示永久驻留）。
            let (old_ts, remaining_ttl) = self
                .session
                .get_token_session_with_ttl(token)
                .await?
                .ok_or_else(|| {
                    GarrisonError::NotLogin("core-auth-token-invalid-or-expired".to_string())
                })?;
            let ttl_secs = remaining_ttl.map(|d| d.as_secs()).unwrap_or(0);

            // 新 token 与旧同 style/login_id，amr/auth_time 从旧账本映射（同一认证延续）。
            let new_token = self.token_handler.generate_with_amr(
                &old_ts.login_id,
                self.timeout,
                &crate::stp::mfa::amr_claim(&old_ts.amr_ledger),
                old_ts.auth_time,
            )?;

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
                #[cfg(feature = "session-extra")]
                dynamic_active_timeout: old_ts.dynamic_active_timeout,
                // 匿名 session 存于 token:session:anon:{token}，入口即返回 NotLogin，该路径不可达。
                #[cfg(feature = "session-extra")]
                is_anon: false,
                // 承接旧会话的 TTL 权威来源。
                effective_timeout: old_ts.effective_timeout,
                // 承接旧账本与 auth_time（同一认证延续，非重新认证）。
                amr_ledger: old_ts.amr_ledger.clone(),
                auth_time: old_ts.auth_time,
            };

            // 保存新 session（剩余 TTL）；失败时旧 token 未触碰、仍有效，无 DoS。
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
                    "renew_to_equivalent: failed to create new token session, old token still valid (A9 no DoS)"
                );
                return Err(GarrisonError::Internal(
                    "core-auth-token-renew-create-failed".to_string(),
                ));
            }

            // 挂到 Account-Session；失败则清理新 token session，旧 token 仍有效，无 DoS。
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
                    "renew_to_equivalent: failed to add new token to Account-Session, cleaning up new token"
                );
                // best-effort 清理新 token session。
                if let Err(rb_err) = self.session.logout(&new_token).await {
                    tracing::error!(
                        rollback_error = %rb_err,
                        new_token_prefix = %new_prefix,
                        "renew_to_equivalent: failed to clean up new token session, new token may be orphaned"
                    );
                }
                // 失败显性化；旧 token 仍有效，用户可重试。
                return Err(GarrisonError::Internal(
                    "core-auth-token-renew-add-to-account-failed".to_string(),
                ));
            }

            // 失效旧 token；失败也不返回 Err（用户已持新 token，返回 Err 反而制造 DoS），仅用
            // error 级别记录稳定 error_code="renew_old_token_cleanup_failed"。这是已知并接受的
            // CWE-613 双 token 窗口：监控按该 code >0 次触发 P2 告警、运维 5 分钟内清理残留旧 token（CWE-613 缓解）；
            // 未注入 `AlertListenerManager` 时日志告警兜底，注入的部署由调用方在 renew 失败回调中
            // 转发 `broadcast_alert`。
            if let Err(e) = self.session.logout(token).await {
                let old_prefix = if token.len() >= 8 { &token[..8] } else { token };
                tracing::error!(
                    error_code = "renew_old_token_cleanup_failed",
                    error = %e,
                    old_token_prefix = %old_prefix,
                    new_token_prefix = %&new_token[..new_token.len().min(8)],
                    "renew_to_equivalent: failed to invalidate old token, old token left behind (CWE-613 security risk), \
                     new token established with no DoS, but operators must clean up the old token immediately to prevent attacker reuse. \
                     Alert rule: trigger P2 alert whenever error_code=\"renew_old_token_cleanup_failed\" appears"
                );
            }

            Ok(new_token)
        }
        .await;

        // 成功 / 失败清理 entry：先 drop guard 释放 Mutex、再 drop Arc，最后 `remove_if` 在
        // shard 锁内原子检查 `Arc::strong_count == 1`（仅 DashMap 持有即无等待者，安全移除；
        // >1 保留，等待者继续用；移除后新调用方 `or_insert_with` 重建，串行化语义不变）。
        drop(_renew_guard);
        drop(renew_lock);
        self.renew_locks
            .remove_if(token, |_, lock| Arc::strong_count(lock) == 1);

        result
    }
}
