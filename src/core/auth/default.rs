//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! `AuthLogicDefault` 的具体实现（builder 方法 + `AuthLogic` trait 实现 + 回滚辅助）。
//!
//! `mod.rs` 仅保留 trait 定义
//! 与 struct 声明，具体实现函数集中在本文件。

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
    /// 创建新的 `AuthLogicDefault` 实例。
    ///
    /// remember_me 默认禁用。使用 `with_remember_me` 启用扩展超时。
    ///
    /// # 安全默认
    ///
    /// `switch_to_guard` 默认为 `DenyAllSwitchToGuard`（拒绝所有切换）。
    /// 调用方必须通过 [`with_switch_to_guard`](Self::with_switch_to_guard)
    /// 注入自定义 guard 才能启用 `switch_to` 功能。
    ///
    /// # 参数
    /// - `session`: 会话管理器。
    /// - `token_handler`: Token 生成与校验处理器。
    /// - `timeout`: 默认 token 有效期（秒）。非正数（<= 0）时回退为 3600 秒并输出
    ///   `warn` 日志（负值若未经校验，`as u64` 会回绕为巨大 TTL，
    ///   产生事实上的永久 Token-Session）。
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
            switch_to_guard: Arc::new(DenyAllSwitchToGuard),
            renew_locks: Arc::new(DashMap::new()),
        }
    }

    /// 配置 remember_me 扩展超时。
    ///
    /// 启用后，`login` 时 params 含 `remember_me=true` 将使用 `remember_me_timeout` 作为
    /// Token-Session 的 TTL，否则使用默认 `timeout`。
    ///
    /// # 参数
    /// - `enabled`: 是否启用 remember_me。
    /// - `timeout`: remember_me 扩展超时秒数（应大于 `timeout`）。非正数（<= 0）时
    ///   回退为 7776000 秒（90 天）并输出 `warn` 日志（构造器级正数校验）。
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

    /// 注入身份切换权限校验 guard。
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
    async fn login(&self, id: &str, params: Option<&str>) -> GarrisonResult<String> {
        // 解析 remember_me 参数
        let remember_me = parse_remember_me_param(params);
        let effective_timeout = if remember_me && self.remember_me_enabled {
            self.remember_me_timeout
        } else {
            self.timeout
        };
        let token = self.token_handler.generate(id, effective_timeout)?;
        self.session.create(id, &token).await?;
        // remember_me 扩展 Token-Session TTL
        if effective_timeout != self.timeout {
            // 构造器已保证 timeout/remember_me_timeout 为正数，
            // 此处仍用 try_from 防御性校验——负值绝不允许经 `as u64` 回绕为巨大 TTL
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
        // 幂等处理：logout 不存在的 token 返回 Ok(())
        // session.logout 内部对不存在的 token 返回 Ok(())，直接委托
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
        // 验证 target_login_id 非空
        if target_login_id.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "core-auth-target-login-id-empty".to_string(),
            ));
        }

        // 获取当前 TokenSession
        let mut ts = self
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| {
                GarrisonError::NotLogin("core-auth-token-invalid-or-expired".to_string())
            })?;

        // 校验目标 Account-Session 存在（纵深防御层）。
        // 在 guard 检查前校验，原因有二：
        // 1. 防止 switch_to 切到不存在的 login_id（ensure_token_in_account_session 已 fail-closed，
        // 此层提前拒绝，避免执行到后续步骤）
        // 2. guard 可能依赖 target 的属性，target 不存在时 guard 行为未定义
        //
        // 防止 login_id 枚举：统一返回与权限拒绝同类型的模糊错误
        // `NotPermission("core-auth-switch-to-denied")`，使「target 不存在」与
        // 「无权切换」在外部不可区分。
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

        // 执行权限校验（guard 默认 DenyAllSwitchToGuard，fail-closed）
        // 在修改 session 前校验，确保无权限时不产生任何副作用
        let original_login_id = ts.login_id.clone();
        self.switch_to_guard
            .check(&original_login_id, target_login_id)
            .await?;

        // 保存原始 TokenSession 快照：两阶段 Account-Session 迁移的失败路径回滚用
        let ts_original = ts.clone();

        // 存储原始 login_id 到 attrs["switched_from"]
        ts.attrs
            .insert("switched_from".to_string(), original_login_id.clone());

        // 更新 login_id 为 target_login_id
        ts.login_id = target_login_id.to_string();
        ts.last_active_at = Utc::now().timestamp();

        // 保存更新后的 session 到 DAO（保留原 TTL）
        self.session.save_token_session(token, &ts).await?;

        // 在添加 token 到 target Account-Session 之前，先从 original
        // Account-Session 中移除该 token，避免数据不一致：
        // 1. `list_devices(original)` 否则会误返回已切换的 token
        // 2. `logout_by_login_id(original)` 否则会误杀已切到 target 的 token（越权踢出）
        // 3. `enforce_max_login_count(original)` 否则会误算已切换的 token
        //
        // 顺序选择：先 remove original，再 ensure target。
        //
        // 两阶段失败路径的 token 孤儿防护：save_token_session 之后
        // 任一 Account-Session 操作失败，原本会直接返回 Err 且无回滚——token 在两侧
        // Account-Session 间处于孤儿/双注册状态（ts.login_id 已改但注册关系未跟随）。
        // 修复：失败路径 best-effort 回滚到迁移前快照（恢复 ts_original；ensure 失败时
        // 还需把 token 挂回 original）。回滚成功 → 状态一致，透传原始错误；
        // 回滚也失败 → 升级为 Internal 聚合错误（失败显性化，禁止静默残留）。
        //
        // remove/ensure 内部均用 `with_login_lock` 串行化 Account-Session
        // read-modify-write，避免与 login/logout 竞态。
        if let Err(remove_err) = self
            .session
            .remove_token_from_account_session(&original_login_id, token)
            .await
        {
            // 回滚：恢复原始 TokenSession（login_id = original），与「token 仍在 original
            // Account-Session」重新一致
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

        // 确保 token 存在于目标 login_id 的 Account-Session 中
        //（否则 is_valid 检查会因 Account-Session 不存在而返回 false）
        if let Err(ensure_err) = self
            .session
            .ensure_token_in_account_session(target_login_id, token)
            .await
        {
            // 回滚：token 已从 original 移除，需先挂回 original Account-Session，
            // 再恢复原始 TokenSession，回到迁移前状态
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
            // 回滚成功（或部分成功但状态可由返回错误显性化）：透传原始错误。
            // 单边回滚失败时也在此显性化，避免静默孤儿。
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

        // 审计日志
        // token 脱敏：仅记录前 8 字符
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
        // 修复 CWE-362 TOCTOU 竞态：per-token 串行化整个 renew 流程。
        //
        // 多个并发 renew 同一 token 时，第 1 个拿到锁执行完整流程（读旧 → 生成新 → 失效旧），
        // 其他请求等待锁。第 1 个完成（旧 token 已失效）后，其他请求拿到锁，
        // step 1 读旧 token 返回 None → NotLogin 错误，确保"恰好 1 个成功"。
        //
        // 锁粒度：per-token（不同 token 仍可并行），不使用 per-login_id（粒度过粗）
        // 或全局锁（性能不可接受）。
        //
        // 锁类型：`tokio::sync::Mutex`（异步锁，保护 renew 流程可跨 `.await` 持有）。
        // 数据结构：`DashMap`（分片锁，与 `GarrisonSession::login_locks` 一致）。
        //
        // 内存清理：renew 流程结束（无论成功/失败）、锁释放后，用 `remove_if` 检查
        // `Arc::strong_count`，若 == 1（无其他等待者）则移除 entry，避免攻击者用大量
        // 不同随机 token 灌满 DashMap 导致 OOM（CWE-770）。
        //
        // 实现模式：用 `async { ... }.await` block 包裹整个 renew 流程，外层统一执行
        // entry 清理。这样无论 inner block 内任何 `?` 提前返回 Err，外层清理都会执行
        //（失败路径也必须清理 entry，防止失败 renew 累积导致 OOM）。
        let renew_lock = self
            .renew_locks
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _renew_guard = renew_lock.lock().await;

        // 用 inner async block 包裹整个 renew 流程，使所有 ? 提前返回路径统一经过外层清理。
        //
        // 此模式的设计意图：
        // - renew 流程有 6 个步骤，其中 step 1/3/4/5 可能通过 `?` 提前返回 Err
        // - 若不包裹 inner async block，提前返回路径会跳过末尾的 `renew_locks.remove_if` 清理
        // - 残留的 entry 会被攻击者用大量随机 token 灌满（CWE-770 OOM）
        // - inner async block 将所有 `?` 路径统一收敛到外层的 `drop(_renew_guard)` + `remove_if`
        // - 代价：多一次 `async { ... }.await` 的状态机包装（编译期完成，运行时零开销）
        // - 替代方案（已否决）：在每个 `?` 前手动清理 entry — 代码重复 4 次，易遗漏
        let result: GarrisonResult<String> = async {
            // 调整顺序为"先创建新 token session，再失效旧 token"，消除续期窗口漏洞
            // （CWE-362 / CVSS 7.5）。
        //
            // 若"先失效旧 token，再创建新 token"，在步骤 2（logout old）与步骤 5
            //（create new）之间存在 DoS gap window：用户在此窗口内无任何有效 token，
            // 若新 token 创建失败且回滚也失败，用户将彻底失去会话。
        //
            // 两种顺序的权衡：
            // - delete first → 无双 token 窗口，但有 DoS gap（HIGH 风险）
            // - create first → 无 DoS gap，但有短暂双 token 窗口
        //
            // 决策依据：DoS gap 为 HIGH 风险（CVSS 7.5），
            // 而双 token 窗口仅持续毫秒级（create 与 delete 之间），且旧 token 在 delete
            // 成功后立即失效，攻击窗口极小。可用性 > 短暂安全窗口，故采用 create first。
        //
            // 新顺序：
            // 1. 获取旧 TokenSession + 剩余 TTL
            // 2. 生成新 token + 构建新 TokenSession
            // 3. 保存新 Token-Session with TTL
            // 若失败，旧 token 仍有效 → 直接返回错误（无需回滚）
            // 4. 添加新 token 到 Account-Session
            // 若失败，删除新 token session → 旧 token 仍有效 → 返回错误
            // 5. 失效旧 token（logout 同时删除 Token-Session 与 Account-Session 条目）
            // 若失败，记录 warn 但返回 Ok(new_token) — 用户已持有新 token，
            // 旧 token 残留属安全风险但非 DoS，需运维介入清理

            // 1. 获取旧 TokenSession + 剩余 TTL（性能优化：单次 DAO 调用）
            // None 表示永久键（无 TTL），用 0 表示永久驻留
            let (old_ts, remaining_ttl) = self
                .session
                .get_token_session_with_ttl(token)
                .await?
                .ok_or_else(|| {
                    GarrisonError::NotLogin("core-auth-token-invalid-or-expired".to_string())
                })?;
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
                #[cfg(feature = "session-extra")]
                dynamic_active_timeout: old_ts.dynamic_active_timeout,
                // 匿名 token 不可达此路径（get_token_session 读 token:session:{token}，
                // 匿名 session 在 token:session:anon:{token}，入口即返回 NotLogin）
                #[cfg(feature = "session-extra")]
                is_anon: false,
                // renew 复制旧会话的 TTL 权威来源
                effective_timeout: old_ts.effective_timeout,
            };

            // 4. 保存新 Token-Session with remaining TTL
            // 若失败，旧 token 仍有效（未触碰），直接返回错误 — 无 DoS
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

            // 5. 添加新 token 到 Account-Session
            // 若失败，删除新 token session → 旧 token 仍有效 → 返回错误 — 无 DoS
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
                // 清理刚创建的新 token session（best-effort）
                if let Err(rb_err) = self.session.logout(&new_token).await {
                    tracing::error!(
                        rollback_error = %rb_err,
                        new_token_prefix = %new_prefix,
                        "renew_to_equivalent: failed to clean up new token session, new token may be orphaned"
                    );
                }
                // 失败显性化 — 旧 token 仍有效，用户可用旧 token 重试
                return Err(GarrisonError::Internal(
                    "core-auth-token-renew-add-to-account-failed".to_string(),
                ));
            }

            // 6. 失效旧 token（logout 同时删除 Token-Session 与 Account-Session 条目）
            // 此步在"新 token 已完全建立"之后执行。
            // 若此步失败，用户已持有新 token（无 DoS），但旧 token 残留（安全风险）。
            // 决策：返回 Ok(new_token) 让用户继续操作，旧 token 残留由运维介入清理。
            // 理由：若因 delete 失败而返回 Err，用户将丢失新 token（已建立），
            // 反而制造新的 DoS — 与 create first 的目标相悖。
        //
            // CWE-613 双 token 窗口：此权衡是**已知并接受**的
            // 安全残留——旧 token 在 logout 失败时保持有效，攻击者若提前持有旧 token
            // 可继续使用。缓解措施（本实现的承诺）：
            // - 审计事件必须记录失败：下方 `tracing::error!` 携带稳定
            // `error_code = "renew_old_token_cleanup_failed"`，审计/监控依赖此 code
            // - 失败显性化 + 主动告警：
            // 用 `error` 级别记录（而非 `warn`），确保生产环境监控系统触发告警
            // - 告警规则建议：error_code="renew_old_token_cleanup_failed" 出现 >0 次即触发
            // P2 告警，运维需在 5 分钟内介入清理残留旧 token（CWE-613 缓解）
            // - 未注入 `AlertListenerManager` 时无法主动广播 `SecurityAlertEvent`，
            // 日志告警是兜底手段；注入了 alert_manager 的部署应额外调用
            // `broadcast_alert` 触发告警链路（本层不持有 alert_manager 引用，
            // 由调用方 `GarrisonLogicDefault` 在 renew 失败回调中转发）
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

        // 无论 renew 成功/失败，都清理 DashMap entry，防止无限制增长。
        // 必须先 drop `_renew_guard`（释放 tokio::sync::Mutex 锁），再 drop `renew_lock`
        //（释放 Arc clone），最后用 `remove_if` 原子检查 `Arc::strong_count == 1`。
        //
        // 安全性分析：
        // - `remove_if` 在 DashMap shard 锁内检查条件，原子操作不会 race
        // - 若 strong_count == 1（只有 DashMap 持有），说明无其他等待者，安全移除
        // - 若 strong_count > 1（有其他等待者已 clone Arc），保留 entry，其他等待者继续用
        // - 移除后，新调用方通过 `or_insert_with` 创建新 Arc，不影响串行化语义
        // - 失败路径（NotLogin / 创建新 token 失败 / 添加 Account-Session 失败）也走此清理
        // 防止攻击者用大量不同随机 token 触发失败路径累积 entry 导致 OOM
        drop(_renew_guard);
        drop(renew_lock);
        self.renew_locks
            .remove_if(token, |_, lock| Arc::strong_count(lock) == 1);

        result
    }
}
