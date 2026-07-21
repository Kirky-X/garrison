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
use crate::error::{GarrisonError, GarrisonResult};
use crate::session::{GarrisonSession, TokenSession};

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
    pub fn new(session: Arc<GarrisonSession>, token_handler: Arc<dyn Token>, timeout: i64) -> Self {
        Self {
            session,
            token_handler,
            timeout,
            remember_me_enabled: false,
            remember_me_timeout: 7_776_000,
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
    /// use garrison::core::auth::{AuthLogicDefault, SwitchToGuard};
    /// use garrison::error::{GarrisonError, GarrisonResult};
    ///
    /// struct AdminOnlyGuard;
    /// #[async_trait::async_trait]
    /// impl SwitchToGuard for AdminOnlyGuard {
    ///     async fn check(&self, original: &str, target: &str) -> GarrisonResult<()> {
    ///         if original.starts_with("admin:") {
    ///             Ok(())
    ///         } else {
    ///             Err(GarrisonError::NotPermission(format!("{} 无权切换", original)))
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
    async fn login(&self, id: &str, params: Option<&str>) -> GarrisonResult<String> {
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
            return Err(GarrisonError::InvalidParam(format!(
                "core-auth-target-login-id-not-found::{}",
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

        // H1 修复：在添加 token 到 target Account-Session 之前，先从 original
        // Account-Session 中移除该 token，避免数据不一致：
        // 1. `list_devices(original)` 否则会误返回已切换的 token
        // 2. `logout_by_login_id(original)` 否则会误杀已切到 target 的 token（越权踢出）
        // 3. `enforce_max_login_count(original)` 否则会误算已切换的 token
        //
        // 顺序选择：先 remove original，再 ensure target。
        // - 若 remove original 失败：返回 Err，token 仍在 original。ts.login_id 已改为
        //   target（save_token_session 已执行），但 is_valid 会失败（target 未含 token）。
        //   用户需重新登录或重试 switch_to。权衡：相比"双指"残留（先 ensure target 再
        //   remove original 失败导致 token 同时在两边），孤立状态更易被发现且不会越权踢出。
        // - 若 ensure target 失败：token 已从 original 移除但未加到 target，is_valid 失败。
        //   用户需重新登录。trade-off：可观测的失败优于静默的双指状态。
        //
        // remove_token_from_account_session 内部用 `with_login_lock(original)` 串行化
        // Account-Session read-modify-write，避免与 original 的 login/logout 竞态。
        self.session
            .remove_token_from_account_session(&original_login_id, token)
            .await?;

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

    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
        // 修复 CWE-362 TOCTOU 竞态：per-token 串行化整个 renew 流程
        //（fix-refresh-race-and-test-contracts / spec R-refresh-token-001）。
        //
        // 多个并发 renew 同一 token 时，第 1 个拿到锁执行完整流程（读旧 → 生成新 → 失效旧），
        // 其他请求等待锁。第 1 个完成（旧 token 已失效）后，其他请求拿到锁，
        // step 1 读旧 token 返回 None → NotLogin 错误，确保"恰好 1 个成功"。
        //
        // 锁粒度：per-token（不同 token 仍可并行），不使用 per-login_id（粒度过粗）
        // 或全局锁（性能不可接受）。
        //
        // 锁类型：`tokio::sync::Mutex`（异步锁，保护 renew 流程可跨 `.await` 持有）。
        // 数据结构：`DashMap`（分片锁，与 `GarrisonSession::login_locks` 一致，rule 11）。
        //
        // 内存清理：renew 流程结束（无论成功/失败）、锁释放后，用 `remove_if` 检查
        // `Arc::strong_count`，若 == 1（无其他等待者）则移除 entry，避免攻击者用大量
        // 不同随机 token 灌满 DashMap 导致 OOM（CWE-770 / HIGH-1 修复）。
        //
        // 实现模式：用 `async { ... }.await` block 包裹整个 renew 流程，外层统一执行
        // entry 清理。这样无论 inner block 内任何 `?` 提前返回 Err，外层清理都会执行
        //（HIGH-1 修复：失败路径也必须清理 entry，防止失败 renew 累积导致 OOM）。
        let renew_lock = self
            .renew_locks
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _renew_guard = renew_lock.lock().await;

        // 用 inner async block 包裹整个 renew 流程，使所有 ? 提前返回路径统一经过外层清理。
        //
        // LOW 文档补全（fix-refresh-race-and-test-contracts）：此模式的设计意图：
        // - renew 流程有 6 个步骤，其中 step 1/3/4/5 可能通过 `?` 提前返回 Err
        // - 若不包裹 inner async block，提前返回路径会跳过末尾的 `renew_locks.remove_if` 清理
        // - 残留的 entry 会被攻击者用大量随机 token 灌满（CWE-770 OOM）
        // - inner async block 将所有 `?` 路径统一收敛到外层的 `drop(_renew_guard)` + `remove_if`
        // - 代价：多一次 `async { ... }.await` 的状态机包装（编译期完成，运行时零开销）
        // - 替代方案（已否决）：在每个 `?` 前手动清理 entry — 代码重复 4 次，易遗漏
        let result: GarrisonResult<String> = async {
            // A9: 调整顺序为"先创建新 token session，再失效旧 token"，消除续期窗口漏洞
            // （vuln-0003 / CWE-362 / CVSS 7.5）。
            //
            // 原实现"先失效旧 token，再创建新 token"在步骤 2（logout old）与步骤 5
            //（create new）之间存在 DoS gap window：用户在此窗口内无任何有效 token，
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
                return Err(GarrisonError::Internal(
                    "core-auth-token-renew-create-failed".to_string(),
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
                return Err(GarrisonError::Internal(
                    "core-auth-token-renew-add-to-account-failed".to_string(),
                ));
            }

            // 6. 失效旧 token（logout 同时删除 Token-Session 与 Account-Session 条目）
            //    A9 关键变化：此步在"新 token 已完全建立"之后执行。
            //    若此步失败，用户已持有新 token（无 DoS），但旧 token 残留（安全风险）。
            //    决策：返回 Ok(new_token) 让用户继续操作，旧 token 残留由运维介入清理。
            //    理由：若因 delete 失败而返回 Err，用户将丢失新 token（已建立），
            //    反而制造新的 DoS — 与 A9 修复目标相悖。
            //
            //    rule 12（失败显性化）+ 安全审查 MEDIUM-1（主动告警）：
            //    - 用 `error` 级别记录（而非 `warn`），确保生产环境监控系统触发告警
            //    - 携带稳定 `error_code = "renew_old_token_cleanup_failed"` 字段，
            //      供运维日志告警系统（如 Loki/ELK + Alertmanager）基于此 code 配置告警规则
            //    - 告警规则建议：error_code="renew_old_token_cleanup_failed" 出现 >0 次即触发
            //      P2 告警，运维需在 5 分钟内介入清理残留旧 token（CWE-613 缓解）
            //    - 未注入 `AlertListenerManager` 时无法主动广播 `SecurityAlertEvent`，
            //      日志告警是兜底手段；注入了 alert_manager 的部署应额外调用
            //      `broadcast_alert` 触发告警链路（本层不持有 alert_manager 引用，
            //      由调用方 `GarrisonLogicDefault` 在 renew 失败回调中转发）
            if let Err(e) = self.session.logout(token).await {
                let old_prefix = if token.len() >= 8 { &token[..8] } else { token };
                tracing::error!(
                    error_code = "renew_old_token_cleanup_failed",
                    error = %e,
                    old_token_prefix = %old_prefix,
                    new_token_prefix = %&new_token[..new_token.len().min(8)],
                    "renew_to_equivalent 失效旧 token 失败，旧 token 残留（CWE-613 安全风险），\
                     新 token 已建立无 DoS，但需运维立即清理旧 token 防止被攻击者利用。\
                     告警规则：error_code=\"renew_old_token_cleanup_failed\" 出现即触发 P2 告警"
                );
            }

            Ok(new_token)
        }
        .await;

        // HIGH-1 修复：无论 renew 成功/失败，都清理 DashMap entry，防止无限制增长。
        // 必须先 drop `_renew_guard`（释放 tokio::sync::Mutex 锁），再 drop `renew_lock`
        //（释放 Arc clone），最后用 `remove_if` 原子检查 `Arc::strong_count == 1`。
        //
        // 安全性分析：
        // - `remove_if` 在 DashMap shard 锁内检查条件，原子操作不会 race
        // - 若 strong_count == 1（只有 DashMap 持有），说明无其他等待者，安全移除
        // - 若 strong_count > 1（有其他等待者已 clone Arc），保留 entry，其他等待者继续用
        // - 移除后，新调用方通过 `or_insert_with` 创建新 Arc，不影响串行化语义
        // - 失败路径（NotLogin / 创建新 token 失败 / 添加 Account-Session 失败）也走此清理
        //   防止攻击者用大量不同随机 token 触发失败路径累积 entry 导致 OOM
        drop(_renew_guard);
        drop(renew_lock);
        self.renew_locks
            .remove_if(token, |_, lock| Arc::strong_count(lock) == 1);

        result
    }
}
