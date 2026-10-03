// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 找回密码服务：请求（防枚举）与重置（两段式防竞态）两大入口。
//!
//! # 请求阶段（`request_reset`）——防存在性预言机
//!
//! 已知/未知标识走**同一路径**：已知 → 真实 subject 签发 ActionToken 并
//! 交付邮件；未知 → 对 [`DUMMY_RESET_SUBJECT`] 签发 dummy token 后丢弃
//! （等价开销、从不交付）。两类标识执行相同的限流计数递增，返回相同的
//! 响应外形（[`ResetRequestOutcome`] 不携带「目标是否存在」信号），消除
//! authgear forgotpassword 声明的存在性预言机（service.go:121-128：对
//! 未知用户同样执行等价工作）。邮件只发给真实存在的收件人（发往不存在
//! 邮箱没有意义），存在性信号只经邮件通道带出、响应体零信号。
//!
//! # 重置阶段（`reset`）——两段式防竞态
//!
//! ①校验：ActionToken 签名/exp/purpose + code-subject 绑定一致
//! （`pwdreset:bind:{jti}`，防跨用户挪用）；
//! ②授权凭据操作：恢复会话打 restricted 标记（[`RestrictedSessionGuard::grant`]，幂等）；
//! ③策略校验：宿主注入的 [`PasswordPolicyEngine`]（含 HistoryRule）校验新密码，
//!   历史取自 [`PasswordHistoryRepository`]——失败时 token 未消费，可换密码重试；
//! ④消费 token：`ActionTokenConsumer::consume` 原子登记（恰一赢家）；
//! ⑤凭据提交：消费成功后才写新凭据 + 追加 `app_password_history`。
//!   消费失败路径**无凭据变更**（写操作在消费之后，结构化保证）；
//!   历史追加失败则尽力回滚凭据到原 hash 并透传错误（显性化，不静默吞）。
//!
//! 成功后 token 不可复用：jti 已登记。restricted 标记在 reset 返回后
//! **保留**（fail-safe：恢复会话始终只可达改密端点，宿主可显式
//! [`RestrictedSessionGuard::clear`] 升级会话）。
//!
//! # 挂 authflow DSL
//!
//! 绑定记录即找回密码 flow 的跨请求会话状态（`request_reset` 创建、
//! `reset` 消费），凭据/策略设施复用 `account-credential` 与
//! `account-policy`，不另造第二套执行器。

use super::action_token::{unix_now, ActionTokenService};
use super::consumer::ActionTokenConsumer;
use super::restricted::RestrictedSessionGuard;
use crate::account::credential::password::PasswordHasher;
use crate::account::credential::CredentialRepository;
use crate::account::policy::PasswordPolicyEngine;
use crate::account::policy::PolicyContext;
use crate::constants::DaoKeyPrefix;
use crate::dao::repository::PasswordHistoryRepository;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::session::GarrisonSession;
use std::sync::Arc;

/// 防枚举限流默认窗口（秒）：1 小时（与 email-verification 小时窗口同口径）。
pub const DEFAULT_RATE_WINDOW_SECS: u64 = 3600;

/// 防枚举限流默认窗口内最大请求数。
pub const DEFAULT_RATE_LIMIT_MAX: u64 = 5;

/// 历史密码比对条数：与 `HistoryRule` 的硬上限（24）对齐。
pub const HISTORY_CHECK_COUNT: u32 = 24;

/// dummy token 签发目标（未知标识路径）：固定无效主体。
///
/// dummy token 从不交付也从不登记绑定；若被构造 replay，`reset` 在绑定
/// 校验处以 `pwdreset-binding-missing` 拒绝。该主体值仅保证签发路径与
/// 已知标识等价开销（防存在性预言机的时序差）。
pub const DUMMY_RESET_SUBJECT: &str = "__garrison_pwdreset_dummy__";

/// 请求阶段响应外形（防枚举）。
///
/// 存在/不存在标识返回的字段完全一致——「目标是否存在」的信息只经
/// 邮件通道带出，响应体零信号。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetRequestOutcome {
    /// 响应固定文案键（i18n 渲染由调用方完成），两类路径同值。
    pub message_key: &'static str,
    /// 限流计数（窗口内已递增到的值，含本次；两类路径同规则递增）。
    pub rate_count: u64,
}

/// 标识解析 SPI：标识（邮箱/用户名）→ 归属用户（不存在 → `None`）。
///
/// 生产实现委托 [`crate::dao::repository::UserIdentifierRepository::find_owner`]；
/// 独立 trait 使服务可脱离具体 DAO 后端测试。
#[async_trait::async_trait]
pub trait ResetIdentityResolver: Send + Sync {
    /// 解析标识归属；未知返回 `Ok(None)`。
    async fn resolve_subject(
        &self,
        tenant_id: i64,
        identifier: &str,
    ) -> GarrisonResult<Option<String>>;
}

/// 找回邮件发送 SPI（主题/正文已按 i18n FTL 渲染）。
///
/// 生产实现 [`EmailResetMailSender`] 委托既有
/// [`crate::secure::email::EmailSender`] 发送设施。
#[async_trait::async_trait]
pub trait ResetMailSender: Send + Sync {
    /// 交付找回邮件（收件人/主题/正文）。
    async fn deliver(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()>;
}

/// 生产邮件发送实现：委托既有 `EmailSender`（email-verification 设施）。
pub struct EmailResetMailSender {
    inner: Arc<dyn crate::secure::email::EmailSender>,
}

impl EmailResetMailSender {
    /// 包装既有邮件发送器。
    pub fn new(inner: Arc<dyn crate::secure::email::EmailSender>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl ResetMailSender for EmailResetMailSender {
    async fn deliver(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()> {
        self.inner.send(to, subject, body).await
    }
}

/// 找回密码服务。
pub struct PasswordResetService {
    dao: Arc<dyn GarrisonDao>,
    session: Arc<GarrisonSession>,
    tokens: ActionTokenService,
    consumer: ActionTokenConsumer,
    credentials: Arc<dyn CredentialRepository>,
    hasher: Arc<dyn PasswordHasher>,
    policy: PasswordPolicyEngine,
    history: Arc<dyn PasswordHistoryRepository>,
    resolver: Arc<dyn ResetIdentityResolver>,
    sender: Arc<dyn ResetMailSender>,
    rate_window_secs: u64,
    rate_limit_max: u64,
}

impl std::fmt::Debug for PasswordResetService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetService")
            .field("rate_window_secs", &self.rate_window_secs)
            .field("rate_limit_max", &self.rate_limit_max)
            .finish_non_exhaustive()
    }
}

impl PasswordResetService {
    /// 创建服务（默认限流：[`DEFAULT_RATE_LIMIT_MAX`] / [`DEFAULT_RATE_WINDOW_SECS`]）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dao: Arc<dyn GarrisonDao>,
        session: Arc<GarrisonSession>,
        tokens: ActionTokenService,
        credentials: Arc<dyn CredentialRepository>,
        hasher: Arc<dyn PasswordHasher>,
        policy: PasswordPolicyEngine,
        history: Arc<dyn PasswordHistoryRepository>,
        resolver: Arc<dyn ResetIdentityResolver>,
        sender: Arc<dyn ResetMailSender>,
    ) -> Self {
        let consumer = ActionTokenConsumer::new(dao.clone());
        Self {
            dao,
            session,
            tokens,
            consumer,
            credentials,
            hasher,
            policy,
            history,
            resolver,
            sender,
            rate_window_secs: DEFAULT_RATE_WINDOW_SECS,
            rate_limit_max: DEFAULT_RATE_LIMIT_MAX,
        }
    }

    /// 覆盖防枚举限流参数（窗口秒数 / 窗口内最大数）。
    pub fn with_rate_limit(mut self, window_secs: u64, max: u64) -> Self {
        self.rate_window_secs = window_secs;
        self.rate_limit_max = max;
        self
    }

    /// 请求找回：限流计数递增 → 解析标识 →（存在）签发 + 写绑定 + 发邮件 /
    /// （不存在）对 dummy subject 签发并丢弃。
    ///
    /// 限流键 `pwdreset:rate:{标识}` 与既有登录限流键空间隔离、口径一致
    /// （DAO 原子计数 + 窗口 TTL）。计数递增发生在解析之前：未知标识的
    /// 请求同样消耗配额（防枚举探测打满窗口）。超限返回
    /// [`GarrisonError::RateLimited`]。发送失败时计数**不回滚**
    /// （失败重试同样消耗配额，防邮件轰炸），错误显性透传。
    pub async fn request_reset(
        &self,
        tenant_id: i64,
        identifier: &str,
    ) -> GarrisonResult<ResetRequestOutcome> {
        let identifier = normalize_identifier(identifier);
        validate_identifier(&identifier)?;
        let count = self
            .dao
            .incr(&rate_key(&identifier), self.rate_window_secs)
            .await?;
        if count > self.rate_limit_max {
            return Err(GarrisonError::RateLimited {
                retry_after_secs: self.rate_window_secs,
            });
        }

        match self
            .resolver
            .resolve_subject(tenant_id, &identifier)
            .await?
        {
            Some(subject) => {
                let issued = self.tokens.issue(&subject)?;
                let ttl = (issued.claims.exp - unix_now()?).clamp(1, i64::MAX) as u64;
                // code-subject 绑定（flow 跨请求会话状态）：消费时校验
                self.dao
                    .set(&binding_key(&issued.claims.jti), &subject, ttl)
                    .await?;
                // code-tenant 绑定（渗透-租户隔离-标识符注册表-1）：与 subject 绑定
                // 同 TTL，reset 时校验请求租户与签发租户一致。写失败显性透传——
                // 缺 tenant 绑定的 token 会被 reset 以 fail-closed 拒绝，不得静默降级。
                self.dao
                    .set(
                        &binding_tenant_key(&issued.claims.jti),
                        &tenant_id.to_string(),
                        ttl,
                    )
                    .await?;
                let (subject_line, body_line) = render_mail(&issued.token);
                // 投递 fire-and-forget（对齐 authgear 异步投递）：请求路径不做
                // SMTP 同步等待——时序与错误通道都与未知标识路径不可区分
                // （投递失败仅记掩码日志，不向调用方透传；防存在性预言机）
                let sender = self.sender.clone();
                let to = identifier.clone();
                tokio::spawn(async move {
                    if let Err(e) = sender.deliver(&to, &subject_line, &body_line).await {
                        tracing::error!(
                            to = %mask_email_for_log(&to),
                            error = %e,
                            "password reset mail delivery failed"
                        );
                    }
                });
            },
            // 未知标识：同路径等价开销签发 dummy token（丢弃不交付），
            // 响应外形与存在路径一致
            None => {
                let _dummy = self.tokens.issue(DUMMY_RESET_SUBJECT)?;
            },
        }
        Ok(ResetRequestOutcome {
            message_key: "pwdreset-request-accepted",
            rate_count: count,
        })
    }

    /// 重置密码（两段式防竞态）。
    ///
    /// # 参数
    /// - `tenant_id`: 租户（历史记录归属）。必须与 `request_reset` 签发 token 时的
    ///   租户一致（code-tenant 绑定校验，渗透-租户隔离-标识符注册表-1）。
    /// - `session_token`: 恢复会话 token（须为已存在的 Token-Session，
    ///   宿主在用户点击邮件链接后创建）。reset 会对其打 restricted 标记，
    ///   标记在返回后保留（fail-safe），宿主可显式清除。
    /// - `action_token`: 邮件交付的 ActionToken。
    /// - `new_password`: 新明文密码（仅校验/哈希时临时持有，不存储）。
    ///
    /// # 错误
    /// - token 非法/过期/purpose 不符：透传 [`ActionTokenService::verify`]
    /// - 绑定缺失：`InvalidToken("pwdreset-binding-missing::")`
    /// - 跨用户挪用（绑定不一致）：`NotPermission("pwdreset-subject-binding-mismatch::...")`
    /// - 租户绑定缺失（升级前签发的旧 token，fail-closed）：
    ///   `InvalidToken("pwdreset-tenant-binding-missing::")`
    /// - 跨租户重置（请求租户与签发租户不一致，错误不含归属信息）：
    ///   `NotPermission("pwdreset-tenant-mismatch::")`
    /// - 恢复会话归属他人：`NotPermission("pwdreset-session-subject-mismatch::...")`
    /// - 二次消费/并发败者：`InvalidToken("pwdreset-token-consume-failed::")`
    ///   （此刻无任何凭据变更——两段式回滚由「消费前不改凭据」结构保证）
    /// - 策略拒绝（含历史重用）：`InvalidParam("pwdreset-policy-violated::...")`
    ///   （token 未消费，可换密码重试）
    /// - 历史追加失败：透传 DAO 错误，凭据尽力回滚到原 hash（best-effort，
    ///   回滚失败仅 error 告警不掩盖原始错误；token 已消费不可复用）
    pub async fn reset(
        &self,
        tenant_id: i64,
        session_token: &str,
        action_token: &str,
        new_password: &str,
    ) -> GarrisonResult<()> {
        // 第 1 段：校验（签名/exp/purpose + 绑定）——不做任何凭据写入
        let claims = self.tokens.verify(action_token)?;
        let bound = self.dao.get(&binding_key(&claims.jti)).await?;
        match bound {
            Some(bound) if bound == claims.sub => {},
            Some(bound) => {
                return Err(GarrisonError::NotPermission(format!(
                    "pwdreset-subject-binding-mismatch::token-sub={}::binding={bound}",
                    claims.sub
                )));
            },
            None => {
                return Err(GarrisonError::InvalidToken(
                    "pwdreset-binding-missing::".to_string(),
                ));
            },
        }
        // subject∈tenant 校验（渗透-租户隔离-标识符注册表-1）：请求租户必须与
        // 签发租户一致。绑定缺失（升级前旧 token）fail-closed 拒绝；不匹配拒绝
        // 且错误不含归属信息（不泄露 token 签发租户）。两条校验都在任何凭据
        // 写入之前——被拒路径零凭据变更。
        let bound_tenant = self.dao.get(&binding_tenant_key(&claims.jti)).await?;
        match bound_tenant {
            Some(t) if t == tenant_id.to_string() => {},
            Some(_) => {
                return Err(GarrisonError::NotPermission(
                    "pwdreset-tenant-mismatch::".to_string(),
                ));
            },
            None => {
                return Err(GarrisonError::InvalidToken(
                    "pwdreset-tenant-binding-missing::".to_string(),
                ));
            },
        }

        // 第 2 段：授权凭据操作（restricted 标记，幂等；保留至宿主显式清除）
        // 前置：恢复会话必须归属目标主体，防 restricted 标记落到他人会话
        let session_subject = self
            .session
            .get_token_session(session_token)
            .await?
            .ok_or_else(|| GarrisonError::InvalidToken("pwdreset-session-not-found::".to_string()))?
            .login_id;
        if session_subject != claims.sub {
            return Err(GarrisonError::NotPermission(format!(
                "pwdreset-session-subject-mismatch::session={}::token={}",
                session_subject, claims.sub
            )));
        }
        RestrictedSessionGuard::grant(self.session.clone(), session_token).await?;

        // 凭据存在性检查前移（消费之前）：无 password 凭据的账号在消费前
        // 显性拒绝，token 不被烧毁（消费不可逆）
        let existing = self
            .credentials
            .find_by_user_and_type(&claims.sub, "password")
            .await?;
        let current = existing.into_iter().find(|c| c.enabled).ok_or_else(|| {
            GarrisonError::InvalidParam("pwdreset-password-credential-missing::".to_string())
        })?;
        // 新密码不得等于当前密码（框架自身闭合「重置为当前密码」——存量用户
        // 历史表为空时 HistoryRule 无从比对，直接比对补齐该缺口）
        if self.hasher.verify(new_password, &current.secret_data)? {
            return Err(GarrisonError::InvalidParam(
                "pwdreset-policy-violated::history-rule::new password equals current password"
                    .to_string(),
            ));
        }

        // 策略校验（含 HistoryRule）：失败时 token 未消费，可重试
        let history = self
            .history
            .recent(tenant_id, &claims.sub, HISTORY_CHECK_COUNT)
            .await?;
        let ctx = PolicyContext {
            user_id: claims.sub.clone(),
            tenant_id: Some(tenant_id.to_string()),
            username: None,
            email: None,
            password_history: history,
            password_created_at: None,
        };
        if let Err(errors) = self.policy.validate(&ctx, new_password) {
            let first = errors.first();
            let detail = match first {
                Some(e) => format!("{}::{}", e.rule_name, e.message),
                None => "unknown".to_string(),
            };
            return Err(GarrisonError::InvalidParam(format!(
                "pwdreset-policy-violated::{detail}"
            )));
        }

        // 第 3 段：原子消费（恰一赢家）——失败即显性拒绝，无凭据变更
        let remaining = (claims.exp - unix_now()?).clamp(1, i64::MAX) as u64;
        if !self.consumer.consume(&claims.jti, remaining).await? {
            return Err(GarrisonError::InvalidToken(
                "pwdreset-token-consume-failed::".to_string(),
            ));
        }

        // 第 4 段：凭据提交（消费已成功，token 从此不可复用）
        let original = current.clone();
        let original_secret_hash = current.secret_data.clone();
        let new_hash = self.hasher.hash(new_password)?;
        let mut updated = current;
        updated.secret_data = new_hash.clone();
        self.credentials.update(&claims.sub, updated).await?;

        // 被替换的当前 hash 也入历史：否则 P1→P2 后历史只有 [P2]，
        // 再改回 P1 时 recent() 查不到 → 两条密码交替即可绕过 HistoryRule；
        // 存量用户（016 迁移空表）同样依赖本条闭合「重置为当前密码」检测
        if let Err(e) = self
            .history
            .append(tenant_id, &claims.sub, &original_secret_hash)
            .await
        {
            tracing::error!(
                error = %e,
                "password history append (replaced generation) failed; current-generation hash may be invisible to HistoryRule"
            );
        }
        if let Err(e) = self.history.append(tenant_id, &claims.sub, &new_hash).await {
            // 历史追加失败：尽力回滚凭据到原 hash（失败仅告警，不掩盖原始错误）
            if let Err(re) = self.credentials.update(&claims.sub, original).await {
                tracing::error!(
                    error = %re,
                    "password history append failed and credential rollback also failed; credential may be inconsistent"
                );
            }
            return Err(e);
        }
        Ok(())
    }
}

/// 标识结构校验（DAO key 注入防护）：非空、无 `:`、无控制字符、长度 ≤ 254。
///
/// 与 `secure/email` 的 `validate_email` 同口径（key 注入 + DoS 防护）；
/// 标识可为邮箱或用户名，故不强制 `@`。校验先于限流计数——非法请求
/// 不消耗配额。
fn validate_identifier(identifier: &str) -> GarrisonResult<()> {
    if identifier.is_empty()
        || identifier.len() > 254
        || identifier.contains(':')
        || identifier.chars().any(|c| c.is_control())
    {
        return Err(GarrisonError::InvalidParam(format!(
            "pwdreset-identifier-invalid::len={}",
            identifier.len()
        )));
    }
    Ok(())
}

/// 邮箱脱敏：保留首字符 + `***` + `@` + 域名（模块内本地实现，对齐
/// secure/email 侧 `mask_email_for_log` 先例——secure-masking 是独立 feature，
/// 跨模块引用会在单 feature 组合下编译失败）。
fn mask_email_for_log(email: &str) -> String {
    match email.find('@') {
        Some(at_pos) if at_pos > 0 => {
            let first = email[..at_pos].chars().next().unwrap_or('*');
            format!("{first}***{}", &email[at_pos..])
        },
        _ => "*".repeat(email.chars().count()),
    }
}

/// 标识规范化（trim + 小写化，对齐 email-verification 的 normalize 惯例）。
fn normalize_identifier(identifier: &str) -> String {
    identifier.trim().to_lowercase()
}

/// 防枚举限流 key：`pwdreset:rate:{identifier}`。
pub(crate) fn rate_key(identifier: &str) -> String {
    format!("{}rate:{}", DaoKeyPrefix::PasswordReset, identifier)
}

/// code-subject 绑定 key：`pwdreset:bind:{jti}`。
pub(crate) fn binding_key(jti: &str) -> String {
    format!("{}bind:{}", DaoKeyPrefix::PasswordReset, jti)
}

/// code-tenant 绑定 key：`pwdreset:bindt:{jti}`。
///
/// 记录 ActionToken 签发时的 tenant_id，`reset` 校验请求租户一致
/// （subject∈tenant 校验，渗透-租户隔离-标识符注册表-1）。
pub(crate) fn binding_tenant_key(jti: &str) -> String {
    format!("{}bindt:{}", DaoKeyPrefix::PasswordReset, jti)
}

/// 渲染找回邮件主题/正文（走 i18n FTL，禁止硬编码文案；与
/// `secure/email` 的 FTL 惯例一致）。
fn render_mail(token: &str) -> (String, String) {
    let subject = crate::i18n::translate_detail("pwdreset-mail-subject", &[]);
    let minutes = (super::action_token::DEFAULT_TOKEN_TTL_SECS / 60).to_string();
    let body = crate::i18n::translate_detail(
        "pwdreset-mail-body",
        &[("token", token), ("minutes", minutes.as_str())],
    );
    (subject, body)
}
