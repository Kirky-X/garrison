// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 找回密码流程测试。
//!
//! 每个行为属性一个测试（断言具体行为，非「不报错」）：
//! - ActionToken：roundtrip / purpose 不符拒 / 过期拒 / 篡改拒
//! - 一次性消费：二次消费拒 / 并发消费仅一成功
//! - 两段式防竞态：消费失败路径无凭据变更 / 成功路径凭据更新且 token 不可复用
//! - 防枚举：存在/不存在标识响应不可区分且限流计数均递增
//! - 绑定与历史：跨用户 token 拒 / 历史密码重用拒
//! - restricted 会话：仅改密端点可达，其余 403

use super::action_token::{ActionTokenClaims, ActionTokenService, PURPOSE_PASSWORD_RESET};
use crate::error::{GarrisonError, GarrisonResult};
use crate::protocol::jwt::JwtHandler;
use std::sync::Arc;

/// 测试用 JWT 密钥（≥ 32 字节，满足 JwtHandler 最小长度检查）。
const TEST_SECRET: &str = "pwdreset-test-secret-0123456789abcdef";

/// 构造 ActionTokenService（默认 TTL）。
fn token_service() -> ActionTokenService {
    ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)))
}

// ============================================================================
// ActionToken：自包含 JWT（sub/purpose=password_reset/jti/exp）
// ============================================================================

/// 签发→校验 roundtrip：claims 原样可读，purpose 固定 password_reset，jti 非空，
/// exp = iat + TTL。
#[test]
fn action_token_roundtrip_carries_sub_purpose_jti_exp() {
    let service = token_service();
    let issued = service.issue("alice").expect("签发应成功");
    let claims = service.verify(&issued.token).expect("校验应成功");
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.purpose, PURPOSE_PASSWORD_RESET);
    assert_eq!(claims.jti, issued.claims.jti);
    assert!(!claims.jti.is_empty(), "jti 必须非空（一次性消费主键）");
    assert_eq!(
        claims.exp - claims.iat,
        super::action_token::DEFAULT_TOKEN_TTL_SECS,
        "exp 应为 iat + 默认 TTL"
    );
}

/// 两次签发 jti 必须不同（一次性消费语义依赖 jti 全局唯一）。
#[test]
fn action_token_issue_generates_distinct_jti() {
    let service = token_service();
    let a = service.issue("alice").expect("签发应成功");
    let b = service.issue("alice").expect("签发应成功");
    assert_ne!(a.claims.jti, b.claims.jti, "同主体两次签发 jti 应不同");
}

/// purpose 不符拒绝：同密钥签发的其他用途 token 不得通过改密校验。
#[test]
fn action_token_rejects_wrong_purpose() {
    let handler = Arc::new(JwtHandler::new(TEST_SECRET));
    let service = token_service();
    let now = super::action_token::unix_now().expect("时钟应正常");
    let forged = handler
        .sign_custom(&ActionTokenClaims {
            sub: "alice".to_string(),
            purpose: "email_verify".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now,
            exp: now + 600,
        })
        .expect("同密钥签发的其他用途 token 应可构造");
    let err = service
        .verify(&forged)
        .expect_err("purpose 不符的 token 必须拒绝");
    assert!(
        matches!(err, GarrisonError::InvalidToken(ref m) if m.contains("action-token-purpose-mismatch")),
        "应返回 purpose 不符的显性 InvalidToken，实际: {err:?}"
    );
}

/// 过期拒绝：exp 已过时刻的 token 拒绝（leeway=0，不容忍时钟偏差）。
#[test]
fn action_token_rejects_expired() {
    let handler = Arc::new(JwtHandler::new(TEST_SECRET));
    let service = token_service();
    let now = super::action_token::unix_now().expect("时钟应正常");
    let expired = handler
        .sign_custom(&ActionTokenClaims {
            sub: "alice".to_string(),
            purpose: PURPOSE_PASSWORD_RESET.to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now - 600,
            exp: now - 1,
        })
        .expect("exp 已过时刻的 token 应可构造");
    let err = service.verify(&expired).expect_err("过期 token 必须拒绝");
    assert!(
        matches!(err, GarrisonError::ExpiredToken(_)),
        "应返回 ExpiredToken，实际: {err:?}"
    );
}

/// 负 TTL 显性拒绝（签发期 fail-fast，不产出非法 token）。
#[test]
fn action_token_rejects_negative_ttl() {
    let err = token_service().with_ttl(-1).expect_err("负 TTL 必须拒绝");
    assert!(
        matches!(err, GarrisonError::InvalidParam(ref m) if m.contains("pwdreset-ttl-negative")),
        "应返回显性 InvalidParam，实际: {err:?}"
    );
}

/// 篡改 payload 拒绝（签名校验）。
#[test]
fn action_token_rejects_tampered_payload() {
    let service = token_service();
    let issued = service.issue("alice").expect("签发应成功");
    // JWT 三段式：翻转载荷段最后一个 base64 字符，构造必然破坏签名的变体
    let mut chars: Vec<char> = issued.token.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert_ne!(tampered, issued.token, "篡改后 token 必须与原 token 不同");
    let err = service.verify(&tampered).expect_err("篡改 token 必须拒绝");
    assert!(
        matches!(
            err,
            GarrisonError::InvalidToken(_) | GarrisonError::ExpiredToken(_)
        ),
        "应返回签名类拒绝错误，实际: {err:?}"
    );
}

// ============================================================================
// 找回流程端到端（两段式防竞态 / 防枚举 / 绑定与历史 / restricted 会话）
// ============================================================================

use super::consumer::ActionTokenConsumer;
use super::restricted::{RestrictedSessionGuard, ENDPOINT_PASSWORD_CHANGE, RESTRICTED_ATTR_KEY};
use super::service::{
    binding_key, binding_tenant_key, rate_key, PasswordResetService, ResetIdentityResolver,
    ResetMailSender,
};
use crate::account::credential::password::{Argon2Hasher, PasswordHasher as _};
use crate::account::credential::{CredentialModel, CredentialRepository, DaoCredentialRepository};
use crate::account::policy::rules::HistoryRule;
use crate::account::policy::{ErrorMode, PasswordPolicyEngine};
use crate::dao::repository::PasswordHistoryRepository;
use crate::dao::{GarrisonDao, InMemoryDao};
use crate::session::GarrisonSession;
use crate::stp::LoginParams;

const TENANT: i64 = 1;

/// 测试标识解析器：HashMap 映射，未命中返回 None（未知标识路径）。
struct MapResolver {
    entries: std::collections::HashMap<String, String>,
}

#[async_trait::async_trait]
impl ResetIdentityResolver for MapResolver {
    async fn resolve_subject(
        &self,
        _tenant_id: i64,
        identifier: &str,
    ) -> GarrisonResult<Option<String>> {
        Ok(self.entries.get(identifier).cloned())
    }
}

fn map_resolver(entries: &[(&str, &str)]) -> MapResolver {
    MapResolver {
        entries: entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

/// 测试邮件发送器：记录交付三元组（收件人/主题/正文）。
#[derive(Default)]
struct RecordingSender {
    deliveries: std::sync::Mutex<Vec<(String, String, String)>>,
}

impl RecordingSender {
    /// 等待投递到达（投递已改为 fire-and-forget spawn，请求返回不等 SMTP）。
    /// 必须 async：current-thread 测试 runtime 下 spawn 的任务仅在 yield 点
    /// 被 poll，阻塞式等待会让其永远不被执行。2s 上界超时 panic。
    async fn wait_for_deliveries(&self, min: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while self.deliveries.lock().unwrap().len() < min {
            if std::time::Instant::now() >= deadline {
                panic!(
                    "等待投递超时：期望 ≥{min} 封，实际 {}",
                    self.deliveries.lock().unwrap().len()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

#[async_trait::async_trait]
impl ResetMailSender for RecordingSender {
    async fn deliver(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()> {
        self.deliveries.lock().unwrap().push((
            to.to_string(),
            subject.to_string(),
            body.to_string(),
        ));
        Ok(())
    }
}

/// 测试密码历史：插入序倒序即 recent 顺序（新在前）。
#[derive(Default)]
struct InMemoryHistory {
    entries: std::sync::Mutex<Vec<(i64, String, String)>>,
}

#[async_trait::async_trait]
impl PasswordHistoryRepository for InMemoryHistory {
    async fn append(
        &self,
        tenant_id: i64,
        user_id: &str,
        password_hash: &str,
    ) -> GarrisonResult<()> {
        self.entries.lock().unwrap().push((
            tenant_id,
            user_id.to_string(),
            password_hash.to_string(),
        ));
        Ok(())
    }

    async fn recent(
        &self,
        tenant_id: i64,
        user_id: &str,
        limit: u32,
    ) -> GarrisonResult<Vec<String>> {
        let guard = self.entries.lock().unwrap();
        Ok(guard
            .iter()
            .rev()
            .filter(|(t, u, _)| *t == tenant_id && u == user_id)
            .take(limit as usize)
            .map(|(_, _, h)| h.clone())
            .collect())
    }
}

/// append 恒失败的实现（回滚路径测试）。
struct FailingAppendHistory;

#[async_trait::async_trait]
impl PasswordHistoryRepository for FailingAppendHistory {
    async fn append(&self, _t: i64, _u: &str, _h: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "pwdreset-test-append-failure".to_string(),
        ))
    }

    async fn recent(&self, _t: i64, _u: &str, _l: u32) -> GarrisonResult<Vec<String>> {
        Ok(Vec::new())
    }
}

/// 组装被测服务（测试桩注入）。
fn make_service(
    dao: &Arc<InMemoryDao>,
    session: &Arc<GarrisonSession>,
    policy: PasswordPolicyEngine,
    history: Arc<dyn PasswordHistoryRepository>,
    resolver: MapResolver,
    sender: &Arc<RecordingSender>,
    tokens: &ActionTokenService,
) -> PasswordResetService {
    PasswordResetService::new(
        dao.clone(),
        session.clone(),
        tokens.clone(),
        Arc::new(DaoCredentialRepository::new(dao.clone())),
        Arc::new(Argon2Hasher::default()),
        policy,
        history,
        Arc::new(resolver),
        sender.clone(),
    )
}

/// 创建恢复会话（宿主在用户点击邮件链接后创建的 Token-Session）。
async fn ensure_token_session(session: &GarrisonSession, login_id: &str, token: &str) {
    session
        .create_token_session(
            login_id,
            token,
            &LoginParams {
                device: None,
                ip: None,
                user_agent: None,
                remember_me: false,
                require_mfa: false,
            },
        )
        .await
        .expect("创建恢复会话应成功");
}

/// 预置密码凭据，返回其 hash。
async fn seed_credential(
    creds: &DaoCredentialRepository,
    hasher: &Argon2Hasher,
    user_id: &str,
    password: &str,
) -> String {
    let hash = hasher.hash(password).expect("hash 应成功");
    creds
        .create(CredentialModel {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            credential_type: "password".to_string(),
            secret_data: hash.clone(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        })
        .await
        .expect("seed credential 应成功");
    hash
}

/// 读取用户当前密码凭据 hash。
async fn stored_hash(creds: &DaoCredentialRepository, user_id: &str) -> String {
    let model = creds
        .find_by_user(user_id, user_id)
        .await
        .expect("查询凭据应成功")
        .remove(0);
    model.secret_data.clone()
}

/// 从邮件正文提取一次性 token（正文含 `/reset-password?token={token}`）。
fn extract_token(body: &str) -> &str {
    body.split("token=")
        .nth(1)
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
}

// ============================================================================
// jti 一次性消费
// ============================================================================

/// 首次消费成功，二次消费返回 false（原子 SETNX 语义）。
#[tokio::test]
async fn jti_consume_first_call_succeeds_second_fails() {
    let dao = Arc::new(InMemoryDao::new());
    let consumer = ActionTokenConsumer::new(dao);
    assert!(
        consumer
            .consume("jti-once", 60)
            .await
            .expect("首次消费应成功"),
        "首次消费应返回 true"
    );
    assert!(
        !consumer
            .consume("jti-once", 60)
            .await
            .expect("二次消费应返回 false 而非报错"),
        "二次消费必须被拒"
    );
}

/// 10 个并发消费同一 jti：恰一赢家。
#[tokio::test]
async fn jti_concurrent_consume_exactly_one_winner() {
    let dao = Arc::new(InMemoryDao::new());
    let consumer = Arc::new(ActionTokenConsumer::new(dao));
    let attempts: Vec<_> = (0..10)
        .map(|_| {
            let c = consumer.clone();
            async move { c.consume("jti-race", 60).await.expect("消费调用不应报错") }
        })
        .collect();
    let winners = futures::future::join_all(attempts).await;
    assert_eq!(
        winners.into_iter().filter(|w| *w).count(),
        1,
        "并发消费同一 jti 应恰一成功"
    );
}

// ============================================================================
// 两段式防竞态
// ============================================================================

/// 消费失败路径无凭据变更；成功路径凭据更新、token 不可复用、restricted 标记保留。
#[tokio::test]
async fn two_phase_consume_failure_leaves_credential_unchanged() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let creds = DaoCredentialRepository::new(dao.clone());
    let hasher = Argon2Hasher::default();
    let first_hash = seed_credential(&creds, &hasher, "carol", "FirstPass1!").await;
    // 最小策略集：本测试聚焦两段式竞态属性，不注入规则
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("carol@x.com", "carol")]),
        &sender,
        &tokens,
    );
    ensure_token_session(&session, "carol", "sess-carol").await;
    service
        .request_reset(TENANT, "carol@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 1, "已知标识应交付一封邮件");
        extract_token(&deliveries[0].2).to_string()
    };

    service
        .reset(TENANT, "sess-carol", &token, "SecondPass2!")
        .await
        .expect("首次重置应成功");
    let after_first = stored_hash(&creds, "carol").await;
    assert_ne!(after_first, first_hash, "首次重置应更新凭据");
    assert!(
        hasher
            .verify("SecondPass2!", &after_first)
            .expect("verify 应成功"),
        "首次重置后凭据应为新密码"
    );

    // 二次消费同一 token：消费失败路径，凭据必须保持首次重置后的值
    let err = service
        .reset(TENANT, "sess-carol", &token, "ThirdPass3!")
        .await
        .expect_err("二次消费必须拒绝");
    assert!(
        matches!(err, GarrisonError::InvalidToken(ref m) if m.contains("pwdreset-token-consume-failed")),
        "应返回消费失败的显性 InvalidToken，实际: {err:?}"
    );
    let after_second = stored_hash(&creds, "carol").await;
    assert_eq!(after_second, after_first, "消费失败路径不得变更凭据");
    assert!(
        !hasher
            .verify("ThirdPass3!", &after_second)
            .expect("verify 应成功"),
        "消费失败路径的第三密码不得生效"
    );

    // restricted 标记在 reset 返回后保留（fail-safe：恢复会话始终只可达改密端点）
    let marker = session
        .get("sess-carol", RESTRICTED_ATTR_KEY)
        .await
        .expect("会话查询应成功");
    assert!(marker.is_some(), "恢复会话的 restricted 标记应保留");
}

/// restricted 会话端点约束：仅改密端点可达，其余 403；清除后放行。
#[tokio::test]
async fn restricted_session_endpoint_constraints() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    ensure_token_session(&session, "alice", "sess-alice").await;

    // 无标记：任意端点放行（按既有权限体系）
    RestrictedSessionGuard::check_endpoint(&session, "sess-alice", "profile_view")
        .await
        .expect("无标记会话不应受限");

    let guard = RestrictedSessionGuard::grant(session.clone(), "sess-alice")
        .await
        .expect("授权应成功");
    RestrictedSessionGuard::check_endpoint(&session, "sess-alice", ENDPOINT_PASSWORD_CHANGE)
        .await
        .expect("改密端点应可达");
    let err = RestrictedSessionGuard::check_endpoint(&session, "sess-alice", "profile_view")
        .await
        .expect_err("非改密端点必须 403");
    assert!(
        matches!(err, GarrisonError::NotPermission(_)),
        "应返回 NotPermission（403），实际: {err:?}"
    );

    guard.clear().await.expect("显式清除应成功");
    RestrictedSessionGuard::check_endpoint(&session, "sess-alice", "profile_view")
        .await
        .expect("显式清除后应放行");
}

// ============================================================================
// 防枚举
// ============================================================================

/// 存在/不存在标识：响应不可区分且限流计数均递增；邮件只交付给真实收件人。
#[tokio::test]
async fn request_outcome_indistinguishable_and_rate_counts_increment() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("known@x.com", "user-1")]),
        &sender,
        &tokens,
    );

    let known = service
        .request_reset(TENANT, "Known@X.com")
        .await
        .expect("已知标识请求应成功");
    let unknown = service
        .request_reset(TENANT, "unknown@x.com")
        .await
        .expect("未知标识请求应成功");
    assert_eq!(known, unknown, "存在/不存在标识的响应必须不可区分");
    assert_eq!(known.rate_count, 1, "两类路径限流计数均应递增");

    assert_eq!(
        dao.get(&rate_key("known@x.com"))
            .await
            .expect("读计数应成功")
            .as_deref(),
        Some("1"),
        "已知标识限流计数应递增"
    );
    assert_eq!(
        dao.get(&rate_key("unknown@x.com"))
            .await
            .expect("读计数应成功")
            .as_deref(),
        Some("1"),
        "未知标识限流计数应递增（同路径同规则）"
    );

    sender.wait_for_deliveries(1).await;
    let deliveries = sender.deliveries.lock().unwrap();
    assert_eq!(deliveries.len(), 1, "邮件只交付给真实存在的收件人");
    assert_eq!(
        deliveries[0].0, "known@x.com",
        "收件人应为规范化后的已知标识"
    );
}

/// 超过窗口内最大请求数：RateLimited（与登录限流同错误码）。
#[tokio::test]
async fn request_rate_limit_blocks_after_max() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[]),
        &sender,
        &tokens,
    )
    .with_rate_limit(3600, 2);

    service
        .request_reset(TENANT, "u@x.com")
        .await
        .expect("第 1 次应成功");
    service
        .request_reset(TENANT, "u@x.com")
        .await
        .expect("第 2 次应成功");
    let err = service
        .request_reset(TENANT, "u@x.com")
        .await
        .expect_err("第 3 次必须限流");
    assert!(
        matches!(
            err,
            GarrisonError::RateLimited {
                retry_after_secs: 3600
            }
        ),
        "应返回 RateLimited 且建议等待一个窗口，实际: {err:?}"
    );
}

// ============================================================================
// 绑定与历史
// ============================================================================

/// 跨用户 token（绑定主体与 token.sub 不一致）被拒。
#[tokio::test]
async fn cross_user_token_rejected_by_subject_binding() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let creds = DaoCredentialRepository::new(dao.clone());
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("alice@x.com", "alice")]),
        &sender,
        &tokens,
    );
    service
        .request_reset(TENANT, "alice@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        extract_token(&deliveries[0].2).to_string()
    };
    let claims = tokens.verify(&token).expect("token 应可校验");
    assert_eq!(claims.sub, "alice");

    // 绑定记录被改写为他人（模拟跨用户挪用/绑定篡改）
    dao.set(&binding_key(&claims.jti), "bob", 600)
        .await
        .expect("改写绑定应成功");
    dao.set(&binding_tenant_key(&claims.jti), &TENANT.to_string(), 600)
        .await
        .expect("改写租户绑定应成功");
    ensure_token_session(&session, "bob", "sess-bob").await;
    let err = service
        .reset(TENANT, "sess-bob", &token, "NewPass9!")
        .await
        .expect_err("跨用户 token 必须拒绝");
    assert!(
        matches!(err, GarrisonError::NotPermission(ref m) if m.contains("pwdreset-subject-binding-mismatch")),
        "应返回跨用户挪用的 NotPermission，实际: {err:?}"
    );
    assert!(
        creds
            .find_by_user("bob", "bob")
            .await
            .expect("查询 bob 凭据应成功")
            .is_empty(),
        "被拒路径不得为 bob 建立凭据"
    );
}

/// 跨租户重置被拒（subject∈tenant 校验，渗透-租户隔离-标识符注册表-1）：
/// 请求租户与签发租户不一致时拒绝，凭据零变更，错误不泄露归属信息。
#[tokio::test]
async fn cross_tenant_reset_rejected_without_ownership_leak() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let creds = DaoCredentialRepository::new(dao.clone());
    let hasher = Argon2Hasher::default();
    let original_hash = seed_credential(&creds, &hasher, "alice", "OldPass1!").await;
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("alice@x.com", "alice")]),
        &sender,
        &tokens,
    );
    ensure_token_session(&session, "alice", "sess-alice").await;
    service
        .request_reset(TENANT, "alice@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        extract_token(&deliveries[0].2).to_string()
    };

    // 他租户（2）携带合法 token 重置租户 1 主体：必须拒绝
    let other_tenant = TENANT + 1;
    let err = service
        .reset(other_tenant, "sess-alice", &token, "NewPass9!")
        .await
        .expect_err("跨租户重置必须拒绝");
    assert!(
        matches!(err, GarrisonError::NotPermission(ref m) if m.contains("pwdreset-tenant-mismatch")),
        "应返回跨租户拒绝的 NotPermission，实际: {err:?}"
    );
    let err_text = format!("{err:?}");
    assert!(
        !err_text.contains("alice") && !err_text.contains(&TENANT.to_string()),
        "错误信息不得泄露归属主体/签发租户，实际: {err_text}"
    );
    // 凭据零变更（被拒路径在消费之前）
    let after = stored_hash(&creds, "alice").await;
    assert_eq!(after, original_hash, "被拒路径不得变更凭据");
    // 同租户重放同 token 仍可成功（token 未被跨租户路径消费）
    service
        .reset(TENANT, "sess-alice", &token, "NewPass9!")
        .await
        .expect("同租户重置应成功");
}

/// 升级前旧 token（无 tenant 绑定键）fail-closed 拒绝，不静默降级为无租户校验。
#[tokio::test]
async fn legacy_token_without_tenant_binding_fail_closed() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("alice@x.com", "alice")]),
        &sender,
        &tokens,
    );
    ensure_token_session(&session, "alice", "sess-alice").await;
    service
        .request_reset(TENANT, "alice@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        extract_token(&deliveries[0].2).to_string()
    };
    let claims = tokens.verify(&token).expect("token 应可校验");

    // 模拟升级前签发的 token：删除 tenant 绑定键，仅保留 subject 绑定
    dao.delete(&binding_tenant_key(&claims.jti))
        .await
        .expect("删除 tenant 绑定应成功");

    let err = service
        .reset(TENANT, "sess-alice", &token, "NewPass9!")
        .await
        .expect_err("缺 tenant 绑定的旧 token 必须 fail-closed 拒绝");
    assert!(
        matches!(err, GarrisonError::InvalidToken(ref m) if m.contains("pwdreset-tenant-binding-missing")),
        "应返回 tenant 绑定缺失的显性 InvalidToken，实际: {err:?}"
    );
}

/// 重用历史密码被拒（HistoryRule）：token 未消费、凭据不变，可换密码重试。
#[tokio::test]
async fn reused_history_password_rejected_and_token_not_consumed() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let creds = DaoCredentialRepository::new(dao.clone());
    let hasher = Argon2Hasher::default();
    let history = Arc::new(InMemoryHistory::default());
    let old_hash = seed_credential(&creds, &hasher, "dave", "OldPass1!").await;
    // 注册路径追加的历史（host 责任），使「当前密码」在历史中可查
    history
        .append(TENANT, "dave", &old_hash)
        .await
        .expect("追加历史应成功");
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(vec![Box::new(HistoryRule::new(3))], ErrorMode::FirstError),
        history.clone(),
        map_resolver(&[("dave@x.com", "dave")]),
        &sender,
        &tokens,
    );
    let consumer = ActionTokenConsumer::new(dao.clone());
    ensure_token_session(&session, "dave", "sess-dave").await;
    service
        .request_reset(TENANT, "dave@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        extract_token(&deliveries[0].2).to_string()
    };

    // 重用历史密码：策略拒绝
    let err = service
        .reset(TENANT, "sess-dave", &token, "OldPass1!")
        .await
        .expect_err("重用历史密码必须拒绝");
    assert!(
        matches!(err, GarrisonError::InvalidParam(ref m) if m.contains("pwdreset-policy-violated")),
        "应返回策略拒绝的 InvalidParam，实际: {err:?}"
    );
    let claims = tokens.verify(&token).expect("token 应可校验");
    assert!(
        !consumer
            .is_consumed(&claims.jti)
            .await
            .expect("查询消费状态应成功"),
        "策略失败不得消费 token（用户可换密码重试）"
    );
    assert_eq!(
        stored_hash(&creds, "dave").await,
        old_hash,
        "策略失败路径凭据不变"
    );

    // 换新密码重试（同一 token）：成功 + 历史追加
    service
        .reset(TENANT, "sess-dave", &token, "NewPass2!")
        .await
        .expect("换密码重试应成功");
    assert!(
        hasher
            .verify("NewPass2!", &stored_hash(&creds, "dave").await)
            .expect("verify 应成功"),
        "重试成功后凭据应为新密码"
    );
    assert_eq!(
        history
            .recent(TENANT, "dave", 10)
            .await
            .expect("读历史应成功")
            .len(),
        3, // 预置 1 条 + 被替换代 1 条 + 新密码 1 条
        "重置成功应追加被替换代与新密码到历史"
    );
}

/// 历史追加失败：凭据尽力回滚到原 hash，错误显性透传。
#[tokio::test]
async fn history_append_failure_rolls_back_credential() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let creds = DaoCredentialRepository::new(dao.clone());
    let hasher = Argon2Hasher::default();
    seed_credential(&creds, &hasher, "erin", "Pass1!").await;
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(FailingAppendHistory),
        map_resolver(&[("erin@x.com", "erin")]),
        &sender,
        &tokens,
    );
    ensure_token_session(&session, "erin", "sess-erin").await;
    service
        .request_reset(TENANT, "erin@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        extract_token(&deliveries[0].2).to_string()
    };
    let err = service
        .reset(TENANT, "sess-erin", &token, "NewPass2!")
        .await
        .expect_err("历史追加失败必须显性报错");
    assert!(
        matches!(err, GarrisonError::Dao(ref m) if m.contains("pwdreset-test-append-failure")),
        "应透传历史追加错误，实际: {err:?}"
    );
    assert!(
        hasher
            .verify("Pass1!", &stored_hash(&creds, "erin").await)
            .expect("verify 应成功"),
        "追加失败后凭据应回滚到原 hash"
    );
}

// ============================================================================
// 邮件通道
// ============================================================================

/// 邮件正文携带可校验 ActionToken 且与解析出的 subject 绑定（TTL 渲染非空）。
#[tokio::test]
async fn delivered_mail_carries_action_token_bound_to_subject() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("alice@x.com", "alice")]),
        &sender,
        &tokens,
    );
    service
        .request_reset(TENANT, "alice@x.com")
        .await
        .expect("请求应成功");
    sender.wait_for_deliveries(1).await;
    let deliveries = sender.deliveries.lock().unwrap();
    assert_eq!(deliveries.len(), 1);
    assert!(!deliveries[0].1.is_empty(), "主题应由 FTL 渲染");
    let token = extract_token(&deliveries[0].2);
    assert!(!token.is_empty(), "正文应携带一次性 token");
    let claims = tokens
        .verify(token)
        .expect("邮件中的 token 应为可校验 ActionToken");
    assert_eq!(claims.sub, "alice", "token 应绑定解析出的 subject");
    assert_eq!(claims.purpose, PURPOSE_PASSWORD_RESET);
}

/// 恢复会话归属校验：会话主体与 token.sub 不一致时拒绝（标记不得落到他人会话）。
#[tokio::test]
async fn reset_rejects_session_owned_by_other_subject() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let creds = DaoCredentialRepository::new(dao.clone());
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[("alice@x.com", "alice")]),
        &sender,
        &tokens,
    );
    service
        .request_reset(TENANT, "alice@x.com")
        .await
        .expect("请求应成功");
    let token = {
        sender.wait_for_deliveries(1).await;
        sender.wait_for_deliveries(1).await;
        let deliveries = sender.deliveries.lock().unwrap();
        extract_token(&deliveries[0].2).to_string()
    };
    // 恢复会话归属他人（bob 的会话拿 alice 的 token 改密）
    ensure_token_session(&session, "bob", "sess-bob").await;
    let err = service
        .reset(TENANT, "sess-bob", &token, "NewPass7!")
        .await
        .expect_err("他人会话必须拒绝");
    assert!(
        matches!(err, GarrisonError::NotPermission(ref m) if m.contains("pwdreset-session-subject-mismatch")),
        "应返回会话归属不匹配的 NotPermission，实际: {err:?}"
    );
    assert!(
        creds
            .find_by_user("alice", "alice")
            .await
            .expect("查询 alice 凭据应成功")
            .is_empty(),
        "被拒路径不得建立/变更 alice 凭据"
    );
}

/// 非法标识（空/超长/含冒号/控制字符）显性拒绝且不递增限流计数。
#[tokio::test]
async fn request_rejects_invalid_identifier_without_counting() {
    let dao = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let sender = Arc::new(RecordingSender::default());
    let tokens = ActionTokenService::new(Arc::new(JwtHandler::new(TEST_SECRET)));
    let service = make_service(
        &dao,
        &session,
        PasswordPolicyEngine::new(Vec::new(), ErrorMode::FirstError),
        Arc::new(InMemoryHistory::default()),
        map_resolver(&[]),
        &sender,
        &tokens,
    );
    for bad in ["", "a".repeat(255).as_str(), "with:colon", "ctrl\u{7f}"] {
        let err = service
            .request_reset(TENANT, bad)
            .await
            .expect_err("非法标识必须拒绝");
        assert!(
            matches!(err, GarrisonError::InvalidParam(ref m) if m.contains("pwdreset-identifier-invalid")),
            "标识 {bad:?} 应返回显性 InvalidParam，实际: {err:?}"
        );
    }
    assert_eq!(
        dao.get(&rate_key("")).await.expect("读计数应成功"),
        None,
        "被拒请求不得递增限流计数（校验先于计数）"
    );
}
