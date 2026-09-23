// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! qrlogin 协议模块单元测试。
//!
//! 覆盖：构造校验、serde 往返、create/scan/confirm/poll 全状态机路径、
//! 票据签名与域名白名单、原子兑换并发语义。

use super::QrLoginService;
use super::{
    QrLoginAction, QrLoginConfig, QrLoginPollOutcome, QrLoginSessionData, QrLoginStatus,
    QrLoginWebContext,
};
use crate::dao::InMemoryDao;
use crate::error::GarrisonError;
use crate::i18n::{set_locale, GarrisonLocale};
use std::sync::Arc;

/// 构造默认配置的测试服务。
fn service() -> QrLoginService {
    QrLoginService::new(
        Arc::new(InMemoryDao::new()),
        "test-secret-key-0123456789abcdef-0123456789abcdef",
    )
    .unwrap()
}

/// 构造带域名白名单的测试服务。
fn service_with_domains(domains: &[&str]) -> QrLoginService {
    QrLoginService::new(
        Arc::new(InMemoryDao::new()),
        "test-secret-key-0123456789abcdef-0123456789abcdef",
    )
    .unwrap()
    .with_config(QrLoginConfig {
        allowed_domains: Some(domains.iter().map(|s| (*s).to_string()).collect()),
        ..Default::default()
    })
}

/// 构造待登录端上下文。
fn web_context() -> QrLoginWebContext {
    QrLoginWebContext {
        ip: Some("203.0.113.7".to_string()),
        user_agent: Some(
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
                .to_string(),
        ),
        created_at_ms: 1_725_000_000_000,
    }
}

/// 从 qr_content 提取 t 参数票据（测试断言验签用）。
fn ticket_of(qr_content: &str) -> &str {
    qr_content
        .split("t=")
        .nth(1)
        .expect("qr_content 应含 t= 参数")
}

/// 断言错误消息含指定英文文案片段（loc! 命中 FTL 与 fallback 的 En 文案一致，
/// 断言稳定；locale 显式锁 En 消除系统探测差异）。
fn assert_error_text(err: &GarrisonError, text: &str) {
    set_locale(GarrisonLocale::En);
    let rendered = match err {
        GarrisonError::InvalidParam(m)
        | GarrisonError::InvalidToken(m)
        | GarrisonError::Dao(m)
        | GarrisonError::Internal(m) => m.clone(),
        other => format!("{other:?}"),
    };
    assert!(rendered.contains(text), "应含 {text:?}，实际: {rendered}");
}

// ============================================================================
// 构造校验与 serde（T003）
// ============================================================================

/// 空 secret 拒绝构造，错误为 InvalidParam。
#[tokio::test]
async fn new_rejects_empty_secret() {
    let err = QrLoginService::new(Arc::new(InMemoryDao::new()), "")
        .expect_err("empty secret must be rejected");
    assert_error_text(&err, "secret must not be empty");
}

/// 31 字节 secret 拒绝构造（强度下限 = 32 字节，对齐 JWT HS256）。
#[tokio::test]
async fn new_rejects_short_secret() {
    let err = QrLoginService::new(Arc::new(InMemoryDao::new()), "a".repeat(31))
        .expect_err("31-byte secret must be rejected");
    assert_error_text(&err, "at least 32 bytes");
}

/// 32 字节 secret 恰好通过强度下限。
#[tokio::test]
async fn new_accepts_32_byte_secret() {
    let svc = QrLoginService::new(Arc::new(InMemoryDao::new()), "b".repeat(32))
        .expect("32-byte secret must be accepted");
    assert!(
        svc.with_config(QrLoginConfig::default())
            .config
            .session_ttl_secs
            > 0
    );
}

/// QrLoginSessionData serde 往返相等。
#[test]
fn session_data_serde_roundtrip() {
    let data = QrLoginSessionData {
        qr_id: "abc123".to_string(),
        status: QrLoginStatus::Scanned,
        tenant_id: 3,
        app_login_id: Some("user-1".to_string()),
        confirm_token_hash: Some("deadbeef".to_string()),
        web: web_context(),
    };
    let json = serde_json::to_string(&data).unwrap();
    let back: QrLoginSessionData = serde_json::from_str(&json).unwrap();
    assert_eq!(back.qr_id, data.qr_id);
    assert_eq!(back.status, data.status);
    assert_eq!(back.tenant_id, data.tenant_id);
    assert_eq!(back.app_login_id, data.app_login_id);
    assert_eq!(back.confirm_token_hash, data.confirm_token_hash);
    assert_eq!(back.web.ip, data.web.ip);
    assert_eq!(back.web.user_agent, data.web.user_agent);
    assert_eq!(back.web.created_at_ms, data.web.created_at_ms);
}

/// tenant_id 缺省反序列化为 0（serde default）。
#[test]
fn session_data_tenant_defaults_to_zero() {
    let json = r#"{"qr_id":"x","status":"Pending","web":{}}"#;
    let data: QrLoginSessionData = serde_json::from_str(json).unwrap();
    assert_eq!(data.tenant_id, 0);
    assert_eq!(data.status, QrLoginStatus::Pending);
    assert!(data.app_login_id.is_none());
    assert_eq!(data.web.created_at_ms, 0);
}

// ============================================================================
// create / scan / confirm / poll 状态机（T004-T007）
// ============================================================================

/// create 返回可验签的 qr_content，会话落盘为 Pending。
#[tokio::test]
async fn create_issues_signed_ticket_and_pending_session() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    assert_eq!(created.expires_in_secs, 120);
    assert_eq!(created.qr_id.len(), 64, "qr_id 应为 64 hex");
    assert_eq!(created.bind_token.len(), 64, "bind_token 应为 64 hex");
    // 二维码票据不得携带 bind_token（它是 poll 第二票，仅 create 响应下发）
    assert!(
        !created.qr_content.contains(&created.bind_token),
        "二维码内容不得泄露 bind_token"
    );
    // qr_content 的 t 参数票据可验签还原 qr_id
    let qr_id = svc
        .verify_ticket_signature(ticket_of(&created.qr_content))
        .unwrap();
    assert_eq!(qr_id, created.qr_id);

    let data = svc.load_session(&created.qr_id).await.unwrap().unwrap();
    assert_eq!(data.status, QrLoginStatus::Pending);
    assert_eq!(data.web.ip.as_deref(), Some("203.0.113.7"));
}

/// scan：Pending → Scanned，颁发一次性 confirm_token 与脱敏摘要。
#[tokio::test]
async fn scan_moves_pending_to_scanned_and_issues_confirm_token() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();

    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    assert_eq!(view.expires_in_secs, 60);
    assert_eq!(view.web_created_at_ms, 1_725_000_000_000);
    assert_eq!(view.web_device_label, "Chrome", "UA 应解析为 Chrome");
    assert!(!view.confirm_token.is_empty());

    let data = svc.load_session(&created.qr_id).await.unwrap().unwrap();
    assert_eq!(data.status, QrLoginStatus::Scanned);
    assert_eq!(data.app_login_id.as_deref(), Some("user-1"));
    assert_eq!(
        data.confirm_token_hash.as_deref(),
        Some(QrLoginService::token_digest(&view.confirm_token).as_str())
    );
}

/// scan：非法签名票据拒绝（无白名单配置时跳过域名校验，仍验签）。
#[tokio::test]
async fn scan_rejects_forged_ticket() {
    let svc = service();
    let err = svc
        .scan(
            "garrison://qrlogin?t=forged_random.not_a_valid_sig",
            "user-1",
            None,
        )
        .await
        .unwrap_err();
    assert_error_text(&err, "ticket signature is invalid");
}

/// scan：白名单模式下 create 使用白名单域名拼 qr_content，scan 放行。
#[tokio::test]
async fn scan_allows_allowlisted_domain() {
    let svc = service_with_domains(&["app.example.com"]);
    let created = svc.create_session(web_context()).await.unwrap();
    assert!(
        created.qr_content.starts_with("https://app.example.com/"),
        "白名单模式下 qr_content 应使用白名单域名，实际: {}",
        created.qr_content
    );
    svc.scan(&created.qr_content, "user-1", None).await.unwrap();
}

/// scan：白名单外域名的 qr_content 拒绝。
#[tokio::test]
async fn scan_rejects_non_allowlisted_domain() {
    let svc = service_with_domains(&["app.example.com"]);
    let created = svc.create_session(web_context()).await.unwrap();
    // 篡改 host 为白名单外域名（票据本身不变）
    let ticket = ticket_of(&created.qr_content);
    let evil = format!("https://evil.example.com/qrlogin/confirm?t={ticket}");
    let err = svc.scan(&evil, "user-1", None).await.unwrap_err();
    assert_error_text(&err, "domain is not allowed");
}

/// scan：重复扫码返回 already-scanned；App 取消后再扫返回 cancelled。
#[tokio::test]
async fn scan_rejects_repeated_scan_and_cancelled_session() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    let err = svc
        .scan(&created.qr_content, "user-1", None)
        .await
        .unwrap_err();
    assert_error_text(&err, "already been scanned");

    // App 确认页取消后再扫：cancelled
    let created2 = svc.create_session(web_context()).await.unwrap();
    let view2 = svc
        .scan(&created2.qr_content, "user-1", None)
        .await
        .unwrap();
    svc.confirm(&view2.confirm_token, "user-1", QrLoginAction::Cancel, None)
        .await
        .unwrap();
    let err2 = svc
        .scan(&created2.qr_content, "user-1", None)
        .await
        .unwrap_err();
    assert_error_text(&err2, "has been cancelled");
}

/// 非扫码者（另一登录用户）持他人 confirm_token 确认 → 拒绝，且错误与
/// 「token 无效」完全一致（身份绑定 + 防枚举）。
#[tokio::test]
async fn confirm_by_other_user_rejected_indistinguishable() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    let err = svc
        .confirm(&view.confirm_token, "user-2", QrLoginAction::Confirm, None)
        .await
        .expect_err("other user must not confirm");
    assert_error_text(&err, "confirm token is invalid");

    // 对照组：真实无效 token 的错误文本必须逐字一致（无区分度）
    let svc2 = service();
    let err2 = svc2
        .confirm("nonexistent-token", "user-1", QrLoginAction::Confirm, None)
        .await
        .expect_err("invalid token must fail");
    assert_eq!(format!("{}", err), format!("{}", err2));
}

/// confirm：Scanned → Confirmed；confirm_token 重放失败。
#[tokio::test]
async fn confirm_moves_scanned_to_confirmed_and_replay_fails() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();

    svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap();
    let data = svc.load_session(&created.qr_id).await.unwrap().unwrap();
    assert_eq!(data.status, QrLoginStatus::Confirmed);

    // 重放同一 confirm_token：原子消费后第二次失败
    let err = svc
        .confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap_err();
    assert_error_text(&err, "confirm token is invalid");
}

/// confirm：未扫码会话（Pending）确认返回 not-scanned。
#[tokio::test]
async fn confirm_pending_session_fails() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    // 直接注入一个与 qr_id 关联的 confirm token（模拟 scan 后又手动回退状态的异常路径）
    let token = "pending-path-confirm-token";
    svc.store_confirm_token_for_test(token, &created.qr_id)
        .await;
    let err = svc
        .confirm(token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap_err();
    assert_error_text(&err, "has not been scanned");
}

/// cancel：App 端取消动作迁移 Cancelled，poll 返回 Cancelled。
#[tokio::test]
async fn cancel_action_moves_to_cancelled() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Cancel, None)
        .await
        .unwrap();
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Cancelled
    );
}

/// poll：Confirmed 分支原子兑换，并发仅一胜出。
#[tokio::test]
async fn poll_confirmed_exchanges_atomically() {
    let svc = Arc::new(service());
    let created = svc.create_session(web_context()).await.unwrap();
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap();

    let s1 = Arc::clone(&svc);
    let s2 = Arc::clone(&svc);
    let qr_id = created.qr_id.clone();
    let bind = created.bind_token.clone();
    let (r1, r2) = tokio::join!(s1.poll(&qr_id, &bind), s2.poll(&qr_id, &bind));
    let outcomes = [r1.unwrap(), r2.unwrap()];
    let confirmed = outcomes
        .iter()
        .filter(|o| matches!(o, QrLoginPollOutcome::Confirmed { .. }))
        .count();
    let expired = outcomes
        .iter()
        .filter(|o| matches!(o, QrLoginPollOutcome::Expired))
        .count();
    assert_eq!(confirmed, 1, "并发兑换仅一者成功");
    assert_eq!(expired, 1, "另一者应见 Expired");
    if let QrLoginPollOutcome::Confirmed { login_id, .. } = &outcomes[0] {
        assert_eq!(login_id, "user-1");
    }
}

/// poll：未扫码/已扫码/不存在 各返回对应 outcome；兑换后再 confirm 返回 already-consumed。
#[tokio::test]
async fn poll_outcomes_and_post_exchange_confirm() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Pending
    );
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Scanned
    );
    assert_eq!(
        svc.poll("nonexistent-qr-id", &created.bind_token)
            .await
            .unwrap(),
        QrLoginPollOutcome::Expired
    );

    svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap();
    assert!(matches!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Confirmed { .. }
    ));
    // 兑换后重放已消费的 confirm_token：原子消费先于状态检查，fail-closed
    let err = svc
        .confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap_err();
    assert_error_text(&err, "confirm token is invalid");
}

/// confirm：Cancel 后重放同一 confirm_token 返回 confirm-token-invalid
///（原子消费先于状态检查，fail-closed——回归钉住 T015 收敛缺口）。
#[tokio::test]
async fn confirm_replay_after_cancel_fails_fail_closed() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Cancel, None)
        .await
        .unwrap();
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Cancelled
    );
    // 重放已消费的 token：token 查找失败优先于会话状态分支
    let err = svc
        .confirm(&view.confirm_token, "user-1", QrLoginAction::Cancel, None)
        .await
        .unwrap_err();
    assert_error_text(&err, "confirm token is invalid");
}

/// 双票：错误 bind_token → Expired（无区分度）。
#[tokio::test]
async fn poll_with_wrong_bind_token_is_expired() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    assert_eq!(
        svc.poll(&created.qr_id, "wrong-bind-token").await.unwrap(),
        QrLoginPollOutcome::Expired
    );
}

/// 双票：非终态轮询不消费 bind_token（可循环轮询），Confirmed 兑换消费后
/// 重放 → Expired（第二票一次性）。
#[tokio::test]
async fn poll_bind_token_replay_is_expired() {
    let svc = service();
    let created = svc.create_session(web_context()).await.unwrap();
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Pending
    );
    // 非终态：bind_token 未消费，可继续轮询
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Pending
    );
    // Confirmed 兑换消费第二票
    let view = svc.scan(&created.qr_content, "user-1", None).await.unwrap();
    svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, None)
        .await
        .unwrap();
    assert!(matches!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Confirmed { .. }
    ));
    assert_eq!(
        svc.poll(&created.qr_id, &created.bind_token).await.unwrap(),
        QrLoginPollOutcome::Expired,
        "重放已消费的 bind_token 必须 Expired"
    );
}

/// R-qrlogin-005 复查补证：scan/confirm 传入的 app_context 真实进入广播事件的
/// request_context（此前零覆盖，converge PASS 无证据——listener feature 下验证）。
#[cfg(all(feature = "listener", feature = "protocol-qrlogin"))]
mod app_context_event_tests {
    use super::*;
    use crate::error::GarrisonResult;
    use crate::listener::{GarrisonEvent, GarrisonListener, GarrisonListenerManager};
    use std::sync::Mutex;

    struct CapturingListener(Mutex<Vec<GarrisonEvent>>);

    #[async_trait::async_trait]
    impl GarrisonListener for CapturingListener {
        async fn on_event(&self, event: &GarrisonEvent) -> GarrisonResult<()> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    fn ctx() -> Option<(String, String)> {
        Some(("198.51.100.9".to_string(), "TestAgent/1.0".to_string()))
    }

    /// scan 事件的 request_context 携带 App 端 IP/UA。
    #[tokio::test]
    async fn scan_event_carries_app_context() {
        let captured = std::sync::Arc::new(CapturingListener(Mutex::new(Vec::new())));
        let lm = GarrisonListenerManager::new();
        lm.register(std::sync::Arc::clone(&captured) as std::sync::Arc<dyn GarrisonListener>);

        let svc = service().with_listener_manager(std::sync::Arc::new(lm));
        let created = svc.create_session(web_context()).await.unwrap();
        let view = svc
            .scan(&created.qr_content, "user-1", ctx())
            .await
            .unwrap();
        let _ = view.confirm_token;

        let events = captured.0.lock().unwrap();
        let scanned = events
            .iter()
            .find_map(|e| match e {
                GarrisonEvent::QrLoginScanned {
                    app_login_id,
                    request_context,
                    ..
                } => Some((app_login_id.clone(), request_context.clone())),
                _ => None,
            })
            .expect("应广播 QrLoginScanned");
        assert_eq!(scanned.0, "user-1");
        let rc = scanned.1.expect("request_context 应非 None");
        assert_eq!(rc.ip.as_deref(), Some("198.51.100.9"));
        assert_eq!(rc.user_agent.as_deref(), Some("TestAgent/1.0"));
    }

    /// confirm 事件的 request_context 携带 App 端 IP/UA。
    #[tokio::test]
    async fn confirm_event_carries_app_context() {
        let captured = std::sync::Arc::new(CapturingListener(Mutex::new(Vec::new())));
        let lm = GarrisonListenerManager::new();
        lm.register(std::sync::Arc::clone(&captured) as std::sync::Arc<dyn GarrisonListener>);

        let svc = service().with_listener_manager(std::sync::Arc::new(lm));
        let created = svc.create_session(web_context()).await.unwrap();
        let view = svc
            .scan(&created.qr_content, "user-1", ctx())
            .await
            .unwrap();
        svc.confirm(&view.confirm_token, "user-1", QrLoginAction::Confirm, ctx())
            .await
            .unwrap();

        let events = captured.0.lock().unwrap();
        let confirmed = events
            .iter()
            .find_map(|e| match e {
                GarrisonEvent::QrLoginConfirmed {
                    request_context, ..
                } => Some(request_context.clone()),
                _ => None,
            })
            .expect("应广播 QrLoginConfirmed");
        let rc = confirmed.expect("request_context 应非 None");
        assert_eq!(rc.ip.as_deref(), Some("198.51.100.9"));
    }
}
