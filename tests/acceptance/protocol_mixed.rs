//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! protocol 混合域验收（spec `acceptance-matrix` R-acceptance-matrix-002，
//! 任务 T025）。sso / sign / apikey / temp 四个协议处理器「正常 + 异常」成对
//! 覆盖，场景编号 `ACC-MIXED-NNN`。
//!
//! 全部场景直构处理器 + 产品 `InMemoryDao`（参考 tests/protocol/{sso,sign,apikey,temp}
//! 的已知良好装配），不触碰 `GarrisonManager` 全局单例，故不加 `#[serial]`；
//! 一次性消费竞争场景统一使用 `multi_thread` flavor（与 tests/acceptance/storage.rs
//! 的并发惯例一致）。
//!
//! # SSO 模拟说明
//!
//! `SsoClient` 为纯 DAO 实现（HMAC 验签与 ticket 存储均在本地共享 DAO，无网络
//! 路径，见 src/protocol/sso/client.rs），按任务「参考 tests/protocol/sso 的做法」
//! 以共享 `InMemoryDao` 模拟 SSO server 域（签发 / 校验双方持有同一 DAO），
//! 不需要 wiremock。
//!
//! # API 偏差记录
//!
//! 产品 `InMemoryDao::get` 在读取时清理已过期键（src/dao/in_memory.rs:52-66），
//! 故 apikey 过期后 `verify` 返回 `InvalidToken("apikey-not-found")` 而非
//! 处理器内部的 `ExpiredToken`（后者需 mock DAO 的「get 不清理过期键」语义，
//! 与 tests/protocol/apikey_edge_cases.rs 的说明一致）；两者均拒绝过期 key。

use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::GarrisonError;
use garrison::protocol::apikey::ApiKeyHandler;
use garrison::protocol::sign::SignHandler;
use garrison::protocol::sso::SsoClient;
use garrison::protocol::temp::TempCredentialHandler;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 并发 task 数（与 storage 域一致）。
const CONCURRENCY: usize = 100;

// ============================================================================
// 辅助
// ============================================================================

/// 构造产品内存 DAO（`Arc<dyn GarrisonDao>`）。
fn make_dao() -> Arc<dyn GarrisonDao> {
    Arc::new(InMemoryDao::new())
}

/// 当前 Unix 时间戳（秒）。
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ------------------------------------------------------------------------
// ACC-MIXED-001..004：sso（ticket 签发 / 一次性消费 / 并发竞争 / 过期）
// ------------------------------------------------------------------------

/// ACC-MIXED-001（正常）：`SsoClient` ticket 签发 → 校验 roundtrip——ticket 为
/// `{64_hex_random}.{hmac_b64}` 签名格式（M5），校验返回签入时的 login_id。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_001_sso_ticket_issue_and_validate() {
    let dao: Arc<dyn GarrisonDao> = make_dao();
    let client_a = SsoClient::new(dao.clone(), "acceptance-sso-secret");
    let client_b = SsoClient::new(dao, "acceptance-sso-secret");

    let ticket = client_a
        .issue_ticket("1001", 2001)
        .await
        .expect("签发应成功");
    let (random_part, sig) = ticket
        .split_once('.')
        .expect("ticket 应含 '.' 分隔符（M5 签名格式）");
    assert_eq!(random_part.len(), 64, "ticket 随机部分应为 64 字符");
    assert!(
        random_part.chars().all(|c| c.is_ascii_hexdigit()),
        "ticket 随机部分应为 hex 字符"
    );
    assert!(!sig.is_empty(), "ticket 签名部分不应为空");

    let login_id = client_b
        .validate_ticket(&ticket, 2001)
        .await
        .expect("校验应成功");
    assert_eq!(login_id, "1001".to_string(), "校验应返回签入主体");
}

/// ACC-MIXED-002（异常）：`get_and_delete` 一次性消费语义——同一 ticket 首次
/// 校验成功，二次使用被拒绝（`InvalidToken`），且错误 client_id 不消费 ticket、
/// 正确 client_id 仍可成功（非破坏性拒绝）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_002_sso_ticket_one_time_use_rejects_replay() {
    let dao: Arc<dyn GarrisonDao> = make_dao();
    let client_a = SsoClient::new(dao.clone(), "acceptance-sso-secret");
    let client_b = SsoClient::new(dao, "acceptance-sso-secret");

    let ticket = client_a.issue_ticket("1001", 2001).await.unwrap();

    // 首次校验成功
    assert_eq!(
        client_b.validate_ticket(&ticket, 2001).await.unwrap(),
        "1001".to_string()
    );

    // 二次使用拒绝（一次性）
    let replay = client_b.validate_ticket(&ticket, 2001).await;
    assert!(
        matches!(replay, Err(GarrisonError::InvalidToken(_))),
        "二次使用同一 ticket 应被拒绝，实际: {replay:?}"
    );

    // 错误 client_id 不消费：同一 ticket 换正确 client_id 仍可校验
    let wrong_client = SsoClient::new(make_dao(), "acceptance-sso-secret");
    let ticket2 = wrong_client.issue_ticket("1002", 3003).await.unwrap();
    let mismatch = wrong_client.validate_ticket(&ticket2, 9999).await;
    assert!(
        matches!(mismatch, Err(GarrisonError::InvalidToken(_))),
        "client_id 不匹配应拒绝"
    );
    assert_eq!(
        wrong_client.validate_ticket(&ticket2, 3003).await.unwrap(),
        "1002".to_string(),
        "client_id 不匹配不应消费 ticket（正确 client_id 仍可校验）"
    );
}

/// ACC-MIXED-003（异常/竞争）：100 task 并发校验同一 ticket（同 client_id），
/// 恰好 1 个成功、其余全部 `InvalidToken`——`get_and_delete` 原子消费无 TOCTOU。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_mixed_003_sso_concurrent_consume_exactly_once() {
    let dao: Arc<dyn GarrisonDao> = make_dao();
    let client = Arc::new(SsoClient::new(dao, "acceptance-sso-secret"));
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();

    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let client = client.clone();
        let ticket = ticket.clone();
        handles.push(tokio::spawn(async move {
            client.validate_ticket(&ticket, 2001).await
        }));
    }
    let mut ok_count = 0usize;
    for h in handles {
        match h.await.expect("task 不应 panic") {
            Ok(login_id) => {
                assert_eq!(login_id, "1001", "唯一成功者应拿到签入主体");
                ok_count += 1;
            },
            Err(GarrisonError::InvalidToken(_)) => {},
            other => panic!("并发消费失败应统一 InvalidToken，实际: {other:?}"),
        }
    }
    assert_eq!(
        ok_count, 1,
        "并发校验同一 ticket 应恰好 1 个成功（TOCTOU 将出现多个），实际 {ok_count}"
    );
}

/// ACC-MIXED-004（异常）：ticket 过期——`with_ticket_ttl(1)` 签发后等待超过
/// TTL，校验被拒（`InvalidToken`，ticket 已从 DAO 过期清理）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_004_sso_ticket_expired_rejected() {
    let client = SsoClient::new(make_dao(), "acceptance-sso-secret").with_ticket_ttl(1);
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();

    // 过期前：可校验
    client
        .validate_ticket(&ticket, 2001)
        .await
        .expect("未过期 ticket 应可校验");

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    let expired = client.validate_ticket(&ticket, 2001).await;
    assert!(
        matches!(expired, Err(GarrisonError::InvalidToken(_))),
        "超过 TTL 的 ticket 应被拒绝，实际: {expired:?}"
    );
}

// ------------------------------------------------------------------------
// ACC-MIXED-005..007：sign（签名验证 / 时间窗口 / nonce 重放）
// ------------------------------------------------------------------------

/// ACC-MIXED-005（正常+异常）：`SignHandler` 签名验证通过——sign/validate
/// roundtrip 返回 Ok；异常侧：请求体被篡改（同一 nonce 不同 body）签名不匹配
/// 被拒（`InvalidToken`）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_005_sign_validate_passes_and_mismatch_rejected() {
    let handler = SignHandler::new(
        "app-001",
        "acceptance-sign-secret-0123456789abcdef",
        make_dao(),
    )
    .expect("app_secret ≥32 字节应构造成功");
    let ts = now_ts();

    let sig = handler.sign("POST", "/api/v1/data", ts, "nonce-pass-001", "body-hash-1");
    handler
        .validate(
            "POST",
            "/api/v1/data",
            ts,
            "nonce-pass-001",
            "body-hash-1",
            &sig,
        )
        .await
        .expect("合法签名应校验通过");

    // 篡改 body（新 nonce + timestamp，不同 body_hash）→ 签名不匹配
    //（nonce 校验先于签名校验：此处用新 nonce 隔离 nonce-replay 路径）
    let tampered = handler
        .validate(
            "POST",
            "/api/v1/data",
            ts,
            "nonce-tampered-001",
            "body-hash-TAMPERED",
            &sig,
        )
        .await;
    assert!(
        matches!(tampered, Err(GarrisonError::InvalidToken(ref msg)) if msg.contains("mismatch")),
        "body 篡改应拒绝（sign-mismatch），实际: {tampered:?}"
    );
}

/// ACC-MIXED-006（异常）：时间窗口外拒绝——默认 300s 窗口下，过去/未来 400s
/// 的时间戳均返回 `ExpiredToken`；`with_timestamp_window(10)` 收窄后 60s 漂移
/// 同样被拒。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_006_sign_timestamp_outside_window_rejected() {
    let handler = SignHandler::new(
        "app-002",
        "acceptance-sign-secret-0123456789abcdef",
        make_dao(),
    )
    .expect("构造应成功");
    let now = now_ts();

    // 过去 400s（> 默认 300s 窗口）
    let past_ts = now - 400;
    let sig = handler.sign("POST", "/api", past_ts, "nonce-past-001", "body");
    let result = handler
        .validate("POST", "/api", past_ts, "nonce-past-001", "body", &sig)
        .await;
    assert!(
        matches!(result, Err(GarrisonError::ExpiredToken(_))),
        "过去时间戳超出窗口应 ExpiredToken，实际: {result:?}"
    );

    // 未来 400s
    let future_ts = now + 400;
    let sig = handler.sign("POST", "/api", future_ts, "nonce-future-001", "body");
    let result = handler
        .validate("POST", "/api", future_ts, "nonce-future-001", "body", &sig)
        .await;
    assert!(
        matches!(result, Err(GarrisonError::ExpiredToken(_))),
        "未来时间戳超出窗口应 ExpiredToken，实际: {result:?}"
    );

    // 收窄窗口 10s：60s 漂移（窗口内于默认 300s，但超出 10s）仍拒绝
    let strict = SignHandler::new(
        "app-002",
        "acceptance-sign-secret-0123456789abcdef",
        make_dao(),
    )
    .expect("构造应成功")
    .with_timestamp_window(10);
    let drift_ts = now - 60;
    let sig = strict.sign("POST", "/api", drift_ts, "nonce-drift-001", "body");
    let result = strict
        .validate("POST", "/api", drift_ts, "nonce-drift-001", "body", &sig)
        .await;
    assert!(
        matches!(result, Err(GarrisonError::ExpiredToken(_))),
        "窗口收窄后 60s 漂移应被拒，实际: {result:?}"
    );
}

/// ACC-MIXED-007（异常）：nonce 重放拒绝——同一 nonce 首次校验成功（incr=1），
/// 窗口内二次使用同一 nonce 被拒（`InvalidToken` nonce 已消费）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_007_sign_nonce_replay_rejected() {
    let handler = SignHandler::new(
        "app-003",
        "acceptance-sign-secret-0123456789abcdef",
        make_dao(),
    )
    .expect("构造应成功");
    let ts = now_ts();
    let nonce = "nonce-replay-acceptance-001";
    let sig = handler.sign("GET", "/api/v1/list", ts, nonce, "body-hash");

    handler
        .validate("GET", "/api/v1/list", ts, nonce, "body-hash", &sig)
        .await
        .expect("首次校验应成功");

    // 同一 nonce 重放（完全相同的参数与签名）
    let replay = handler
        .validate("GET", "/api/v1/list", ts, nonce, "body-hash", &sig)
        .await;
    assert!(
        matches!(replay, Err(GarrisonError::InvalidToken(ref msg)) if msg.contains("nonce")),
        "同一 nonce 在窗口内重放应被拒绝，实际: {replay:?}"
    );
}

// ------------------------------------------------------------------------
// ACC-MIXED-008..012：apikey（生成 / 吊销 / 轮换 / 无效格式 / 过期）
// ------------------------------------------------------------------------

/// ACC-MIXED-008（正常）：`ApiKeyHandler` 生成 → 校验 roundtrip——key 为
/// `{32_hex}.{32_hex}` 双段格式，`verify` 返回完整 `ApiKeyInfo`
/// （login_id / scopes / namespace / revoked=false）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_008_apikey_generate_and_verify() {
    let handler = ApiKeyHandler::new(make_dao());

    let key = handler
        .generate("1001", vec!["read".to_string(), "write".to_string()], 3600)
        .await
        .expect("生成应成功");
    let (key_id, key_secret) = key
        .split_once('.')
        .expect("key 应为 key_id.key_secret 双段格式");
    assert_eq!(key_id.len(), 32, "key_id 应为 32 hex");
    assert_eq!(key_secret.len(), 32, "key_secret 应为 32 hex");
    assert!(
        key_id.chars().all(|c| c.is_ascii_hexdigit())
            && key_secret.chars().all(|c| c.is_ascii_hexdigit()),
        "key 两段均应为 hex 字符"
    );

    let info = handler.verify(&key).await.expect("verify 应成功");
    assert_eq!(info.login_id, "1001", "verify 应返回绑定 login_id");
    assert_eq!(info.scopes, vec!["read".to_string(), "write".to_string()]);
    assert_eq!(info.namespace, "default", "默认 namespace 应为 default");
    assert!(!info.revoked, "新生成 key 不应 revoked");
}

/// ACC-MIXED-009（异常）：吊销后失效——`revoke` 后 `verify` 返回
/// `InvalidToken`（apikey-revoked）；吊销不存在的 key 显性返回
/// `InvalidToken("apikey-not-found")`（lookup 先行 fail-loud，非静默成功）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_009_apikey_revoked_invalidates() {
    let handler = ApiKeyHandler::new(make_dao());
    let key = handler
        .generate("1001", vec!["read".to_string()], 3600)
        .await
        .expect("生成应成功");
    handler.verify(&key).await.expect("吊销前应可校验");

    handler.revoke(&key).await.expect("吊销应成功");
    let revoked = handler.verify(&key).await;
    assert!(
        matches!(revoked, Err(GarrisonError::InvalidToken(_))),
        "吊销后 verify 应被拒，实际: {revoked:?}"
    );

    // 吊销不存在的 key：显性失败（Fail Loud，规则 12）
    let ghost = handler
        .revoke(&format!("{}.{}", "0".repeat(32), "0".repeat(32)))
        .await;
    assert!(
        matches!(ghost, Err(GarrisonError::InvalidToken(_))),
        "吊销不存在的 key 应显性返回 InvalidToken，实际: {ghost:?}"
    );
}

/// ACC-MIXED-010（异常）：轮换后旧 key 失效——`rotate` 产出新 key（可校验、
/// login_id/scope 保留），旧 key 已被吊销无法再校验。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_010_apikey_rotation_invalidates_old_key() {
    let handler = ApiKeyHandler::new(make_dao());
    let old_key = handler
        .generate("1001", vec!["read".to_string()], 3600)
        .await
        .expect("生成应成功");

    let new_key = handler.rotate(&old_key).await.expect("轮换应成功");
    assert_ne!(new_key, old_key, "轮换应产出新 key");

    let info = handler.verify(&new_key).await.expect("新 key 应可校验");
    assert_eq!(info.login_id, "1001", "轮换应保留 login_id");
    assert_eq!(info.scopes, vec!["read".to_string()], "轮换应保留 scopes");

    let old = handler.verify(&old_key).await;
    assert!(
        matches!(old, Err(GarrisonError::InvalidToken(_))),
        "轮换后旧 key 应失效，实际: {old:?}"
    );
}

/// ACC-MIXED-011（异常）：无效格式拒绝——短字符串 / 非 hex 长串 / 空串
/// 校验均返回 `InvalidToken`（DAO 查找不命中，fail-closed）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_011_apikey_invalid_format_rejected() {
    let handler = ApiKeyHandler::new(make_dao());

    for (name, bad) in [
        ("短字符串", "short"),
        (
            "非 hex 长串",
            "ZZZZ_invalid_apikey_with_non_hex_chars_padding",
        ),
        ("空串", ""),
    ] {
        let result = handler.verify(bad).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidToken(_))),
            "{name} 应被拒绝，实际: {result:?}"
        );
    }
}

/// ACC-MIXED-012（异常）：过期失效——`timeout=1` 生成后等待超过 TTL，
/// `verify` 被拒。产品 `InMemoryDao` 在 get 时清理过期键，返回
/// `InvalidToken("apikey-not-found")`（见文件头 API 偏差记录）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_012_apikey_expired_rejected() {
    let handler = ApiKeyHandler::new(make_dao());
    let key = handler
        .generate("1001", vec!["read".to_string()], 1)
        .await
        .expect("timeout=1 生成应成功");
    handler.verify(&key).await.expect("过期前应可校验");

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    let expired = handler.verify(&key).await;
    assert!(
        matches!(expired, Err(GarrisonError::InvalidToken(_))),
        "过期 key 应被拒绝，实际: {expired:?}"
    );
}

// ------------------------------------------------------------------------
// ACC-MIXED-013..016：temp（issue/consume 一次性 / 过期 / 吊销 / 并发竞争）
// ------------------------------------------------------------------------

/// ACC-MIXED-013（正常+异常）：`TempCredentialHandler` issue → get → consume——
/// 首次 `consume` 原子返回凭证值（一次性），二次 `consume` / `get` 均返回 None。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_013_temp_credential_issue_and_one_time_consume() {
    let handler = TempCredentialHandler::new(make_dao());

    let key = handler
        .issue("invite", "payload-data-001", 600)
        .await
        .expect("签发应成功");
    assert!(
        key.starts_with("garrison:temp:invite:"),
        "key 应带前缀与场景: {key}"
    );

    assert_eq!(
        handler.get(&key).await.unwrap(),
        Some("payload-data-001".to_string()),
        "消费前 get 应返回凭证值"
    );

    // 一次性消费
    assert_eq!(
        handler.consume(&key).await.unwrap(),
        Some("payload-data-001".to_string()),
        "首次 consume 应返回凭证值"
    );
    assert_eq!(
        handler.consume(&key).await.unwrap(),
        None,
        "二次 consume 应返回 None（一次性）"
    );
    assert_eq!(
        handler.get(&key).await.unwrap(),
        None,
        "消费后 get 应返回 None"
    );
}

/// ACC-MIXED-014（异常）：过期失效——`ttl=1` 签发后等待超过 TTL，`get` /
/// `consume` 均返回 None。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_014_temp_credential_expired_reads_empty() {
    let handler = TempCredentialHandler::new(make_dao());
    let key = handler
        .issue("reset", "reset-token-001", 1)
        .await
        .expect("签发应成功");

    assert!(
        handler.get(&key).await.unwrap().is_some(),
        "过期前 get 应返回凭证值"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    assert_eq!(
        handler.get(&key).await.unwrap(),
        None,
        "过期后 get 应返回 None"
    );
    assert_eq!(
        handler.consume(&key).await.unwrap(),
        None,
        "过期后 consume 应返回 None"
    );
}

/// ACC-MIXED-015（异常）：吊销——`revoke` 后 get/consume 均不可读，重复
/// revoke 幂等返回 Ok。
#[tokio::test(flavor = "multi_thread")]
async fn acc_mixed_015_temp_credential_revoked() {
    let handler = TempCredentialHandler::new(make_dao());
    let key = handler
        .issue("coupon", "coupon-abc-001", 600)
        .await
        .expect("签发应成功");

    handler.revoke(&key).await.expect("吊销应成功");
    assert_eq!(
        handler.get(&key).await.unwrap(),
        None,
        "吊销后 get 应为 None"
    );
    assert_eq!(
        handler.consume(&key).await.unwrap(),
        None,
        "吊销后 consume 应为 None"
    );

    // 幂等：重复吊销 / 吊销不存在 key 均 Ok
    handler.revoke(&key).await.expect("重复吊销应幂等 Ok");
    handler
        .revoke("garrison:temp:ghost:nonexistent")
        .await
        .expect("吊销不存在 key 应幂等 Ok");
}

/// ACC-MIXED-016（异常/竞争）：100 task 并发 `consume` 同一临时凭证，恰好
/// 1 个取到值、其余全部 None——`get_and_delete` 原子消费防 double-spend。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_mixed_016_temp_concurrent_consume_exactly_once() {
    let handler = Arc::new(TempCredentialHandler::new(make_dao()));
    let key = handler
        .issue("vote", "ballot-001", 600)
        .await
        .expect("签发应成功");

    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let handler = handler.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move { handler.consume(&key).await }));
    }
    let mut hit_count = 0usize;
    for h in handles {
        let got = h.await.expect("task 不应 panic").expect("consume 不应 Err");
        if got.is_some() {
            assert_eq!(got.as_deref(), Some("ballot-001"), "唯一消费者应取到原值");
            hit_count += 1;
        }
    }
    assert_eq!(
        hit_count, 1,
        "并发 consume 同一凭证应恰好 1 个取到（TOCTOU 将出现多次），实际 {hit_count}"
    );
}
