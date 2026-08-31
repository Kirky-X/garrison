//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! protocol-jwt 域验收（spec `acceptance-matrix` R-acceptance-matrix-002，
//! 任务 T023）。JWT 签发/校验/轮换「正常 + 异常」成对覆盖：
//! HS256/HS512 roundtrip、mixin 模式（token_style=jwt + JwtMode::Mixin）、
//! refresh token 轮换链（parent hash 保留）、过期/篡改/算法不匹配/
//! 重用检测链吊销/错误密钥拒绝。
//!
//! ACC-JWT-010..014 吸收 tests/protocol/jwt_integration.rs（全生命周期
//! login/verify/refresh/logout）与 jwt_edge_cases.rs（alg:none 注入、
//! 空 claims、iat 时钟偏差、过期 refresh），Phase 4 迁移追溯。
//!
//! 场景编号约定：`ACC-JWT-NNN（正常|异常）`。
//!
//! 经 `GarrisonManager` 全局单例的用例（ACC-JWT-003）标注 `#[serial]`，
//! 其余用例直接构造 `JwtHandler` / `RefreshTokenRotation`（独立 SQLite
//! 内存库），无全局状态，可并行。

#![allow(clippy::useless_conversion)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use garrison::error::GarrisonError;
use garrison::protocol::jwt::JwtHandler;
use garrison::stp::{with_current_token, GarrisonUtil};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serial_test::serial;
use std::sync::{Arc, RwLock};

use crate::common::harness::GarrisonTestHarness;
use crate::common::{setup_db, sha256_hex};

// ------------------------------------------------------------------------
// 辅助函数
// ------------------------------------------------------------------------

/// 「校验必须失败」的统一断言：verify 返回 Err。
fn assert_verify_rejected(
    result: &garrison::error::GarrisonResult<garrison::protocol::jwt::GarrisonJwtClaims>,
    msg: &str,
) {
    assert!(result.is_err(), "{}（实际: {:?}）", msg, result);
}

/// 构造共享 secret 的两个 JwtHandler（HS256 / HS512）。
fn handlers_with_shared_secret() -> (JwtHandler, JwtHandler) {
    let secret = "acceptance-jwt-shared-secret-0123456789abcdef"; // ≥32 字节
    (
        JwtHandler::new(secret),
        JwtHandler::new(secret).with_algorithm(Algorithm::HS512),
    )
}

// ------------------------------------------------------------------------
// ACC-JWT-001..002：HS256 / HS512 roundtrip（正常）
// ------------------------------------------------------------------------

/// ACC-JWT-001（正常）：HS256 签发 → 校验 roundtrip，claims 字段一致
/// （login_id / sub / jti 唯一），伪造 token 在正常路径的对比锚点（verify 只
/// 接受合法 JWT 三段式）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_001_hs256_sign_verify_roundtrip() {
    let handler = JwtHandler::new("acceptance-hs256-secret-0123456789abcdef");
    assert_eq!(handler.algorithm, Algorithm::HS256);

    let token = handler.sign("1001", 3600).expect("HS256 sign 应成功");
    assert_eq!(token.matches('.').count(), 2, "JWT 应为三段式（两个 .）");

    let claims = handler.verify(&token).expect("HS256 verify 应成功");
    assert_eq!(claims.login_id, "1001".to_string());
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.exp - claims.iat, 3600, "exp - iat 应等于 timeout");
    assert!(claims.device.is_none(), "未设置 device 时应为 None");
    assert!(claims.jti.is_some(), "v0.6.3 起 sign 应自动生成 jti");
}

/// ACC-JWT-002（正常）：HS512 签发 → 校验 roundtrip，token 头声明的算法
/// 必须是 HS512（`with_algorithm` 生效）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_002_hs512_sign_verify_roundtrip() {
    let handler = JwtHandler::new("acceptance-hs512-secret-0123456789abcdef")
        .with_algorithm(Algorithm::HS512);
    assert_eq!(handler.algorithm, Algorithm::HS512);

    let token = handler.sign("2002", 7200).expect("HS512 sign 应成功");
    // 解码 header（token 第一段，'.' 之前）断言声明的 alg 为 HS512
    let (header_b64, _) = token.split_once('.').expect("JWT 应有 '.'");
    let header_json = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("header base64url 解码应成功");
    let header: serde_json::Value =
        serde_json::from_slice(&header_json).expect("header 应为合法 JSON");
    assert_eq!(
        header["alg"], "HS512",
        "token 头声明的算法应为 HS512，实际: {}",
        header["alg"]
    );

    let claims = handler.verify(&token).expect("HS512 verify 应成功");
    assert_eq!(claims.login_id, "2002".to_string());
}

// ------------------------------------------------------------------------
// ACC-JWT-003：mixin 模式（正常 + 异常）
// ------------------------------------------------------------------------

/// ACC-JWT-003（正常+异常）：token_style=jwt + JwtMode::Mixin（默认）——
/// 经全局管理器 login 签发 JWT，verify_token 反查主体、check_login 通过；
/// 异常侧：仅 JWT 无 session 的 token 被二级 session 校验拒绝（Mixin 语义）。
#[tokio::test]
#[serial]
async fn acc_jwt_003_mixin_mode_jwt_with_session_required() {
    let mut c = garrison::config::GarrisonConfig::default_config();
    c.token_style = "jwt".to_string();
    c.jwt_secret = "acceptance-jwt-mixin-secret-0123456789abcdef"
        .to_string()
        .into();
    c.timeout = 3600;
    c.throw_on_not_login = true;
    let _h = GarrisonTestHarness::builder()
        .config(Arc::new(c))
        .init()
        .await
        .expect("jwt mixin 配置下 harness init 应成功");

    // 正常：login 产出 JWT，verify 反查主体，check_login 通过（JWT + session 双校验）
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");
    assert_eq!(
        token.matches('.').count(),
        2,
        "token_style=jwt 下 token 应为 JWT"
    );
    assert_eq!(
        GarrisonUtil::verify_token(&token)
            .await
            .expect("verify_token 应成功"),
        "1001".to_string(),
        "verify_token 应反查回登录主体"
    );
    let logged = with_current_token(token.clone(), async {
        GarrisonUtil::check_login()
            .await
            .expect("有效 JWT+session 应通过")
    })
    .await;
    assert!(logged, "Mixin 模式有效会话 check_login 应为 true");

    // 异常：同 secret 直接签发的 JWT（无 session）在 Mixin 下必须被拒绝
    let handler = JwtHandler::new("acceptance-jwt-mixin-secret-0123456789abcdef");
    let jwt_only = handler.sign("1001", 3600).expect("直接签发应成功");
    let rejected = with_current_token(jwt_only, GarrisonUtil::check_login()).await;
    assert!(
        rejected.is_err(),
        "Mixin 模式仅 JWT 无 session 应被拒绝（二级校验），实际: {:?}",
        rejected
    );
}

// ------------------------------------------------------------------------
// ACC-JWT-004：refresh 轮换链（正常）
// ------------------------------------------------------------------------

/// ACC-JWT-004（正常）：RefreshTokenRotation 轮换链——issue 首 token →
/// 两次 rotate 生成新 token，每代 record 保留 parent_token_hash 指向旧 hash，
/// 旧代标记 revoked（hash chain 形成）；轮换不破坏新 token 可用性。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_004_refresh_rotation_chain_keeps_parent_hash() {
    let pool = setup_db().await;
    let handler = Arc::new(JwtHandler::new("acceptance-rotation-secret-0123456789ab"));
    let rotation = garrison::RefreshTokenRotation::new(pool, handler, Arc::new(RwLock::new(1u32)));

    // issue 首 token：parent 为 None，revoked=false
    let rt1 = rotation
        .issue(
            "client-1",
            Some(1001),
            &["read".to_string()],
            Some("alice"),
            1001,
            0,
            3600,
        )
        .await
        .expect("issue 应成功");
    let r1 = rotation
        .validate(&rt1)
        .await
        .expect("validate 应成功")
        .expect("首 token record 应存在");
    assert_eq!(
        r1.parent_token_hash, None,
        "首次签发 parent_token_hash 应为 None"
    );
    assert!(!r1.revoked, "新签发 token 应未 revoked");

    // 第一次 rotate：rt1 → rt2，rt2.parent == sha256(rt1)，rt1 revoked
    let (access1, rt2) = rotation.rotate(&rt1).await.expect("第一次 rotate 应成功");
    assert!(!access1.is_empty(), "rotate 应产出新 access token");
    assert_ne!(rt2, rt1, "新 refresh token 不应与旧 token 相同");
    let h1 = sha256_hex(&rt1);
    let r2 = rotation
        .validate(&rt2)
        .await
        .expect("validate 应成功")
        .expect("rt2 record 应存在");
    assert_eq!(
        r2.parent_token_hash,
        Some(h1.clone()),
        "rt2 的 parent 应指向 rt1 的 hash"
    );
    assert!(!r2.revoked, "rt2 应未 revoked");
    assert!(
        rotation
            .validate(&rt1)
            .await
            .expect("validate 应成功")
            .is_none(),
        "rotate 后旧 token rt1 应 revoked（validate 返回 None）"
    );

    // 第二次 rotate：rt2 → rt3，rt3.parent == sha256(rt2)
    let (_, rt3) = rotation.rotate(&rt2).await.expect("第二次 rotate 应成功");
    let h2 = sha256_hex(&rt2);
    let r3 = rotation
        .validate(&rt3)
        .await
        .expect("validate 应成功")
        .expect("rt3 record 应存在");
    assert_eq!(
        r3.parent_token_hash,
        Some(h2),
        "rt3 的 parent 应指向 rt2 的 hash"
    );
    assert!(
        rotation
            .validate(&rt2)
            .await
            .expect("validate 应成功")
            .is_none(),
        "rt2 轮换后应 revoked"
    );
}

// ------------------------------------------------------------------------
// ACC-JWT-005..009：异常路径
// ------------------------------------------------------------------------

/// ACC-JWT-005（异常）：过期 token 被拒绝——timeout=0 签发（exp=iat），
/// 跨越至少一个秒边界后 verify 必须返回 ExpiredToken。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_005_expired_token_rejected() {
    let handler = JwtHandler::new("acceptance-expired-secret-0123456789abcdef");
    let token = handler.sign("1001", 0).expect("timeout=0 应允许签发");

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let result = handler.verify(&token);
    assert_verify_rejected(&result, "已过期 token 不得通过校验");
    match result.unwrap_err() {
        GarrisonError::ExpiredToken(msg) => {
            assert!(msg.contains("jwt-expired"), "应为 jwt-expired 错误: {msg}");
        },
        other => panic!("期望 ExpiredToken，实际: {:?}", other),
    }
}

/// ACC-JWT-006（异常）：签名篡改——payload 改一个字节（sub 1001→1000）后
/// 签名失效，verify 必须拒绝（签名覆盖 header+payload，任何改动即失效）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_006_tampered_payload_rejected() {
    let handler = JwtHandler::new("acceptance-tamper-secret-0123456789abcdef");
    let token = handler.sign("1001", 3600).expect("sign 应成功");

    // 篡改 payload 中 sub 的一个字节：1001 → 1000
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT 应为三段式");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload base64url 解码应成功");
    let payload = String::from_utf8(payload).expect("payload 应为 UTF-8");
    let tampered = payload.replacen("1001", "1000", 1);
    assert_ne!(tampered, payload, "篡改必须实际改变 payload");
    let tampered_b64 = URL_SAFE_NO_PAD.encode(tampered.as_bytes());
    let forged = format!("{}.{}.{}", parts[0], tampered_b64, parts[2]);

    let result = handler.verify(&forged);
    assert_verify_rejected(&result, "payload 篡改后签名校验必须失败");
    match result.unwrap_err() {
        GarrisonError::InvalidToken(_) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// ACC-JWT-007（异常）：算法不匹配拒绝——(a) HS512 签名的 token 用 HS256
/// 验证器校验失败；(b) 手动构造声明 HS256 但实际为 HS512 签名的 token 用
/// HS512 验证器校验失败（声明的 alg 与验证器不匹配必须拒绝）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_007_algorithm_mismatch_rejected() {
    let (hs256, hs512) = handlers_with_shared_secret();

    // (a) HS512 token → HS256 验证器：头声明 alg=HS512 ≠ HS256 → 拒绝
    let hs512_token = hs512.sign("1001", 3600).expect("HS512 sign 应成功");
    let cross = hs256.verify(&hs512_token);
    assert_verify_rejected(&cross, "HS512 签发的 token 不得被 HS256 验证器接受");
    match cross.unwrap_err() {
        GarrisonError::InvalidToken(_) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }

    // (b) 声明 HS256 的 token 用 HS512 验证器：声明 alg ≠ 验证器 alg → 拒绝
    let claims = garrison::protocol::jwt::GarrisonJwtClaims {
        sub: "1001".to_string(),
        iat: 0,
        exp: 9999999999,
        login_id: "1001".to_string(),
        device: None,
        jti: None,
        nbf: None,
    };
    let header = Header::new(Algorithm::HS256);
    let declared_hs256 = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("acceptance-jwt-shared-secret-0123456789abcdef".as_bytes()),
    )
    .expect("手工签发应成功");
    let result = hs512.verify(&declared_hs256);
    assert_verify_rejected(&result, "声明 HS256 的 token 不得被 HS512 验证器接受");
}

/// ACC-JWT-008（异常）：refresh token 重用检测——已轮换的旧 refresh token
/// 再次使用触发 detect_reuse，返回 TokenRevoked 并吊销整条链（rt1 + rt2）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_008_old_refresh_token_reuse_revokes_chain() {
    let pool = setup_db().await;
    let handler = Arc::new(JwtHandler::new("acceptance-reuse-secret-0123456789abcdef"));
    let rotation = garrison::RefreshTokenRotation::new(pool, handler, Arc::new(RwLock::new(1u32)));

    let rt1 = rotation
        .issue(
            "client-1",
            Some(1001),
            &["read".to_string()],
            Some("alice"),
            1001,
            0,
            3600,
        )
        .await
        .expect("issue 应成功");
    let (_access, rt2) = rotation.rotate(&rt1).await.expect("首次 rotate 应成功");

    // detect_reuse：rt1 已 revoked → true；rt2 未 revoked → false
    let h1 = sha256_hex(&rt1);
    assert!(
        rotation
            .detect_reuse(&h1)
            .await
            .expect("detect_reuse 应成功"),
        "已轮换的旧 token 应检测为重用"
    );
    let h2 = sha256_hex(&rt2);
    assert!(
        !rotation
            .detect_reuse(&h2)
            .await
            .expect("detect_reuse 应成功"),
        "当前有效的 rt2 不应检测为重用"
    );

    // 重用旧 token：rotate(rt1) → TokenRevoked，整条链吊销
    let reuse_result = rotation.rotate(&rt1).await;
    match reuse_result {
        Err(GarrisonError::TokenRevoked(msg)) => {
            assert!(msg.contains("reuse"), "应说明 reuse 语义: {msg}");
        },
        other => panic!(
            "重用旧 refresh token 应返回 TokenRevoked，实际: {:?}",
            other
        ),
    }

    // 链吊销后：rt1、rt2 全部失效
    assert!(
        rotation
            .validate(&rt1)
            .await
            .expect("validate 应成功")
            .is_none(),
        "重用检测后 rt1 应失效"
    );
    assert!(
        rotation
            .validate(&rt2)
            .await
            .expect("validate 应成功")
            .is_none(),
        "重用检测后整条链（含 rt2）应被吊销"
    );
}

/// ACC-JWT-009（异常）：错误密钥/缺失 kid 拒绝——验证器只信任自己的密钥：
/// (a) 未知密钥签发的 token（含 kid 声明）被拒；(b) 无 kid 的错误密钥 token
/// 被拒；(c) kid 仅是头部声明，正确密钥 + 任意 kid 仍可通过（kid 不构成信任）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_009_wrong_key_with_or_without_kid_rejected() {
    let verifier_secret = "acceptance-jwt-verifier-secret-0123456789abcdef";
    let attacker_secret = "acceptance-jwt-attacker-secret-0123456789abcdef";
    let handler = JwtHandler::new(verifier_secret);

    // (a) 攻击者密钥签发、HEADER 含 kid 声明指向未知密钥 → 必须拒绝
    let claims = garrison::protocol::jwt::GarrisonJwtClaims {
        sub: "victim".to_string(),
        iat: 0,
        exp: 9999999999,
        login_id: "victim".to_string(),
        device: None,
        jti: None,
        nbf: None,
    };
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("attacker-key-1".to_string());
    let token_with_kid = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(attacker_secret.as_bytes()),
    )
    .expect("攻击者签发应成功");
    let rejected_kid = handler.verify(&token_with_kid);
    assert_verify_rejected(&rejected_kid, "带 kid 声明但密钥错误的 token 必须被拒");

    // (b) 无 kid 的错误密钥 token → 必须拒绝（缺 kid 不改变密钥判定）
    let token_no_kid = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(attacker_secret.as_bytes()),
    )
    .expect("攻击者签发（无 kid）应成功");
    let rejected_no_kid = handler.verify(&token_no_kid);
    assert_verify_rejected(&rejected_no_kid, "无 kid 的错误密钥 token 必须被拒");

    // (c) 正确密钥 + kid 声明 → 通过（kid 不参与信任判定，密钥才是信任根）
    let mut header_ok = Header::new(Algorithm::HS256);
    header_ok.kid = Some("any-key-id".to_string());
    let token_ok = encode(
        &header_ok,
        &claims,
        &EncodingKey::from_secret(verifier_secret.as_bytes()),
    )
    .expect("正确密钥签发应成功");
    handler
        .verify(&token_ok)
        .expect("正确密钥 + kid 声明的 token 应通过");
}

// ------------------------------------------------------------------------
// ACC-JWT-010..014：JWT 生命周期与边界场景（迁自 tests/protocol/jwt_*.rs）
// ------------------------------------------------------------------------

/// token_style=jwt 的全局配置（生命周期场景共用；与
/// tests/protocol/jwt_integration.rs::init_jwt_manager 一致——
/// `throw_on_not_login=false` 保持 logout 后 `check_login` 返回 `Ok(false)`）。
fn jwt_manager_config() -> std::sync::Arc<garrison::config::GarrisonConfig> {
    let mut c = garrison::config::GarrisonConfig::default_config();
    c.token_style = "jwt".to_string();
    c.jwt_secret = "acceptance-jwt-lifecycle-secret-0123456789abcdef"
        .to_string()
        .into();
    c.timeout = 3600;
    c.throw_on_not_login = false;
    std::sync::Arc::new(c)
}

/// ACC-JWT-010（正常）：JWT 完整生命周期——login 签发 → verify_token 反查主体 →
/// refresh_token 轮换（新 token 主体一致、可校验）→ check_login true →
/// logout 销毁会话 → check_login false。经全局管理器（`#[serial]`）。
/// 迁自 tests/protocol/jwt_integration.rs::jwt_end_to_end_login_verify_refresh_logout
#[tokio::test]
#[serial]
async fn acc_jwt_010_full_lifecycle_login_verify_refresh_logout() {
    let _h = GarrisonTestHarness::builder()
        .config(jwt_manager_config())
        .init()
        .await
        .expect("jwt 配置下 harness init 应成功");

    // 1. login 生成 JWT（三段式）
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");
    assert_eq!(token.matches('.').count(), 2, "JWT 应为三段式");

    // 2. verify_token 反查 login_id
    assert_eq!(
        GarrisonUtil::verify_token(&token)
            .await
            .expect("verify_token 应成功"),
        "1001".to_string(),
        "verify_token 应返回原 login_id"
    );

    // 3. refresh_token 轮换：新 token 主体一致（同一秒内 iat/exp 相同，
    //    token 可能相同，此处仅验证主体一致与可校验，同原用例注记）
    let new_token = GarrisonUtil::refresh_token(&token)
        .await
        .expect("refresh_token 应成功");
    assert_eq!(
        GarrisonUtil::verify_token(&new_token)
            .await
            .expect("新 token 应可校验"),
        "1001".to_string(),
        "新 token 的 login_id 应一致"
    );

    // 4. check_login：task_local 上下文内为 true
    let logged_in = with_current_token(token.clone(), async {
        GarrisonUtil::check_login()
            .await
            .expect("check_login 不应报错")
    })
    .await;
    assert!(logged_in, "登录后 check_login 应为 true");

    // 5. logout 销毁会话；此后 check_login 为 false
    with_current_token(token.clone(), async {
        GarrisonUtil::logout().await.expect("logout 不应报错")
    })
    .await;
    let logged_in_after = with_current_token(token.clone(), async {
        GarrisonUtil::check_login()
            .await
            .expect("check_login 不应报错")
    })
    .await;
    assert!(!logged_in_after, "logout 后 check_login 应为 false");
}

/// ACC-JWT-011（异常）：verify_token 拒绝无效 JWT / 空串；refresh_token 拒绝
/// 无效 token（均返回 Err，不 panic 不静默放行）。
/// 迁自 tests/protocol/jwt_integration.rs::verify_token_rejects_invalid_jwt、
/// verify_token_rejects_empty_string、refresh_token_rejects_invalid_token（3 例合并）
#[tokio::test]
#[serial]
async fn acc_jwt_011_verify_and_refresh_reject_invalid_tokens() {
    let _h = GarrisonTestHarness::builder()
        .config(jwt_manager_config())
        .init()
        .await
        .expect("jwt 配置下 harness init 应成功");

    assert!(
        GarrisonUtil::verify_token("not.a.valid.jwt").await.is_err(),
        "无效 JWT 应校验失败"
    );
    assert!(
        GarrisonUtil::verify_token("").await.is_err(),
        "空 token 应校验失败"
    );
    assert!(
        GarrisonUtil::refresh_token("invalid-token").await.is_err(),
        "无效 token 刷新应失败"
    );
}

/// ACC-JWT-012（异常）：手工构造的畸形 JWT 必须被拒绝——
/// (a) `alg:none` 注入（header 声明 none、签名段为空，绕过签名校验的经典攻击）；
/// (b) 空 claims `{}`（缺必填字段，反序列化失败）。
/// 迁自 tests/protocol/jwt_edge_cases.rs::none_algorithm_injection_rejected、
/// empty_claims_jwt_rejected（2 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_012_none_algorithm_and_empty_claims_rejected() {
    let secret = "acceptance-jwt-edge-secret-0123456789abcdef";
    let handler = JwtHandler::new(secret);

    // (a) alg:none 注入：header.payload. 三段式，签名段为空
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let claims_b64 = URL_SAFE_NO_PAD.encode(
        br#"{"sub":"1001","iat":1700000000,"exp":9999999999,"login_id":1001,"device":null}"#,
    );
    let forged = format!("{header_b64}.{claims_b64}.");
    let result = handler.verify(&forged);
    assert_verify_rejected(&result, "alg:none 注入应被拒绝（安全边界）");
    match result {
        Err(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }

    // (b) 空 claims（{}）→ 缺必填字段，反序列化失败
    let empty = encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({}),
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("编码空 claims 应成功");
    let result = handler.verify(&empty);
    assert_verify_rejected(&result, "空 claims 的 JWT 应被拒绝");
    match result {
        Err(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// ACC-JWT-013（正常）：iat 稍在未来容忍时钟偏差——`Validation` 仅校验 exp
/// 不校验 iat，签发方时钟快几秒时 token 仍可用，且 iat 值原样保留。
/// 迁自 tests/protocol/jwt_edge_cases.rs::iat_future_time_tolerates_clock_skew
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_013_future_iat_tolerates_clock_skew() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secret = "acceptance-jwt-clock-skew-secret-0123456789ab";
    let handler = JwtHandler::new(secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // iat 在未来 60 秒（模拟时钟偏差）；exp 未过期
    let claims = garrison::protocol::jwt::GarrisonJwtClaims {
        sub: "1001".to_string(),
        iat: now + 60,
        exp: now + 3600,
        login_id: "1001".to_string(),
        device: None,
        jti: None,
        nbf: None,
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("手工签发应成功");

    let verified = handler
        .verify(&token)
        .expect("iat 在未来应被容忍（不校验 iat）");
    assert_eq!(verified.login_id, "1001".to_string());
    assert_eq!(verified.iat, now + 60, "iat 应保留未来时间值");
}

/// ACC-JWT-014（异常）：已过期 JWT 的 refresh 返回 `ExpiredToken`——refresh
/// 内部先 verify，过期的 token 在校验阶段即被拒绝。
/// 迁自 tests/protocol/jwt_edge_cases.rs::refresh_expired_token_returns_error
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_014_refresh_expired_token_returns_expired() {
    let handler = JwtHandler::new("acceptance-jwt-refresh-expired-secret-0123");
    let token = handler.sign("1001", 1).expect("timeout=1 应允许签发");

    // jsonwebtoken 以 u64 秒比较 exp < now：sleep 必须跨过整数秒边界，
    // 否则 floor(now)==exp 时过期判定失败（探测定时缺陷，2.5s 稳过）。
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    let result = handler.refresh(&token, 3600);
    match result {
        Err(GarrisonError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken，实际: {:?}", other),
    }
}

// ============================================================================
// ACC-JWT-015..019：JWT 三模式矩阵（T041 迁移自 tests/integration/jwt_modes.rs；
// HS256/HS512 roundtrip、跨算法、Mixin 语义去重至 ACC-JWT-001/002/003/007，
// refresh 轮换/无效拒绝去重至 ACC-JWT-010/011）
// ============================================================================

/// ACC-JWT-015（正常）：`with_device` 设置设备标识后 claims.device 为 Some
///（原 with_device_sets_claims_device）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_015_with_device_sets_claims_device() {
    let handler = JwtHandler::new("device-secret-min-32-bytes-long!!").with_device("web-browser");
    let token = handler.sign("3003", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.device.as_deref(), Some("web-browser"));
}

/// ACC-JWT-016（异常）：`sign` 参数校验 fail-fast——空 secret 返回含 "secret"
/// 的 Config 错误；负数 timeout 返回含 "timeout" 的 Config 错误
///（原 sign_rejects_empty_secret + sign_rejects_negative_timeout 合并）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_016_sign_rejects_empty_secret_and_negative_timeout() {
    let handler = JwtHandler::new("");
    match handler.sign("1001", 3600).unwrap_err() {
        GarrisonError::Config(msg) => assert!(
            msg.contains("secret"),
            "错误消息应提及 secret，实际: {}",
            msg
        ),
        other => panic!("期望 Config，实际: {:?}", other),
    }

    let handler = JwtHandler::new("valid-secret-min-32-bytes-long!!!!");
    match handler.sign("1001", -1).unwrap_err() {
        GarrisonError::Config(msg) => assert!(
            msg.contains("timeout"),
            "错误消息应提及 timeout，实际: {}",
            msg
        ),
        other => panic!("期望 Config，实际: {:?}", other),
    }
}

/// 空授权 `GarrisonInterface` 替身（仅满足策略构造，不参与断言）。
struct JwtNoopInterface;

#[async_trait::async_trait]
impl garrison::stp::GarrisonInterface for JwtNoopInterface {
    async fn get_permission_list(
        &self,
        _login_id: &str,
    ) -> garrison::error::GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> garrison::error::GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

/// 构造带指定 `JwtMode` + `token_style=jwt` 的 `GarrisonLogicDefault`
///（镜像 integration/jwt_modes.rs 的 make_logic_with_mode 装配）。
async fn make_logic_with_jwt_mode(
    mode: garrison::stp::JwtMode,
) -> Arc<garrison::stp::GarrisonLogicDefault> {
    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
    use garrison::session::GarrisonSession;
    use garrison::stp::JwtMode;
    use garrison::strategy::GarrisonPermissionStrategy;

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
    let mut config = garrison::config::GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "jwt-modes-test-secret-0123456789abcdef".to_string().into();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    // T017：Stateless JWT 模式必须启用 JWT 撤销黑名单（fail-closed 守卫）。
    if mode == JwtMode::Stateless {
        config.enable_jwt_revocation = true;
    }
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        garrison::strategy::GarrisonPermissionStrategyDefault::new(Arc::new(JwtNoopInterface)),
    );
    Arc::new(
        garrison::stp::GarrisonLogicDefault::new(session, Arc::new(config), firewall)
            .with_jwt_mode(mode),
    )
}

/// ACC-JWT-017（正常+异常）：`JwtMode::Stateless`——仅 JWT verify 不查 session：
/// 用 `JwtHandler` 直接签发的 token（无 session）通过 `check_login`；无效 JWT 被拒
///（原 stateless_mode_passes_with_jwt_only + stateless_mode_rejects_invalid_jwt）。
/// 注：与 ACC-RES-001（DAO 故障下无状态降级）互补——本场景断言「无 session 也
/// 可验证」的 Stateless 核心语义。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_017_stateless_mode_requires_jwt_only() {
    use garrison::stp::{with_current_token, JwtMode, SessionLogic};

    let logic = make_logic_with_jwt_mode(JwtMode::Stateless).await;

    // 正常：JwtHandler 直接签发（无 session）→ check_login 通过
    let handler = JwtHandler::new("jwt-modes-test-secret-0123456789abcdef");
    let token = handler.sign("5005", 3600).unwrap();
    let result = with_current_token(token, async { logic.check_login().await }).await;
    assert!(
        result.is_ok(),
        "Stateless 模式有效 JWT 应通过: {:?}",
        result.err()
    );
    assert!(result.unwrap(), "check_login 应返回 true");

    // 异常：无效 JWT → 拒绝
    let result = with_current_token("invalid.jwt.token".to_string(), async {
        logic.check_login().await
    })
    .await;
    assert!(result.is_err(), "Stateless 模式无效 JWT 应被拒绝");
}

/// ACC-JWT-018（正常+异常）：`JwtMode::Simple`——仅 session 校验，不验证 JWT
/// 签名（token_style=uuid）：login 创建 session 后通过；无 session 的任意 token
/// 失败（原 simple_mode_passes_with_session_only + simple_mode_fails_without_session）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_jwt_018_simple_mode_session_only() {
    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
    use garrison::session::GarrisonSession;
    use garrison::stp::{
        with_current_token, GarrisonLogicDefault, JwtMode, LoginParams, SessionLogic,
    };
    use garrison::strategy::GarrisonPermissionStrategy;

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
    let mut config = garrison::config::GarrisonConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        garrison::strategy::GarrisonPermissionStrategyDefault::new(Arc::new(JwtNoopInterface)),
    );
    let logic = Arc::new(
        GarrisonLogicDefault::new(session, Arc::new(config), firewall)
            .with_jwt_mode(JwtMode::Simple),
    );

    // 正常：login 创建 session → 通过
    let token = logic
        .login("8008", &LoginParams::default())
        .await
        .expect("login 应成功");
    let result = with_current_token(token, async { logic.check_login().await }).await;
    assert!(
        result.is_ok(),
        "Simple 模式 login 后 check_login 应通过: {:?}",
        result.err()
    );
    assert!(result.unwrap(), "check_login 应返回 true");

    // 异常：无 session → 失败
    let result = with_current_token("any-token-without-session".to_string(), async {
        logic.check_login().await
    })
    .await;
    assert!(result.is_err(), "Simple 模式无 session 应失败");
}

/// ACC-JWT-019（正常）：`JwtMode::default() == Mixin`（spec R-001 推荐默认）且
/// `JwtMode` 为 Copy（赋值后原值仍可用；原 jwt_mode_default_is_mixin +
/// jwt_mode_is_copy 合并）。
#[test]
fn acc_jwt_019_jwt_mode_default_is_mixin_and_copy() {
    use garrison::stp::JwtMode;

    assert_eq!(JwtMode::default(), JwtMode::Mixin);
    let mode = JwtMode::Stateless;
    let copied = mode;
    assert_eq!(mode, copied);
    assert_eq!(mode, JwtMode::Stateless);
}
