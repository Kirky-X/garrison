// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! oauth2 域验收。
//! `OAuth2Client` 客户端侧四种授权流程（authorization_code+PKCE / client_credentials /
//! password / refresh_token）+ Token Introspection，以及授权码重放 / 错误 client_secret /
//! 错误 redirect_uri / PKCE verifier 不匹配 / 无效 refresh token / scope 越权
//! 等异常路径，「正常 + 异常」成对覆盖。
//!
//! # 真实授权服务器（2026-09 起，用户裁定：验收层禁止 mock）
//!
//! 全部场景打 docker-compose.e2e.yml 拉起的真实 Keycloak 26（realm=garrison，
//! scripts/keycloak_provision.py 幂等供给），授权码经 tests/acceptance/
//! keycloak_fixture.rs 驱动真实登录表单流获取。Keycloak 不可达时按
//! environment.rs 门控约定 `[SKIP]`。原 wiremock 模拟面（响应体断言 /
//! expires_in=0 / 空串 scope 请求体差异）下沉至 src/protocol/oauth2/tests.rs
//! 单元测试（单元层允许 mock）。
//!
//! # API 偏差记录
//!
//! - `OAuth2Client` 不提供 revoke 方法（RFC 7009 撤销属授权服务器职责，客户端库
//!   无此 API）。撤销路径以「fixture 直连真实 /revoke 端点吊销 → introspection
//!   返回 active=false」的客户端可观测语义覆盖。
//! - 授权码重放检测同样是授权服务器的职责（客户端无状态），由真实 Keycloak
//!   的授权码单次消费语义覆盖（首次 200 / 重放 400 invalid_grant）。

#![cfg(feature = "protocol-oauth2")]

use crate::keycloak_fixture::{
    KeycloakFixture, CLIENT_ID, CLIENT_SECRET, PASSWORD, REDIRECT_HTTPS, REDIRECT_LOCAL,
    REVOKE_PATH, USERNAME,
};
use garrison::error::GarrisonError;
use garrison::protocol::oauth2::OAuth2Client;
use serial_test::serial;

/// Keycloak 不可达时统一跳过（真实 IdP 门控）。
macro_rules! require_keycloak {
    ($fx:expr) => {
        if !$fx.available_or_skip("oauth2").await {
            return;
        }
    };
}

/// 断言错误类型为 `GarrisonError::OAuth2` 且消息包含 `needle`。
fn assert_oauth2_err(
    result: &garrison::error::GarrisonResult<garrison::protocol::oauth2::TokenResponse>,
    needle: &str,
) {
    match result.as_ref().err() {
        Some(GarrisonError::OAuth2(msg)) => assert!(
            msg.contains(needle),
            "OAuth2 错误消息应包含 {}，实际: {}",
            needle,
            msg
        ),
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 驱动真实登录表单流获取授权码（带 PKCE challenge），返回 `(code, state)`。
async fn real_auth_code(
    fx: &KeycloakFixture,
    scope: Option<&str>,
    redirect_uri: &str,
    state: &str,
    code_challenge: Option<&str>,
) -> (String, String) {
    fx.obtain_auth_code(scope, redirect_uri, state, code_challenge)
        .await
        .expect("真实登录表单流应成功获取授权码")
}

// ============================================================================
// 四种授权流程 + introspection（正常）
// ============================================================================

/// （正常）：authorization_code + PKCE 全流程（真实 Keycloak）——授权 URL 参数
/// 齐全、code_challenge 符合 RFC 7636 测试向量；经真实登录表单流获取授权码后
/// 交换成功。PKCE 真实验证语义：challenge 绑定在授权码上，错误 verifier 的
/// 交换必须失败（见 acc_oauth2_010），故交换成功本身就证明 code_verifier
/// 被真实发送并通过了授权服务器的 S256 比对。
#[tokio::test]
#[serial]
async fn acc_oauth2_001_authorization_code_with_pkce_full_flow() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_LOCAL);
    // RFC 7636 Appendix B 测试向量（43 字符合法 verifier）
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // 1) 授权 URL：含 PKCE 所需全部参数（客户端侧构造）
    let (auth_url, challenge) = client
        .get_auth_url_with_pkce("acc-state", verifier)
        .expect("get_auth_url_with_pkce 应成功");
    assert_eq!(
        challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge 应符合 RFC 7636 B.2 测试向量"
    );
    assert!(
        auth_url.contains("response_type=code"),
        "URL 应含 response_type=code"
    );
    assert!(
        auth_url.contains(&format!("client_id={}", CLIENT_ID)),
        "URL 应含 client_id"
    );
    assert!(auth_url.contains("state=acc-state"), "URL 应含 state");
    assert!(
        auth_url.contains("code_challenge="),
        "URL 应含 code_challenge"
    );
    assert!(
        auth_url.contains("code_challenge_method=S256"),
        "URL 应含 code_challenge_method=S256"
    );

    // 2) 真实登录表单流：以授权 URL 的 challenge 获取真实授权码
    let (code, state) = real_auth_code(
        &fx,
        Some("openid"),
        REDIRECT_LOCAL,
        "acc-state",
        Some(&challenge),
    )
    .await;
    assert_eq!(
        state, "acc-state",
        "回调 state 应与授权请求一致（真实 CSRF 锚点）"
    );

    // 3) 授权码 + verifier 交换 token（真实 Keycloak 校验 S256(verifier)=challenge）
    let token = client
        .exchange_code_with_pkce(&code, "acc-state", &state, verifier)
        .await
        .expect("PKCE 交换应成功");
    assert!(
        !token.access_token.is_empty(),
        "access_token 应非空（真实签发）"
    );
    assert_eq!(token.token_type, "Bearer");
    assert!(
        token.expires_in.map(|e| e > 0).unwrap_or(false),
        "expires_in 应为正数，实际: {:?}",
        token.expires_in
    );
    assert!(
        token.refresh_token.is_some(),
        "authorization_code 流程应签发 refresh_token"
    );
    assert!(
        token
            .scope
            .as_deref()
            .unwrap_or_default()
            .contains("openid"),
        "scope 应包含请求的 openid，实际: {:?}",
        token.scope
    );
}

/// （正常）：client_credentials 流程（真实 Keycloak 服务账号）——token 签发
/// 且不含 refresh_token（授权服务器对 client_credentials 不签发刷新令牌的
/// 真实语义）。
#[tokio::test]
#[serial]
async fn acc_oauth2_002_client_credentials_flow() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);
    let token = client
        .get_client_credentials_token(None)
        .await
        .expect("client_credentials 应成功");
    assert!(!token.access_token.is_empty(), "access_token 应非空");
    assert!(
        token.expires_in.map(|e| e > 0).unwrap_or(false),
        "expires_in 应为正数"
    );
    assert_eq!(
        token.refresh_token, None,
        "client_credentials 响应不应含 refresh_token（Keycloak 真实语义）"
    );
}

/// （正常+异常）：password grant（真实 Keycloak ROPC）——正确凭证换 token
/// （含 refresh_token）；空 username 客户端预校验拒绝（InvalidParam，不发 HTTP）。
#[tokio::test]
#[serial]
async fn acc_oauth2_003_password_grant_flow() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);

    // 正常：真实用户凭证 → token + refresh_token
    let token = client
        .get_password_token(USERNAME, PASSWORD, Some("openid"))
        .await
        .expect("password grant 应成功");
    assert!(!token.access_token.is_empty(), "access_token 应非空");
    assert!(token.refresh_token.is_some(), "ROPC 响应应含 refresh_token");
    assert!(
        token
            .scope
            .as_deref()
            .unwrap_or_default()
            .contains("openid"),
        "scope 应包含请求的 openid，实际: {:?}",
        token.scope
    );

    // 异常：空 username 客户端预校验拒绝（不发 HTTP）
    let err = client
        .get_password_token("", "secret-pass", None)
        .await
        .unwrap_err();
    match err {
        GarrisonError::InvalidParam(msg) => assert!(msg.contains("username"), "实际: {}", msg),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
}

/// （正常+异常）：refresh_token 换新 access_token（真实 Keycloak）；空
/// refresh_token 客户端预校验拒绝（InvalidParam）。
#[tokio::test]
#[serial]
async fn acc_oauth2_004_refresh_token_flow() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);
    let granted = client
        .get_password_token(USERNAME, PASSWORD, Some("openid"))
        .await
        .expect("password grant 应成功");
    let refresh_token = granted
        .refresh_token
        .expect("password grant 应含 refresh_token");

    // 正常：刷新成功且 access_token 轮换
    let token = client
        .refresh_access_token(&refresh_token, Some("openid"))
        .await
        .expect("refresh_token 应成功");
    assert!(!token.access_token.is_empty(), "刷新后 access_token 应非空");
    assert_ne!(
        token.access_token, granted.access_token,
        "刷新应签发新的 access_token（真实轮换）"
    );

    // 异常：空 refresh_token → InvalidParam
    let err = client.refresh_access_token("", None).await.unwrap_err();
    match err {
        GarrisonError::InvalidParam(_) => {},
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
}

/// （正常）：introspect（RFC 7662，真实 Keycloak）——active token 内省返回
/// active=true 与 sub/exp/jti 等标准 claims，查询请求 POST 至真实
/// introspection 端点并携带 client 凭证。
#[tokio::test]
#[serial]
async fn acc_oauth2_005_introspect_active_token() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx
        .oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS)
        .with_introspect_url(format!(
            "{}/token/introspect",
            crate::keycloak_fixture::oidc_base()
        ));
    let token = client
        .get_password_token(USERNAME, PASSWORD, Some("openid"))
        .await
        .expect("password grant 应成功");

    let info = client
        .introspect_token(&token.access_token)
        .await
        .expect("introspect 应成功");
    assert!(info.active, "真实签发的 token 应为 active");
    assert!(
        info.sub.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
        "active 响应应携带 sub（Keycloak 真实 claims），实际: {:?}",
        info.sub
    );
    assert!(info.exp.is_some(), "active 响应应携带 exp");
    assert!(info.jti.is_some(), "active 响应应携带 jti");
}

// ============================================================================
// 撤销后的 introspection（异常侧，客户端可观测语义）
// ============================================================================

/// （异常）：token 被撤销后 introspection 返回 active=false——fixture 直连
/// 真实 RFC 7009 /revoke 端点吊销有效 token，验证内省状态真实翻转
///（active=true → 吊销 → false）。
/// 注：OAuth2Client 无 revoke API（RFC 7009 属授权服务器职责），见文件头偏差记录。
#[tokio::test]
#[serial]
async fn acc_oauth2_006_revoked_token_introspects_inactive() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx
        .oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS)
        .with_introspect_url(format!(
            "{}/token/introspect",
            crate::keycloak_fixture::oidc_base()
        ));
    let token = client
        .get_password_token(USERNAME, PASSWORD, Some("openid"))
        .await
        .expect("password grant 应成功");

    let before = client
        .introspect_token(&token.access_token)
        .await
        .expect("撤销前 introspect 应成功");
    assert!(before.active, "撤销前 token 应 active");
    assert!(before.sub.is_some(), "撤销前 active 响应应携带 sub");

    // 真实吊销：RFC 7009 端点（客户端凭证 + token）
    let resp = fx
        .post_form(
            REVOKE_PATH,
            &[
                ("token", token.access_token.as_str()),
                ("client_id", CLIENT_ID),
                ("client_secret", CLIENT_SECRET),
            ],
        )
        .await
        .expect("吊销请求应发送成功");
    assert!(
        resp.status().is_success(),
        "真实 /revoke 端点应成功，实际: {}",
        resp.status()
    );

    let after = client
        .introspect_token(&token.access_token)
        .await
        .expect("撤销后 introspect 应成功");
    assert!(!after.active, "撤销后 token 应 inactive（真实吊销语义）");
}

// ============================================================================
// 异常路径
// ============================================================================

/// （异常）：授权码重放被拒（真实 Keycloak 单次消费语义）——首次交换 200
/// 成功，同一 code 二次交换被授权服务器拒绝（400 invalid_grant），客户端返回
/// OAuth2 错误。
#[tokio::test]
#[serial]
async fn acc_oauth2_007_authorization_code_replay_rejected() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_LOCAL);
    let verifier = "a".repeat(43);
    let challenge = OAuth2Client::generate_pkce_challenge(&verifier).expect("challenge 应生成");
    let (code, state) = real_auth_code(
        &fx,
        Some("openid"),
        REDIRECT_LOCAL,
        "state",
        Some(&challenge),
    )
    .await;

    let first = client
        .exchange_code_with_pkce(&code, "state", &state, &verifier)
        .await;
    assert!(first.is_ok(), "首次使用 code 应成功");
    assert!(
        !first.unwrap().access_token.is_empty(),
        "首次交换应签发真实 token"
    );

    let second = client
        .exchange_code_with_pkce(&code, "state", "state", &verifier)
        .await;
    assert!(second.is_err(), "重放同一 code 应被拒绝");
    match second.err() {
        Some(GarrisonError::OAuth2(msg)) => {
            assert!(msg.contains("400"), "应报告 400 状态，实际: {}", msg);
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// （异常）：错误 client_secret——真实 Keycloak 拒绝（401 invalid_client），
/// 客户端返回 OAuth2 错误；同一客户端凭证在密钥正确时成功，证明传输的正是
/// 所配置密钥（错误密钥被真实校验拒绝）。
#[tokio::test]
#[serial]
async fn acc_oauth2_008_wrong_client_secret_rejected() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client("wrong-secret", REDIRECT_HTTPS);
    let err = client
        .get_client_credentials_token(None)
        .await
        .expect_err("错误 client_secret 应被真实授权服务器拒绝");
    match err {
        GarrisonError::OAuth2(msg) => assert!(msg.contains("401"), "实际: {}", msg),
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }

    // 对照：密钥正确时同一端点成功（错误密钥确实被传输并被真实校验拒绝）
    let ok_client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);
    assert!(
        ok_client.get_client_credentials_token(None).await.is_ok(),
        "正确 client_secret 应成功（对照）"
    );
}

/// （异常）：错误 redirect_uri——构造期拒绝非 https/localhost 回调
/// （spec P2.3 客户端侧校验）；真实 Keycloak 对回调不匹配的交换返回 400
/// invalid_grant（授权码绑定授权请求时的 redirect_uri）。
#[tokio::test]
#[serial]
async fn acc_oauth2_009_wrong_redirect_uri_rejected() {
    // 1) 构造期：明文 HTTP + 公网域名回调被拒绝（P2.3）
    // OAuth2Client 无 Debug，unwrap_err 不可用，用 match 解构
    let err = match OAuth2Client::new(
        CLIENT_ID,
        CLIENT_SECRET,
        "http://evil.example.com/callback",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    ) {
        Ok(_) => panic!("http://evil.example.com 回调应被构造期拒绝"),
        Err(e) => e,
    };
    match err {
        GarrisonError::InvalidParam(msg) => assert!(msg.contains("redirect_uri"), "实际: {}", msg),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    // localhost 开发例外放行
    assert!(
        OAuth2Client::new(
            CLIENT_ID,
            CLIENT_SECRET,
            "http://localhost:8080/cb",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .is_ok(),
        "localhost 回调应放行"
    );

    // 2) 授权服务器侧（真实 Keycloak）：以 REDIRECT_LOCAL 获取授权码，
    //    再以另一个已注册回调 REDIRECT_HTTPS 交换 → 授权码绑定的回调
    //    不匹配 → 400 invalid_grant
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);
    let verifier = "a".repeat(43);
    let challenge = OAuth2Client::generate_pkce_challenge(&verifier).expect("challenge 应生成");
    let (code, state) = real_auth_code(
        &fx,
        Some("openid"),
        REDIRECT_LOCAL,
        "state",
        Some(&challenge),
    )
    .await;

    let mismatched = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);
    let result = mismatched
        .exchange_code_with_pkce(&code, "state", &state, &verifier)
        .await;
    assert_oauth2_err(&result, "400");
}

/// （异常）：PKCE verifier 不匹配——客户端预校验非法 verifier
/// （InvalidParam，不发 HTTP）；state 不匹配（CSRF 防护，不发 HTTP）；真实
/// Keycloak 端 verifier 与授权码绑定的 challenge 不一致返回 400 invalid_grant。
#[tokio::test]
#[serial]
async fn acc_oauth2_010_pkce_verifier_mismatch_rejected() {
    // 1) 非法 verifier（长度 < 43）：客户端预校验拒绝，不发 HTTP
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);
    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_LOCAL);

    let err = client
        .exchange_code_with_pkce("code-x", "state", "state", "too-short")
        .await
        .unwrap_err();
    match err {
        GarrisonError::InvalidParam(msg) => {
            assert!(msg.contains("oauth2-pkce-length-invalid"), "实际: {}", msg)
        },
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }

    // 2) state 不匹配：CSRF 防护在客户端拦截，不发 HTTP
    let verifier = "a".repeat(43);
    let err = client
        .exchange_code_with_pkce("code-x", "expected-state", "attacker-state", &verifier)
        .await
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => assert!(msg.contains("state"), "实际: {}", msg),
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }

    // 3) 授权服务器端（真实 Keycloak）：verifier 与授权请求的 challenge
    //    不一致 → 400 invalid_grant
    let challenge = OAuth2Client::generate_pkce_challenge(&verifier).expect("challenge 应生成");
    let (code, state) = real_auth_code(
        &fx,
        Some("openid"),
        REDIRECT_LOCAL,
        "state",
        Some(&challenge),
    )
    .await;
    let wrong_verifier = "b".repeat(43);
    let result = client
        .exchange_code_with_pkce(&code, "state", &state, &wrong_verifier)
        .await;
    assert_oauth2_err(&result, "400");
}

/// （异常）：无效 refresh_token——真实 Keycloak 返回 400 invalid_grant，
/// 客户端返回 OAuth2 错误。
#[tokio::test]
#[serial]
async fn acc_oauth2_011_invalid_refresh_token_rejected() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);
    let result = client
        .refresh_access_token("stolen-or-expired-not-a-real-token", None)
        .await;
    assert_oauth2_err(&result, "400");
}

/// （异常）：scope 越权——client 注入 ScopeRegistry（oauth2-scope-handler）
/// 后，请求未授权 scope 在发送 HTTP 前被拦截（OAuth2 错误）；授权 scope
/// 经真实 Keycloak client_credentials 正常放行（token scope 含 read）。
#[cfg(feature = "oauth2-scope-handler")]
#[tokio::test]
#[serial]
async fn acc_oauth2_012_scope_privilege_escalation_blocked_client_side() {
    use garrison::protocol::oauth2::scope::{ScopeHandler, ScopeRegistry};
    use std::sync::Arc;

    struct ReadOnlyScope;
    impl ScopeHandler for ReadOnlyScope {
        fn validate(&self, scope: &str, _login_id: i64) -> garrison::error::GarrisonResult<bool> {
            Ok(scope == "read")
        }
    }

    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let registry = ScopeRegistry::new();
    registry.register("read", Arc::new(ReadOnlyScope));
    registry.register("admin", Arc::new(ReadOnlyScope)); // admin → handler 拒绝（越权）
    let client = fx
        .oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS)
        .with_scope_registry(Arc::new(registry));

    // 越权 scope（handler 显式拒绝）：客户端侧拦截（OAuth2 错误）
    let err = client
        .get_client_credentials_token(Some("admin"))
        .await
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(msg.contains("scope validation failed"), "实际: {}", msg)
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }

    // 未注册 scope：同样客户端侧拦截（fail-loud，不静默放行）
    let err = client
        .get_client_credentials_token(Some("write"))
        .await
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(
                msg.contains("oauth2-scope-handler-not-registered"),
                "实际: {}",
                msg
            )
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }

    // 授权 scope：真实 Keycloak 放行，token scope 含 read（realm 内置
    // optional client scope read，scripts/keycloak_provision.py 供给）
    let token = client
        .get_client_credentials_token(Some("read"))
        .await
        .expect("授权 scope 应放行");
    assert!(
        token
            .scope
            .as_deref()
            .unwrap_or_default()
            .split(' ')
            .any(|s| s == "read"),
        "真实签发 token 的 scope 应含 read，实际: {:?}",
        token.scope
    );
}

// ============================================================================
// 构造校验与边界（迁自 tests/protocol/oauth2_*.rs）
// ============================================================================

/// （正常+异常）：授权 URL 构造——`redirect_uri` 以 URL 编码查询参数出现；
/// 空 client_id 构造期拒绝（`Config("oauth2-client-id-empty")`）。
/// 迁自 tests/protocol/oauth2_integration.rs::get_auth_url_with_pkce_includes_required_params
/// 与 new_rejects_empty_client_id（2 例合并）。纯客户端构造，无网络请求。
#[tokio::test]
#[serial]
async fn acc_oauth2_013_auth_url_redirect_uri_and_empty_client_id_rejected() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    // 正常：授权 URL 含 URL 编码的 redirect_uri 参数（真实端点 URL 拼接）
    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);
    let verifier = "a".repeat(43);
    let (url, _challenge) = client
        .get_auth_url_with_pkce("xyz-state", &verifier)
        .expect("get_auth_url_with_pkce 应成功");
    assert!(
        url.contains("redirect_uri="),
        "URL 应含 redirect_uri（URL 编码），实际: {}",
        url
    );

    // 异常：空 client_id → 构造期拒绝
    let err = match OAuth2Client::new(
        "",
        "secret",
        "https://cb.example.com",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    ) {
        Ok(_) => panic!("空 client_id 应构造失败"),
        Err(e) => e,
    };
    match err {
        GarrisonError::Config(msg) => {
            assert!(msg.contains("client-id-empty"), "实际: {}", msg)
        },
        other => panic!("期望 Config（client-id-empty），实际: {:?}", other),
    }
}

/// （正常）：请求 scope 与不请求 scope 的真实行为差异——client_credentials
/// 携带 `scope=read` 时真实 Keycloak 签发的 token scope 含 `read`，未携带时
/// 仅含默认 scopes，证明 scope 参数真实随请求传输并被授权服务器生效。
/// （原 wiremock 场景「空串 scope 请求体差异」已下沉至单元测试
/// src/protocol/oauth2/tests.rs，验收层以真实服务器可观测语义覆盖。）
#[tokio::test]
#[serial]
async fn acc_oauth2_014_requested_scope_narrows_real_token_scope() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS);

    let with_scope = client
        .get_client_credentials_token(Some("read"))
        .await
        .expect("scope=read 请求应成功");
    assert!(
        with_scope
            .scope
            .as_deref()
            .unwrap_or_default()
            .split(' ')
            .any(|s| s == "read"),
        "携带 scope=read 时签发 token 应含 read，实际: {:?}",
        with_scope.scope
    );

    let without_scope = client
        .get_client_credentials_token(None)
        .await
        .expect("无 scope 请求应成功");
    assert!(
        !without_scope
            .scope
            .as_deref()
            .unwrap_or_default()
            .split(' ')
            .any(|s| s == "read"),
        "未携带 scope 时签发 token 不应含 read，实际: {:?}",
        without_scope.scope
    );
}

/// （正常）：真实签发 token 的 `expires_in` 为正且内省 active——协议层只解析
/// 不判定过期（判定权在业务方）；真实授权服务器不会签发立即过期的 token，
/// `expires_in=0` 的解析边界已下沉至单元测试（src/protocol/oauth2/tests.rs）。
#[tokio::test]
#[serial]
async fn acc_oauth2_015_expires_in_positive_and_token_active() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let client = fx
        .oauth2_client(CLIENT_SECRET, REDIRECT_HTTPS)
        .with_introspect_url(format!(
            "{}/token/introspect",
            crate::keycloak_fixture::oidc_base()
        ));
    let resp = client
        .get_client_credentials_token(None)
        .await
        .expect("请求应成功");

    assert_eq!(
        resp.expires_in.map(|e| e > 0),
        Some(true),
        "真实签发 token 的 expires_in 应为正，实际: {:?}",
        resp.expires_in
    );
    let info = client
        .introspect_token(&resp.access_token)
        .await
        .expect("内省应成功");
    assert!(info.active, "expires_in>0 的真实 token 应内省 active");
}

// ============================================================================
// Keycloak OIDC RP 完整流程（`keycloak-oidc` 门控）
// ============================================================================

/// （正常）：Keycloak OIDC RP 完整授权码流程端到端（真实 Keycloak）——
/// `discover` → 真实登录表单流获取授权码 → `exchange_code` →
/// `verify_id_token`（真实 JWKS RS256 验签，id_token 含
/// sub / preferred_username / email / realm_access.roles / resource_access /
/// tenant_id claim 全部由真实 realm 供给产生，scripts/keycloak_provision.py）。
#[cfg(all(
    feature = "keycloak-oidc",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_oauth2_016_keycloak_oidc_rp_full_flow_e2e() {
    use garrison::dao::GarrisonDaoOxcache;
    use garrison::{KeycloakConfig, KeycloakProvider};
    use std::sync::Arc;

    let fx = KeycloakFixture::new();
    require_keycloak!(fx);

    let config = KeycloakConfig {
        base_url: crate::keycloak_fixture::realm_base(),
        client_id: CLIENT_ID.to_string(),
        client_secret: Some(CLIENT_SECRET.to_string()),
        redirect_uri: REDIRECT_HTTPS.to_string(),
        expected_iss: crate::keycloak_fixture::realm_base(),
    };
    let provider = KeycloakProvider::new(config)
        .expect("KeycloakProvider::new 应成功")
        .with_dao(Arc::new(
            GarrisonDaoOxcache::new()
                .await
                .expect("构造 GarrisonDaoOxcache 应成功"),
        ));

    // Step 1: discover（真实 discovery 端点）
    let metadata = provider.discover().await.expect("discover 应成功");
    assert_eq!(metadata.issuer, crate::keycloak_fixture::realm_base());
    assert_eq!(
        metadata.token_endpoint,
        format!("{}/token", crate::keycloak_fixture::oidc_base())
    );
    assert_eq!(
        metadata.jwks_uri,
        format!(
            "{}/protocol/openid-connect/certs",
            crate::keycloak_fixture::realm_base()
        )
    );

    // Step 2: 真实登录表单流获取授权码（无 PKCE，confidential client 凭证交换）
    let (code, state) = real_auth_code(&fx, Some("openid"), REDIRECT_HTTPS, "rp-state", None).await;
    assert_eq!(state, "rp-state", "回调 state 应与授权请求一致");
    let token_set = provider
        .exchange_code(&code)
        .await
        .expect("exchange_code 应成功");
    assert!(!token_set.access_token.is_empty(), "access_token 应非空");
    assert!(!token_set.refresh_token.is_empty(), "refresh_token 应非空");
    assert!(!token_set.id_token.is_empty(), "id_token 应非空");
    assert!(token_set.expires_in > 0, "expires_in 应为正数");

    // Step 3: verify_id_token（真实 JWKS RS256 验签 + claims 解析）
    let keycloak_claims = provider
        .verify_id_token(&token_set.id_token)
        .await
        .expect("verify_id_token 应成功");
    assert!(
        !keycloak_claims.sub.is_empty(),
        "claims.sub 应为真实用户主体标识"
    );
    assert_eq!(
        keycloak_claims.preferred_username.as_deref(),
        Some(USERNAME),
        "preferred_username 应匹配"
    );
    assert_eq!(
        keycloak_claims.email.as_deref(),
        Some("alice@garrison.test"),
        "email 应匹配"
    );
    assert!(
        keycloak_claims
            .realm_access
            .roles
            .contains(&"admin".to_string())
            && keycloak_claims
                .realm_access
                .roles
                .contains(&"user".to_string()),
        "realm_access.roles 应含 admin/user，实际: {:?}",
        keycloak_claims.realm_access.roles
    );
    assert_eq!(
        keycloak_claims.tenant_id,
        Some(42),
        "tenant_id claim 应正确解析（user profile + mapper 真实供给）"
    );
    assert!(
        keycloak_claims.resource_access.contains_key("account"),
        "resource_access 应包含 account，实际: {:?}",
        keycloak_claims.resource_access
    );
}

// ============================================================================
// redirect_uri / state / nonce 对抗测试（审计项 2：OAuth state/nonce 绕过、
// redirect_uri 精确匹配、token/state 重放的对抗回归锁定）
// ============================================================================

/// （对抗）：redirect_uri 白名单精确匹配锁定（garrison 自有 AS 侧，进程内真实
/// `AuthorizeHandler`，非 mock）——白名单含 query string 的既有行为保持（精确相等
/// 放行）；前缀 / 子路径 / 大小写 / 百分号编码变体全部拒绝。open-redirect 防线的
/// 回归锚点：白名单匹配一旦漂移为前缀/大小写不敏感匹配，本测试即红。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_oauth2_017_redirect_uri_exact_match_adversarial() {
    use garrison::dao::InMemoryDao;
    use garrison::oauth2_server::authorize::{
        generate_code_challenge, AuthorizeHandler, AuthorizeRequest, AuthorizeResponse,
    };
    use garrison::oauth2_server::client::{DaoOAuth2ClientStore, GrantType, OAuth2ClientStore};
    use std::sync::Arc;

    const ALLOWED: &str = "https://app.example.com/cb?tenant=acme";

    let dao = Arc::new(InMemoryDao::new());
    let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
    let handler =
        AuthorizeHandler::new(store.clone(), dao, "https://auth.example.com/login".into());

    store
        .create(
            garrison::oauth2_server::client::OAuth2Client::new(
                "acc-017",
                "secret-123",
                vec![ALLOWED.to_string()],
                vec![GrantType::AuthorizationCode],
                vec!["read".into()],
            )
            .expect("client 构造应成功"),
        )
        .await
        .expect("client 注册应成功");

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = generate_code_challenge(verifier);
    let mut req = AuthorizeRequest {
        response_type: "code".into(),
        client_id: "acc-017".into(),
        redirect_uri: ALLOWED.into(),
        scope: Some("read".into()),
        state: Some("acc-017-state".into()),
        code_challenge: challenge,
        code_challenge_method: "S256".into(),
    };

    // 白名单含 query string 的既有行为保持：精确相等 → 放行（Redirect）
    let resp = handler
        .authorize(&req, Some(1))
        .await
        .expect("精确匹配（含 query string）应放行");
    match resp {
        AuthorizeResponse::Redirect { location } => {
            assert!(
                location.starts_with(ALLOWED),
                "重定向应落在白名单 URI 上，实际: {}",
                location
            );
        },
        other => panic!("期望 Redirect，实际: {:?}", other),
    }

    // 对抗变体：全部必须拒绝（任何变体被放行即 open-redirect 防线失效）
    let variants: Vec<(&str, String)> = vec![
        // 前缀变体：白名单 URI 前缀 + 附加路径段
        ("path-prefix", format!("{}/extra", ALLOWED)),
        // 子路径变体：scheme+host 相同、路径不同
        (
            "sub-path",
            "https://app.example.com/cb/tenant=acme".to_string(),
        ),
        // query 注入变体：额外参数拼接
        ("query-append", format!("{}&evil=1", ALLOWED)),
        // 大小写变体：host / scheme 大小写混淆
        (
            "case-variant",
            "https://app.example.com/CB?tenant=acme".to_string(),
        ),
        // 百分号编码变体：query 值编码形式不同（%61cme ≙ acme）
        (
            "percent-encoded",
            "https://app.example.com/cb?tenant=%61cme".to_string(),
        ),
    ];
    for (name, uri) in variants {
        req.redirect_uri = uri;
        let result = handler.authorize(&req, Some(1)).await;
        assert!(
            result.is_err(),
            "redirect_uri 变体 [{}] 必须被精确匹配拒绝，实际放行",
            name
        );
    }
}

/// （对抗）：state 缺失与旧回调重放拒绝——
/// 1) state 缺失（expected/actual 任一空串）：客户端 fail-closed 拦截，不发 HTTP；
/// 2) state 重复使用（攻击者重放旧回调 URL：旧 state + 已消费授权码）：
///    客户端 state 比对通过（旧 state 与预期一致），由授权服务器授权码单次消费
///    语义拒绝（400 invalid_grant）——state 防护 + 单次消费双层防线端到端锁定。
#[tokio::test]
#[serial]
async fn acc_oauth2_018_state_missing_and_callback_replay_rejected() {
    let fx = KeycloakFixture::new();
    require_keycloak!(fx);
    let client = fx.oauth2_client(CLIENT_SECRET, REDIRECT_LOCAL);

    // 1) state 缺失：客户端 fail-closed（不发 HTTP）
    let verifier = "a".repeat(43);
    for (expected, actual) in [("", ""), ("expected", ""), ("", "actual")] {
        let err = client
            .exchange_code_with_pkce("code-x", expected, actual, &verifier)
            .await
            .unwrap_err();
        match err {
            GarrisonError::OAuth2(msg) => {
                assert!(
                    msg.contains("oauth2-state-missing"),
                    "state 缺失应返回 state-missing，实际: {}",
                    msg
                );
            },
            other => panic!("期望 OAuth2(state-missing)，实际: {:?}", other),
        }
    }

    // 2) 旧回调重放：真实流程获取授权码 → 正常交换 → 重放同一回调
    //    （同 state、同 code）→ 授权服务器 400 invalid_grant
    let challenge = OAuth2Client::generate_pkce_challenge(&verifier).expect("challenge 应生成");
    let (code, state) = real_auth_code(
        &fx,
        Some("openid"),
        REDIRECT_LOCAL,
        "acc-018-state",
        Some(&challenge),
    )
    .await;

    client
        .exchange_code_with_pkce(&code, "acc-018-state", &state, &verifier)
        .await
        .expect("首次交换应成功");

    let replay = client
        .exchange_code_with_pkce(&code, "acc-018-state", "acc-018-state", &verifier)
        .await;
    assert_oauth2_err(&replay, "400");
}

/// （对抗）：OIDC nonce 缺失拒绝（garrison OidcHandler 签发/验证原语，进程内
/// 真实代码）——expected nonce 缺失（空串）fail-closed 拒绝（含空对空）；token
/// nonce 缺失（签发方未回传）由常量时间比较拒绝；正确 nonce 对照放行。
#[cfg(feature = "protocol-oidc")]
#[test]
#[serial]
fn acc_oauth2_019_oidc_nonce_missing_rejected() {
    use garrison::protocol::oauth2::oidc::OidcHandler;

    let handler = OidcHandler::new(
        "https://auth.example.com",
        "acc-019-client",
        "acc-019-signing-secret-with-enough-entropy",
    )
    .expect("OidcHandler 构造应成功");

    // nonce 缺失形态 1：调用方未生成 expected nonce（空串）→ fail-closed
    let token = handler
        .sign_id_token("1001", "acc-019-nonce", "openid", 3600)
        .expect("签发应成功");
    let err = handler.verify_id_token(&token, "").unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(
                msg.contains("oidc-nonce-missing"),
                "expected nonce 缺失应 fail-closed，实际: {}",
                msg
            );
        },
        other => panic!("期望 OAuth2(nonce-missing)，实际: {:?}", other),
    }

    // nonce 缺失形态 2：空对空（token 无 nonce + expected 空）→ 拒绝
    let nonceless = handler
        .sign_id_token("1001", "", "openid", 3600)
        .expect("签发应成功");
    let err = handler.verify_id_token(&nonceless, "").unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(
                msg.contains("oidc-nonce-missing"),
                "空对空 nonce 不得放行，实际: {}",
                msg
            );
        },
        other => panic!("期望 OAuth2(nonce-missing)，实际: {:?}", other),
    }

    // nonce 缺失形态 3：token nonce 缺失而 expected 非空 → 常量时间比较拒绝
    let err = handler
        .verify_id_token(&nonceless, "acc-019-nonce")
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(msg.contains("nonce mismatch"), "实际: {}", msg);
        },
        other => panic!("期望 OAuth2(nonce mismatch)，实际: {:?}", other),
    }

    // 对照：正确 nonce 校验通过
    let claims = handler
        .verify_id_token(&token, "acc-019-nonce")
        .expect("正确 nonce 应放行");
    assert_eq!(claims.nonce, "acc-019-nonce");
}
