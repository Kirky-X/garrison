// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! protocol-webauthn 模块测试。
//!
//! 按安全属性组织：challenge 一次性（重放/TTL 过期/并发消费恰一成功）、
//! 注册仪式（重复绑定被拒/attestation 非法被拒/ExcludeCredentials）、
//! 认证仪式（assertion 重放被拒/克隆检测触发/正常认证更新落库）、
//! RP 配置派生（issuer 变更 rp_id 跟随/双 policy 准入差异）。
//!
//! 仪式测试采用 webauthn-rs 上游测试集的**真实 authenticator 录制向量**
//! （MPL-2.0，出处 webauthn-rs-core 0.5.5 src/core.rs 测试模块）：
//! challenge 固定，测试经 [`seed_registration`]/[`seed_authentication`]
//! 以与 start_* 相同的 SETNX 路径植入与向量匹配的仪式态。

use super::challenge::{ChallengePayload, ChallengeStore};
use super::credential::WebauthnCredential;
use super::service::{RelyingParty, WebauthnAuthentication, WebauthnService};
use super::{FactorPolicy, FactorPurpose, WebauthnCeremonyError, WebauthnConfig};
use crate::dao::repository::sqlite::DbnexusWebauthnCredentialRepository;
use crate::dao::repository::WebauthnCredentialRepository;
use crate::dao::InMemoryDao;
use std::sync::Arc;
use webauthn_rs::prelude::{
    Credential, CredentialID, PublicKeyCredential, RegisterPublicKeyCredential, Url,
    WebauthnBuilder,
};
use webauthn_rs_core::proto::{
    AttestationFormat, AttestationMetadata, COSEAlgorithm, COSEEC2Key, COSEKeyType, ECDSACurve,
    ParsedAttestation, ParsedAttestationData, RegisteredExtensions, UserVerificationPolicy,
};

// ============================================================================
// 测试装置
// ============================================================================

/// RP issuer：与录制向量的 origin/rp_id 一致（origin 带 8080 端口，rp_id=host）。
const ISSUER: &str = "https://etools-dev.example.com:8080";

/// 构造测试用 ChallengeStore（TTL 120s）。
fn test_store() -> ChallengeStore {
    ChallengeStore::new(Arc::new(InMemoryDao::new()), 120)
}

/// 构造测试用 WebauthnService（InMemoryDao + sqlite 凭据仓库在仪式测试中
/// 由 `test_service_with` 注入）。
pub(crate) fn test_config() -> WebauthnConfig {
    WebauthnConfig {
        issuer: ISSUER.to_string(),
        challenge_ttl_secs: 120,
        passwordless: FactorPolicy { enabled: true },
        second_factor: FactorPolicy { enabled: true },
    }
}

/// patch 序列化仪式态 JSON 中的 challenge 字段（录制向量 challenge 固定）。
///
/// webauthn-rs 的仪式态序列化带外层包装（PasskeyRegistration → `rs` /
/// PasskeyAuthentication → `ast`），patch 落在内层唯一对象的 `challenge`。
fn patch_state_challenge(state: &impl serde::Serialize, challenge_b64: &str) -> serde_json::Value {
    let mut v = serde_json::to_value(state).expect("仪式态应可序列化");
    let inner = v
        .as_object_mut()
        .expect("仪式态应为对象")
        .values_mut()
        .next()
        .expect("仪式态应有唯一内层对象")
        .as_object_mut()
        .expect("内层应为对象");
    inner["challenge"] = serde_json::Value::String(challenge_b64.to_string());
    v
}

/// 从 clientDataJSON 字节提取 challenge（base64url）。
fn client_data_challenge(client_data_json: &[u8]) -> String {
    let text = String::from_utf8(client_data_json.to_vec()).expect("clientDataJSON 应为 UTF-8");
    let v: serde_json::Value = serde_json::from_str(&text).expect("clientDataJSON 应为 JSON");
    v["challenge"]
        .as_str()
        .expect("clientDataJSON 应含 challenge")
        .to_string()
}

// ============================================================================
// 录制向量（webauthn-rs-core 0.5.5 测试集，MPL-2.0）
// ============================================================================

/// 注册向量（Windows Hello，fmt=none，RS256，flags=0x45 UP|UV|AT，counter=0）：
/// origin=https://etools-dev.example.com:8080，rp_id=etools-dev.example.com。
/// 字节数组自 webauthn-rs-core 0.5.5 测试集 test_win_hello_attest_none（MPL-2.0）
/// 程序化提取。
const REG_VECTOR_JSON: &str = r#"{
  "id": "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI",
  "rawId": "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI",
  "response": {
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ2wpgejnsqySxmYA_6D63eOJKMSO0N1z9i_GRS2layobRQAAAAAAAAAAAAAAAAAAAAAAAAAAACArCUQM4EIFz0_VhTc1aKFgsJ5j4j0oYyE9qn2_AdtWgqQBAwM5AQAgWQEApqOD6WFAiM9vJ1BQ5hMuOwz3l3GnnYzG46if0-hwdNE2lBqcOFg4G3Rm7VhjUUFPhfLAGRwtdIOB_blbI4EjwSxAVleJLBNK70iy8wvDh8LYbT5UrBC2UoyqAf9bUElkAXU9lLNfx6nk9K5FNrkPawUAbpsc83IgsNxdxKyeFgOaEpQUhF6mLRgbCP9sH-bEen3w19t2UOCSXFDbW9NYLRyFh1P01B15hGi9A2IqtAr56DuszG1AzotM9-YoJEdPC4tU05l9bGw3w80FWvhIKl4oiMFZA2ZtHkF1TGeWBCybaM9-XBChr9939ql_SA1TgQykZiqNrWaMNDkrcwzuWSFDAQAB",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRlFreTBGcW5tVjVLWXFGVTk2RTlhQXBTSVJ0alhpS2NWRlVmOEFtOGlEUSIsIm9yaWdpbiI6Imh0dHBzOi8vZXRvb2xzLWRldi5leGFtcGxlLmNvbTo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
  },
  "type": "public-key"
}"#;

/// 认证向量（与注册向量同凭据）：flags=0x05 UP|UV，BE/BS=0，counter=1
/// （注册 0 → 断言 1，单调推进）。pub(crate) 供 stp/mfa 全流程穿透测试复用。
pub(crate) const AUTH_VECTOR_JSON: &str = r#"{
  "id": "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI",
  "rawId": "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI",
  "response": {
    "authenticatorData": "bCmB6OeyrJLGZgD_oPrd44koxI7Q3XP2L8ZFLaVrKhsFAAAAAQ",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidlhSLWEwb2QwclZqc3EzV3B0UjgyeDJwQ1RvYUczajJWNjJwMHZHWmxyMCIsIm9yaWdpbiI6Imh0dHBzOi8vZXRvb2xzLWRldi5leGFtcGxlLmNvbTo4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
    "signature": "Tf2YU7jGBRBEM7IF5BSUqLYDyTuitWDdQ4jmPfwAJvSPYmQO4t_qOkgJ5r4AvbBlrLCSGd11Tw2wY9DThw889Wrow9clRojGGbqc4k3YVWSLSUmt0vR0VGy0inMPu4zGbtpO7mOD0uXyuIXbsetgu49S81h41rZ2WMad6VPOpbtvU9NEk4mwHK0kQlfh_MNltSx3xjDSury-FE4OMUOQg0xVRl-CiYSoIcRxUzsmLgGna8io8gZqjct7yzJFrQa3dXblvCd4vDA2dd8PmXoEGNo4-62mcfDnrxUc5PgKAUneNDlIMyyDzgTzQmQ9ce3dc7Ylux36Z7JoRZkv1EzI8g",
    "userHandle": "bWNoYW4"
  },
  "type": "public-key"
}"#;

/// 注册向量的 challenge（自 clientDataJSON 解出，与录制值一致）。
fn reg_vector_challenge() -> String {
    let reg: RegisterPublicKeyCredential =
        serde_json::from_str(REG_VECTOR_JSON).expect("注册向量应可解析");
    client_data_challenge(reg.response.client_data_json.as_slice())
}

/// 认证向量的 challenge。
fn auth_vector_challenge() -> String {
    let auth: PublicKeyCredential =
        serde_json::from_str(AUTH_VECTOR_JSON).expect("认证向量应可解析");
    client_data_challenge(auth.response.client_data_json.as_slice())
}

// ============================================================================
// service/sqlite 装置
// ============================================================================

/// 构造绑定 InMemoryDao + 内存凭据仓库的 service——凭据仓库用 sqlite 装置。
/// 仪式链路对仓库 trait 的依赖经 [`WebauthnCredentialRepository`]，测试用
/// sqlite 实现（setup_db 建表含 014）。
async fn test_service_sqlite(
    config: WebauthnConfig,
) -> (
    WebauthnService,
    Arc<DbnexusWebauthnCredentialRepository>,
    ChallengeStore,
) {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(InMemoryDao::new());
    let pool = super::super::super::dao::repository::sqlite::test_support::setup_db().await;
    let repo = Arc::new(DbnexusWebauthnCredentialRepository::new(pool));
    let service = WebauthnService::new(dao.clone(), repo.clone(), config);
    let store = ChallengeStore::new(dao, 120);
    (service, repo, store)
}

/// 以与 start_registration 相同的 SETNX 路径植入与注册向量匹配的仪式态。
async fn seed_registration(
    store: &ChallengeStore,
    tenant_id: i64,
    user_id: &str,
    purpose: FactorPurpose,
) {
    let rp = RelyingParty::derive(ISSUER).expect("issuer 派生应成功");
    let wan = WebauthnBuilder::new(&rp.rp_id, &rp.origin)
        .expect("RP 应合法")
        .build()
        .expect("Webauthn 构造应成功");
    let (_, state) = wan
        .start_passkey_registration(
            webauthn_rs::prelude::Uuid::new_v4(),
            "user-1",
            "user-1",
            Some(vec![]),
        )
        .expect("start_passkey_registration 应成功");
    let patched = patch_state_challenge(&state, &reg_vector_challenge());
    let state: webauthn_rs::prelude::PasskeyRegistration =
        serde_json::from_value(patched).expect("patch 后仪式态应可反序列化");
    store
        .store(
            &reg_vector_challenge(),
            &ChallengePayload::Registration {
                state,
                tenant_id,
                user_id: user_id.to_string(),
                purpose,
            },
        )
        .await
        .expect("植入注册仪式态应成功");
}

/// 以与 start_authentication 相同的 SETNX 路径植入与认证向量匹配的仪式态。
pub(crate) async fn seed_authentication(
    store: &ChallengeStore,
    tenant_id: i64,
    user_id: &str,
    credential: Credential,
) {
    let rp = RelyingParty::derive(ISSUER).expect("issuer 派生应成功");
    let wan = WebauthnBuilder::new(&rp.rp_id, &rp.origin)
        .expect("RP 应合法")
        .build()
        .expect("Webauthn 构造应成功");
    let (_, state) = wan
        .start_passkey_authentication(&[webauthn_rs::prelude::Passkey::from(credential)])
        .expect("start_passkey_authentication 应成功");
    let patched = patch_state_challenge(&state, &auth_vector_challenge());
    let state: webauthn_rs::prelude::PasskeyAuthentication =
        serde_json::from_value(patched).expect("patch 后仪式态应可反序列化");
    store
        .store(
            &auth_vector_challenge(),
            &ChallengePayload::Authentication {
                state,
                tenant_id,
                user_id: user_id.to_string(),
            },
        )
        .await
        .expect("植入认证仪式态应成功");
}

// ============================================================================
// challenge 一次性防重放
// ============================================================================

/// 二次消费被拒：GETDEL 语义下首个消费者取到载荷，第二个消费者见键已删
/// → `ChallengeReplayed`。
#[tokio::test(flavor = "multi_thread")]
async fn challenge_second_consume_is_rejected_as_replayed() {
    let store = test_store();
    let challenge_b64 = "dGVzdC1jaGFsbGVuZ2UtYWFhYQ";
    store
        .store(
            challenge_b64,
            &ChallengePayload::Authentication {
                state: test_authentication_state(),
                tenant_id: 0,
                user_id: "user-1".to_string(),
            },
        )
        .await
        .expect("首次签发应成功");

    let first = store.consume(challenge_b64).await;
    assert!(first.is_ok(), "首次消费应成功: {:?}", first.err());

    let second = store.consume(challenge_b64).await;
    assert_eq!(
        second.err(),
        Some(WebauthnCeremonyError::ChallengeReplayed),
        "二次消费必须被拒（challenge 一次性）"
    );
}

/// TTL 过期被拒：TTL=1s 的签发在窗口过后不可再消费，返回 `ChallengeReplayed`
/// （过期与重放同样不可区分地拒绝，不泄露状态差异）。
/// 墙钟过期沿用 DAO 契约套件惯例：每测试仅一次 sleep（ttl=1 + sleep 2s）。
#[tokio::test(flavor = "multi_thread")]
async fn challenge_expired_by_ttl_is_rejected() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(InMemoryDao::new());
    let store = ChallengeStore::new(dao, 1);
    let challenge_b64 = "dHRsLWV4cGlyZWQtY2hhbGxlbmdl";
    store
        .store(
            challenge_b64,
            &ChallengePayload::Authentication {
                state: test_authentication_state(),
                tenant_id: 0,
                user_id: "user-1".to_string(),
            },
        )
        .await
        .expect("签发应成功");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let consumed = store.consume(challenge_b64).await;
    assert_eq!(
        consumed.err(),
        Some(WebauthnCeremonyError::ChallengeReplayed),
        "TTL 过期后的消费必须被拒"
    );
}

/// 并发消费仅一成功：N 个并发消费者对同一 challenge，恰一个取到载荷，
/// 其余全部 `ChallengeReplayed`。
#[tokio::test(flavor = "multi_thread")]
async fn challenge_concurrent_consume_exactly_one_succeeds() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(InMemoryDao::new());
    let store = Arc::new(ChallengeStore::new(dao, 120));
    let challenge_b64 = "Y29uY3VycmVudC1jaGFsbGVuZ2U";
    store
        .store(
            challenge_b64,
            &ChallengePayload::Authentication {
                state: test_authentication_state(),
                tenant_id: 0,
                user_id: "user-1".to_string(),
            },
        )
        .await
        .expect("签发应成功");

    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let s = Arc::clone(&store);
        let chal = challenge_b64.to_string();
        handles.push(tokio::spawn(async move { s.consume(&chal).await }));
    }

    let mut successes = 0;
    let mut replays = 0;
    for h in handles {
        match h.await.expect("并发消费任务不应 panic") {
            Ok(_) => successes += 1,
            Err(WebauthnCeremonyError::ChallengeReplayed) => replays += 1,
            Err(other) => panic!("并发消费不应出现其他错误: {other:?}"),
        }
    }
    assert_eq!(successes, 1, "并发消费应恰一成功");
    assert_eq!(replays, N - 1, "其余消费应全部判重放");
}

/// 未知 challenge 被拒：伪造的 challenge 键位消费返回 `ChallengeReplayed`。
#[tokio::test(flavor = "multi_thread")]
async fn challenge_unknown_is_rejected() {
    let store = test_store();
    let consumed = store.consume("ZmFrZS1jaGFsbGVuZ2U").await;
    assert_eq!(
        consumed.err(),
        Some(WebauthnCeremonyError::ChallengeReplayed),
        "未知/伪造 challenge 必须被拒"
    );
}

/// 签发冲突显性报错：同一 challenge 键位二次 SETNX 报错
/// （不复写既有仪式态，防覆盖攻击）。
#[tokio::test(flavor = "multi_thread")]
async fn challenge_store_conflict_is_explicit_error() {
    let store = test_store();
    let challenge_b64 = "c2V0bngtY29uZmxpY3Q";
    let payload = || ChallengePayload::Authentication {
        state: test_authentication_state(),
        tenant_id: 0,
        user_id: "user-1".to_string(),
    };
    store
        .store(challenge_b64, &payload())
        .await
        .expect("首次签发应成功");

    let second = store.store(challenge_b64, &payload()).await;
    assert!(
        second.is_err(),
        "同键位二次签发必须显性报错（防覆盖既有仪式态）"
    );
}

/// 装置：完成「注册向量 → 凭据落库」的真实路径，返回 (service, repo, store,
/// 已绑定凭据)。
#[cfg(feature = "db-sqlite")]
pub(crate) async fn service_with_bound_vector_credential(
    config: WebauthnConfig,
) -> (
    WebauthnService,
    Arc<DbnexusWebauthnCredentialRepository>,
    ChallengeStore,
    WebauthnCredential,
) {
    let (service, repo, store) = test_service_sqlite(config).await;
    seed_registration(&store, 0, "user-1", FactorPurpose::Passwordless).await;
    let reg: RegisterPublicKeyCredential =
        serde_json::from_str(REG_VECTOR_JSON).expect("注册向量应可解析");
    let credential = service
        .finish_registration(&reg)
        .await
        .expect("注册向量绑定应成功");
    (service, repo, store, credential)
}

/// 构造测试用认证仪式态。
fn test_authentication_state() -> webauthn_rs::prelude::PasskeyAuthentication {
    let rp = RelyingParty::derive("https://garrison.example.com").expect("issuer 派生应成功");
    let wan = WebauthnBuilder::new(&rp.rp_id, &rp.origin)
        .expect("RP 配置应合法")
        .build()
        .expect("Webauthn 构造应成功");
    let (_, state) = wan
        .start_passkey_authentication(&[webauthn_rs::prelude::Passkey::from(
            test_only_credential_placeholder(),
        )])
        .expect("start_passkey_authentication 应成功");
    state
}

/// 占位凭据（仅用于 challenge 一次性测试的仪式态构造，无密码学意义）。
fn test_only_credential_placeholder() -> Credential {
    use webauthn_rs_core::proto::{COSEAlgorithm, COSEKey, COSEKeyType};
    use webauthn_rs_core::proto::{RegisteredExtensions, UserVerificationPolicy};
    Credential {
        cred_id: CredentialID::from(vec![1, 2, 3, 4]),
        cred: COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(webauthn_rs_core::proto::COSEEC2Key {
                curve: webauthn_rs_core::proto::ECDSACurve::SECP256R1,
                x: vec![0; 32].into(),
                y: vec![0; 32].into(),
            }),
        },
        counter: 0,
        transports: None,
        user_verified: false,
        backup_eligible: false,
        backup_state: false,
        registration_policy: UserVerificationPolicy::Required,
        extensions: RegisteredExtensions::none(),
        attestation: webauthn_rs_core::proto::ParsedAttestation {
            data: webauthn_rs_core::proto::ParsedAttestationData::None,
            metadata: webauthn_rs_core::proto::AttestationMetadata::None,
        },
        attestation_format: webauthn_rs_core::proto::AttestationFormat::None,
    }
}

/// 从领域模型取协议态副本（植入认证仪式态用）。
#[cfg(feature = "db-sqlite")]
pub(crate) fn domain_to_credential(domain: &WebauthnCredential) -> Credential {
    domain.protocol_credential().clone()
}

// ============================================================================
// 注册仪式
// ============================================================================

/// 注册向量全流程：challenge 消费 + attestation 复核 + 凭据落库，落库字段
/// 与向量一致（fmt=none，UV=1，counter=0，BE/BS=0）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn registration_vector_completes_and_persists() {
    let (service, repo, store) = test_service_sqlite(test_config()).await;
    seed_registration(&store, 0, "user-1", FactorPurpose::Passwordless).await;

    let reg: RegisterPublicKeyCredential =
        serde_json::from_str(REG_VECTOR_JSON).expect("注册向量应可解析");
    let credential = service
        .finish_registration(&reg)
        .await
        .expect("注册向量应通过 attestation 复核并落库");

    assert_eq!(
        credential.credential_id, reg.id,
        "落库 credential_id 应与向量一致"
    );
    assert_eq!(credential.user_id, "user-1");
    assert_eq!(credential.sign_count, 0, "注册 counter 应为 0");
    assert!(
        !credential.backup_eligible && !credential.backup_state,
        "BE/BS 应为 0"
    );
    assert_eq!(
        credential.attestation_format.as_str(),
        "none",
        "attestation 格式应如实落库"
    );

    let stored = repo
        .find_by_credential_id(0, &credential.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应已落库");
    assert_eq!(stored.user_id, "user-1");
}

/// 同 authenticator 重复绑定被拒：同一注册向量二次仪式（签名合法但
/// credential_id 已占用）在唯一约束处显性拒绝，库内仍只有一行。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn registration_duplicate_authenticator_binding_is_rejected() {
    let (service, repo, store) = test_service_sqlite(test_config()).await;
    let reg: RegisterPublicKeyCredential =
        serde_json::from_str(REG_VECTOR_JSON).expect("注册向量应可解析");

    seed_registration(&store, 0, "user-1", FactorPurpose::Passwordless).await;
    service
        .finish_registration(&reg)
        .await
        .expect("首次绑定应成功");

    seed_registration(&store, 0, "user-2", FactorPurpose::Passwordless).await;
    let second = service.finish_registration(&reg).await;
    assert_eq!(
        second.err(),
        Some(WebauthnCeremonyError::CredentialAlreadyBound),
        "同 authenticator 重复绑定必须被拒"
    );

    let rows = repo.list_by_user(0, "user-2").await.expect("列举应成功");
    assert!(rows.is_empty(), "被拒绑定不得产生第二行");
}

/// 非法 attestation 显性拒绝：attestationObject 被篡改为非法 base64，
/// 解析失败 → `CeremonyRejected`，库内无行。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn registration_invalid_attestation_is_rejected_explicitly() {
    let (service, repo, store) = test_service_sqlite(test_config()).await;
    seed_registration(&store, 0, "user-1", FactorPurpose::Passwordless).await;

    let mut tampered = REG_VECTOR_JSON.to_string();
    // attestationObject 首字符是 CBOR map 头（0xa3 = 3 项）：翻成 6 项破坏
    // CBOR 结构（base64url 字符仍合法，JSON 解析可过，仪式侧显性拒绝）
    let marker = "attestationObject\": \"o2NmbXRkbm9uZW";
    let pos = tampered.find(marker).expect("应找到 attestationObject");
    tampered.replace_range(pos + marker.len() - 1..pos + marker.len(), "p");

    let reg: RegisterPublicKeyCredential =
        serde_json::from_str(&tampered).expect("篡改后向量仍应可 JSON 解析");
    let outcome = service.finish_registration(&reg).await;
    assert!(
        matches!(outcome, Err(WebauthnCeremonyError::CeremonyRejected(_))),
        "非法 attestation 必须显性拒绝，实际: {outcome:?}"
    );

    let rows = repo.list_by_user(0, "user-1").await.expect("列举应成功");
    assert!(rows.is_empty(), "被拒注册不得落库");
}

/// start_registration 的 ExcludeCredentials：用户既有凭据出现在 creation
/// options 的 exclude_credentials 中（防同 authenticator 重复绑定的协议级防线）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn start_registration_carries_exclude_credentials() {
    let (service, _repo, store) = test_service_sqlite(test_config()).await;

    // 经注册向量完成首次绑定（真实落库路径）
    seed_registration(&store, 0, "user-1", FactorPurpose::Passwordless).await;
    let reg: RegisterPublicKeyCredential =
        serde_json::from_str(REG_VECTOR_JSON).expect("注册向量应可解析");
    let bound = service
        .finish_registration(&reg)
        .await
        .expect("首次绑定应成功");

    let ccr = service
        .start_registration(
            0,
            "user-1",
            "user-1",
            "user-1",
            webauthn_rs::prelude::Uuid::new_v4(),
            FactorPurpose::Passwordless,
        )
        .await
        .expect("start_registration 应成功");

    let ccr_json = serde_json::to_value(&ccr).expect("ccr 应可序列化");
    let exclude = ccr_json["publicKey"]["excludeCredentials"]
        .as_array()
        .expect("excludeCredentials 应存在");
    let ids: Vec<&str> = exclude.iter().filter_map(|e| e["id"].as_str()).collect();
    assert!(
        ids.contains(&bound.credential_id.as_str()),
        "excludeCredentials 应包含用户既有凭据，实际: {ids:?}"
    );
}

// ============================================================================
// 认证仪式
// ============================================================================

/// 正常认证：签名复核通过，sign_count 单调推进（0→1）并落库，
/// 返回视图携带断言后的 backup flags 与 UV。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn authentication_updates_sign_count_and_backup_flags() {
    let (service, repo, store, bound) = service_with_bound_vector_credential(test_config()).await;

    // 预置 backup_state=true（断言 BS=0）：验证 BS 跟随最新断言回落
    repo.update_authenticator_state(0, &bound.credential_id, 0, false, true)
        .await
        .expect("预置 BS 应成功");

    let stored_cred = repo
        .find_by_credential_id(0, &bound.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应存在");
    let domain = WebauthnCredential::from_row(stored_cred).expect("行重建应成功");
    seed_authentication(&store, 0, "user-1", domain_to_credential(&domain)).await;
    let auth: PublicKeyCredential =
        serde_json::from_str(AUTH_VECTOR_JSON).expect("认证向量应可解析");

    let outcome = service
        .finish_authentication(&auth)
        .await
        .expect("正常认证应通过");
    assert!(
        outcome.credential_updated,
        "counter 0→1 与 BS 回落应触发更新"
    );
    assert_eq!(outcome.sign_count, 1, "sign_count 应单调推进到 1");
    assert!(outcome.user_verified, "向量断言 UV=1");
    assert!(!outcome.backup_state, "BS 应跟随断言回落为 false");

    let stored = repo
        .find_by_credential_id(0, &outcome.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应存在");
    assert_eq!(stored.sign_count, 1, "sign_count 应已落库");
    assert!(!stored.backup_state, "BS 回落应已落库");
}

/// assertion 重放被拒：challenge 一次性——首次认证已消费 challenge，
/// 同一 assertion 二次提交在消费处即拒（`ChallengeReplayed`）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn authentication_replayed_assertion_is_rejected() {
    let (service, repo, store, bound) = service_with_bound_vector_credential(test_config()).await;

    let stored_cred = repo
        .find_by_credential_id(0, &bound.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应存在");
    let domain = WebauthnCredential::from_row(stored_cred).expect("行重建应成功");
    seed_authentication(&store, 0, "user-1", domain_to_credential(&domain)).await;
    let auth: PublicKeyCredential =
        serde_json::from_str(AUTH_VECTOR_JSON).expect("认证向量应可解析");

    service
        .finish_authentication(&auth)
        .await
        .expect("首次认证应通过");

    let replay = service.finish_authentication(&auth).await;
    assert_eq!(
        replay.err(),
        Some(WebauthnCeremonyError::ChallengeReplayed),
        "重放 assertion 必须被拒（challenge 一次性）"
    );
}

/// 克隆检测触发：落库 sign_count=1 ≥ 向量断言 counter（1），
/// webauthn-rs 判 counter 回退 → `CloneSuspected` 显性拒绝，库内不变。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn authentication_counter_regression_is_rejected_as_clone_suspect() {
    let (service, repo, store, bound) = service_with_bound_vector_credential(test_config()).await;

    // 抬高落库 counter 至断言值（断言 counter=1 ≤ stored=1 → 回退）
    repo.update_authenticator_state(0, &bound.credential_id, 1, false, false)
        .await
        .expect("抬高 counter 应成功");

    let stored_cred = repo
        .find_by_credential_id(0, &bound.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应存在");
    let domain = WebauthnCredential::from_row(stored_cred).expect("行重建应成功");
    seed_authentication(&store, 0, "user-1", domain_to_credential(&domain)).await;
    let auth: PublicKeyCredential =
        serde_json::from_str(AUTH_VECTOR_JSON).expect("认证向量应可解析");

    let outcome = service.finish_authentication(&auth).await;
    match outcome.err() {
        Some(WebauthnCeremonyError::CloneSuspected { stored, asserted }) => {
            assert_eq!(stored, 1, "stored 应为落库值");
            assert_eq!(asserted, 1, "asserted 应为 authenticatorData 声称值");
        },
        other => panic!("counter 回退必须判克隆嫌疑，实际: {other:?}"),
    }

    let stored = repo
        .find_by_credential_id(0, &bound.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应存在");
    assert_eq!(stored.sign_count, 1, "被拒断言不得更新落库值");
}

/// 签名错误显性拒绝：篡改 assertion 签名字段 → 复核失败 → `CeremonyRejected`。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn authentication_bad_signature_is_rejected_explicitly() {
    let (service, repo, store, bound) = service_with_bound_vector_credential(test_config()).await;

    let stored_cred = repo
        .find_by_credential_id(0, &bound.credential_id)
        .await
        .expect("查询应成功")
        .expect("凭据应存在");
    let domain = WebauthnCredential::from_row(stored_cred).expect("行重建应成功");
    seed_authentication(&store, 0, "user-1", domain_to_credential(&domain)).await;

    let mut tampered = AUTH_VECTOR_JSON.to_string();
    // 翻转签名末字符为另一合法 base64url 字符（JSON 可解析，签名不符）
    let marker = "\"signature\": \"";
    let pos = tampered.find(marker).expect("应找到签名字段");
    let sig_start = pos + marker.len();
    tampered.replace_range(sig_start..sig_start + 1, "A");

    let auth: PublicKeyCredential = serde_json::from_str(&tampered).expect("篡改后仍应可解析");
    let outcome = service.finish_authentication(&auth).await;
    assert!(
        matches!(outcome, Err(WebauthnCeremonyError::CeremonyRejected(_))),
        "签名错误必须显性拒绝，实际: {outcome:?}"
    );
}

/// 认证目标用户无凭据：start_authentication 显性拒绝（`NoCredentialBound`）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn authentication_start_without_credentials_is_rejected() {
    let (service, _repo, _store) = test_service_sqlite(test_config()).await;
    let outcome = service.start_authentication(0, "user-none").await;
    assert_eq!(
        outcome.err(),
        Some(WebauthnCeremonyError::NoCredentialBound),
        "无绑定凭据的认证发起必须显性拒绝"
    );
}

// ============================================================================
// RP 配置派生与双 policy
// ============================================================================

/// issuer 变更后 rp_id 跟随：派生纯函数对 issuer 的 host 一一对应。
#[test]
fn relying_party_derivation_follows_issuer_host() {
    let rp = RelyingParty::derive("https://sso.example.com").expect("派生应成功");
    assert_eq!(rp.rp_id, "sso.example.com");
    assert_eq!(rp.origin.as_str(), "https://sso.example.com/");

    let rp2 = RelyingParty::derive("https://auth.other.org").expect("派生应成功");
    assert_eq!(rp2.rp_id, "auth.other.org", "issuer 变更后 rp_id 应跟随");
    assert_eq!(rp2.origin.as_str(), "https://auth.other.org/");

    // 带端口的 issuer：host 为 rp_id，origin 保留端口（浏览器 origin 语义）
    let rp3 = RelyingParty::derive("http://localhost:8080").expect("派生应成功");
    assert_eq!(rp3.rp_id, "localhost");
    assert_eq!(rp3.origin.as_str(), "http://localhost:8080/");
}

/// issuer 非法（无 host / 非法 URL）显性报错。
#[test]
fn relying_party_derivation_rejects_invalid_issuer() {
    assert!(
        RelyingParty::derive("not a url").is_err(),
        "非法 URL 必须报错"
    );
    assert!(
        RelyingParty::derive("mailto:admin@example.com").is_err(),
        "无 host 的 URL 必须报错"
    );
}

/// 双 policy 准入差异：passwordless 关闭时 Passwordless 用途注册被拒，
/// SecondFactor 用途仍可发起（两 policy 分立、互不影响）。
#[cfg(feature = "db-sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn dual_policy_admission_differs_by_purpose() {
    let config = WebauthnConfig {
        issuer: ISSUER.to_string(),
        challenge_ttl_secs: 120,
        passwordless: FactorPolicy { enabled: false },
        second_factor: FactorPolicy { enabled: true },
    };
    let (service, _repo, _store) = test_service_sqlite(config).await;

    let passwordless = service
        .start_registration(
            0,
            "user-1",
            "user-1",
            "user-1",
            webauthn_rs::prelude::Uuid::new_v4(),
            FactorPurpose::Passwordless,
        )
        .await;
    assert_eq!(
        passwordless.err(),
        Some(WebauthnCeremonyError::PolicyDisabled(
            FactorPurpose::Passwordless
        )),
        "passwordless 关闭时该用途注册必须被拒"
    );

    let second_factor = service
        .start_registration(
            0,
            "user-1",
            "user-1",
            "user-1",
            webauthn_rs::prelude::Uuid::new_v4(),
            FactorPurpose::SecondFactor,
        )
        .await;
    assert!(
        second_factor.is_ok(),
        "second_factor 开启时该用途注册应放行: {:?}",
        second_factor.err()
    );
}
