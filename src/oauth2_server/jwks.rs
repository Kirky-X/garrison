// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! JWKS（JSON Web Key Set）端点构建：按 RFC 7517/7518 导出非对称签名公钥。
//!
//! 供下游 RP 验证 Garrison 签发的 RS256/ES256/EdDSA 令牌；仅含公钥成分
//! （RSA: n/e、EC: crv/x/y、OKP: x），绝不暴露私钥。`kid` 采用
//! RFC 7638 JWK thumbprint（SHA-256，确定性，无需额外配置）。

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::protocol::jwt::{JwkPublicKey, JwtHandler};

/// 单条 JWK（`use=sig`，含 `alg` 与 `kid`）。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Jwk {
    /// 密钥类型（RSA / EC / OKP）。
    #[serde(rename = "kty")]
    pub kty: String,
    /// 用途：签名。
    #[serde(rename = "use")]
    pub use_: &'static str,
    /// 签名算法（与 config `jwt_algorithm` 一致）。
    #[serde(rename = "alg")]
    pub alg: String,
    /// 密钥 ID：RFC 7638 thumbprint（SHA-256，base64url）。
    #[serde(rename = "kid")]
    pub kid: String,
    /// RSA 模数（仅 RSA）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA 公钥指数（仅 RSA）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EC 曲线 / OKP 曲线（仅 EC / OKP）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x 坐标 / OKP 公钥（仅 EC / OKP）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y 坐标（仅 EC）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// JWK Set。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct JwkSet {
    /// 本服务器发布的 JWK 密钥集合（首版单密钥）。
    pub keys: Vec<Jwk>,
}

/// RFC 7638 JWK thumbprint：对必选成员按字母序组成的最小化 JSON
/// 取 SHA-256，再 base64url（无 padding）编码。
fn thumbprint(canonical_json: &str) -> String {
    let digest = Sha256::digest(canonical_json.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// 按算法名与私钥 PEM 构建 JWK Set。
///
/// 仅支持非对称算法（RS256/ES256/EdDSA）；对称算法无可公开成分，
/// 返回错误（端点层应以 404 fail-closed 处理）。
pub fn build_jwk_set(jwt_algorithm: &str, private_key_pem: &str) -> GarrisonResult<JwkSet> {
    if !matches!(jwt_algorithm, "RS256" | "ES256" | "EdDSA") {
        return Err(GarrisonError::Config(format!(
            "jwt-jwks-unsupported-alg::{jwt_algorithm}"
        )));
    }
    // from_algorithm_parts 按算法名只消费对应类型的 PEM；非对称算法统一
    // 从 private_key_pem 提取公钥成分（不匹配的参数分支不会被读取）
    let parts = JwtHandler::from_algorithm_parts(
        jwt_algorithm,
        "",
        Some(private_key_pem),
        Some(private_key_pem),
        Some(private_key_pem),
    )?
    .export_public_jwk_parts()?
    .ok_or_else(|| GarrisonError::Internal("jwt-jwks-symmetric::".to_string()))?;

    let jwk = match parts {
        JwkPublicKey::Rsa { n, e } => {
            let kid = thumbprint(&format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#));
            Jwk {
                kty: "RSA".to_string(),
                use_: "sig",
                alg: jwt_algorithm.to_string(),
                kid,
                n: Some(n),
                e: Some(e),
                crv: None,
                x: None,
                y: None,
            }
        },
        JwkPublicKey::Ec { crv, x, y } => {
            let kid = thumbprint(&format!(
                r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#
            ));
            Jwk {
                kty: "EC".to_string(),
                use_: "sig",
                alg: jwt_algorithm.to_string(),
                kid,
                n: None,
                e: None,
                crv: Some(crv.to_string()),
                x: Some(x),
                y: Some(y),
            }
        },
        JwkPublicKey::Okp { x } => {
            let kid = thumbprint(&format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#));
            Jwk {
                kty: "OKP".to_string(),
                use_: "sig",
                alg: jwt_algorithm.to_string(),
                kid,
                n: None,
                e: None,
                crv: Some("Ed25519".to_string()),
                x: Some(x),
                y: None,
            }
        },
    };
    Ok(JwkSet { keys: vec![jwk] })
}

/// DAO 状态键（`oauth2:jwks:` 命名空间；值 = 全量密钥快照 JSON，永久驻留）。
///
/// 多实例共享同一状态：轮换经 `compare_and_swap` 以「读到的原始 JSON」为
/// expected 提交，并发轮换只有一方成功，杜绝中间状态被覆盖。
///
/// **后端契约（多实例语义成立的前提）**：该后端必须被全部实例共享，且其
/// `compare_and_swap` 跨进程原子——进程内后端（InMemoryDao / oxcache L1）
/// 多实例部署下各持独立状态、Active kid 静默发散；oxcache+Redis 组合因
/// CAS 无跨进程原子性显性拒绝（fail-closed）。跨进程原子 CAS（如 Redis
/// Lua）落地前，多实例部署不得启用 keystore 轮换。
///
/// **已知限制（审查记录）**：快照含全部历史私钥 PEM **明文**驻留 DAO——
/// `field-encryption` 加密面（R17）未覆盖此命名空间（`FieldEncryptionDao`
/// 对 CAS 敏感命名空间的接入需版本化乐观并发设计，后续变更承接）；
/// Disabled 钥为审计保留、无物理删除路径。部署侧须以 DAO/Redis 访问控制、
/// 备份加密与密钥轮换节奏承接该暴露面。
pub const JWKS_STATE_KEY: &str = "oauth2:jwks:state";

/// 多实例 JWKS 密钥库账本：DAO `compare_and_swap` 之上的轮换 API。
///
/// 职责边界：
/// - 本结构负责**持久状态**（跨实例一致）——轮换提交、retention 退役、快照装载；
/// - 内存态三视图（签名/验证/JWKS）由 [`JwkSet`](crate::protocol::jwt::JwkSet)
///   承载，本结构按需从 DAO 快照恢复。
///
/// 快照 JSON 含全部私钥 PEM（跨实例恢复签名能力的前提），与配置层的
/// `jwt_*_private_key_pem` 同级敏感：不得写入日志/调试输出。
pub struct JwksKeystore {
    dao: Arc<dyn GarrisonDao>,
}

/// DAO 状态文档（serde 载体）。
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JwksStateDoc {
    entries: Vec<crate::protocol::jwt::KeySnapshot>,
}

impl JwksKeystore {
    /// 创建账本（`dao` 为共享存储，多实例指向同一后端）。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 轮换：新钥转 Active、旧 Active 转 Passive、retention 到期的 Passive 转
    /// Disabled，一次 CAS 原子提交。
    ///
    /// 多实例并发轮换仅一方成功：CAS expected 取「本次读到的原始 JSON」，
    /// 失败方返回 `jwks-rotation-conflict` 显性错误（重读后可重试）。
    ///
    /// # 参数
    /// - `jwt_algorithm`: 非对称算法名（RS256 / ES256 / EdDSA）。
    /// - `private_key_pem`: 新钥私钥 PEM（对称算法显性拒绝——无可发布公钥成分）。
    /// - `now_secs`: 本次轮换时刻（Unix 秒），作为 Passive/Active 计时基准。
    /// - `retention_secs`: Passive 保留时长（超期转 Disabled 并移出 JWKS）。
    pub async fn rotate(
        &self,
        jwt_algorithm: &str,
        private_key_pem: &str,
        now_secs: i64,
        retention_secs: u64,
    ) -> GarrisonResult<crate::protocol::jwt::KeyRotationOutcome> {
        if !matches!(jwt_algorithm, "RS256" | "ES256" | "EdDSA") {
            return Err(GarrisonError::Config(format!(
                "jwt-jwks-unsupported-alg::{jwt_algorithm}"
            )));
        }
        let expected = self.dao.get(JWKS_STATE_KEY).await?;
        let mut doc: JwksStateDoc = match &expected {
            Some(raw) => serde_json::from_str(raw)
                .map_err(|e| GarrisonError::Internal(format!("jwks-state-corrupt::{e}")))?,
            None => JwksStateDoc {
                entries: Vec::new(),
            },
        };
        // 新钥 kid 派生 + 重复注册检查（同钥重复提交是误操作，显性拒绝）
        let probe = crate::protocol::jwt::JwtHandler::from_algorithm_parts(
            jwt_algorithm,
            "",
            Some(private_key_pem),
            Some(private_key_pem),
            Some(private_key_pem),
        )?;
        let new_kid = crate::protocol::jwt::kid_for(&probe)?;
        if doc.entries.iter().any(|e| e.kid == new_kid) {
            return Err(GarrisonError::InvalidParam(format!(
                "jwt-kid-already-registered::{new_kid}"
            )));
        }
        // retention 退役（与轮换同一次提交，避免两次写竞态）
        let retention = i64::try_from(retention_secs).unwrap_or(i64::MAX);
        for entry in doc.entries.iter_mut() {
            if entry.status == crate::protocol::jwt::KeyStatus::Passive
                && now_secs.saturating_sub(entry.status_since_secs) >= retention
            {
                entry.status = crate::protocol::jwt::KeyStatus::Disabled;
            }
        }
        // 旧 Active 转 Passive
        let passive_kid = doc
            .entries
            .iter()
            .find(|e| e.status == crate::protocol::jwt::KeyStatus::Active)
            .map(|e| e.kid.clone());
        for entry in doc.entries.iter_mut() {
            if entry.status == crate::protocol::jwt::KeyStatus::Active {
                entry.status = crate::protocol::jwt::KeyStatus::Passive;
                entry.status_since_secs = now_secs;
            }
        }
        doc.entries.push(crate::protocol::jwt::KeySnapshot {
            kid: new_kid.clone(),
            status: crate::protocol::jwt::KeyStatus::Active,
            algorithm: jwt_algorithm.to_string(),
            private_pem: private_key_pem.to_string(),
            status_since_secs: now_secs,
        });
        let next = serde_json::to_string(&doc)
            .map_err(|e| GarrisonError::Internal(format!("jwks-state-serialize::{e}")))?;
        let committed = self
            .dao
            .compare_and_swap(JWKS_STATE_KEY, expected.as_deref(), &next, 0)
            .await?;
        if !committed {
            return Err(GarrisonError::OAuth2(
                "oauth2-server-jwks-rotation-conflict::another-instance-rotated-reload-and-retry"
                    .to_string(),
            ));
        }
        Ok(crate::protocol::jwt::KeyRotationOutcome {
            activated_kid: new_kid,
            passive_kid,
        })
    }

    /// retention 退役：Passive 超期转 Disabled（CAS 提交），返回退役 kid 列表。
    ///
    /// 无到期键时不写 DAO（幂等空操作）；CAS 失败显性报错（另一实例正在轮换，
    /// 由其同批提交承担退役）。
    pub async fn retire_expired(
        &self,
        now_secs: i64,
        retention_secs: u64,
    ) -> GarrisonResult<Vec<String>> {
        let expected = self.dao.get(JWKS_STATE_KEY).await?;
        let Some(raw) = expected.clone() else {
            return Ok(Vec::new());
        };
        let mut doc: JwksStateDoc = serde_json::from_str(&raw)
            .map_err(|e| GarrisonError::Internal(format!("jwks-state-corrupt::{e}")))?;
        let mut retired = Vec::new();
        let retention = i64::try_from(retention_secs).unwrap_or(i64::MAX);
        for entry in doc.entries.iter_mut() {
            if entry.status == crate::protocol::jwt::KeyStatus::Passive
                && now_secs.saturating_sub(entry.status_since_secs) >= retention
            {
                entry.status = crate::protocol::jwt::KeyStatus::Disabled;
                retired.push(entry.kid.clone());
            }
        }
        if retired.is_empty() {
            return Ok(retired);
        }
        let next = serde_json::to_string(&doc)
            .map_err(|e| GarrisonError::Internal(format!("jwks-state-serialize::{e}")))?;
        let committed = self
            .dao
            .compare_and_swap(JWKS_STATE_KEY, expected.as_deref(), &next, 0)
            .await?;
        if !committed {
            return Err(GarrisonError::OAuth2(
                "oauth2-server-jwks-retirement-conflict::another-instance-rotated-retirement-deferred-to-that-rotation".to_string(),
            ));
        }
        Ok(retired)
    }

    /// 从 DAO 快照恢复内存密钥库（多实例各自加载同一状态）。
    pub async fn load_keystore(&self) -> GarrisonResult<crate::protocol::jwt::JwkSet> {
        match self.dao.get(JWKS_STATE_KEY).await? {
            Some(raw) => {
                let doc: JwksStateDoc = serde_json::from_str(&raw)
                    .map_err(|e| GarrisonError::Internal(format!("jwks-state-corrupt::{e}")))?;
                crate::protocol::jwt::JwkSet::from_snapshots(doc.entries)
            },
            None => Ok(crate::protocol::jwt::JwkSet::new()),
        }
    }

    /// 读取原始状态文档 JSON（缓存键材料，不做解析/重建）。
    pub async fn state_raw(&self) -> GarrisonResult<Option<String>> {
        self.dao.get(JWKS_STATE_KEY).await
    }

    /// JWKS 发布文档：快照装载 + 按当前时刻应用 retention 视图（Active ∪ Passive，
    /// Disabled 恒不出现在发布面）。
    ///
    /// 装载后未落库的到期键在此按 Disabled 处理（服务视图即时生效；持久化由
    /// `retire_expired` / 下一次轮换提交）。
    pub async fn jwks_document(
        &self,
        now_secs: i64,
        retention_secs: u64,
    ) -> GarrisonResult<JwkSet> {
        let keystore = self.load_keystore().await?;
        let mut keystore = keystore;
        keystore.retire_expired(now_secs, retention_secs);
        let entries = keystore.jwks_entries();
        let keys = entries
            .iter()
            .map(|entry| match &entry.parts {
                JwkPublicKey::Rsa { n, e } => Jwk {
                    kty: "RSA".to_string(),
                    use_: "sig",
                    alg: entry.alg.clone(),
                    kid: entry.kid.clone(),
                    n: Some(n.clone()),
                    e: Some(e.clone()),
                    crv: None,
                    x: None,
                    y: None,
                },
                JwkPublicKey::Ec { crv, x, y } => Jwk {
                    kty: "EC".to_string(),
                    use_: "sig",
                    alg: entry.alg.clone(),
                    kid: entry.kid.clone(),
                    n: None,
                    e: None,
                    crv: Some(crv.to_string()),
                    x: Some(x.clone()),
                    y: Some(y.clone()),
                },
                JwkPublicKey::Okp { x } => Jwk {
                    kty: "OKP".to_string(),
                    use_: "sig",
                    alg: entry.alg.clone(),
                    kid: entry.kid.clone(),
                    n: None,
                    e: None,
                    crv: Some("Ed25519".to_string()),
                    x: Some(x.clone()),
                    y: None,
                },
            })
            .collect();
        let doc = JwkSet { keys };
        Ok(doc)
    }

    /// 以当前 Active 钥签发 token（header 携带 Active kid）。
    pub async fn sign(&self, login_id: impl Into<String>, timeout: i64) -> GarrisonResult<String> {
        self.load_keystore().await?.sign(login_id, timeout)
    }
}

#[cfg(test)]
mod keystore_ledger_tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::protocol::jwt::{KeySnapshot, KeyStatus};
    use std::sync::Arc;

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const LEDGER_RSA_PEM_1: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpfIC0d10OgO90
LkTO2R4C+FBeNQm4qt2lgnH1zDDUT+NRW3wcZEQPxHXHZlSoK7+TEdbsMUBEoQfE
6RCs37mBe0pusLR4gSuS6nrLH8weaAs5cy8jOQNCxOGeZS3TMh4jSSxKt78e2RUP
Cwwde0jgYw779wqOvDg4rocuXFP2rtQuFu8m3AY99DGvz4clCN2lOqFF64g3/D2S
lgVUWmyz/IHXvrI1EaHK6pj3lzOu4EZzJQfvBNS6zjmh61AIQe/EXUyRKPZJjEnV
ubtPTOji+L5ndlLULJqs6xBGhaHcAbiGMHH3c+OcXnZsMmZREY2zD0wiY+RhYcBi
CmK4V2KvAgMBAAECggEAP8RlokCUpPvS2/n6jn624XQuvLskzLOQ0BBLsyifqInk
I3yRrhb1Wp9Wlu7D5EANhJZ+MAB5xzh09VuhGAHWyEYsY4gdZodm7xBEof71K+2G
Z5eUQSLWvLzZjGBSBPeCylDiFryabk9Lsoy8Aq2bZj0u6pLwiHJ9jqnvl3xKZPGW
NWBBVy4MFkzuS2QCTnVLGx+V4Uuekm0oI0tB5qCKsGMpU+bnkKJfhaAy21YIAf/y
l33h51PNi/txgcptn1+fm9uu7w0YIWc7BMqoQhjL1nPaOB/+T0aEHZkkMKGxT1rC
bFrQEZA/ottapHkPSXqD7JezCDuLB8qnIEFGpnzjVQKBgQDeSlPeluvfxkHTEmZR
CUZ8El5UAG/4Z/mJWwOpXy0WbKaHksgW0t+lSGNwMuF75ToYCJ1GroDHpxVjxCcF
KCCbYVqFtj/sGynv/sd1zZ4R0fakl/ItrOxLcMHdtpn37IpdTUXlXiiQapfZRJDV
eG9DA9Wrge6QGpgeV5IDwPmv7QKBgQDDMDznNzZwv7Uv+Cdde8Ce5bAkFhkfvF7E
jdVn2g3ZgB9/8fnGHdA0cGH5tzrLOmU/9nZcTFQja/3skzJwQ5WTFICl4ka2LGBt
A/Dv1xDgA2p3asZvtzvfSuQB3d3N24LHc2WbABCQjBNQCuQXrLwWYK1Qvx8YyGcb
PShEjmqxiwKBgEG1vRcmi/FpXNn1LXO1BzX0BBhWzMKkkbpNwkZWETD4yz12YVmF
2oC0ZlirYcZLG6IxIbTcLstWE9ebC2HV29WysJyoJDs6SGpeaT3km15vL7a2B+wC
mxMt8NEGgnssXDZ6ejf0Xo9aQysBvsKryFAKGSaK0SeeBOurPUmIyQZ9AoGAWA8o
OuxG7GEhHk4nfF57jXR0niM2HIJAgw62K89NlkXecDu8AyyqJS5alW2b4dormcrY
pVVuVDjBa30RMWLcVWnXjH9khYXJzwULKzltDJOd8dhDRF13bor8CPeOvPP+sXsX
aPGDh6Mah28Sbrfod3QQXTCMmAK5ualCxIM4EXcCgYA8rN6qszVmCuxJNDaW4lWD
E74zsDrDRo+3K8CM/XqY7P2fPiYOChb7/mQ8TiPovXVtI76WwtbcZ1NH+07pDg07
ef2ciVLpNBQ3dV6q95yzIOfXwqJyePxotdB6KYLXgHKAt+HUKPrU/Sub9PE561O0
TVOiVROQ8xegHGbo4Bx/Mg==
-----END PRIVATE KEY-----
";

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const LEDGER_RSA_PEM_2: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC751S0Pf/oKnCq
AvE+iD2TB3fvkUXTiHfGgVHXfuFrVnam2DV9rPAWtzj78N/n4SzwIojGGzPFZtpd
Kw+VMWOEf0y5kTwOYEIAGJel6MPZBm8r2BqkgiDUw4usrI9BCRy9zRuDighMWoo0
r23RtOglWjwh6YbEXkg+dlaaFzuwZbtd7zOokVcd7MlXV51PRGT3HHbLekMJqKjM
+L+cN7NSoR6CsWHSqx8HlEJ8VQyNizsO1wKFo6gUSzGPeMH1uNMVxguI2OOzM8NS
8iEJmvMtVbcUxdYgIgFCol8ibBXYBsRQ02/arulEts3DoNJ/dOqt3uWaHv/+SVpc
CjdCgxdXAgMBAAECggEABSHWYG3pFXBDT4FxEWIrPF7R2cs/+v0ZOGTD1XzzrzjX
WMtC+sHEdPpgJhF4LB8sWQq4baDEkzmx8SWB8XM94pqPf+oFl+btJo+FZNSstLrG
Qo5Oe/vJ5cXJhNfZuc8D5/M4MymL/HnkmHfKKhYk2RBT4CE+uxJQKtSUnPTRfonc
v74IXU9mgrEWyhRnRLDCQTDS+MiFx+ca+Q2j3A3VXb6mLngi7+MlCTHesOrNi/h4
Krh6gXQDE3xw4oWlSy59zRXswrThFeNePbtN5suqHrGfhAJqvcVTuJRNPBL1OhYL
z9Fw+i5ypa0IFiiWmzIdTf6Z8fWAIRa16Gi7HofgYQKBgQDyasNqMmH2SJZ0X5Sk
RNsrHXlCVHdofP7B/w1mRXdXQN7bEdt+TkgHBOqO+005kHqcpjnm8GfKwaTVo9UK
cpYYDg11mBTULFn8BFKMH+MEzYTjKrHjA62DlM9PfdmKjPDXqJceWG1bp6Z2d+Rd
U0TfkTQLKmWihLYTUn2+c/gIWQKBgQDGbqAv9KU/7SKiUNVfSMMw/YYBm2jjEdQb
++IQuugzg0/cTwm+5sVbdzwqqt0jihO+2KWDbEHLqRndEeRjA5hvk+qp316MaeV8
x/dySeNG/lCnobiY+9ZjF14Zmaz1jGe+oAwmqGF4beoL5hkF77tFKUQtBRzkZgFC
A7yXzdQnLwKBgQCUu/Cd7b+xLiQxzpsSlrSqJXFKwyxoTZi5SlXcU+6++CxD2RcE
zd7ff6Kyi3l8QisYhdys1v+3pUwPUG/b8yYoKCcV6XOOIpArUjObiczuG3LXNlDi
alVBkEIKEbsxiPwUNXpSwgqG27wEn9bbc8WkLiDyYNbu+eIExO4ltl2OMQKBgHYk
KTVEGBruab9wFwmq/aOuXdmZGKKQ29NpbRf+3/7DgImveSLyrLAfVnAk2JKvQ8BN
poWPr8C8xkxLucmFu306+Oz4s4cwCVT4jYe7HBkJkyWq8IgM8ICAyiK9zy9G0AG7
smBVwep8rms1LNLO/5VW02NmduQ5IyiVpvROtLA7AoGBALycmaxr5wjzgTiw0oyh
/SSBunDWL23NnXrjjnLZ9BsmglkQUvhtkaA9AquuGJA4RiVxznoQQ6iXgZV80+Ui
j3MTO7dWRoAlfHi/NMU1BNA7zXLA2xPP/ekmHfb3PwCt5AhZTl43dEL+8V3xNlxp
HxmxsMlpmvvbydfhRl3OoqMR
-----END PRIVATE KEY-----
";

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const LEDGER_RSA_PEM_3: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMQoXOvmvs4kpj
nYshns5CYyNziLt/xBQBZtlkzY3KUuHtJMz9zK0TTz0DbhCnDCWF8tpWqxHBTtON
pMnnC6bTN4Wg/PWDn67hub23b4xAKq5qH45RmWn4a0TGTUyQktebjlCiWBlMCo43
j7FLyvGrOx3SmyUUaI5vh02Pf5Swg2CCQ69ht3L58jM6lp+jILJ4gEjNC2hmaWgH
bbYhTX5qCaPgZTndfgPXX9wkDG8jhpgRpfwmSuJ4aRiRrjvgycWuPccryX7aXiBU
c5H8rdKVgnjPTzSL8h3P/2tpZkNj5OFBZKTgmdPuwF87Mjlbr7Oi2xpCIpNpnyF1
L8G/mIIRAgMBAAECggEAY2vnzIOEbceRtN4cuC8fr1GpElXWCfELWclRfI7O+tGP
9YlpnAmxnsn9ZTuAMIcphoL4QqI+4Kw5LeMtgV/7AikuyncGG9ywV1+819ocVqlP
vwkAEXjOi2PPFITQhThsaOODHRorqgcjRSkUf9NXAWUjdX0dtcrUtbWSi4vqeGWC
O0Ni/9iWJYFjAgHu+XJgYXZtn7sJGe30PuIFmiKHfHuuM9alo6SubQ3UU80B+hQm
N4VVuYN+dYmGsekp+Ofj65mq2+WAyvHE2V9OB92L+yVY0uKZ428eXdN9ydp8kVqh
yOW2yLTq6sBNBOi/F/DMim6QrIzn6zpp0hXyc97d1wKBgQD+2qQOQ+urTE1ymdXT
C/os5kMrjsYd/rfcMaBbl4XmDE/PjlJg1Z6yVBGMmvM/shjTslcV8kgKyKf+aHm1
b3ckgu9PLtoYGX0yjeHbYCidwkjJPz8sy5pIFHslY/bGhV5RqsSPJo1aX2En0c4R
3cJHGGGn2YguQuWSOU94VTKgowKBgQDNLaS9Q08j/tiozEY23oH9i5p5iSwxc3It
hS/UwLYNFad6byRiDgVlvx+sVHZfLBsmNMlHEY+oMGocctqGAC8+a0pvtaLnU12/
GI61axWfAlCJrYs3CBOKwOH3hBM04mqPUb2ySHdlzPawpIr55jMkohuXXyw/22je
pK7iIPHZuwKBgQC+/Gi/TAUbjQXpIQHNtAcaiMDDrq4nolB00jfjC81LVeSlnXl8
mfngmAHCxggOrs/OLbL3fmagtji2/eJfppW5penjBDBqqQda0Fr2xLwLZaKYNi6I
ylfnNnoGzkAMC7xgJUJCKNj7ZcjwR1lPqElEcDAW0n0sdfOGvi4g9nAHUwKBgGIB
E1dz9zFyYXr/V+qNjfnV3QuAgiN8yWUE4Tv2cP7/AOhyfiZ4HAvlpvNhxMjhAHbX
b+0KblwgBA9irQ6kt+xQw1VopU9perX0vPXbGJDDQkUBKCY5LVxxlX3tEF+KZuve
V4X5J07xAESP0/JaCsPMyvEa/L/jxcvTTdWlduBRAoGBAPx2MMqUGXa+UZ+a0cyF
tW0xGglEWCX+e2vSNf31v4FyoGxNi6h2ap2OWEddpGttS+UbOzO9BlzcCtYJvPwW
lRVGEQXEoVyslCUwTlV8LmtrJS6Xl9YwRHmmajJMH6GJTk/CToOLIvj2bOMxHW5A
dzWfBsm+KAfTJuqbV7VnJL3G
-----END PRIVATE KEY-----
";

    fn ledger() -> (JwksKeystore, Arc<InMemoryDao>) {
        let dao = Arc::new(InMemoryDao::new());
        (JwksKeystore::new(dao.clone()), dao)
    }

    /// 引导轮换：空库写入首把 Active，无 Passive 产出。
    #[tokio::test]
    async fn rotate_bootstraps_first_active_key() {
        let (ledger, _dao) = ledger();
        let outcome = ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .expect("引导轮换必须成功");
        assert!(outcome.passive_kid.is_none());
        let keystore = ledger.load_keystore().await.unwrap();
        assert_eq!(keystore.active_kid(), Some(outcome.activated_kid.as_str()));
    }

    /// 第二次轮换：旧 Active 转 Passive（保留验证），新钥转 Active。
    #[tokio::test]
    async fn rotate_passivates_old_active_key() {
        let (ledger, _dao) = ledger();
        let first = ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        let second = ledger
            .rotate("RS256", LEDGER_RSA_PEM_2, 2_000, 10_000)
            .await
            .unwrap();
        assert_eq!(
            second.passive_kid.as_deref(),
            Some(first.activated_kid.as_str())
        );
        let keystore = ledger.load_keystore().await.unwrap();
        assert_eq!(
            keystore.status_of(&first.activated_kid),
            Some(KeyStatus::Passive)
        );
        assert_eq!(
            keystore.status_of(&second.activated_kid),
            Some(KeyStatus::Active)
        );
    }

    /// 同钥重复轮换（kid 已注册）：显性拒绝。
    #[tokio::test]
    async fn rotate_rejects_duplicate_kid() {
        let (ledger, _dao) = ledger();
        ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        let err = ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 2_000, 10_000)
            .await
            .expect_err("同钥重复轮换必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-kid-already-registered"),
            "错误必须显性指明 kid 重复，实际: {err}"
        );
    }

    /// 冻结读测试桩：`get` 对状态键恒返回冻结快照（模拟多实例并发下两个实例
    /// 读到同一旧状态后各自提交），CAS 委托真实 InMemoryDao（按当前值判定）。
    struct FrozenReadDao {
        frozen_state: std::sync::Mutex<String>,
        inner: Arc<InMemoryDao>,
    }

    impl FrozenReadDao {
        fn new(frozen_state: String, inner: Arc<InMemoryDao>) -> Self {
            Self {
                frozen_state: std::sync::Mutex::new(frozen_state),
                inner,
            }
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for FrozenReadDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            if key == JWKS_STATE_KEY {
                return Ok(Some(self.frozen_state.lock().unwrap().clone()));
            }
            self.inner.get(key).await
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            self.inner.update(key, value).await
        }

        async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
            self.inner.expire(key, seconds).await
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.inner.delete(key).await
        }

        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<&str>,
            new_value: &str,
            ttl_seconds: u64,
        ) -> GarrisonResult<bool> {
            self.inner
                .compare_and_swap(key, expected, new_value, ttl_seconds)
                .await
        }

        async fn set_if_absent(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> GarrisonResult<bool> {
            self.inner.set_if_absent(key, value, ttl_seconds).await
        }

        async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
            self.inner.rename(old_key, new_key).await
        }

        async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
            self.inner.get_and_delete(key).await
        }

        async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
            self.inner.incr(key, ttl_seconds).await
        }

        async fn decr(&self, key: &str) -> GarrisonResult<u64> {
            self.inner.decr(key).await
        }
    }

    /// 两实例并发轮换仅一成功（CAS 防多实例竞态）：双方基于同一旧状态提交，
    /// CAS 保证仅首方落库，失败方拿到显性冲突错误、当前状态与胜方写入一致。
    #[tokio::test]
    async fn concurrent_rotations_exactly_one_wins_and_loser_sees_consistent_state() {
        // 引导：真实 InMemoryDao 上完成首钥轮换，产出 v1 状态
        let (bootstrap, dao) = ledger();
        bootstrap
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        let state_v1 = dao.get(JWKS_STATE_KEY).await.unwrap().unwrap();
        // 冻结读 DAO：两个实例都读到 v1 后各自构建提交
        let frozen = Arc::new(FrozenReadDao::new(state_v1.clone(), dao.clone()));
        let a = JwksKeystore::new(frozen.clone());
        let b = JwksKeystore::new(frozen);
        let (ra, rb) = tokio::join!(
            a.rotate("RS256", LEDGER_RSA_PEM_2, 2_000, 10_000),
            b.rotate("RS256", LEDGER_RSA_PEM_3, 2_000, 10_000),
        );
        let wins = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
        assert_eq!(wins, 1, "同一基线上的两并发轮换必须恰有一方成功");
        let err = ra
            .as_ref()
            .err()
            .or_else(|| rb.as_ref().err())
            .expect("恰有一方失败");
        assert!(
            err.to_string().contains("jwks-rotation-conflict"),
            "失败方错误必须显性指明 CAS 冲突，实际: {err}"
        );
        let winner_kid = match (ra, rb) {
            (Ok(o), _) => o.activated_kid,
            (_, Ok(o)) => o.activated_kid,
            _ => unreachable!(),
        };
        // 失败方读到的状态与胜方写入一致：胜方 kid 为 Active、败方 kid 不存在
        let keystore = bootstrap.load_keystore().await.unwrap();
        assert_eq!(keystore.active_kid(), Some(winner_kid.as_str()));
        assert!(
            keystore.status_of(&winner_kid).is_some(),
            "胜方 kid 必须在状态中"
        );
        assert_eq!(
            keystore
                .snapshots()
                .iter()
                .filter(|s| s.status == KeyStatus::Active)
                .count(),
            1,
            "并发后库内恰有一把 Active"
        );
    }

    /// retention 退役：Passive 超期转 Disabled 并移出 JWKS 输出；未超期保留。
    #[tokio::test]
    async fn retire_expired_disables_aged_passive_and_removes_from_jwks() {
        let (ledger, _dao) = ledger();
        let first = ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        ledger
            .rotate("RS256", LEDGER_RSA_PEM_2, 2_000, 10_000)
            .await
            .unwrap();
        // 未超期：无退役，JWKS 含两把
        let retired = ledger.retire_expired(5_000, 10_000).await.unwrap();
        assert!(retired.is_empty());
        assert_eq!(
            ledger
                .jwks_document(5_000, 10_000)
                .await
                .unwrap()
                .keys
                .len(),
            2
        );
        // 超期：first 退役，JWKS 仅剩 Active
        let retired = ledger.retire_expired(12_000, 10_000).await.unwrap();
        assert_eq!(retired, vec![first.activated_kid.clone()]);
        let doc = ledger.jwks_document(12_000, 10_000).await.unwrap();
        assert_eq!(doc.keys.len(), 1);
        assert_ne!(
            doc.keys[0].kid, first.activated_kid,
            "退役 kid 必须移出 JWKS"
        );
    }

    /// 仍持有已退役 kid 的 token：验证按策略显性失效（retention 后旧 token 不再可信）。
    #[tokio::test]
    async fn token_of_retired_kid_rejected_after_retention() {
        let (ledger, _dao) = ledger();
        ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        let old_token = ledger.sign("user-8", 3_600).await.unwrap();
        ledger
            .rotate("RS256", LEDGER_RSA_PEM_2, 2_000, 10_000)
            .await
            .unwrap();
        ledger.retire_expired(12_000, 10_000).await.unwrap();
        // 重新加载后旧 token 验证按 Disabled 策略显性拒绝
        let keystore = ledger.load_keystore().await.unwrap();
        let err = keystore
            .verify(&old_token)
            .expect_err("退役钥的 token 必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-kid-retired"),
            "错误必须显性指明钥已退役，实际: {err}"
        );
    }

    /// 对称钥进入轮换：显性拒绝（JWKS 密钥库仅承载非对称钥）。
    #[tokio::test]
    async fn rotate_rejects_symmetric_algorithm() {
        let (ledger, _dao) = ledger();
        let err = ledger
            .rotate("HS256", "some-secret-material", 1_000, 10_000)
            .await
            .expect_err("对称算法必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-jwks-unsupported-alg::HS256"),
            "错误必须显性指明算法不受支持，实际: {err}"
        );
    }

    /// 空库 retire/JWKS 输出不报错（幂等空操作）。
    #[tokio::test]
    async fn empty_state_operations_are_noop() {
        let (ledger, _dao) = ledger();
        let retired = ledger.retire_expired(1_000, 10_000).await.unwrap();
        assert!(retired.is_empty());
        let doc = ledger.jwks_document(1_000, 10_000).await.unwrap();
        assert!(doc.keys.is_empty());
    }

    /// 快照损坏（kid 与私钥不一致）：load 显性拒绝。
    #[tokio::test]
    async fn corrupted_snapshot_rejected_explicitly() {
        let (ledger, _dao) = ledger();
        ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        // 直接篡改 DAO 状态里的 kid
        let raw = _dao.get(JWKS_STATE_KEY).await.unwrap().unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        doc["entries"][0]["kid"] = serde_json::Value::String("tampered".to_string());
        _dao.set(JWKS_STATE_KEY, &doc.to_string(), 0).await.unwrap();
        let err = ledger
            .load_keystore()
            .await
            .expect_err("kid 篡改必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-snapshot-kid-mismatch"),
            "错误必须显性指明快照损坏，实际: {err}"
        );
    }

    /// 签发路径：keystore 签发写入 Active kid；Passive 旧 token 验证不中断。
    #[tokio::test]
    async fn sign_embeds_kid_and_passive_verification_continues() {
        let (ledger, _dao) = ledger();
        let first = ledger
            .rotate("RS256", LEDGER_RSA_PEM_1, 1_000, 10_000)
            .await
            .unwrap();
        let old_token = ledger.sign("user-9", 3_600).await.unwrap();
        ledger
            .rotate("RS256", LEDGER_RSA_PEM_2, 2_000, 10_000)
            .await
            .unwrap();
        let new_token = ledger.sign("user-9", 3_600).await.unwrap();
        let old_header = jsonwebtoken::decode_header(&old_token).unwrap();
        let new_header = jsonwebtoken::decode_header(&new_token).unwrap();
        assert_eq!(
            old_header.kid.as_deref(),
            Some(first.activated_kid.as_str())
        );
        assert_ne!(old_header.kid, new_header.kid, "轮换后签发必须切换到新 kid");
        // 轮换后旧 token 验证不中断（Passive 保留语义）
        let keystore = ledger.load_keystore().await.unwrap();
        assert!(keystore.verify(&old_token).is_ok());
        assert!(keystore.verify(&new_token).is_ok());
    }

    /// KeySnapshot 引用保持（防未使用导入告警的编译期锚点）。
    #[test]
    fn key_snapshot_serde_roundtrip() {
        let snapshot = KeySnapshot {
            kid: "k".to_string(),
            status: KeyStatus::Passive,
            algorithm: "RS256".to_string(),
            private_pem: "pem".to_string(),
            status_since_secs: 1,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("\"status\":\"passive\""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMQoXOvmvs4kpj
nYshns5CYyNziLt/xBQBZtlkzY3KUuHtJMz9zK0TTz0DbhCnDCWF8tpWqxHBTtON
pMnnC6bTN4Wg/PWDn67hub23b4xAKq5qH45RmWn4a0TGTUyQktebjlCiWBlMCo43
j7FLyvGrOx3SmyUUaI5vh02Pf5Swg2CCQ69ht3L58jM6lp+jILJ4gEjNC2hmaWgH
bbYhTX5qCaPgZTndfgPXX9wkDG8jhpgRpfwmSuJ4aRiRrjvgycWuPccryX7aXiBU
c5H8rdKVgnjPTzSL8h3P/2tpZkNj5OFBZKTgmdPuwF87Mjlbr7Oi2xpCIpNpnyF1
L8G/mIIRAgMBAAECggEAY2vnzIOEbceRtN4cuC8fr1GpElXWCfELWclRfI7O+tGP
9YlpnAmxnsn9ZTuAMIcphoL4QqI+4Kw5LeMtgV/7AikuyncGG9ywV1+819ocVqlP
vwkAEXjOi2PPFITQhThsaOODHRorqgcjRSkUf9NXAWUjdX0dtcrUtbWSi4vqeGWC
O0Ni/9iWJYFjAgHu+XJgYXZtn7sJGe30PuIFmiKHfHuuM9alo6SubQ3UU80B+hQm
N4VVuYN+dYmGsekp+Ofj65mq2+WAyvHE2V9OB92L+yVY0uKZ428eXdN9ydp8kVqh
yOW2yLTq6sBNBOi/F/DMim6QrIzn6zpp0hXyc97d1wKBgQD+2qQOQ+urTE1ymdXT
C/os5kMrjsYd/rfcMaBbl4XmDE/PjlJg1Z6yVBGMmvM/shjTslcV8kgKyKf+aHm1
b3ckgu9PLtoYGX0yjeHbYCidwkjJPz8sy5pIFHslY/bGhV5RqsSPJo1aX2En0c4R
3cJHGGGn2YguQuWSOU94VTKgowKBgQDNLaS9Q08j/tiozEY23oH9i5p5iSwxc3It
hS/UwLYNFad6byRiDgVlvx+sVHZfLBsmNMlHEY+oMGocctqGAC8+a0pvtaLnU12/
GI61axWfAlCJrYs3CBOKwOH3hBM04mqPUb2ySHdlzPawpIr55jMkohuXXyw/22je
pK7iIPHZuwKBgQC+/Gi/TAUbjQXpIQHNtAcaiMDDrq4nolB00jfjC81LVeSlnXl8
mfngmAHCxggOrs/OLbL3fmagtji2/eJfppW5penjBDBqqQda0Fr2xLwLZaKYNi6I
ylfnNnoGzkAMC7xgJUJCKNj7ZcjwR1lPqElEcDAW0n0sdfOGvi4g9nAHUwKBgGIB
E1dz9zFyYXr/V+qNjfnV3QuAgiN8yWUE4Tv2cP7/AOhyfiZ4HAvlpvNhxMjhAHbX
b+0KblwgBA9irQ6kt+xQw1VopU9perX0vPXbGJDDQkUBKCY5LVxxlX3tEF+KZuve
V4X5J07xAESP0/JaCsPMyvEa/L/jxcvTTdWlduBRAoGBAPx2MMqUGXa+UZ+a0cyF
tW0xGglEWCX+e2vSNf31v4FyoGxNi6h2ap2OWEddpGttS+UbOzO9BlzcCtYJvPwW
lRVGEQXEoVyslCUwTlV8LmtrJS6Xl9YwRHmmajJMH6GJTk/CToOLIvj2bOMxHW5A
dzWfBsm+KAfTJuqbV7VnJL3G
-----END PRIVATE KEY-----
";

    /// RSA JWK：字段完整、kid 确定性、无私钥成分。
    #[test]
    fn build_jwk_set_rsa_fields_and_deterministic_kid() {
        let set1 = build_jwk_set("RS256", TEST_RSA_PEM).unwrap();
        let set2 = build_jwk_set("RS256", TEST_RSA_PEM).unwrap();

        assert_eq!(set1.keys.len(), 1);
        let jwk = &set1.keys[0];
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.alg, "RS256");
        assert!(jwk.n.is_some() && jwk.e.is_some());
        assert!(jwk.crv.is_none() && jwk.x.is_none() && jwk.y.is_none());
        assert_eq!(jwk.kid, set2.keys[0].kid, "同密钥多次导出 kid 必须一致");
        assert!(!jwk.kid.is_empty());
        let json = serde_json::to_string(jwk).unwrap();
        assert!(!json.contains("private"), "JWK 不得含私钥字段");
        assert!(json.contains("\"use\":\"sig\"") && json.contains("\"kid\":"));
    }

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const TEST_EC_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHu89Emnr1D+OpkZF
T2f/jZRjQNl9Q6AyVEnsI2rH+tihRANCAARSS8Qlg3TwbmWk6ICPdeHxy/X0LARI
FTcfYH6rUSsxJH2JD7Adnx1iw7UhnOZXVf8YOnDrqaXJkQcXNWPSUBqA
-----END PRIVATE KEY-----
";

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const TEST_ED_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOChr1YQD9KWBWWGBLFFjHQiHx9+OznRi69Gh25Uhv8H
-----END PRIVATE KEY-----
";

    // ========================================================================
    // build_jwk_set：三算法 JWK 构建 + 对称/非法输入拒绝
    // ========================================================================

    /// ES256：EC PEM → kty=EC、crv=P-256、x/y 齐备且无私钥成分。
    #[test]
    fn build_jwk_set_ec_produces_ec_key() {
        let doc = build_jwk_set("ES256", TEST_EC_PEM).unwrap();
        assert_eq!(doc.keys.len(), 1);
        let k = &doc.keys[0];
        assert_eq!(k.kty, "EC");
        assert_eq!(k.alg, "ES256");
        assert_eq!(k.crv.as_deref(), Some("P-256"));
        assert!(k.x.is_some() && k.y.is_some(), "EC JWK 应含 x/y");
        assert!(k.n.is_none() && k.e.is_none(), "EC JWK 不得含 RSA 成分");
        assert!(!k.kid.is_empty(), "kid 应为 RFC 7638 thumbprint");
    }

    /// EdDSA：Ed25519 PEM → kty=OKP、crv=Ed25519、仅 x 成分。
    #[test]
    fn build_jwk_set_ed_produces_okp_key() {
        let doc = build_jwk_set("EdDSA", TEST_ED_PEM).unwrap();
        assert_eq!(doc.keys.len(), 1);
        let k = &doc.keys[0];
        assert_eq!(k.kty, "OKP");
        assert_eq!(k.alg, "EdDSA");
        assert_eq!(k.crv.as_deref(), Some("Ed25519"));
        assert!(k.x.is_some(), "OKP JWK 应含 x");
        assert!(k.n.is_none() && k.e.is_none() && k.y.is_none());
    }

    /// RS256：RSA PEM → kty=RSA、n/e 齐备（回归保护，对齐既有测试口径）。
    #[test]
    fn build_jwk_set_rsa_produces_rsa_key() {
        let doc = build_jwk_set("RS256", TEST_RSA_PEM).unwrap();
        assert_eq!(doc.keys.len(), 1);
        let k = &doc.keys[0];
        assert_eq!(k.kty, "RSA");
        assert!(k.n.is_some() && k.e.is_some(), "RSA JWK 应含 n/e");
    }

    /// 对称算法无可公开成分 → 构造期 fail-closed 报错（端点层 404 前置）。
    #[test]
    fn build_jwk_set_rejects_symmetric_algorithm() {
        let err = build_jwk_set("HS256", TEST_RSA_PEM).unwrap_err();
        assert!(
            matches!(err, GarrisonError::Config(ref m) if m.contains("jwt-jwks-unsupported-alg")),
            "HS256 应报 jwt-jwks-unsupported-alg，实际: {err:?}"
        );
    }

    /// 非法 PEM → 构造期报错（不产半成品 JWK Set）。
    #[test]
    fn build_jwk_set_rejects_invalid_pem() {
        assert!(build_jwk_set("RS256", "not-a-pem").is_err());
    }
}
