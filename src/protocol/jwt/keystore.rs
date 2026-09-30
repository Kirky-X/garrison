// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 多 kid 密钥库：`KeyStatus` 三态与 `JwkSet` 三视图。
//!
//! 状态机语义（对齐 keycloak DefaultKeyManager）：
//! - 签名视图：仅 Active（当前签名钥）
//! - 验证视图：Active ∪ Passive（轮换后的旧钥仍可验证存量 token）
//! - JWKS 输出视图：Active ∪ Passive（Disabled 已退役，移出发布面）
//!
//! `kid` 采用 RFC 7638 JWK thumbprint（SHA-256，确定性：同钥同 kid）。
//! 密钥库仅收非对称钥：对称（HS）钥无可发布公钥成分，kid 不可派生，
//! 轮换入口显性拒绝（HS 部署走单钥共享，不经 JWKS 轮换）。

use std::collections::BTreeMap;

use crate::error::{GarrisonError, GarrisonResult};
use crate::protocol::jwt::{GarrisonJwtClaims, JwkPublicKey, JwtHandler};

/// 密钥状态三态。
///
/// - `Active`：当前签名钥（有且仅有一个）
/// - `Passive`：轮换退役保留验证（可验证存量 token，仍发布于 JWKS）
/// - `Disabled`：retention 超期退役（移出 JWKS、拒绝验证）
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// 当前签名钥。
    Active,
    /// 轮换后保留验证的旧钥。
    Passive,
    /// retention 超期退役的钥。
    Disabled,
}

/// JWKS 输出条目视图（无私钥成分）。
#[derive(Debug, Clone, PartialEq)]
pub struct JwkEntryView {
    /// 密钥 ID（RFC 7638 thumbprint）。
    pub kid: String,
    /// 当前状态。
    pub status: KeyStatus,
    /// 签名算法名（如 "RS256"）。
    pub alg: String,
    /// 公钥参数。
    pub parts: JwkPublicKey,
}

/// 一次轮换的结果：新激活的 kid 与被转为 Passive 的旧 kid。
#[derive(Debug, Clone, PartialEq)]
pub struct KeyRotationOutcome {
    /// 本次激活（Active）的 kid。
    pub activated_kid: String,
    /// 被转为 Passive 的旧 kid（引导轮换/空库时为 None）。
    pub passive_kid: Option<String>,
}

impl std::fmt::Debug for JwkSet {
    /// Debug 脱敏：只输出 kid 与状态映射，不输出密钥材料。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries: Vec<(&str, KeyStatus)> = self
            .entries
            .iter()
            .map(|(kid, e)| (kid.as_str(), e.status))
            .collect();
        f.debug_struct("JwkSet").field("entries", &entries).finish()
    }
}

/// 密钥条目（crate 内私有）。
struct KeyEntry {
    status: KeyStatus,
    handler: JwtHandler,
    /// 当前状态生效时刻（Unix 秒）——retention 计时基准。
    status_since_secs: i64,
}

/// 多 kid 密钥库：kid → 密钥条目。
///
/// 线程边界：非 `Sync`，多实例并发轮换的互斥由上层
/// （`oauth2_server::jwks::JwksRotationLedger` 的 DAO compare_and_swap）保证，
/// 本结构只做单实例内存状态机。
#[derive(Default)]
pub struct JwkSet {
    entries: BTreeMap<String, KeyEntry>,
}

/// 从公钥参数派生 RFC 7638 thumbprint kid。
///
/// 对必选成员按字母序组成的最小化 JSON 取 SHA-256，再 base64url（无 padding）
/// 编码；同钥恒得同 kid。
pub fn rfc7638_kid(parts: &JwkPublicKey) -> GarrisonResult<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let canonical = match parts {
        JwkPublicKey::Rsa { n, e } => format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#),
        JwkPublicKey::Ec { crv, x, y } => {
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        },
        JwkPublicKey::Okp { x } => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#),
    };
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// 从 handler 派生 kid（导出公钥成分 + RFC 7638 thumbprint）。
///
/// 对称钥（HS）无可导出成分 → 显性错误。
pub fn kid_for(handler: &JwtHandler) -> GarrisonResult<String> {
    let parts = handler
        .export_public_jwk_parts()?
        .ok_or_else(|| GarrisonError::Config("jwt-kid-symmetric::".to_string()))?;
    rfc7638_kid(&parts)
}

impl JwkSet {
    /// 创建空密钥库。
    pub fn new() -> Self {
        Self::default()
    }

    /// 轮换：新钥转 Active、旧 Active 转 Passive。
    ///
    /// 空库时本调用即引导（无旧钥可退役）。新钥与已注册钥同 kid（同钥重复
    /// 提交）显性拒绝。`now_secs` 为本次状态变更时刻（Unix 秒），作为新 Passive
    /// 条目的 retention 计时起点。
    pub fn rotate(
        &mut self,
        handler: JwtHandler,
        now_secs: i64,
    ) -> GarrisonResult<KeyRotationOutcome> {
        let kid = kid_for(&handler)?;
        if self.entries.contains_key(&kid) {
            return Err(GarrisonError::InvalidParam(format!(
                "jwt-kid-already-registered::{kid}"
            )));
        }
        let passive_kid = self.active_kid().map(str::to_string);
        if let Some(old_kid) = &passive_kid {
            if let Some(old) = self.entries.get_mut(old_kid) {
                old.status = KeyStatus::Passive;
                old.status_since_secs = now_secs;
            }
        }
        self.entries.insert(
            kid.clone(),
            KeyEntry {
                status: KeyStatus::Active,
                handler,
                status_since_secs: now_secs,
            },
        );
        Ok(KeyRotationOutcome {
            activated_kid: kid,
            passive_kid,
        })
    }

    /// retention 退役：Passive 条目 `now - status_since >= retention_secs` 转
    /// Disabled，返回本次退役的 kid 列表。Disabled 条目保留在库内（审计可见）
    /// 但移出全部三个视图。
    pub fn retire_expired(&mut self, now_secs: i64, retention_secs: u64) -> Vec<String> {
        let mut retired = Vec::new();
        for (kid, entry) in self.entries.iter_mut() {
            if entry.status != KeyStatus::Passive {
                continue;
            }
            let age = now_secs.saturating_sub(entry.status_since_secs);
            // u64 > i64::MAX 的 retention 视为「永不退役」（clamp 到 i64::MAX），
            // 失败方向安全：钥保留可验证，不会因回绕为负瞬间全部 Disabled
            let retention = i64::try_from(retention_secs).unwrap_or(i64::MAX);
            if age >= retention {
                entry.status = KeyStatus::Disabled;
                retired.push(kid.clone());
            }
        }
        retired
    }

    /// 当前 Active kid。
    pub fn active_kid(&self) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, e)| e.status == KeyStatus::Active)
            .map(|(kid, _)| kid.as_str())
    }

    /// 查询 kid 状态（不在库内返回 None）。
    pub fn status_of(&self, kid: &str) -> Option<KeyStatus> {
        self.entries.get(kid).map(|e| e.status)
    }

    /// 签名视图：Active 钥（kid, handler）。
    pub fn signing_key(&self) -> Option<(&str, &JwtHandler)> {
        self.entries
            .iter()
            .find(|(_, e)| e.status == KeyStatus::Active)
            .map(|(kid, e)| (kid.as_str(), &e.handler))
    }

    /// 验证视图：Active ∪ Passive 钥（kid, handler），按 kid 字典序。
    pub fn verification_keys(&self) -> Vec<(&str, &JwtHandler)> {
        self.entries
            .iter()
            .filter(|(_, e)| matches!(e.status, KeyStatus::Active | KeyStatus::Passive))
            .map(|(kid, e)| (kid.as_str(), &e.handler))
            .collect()
    }

    /// JWKS 输出视图：Active ∪ Passive 条目（无私钥成分），按 kid 字典序。
    pub fn jwks_entries(&self) -> Vec<JwkEntryView> {
        self.entries
            .iter()
            .filter(|(_, e)| matches!(e.status, KeyStatus::Active | KeyStatus::Passive))
            .filter_map(|(kid, e)| {
                // 对称钥无可导出成分（正常不入库；防御性跳过——HS 成分绝不发布）
                let parts = e.handler.export_public_jwk_parts().ok().flatten()?;
                Some(JwkEntryView {
                    kid: kid.clone(),
                    status: e.status,
                    alg: algorithm_name(e.handler.algorithm),
                    parts,
                })
            })
            .collect()
    }

    /// 以 Active 钥签发 token，header 写入 Active kid（多 kid 验证路由前提）。
    pub fn sign(&self, login_id: impl Into<String>, timeout: i64) -> GarrisonResult<String> {
        let (kid, handler) = self
            .signing_key()
            .ok_or_else(|| GarrisonError::Config("jwt-keystore-no-active-key::".to_string()))?;
        handler.sign_with_kid(login_id, timeout, Some(kid.to_string()))
    }

    /// 验证 token：按 header.kid 在 Active ∪ Passive 查钥；无 kid 回退 Active。
    ///
    /// - 未知 kid：显性拒绝（不静默回退——防伪造 kid 绕过钥选择）
    /// - Disabled kid：显性拒绝（retention 退役后旧 token 按策略失效）
    /// - 算法与选中钥不匹配：jsonwebtoken 校验层拒绝（fail-closed）
    pub fn verify(&self, token: &str) -> GarrisonResult<GarrisonJwtClaims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| GarrisonError::InvalidToken(format!("jwt-header-invalid::{e}")))?;
        let handler = match header.kid.as_deref() {
            Some(kid) => {
                let entry = self.entries.get(kid).ok_or_else(|| {
                    GarrisonError::InvalidToken(format!(
                        "jwt-kid-unknown::{}",
                        sanitize_kid_for_log(kid)
                    ))
                })?;
                match entry.status {
                    KeyStatus::Active | KeyStatus::Passive => &entry.handler,
                    KeyStatus::Disabled => {
                        return Err(GarrisonError::InvalidToken(format!(
                            "jwt-kid-retired::{}",
                            sanitize_kid_for_log(kid)
                        )));
                    },
                }
            },
            None => {
                let (_, handler) = self.signing_key().ok_or_else(|| {
                    GarrisonError::Config("jwt-keystore-no-active-key::".to_string())
                })?;
                handler
            },
        };
        handler.verify(token)
    }

    /// 导出全部密钥快照（持久化 / 跨实例同步用）。
    pub fn snapshots(&self) -> Vec<KeySnapshot> {
        self.entries
            .iter()
            .map(|(kid, e)| KeySnapshot {
                kid: kid.clone(),
                status: e.status,
                algorithm: algorithm_name(e.handler.algorithm),
                private_pem: private_pem_of(&e.handler),
                status_since_secs: e.status_since_secs,
            })
            .collect()
    }

    /// 从快照恢复密钥库（多实例各自加载同一 DAO 状态）。
    ///
    /// 校验（fail-closed）：
    /// - 每条快照的 `kid` 必须与私钥派生的 thumbprint 一致（防状态被篡改）
    /// - Active 至多一把（多 Active 即状态损坏，显性报错）
    pub fn from_snapshots(snapshots: Vec<KeySnapshot>) -> GarrisonResult<Self> {
        let mut keystore = JwkSet::new();
        for snapshot in snapshots {
            let handler = JwtHandler::from_algorithm_parts(
                &snapshot.algorithm,
                "",
                Some(&snapshot.private_pem),
                Some(&snapshot.private_pem),
                Some(&snapshot.private_pem),
            )?;
            let derived_kid = kid_for(&handler)?;
            if derived_kid != snapshot.kid {
                return Err(GarrisonError::InvalidParam(format!(
                    "jwt-snapshot-kid-mismatch::{}::{derived_kid}",
                    snapshot.kid
                )));
            }
            if snapshot.status == KeyStatus::Active && keystore.active_kid().is_some() {
                return Err(GarrisonError::InvalidParam(format!(
                    "jwt-snapshot-multiple-active::{}",
                    snapshot.kid
                )));
            }
            keystore.entries.insert(
                snapshot.kid,
                KeyEntry {
                    status: snapshot.status,
                    handler,
                    status_since_secs: snapshot.status_since_secs,
                },
            );
        }
        Ok(keystore)
    }
}

/// kid 来自 JWT header（不可信输入），入错误消息前截断并剥离控制字符——
/// 防日志注入与日志洪水（HTTP 响应体走静态消息，不受影响）。
fn sanitize_kid_for_log(kid: &str) -> String {
    kid.chars().take(64).filter(|c| !c.is_control()).collect()
}

/// 从 handler 私钥材料提取 PEM（快照导出用；对称钥无可导出 PEM 返回空串——
/// 快照路径不承载对称钥）。
fn private_pem_of(handler: &JwtHandler) -> String {
    handler.private_pem().unwrap_or_default().to_string()
}

/// 算法枚举的规范名（jsonwebtoken `Algorithm` 变体名即 JOSE alg 名）。
fn algorithm_name(algorithm: jsonwebtoken::Algorithm) -> String {
    format!("{algorithm:?}")
}

/// 密钥库快照条目（跨实例持久化载体）。
///
/// 私钥 PEM 以明文入快照——DAO 侧由调用方保证存储安全（与既有
/// `jwt_rsa_private_key_pem` 配置同级敏感，Debug 输出不脱敏单条字段，
/// 整个快照 JSON 不得写入日志）。
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KeySnapshot {
    /// 密钥 ID（RFC 7638 thumbprint，与私钥派生值一致性在恢复时校验）。
    pub kid: String,
    /// 密钥状态。
    pub status: KeyStatus,
    /// 签名算法名（RS256 / ES256 / EdDSA）。
    pub algorithm: String,
    /// 私钥 PEM（PKCS#8 / PKCS#1）。
    pub private_pem: String,
    /// 当前状态生效时刻（Unix 秒，retention 计时基准）。
    pub status_since_secs: i64,
}

// 手写脱敏 Debug（对齐 KeyMaterial/JwkSet 惯例）：private_pem 是私钥明文，
// 派生 Debug 会让任何 `{:?}` 误用把整段 PEM 打进日志。
impl std::fmt::Debug for KeySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySnapshot")
            .field("kid", &self.kid)
            .field("status", &self.status)
            .field("algorithm", &self.algorithm)
            .field("private_pem", &"<redacted>")
            .field("status_since_secs", &self.status_since_secs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::jwt::JwtHandler;

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const TEST_RSA_PEM_1: &str = "-----BEGIN PRIVATE KEY-----
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
    const TEST_RSA_PEM_2: &str = "-----BEGIN PRIVATE KEY-----
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

    fn rsa_handler(pem: &str) -> JwtHandler {
        JwtHandler::new("")
            .with_rsa_private_pem(pem)
            .expect("测试 RSA PEM 必须可解析")
            .try_with_algorithm(jsonwebtoken::Algorithm::RS256)
            .expect("RS256 与 RSA 密钥必须匹配")
    }

    /// KeyStatus 恰有三态：Active / Passive / Disabled（穷尽匹配编译期保证）。
    #[test]
    fn key_status_has_exactly_three_states() {
        let exercise = |status: KeyStatus| match status {
            KeyStatus::Active => 1,
            KeyStatus::Passive => 2,
            KeyStatus::Disabled => 3,
        };
        assert_eq!(exercise(KeyStatus::Active), 1);
        assert_eq!(exercise(KeyStatus::Passive), 2);
        assert_eq!(exercise(KeyStatus::Disabled), 3);
    }

    /// 轮换：新钥转 Active、旧 Active 转 Passive；首钥轮换即引导（无 Passive 产出）。
    #[test]
    fn rotate_activates_new_and_passivates_old() {
        let mut keystore = JwkSet::new();
        let first = keystore
            .rotate(rsa_handler(TEST_RSA_PEM_1), 1_000)
            .expect("首钥轮换即引导");
        assert!(first.passive_kid.is_none(), "引导轮换无旧钥可退役");
        let second = keystore
            .rotate(rsa_handler(TEST_RSA_PEM_2), 2_000)
            .expect("第二次轮换");
        assert_eq!(
            keystore.status_of(&first.activated_kid),
            Some(KeyStatus::Passive),
            "旧 Active 必须转 Passive"
        );
        assert_eq!(
            second.passive_kid.as_deref(),
            Some(first.activated_kid.as_str())
        );
        assert_eq!(
            keystore.status_of(&second.activated_kid),
            Some(KeyStatus::Active)
        );
    }

    /// 签名视图只取 Active：轮换后签名钥为新 kid，旧 kid 不再出现在签名视图。
    #[test]
    fn signing_view_returns_only_active() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        assert_eq!(
            keystore.signing_key().map(|(kid, _)| kid),
            Some(first.activated_kid.as_str())
        );
        let second = keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        let signing = keystore.signing_key().map(|(kid, _)| kid).unwrap();
        assert_eq!(signing, second.activated_kid.as_str());
        assert_ne!(signing, first.activated_kid, "轮换后旧 kid 不得仍是签名钥");
    }

    /// 验证视图取 Active ∪ Passive：两把钥都可用于验证。
    #[test]
    fn verification_view_includes_active_and_passive() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let second = keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        let kids: Vec<&str> = keystore
            .verification_keys()
            .into_iter()
            .map(|(kid, _)| kid)
            .collect();
        assert!(
            kids.contains(&first.activated_kid.as_str()),
            "Passive 旧钥必须在验证视图"
        );
        assert!(
            kids.contains(&second.activated_kid.as_str()),
            "Active 新钥必须在验证视图"
        );
        assert_eq!(kids.len(), 2, "验证视图恰含 Active ∪ Passive");
    }

    /// 轮换后旧 token（Passive kid 签发）验证成功——轮换期间验证不中断。
    #[test]
    fn passive_kid_token_verifies_after_rotation() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let old_token = keystore.sign("user-1", 3_600).unwrap();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        let claims = keystore
            .verify(&old_token)
            .expect("Passive 旧钥签发的 token 必须仍可验证");
        assert_eq!(claims.sub, "user-1");
        assert!(
            !first.activated_kid.is_empty(),
            "旧 kid 存在（轮换语义前置条件）"
        );
    }

    /// 无 kid 的存量 token 回退 Active 验证（兼容既有单钥签发格式）。
    #[test]
    fn token_without_kid_falls_back_to_active() {
        let mut keystore = JwkSet::new();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        // 直接用 handler.sign（不写 kid header）模拟既有签发格式
        let legacy_token = keystore
            .signing_key()
            .expect("签名钥存在")
            .1
            .sign("user-2", 3_600)
            .unwrap();
        let claims = keystore
            .verify(&legacy_token)
            .expect("无 kid token 必须回退 Active 验证成功");
        assert_eq!(claims.sub, "user-2");
    }

    /// 未知 kid 显性报错（非静默回退 Active——防伪造 kid 绕过钥选择）。
    #[test]
    fn unknown_kid_explicit_error() {
        let mut keystore = JwkSet::new();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let forged = keystore
            .signing_key()
            .expect("签名钥存在")
            .1
            .sign_with_kid("user-3", 3_600, Some("ghost-kid".to_string()))
            .unwrap();
        let err = keystore.verify(&forged).expect_err("未知 kid 必须显性报错");
        assert!(
            err.to_string().contains("jwt-kid-unknown::ghost-kid"),
            "错误必须显性指明未知 kid，实际: {err}"
        );
    }

    /// JWKS 输出视图含 Active ∪ Passive、不含 Disabled。
    #[test]
    fn jwks_view_contains_active_and_passive_excludes_disabled() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let second = keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        keystore.retire_expired(2_000 + 10_000, 10_000);
        let kids: Vec<String> = keystore.jwks_entries().into_iter().map(|e| e.kid).collect();
        assert!(
            kids.contains(&second.activated_kid),
            "Active 钥必须在 JWKS 输出"
        );
        assert!(
            !kids.contains(&first.activated_kid),
            "超期退役（Disabled）的钥不得出现在 JWKS 输出"
        );
    }

    /// retention：Passive 超期转 Disabled；未超期保持 Passive。
    #[test]
    fn retire_expired_disables_aged_passive_keys() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        // 未到 retention（retention=10_000，Passive 自 2_000 起）→ 保持 Passive
        let retired = keystore.retire_expired(5_000, 10_000);
        assert!(retired.is_empty(), "未超期不得退役");
        assert_eq!(
            keystore.status_of(&first.activated_kid),
            Some(KeyStatus::Passive)
        );
        // 超期（now - status_since >= retention）→ Disabled
        let retired = keystore.retire_expired(12_000, 10_000);
        assert_eq!(
            retired,
            vec![first.activated_kid.clone()],
            "超期 Passive 必须转 Disabled"
        );
        assert_eq!(
            keystore.status_of(&first.activated_kid),
            Some(KeyStatus::Disabled)
        );
    }

    /// 已退役（Disabled）钥的 token 验证显性拒绝（retention 后旧 token 按策略失效）。
    #[test]
    fn retired_kid_token_rejected_explicitly() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        assert!(
            !first.activated_kid.is_empty(),
            "旧 kid 存在（退役语义前置条件）"
        );
        let old_token = keystore.sign("user-4", 3_600).unwrap();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        keystore.retire_expired(12_000, 10_000);
        let err = keystore
            .verify(&old_token)
            .expect_err("Disabled 钥的 token 必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-kid-retired"),
            "拒绝原因必须显性指明钥已退役，实际: {err}"
        );
    }

    /// keystore 签发的 token header 携带 Active kid（多 kid 验证路由的前提）。
    #[test]
    fn sign_embeds_active_kid_header() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let token = keystore.sign("user-5", 3_600).unwrap();
        let header = jsonwebtoken::decode_header(&token).expect("token header 必须可解析");
        assert_eq!(
            header.kid.as_deref(),
            Some(first.activated_kid.as_str()),
            "签发必须写入 Active kid"
        );
    }

    /// 轮换到已注册的 kid（同钥重复提交）显性拒绝。
    #[test]
    fn duplicate_kid_rotation_rejected() {
        let mut keystore = JwkSet::new();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let err = keystore
            .rotate(rsa_handler(TEST_RSA_PEM_1), 2_000)
            .expect_err("同钥重复轮换必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-kid-already-registered"),
            "错误必须显性指明 kid 重复，实际: {err}"
        );
    }

    /// 对称钥（HS）无可发布公钥成分，轮换入口显性拒绝（JWKS 密钥库仅收非对称钥）。
    #[test]
    fn symmetric_key_rotation_rejected_explicitly() {
        let mut keystore = JwkSet::new();
        let hs = JwtHandler::new("0123456789abcdef0123456789abcdef")
            .try_with_algorithm(jsonwebtoken::Algorithm::HS256)
            .unwrap();
        let err = keystore
            .rotate(hs, 1_000)
            .expect_err("对称钥不得进入 JWKS 密钥库");
        assert!(
            err.to_string().contains("jwt-kid-symmetric"),
            "对称钥拒绝必须显性，实际: {err}"
        );
    }

    /// 快照导出→恢复 roundtrip：状态、kid、签名能力一致；恢复后旧 token 仍可验证。
    #[test]
    fn snapshot_roundtrip_preserves_status_and_signing() {
        let mut keystore = JwkSet::new();
        let first = keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let old_token = keystore.sign("user-6", 3_600).unwrap();
        let second = keystore.rotate(rsa_handler(TEST_RSA_PEM_2), 2_000).unwrap();
        let snapshots = keystore.snapshots();
        assert_eq!(snapshots.len(), 2);
        // 序列化走 serde（DAO 持久化口径）
        let json = serde_json::to_string(&snapshots).unwrap();
        let restored: Vec<KeySnapshot> = serde_json::from_str(&json).unwrap();
        let restored_keystore = JwkSet::from_snapshots(restored).expect("合法快照必须可恢复");
        assert_eq!(
            restored_keystore.active_kid(),
            Some(second.activated_kid.as_str())
        );
        assert_eq!(
            restored_keystore.status_of(&first.activated_kid),
            Some(KeyStatus::Passive)
        );
        assert_eq!(
            restored_keystore
                .sign("user-7", 3_600)
                .unwrap()
                .split('.')
                .count(),
            3,
            "恢复后签名能力可用"
        );
        restored_keystore
            .verify(&old_token)
            .expect("恢复后 Passive 旧 token 仍可验证");
        // 快照不含明文私钥序列化断言被还原——快照必须含 PEM 才能跨实例恢复签名能力
        let restored_pems: Vec<String> = restored_keystore
            .snapshots()
            .iter()
            .map(|s| s.private_pem.clone())
            .collect();
        assert!(
            restored_pems
                .iter()
                .all(|p| p.contains("BEGIN PRIVATE KEY")),
            "快照必须携带私钥 PEM（跨实例恢复签名的前提）"
        );
    }

    /// 快照 kid 与私钥派生值不一致：显性拒绝（防 DAO 状态被篡改后静默错签）。
    #[test]
    fn snapshot_kid_mismatch_rejected() {
        let mut keystore = JwkSet::new();
        keystore.rotate(rsa_handler(TEST_RSA_PEM_1), 1_000).unwrap();
        let mut snapshots = keystore.snapshots();
        snapshots[0].kid = "tampered-kid".to_string();
        let err = JwkSet::from_snapshots(snapshots).expect_err("kid 篡改必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-snapshot-kid-mismatch"),
            "错误必须显性指明 kid 不一致，实际: {err}"
        );
    }

    /// 快照含多把 Active：显性拒绝（状态损坏，恢复后会产生不确定签名钥）。
    #[test]
    fn snapshot_multiple_active_rejected() {
        // kid 必须与私钥派生 thumbprint 一致（kid 校验先于多 Active 校验）
        let kid_of = |pem: &str| kid_for(&rsa_handler(pem)).expect("测试 PEM 必须可派生 kid");
        let snapshots = vec![
            KeySnapshot {
                kid: kid_of(TEST_RSA_PEM_1),
                status: KeyStatus::Active,
                algorithm: "RS256".to_string(),
                private_pem: TEST_RSA_PEM_1.to_string(),
                status_since_secs: 1_000,
            },
            KeySnapshot {
                kid: kid_of(TEST_RSA_PEM_2),
                status: KeyStatus::Active,
                algorithm: "RS256".to_string(),
                private_pem: TEST_RSA_PEM_2.to_string(),
                status_since_secs: 2_000,
            },
        ];
        let err = JwkSet::from_snapshots(snapshots).expect_err("多 Active 必须显性拒绝");
        assert!(
            err.to_string().contains("jwt-snapshot-multiple-active"),
            "错误必须显性指明多 Active，实际: {err}"
        );
    }
}
