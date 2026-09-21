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
        // 序列化无私钥字段
        let json = serde_json::to_string(jwk).unwrap();
        assert!(!json.contains("private"), "JWK 不得含私钥字段");
        assert!(json.contains("\"use\":\"sig\"") && json.contains("\"kid\":"));
    }
}
