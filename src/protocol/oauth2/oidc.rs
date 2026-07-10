//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OIDC（OpenID Connect）扩展模块。
//!
//! 提供 `OidcHandler` 用于：
//! - 签发 OIDC id_token（JWT 格式，含 iss/sub/aud/exp/iat/nonce claims）
//! - 验证 id_token（签名校验 + nonce 校验）
//! - 生成 OIDC discovery endpoint 元数据（JSON）
//!
//! 仅在启用 `protocol-oidc` feature 时编译。
//! `protocol-oidc` 自动启用 `protocol-jwt`（依赖 jsonwebtoken crate）。
//!
//! ## 设计决策
//!
//! - `OidcHandler` 独立 struct，不合并到 `OAuth2Client`（关注点分离）
//! - id_token 使用 `jsonwebtoken` crate 直接签发（复用 `JwtHandler` 的密钥/算法模式，但 claims 不同）
//! - 默认 HS256 算法（与 `JwtHandler` 一致）

use crate::error::{BulwarkError, BulwarkResult};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// OIDC id_token 的 claims 载荷。
///
/// 包含标准 OIDC claims（iss/sub/aud/exp/iat/nonce）+ Bulwark 内部字段（login_id）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// 签发者标识（issuer），通常为 OIDC Provider 的 URL。
    pub iss: String,
    /// 主体标识（subject），与 login_id 字符串一致。
    pub sub: String,
    /// 受众（audience），通常为 client_id。
    pub aud: String,
    /// 签发时间（Unix 秒）。
    pub iat: i64,
    /// 过期时间（Unix 秒）。
    pub exp: i64,
    /// Bulwark 登录标识（字符串形式，与 sub 一致）。
    pub login_id: String,
    /// nonce（防重放，客户端在授权请求中提供，id_token 中回传）。
    pub nonce: String,
}

/// OIDC 处理器，封装 issuer/audience/密钥以供复用。
///
/// 默认采用 HS256 算法，可通过 `with_algorithm` 切换。
pub struct OidcHandler {
    /// 签发者标识（issuer）。
    issuer: String,
    /// 受众（audience），通常为 client_id。
    audience: String,
    /// 签名密钥。
    secret: String,
    /// 签名算法（默认 HS256）。
    algorithm: Algorithm,
}

impl OidcHandler {
    /// 创建新的 OIDC 处理器。
    ///
    /// # 参数
    /// - `issuer`: 签发者标识（如 `https://auth.example.com`）。
    /// - `audience`: 受众 client_id。
    /// - `secret`: JWT 签名密钥，不可为空。
    ///
    /// # 错误
    /// - `BulwarkError::Config`: secret 为空。
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        secret: impl Into<String>,
    ) -> BulwarkResult<Self> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(BulwarkError::Config("OIDC secret 不能为空".to_string()));
        }
        Ok(Self {
            issuer: issuer.into(),
            audience: audience.into(),
            secret,
            algorithm: Algorithm::HS256,
        })
    }

    /// 切换签名算法。
    ///
    /// **注意**：当前实现仅支持 HMAC 系列算法（HS256/HS384/HS512），
    /// 因为 `EncodingKey::from_secret` / `DecodingKey::from_secret` 只接受对称密钥。
    /// 非对称算法（RS*/ES*/PS*）会在 `sign_id_token` / `verify_id_token` 时返回 `Config` 错误。
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// 校验算法是否为 HMAC 系列（HS256/HS384/HS512）。
    ///
    /// 非对称算法需通过 `EncodingKey::from_rsa_pem` 等接口加载密钥，
    /// 当前 `OidcHandler` 仅持有 `secret: String`，不支持非对称密钥（M4 修复）。
    fn require_hmac_algorithm(&self) -> BulwarkResult<()> {
        if matches!(
            self.algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            Ok(())
        } else {
            Err(BulwarkError::Config(format!(
                "OidcHandler 仅支持 HS256/HS384/HS512 算法，当前算法不支持: {:?}",
                self.algorithm
            )))
        }
    }

    /// 签发 OIDC id_token。
    ///
    /// **算法限制**：当前仅支持 HMAC 系列算法（HS256/HS384/HS512）。
    /// 非对称算法（RS*/ES*/PS*）会返回 `BulwarkError::Config`，因为
    /// `EncodingKey::from_secret` 仅接受对称密钥。JWKS + 非对称算法支持待 0.5.0+。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `nonce`: 客户端提供的 nonce（防重放）。
    /// - `_scope`: 授权范围（写入 id_token 的 scope claim 可选，当前实现不写入 scope claim）。
    /// - `timeout`: 有效期（秒），不可为负数。
    ///
    /// # 返回
    /// - `Ok(String)`: JWT 格式的 id_token。
    /// - `Err(BulwarkError::Config)`: timeout 为负，或当前算法为非对称算法。
    /// - `Err(BulwarkError::Internal)`: 签发失败。
    pub fn sign_id_token(
        &self,
        login_id: impl Into<String>,
        nonce: &str,
        _scope: &str,
        timeout: i64,
    ) -> BulwarkResult<String> {
        let login_id: String = login_id.into();
        if timeout < 0 {
            return Err(BulwarkError::Config(format!(
                "timeout 不能为负数: {}",
                timeout
            )));
        }
        // M4 修复：非对称算法无法用 from_secret 加载密钥，提前校验
        self.require_hmac_algorithm()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BulwarkError::Internal(format!("系统时间错误: {}", e)))?
            .as_secs() as i64;
        let claims = OidcClaims {
            iss: self.issuer.clone(),
            sub: login_id.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp: now + timeout,
            login_id,
            nonce: nonce.to_string(),
        };
        let header = Header::new(self.algorithm);
        let key = EncodingKey::from_secret(self.secret.as_bytes());
        encode(&header, &claims, &key)
            .map_err(|e| BulwarkError::Internal(format!("OIDC id_token 签发失败: {}", e)))
    }

    /// 验证 OIDC id_token。
    ///
    /// **算法限制**：当前仅支持 HMAC 系列算法（HS256/HS384/HS512）。
    /// 非对称算法（RS*/ES*/PS*）会返回 `BulwarkError::Config`，因为
    /// `DecodingKey::from_secret` 仅接受对称密钥。JWKS + 非对称算法支持待 0.5.0+。
    ///
    /// # 参数
    /// - `id_token`: JWT 格式的 id_token。
    /// - `expected_nonce`: 客户端期望的 nonce（用于防重放校验）。
    ///
    /// # 返回
    /// - `Ok(OidcClaims)`: 校验成功，返回 claims。
    /// - `Err(BulwarkError::Config)`: 当前算法为非对称算法。
    /// - `Err(BulwarkError::OAuth2)`: nonce 不匹配。
    /// - `Err(BulwarkError::ExpiredToken)`: id_token 已过期。
    /// - `Err(BulwarkError::InvalidToken)`: 签名/格式/iss/aud 校验失败。
    pub fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> BulwarkResult<OidcClaims> {
        // M4 修复：提前校验算法，避免 from_secret 在非对称算法下产生模糊错误
        self.require_hmac_algorithm()?;
        let key = DecodingKey::from_secret(self.secret.as_bytes());
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.leeway = 0;
        // jsonwebtoken 10 默认 validate_aud=true，但未设置 expected audience 会触发 InvalidAudience。
        // 关闭库内置 aud 校验，由我们手动校验 iss/aud 以提供更精确的错误信息。
        validation.validate_aud = false;
        let decoded = decode::<OidcClaims>(id_token, &key, &validation).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("ExpiredSignature") {
                BulwarkError::ExpiredToken(format!("OIDC id_token 已过期: {}", e))
            } else {
                BulwarkError::InvalidToken(format!("OIDC id_token 校验失败: {}", e))
            }
        })?;
        let claims = decoded.claims;
        // OIDC 规范要求校验 iss 和 aud
        if claims.iss != self.issuer {
            return Err(BulwarkError::InvalidToken(format!(
                "OIDC iss 不匹配: 期望 {}, 实际 {}",
                self.issuer, claims.iss
            )));
        }
        if claims.aud != self.audience {
            return Err(BulwarkError::InvalidToken(format!(
                "OIDC aud 不匹配: 期望 {}, 实际 {}",
                self.audience, claims.aud
            )));
        }
        // nonce 校验（防重放）
        if claims.nonce != expected_nonce {
            return Err(BulwarkError::OAuth2("nonce mismatch".to_string()));
        }
        Ok(claims)
    }

    /// 生成 OIDC discovery endpoint 元数据。
    ///
    /// 返回 OIDC Discovery 1.0 规范定义的 provider metadata JSON。
    pub fn discovery_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{}/authorize", self.issuer),
            "token_endpoint": format!("{}/token", self.issuer),
            "userinfo_endpoint": format!("{}/userinfo", self.issuer),
            "jwks_uri": format!("{}/jwks", self.issuer),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [self.algorithm_str()],
        })
    }

    /// 返回算法字符串表示（用于 discovery metadata）。
    fn algorithm_str(&self) -> &'static str {
        match self.algorithm {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            _ => "unknown",
        }
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for OidcHandler {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 创建测试用 OidcHandler。
    fn make_handler() -> OidcHandler {
        OidcHandler::new(
            "https://auth.example.com",
            "test-client-id",
            "test-secret-key",
        )
        .expect("创建 OidcHandler 失败")
    }

    // ========================================================================
    // OidcHandler 构造测试
    // ========================================================================

    /// 构造 OidcHandler，字段正确填充。
    #[test]
    fn new_populates_fields() {
        let handler = make_handler();
        assert_eq!(handler.issuer, "https://auth.example.com");
        assert_eq!(handler.audience, "test-client-id");
        assert_eq!(handler.algorithm, Algorithm::HS256);
    }

    /// secret 为空返回 Config 错误。
    #[test]
    fn new_empty_secret_returns_config_error() {
        let result = OidcHandler::new("issuer", "aud", "");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {},
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// with_algorithm 切换为 HS512。
    #[test]
    fn with_algorithm_switches_to_hs512() {
        let handler = make_handler().with_algorithm(Algorithm::HS512);
        assert_eq!(handler.algorithm, Algorithm::HS512);
    }

    // ========================================================================
    // sign_id_token / verify_id_token 测试
    // ========================================================================

    /// sign_id_token 返回三段 JWT（spec Scenario: 签发 id_token 成功）。
    #[test]
    fn sign_id_token_returns_three_segment_jwt() {
        let handler = make_handler();
        let token = handler
            .sign_id_token("1001", "abc123", "openid profile", 3600)
            .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "id_token 应由三段组成");
    }

    /// sign_id_token + verify_id_token 往返（spec Scenario: 签发 id_token 成功）。
    #[test]
    fn sign_and_verify_id_token_roundtrip() {
        let handler = make_handler();
        let token = handler
            .sign_id_token("1001", "nonce-abc", "openid", 3600)
            .unwrap();
        let claims = handler.verify_id_token(&token, "nonce-abc").unwrap();
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.sub, "1001");
        assert_eq!(claims.aud, "test-client-id");
        assert_eq!(claims.login_id, "1001");
        assert_eq!(claims.nonce, "nonce-abc");
        assert!(claims.exp > claims.iat);
    }

    /// nonce 不匹配返回 OAuth2 错误（spec Scenario: nonce 校验）。
    #[test]
    fn verify_id_token_nonce_mismatch_returns_oauth2_error() {
        let handler = make_handler();
        let token = handler
            .sign_id_token("1001", "correct-nonce", "openid", 3600)
            .unwrap();
        let result = handler.verify_id_token(&token, "wrong-nonce");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => assert!(msg.contains("nonce mismatch")),
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    /// 签名算法 HS256 验证（spec Scenario: 签发 id_token 成功 — HS256）。
    #[test]
    fn sign_id_token_uses_hs256_by_default() {
        let handler = make_handler();
        let token = handler
            .sign_id_token("1001", "nonce", "openid", 3600)
            .unwrap();
        // 解码 header 检查算法
        let parts: Vec<&str> = token.split('.').collect();
        let header_bytes = base64_url_decode(parts[0]);
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "HS256");
    }

    /// 负数 timeout 返回 Config 错误。
    #[test]
    fn sign_id_token_rejects_negative_timeout() {
        let handler = make_handler();
        let result = handler.sign_id_token("1001", "nonce", "openid", -1);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {},
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// 篡改 id_token 返回 InvalidToken 错误（L9 修复：强化断言错误类型）。
    #[test]
    fn verify_id_token_tampered_fails() {
        let handler = make_handler();
        let token = handler
            .sign_id_token("1001", "nonce", "openid", 3600)
            .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "ZmFrZS1wYXlsb2Fk", parts[2]);
        let result = handler.verify_id_token(&tampered, "nonce");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误（签名校验失败），实际: {:?}", other),
        }
    }

    /// M4 回归测试：非对称算法在 sign_id_token 时返回 Config 错误。
    #[test]
    fn sign_id_token_rejects_asymmetric_algorithm() {
        let handler = make_handler().with_algorithm(Algorithm::RS256);
        let result = handler.sign_id_token("1001", "nonce", "openid", 3600);
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(msg)) => assert!(
                msg.contains("HS256") && msg.contains("RS256"),
                "错误消息应包含 HS256 与 RS256，实际: {}",
                msg
            ),
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// M4 回归测试：非对称算法在 verify_id_token 时返回 Config 错误。
    #[test]
    fn verify_id_token_rejects_asymmetric_algorithm() {
        // 即使 token 是用 HS256 签发的，verifier 配置为 RS256 也应提前返回 Config 错误
        let signer = make_handler();
        let token = signer
            .sign_id_token("1001", "nonce", "openid", 3600)
            .unwrap();
        let verifier = make_handler().with_algorithm(Algorithm::RS256);
        let result = verifier.verify_id_token(&token, "nonce");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {},
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// iss 不匹配返回 InvalidToken 错误（使用不同 issuer 的 handler 验证）。
    #[test]
    fn verify_id_token_iss_mismatch_fails() {
        let signer = OidcHandler::new("https://correct-issuer", "aud", "secret").unwrap();
        let verifier = OidcHandler::new("https://wrong-issuer", "aud", "secret").unwrap();
        let token = signer
            .sign_id_token("1001", "nonce", "openid", 3600)
            .unwrap();
        let result = verifier.verify_id_token(&token, "nonce");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => assert!(msg.contains("iss")),
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // discovery_metadata 测试
    // ========================================================================

    /// discovery_metadata 字段完整（spec Scenario: discovery 元数据完整）。
    #[test]
    fn discovery_metadata_contains_all_required_fields() {
        let handler = make_handler();
        let metadata = handler.discovery_metadata();
        assert_eq!(metadata["issuer"], "https://auth.example.com");
        assert!(metadata["authorization_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/authorize"));
        assert!(metadata["token_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/token"));
        assert!(metadata["userinfo_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/userinfo"));
        assert!(metadata["jwks_uri"].as_str().unwrap().ends_with("/jwks"));
        assert!(metadata["response_types_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("code")));
        assert!(metadata["subject_types_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("public")));
        assert!(metadata["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("HS256")));
    }

    /// discovery_metadata issuer 与 handler 配置一致（spec Scenario）。
    #[test]
    fn discovery_metadata_issuer_matches_handler() {
        let handler = OidcHandler::new("https://my-provider.com", "client-1", "secret").unwrap();
        let metadata = handler.discovery_metadata();
        assert_eq!(metadata["issuer"], "https://my-provider.com");
    }

    /// HS512 算法 reflected in discovery metadata。
    #[test]
    fn discovery_metadata_reflects_hs512_algorithm() {
        let handler = make_handler().with_algorithm(Algorithm::HS512);
        let metadata = handler.discovery_metadata();
        assert!(metadata["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("HS512")));
    }

    // ========================================================================
    // verify_id_token 错误路径补充测试
    // ========================================================================

    /// 验证过期 id_token 返回 ExpiredToken 错误。
    ///
    /// 覆盖 verify_id_token 中 `if msg.contains("ExpiredSignature")` 分支：
    /// 创建 timeout=0 的 token，验证时已过期。
    #[test]
    fn verify_id_token_expired_returns_expired_token_error() {
        let handler = make_handler();
        // timeout=0 → exp=now，验证时已过期
        let token = handler.sign_id_token("1001", "nonce", "openid", 0).unwrap();
        // 等待极短时间确保 exp < 当前时间
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let result = handler.verify_id_token(&token, "nonce");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::ExpiredToken(_)) => {},
            other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
        }
    }

    /// 验证 aud 不匹配返回 InvalidToken 错误。
    ///
    /// 覆盖 verify_id_token 中 `if claims.aud != self.audience` 分支。
    #[test]
    fn verify_id_token_aud_mismatch_fails() {
        let signer = OidcHandler::new("https://auth.example.com", "correct-aud", "secret").unwrap();
        let verifier = OidcHandler::new("https://auth.example.com", "wrong-aud", "secret").unwrap();
        let token = signer
            .sign_id_token("1001", "nonce", "openid", 3600)
            .unwrap();
        let result = verifier.verify_id_token(&token, "nonce");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => assert!(msg.contains("aud")),
            other => panic!("期望 InvalidToken (aud) 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // algorithm_str 非对称算法分支测试
    // ========================================================================

    /// 验证 discovery_metadata 对非 HMAC 算法返回 "unknown"。
    ///
    /// 覆盖 algorithm_str 中 `_ => "unknown"` 分支。
    #[test]
    fn discovery_metadata_non_hmac_algorithm_returns_unknown() {
        let handler = make_handler().with_algorithm(Algorithm::RS256);
        let metadata = handler.discovery_metadata();
        // algorithm_str 对 RS256 返回 "unknown"
        assert!(metadata["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("unknown")));
    }

    // ========================================================================
    // 辅助函数
    // ========================================================================

    /// Base64URL 解码（无 padding）。
    fn base64_url_decode(s: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .expect("Base64URL 解码失败")
    }

    // ========================================================================
    // LoginId newtype 接入（impl Into<LoginId>）
    // ========================================================================

    /// 验证 `OidcHandler::sign_id_token` 接受 String 形式 login_id。
    #[test]
    fn sign_id_token_accepts_login_id_numeric() {
        let handler = OidcHandler::new("https://auth.example.com", "aud-abc", "secret").unwrap();
        let token = handler
            .sign_id_token("1001".to_string(), "nonce", "openid", 3600)
            .unwrap();
        let claims = handler.verify_id_token(&token, "nonce").unwrap();
        assert_eq!(claims.login_id, "1001");
    }
}
