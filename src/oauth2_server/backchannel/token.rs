// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Logout token 签发（OIDC Back-Channel Logout 1.0 §2）。
//!
//! 复用 `protocol::jwt` 的 `JwtHandler` 密钥材料与算法-密钥匹配校验签发；
//! claim 集收敛为协议要求的最小面：`iss` / `aud` / `iat` / `exp` / `jti` /
//! `events`，身份面仅 `sub`（可选 `sid`）——不含 `login_id` / `device` 等
//! Garrison 身份扩展，也不含协议禁止的 `nonce`。

use crate::error::{GarrisonError, GarrisonResult};
use crate::protocol::jwt::JwtHandler;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Back-Channel Logout 事件 URI（OIDC Back-Channel Logout 1.0 §2.3 固定值）。
pub const BACKCHANNEL_LOGOUT_EVENT_URI: &str = "http://schemas.openid.net/event/backchannel-logout";

/// logout token 有效期（秒）。
///
/// RP 收到即消费；投递队列按自身 MaxTtl 控制重试窗口，token 本身短时效
/// 限制过期 token 被迟到的 RP 接受的窗口。
pub const LOGOUT_TOKEN_TTL_SECS: i64 = 120;

/// OIDC Back-Channel Logout Token claims。
///
/// `events` 固定含 [`BACKCHANNEL_LOGOUT_EVENT_URI`]（空对象载荷）——RP 据此
/// 区分 logout token 与 ID token。
#[derive(Debug, Clone, Serialize)]
pub struct LogoutTokenClaims {
    /// 签发者（OP issuer 标识，如 `https://op.example.com`）。
    pub iss: String,
    /// 登出主体（用户标识）；无主体语义的登出可省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// 受众（目标 RP 的 client_id）。
    pub aud: String,
    /// 签发时间（Unix 秒）。
    pub iat: i64,
    /// 过期时间（Unix 秒，`iat + LOGOUT_TOKEN_TTL_SECS`）。
    pub exp: i64,
    /// token 唯一标识（RP 可据此去重防重放）。
    pub jti: String,
    /// 事件声明：仅含 backchannel-logout 事件、空对象载荷。
    pub events: BTreeMap<String, serde_json::Value>,
    /// OP 侧会话标识（可选）。登出事件仅携掩码 token，会话 id 不可还原时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// Logout token 签发器：持 OP 的 JWT 密钥材料与 issuer 标识。
pub struct LogoutTokenIssuer {
    handler: Arc<JwtHandler>,
    issuer: String,
}

impl LogoutTokenIssuer {
    /// 从既有 `JwtHandler` 构造（与 ID token 签发共用同一密钥轮换面）。
    pub fn new(handler: Arc<JwtHandler>, issuer: impl Into<String>) -> Self {
        Self {
            handler,
            issuer: issuer.into(),
        }
    }

    /// 为单个 RP 签发 logout token（JWT 紧凑序列化）。
    ///
    /// # 参数
    /// - `client_id`：目标 RP（写入 `aud`）。
    /// - `sub`：登出主体；`None` 时不序列化 `sub`。
    /// - `sid`：OP 侧会话标识；`None` 时不序列化 `sid`。
    pub fn issue(
        &self,
        client_id: &str,
        sub: Option<&str>,
        sid: Option<&str>,
    ) -> GarrisonResult<String> {
        let iat = unix_now_secs()?;
        let exp = iat
            .checked_add(LOGOUT_TOKEN_TTL_SECS)
            .ok_or_else(|| GarrisonError::InvalidParam("logout-token-ttl-overflow".to_string()))?;
        let events = BTreeMap::from([(
            BACKCHANNEL_LOGOUT_EVENT_URI.to_string(),
            serde_json::json!({}),
        )]);
        let claims = LogoutTokenClaims {
            iss: self.issuer.clone(),
            sub: sub.map(str::to_string),
            aud: client_id.to_string(),
            iat,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
            events,
            sid: sid.map(str::to_string),
        };
        self.handler.sign_claims(&claims)
    }
}

fn unix_now_secs() -> GarrisonResult<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| GarrisonError::Internal(format!("system-clock-error::{}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::jwt::JwtHandler;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn issuer() -> LogoutTokenIssuer {
        LogoutTokenIssuer::new(Arc::new(JwtHandler::new(SECRET)), "https://op.example.com")
    }

    /// 跳过 exp 校验解码 claims（claim 形状断言用；签名仍校验）。
    fn decode_claims(token: &str, secret: &[u8]) -> serde_json::Value {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        // 形状断言面向任意 aud 值，aud 归属校验由 RP 侧负责
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        decode::<serde_json::Value>(token, &DecodingKey::from_secret(secret), &validation)
            .expect("解码应成功")
            .claims
    }

    /// events 含 backchannel-logout 空对象；除 sub/sid 外无身份
    /// claim（login_id / device / nonce 均不出现）；iss/aud/jti 就位；
    /// exp = iat + TTL。
    #[test]
    fn logout_token_carries_events_and_no_identity_claims_beyond_subject() {
        let token = issuer()
            .issue("client-a", Some("alice"), None)
            .expect("签发应成功");
        let claims = decode_claims(&token, SECRET.as_bytes());

        let events = claims["events"].as_object().expect("events 应为对象");
        assert!(
            events.contains_key(BACKCHANNEL_LOGOUT_EVENT_URI),
            "events 必须含 backchannel-logout 事件 URI，实际: {events:?}"
        );
        assert!(
            events[BACKCHANNEL_LOGOUT_EVENT_URI].is_object(),
            "事件载荷应为对象"
        );
        assert_eq!(events.len(), 1, "不得夹带其他事件");

        assert_eq!(claims["iss"], "https://op.example.com");
        assert_eq!(claims["aud"], "client-a");
        assert_eq!(claims["sub"], "alice");
        assert!(
            claims["jti"].as_str().is_some_and(|j| !j.is_empty()),
            "jti 必须存在且非空"
        );
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            LOGOUT_TOKEN_TTL_SECS
        );

        for forbidden in ["login_id", "device", "nonce"] {
            assert!(
                claims.get(forbidden).is_none(),
                "logout token 不得携带身份 claim `{forbidden}`，实际: {claims}"
            );
        }
        assert!(claims.get("sid").is_none(), "sid 未提供时不得出现");
    }

    /// 无主体语义登出（sub=None）不序列化 sub。
    #[test]
    fn logout_token_without_subject_omits_sub() {
        let token = issuer().issue("client-a", None, None).expect("签发应成功");
        let claims = decode_claims(&token, SECRET.as_bytes());
        assert!(claims.get("sub").is_none(), "sub=None 时不得序列化 sub");
    }

    /// sid 提供时写入 claims。
    #[test]
    fn logout_token_includes_sid_when_provided() {
        let token = issuer()
            .issue("client-a", Some("alice"), Some("sess-42"))
            .expect("签发应成功");
        let claims = decode_claims(&token, SECRET.as_bytes());
        assert_eq!(claims["sid"], "sess-42");
    }

    /// 签名绑定签发密钥：错误密钥验签必须失败（防伪造）。
    #[test]
    fn logout_token_signature_binds_issuer_key() {
        let token = issuer()
            .issue("client-a", Some("alice"), None)
            .expect("签发应成功");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let wrong_key = jsonwebtoken::DecodingKey::from_secret(b"wrong-secret-wrong-secret-32b");
        assert!(
            jsonwebtoken::decode::<serde_json::Value>(&token, &wrong_key, &validation).is_err(),
            "错误密钥验签必须失败"
        );
    }
}
