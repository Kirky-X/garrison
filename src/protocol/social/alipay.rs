//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 支付宝授权登录 provider（0.5.0 新增，依据 spec social-login R-social-login-003）。
//!
//! 实现 `SocialLoginProvider` trait，覆盖支付宝开放平台授权登录的 OAuth2 流程：
//! - `get_authorization_url`：拼接 `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?` 授权页 URL
//! - `exchange_token`：调用 `https://openapi.alipay.com/gateway.do` 用 RSA2 签名换取 access_token
//! - `get_user_info`：调用 `alipay.user.info.share` 接口获取用户信息
//!
//! ## Feature 门控
//!
//! 启用 `social-alipay` feature 时编译，依赖 `protocol-oauth2`（提供 reqwest HTTP client）。

use crate::error::{BulwarkError, BulwarkResult};
use crate::loc;
use crate::protocol::social::{SocialLoginProvider, SocialProvider, SocialUserInfo};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde_json::Value;

/// 支付宝授权页端点。
const ALIPAY_AUTH_URL: &str = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm";

/// 支付宝开放平台网关端点（默认值，可通过 `with_gateway_url` 覆盖以适配测试）。
const ALIPAY_GATEWAY_URL: &str = "https://openapi.alipay.com/gateway.do";

/// 支付宝授权登录 provider（依据 spec social-login R-social-login-003）。
///
/// 实现 `SocialLoginProvider` trait，封装支付宝开放平台授权登录的 OAuth2 流程。
///
/// # RSA2 签名
///
/// `exchange_token` / `get_user_info` 调用支付宝网关时需用 RSA 私钥对请求参数做
/// SHA256withRSA（RSA2）签名。签名流程：参数按 key ASCII 升序排序 →
/// 拼接 `key=value&...`（不含 sign/sign_type）→ RSA PKCS1v15 签名 → base64 编码。
///
/// # 示例
///
/// ```ignore
/// use bulwark::protocol::social::alipay::AlipayProvider;
/// use bulwark::protocol::social::SocialLoginProvider;
///
/// let provider = AlipayProvider::new("app_id", "private_key_pem");
/// let url = provider.get_authorization_url("state", "https://example.com/cb").await?;
/// ```
pub struct AlipayProvider {
    /// 支付宝开放平台 AppID。
    app_id: String,
    /// RSA 私钥 PEM 字符串（PKCS#1 格式，签名时解析为 RsaPrivateKey）。
    private_key_pem: String,
    /// HTTP 客户端（复用连接池）。
    http: reqwest::Client,
    /// 支付宝网关 URL（默认 `https://openapi.alipay.com/gateway.do`，测试时可覆盖）。
    gateway_url: String,
}

impl AlipayProvider {
    /// 创建 `AlipayProvider` 实例。
    ///
    /// # 参数
    /// - `app_id`: 支付宝开放平台 AppID
    /// - `private_key_pem`: RSA 私钥 PEM 字符串（PKCS#1 格式，用于请求签名）
    pub fn new(app_id: &str, private_key_pem: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            private_key_pem: private_key_pem.to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client build with timeout should succeed"),
            gateway_url: ALIPAY_GATEWAY_URL.to_string(),
        }
    }

    /// 覆盖支付宝网关 URL（用于测试时指向 mock server）。
    #[must_use]
    pub fn with_gateway_url(mut self, gateway_url: impl Into<String>) -> Self {
        self.gateway_url = gateway_url.into();
        self
    }

    /// 对支付宝请求参数做 RSA2（SHA256withRSA）签名。
    ///
    /// # 签名流程
    /// 1. 收集所有请求参数（不含 sign；sign_type 参与签名）
    /// 2. 按 key 的 ASCII 升序排序
    /// 3. 拼接为 `key1=value1&key2=value2&...`
    /// 4. 用 RSA 私钥 + SHA256（PKCS1v15 padding）签名
    /// 5. base64 编码签名值
    ///
    /// # 实现说明
    ///
    /// 使用 `rsa::pkcs1v15::SigningKey::<Sha256>` API，其中 `Sha256` 来自 `rsa::sha2`
    /// re-export（即 `sha2 0.10`，与 rsa 0.9 内部依赖的 `digest 0.10` 兼容）。
    /// 不能用项目顶层 `sha2 0.11` 的 `Sha256`——它实现的是 `digest 0.11` 的 `Digest` trait，
    /// 与 `SigningKey<D: Digest>` 的 bound 不兼容。
    ///
    /// # 参数
    /// - `params`: 请求参数列表（key, value 二元组）
    ///
    /// # 返回
    /// - `Ok(String)`: base64 编码的签名值
    /// - `Err(BulwarkError::Config)`: RSA 私钥解析失败或签名失败
    fn sign_request(&self, params: &[(String, String)]) -> BulwarkResult<String> {
        // 1. 按 key ASCII 升序排序（克隆避免修改原 slice）
        let mut sorted = params.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        // 2. 拼接为 key=value&key=value（不含 sign；sign_type 参与签名）
        let data_to_sign = sorted
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        // 3. 解析 RSA 私钥 PEM（PKCS#1 格式）
        let private_key = RsaPrivateKey::from_pkcs1_pem(&self.private_key_pem).map_err(|e| {
            BulwarkError::Config(loc!(
                "alipay-rsa-key-parse-failed",
                format!("alipay rsa key parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        // 4. RSA2 签名（SHA256withRSA, PKCS1v15 padding）—— 用 rsa re-export 的 sha2 0.10
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(data_to_sign.as_bytes());

        // 5. base64 编码
        Ok(STANDARD.encode(signature.to_bytes()))
    }
}

#[async_trait]
impl SocialLoginProvider for AlipayProvider {
    /// 拼接支付宝授权登录授权页 URL。
    ///
    /// URL 格式：`https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id={app_id}&redirect_uri={redirect_uri}&state={state}`
    ///（依据 spec social-login R-social-login-003 验收标准）。
    async fn get_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
    ) -> BulwarkResult<String> {
        Ok(format!(
            "{}?app_id={}&redirect_uri={}&state={}",
            ALIPAY_AUTH_URL,
            urlencoding::encode(&self.app_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        ))
    }

    /// 用授权码换取用户信息（依据 spec social-login R-social-login-003）。
    ///
    /// 调用支付宝 `alipay.system.oauth.token` 接口，用授权码换取 access_token + user_id，
    /// 返回 `SocialUserInfo`（nickname/avatar 为 None，需调用 `get_user_info` 获取）。
    ///
    /// # 流程
    /// 1. 构造公共参数（app_id/method/charset/sign_type/timestamp/version）+ 业务参数（grant_type/code）
    /// 2. 用 RSA2 签名所有参数
    /// 3. POST 到支付宝网关（form-encoded body）
    /// 4. 解析响应 JSON，检查 error_response
    /// 5. 提取 user_id 返回 SocialUserInfo
    async fn exchange_token(&self, code: &str, _state: &str) -> BulwarkResult<SocialUserInfo> {
        let timestamp = chrono::Utc::now()
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).expect("8*3600 valid"))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        // 收集请求参数（sign_type 参与签名，sign 不参与——sign 由 sign_request 生成后追加）
        let params: Vec<(String, String)> = vec![
            ("app_id".into(), self.app_id.clone()),
            ("method".into(), "alipay.system.oauth.token".into()),
            ("charset".into(), "UTF-8".into()),
            ("sign_type".into(), "RSA2".into()),
            ("timestamp".into(), timestamp),
            ("version".into(), "1.0".into()),
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.to_string()),
        ];

        // RSA2 签名（sign_request 对所有传入参数排序后签名，sign 在签名后追加到 form body）
        let sign = self.sign_request(&params)?;

        // 构造 form-encoded body（params + sign）
        let mut form_body = params;
        form_body.push(("sign".into(), sign));

        // POST 到支付宝网关
        let resp = self
            .http
            .post(&self.gateway_url)
            .form(&form_body)
            .send()
            .await
            .map_err(|e| {
                BulwarkError::Network(loc!(
                    "alipay-token-request-failed",
                    format!("alipay token request failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            return Err(BulwarkError::Network(loc!(
                "alipay-token-request-failed",
                format!("alipay token request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "alipay-token-response-parse-failed",
                format!("alipay token response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        // 检查错误响应
        if let Some(err_resp) = raw.get("error_response").filter(|v| !v.is_null()) {
            let code = err_resp
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let msg = err_resp
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(BulwarkError::Network(loc!(
                "alipay-error-response",
                format!("alipay error {}: {}", code, msg),
                ("code", code),
                ("message", msg)
            )));
        }

        // 提取 user_id
        let user_id = raw
            .get("alipay_system_oauth_token_response")
            .and_then(|v| v.get("user_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BulwarkError::Network(loc!(
                    "alipay-response-missing-user-id",
                    "alipay response missing user_id field".to_string()
                ))
            })?
            .to_string();

        Ok(SocialUserInfo {
            provider: SocialProvider::Alipay,
            provider_user_id: user_id,
            nickname: None,
            avatar: None,
            union_id: None,
            raw,
        })
    }

    /// 用 access_token 获取用户信息（依据 spec social-login R-social-login-003）。
    ///
    /// 调用支付宝 `alipay.user.info.share` 接口，用 access_token 获取用户昵称、头像等信息。
    ///
    /// # 流程
    /// 1. 构造公共参数 + `auth_token` 业务参数
    /// 2. 用 RSA2 签名
    /// 3. POST 到支付宝网关
    /// 4. 解析 `alipay_user_info_share_response` 中的 user_id/nick/avatar
    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<SocialUserInfo> {
        let timestamp = chrono::Utc::now()
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).expect("8*3600 valid"))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        let params: Vec<(String, String)> = vec![
            ("app_id".into(), self.app_id.clone()),
            ("method".into(), "alipay.user.info.share".into()),
            ("charset".into(), "UTF-8".into()),
            ("sign_type".into(), "RSA2".into()),
            ("timestamp".into(), timestamp),
            ("version".into(), "1.0".into()),
            ("auth_token".into(), access_token.to_string()),
        ];

        let sign = self.sign_request(&params)?;

        let mut form_body = params;
        form_body.push(("sign".into(), sign));

        let resp = self
            .http
            .post(&self.gateway_url)
            .form(&form_body)
            .send()
            .await
            .map_err(|e| {
                BulwarkError::Network(loc!(
                    "alipay-user-info-request-failed",
                    format!("alipay user_info request failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            return Err(BulwarkError::Network(loc!(
                "alipay-user-info-request-failed",
                format!("alipay user_info request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "alipay-user-info-response-parse-failed",
                format!("alipay user_info response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        // 检查错误响应
        if let Some(err_resp) = raw.get("error_response").filter(|v| !v.is_null()) {
            let code = err_resp
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let msg = err_resp
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(BulwarkError::Network(loc!(
                "alipay-error-response",
                format!("alipay error {}: {}", code, msg),
                ("code", code),
                ("message", msg)
            )));
        }

        let resp_obj = raw.get("alipay_user_info_share_response").ok_or_else(|| {
            BulwarkError::Network(loc!(
                "alipay-response-missing-user-info-share-response",
                "alipay response missing alipay_user_info_share_response field".to_string()
            ))
        })?;

        let user_id = resp_obj
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BulwarkError::Network(loc!(
                    "alipay-response-missing-user-id",
                    "alipay response missing user_id field".to_string()
                ))
            })?
            .to_string();

        let nickname = resp_obj
            .get("nick")
            .and_then(|v| v.as_str())
            .map(String::from);
        let avatar = resp_obj
            .get("avatar")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(SocialUserInfo {
            provider: SocialProvider::Alipay,
            provider_user_id: user_id,
            nickname,
            avatar,
            union_id: None,
            raw,
        })
    }
}

/// 简单的 URL 编码工具（与 `protocol::oauth2::urlencoding` 同实现，避免跨模块耦合）。
///
/// 对查询参数值进行百分号编码，保留字母、数字、`-`、`_`、`.`、`~`。
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{:02X}", b));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 生成测试用 RSA 私钥并返回 PKCS#1 PEM 字符串。
    ///
    /// 用 `OsRng` 生成 2048 位 RSA 密钥（与 keycloak_oidc_integration 测试模式一致），
    /// 转为 PKCS#1 PEM 字符串供 `AlipayProvider::new` 使用。
    fn generate_test_rsa_pem() -> String {
        let mut rng = OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("转 PKCS#1 PEM 应成功")
            .to_string()
    }

    /// 验证 `AlipayProvider::get_authorization_url` 返回符合支付宝授权登录规范的 URL
    ///（依据 spec social-login R-social-login-003 验收标准）。
    ///
    /// Red 阶段：`AlipayProvider` 类型不存在 → 编译失败。
    /// Green 阶段（T104）：定义 struct + impl 后测试通过。
    #[tokio::test]
    async fn alipay_provider_get_authorization_url_returns_correct_format() {
        let provider = AlipayProvider::new("app_id", "private_key_pem");
        let url = provider
            .get_authorization_url("state", "https://example.com/cb")
            .await
            .expect("get_authorization_url 应返回 Ok");

        assert!(
            url.starts_with("https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?"),
            "URL 应以支付宝授权端点开头，实际: {}",
            url
        );
        assert!(
            url.contains("app_id=app_id"),
            "URL 应含 app_id 参数，实际: {}",
            url
        );
    }

    /// T006 Red: 验证 `AlipayProvider::exchange_token` 解析支付宝 oauth.token 响应中的 user_id
    ///（依据 spec social-login R-social-login-003 验收标准）。
    ///
    /// Red 阶段：`exchange_token` 为 `todo!()` → panic。
    /// Green 阶段（T007）：实现 RSA2 签名 + HTTP 调用后测试通过。
    ///
    /// # 测试流程
    /// 1. 生成测试 RSA 私钥（PKCS#1 PEM）
    /// 2. wiremock 模拟 `POST /gateway.do` 返回 `alipay_system_oauth_token_response`
    /// 3. 构造 `AlipayProvider::new("app_id", &pem).with_gateway_url(server.uri() + "/gateway.do")`
    /// 4. 调用 `exchange_token("auth_code", "state")`
    /// 5. 断言返回 `SocialUserInfo { provider: Alipay, provider_user_id: "user123" }`
    #[tokio::test]
    async fn alipay_provider_exchange_token_parses_user_id_from_response() {
        let pem = generate_test_rsa_pem();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alipay_system_oauth_token_response": {
                    "access_token": "tok123",
                    "user_id": "user123",
                    "expires_in": 3600,
                    "refresh_token": "rt456"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let user_info = provider
            .exchange_token("auth_code", "state")
            .await
            .expect("exchange_token 应返回 Ok");

        assert_eq!(user_info.provider, SocialProvider::Alipay);
        assert_eq!(user_info.provider_user_id, "user123");
    }

    /// T006 Red: 验证 `AlipayProvider::exchange_token` 在私钥 PEM 无效时返回 `Err(Config)`
    /// 而非 panic（Rule 12 失败显性化）。
    ///
    /// Red 阶段：`exchange_token` 为 `todo!()` → panic（不满足 Rule 12）。
    /// Green 阶段（T007）：签名时解析 PEM 失败 → 返回 `BulwarkError::Config`。
    #[tokio::test]
    async fn alipay_provider_exchange_token_returns_error_on_invalid_signature() {
        let provider = AlipayProvider::new("app_id", "invalid_pem");
        let result = provider.exchange_token("auth_code", "state").await;

        assert!(result.is_err(), "无效私钥应返回 Err，实际: {:?}", result);
        let err = result.unwrap_err();
        match err {
            BulwarkError::Config(msg) => {
                assert!(
                    msg.contains("rsa key parse failed")
                        || msg.contains("RSA 私钥解析失败")
                        || msg.contains("RSA private key parse failed"),
                    "错误消息应包含 RSA 密钥解析失败相关描述，实际: {}",
                    msg
                );
            },
            other => panic!("应为 BulwarkError::Config，实际: {:?}", other),
        }
    }

    /// T009 Red: 验证 `AlipayProvider::get_user_info` 解析支付宝 user.info.share 响应中的
    /// nick/avatar/user_id（依据 spec social-login R-social-login-003 验收标准）。
    ///
    /// Red 阶段：`get_user_info` 为 `todo!()` → panic。
    /// Green 阶段（T010）：实现 alipay.user.info.share 调用后测试通过。
    ///
    /// # 测试流程
    /// 1. 生成测试 RSA 私钥（PKCS#1 PEM）
    /// 2. wiremock 模拟 `POST /gateway.do` 返回 `alipay_user_info_share_response`
    /// 3. 构造 `AlipayProvider::new("app_id", &pem).with_gateway_url(server.uri() + "/gateway.do")`
    /// 4. 调用 `get_user_info("valid_access_token")`
    /// 5. 断言返回 `SocialUserInfo { provider: Alipay, provider_user_id: "user123",
    ///    nickname: Some("Bob"), avatar: Some("https://img.example.com/b.png") }`
    #[tokio::test]
    async fn alipay_provider_get_user_info_parses_nick_and_avatar() {
        let pem = generate_test_rsa_pem();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alipay_user_info_share_response": {
                    "user_id": "user123",
                    "nick": "Bob",
                    "avatar": "https://img.example.com/b.png",
                    "is_certified": "T"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let user_info = provider
            .get_user_info("valid_access_token")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider, SocialProvider::Alipay);
        assert_eq!(user_info.provider_user_id, "user123");
        assert_eq!(user_info.nickname.as_deref(), Some("Bob"));
        assert_eq!(
            user_info.avatar.as_deref(),
            Some("https://img.example.com/b.png")
        );
    }
}
