// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 支付宝授权登录 provider（`social-alipay` feature，依赖 `protocol-oauth2` 提供 reqwest HTTP client）。
//!
//! 实现 `SocialLoginProvider`：授权页 URL 拼接、RSA2 签名调用网关换取 access_token、`alipay.user.info.share` 获取用户信息。

use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use crate::protocol::social::urlencoding;
use crate::protocol::social::{provider_names, SocialLoginProvider, SocialUserInfo};
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

/// 支付宝授权登录 provider（封装支付宝开放平台 OAuth2 流程）。
///
/// # RSA2 签名
///
/// 网关请求参数按 key ASCII 升序拼接 `key=value&...`（不含 sign，sign_type 参与），再以 RSA PKCS1v15 + SHA256 签名并 base64 编码。
///
/// # 性能优化
///
/// `new` 时预解析 PEM 为 `RsaPrivateKey` 并缓存 `SigningKey`，避免每次 `sign_request` 重复解析/克隆（单次开销 1-5ms）。
///
/// # 示例
///
/// ```ignore
/// use garrison::protocol::social::alipay::AlipayProvider;
/// use garrison::protocol::social::SocialLoginProvider;
///
/// let provider = AlipayProvider::new("app_id", "private_key_pem")?;
/// let url = provider.get_authorization_url("state", "https://example.com/cb").await?;
/// ```
pub struct AlipayProvider {
    /// 支付宝开放平台 AppID。
    app_id: String,
    /// RSA 私钥 PEM 字符串（PKCS#1，保留用于 Drop 清零）：`rsa` 0.9.x 的 `RsaPrivateKey` 未实现 `Zeroize`，故清零可重建私钥的 PEM。
    private_key_pem: String,
    /// 预构造的 RSA2 签名器（`new` 时构造，`sign_request` 直接使用）：免去每次签名的 `RsaPrivateKey::clone()`（约 500ns-2μs）；`SigningKey<D>` 为 `Send + Sync`，满足 `Arc<dyn SocialLoginProvider>` 线程安全。
    signing_key: SigningKey<Sha256>,
    /// HTTP 客户端（复用连接池）。
    http: reqwest::Client,
    /// 支付宝网关 URL（默认 `ALIPAY_GATEWAY_URL`，测试可覆盖）。
    gateway_url: String,
}

impl AlipayProvider {
    /// 创建 `AlipayProvider` 实例（`private_key_pem` 为 PKCS#1 RSA 私钥 PEM）；解析失败或 HTTP 客户端构建失败返回 `GarrisonError::Config`（不 panic）。
    pub fn new(app_id: &str, private_key_pem: &str) -> GarrisonResult<Self> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem).map_err(|e| {
            GarrisonError::Config(loc!(
                "alipay-rsa-key-parse-failed",
                format!("alipay rsa key parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        // 一次性构造 SigningKey，避免每次签名重复 clone RsaPrivateKey
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            // 构建失败以 Config 传播而非 expect panic（如 TLS 后端初始化失败等可恢复环境问题）
            .map_err(|e| {
                GarrisonError::Config(loc!(
                    "alipay-http-client-build-failed",
                    format!("alipay http client build failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;
        Ok(Self {
            app_id: app_id.to_string(),
            private_key_pem: private_key_pem.to_string(),
            signing_key,
            http,
            gateway_url: ALIPAY_GATEWAY_URL.to_string(),
        })
    }

    /// 覆盖支付宝网关 URL（用于测试时指向 mock server）。
    #[must_use]
    pub fn with_gateway_url(mut self, gateway_url: impl Into<String>) -> Self {
        self.gateway_url = gateway_url.into();
        self
    }

    /// 对支付宝请求参数做 RSA2（SHA256withRSA）签名：按 key ASCII 升序拼接（不含 sign，sign_type 参与）→ RSA PKCS1v15 签名 → base64。
    ///
    /// 用 `rsa::pkcs1v15::SigningKey::<Sha256>`，其 `Sha256` 来自 `rsa::sha2` re-export（sha2 0.10，兼容 rsa 0.9 的 digest 0.10）；
    /// 项目顶层 `sha2 0.11` 的 `Sha256` 实现 `digest 0.11` 的 `Digest`，与 `SigningKey<D: Digest>` bound 不兼容。
    fn sign_request(&self, params: &[(String, String)]) -> GarrisonResult<String> {
        let mut sorted = params.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let data_to_sign = sorted
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let signature = self.signing_key.sign(data_to_sign.as_bytes());

        Ok(STANDARD.encode(signature.to_bytes()))
    }
}

#[async_trait]
impl SocialLoginProvider for AlipayProvider {
    /// 拼接支付宝授权页 URL（`ALIPAY_AUTH_URL` + `app_id`/`redirect_uri`/`state`，值经 URL 编码）。
    async fn get_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
    ) -> GarrisonResult<String> {
        Ok(format!(
            "{}?app_id={}&redirect_uri={}&state={}",
            ALIPAY_AUTH_URL,
            urlencoding::encode(&self.app_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        ))
    }

    /// 用授权码换取完整用户信息：调 `alipay.system.oauth.token` 换 access_token + user_id，再内部调 `get_user_info` 取 nickname/avatar（消费方无需再单独调用）。
    ///
    /// token 端点失败或 `get_user_info` 失败均返回 `GarrisonError::Network`。
    async fn exchange_token(&self, code: &str, _state: &str) -> GarrisonResult<SocialUserInfo> {
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

        // RSA2 签名后把 sign 追加到 form body
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
                GarrisonError::Network(loc!(
                    "alipay-token-request-failed",
                    format!("alipay token request failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "alipay-token-request-failed",
                format!("alipay token request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            GarrisonError::Network(loc!(
                "alipay-token-response-parse-failed",
                format!("alipay token response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        if let Some(err_resp) = raw.get("error_response").filter(|v| !v.is_null()) {
            let code = err_resp
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let msg = err_resp
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(GarrisonError::Network(loc!(
                "alipay-error-response",
                format!("alipay error {}: {}", code, msg),
                ("code", code),
                ("message", msg)
            )));
        }

        let token_resp = raw
            .get("alipay_system_oauth_token_response")
            .ok_or_else(|| {
                GarrisonError::Network(loc!(
                    "alipay-response-missing-oauth-token-response",
                    "alipay response missing alipay_system_oauth_token_response field".to_string()
                ))
            })?;

        let access_token = token_resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GarrisonError::Network(loc!(
                    "alipay-response-missing-access-token",
                    "alipay response missing access_token field".to_string()
                ))
            })?
            .to_string();

        // code 已被支付宝消耗：get_user_info 失败时用户需重新发起授权
        self.get_user_info(&access_token).await
    }

    /// 用 access_token 调 `alipay.user.info.share` 获取用户信息（解析 `alipay_user_info_share_response` 的 user_id/nick/avatar）。
    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<SocialUserInfo> {
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
                GarrisonError::Network(loc!(
                    "alipay-user-info-request-failed",
                    format!("alipay user_info request failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "alipay-user-info-request-failed",
                format!("alipay user_info request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            GarrisonError::Network(loc!(
                "alipay-user-info-response-parse-failed",
                format!("alipay user_info response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        if let Some(err_resp) = raw.get("error_response").filter(|v| !v.is_null()) {
            let code = err_resp
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let msg = err_resp
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(GarrisonError::Network(loc!(
                "alipay-error-response",
                format!("alipay error {}: {}", code, msg),
                ("code", code),
                ("message", msg)
            )));
        }

        let resp_obj = raw.get("alipay_user_info_share_response").ok_or_else(|| {
            GarrisonError::Network(loc!(
                "alipay-response-missing-user-info-share-response",
                "alipay response missing alipay_user_info_share_response field".to_string()
            ))
        })?;

        let user_id = resp_obj
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GarrisonError::Network(loc!(
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
            provider: provider_names::ALIPAY.to_string(),
            provider_user_id: user_id,
            nickname,
            avatar,
            union_id: None,
            raw,
        })
    }
}

/// Drop 时清零 RSA 私钥 PEM（对齐 `WechatProvider` 清零 `client_secret` 的模式）：私钥泄露可伪造任意支付宝请求签名。
///
/// 限制：`rsa` 0.9.x 的 `RsaPrivateKey` 未实现 `Zeroize`，预解析的大数内存不会被清零（如需更强保证可升级 `rsa`）。
#[cfg(feature = "protocol-zeroize")]
impl Drop for AlipayProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key_pem.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 生成 2048 位测试 RSA 私钥（PKCS#1 PEM）；用 `rsa::rand_core::OsRng`（rsa 0.9 基于 rand_core 0.6，与 rand 0.10 的 RNG trait 不兼容）。
    fn generate_test_rsa_pem() -> String {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("转 PKCS#1 PEM 应成功")
            .to_string()
    }

    /// `get_authorization_url` 返回支付宝授权端点 URL（含 app_id）。
    #[tokio::test]
    async fn alipay_provider_get_authorization_url_returns_correct_format() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem).expect("PEM 应解析成功");
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

    /// `exchange_token` 换取 access_token 后内部调 `get_user_info`，返回完整 `SocialUserInfo`（wiremock 模拟 token 与 userinfo 两个端点）。
    #[tokio::test]
    async fn alipay_provider_exchange_token_parses_user_id_from_response() {
        let pem = generate_test_rsa_pem();

        let server = MockServer::start().await;
        // token 端点：body 含 method=alipay.system.oauth.token
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .and(body_string_contains("alipay.system.oauth.token"))
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
        // userinfo 端点：body 含 method=alipay.user.info.share
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .and(body_string_contains("alipay.user.info.share"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alipay_user_info_share_response": {
                    "user_id": "user123",
                    "nick": "Bob",
                    "avatar": "https://img.example.com/b.png"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let user_info = provider
            .exchange_token("auth_code", "state")
            .await
            .expect("exchange_token 应返回 Ok");

        assert_eq!(user_info.provider, provider_names::ALIPAY);
        assert_eq!(user_info.provider_user_id, "user123");
        assert_eq!(user_info.nickname.as_deref(), Some("Bob"));
        assert_eq!(
            user_info.avatar.as_deref(),
            Some("https://img.example.com/b.png")
        );
    }

    /// 无效 PEM 在 `new` 预解析时返回 `Err(Config)` 而非 panic（失败显性化）。
    #[test]
    fn alipay_provider_new_returns_error_on_invalid_pem() {
        let result = AlipayProvider::new("app_id", "invalid_pem");

        match result {
            Err(GarrisonError::Config(msg)) => {
                assert!(
                    msg.contains("rsa key parse failed")
                        || msg.contains("RSA 私钥解析失败")
                        || msg.contains("RSA private key parse failed"),
                    "错误消息应包含 RSA 密钥解析失败相关描述，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("应为 GarrisonError::Config，实际: {:?}", other),
            Ok(_) => panic!("无效 PEM 不应返回 Ok"),
        }
    }

    /// `get_user_info` 解析 `alipay_user_info_share_response` 的 nick/avatar/user_id。
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
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let user_info = provider
            .get_user_info("valid_access_token")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider, provider_names::ALIPAY);
        assert_eq!(user_info.provider_user_id, "user123");
        assert_eq!(user_info.nickname.as_deref(), Some("Bob"));
        assert_eq!(
            user_info.avatar.as_deref(),
            Some("https://img.example.com/b.png")
        );
    }

    // AlipayProvider 构造与 builder 测试

    #[tokio::test]
    async fn alipay_provider_new_sets_app_id() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("my_app_id", &pem).expect("PEM 应解析成功");
        let url = provider
            .get_authorization_url("state", "https://example.com/cb")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(
            url.contains("app_id=my_app_id"),
            "URL 应含 app_id，实际: {}",
            url
        );
    }

    /// with_gateway_url 返回 Self 支持链式调用。
    #[tokio::test]
    async fn alipay_provider_with_gateway_url_returns_self_for_chaining() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url("https://custom.gateway.url");
        let url = provider
            .get_authorization_url("s", "r")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(url.contains("app_id=app_id"));
    }

    /// get_authorization_url 对含特殊字符的 state 和 redirect_uri 进行 URL 编码。
    #[tokio::test]
    async fn alipay_provider_get_authorization_url_encodes_special_chars() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem).expect("PEM 应解析成功");
        let url = provider
            .get_authorization_url("state with space", "https://example.com/cb?foo=bar")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(!url.contains("state with space"), "state 应被 URL 编码");
        assert!(
            url.contains("state=state%20with%20space"),
            "state 空格应编码为 %20，实际: {}",
            url
        );
    }

    // sign_request 单元测试

    /// sign_request 用有效 PEM 返回 base64 编码的签名。
    #[test]
    fn sign_request_valid_pem_returns_signature() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem).expect("PEM 应解析成功");
        let params = vec![
            ("app_id".to_string(), "test_app".to_string()),
            ("method".to_string(), "test.method".to_string()),
        ];
        let result = provider.sign_request(&params);
        assert!(result.is_ok(), "sign_request 应返回 Ok: {:?}", result.err());
        let signature = result.expect("sign_request 应返回 Ok");
        assert!(!signature.is_empty(), "签名不应为空");
        let decoded = STANDARD.decode(&signature);
        assert!(decoded.is_ok(), "签名应为有效 base64: {:?}", decoded.err());
    }

    /// sign_request 对相同参数返回相同签名（确定性）。
    #[test]
    fn sign_request_deterministic_same_params_same_signature() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem).expect("PEM 应解析成功");
        let params = vec![
            ("app_id".to_string(), "test".to_string()),
            ("method".to_string(), "test.method".to_string()),
            ("charset".to_string(), "UTF-8".to_string()),
        ];
        let sig1 = provider
            .sign_request(&params)
            .expect("第一次 sign_request 应成功");
        let sig2 = provider
            .sign_request(&params)
            .expect("第二次 sign_request 应成功");
        assert_eq!(sig1, sig2, "相同参数应返回相同签名");
    }

    /// sign_request 对参数按 key ASCII 升序排序后签名（顺序不影响结果）。
    #[test]
    fn sign_request_sorts_params_before_signing() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem).expect("PEM 应解析成功");
        let params_reverse = vec![
            ("z_param".to_string(), "z".to_string()),
            ("a_param".to_string(), "a".to_string()),
            ("m_param".to_string(), "m".to_string()),
        ];
        let params_sorted = vec![
            ("a_param".to_string(), "a".to_string()),
            ("m_param".to_string(), "m".to_string()),
            ("z_param".to_string(), "z".to_string()),
        ];
        let sig_reverse = provider
            .sign_request(&params_reverse)
            .expect("逆序 sign_request 应成功");
        let sig_sorted = provider
            .sign_request(&params_sorted)
            .expect("正序 sign_request 应成功");
        assert_eq!(
            sig_reverse, sig_sorted,
            "参数顺序不影响签名结果（内部已排序）"
        );
    }

    /// sign_request 对空参数列表返回有效签名。
    #[test]
    fn sign_request_empty_params_returns_signature() {
        let pem = generate_test_rsa_pem();
        let provider = AlipayProvider::new("app_id", &pem).expect("PEM 应解析成功");
        let params: Vec<(String, String)> = vec![];
        let result = provider.sign_request(&params);
        assert!(result.is_ok(), "空参数 sign_request 应返回 Ok");
        let signature = result.expect("sign_request 应返回 Ok");
        assert!(!signature.is_empty(), "空参数签名不应为空");
    }

    // exchange_token 错误路径测试

    /// exchange_token 在 HTTP 500 时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_exchange_token_http_500_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.exchange_token("auth_code", "state").await;

        assert!(result.is_err(), "HTTP 500 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    /// exchange_token 在响应含 error_response 时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_exchange_token_error_response_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error_response": {
                    "code": "20001",
                    "msg": "_insufficient_permissions"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.exchange_token("auth_code", "state").await;

        assert!(result.is_err(), "error_response 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("error_response 不应返回 Ok"),
        }
    }

    /// 响应缺少 access_token 时在 token 解析阶段失败（不会到达 `get_user_info`）。
    #[tokio::test]
    async fn alipay_provider_exchange_token_missing_access_token_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .and(body_string_contains("alipay.system.oauth.token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alipay_system_oauth_token_response": {
                    "user_id": "user123",
                    "expires_in": 3600
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.exchange_token("auth_code", "state").await;

        assert!(result.is_err(), "缺少 access_token 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("缺少 access_token 不应返回 Ok"),
        }
    }

    /// exchange_token 在响应缺少 alipay_system_oauth_token_response 时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_exchange_token_missing_response_object_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "some_other_field": "value"
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.exchange_token("auth_code", "state").await;

        assert!(result.is_err(), "缺少 oauth_token_response 应返回 Err");
    }

    // get_user_info 错误路径测试

    /// get_user_info 在 HTTP 500 时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_get_user_info_http_500_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.get_user_info("access_token").await;

        assert!(result.is_err(), "HTTP 500 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    /// get_user_info 在响应含 error_response 时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_get_user_info_error_response_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error_response": {
                    "code": "20001",
                    "msg": "insufficient permissions"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.get_user_info("access_token").await;

        assert!(result.is_err(), "error_response 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("error_response 不应返回 Ok"),
        }
    }

    /// get_user_info 在响应缺少 alipay_user_info_share_response 时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_get_user_info_missing_response_object_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "some_other_field": "value"
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.get_user_info("access_token").await;

        assert!(result.is_err(), "缺少 user_info_share_response 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("缺少 response object 不应返回 Ok"),
        }
    }

    /// get_user_info 在响应缺少 user_id 字段时返回 Network 错误。
    #[tokio::test]
    async fn alipay_provider_get_user_info_missing_user_id_returns_error() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alipay_user_info_share_response": {
                    "nick": "Bob",
                    "avatar": "https://img.example.com/b.png"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let result = provider.get_user_info("access_token").await;

        assert!(result.is_err(), "缺少 user_id 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("缺少 user_id 不应返回 Ok"),
        }
    }

    /// get_user_info 成功但 nick/avatar 缺失时返回 None。
    #[tokio::test]
    async fn alipay_provider_get_user_info_missing_optional_fields_returns_none() {
        let pem = generate_test_rsa_pem();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway.do"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alipay_user_info_share_response": {
                    "user_id": "user123"
                }
            })))
            .mount(&server)
            .await;

        let provider = AlipayProvider::new("app_id", &pem)
            .expect("PEM 应解析成功")
            .with_gateway_url(format!("{}/gateway.do", server.uri()));
        let user_info = provider
            .get_user_info("access_token")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "user123");
        assert!(user_info.nickname.is_none());
        assert!(user_info.avatar.is_none());
        assert!(user_info.union_id.is_none());
    }
}
