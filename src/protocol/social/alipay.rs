//! 支付宝授权登录 provider（0.5.0 新增，依据 spec social-login R-social-login-003）。
//!
//! 实现 `SocialLoginProvider` trait，覆盖支付宝开放平台授权登录的 OAuth2 流程：
//! - `get_authorization_url`：拼接 `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?` 授权页 URL
//! - `exchange_token`：调用 `https://openapi.alipay.com/gateway.do` 用 RSA 签名换取 access_token
//! - `get_user_info`：调用 `alipay.user.info.share` 接口获取用户信息
//!
//! ## Feature 门控
//!
//! 启用 `social-alipay` feature 时编译，依赖 `protocol-oauth2`（提供 reqwest HTTP client）。

use crate::error::BulwarkResult;
use crate::protocol::social::{SocialLoginProvider, SocialUserInfo};
use async_trait::async_trait;

/// 支付宝授权页端点。
const ALIPAY_AUTH_URL: &str = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm";

/// 支付宝授权登录 provider（依据 spec social-login R-social-login-003）。
///
/// 实现 `SocialLoginProvider` trait，封装支付宝开放平台授权登录的 OAuth2 流程。
///
/// # RSA 签名
///
/// `exchange_token` 需用 RSA 私钥对请求参数签名。当前实现存储 PEM 字符串，
/// 签名时解析为 `RsaPrivateKey`（待后续任务实现 exchange_token 时引入 `rsa` crate）。
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
    /// RSA 私钥 PEM 字符串（exchange_token 时解析为 RsaPrivateKey 签名）。
    private_key_pem: String,
    /// HTTP 客户端（复用连接池）。
    http: reqwest::Client,
}

impl AlipayProvider {
    /// 创建 `AlipayProvider` 实例。
    ///
    /// # 参数
    /// - `app_id`: 支付宝开放平台 AppID
    /// - `private_key_pem`: RSA 私钥 PEM 字符串（用于 exchange_token 时的请求签名）
    pub fn new(app_id: &str, private_key_pem: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            private_key_pem: private_key_pem.to_string(),
            http: reqwest::Client::new(),
        }
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

    /// 用授权码换取用户信息（后续任务实现 RSA 签名）。
    async fn exchange_token(&self, _code: &str, _state: &str) -> BulwarkResult<SocialUserInfo> {
        // 抑制 dead_code：private_key_pem 与 http 将在 exchange_token 实现中读取
        let _ = (&self.private_key_pem, &self.http);
        // 后续任务将实现：POST https://openapi.alipay.com/gateway.do 用 RSA 签名
        todo!("implement exchange_token with RSA signing via alipay gateway")
    }

    /// 用 access_token 获取用户信息（后续任务实现）。
    async fn get_user_info(&self, _access_token: &str) -> BulwarkResult<SocialUserInfo> {
        // 后续任务将实现：调用 alipay.user.info.share 接口
        todo!("implement get_user_info with alipay.user.info.share")
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
}
