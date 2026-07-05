//! 社交登录协议插件模块（0.5.0 新增，依据 proposal H2 / spec social-login）。
//!
//! 提供 `SocialLoginProvider` trait 抽象社交登录第三方平台（微信/支付宝），
//! 统一 `get_authorization_url` / `exchange_token` / `get_user_info` 三个 OAuth2 流程方法。
//!
//! ## 子模块
//!
//! - `wechat`：微信扫码登录（`WechatProvider`，需 `social-wechat` feature）
//! - `alipay`：支付宝授权登录（`AlipayProvider`，需 `social-alipay` feature）
//!
//! ## 与 OAuth2 模块的关系
//!
//! `protocol::oauth2` 提供通用 OAuth2 客户端（Authorization Code / Client Credentials / Password），
//! 本模块针对社交平台特化（微信/支付宝的自定义 API 签名、用户信息格式）。

use crate::error::BulwarkResult;
use async_trait::async_trait;
use serde_json::Value;

// ============================================================================
// SocialProvider enum：社交平台标识
// ============================================================================

/// 社交登录平台标识（依据 spec social-login R-social-login-001）。
///
/// 用于 `SocialUserInfo.provider` 字段标识用户来源平台。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialProvider {
    /// 微信开放平台扫码登录。
    Wechat,
    /// 支付宝开放平台授权登录。
    Alipay,
    /// 微信小程序登录（v0.5.0+ 预留，实现推迟到 v0.5.1+）。
    WechatMiniApp,
}

// ============================================================================
// SocialUserInfo：社交用户信息
// ============================================================================

/// 社交用户信息（依据 spec social-login R-social-login-001）。
///
/// `exchange_token` / `get_user_info` 方法的返回类型，承载第三方平台返回的用户字段。
#[derive(Debug, Clone)]
pub struct SocialUserInfo {
    /// 用户来源平台标识。
    pub provider: SocialProvider,
    /// 第三方平台用户唯一 ID（微信 openid / 支付宝 user_id）。
    pub provider_user_id: String,
    /// 用户昵称（可能为空）。
    pub nickname: Option<String>,
    /// 用户头像 URL（可能为空）。
    pub avatar: Option<String>,
    /// 跨应用统一 ID（微信 unionid，用于同一开发者主体下多应用账号打通）。
    pub union_id: Option<String>,
    /// 第三方平台原始响应 JSON（调试用，不应依赖其结构）。
    pub raw: Value,
}

// ============================================================================
// SocialLoginProvider trait：社交登录抽象
// ============================================================================

/// 社交登录服务提供方 trait（依据 spec social-login R-social-login-001）。
///
/// 定义三个异步方法覆盖 OAuth2 授权码流程：
/// - `get_authorization_url`：拼接授权页 URL（用户跳转到第三方平台授权）
/// - `exchange_token`：用授权码换取用户信息（内部完成 code → access_token → user_info 两步）
/// - `get_user_info`：用 access_token 获取用户信息（用于已缓存 token 的场景）
///
/// # 实现
///
/// - `WechatProvider`（`social-wechat` feature）
/// - `AlipayProvider`（`social-alipay` feature）
#[async_trait]
pub trait SocialLoginProvider: Send + Sync {
    /// 拼接第三方平台授权页 URL。
    ///
    /// # 参数
    /// - `state`: OAuth2 state 参数（CSRF 防护，调用方生成随机串并缓存校验）
    /// - `redirect_uri`: 授权回调 URL（需在第三方平台配置白名单）
    async fn get_authorization_url(&self, state: &str, redirect_uri: &str)
        -> BulwarkResult<String>;

    /// 用授权码换取用户信息。
    ///
    /// 内部完成两步：1) code → access_token（POST token endpoint）2) access_token → user_info（GET userinfo endpoint）。
    ///
    /// # 参数
    /// - `code`: 授权码（第三方平台回调时附在 query 参数）
    /// - `state`: OAuth2 state 参数（校验一致性，防 CSRF）
    async fn exchange_token(&self, code: &str, state: &str) -> BulwarkResult<SocialUserInfo>;

    /// 用 access_token 获取用户信息。
    ///
    /// 用于已缓存 access_token 的场景（避免重复授权）。
    ///
    /// # 参数
    /// - `access_token`: 第三方平台访问令牌
    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<SocialUserInfo>;
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    /// 验证 `SocialLoginProvider` trait 可被 mock 实现并调用三个方法
    ///（依据 spec social-login R-social-login-001 验收标准 1）。
    ///
    /// Red 阶段：`SocialLoginProvider` / `SocialUserInfo` / `SocialProvider` 类型不存在 → 编译失败。
    /// Green 阶段（T098）：定义完整类型后测试通过。
    #[tokio::test]
    async fn social_login_provider_trait_defines_three_methods() {
        use super::*;

        struct MockSocialProvider;

        #[async_trait]
        impl SocialLoginProvider for MockSocialProvider {
            async fn get_authorization_url(
                &self,
                _state: &str,
                _redirect_uri: &str,
            ) -> BulwarkResult<String> {
                Ok("https://example.com/auth".into())
            }

            async fn exchange_token(
                &self,
                _code: &str,
                _state: &str,
            ) -> BulwarkResult<SocialUserInfo> {
                Ok(SocialUserInfo {
                    provider: SocialProvider::Wechat,
                    provider_user_id: "mock_openid".into(),
                    nickname: None,
                    avatar: None,
                    union_id: Some("mock_unionid".into()),
                    raw: serde_json::json!({"mock": true}),
                })
            }

            async fn get_user_info(&self, _access_token: &str) -> BulwarkResult<SocialUserInfo> {
                Ok(SocialUserInfo {
                    provider: SocialProvider::Wechat,
                    provider_user_id: "mock_openid".into(),
                    nickname: Some("MockUser".into()),
                    avatar: Some("https://example.com/avatar.png".into()),
                    union_id: Some("mock_unionid".into()),
                    raw: serde_json::json!({"mock": true}),
                })
            }
        }

        let provider = MockSocialProvider;

        // 验证 get_authorization_url 可调用且返回非空 URL
        let auth_url = provider
            .get_authorization_url("state123", "https://example.com/cb")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(!auth_url.is_empty(), "授权 URL 不应为空");

        // 验证 exchange_token 可调用且返回 SocialUserInfo
        let user_info = provider
            .exchange_token("code456", "state123")
            .await
            .expect("exchange_token 应返回 Ok");
        assert_eq!(user_info.provider, SocialProvider::Wechat);
        assert_eq!(user_info.provider_user_id, "mock_openid");
        assert_eq!(user_info.union_id.as_deref(), Some("mock_unionid"));

        // 验证 get_user_info 可调用且返回 SocialUserInfo
        let user_info = provider
            .get_user_info("access_token789")
            .await
            .expect("get_user_info 应返回 Ok");
        assert_eq!(user_info.nickname.as_deref(), Some("MockUser"));
        assert_eq!(
            user_info.avatar.as_deref(),
            Some("https://example.com/avatar.png")
        );
    }

    /// 验证 `SocialProvider` enum 含三个变体
    ///（依据 spec social-login R-social-login-001 验收标准 3）。
    #[test]
    fn social_provider_enum_has_three_variants() {
        use super::*;

        let wechat = SocialProvider::Wechat;
        let alipay = SocialProvider::Alipay;
        let mini_app = SocialProvider::WechatMiniApp;

        // 验证三个变体互不相等
        assert_ne!(wechat, alipay);
        assert_ne!(wechat, mini_app);
        assert_ne!(alipay, mini_app);
    }
}
