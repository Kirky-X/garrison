// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 社交登录协议层测试 mock（仅 `cfg(test)` 编译）：`MockSocialProvider` 供 `tests` 做 trait 契约验证。

use crate::error::GarrisonResult;
use crate::protocol::social::{provider_names, SocialLoginProvider, SocialUserInfo};
use async_trait::async_trait;

/// 测试用 Mock 社交登录 Provider。
pub struct MockSocialProvider;

#[async_trait]
impl SocialLoginProvider for MockSocialProvider {
    async fn get_authorization_url(
        &self,
        _state: &str,
        _redirect_uri: &str,
    ) -> GarrisonResult<String> {
        Ok("https://example.com/auth".into())
    }

    async fn exchange_token(&self, _code: &str, _state: &str) -> GarrisonResult<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: provider_names::WECHAT.to_string(),
            provider_user_id: "mock_openid".into(),
            nickname: None,
            avatar: None,
            union_id: Some("mock_unionid".into()),
            raw: serde_json::json!({"mock": true}),
        })
    }

    async fn get_user_info(&self, _access_token: &str) -> GarrisonResult<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: provider_names::WECHAT.to_string(),
            provider_user_id: "mock_openid".into(),
            nickname: Some("MockUser".into()),
            avatar: Some("https://example.com/avatar.png".into()),
            union_id: Some("mock_unionid".into()),
            raw: serde_json::json!({"mock": true}),
        })
    }
}
