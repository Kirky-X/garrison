//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 社交登录协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockSocialProvider`（实现 `SocialLoginProvider` trait 的单元结构体），
//! 供 `protocol::social::tests` 验证 trait 契约测试复用。

use crate::error::GarrisonResult;
use crate::protocol::social::{SocialLoginProvider, SocialProvider, SocialUserInfo};
use async_trait::async_trait;

/// 测试用 Mock 社交登录 Provider，实现 `SocialLoginProvider` trait 的三个方法。
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
            provider: SocialProvider::Wechat,
            provider_user_id: "mock_openid".into(),
            nickname: None,
            avatar: None,
            union_id: Some("mock_unionid".into()),
            raw: serde_json::json!({"mock": true}),
        })
    }

    async fn get_user_info(&self, _access_token: &str) -> GarrisonResult<SocialUserInfo> {
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
