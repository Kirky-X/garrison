// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `SocialLoginService` 注册中心 —— 社交登录扩展点：运行时 provider 注册表，允许外部 crate 注册自定义 `SocialLoginProvider`（如华为 Account Kit）。
//!
//! # 设计
//!
//! - `HashMap<String, Arc<dyn SocialLoginProvider>>` + `parking_lot::RwLock` 存储 provider，提供 register/unregister/get/list CRUD API；
//! - 委托方法（`get_authorization_url` / `exchange_token` / `get_user_info`）按 name 查找并转发；
//! - 实现 `SocialProviderResolver` trait（cfg `account-authflow`），与 authflow executor 适配。
//!
//! # 扩展示例
//!
//! ```ignore
//! use garrison::protocol::social::{SocialLoginService, SocialLoginProvider};
//! use std::sync::Arc;
//!
//! let svc = SocialLoginService::new();
//! svc.register("wechat", Arc::new(garrison::WechatProvider::new("appid", "secret")))?;
//! svc.register("huawei", Arc::new(my_crate::HuaweiProvider::new("client_id", "client_secret")))?;
//!
//! let url = svc.get_authorization_url("huawei", "state", "https://example.com/cb").await?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(any(feature = "account-authflow", test))]
use async_trait::async_trait;

use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use crate::protocol::social::{SocialLoginProvider, SocialUserInfo};

/// 错误码：社交登录 provider 未注册。
///
/// 三个委托方法在 provider 未注册时返回 `InvalidParam(loc!(ERR_SOCIAL_PROVIDER_NOT_REGISTERED, ...))`；消费方（如 sinnan）用 `starts_with` 匹配，避免硬编码字符串契约。
pub const ERR_SOCIAL_PROVIDER_NOT_REGISTERED: &str = "social-provider-not-registered";

/// 错误码：社交登录 provider 名称格式非法（`register` 未通过 `is_valid_provider_name` 校验时返回）。
pub const ERR_SOCIAL_PROVIDER_NAME_INVALID: &str = "social-provider-name-invalid";

/// 社交登录注册中心：持有 `provider_name → Arc<dyn SocialLoginProvider>` 映射。
///
/// 内部 `parking_lot::RwLock<HashMap>` 支持并发读、互斥写（register/unregister 写锁，get/list/委托方法读锁）。
pub struct SocialLoginService {
    providers: parking_lot::RwLock<HashMap<String, Arc<dyn SocialLoginProvider>>>,
}

impl SocialLoginService {
    /// 创建空的 `SocialLoginService`。
    pub fn new() -> Self {
        Self {
            providers: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// 注册 provider（`name` 已存在时覆盖并返回被替换的 provider）。
    ///
    /// # 安全
    ///
    /// 在数据入口强制校验名称（防御编程 + 数据不变性原则），防恶意 name 造成 DAO key 注入（`:`）、日志注入（`\n`）、SQL 注入；格式非法返回 `GarrisonError::InvalidParam`（规则见 [`is_valid_provider_name`](crate::protocol::social::validation::is_valid_provider_name)）。
    pub fn register(
        &self,
        name: impl Into<String>,
        provider: Arc<dyn SocialLoginProvider>,
    ) -> GarrisonResult<Option<Arc<dyn SocialLoginProvider>>> {
        let name = name.into();
        if !crate::protocol::social::validation::is_valid_provider_name(&name) {
            return Err(GarrisonError::InvalidParam(loc!(
                ERR_SOCIAL_PROVIDER_NAME_INVALID,
                format!("invalid provider name: '{}'", name),
                ("provider", &name)
            )));
        }
        let mut map = self.providers.write();
        Ok(map.insert(name, provider))
    }

    /// 注销 provider，返回被移除者（`name` 不存在返回 `None`）。
    pub fn unregister(&self, name: &str) -> Option<Arc<dyn SocialLoginProvider>> {
        let mut map = self.providers.write();
        map.remove(name)
    }

    /// 查找 provider。
    pub fn get(&self, name: &str) -> Option<Arc<dyn SocialLoginProvider>> {
        let map = self.providers.read();
        map.get(name).cloned()
    }

    /// 列出所有已注册 provider 名称。
    pub fn list(&self) -> Vec<String> {
        let map = self.providers.read();
        map.keys().cloned().collect()
    }

    /// 拼接授权页 URL（按 name 查找 provider 并委托；未注册返回 `GarrisonError::InvalidParam`）。
    pub async fn get_authorization_url(
        &self,
        name: &str,
        state: &str,
        redirect_uri: &str,
    ) -> GarrisonResult<String> {
        let provider = self.get(name).ok_or_else(|| {
            GarrisonError::InvalidParam(loc!(
                ERR_SOCIAL_PROVIDER_NOT_REGISTERED,
                format!("social provider '{}' not registered", name),
                ("provider", name)
            ))
        })?;
        provider.get_authorization_url(state, redirect_uri).await
    }

    /// 用授权码换取用户信息（按 name 查找 provider 并委托；未注册返回 `InvalidParam`，其他错误由 provider 实现决定）。
    pub async fn exchange_token(
        &self,
        name: &str,
        code: &str,
        state: &str,
    ) -> GarrisonResult<SocialUserInfo> {
        let provider = self.get(name).ok_or_else(|| {
            GarrisonError::InvalidParam(loc!(
                ERR_SOCIAL_PROVIDER_NOT_REGISTERED,
                format!("social provider '{}' not registered", name),
                ("provider", name)
            ))
        })?;
        provider.exchange_token(code, state).await
    }

    /// 用 access_token 获取用户信息（按 name 查找 provider 并委托；未注册返回 `InvalidParam`，其他错误由 provider 实现决定）。
    pub async fn get_user_info(
        &self,
        name: &str,
        access_token: &str,
    ) -> GarrisonResult<SocialUserInfo> {
        let provider = self.get(name).ok_or_else(|| {
            GarrisonError::InvalidParam(loc!(
                ERR_SOCIAL_PROVIDER_NOT_REGISTERED,
                format!("social provider '{}' not registered", name),
                ("provider", name)
            ))
        })?;
        provider.get_user_info(access_token).await
    }
}

impl Default for SocialLoginService {
    fn default() -> Self {
        Self::new()
    }
}

/// `SocialProviderResolver` 实现（cfg `account-authflow`）：可直接作为 `AuthExecutor::execute_with_full` 的 `social_resolver` 参数，避免 sinnan 重复实现 resolver。
#[cfg(feature = "account-authflow")]
#[async_trait]
impl crate::account::authflow::executor::SocialProviderResolver for SocialLoginService {
    async fn resolve_login_id(
        &self,
        provider: &str,
        code: &str,
        state: &str,
    ) -> GarrisonResult<String> {
        let user = self.exchange_token(provider, code, state).await?;
        Ok(user.provider_user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 mock provider（独立于 `mock.rs`，避免 cfg(test) 跨模块依赖）。
    struct StubProvider {
        name: String,
    }

    #[async_trait]
    impl SocialLoginProvider for StubProvider {
        async fn get_authorization_url(
            &self,
            state: &str,
            redirect_uri: &str,
        ) -> GarrisonResult<String> {
            Ok(format!(
                "https://stub.example.com/auth?name={}&state={}&redirect={}",
                self.name, state, redirect_uri
            ))
        }

        async fn exchange_token(&self, code: &str, _state: &str) -> GarrisonResult<SocialUserInfo> {
            Ok(SocialUserInfo {
                provider: self.name.clone(),
                provider_user_id: format!("openid_{}", code),
                nickname: Some(format!("nick_{}", self.name)),
                avatar: None,
                union_id: None,
                raw: serde_json::json!({"code": code}),
            })
        }

        async fn get_user_info(&self, access_token: &str) -> GarrisonResult<SocialUserInfo> {
            Ok(SocialUserInfo {
                provider: self.name.clone(),
                provider_user_id: format!("openid_{}", access_token),
                nickname: Some(format!("nick_{}", self.name)),
                avatar: Some(format!("https://img.example.com/{}.png", self.name)),
                union_id: None,
                raw: serde_json::json!({"token": access_token}),
            })
        }
    }

    fn make_stub(name: &str) -> Arc<dyn SocialLoginProvider> {
        Arc::new(StubProvider {
            name: name.to_string(),
        })
    }

    // register / get / unregister / list 测试

    #[test]
    fn register_stores_provider_and_get_returns_it() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let provider = svc.get("wechat");
        assert!(provider.is_some(), "register 后 get 应返回 Some");
    }

    #[test]
    fn register_returns_previous_provider_when_overwriting() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let previous = svc.register("wechat", make_stub("wechat_v2")).unwrap();
        assert!(
            previous.is_some(),
            "重复 register 同名应返回被替换的旧 provider"
        );
    }

    #[test]
    fn register_rejects_invalid_provider_name() {
        let svc = SocialLoginService::new();

        let result = svc.register("a:b", make_stub("bad"));
        assert!(result.is_err(), "含冒号的 provider name 应拒绝");

        let result = svc.register("WeChat", make_stub("bad"));
        assert!(result.is_err(), "大写字母 provider name 应拒绝");

        let result = svc.register("", make_stub("bad"));
        assert!(result.is_err(), "空字符串 provider name 应拒绝");

        let result = svc.register("a\nb", make_stub("bad"));
        assert!(result.is_err(), "含换行符的 provider name 应拒绝");

        assert!(svc.list().is_empty(), "非法 name 不应被写入注册表");
    }

    #[test]
    fn get_unregistered_returns_none() {
        let svc = SocialLoginService::new();
        assert!(svc.get("huawei").is_none(), "未注册 provider 应返回 None");
    }

    #[test]
    fn unregister_removes_provider_and_returns_it() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let removed = svc.unregister("wechat");
        assert!(removed.is_some(), "unregister 已注册 provider 应返回 Some");
        assert!(svc.get("wechat").is_none(), "unregister 后 get 应返回 None");
    }

    #[test]
    fn unregister_unregistered_returns_none() {
        let svc = SocialLoginService::new();
        assert!(
            svc.unregister("huawei").is_none(),
            "unregister 未注册 provider 应返回 None"
        );
    }

    #[test]
    fn list_returns_all_registered_names() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();
        svc.register("huawei", make_stub("huawei")).unwrap();
        svc.register("alipay", make_stub("alipay")).unwrap();

        let mut names = svc.list();
        names.sort();
        assert_eq!(names, vec!["alipay", "huawei", "wechat"]);
    }

    #[test]
    fn list_empty_when_no_providers_registered() {
        let svc = SocialLoginService::new();
        assert!(svc.list().is_empty(), "未注册任何 provider 时 list 应为空");
    }

    // 委托方法测试（get_authorization_url / exchange_token / get_user_info）

    #[tokio::test]
    async fn get_authorization_url_delegates_to_registered_provider() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let url = svc
            .get_authorization_url("wechat", "state123", "https://cb.example.com")
            .await
            .expect("已注册 provider 的 get_authorization_url 应返回 Ok");

        assert!(url.contains("name=wechat"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("redirect=https://cb.example.com"));
    }

    #[tokio::test]
    async fn get_authorization_url_returns_error_for_unregistered() {
        let svc = SocialLoginService::new();
        let result = svc.get_authorization_url("huawei", "s", "r").await;
        assert!(result.is_err(), "未注册 provider 应返回 Err");
        match result {
            Err(GarrisonError::InvalidParam(_)) => {},
            Err(other) => panic!("期望 InvalidParam，实际: {:?}", other),
            Ok(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn exchange_token_delegates_to_registered_provider() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let user = svc
            .exchange_token("wechat", "code456", "state")
            .await
            .expect("exchange_token 应返回 Ok");

        assert_eq!(user.provider, "wechat");
        assert_eq!(user.provider_user_id, "openid_code456");
        assert_eq!(user.nickname.as_deref(), Some("nick_wechat"));
    }

    #[tokio::test]
    async fn exchange_token_returns_error_for_unregistered() {
        let svc = SocialLoginService::new();
        let result = svc.exchange_token("huawei", "code", "state").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_user_info_delegates_to_registered_provider() {
        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let user = svc
            .get_user_info("wechat", "tok789")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user.provider, "wechat");
        assert_eq!(user.provider_user_id, "openid_tok789");
        assert_eq!(
            user.avatar.as_deref(),
            Some("https://img.example.com/wechat.png")
        );
    }

    #[tokio::test]
    async fn get_user_info_returns_error_for_unregistered() {
        let svc = SocialLoginService::new();
        let result = svc.get_user_info("huawei", "tok").await;
        assert!(result.is_err());
    }

    // 并发安全测试（parking_lot::RwLock）

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_register_and_get_is_safe() {
        let svc = Arc::new(SocialLoginService::new());
        let mut handles = vec![];

        for i in 0..10 {
            let svc_clone = svc.clone();
            handles.push(tokio::spawn(async move {
                svc_clone
                    .register(format!("p{}", i), make_stub(&format!("p{}", i)))
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let mut names = svc.list();
        names.sort();
        assert_eq!(names.len(), 10);
        for i in 0..10 {
            assert!(svc.get(&format!("p{}", i)).is_some());
        }
    }

    // Default trait 测试

    #[test]
    fn default_creates_empty_service() {
        let svc = SocialLoginService::default();
        assert!(svc.list().is_empty());
    }

    // SocialProviderResolver 实现（cfg account-authflow）

    #[cfg(feature = "account-authflow")]
    #[tokio::test]
    async fn resolve_login_id_returns_provider_user_id() {
        use crate::account::authflow::executor::SocialProviderResolver;

        let svc = SocialLoginService::new();
        svc.register("wechat", make_stub("wechat")).unwrap();

        let login_id = svc
            .resolve_login_id("wechat", "code789", "state")
            .await
            .expect("resolve_login_id 应返回 Ok");
        assert_eq!(login_id, "openid_code789");
    }

    #[cfg(feature = "account-authflow")]
    #[tokio::test]
    async fn resolve_login_id_returns_error_for_unregistered() {
        use crate::account::authflow::executor::SocialProviderResolver;

        let svc = SocialLoginService::new();
        let result = svc.resolve_login_id("huawei", "code", "state").await;
        assert!(result.is_err());
    }
}
