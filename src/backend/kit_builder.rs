// Copyright (c) 2026 Kirky.X
// SPDX-License-Identifier: MIT

//! trait-kit AsyncKit 构建器集成（feature = "backend-kit"）。
//!
//! 用 typestate DI 构建 `BulwarkAuthServer` 初始化路径。
//! `BackendModule` 实现 `AsyncAutoBuilder`，`Capability = Arc<dyn AuthBackend>`。

#![cfg(feature = "backend-kit")]

use crate::backend::{AuthBackend, BackendEmbedded};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use trait_kit::core::{AsyncAutoBuilder, ModuleMeta};
use trait_kit::kit::AsyncKit;

/// trait-kit 错误类型（包装 BulwarkError）。
#[derive(Debug, thiserror::Error)]
pub enum BackendKitError {
    /// 后端构建失败。
    #[error("backend build failed: {0}")]
    BuildFailed(String),
}

/// BackendEmbedded 的 trait-kit 模块定义。
///
/// 实现 `AsyncAutoBuilder`，`Capability = Arc<dyn AuthBackend>`。
/// `build()` 创建 `BackendEmbedded::new()` 并转为 `Arc<dyn AuthBackend>`。
pub struct BackendModule;

impl ModuleMeta for BackendModule {
    const NAME: &'static str = "backend-embedded";

    fn dependencies() -> &'static [(&'static str, std::any::TypeId)] {
        &[]
    }
}

impl AsyncAutoBuilder for BackendModule {
    type Capability = Arc<dyn AuthBackend>;
    type Error = BackendKitError;

    fn build<'a>(
        _kit: &'a AsyncKit,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Capability, Self::Error>> + Send + 'a>> {
        Box::pin(async move {
            // BackendEmbedded 是零字段 struct，new() 无参数
            // 未来可从 kit.config() 读取配置注入依赖
            let backend = BackendEmbedded::new();
            Ok(Arc::new(backend) as Arc<dyn AuthBackend>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trait_kit::kit::AsyncKit;

    /// 测试 AsyncKit 构建 BackendModule 成功。
    #[tokio::test]
    async fn test_kit_builds_backend_module() {
        let mut kit = AsyncKit::new();
        kit.register::<BackendModule>()
            .expect("register BackendModule failed");
        let kit = kit.build().await.expect("kit build failed");
        let backend: Arc<dyn AuthBackend> = kit
            .require::<BackendModule>()
            .expect("require BackendModule failed");
        // 验证 backend 已构建（Arc<dyn AuthBackend> 非空）
        let _ = backend;
    }

    /// 测试 BackendModule::NAME 正确。
    #[test]
    fn test_backend_module_name() {
        assert_eq!(BackendModule::NAME, "backend-embedded");
    }

    /// 测试 BackendModule 无依赖。
    #[test]
    fn test_backend_module_no_dependencies() {
        assert!(BackendModule::dependencies().is_empty());
    }

    /// 测试 AsyncKit 重复注册同一模块返回错误。
    #[tokio::test]
    async fn test_duplicate_registration_fails() {
        let mut kit = AsyncKit::new();
        kit.register::<BackendModule>().unwrap();
        let result = kit.register::<BackendModule>();
        assert!(result.is_err(), "重复注册应返回错误");
    }

    /// 测试 require 未构建模块返回错误。
    #[tokio::test]
    async fn test_require_unbuilt_module_fails() {
        let kit = AsyncKit::new();
        let built = kit.build().await.expect("empty build should succeed");
        let result: Result<Arc<dyn AuthBackend>, _> = built.require::<BackendModule>();
        assert!(result.is_err(), "require 未构建模块应返回错误");
    }

    /// 测试 BackendKitError Display 实现。
    #[test]
    fn test_backend_kit_error_display() {
        let err = BackendKitError::BuildFailed("test reason".to_string());
        assert_eq!(err.to_string(), "backend build failed: test reason");
    }

    /// 测试 build 产出的 backend 可作为 Arc<dyn AuthBackend> 使用。
    #[tokio::test]
    async fn test_built_backend_is_dyn_auth_backend() {
        let mut kit = AsyncKit::new();
        kit.register::<BackendModule>().expect("register failed");
        let kit = kit.build().await.expect("build failed");
        let backend: Arc<dyn AuthBackend> = kit.require::<BackendModule>().expect("require failed");
        // 验证 trait object 可调用（check_login 会因未初始化 BulwarkManager 返回错误，
        // 但这证明了 Arc<dyn AuthBackend> 已成功构建且可分发）
        let _ = backend.check_login("any-token").await;
    }
}
