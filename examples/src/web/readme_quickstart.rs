// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! README 快速开始回归示例。
//!
//! 本文件的 `readme_flow()` 与 README.md「最小示例」代码**逐字对应**，
//! 由 [`crate::tests 旁的 examples/tests/readme_quickstart.rs`] 随 CI 运行，
//! 防止文档示例与实际 API 漂移。
//!
//! # 编译 / 运行
//!
//! ```bash
//! cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"
//! ```

use async_trait::async_trait;
use garrison::error::GarrisonResult;
use garrison::prelude::*;
use std::sync::Arc;

/// README「最小示例」的业务 Interface 实现（逐字对应）。
struct MyInterface;
#[async_trait]
impl GarrisonInterface for MyInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["user:read".into(), "user:write".into()])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["user".into()])
    }
}

/// 运行 README 快速开始完整流程（登录 → 校验登录 → 校验权限 → 登出）。
pub async fn run() -> GarrisonResult<()> {
    // tenant-isolation feature 启用（如 --features full）时需要租户上下文；
    // README 基础场景（development 聚合）不启用该 feature，直接执行。
    #[cfg(feature = "tenant-isolation")]
    {
        use garrison::context::tenant::{TenantContext, TenantSource, TENANT};
        let tenant = TenantContext {
            tenant_id: 0,
            resolved_from: TenantSource::Header,
        };
        TENANT.scope(tenant, readme_flow()).await
    }
    #[cfg(not(feature = "tenant-isolation"))]
    {
        readme_flow().await
    }
}

/// README.md「最小示例」代码（逐字对应，除包装为函数外无改动）。
async fn readme_flow() -> GarrisonResult<()> {
    // 2. 准备依赖
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);

    // 3. 初始化全局管理器
    GarrisonManager::builder()
        .dao(dao)
        .config(config)
        .interface(interface)
        .build()
        .await?;

    // 4. 在 task_local 上下文中执行登录
    let token = garrison::stp::with_current_token(
        String::new(),
        GarrisonUtil::login("1001", &LoginParams::default()),
    )
    .await?;
    println!("登录成功，token = {}", &token[..8.min(token.len())]);

    // 5. 校验登录状态
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::check_login()).await?;

    // 6. 校验权限（无权限时报错）
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::check_permission("user:read"))
        .await?;

    // 7. 登出
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::logout()).await?;

    Ok(())
}
