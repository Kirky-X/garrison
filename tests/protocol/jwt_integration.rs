//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JWT 协议端到端集成测试：login → verify_token → refresh_token → check_login → logout。
//!
//! 验证 `GarrisonManager` + `GarrisonLogicDefault`（token_style=jwt）的完整 JWT 生命周期：
//! 1. `GarrisonUtil::login` 生成 JWT 并写入会话
//! 2. `GarrisonUtil::verify_token` 校验 JWT 并返回 login_id
//! 3. `GarrisonUtil::refresh_token` 刷新 JWT
//! 4. `GarrisonUtil::check_login`（task_local 上下文内）校验登录状态
//! 5. `GarrisonUtil::logout` 销毁会话
//!
//! 依据 spec protocol-jwt + core-auth-api。
//!
//! # NEEDS CLARIFICATION: 无产品 GarrisonInterface 实现
//!
//! `GarrisonManager::builder().interface(...)` 是必需的依赖注入点，但 garrison
//! 仓库内基于 Dao 的 `GarrisonInterface` **只有 `#[cfg(test)]` mock 实现**，
//! 无产品实现（trait 设计为业务方回调）。按 production-mock-purge 规则
//! "不发明生产代码"，此处保留本地 `MockInterface`（返回空权限/角色列表）
//! 并明确标注，等待用户裁定（见报告 NEEDS CLARIFICATION #1）。

#![cfg(feature = "protocol-jwt")]
// jwt_secret 的 `.into()` 是跨 feature 兼容的必要转换：protocol-zeroize 下字段
// 类型为 Zeroizing<String>，feature 关闭时退化为 String，被 clippy 误报。
#![allow(clippy::useless_conversion)]

use async_trait::async_trait;
use garrison::config::GarrisonConfig;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::GarrisonResult;
use garrison::manager::GarrisonManager;
use garrison::stp::{with_current_token, GarrisonInterface, GarrisonUtil};
use serial_test::serial;
use std::sync::Arc;

// ============================================================================
// MockInterface（权限/角色数据回调）
// ============================================================================
// NEEDS CLARIFICATION: 无产品 GarrisonInterface 实现，保留本地 mock（见文件头说明）。

struct MockInterface;

#[async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 初始化 GarrisonManager（token_style=jwt，jwt_secret ≥ 32 字节）。
///
/// DAO 使用产品内存实现 `InMemoryDao`（garrison::dao::InMemoryDao）。
async fn init_jwt_manager() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    // ≥32 字节，满足 HS256 jwt_secret 最小长度校验
    config.jwt_secret = "test-secret-key-0123456789abcdef".to_string().into();
    config.timeout = 3600;
    config.throw_on_not_login = false;
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface);
    GarrisonManager::builder()
        .dao(dao)
        .config(config)
        .interface(interface)
        .build()
        .await
        .unwrap();
}

// ============================================================================
// 集成测试
// ============================================================================

/// 端到端 JWT 流程：login → verify_token → refresh_token → check_login → logout。
#[tokio::test]
#[serial]
async fn jwt_end_to_end_login_verify_refresh_logout() {
    init_jwt_manager().await;

    // 1. 登录：生成 JWT token 并写入会话
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty(), "login 应返回非空 token");
    assert!(token.contains('.'), "JWT 应为三段式（含 .）：{}", token);
    println!("[登录] token={}", &token[..40.min(token.len())]);

    // 2. verify_token：校验 JWT 并返回 login_id
    let login_id = GarrisonUtil::verify_token(&token).await.unwrap();
    assert_eq!(
        login_id,
        "1001".to_string(),
        "verify_token 应返回原 login_id"
    );
    println!("[校验] login_id={}", login_id);

    // 3. refresh_token：刷新 JWT（生成新 token）
    //    注意：JWT 内容由 (login_id, iat, exp, device, secret) 决定，
    //    若同一秒内签发，refresh 可能返回相同字符串（iat/exp 相同）。
    //    此处仅验证 refresh 产出的 token 仍可校验通过且 login_id 一致。
    let new_token = GarrisonUtil::refresh_token(&token).await.unwrap();
    let new_login_id = GarrisonUtil::verify_token(&new_token).await.unwrap();
    assert_eq!(
        new_login_id,
        "1001".to_string(),
        "新 token 的 login_id 应一致"
    );
    println!("[刷新] 新 token 已校验通过");

    // 4. check_login：在 task_local 上下文内校验登录状态
    let logged_in = with_current_token(token.clone(), async {
        GarrisonUtil::check_login().await.unwrap()
    })
    .await;
    assert!(logged_in, "登录后 check_login 应返回 true");
    println!("[校验登录] check_login=true");

    // 5. logout：销毁会话
    with_current_token(token.clone(), async {
        GarrisonUtil::logout().await.unwrap()
    })
    .await;
    println!("[登出] 会话已销毁");

    // 6. logout 后 check_login 应返回 false
    let logged_in_after = with_current_token(token.clone(), async {
        GarrisonUtil::check_login().await.unwrap()
    })
    .await;
    assert!(!logged_in_after, "logout 后 check_login 应返回 false");
    println!("[校验登出] check_login=false");
}

/// verify_token 对无效 JWT 返回 InvalidToken。
#[tokio::test]
#[serial]
async fn verify_token_rejects_invalid_jwt() {
    init_jwt_manager().await;

    let result = GarrisonUtil::verify_token("not.a.valid.jwt").await;
    assert!(result.is_err(), "无效 JWT 应校验失败");
    println!("[异常] 无效 JWT 被拒绝：{:?}", result.err());
}

/// verify_token 对空字符串返回错误。
#[tokio::test]
#[serial]
async fn verify_token_rejects_empty_string() {
    init_jwt_manager().await;

    let result = GarrisonUtil::verify_token("").await;
    assert!(result.is_err(), "空 token 应校验失败");
}

/// refresh_token 对无效 token 返回错误。
#[tokio::test]
#[serial]
async fn refresh_token_rejects_invalid_token() {
    init_jwt_manager().await;

    let result = GarrisonUtil::refresh_token("invalid-token").await;
    assert!(result.is_err(), "无效 token 刷新应失败");
}
