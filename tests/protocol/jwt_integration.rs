//! JWT 协议端到端集成测试：login → verify_token → refresh_token → check_login → logout。
//!
//! 验证 `BulwarkManager` + `BulwarkLogicDefault`（token_style=jwt）的完整 JWT 生命周期：
//! 1. `BulwarkUtil::login` 生成 JWT 并写入会话
//! 2. `BulwarkUtil::verify_token` 校验 JWT 并返回 login_id
//! 3. `BulwarkUtil::refresh_token` 刷新 JWT
//! 4. `BulwarkUtil::check_login`（task_local 上下文内）校验登录状态
//! 5. `BulwarkUtil::logout` 销毁会话
//!
//! 依据 spec protocol-jwt + core-auth-api。

#![cfg(feature = "protocol-jwt")]

use async_trait::async_trait;
use bulwark::config::BulwarkConfig;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkUtil};
use parking_lot::Mutex;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// MockDao（HashMap + Instant 模拟 TTL）
// ============================================================================

struct MockDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        let mut store = self.store.lock();
        match store.get(key) {
            Some((value, expire_at)) => {
                if let Some(deadline) = expire_at {
                    if Instant::now() >= *deadline {
                        store.remove(key);
                        return Ok(None);
                    }
                }
                Ok(Some(value.clone()))
            },
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
        let expire_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), expire_at));
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((_, expire_at)) => {
                *expire_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
}

// ============================================================================
// MockInterface（权限/角色数据回调）
// ============================================================================

struct MockInterface;

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 初始化 BulwarkManager（token_style=jwt，jwt_secret=test-secret）。
fn init_jwt_manager() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "test-secret-key".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = false;
    let config = Arc::new(config);
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, config, interface).unwrap();
}

// ============================================================================
// 集成测试
// ============================================================================

/// 端到端 JWT 流程：login → verify_token → refresh_token → check_login → logout。
#[tokio::test]
#[serial]
async fn jwt_end_to_end_login_verify_refresh_logout() {
    init_jwt_manager();

    // 1. 登录：生成 JWT token 并写入会话
    let token = BulwarkUtil::login("1001").await.unwrap();
    assert!(!token.is_empty(), "login 应返回非空 token");
    assert!(token.contains('.'), "JWT 应为三段式（含 .）：{}", token);
    println!("[登录] token={}", &token[..40.min(token.len())]);

    // 2. verify_token：校验 JWT 并返回 login_id
    let login_id = BulwarkUtil::verify_token(&token).await.unwrap();
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
    let new_token = BulwarkUtil::refresh_token(&token).await.unwrap();
    let new_login_id = BulwarkUtil::verify_token(&new_token).await.unwrap();
    assert_eq!(
        new_login_id,
        "1001".to_string(),
        "新 token 的 login_id 应一致"
    );
    println!("[刷新] 新 token 已校验通过");

    // 4. check_login：在 task_local 上下文内校验登录状态
    let logged_in = with_current_token(token.clone(), async {
        BulwarkUtil::check_login().await.unwrap()
    })
    .await;
    assert!(logged_in, "登录后 check_login 应返回 true");
    println!("[校验登录] check_login=true");

    // 5. logout：销毁会话
    with_current_token(token.clone(), async {
        BulwarkUtil::logout().await.unwrap()
    })
    .await;
    println!("[登出] 会话已销毁");

    // 6. logout 后 check_login 应返回 false
    let logged_in_after = with_current_token(token.clone(), async {
        BulwarkUtil::check_login().await.unwrap()
    })
    .await;
    assert!(!logged_in_after, "logout 后 check_login 应返回 false");
    println!("[校验登出] check_login=false");
}

/// verify_token 对无效 JWT 返回 InvalidToken。
#[tokio::test]
#[serial]
async fn verify_token_rejects_invalid_jwt() {
    init_jwt_manager();

    let result = BulwarkUtil::verify_token("not.a.valid.jwt").await;
    assert!(result.is_err(), "无效 JWT 应校验失败");
    println!("[异常] 无效 JWT 被拒绝：{:?}", result.err());
}

/// verify_token 对空字符串返回错误。
#[tokio::test]
#[serial]
async fn verify_token_rejects_empty_string() {
    init_jwt_manager();

    let result = BulwarkUtil::verify_token("").await;
    assert!(result.is_err(), "空 token 应校验失败");
}

/// refresh_token 对无效 token 返回错误。
#[tokio::test]
#[serial]
async fn refresh_token_rejects_invalid_token() {
    init_jwt_manager();

    let result = BulwarkUtil::refresh_token("invalid-token").await;
    assert!(result.is_err(), "无效 token 刷新应失败");
}
