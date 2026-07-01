//! 认证逻辑示例：演示 AuthLogic trait 与 AuthLogicDefault 默认实现。
//!
//! 对应模块：`src/core/auth/mod.rs`（always on，无需 feature）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin auth_logic_impl --features full
//! ```

use async_trait::async_trait;
use bulwark::core::auth::{AuthLogic, AuthLogicDefault};
use bulwark::core::token::{Token, UuidTokenStyle};
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::session::BulwarkSession;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// 测试用 Mock DAO（模拟 oxcache 的存储行为，无 TTL 过期）
// ============================================================================

/// 内存 HashMap 实现的 DAO，用于示例演示。
///
/// 生产环境应使用 `BulwarkDaoOxcache`（cache-memory feature）或
/// `BulwarkDaoDbnexus`（db-sqlite feature）。
pub struct MockDao {
    data: Mutex<HashMap<String, String>>,
}

impl MockDao {
    /// 创建 MockDao 实例。
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockDao {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        Ok(self.data.lock().await.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
        self.data
            .lock()
            .await
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(BulwarkError::Dao(format!("键不存在: {}", key)))
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.data.lock().await.remove(key);
        Ok(())
    }
}

/// 运行认证逻辑示例。
///
/// 演示 AuthLogicDefault 的 login / is_login / get_login_id / verify_token / logout，
/// 以及 logout 的幂等语义。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 认证逻辑示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 AuthLogicDefault（注入 Session + Token 处理器）
    // ----------------------------------------------------------------
    // 注意：AuthLogicDefault 不依赖 task_local 上下文，所有方法以 token 为入参，
    // 便于 protocol-jwt 等协议层模块干净复用。
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    let auth = AuthLogicDefault::new(session, token_handler, 3600);
    println!("[1] AuthLogicDefault 构建完成（timeout=3600s, active_timeout=86400s）\n");

    // ----------------------------------------------------------------
    // 2. login：生成 token 并建立会话
    // ----------------------------------------------------------------
    let token = auth.login(1001, None).await?;
    println!("[2] login(1001):");
    println!("    token = {}", token);
    assert!(!token.is_empty());
    println!();

    // ----------------------------------------------------------------
    // 3. is_login / get_login_id / verify_token 校验
    // ----------------------------------------------------------------
    let logged_in = auth.is_login(&token).await?;
    println!("[3] is_login(\"{}\"):", &token[..8]);
    println!("    返回 = {}", logged_in);
    assert!(logged_in);

    let login_id = auth.get_login_id(&token).await?;
    println!("\n[4] get_login_id(\"{}\"):", &token[..8]);
    println!("    返回 = {:?}", login_id);
    assert_eq!(login_id, Some(1001));

    let verified_id = auth.verify_token(&token).await?;
    println!("\n[5] verify_token(\"{}\"):", &token[..8]);
    println!(
        "    返回 = {}（校验失败会抛 InvalidToken 错误）",
        verified_id
    );
    assert_eq!(verified_id, 1001);

    // 校验无效 token
    let invalid_result = auth.verify_token("invalid-token").await;
    assert!(invalid_result.is_err());
    println!("\n[6] verify_token(\"invalid-token\"):");
    println!("    返回错误（InvalidToken）✓\n");

    // ----------------------------------------------------------------
    // 4. logout：销毁会话（幂等）
    // ----------------------------------------------------------------
    auth.logout(&token).await?;
    println!("[7] logout(\"{}\"):", &token[..8]);
    println!("    完成");

    // logout 后 is_login 返回 false
    let after_logout = auth.is_login(&token).await?;
    assert!(!after_logout);
    println!(
        "\n[8] logout 后 is_login 返回 = {}（会话已销毁）",
        after_logout
    );

    // logout 幂等：再次 logout 不存在的 token 返回 Ok(())
    auth.logout(&token).await?;
    println!("[9] 再次 logout 同一 token：Ok(())（幂等语义）✓\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
