//! API Key 管理示例：演示 ApiKeyHandler 的生成/校验/吊销/轮换全生命周期。
//!
//! 对应模块：`src/protocol/apikey/mod.rs`（feature: protocol-apikey）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin apikey_management --features protocol-apikey
//! ```

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::apikey::ApiKeyHandler;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// 测试用 Mock DAO
// ============================================================================

struct MockDao {
    data: Mutex<HashMap<String, String>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
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

/// 运行 API Key 管理示例。
///
/// 演示 ApiKeyHandler 的 generate / verify / revoke / rotate 全生命周期。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark API Key 管理示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 ApiKeyHandler
    // ----------------------------------------------------------------
    // Key 存储命名空间：bulwark:apikey:<key>
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao);
    println!("[1] ApiKeyHandler 构建完成\n");

    // ----------------------------------------------------------------
    // 2. generate 生成 API Key
    // ----------------------------------------------------------------
    let key = handler
        .generate(1001, vec!["read".to_string(), "write".to_string()], 3600)
        .await?;
    println!("[2] generate:");
    println!("    login_id = 1001");
    println!("    scopes   = [read, write]");
    println!("    timeout  = 3600s");
    println!("    key      = {}", key);
    println!("    长度      = {} 字符（64 hex）\n", key.len());
    assert_eq!(key.len(), 64);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));

    // ----------------------------------------------------------------
    // 3. verify 校验 Key
    // ----------------------------------------------------------------
    let info = handler.verify(&key).await?;
    println!("[3] verify:");
    println!("    login_id  = {}", info.login_id);
    println!("    scopes    = {:?}", info.scopes);
    println!("    expire_at = {}（Unix 秒）", info.expire_at);
    println!("    revoked   = {}\n", info.revoked);
    assert_eq!(info.login_id, 1001);
    assert!(!info.revoked);

    // 校验不存在的 Key
    let invalid = handler.verify("nonexistent-key").await;
    assert!(invalid.is_err());
    println!("    verify(\"nonexistent-key\") → Err(InvalidToken) ✓\n");

    // ----------------------------------------------------------------
    // 4. revoke 吊销 Key
    // ----------------------------------------------------------------
    handler.revoke(&key).await?;
    println!("[4] revoke:");
    println!("    吊销 key = {}...", &key[..16]);
    // 吊销后 verify 失败
    let revoked = handler.verify(&key).await;
    assert!(revoked.is_err());
    println!("    吊销后 verify → Err(InvalidToken) ✓\n");

    // ----------------------------------------------------------------
    // 5. rotate 轮换 Key（保留 login_id/scopes/剩余 TTL）
    // ----------------------------------------------------------------
    // 先生成一个新的有效 key
    let key2 = handler
        .generate(2002, vec!["admin".to_string()], 7200)
        .await?;
    println!("[5] rotate:");
    println!("    原 key = {}...", &key2[..16]);

    // 轮换：吊销旧 key + 生成新 key（保留 login_id/scopes/剩余 TTL）
    let new_key = handler.rotate(&key2).await?;
    println!("    新 key = {}...", &new_key[..16]);
    assert_ne!(key2, new_key);
    assert_eq!(new_key.len(), 64);

    // 旧 key 已被吊销
    let old_result = handler.verify(&key2).await;
    assert!(old_result.is_err());
    println!("    原 key verify → Err（已吊销）✓");

    // 新 key 有效，保留 login_id 和 scopes
    let new_info = handler.verify(&new_key).await?;
    assert_eq!(new_info.login_id, 2002);
    assert_eq!(new_info.scopes, vec!["admin".to_string()]);
    println!(
        "    新 key verify → login_id={}, scopes={:?}",
        new_info.login_id, new_info.scopes
    );
    println!("    ✓ login_id 与 scopes 已保留\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
