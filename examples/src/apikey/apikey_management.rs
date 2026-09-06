//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 管理示例：演示 ApiKeyHandler 的生成/校验/吊销/轮换全生命周期。
//!
//! 对应模块：`src/protocol/apikey/mod.rs`（feature: protocol-apikey）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin apikey_management --features protocol-apikey
//! ```

use async_trait::async_trait;
use garrison::dao::GarrisonDao;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::protocol::apikey::ApiKeyHandler;
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
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.data.lock().await.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        self.data
            .lock()
            .await
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(GarrisonError::Dao(format!("键不存在: {}", key)))
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.data.lock().await.remove(key);
        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        _ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            Ok(false)
        } else {
            data.insert(key.to_string(), value.to_string());
            Ok(true)
        }
    }

    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        if let Some(value) = data.remove(old_key) {
            data.insert(new_key.to_string(), value);
        }
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.data.lock().await.remove(key))
    }

    async fn incr(&self, key: &str, _ttl_seconds: u64) -> GarrisonResult<u64> {
        let mut data = self.data.lock().await;
        let val = data
            .get(key)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        data.insert(key.to_string(), val.to_string());
        Ok(val)
    }

    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        let mut data = self.data.lock().await;
        let val = data
            .get(key)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if val == 0 {
            return Ok(0);
        }
        let new_val = val - 1;
        data.insert(key.to_string(), new_val.to_string());
        Ok(new_val)
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        _ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let mut data = self.data.lock().await;
        let current = data.get(key).map(|s| s.as_str());
        if current == expected {
            data.insert(key.to_string(), new_value.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// 运行 API Key 管理示例。
///
/// 演示 ApiKeyHandler 的 generate / verify / revoke / rotate 全生命周期。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison API Key 管理示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 ApiKeyHandler
    // ----------------------------------------------------------------
    // Key 存储命名空间：garrison:apikey:<key>
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let handler = ApiKeyHandler::new(dao);
    println!("[1] ApiKeyHandler 构建完成\n");

    // ----------------------------------------------------------------
    // 2. generate 生成 API Key
    // ----------------------------------------------------------------
    let key = handler
        .generate("1001", vec!["read".to_string(), "write".to_string()], 3600)
        .await?;
    println!("[2] generate:");
    println!("    login_id = 1001");
    println!("    scopes   = [read, write]");
    println!("    timeout  = 3600s");
    println!("    key      = {}", key);
    println!(
        "    长度      = {} 字符（key_id.key_secret 双段，各 32 hex）\n",
        key.len()
    );
    // 双段格式：key_id.key_secret（各 32 hex，`.` 分隔）
    let (key_id, key_secret) = key.split_once('.').expect("应为双段格式");
    assert_eq!(key_id.len(), 32);
    assert_eq!(key_secret.len(), 32);
    assert!(key_id.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(key_secret.chars().all(|c| c.is_ascii_hexdigit()));

    // ----------------------------------------------------------------
    // 3. verify 校验 Key
    // ----------------------------------------------------------------
    let info = handler.verify(&key).await?;
    println!("[3] verify:");
    println!("    login_id  = {}", info.login_id);
    println!("    scopes    = {:?}", info.scopes);
    println!("    expire_at = {}（Unix 秒）", info.expire_at);
    println!("    revoked   = {}\n", info.revoked);
    assert_eq!(info.login_id, "1001");
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
        .generate("2002", vec!["admin".to_string()], 7200)
        .await?;
    println!("[5] rotate:");
    println!("    原 key = {}...", &key2[..16]);

    // 轮换：吊销旧 key + 生成新 key（保留 login_id/scopes/剩余 TTL）
    let new_key = handler.rotate(&key2).await?;
    println!("    新 key = {}...", &new_key[..16]);
    assert_ne!(key2, new_key);
    assert!(
        new_key.contains('.'),
        "新 key 应为 key_id.key_secret 双段格式"
    );

    // 旧 key 已被吊销
    let old_result = handler.verify(&key2).await;
    assert!(old_result.is_err());
    println!("    原 key verify → Err（已吊销）✓");

    // 新 key 有效，保留 login_id 和 scopes
    let new_info = handler.verify(&new_key).await?;
    assert_eq!(new_info.login_id, "2002");
    assert_eq!(new_info.scopes, vec!["admin".to_string()]);
    println!(
        "    新 key verify → login_id={}, scopes={:?}",
        new_info.login_id, new_info.scopes
    );
    println!("    ✓ login_id 与 scopes 已保留\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
