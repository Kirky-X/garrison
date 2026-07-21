//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 临时凭证示例：演示 TempCredentialHandler 的签发/读取/撤销/消费。
//!
//! 对应模块：`src/protocol/temp/mod.rs`（feature: protocol-temp）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin temp_credential --features protocol-temp
//! ```

use async_trait::async_trait;
use garrison::dao::GarrisonDao;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::protocol::temp::TempCredentialHandler;
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
}

/// 运行临时凭证示例。
///
/// 演示 TempCredentialHandler 的 issue / get / consume / revoke 与参数校验。
/// 适用场景：邀请码、密码重置链接、邮箱验证码等短时一次性凭证。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 临时凭证示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 TempCredentialHandler
    // ----------------------------------------------------------------
    // Key 命名空间：garrison:temp:<prefix>:<random>
    // prefix 用于区分业务场景（如 invite / reset / verify），不可包含 ':'
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let handler = TempCredentialHandler::new(dao);
    println!("[1] TempCredentialHandler 构建完成\n");

    // ----------------------------------------------------------------
    // 2. issue 签发临时凭据
    // ----------------------------------------------------------------
    // 场景：生成邀请码，载荷为用户 ID，TTL 600 秒
    let invite_key = handler.issue("invite", "user-id-1001", 600).await?;
    println!("[2] issue（邀请码场景）:");
    println!("    prefix = \"invite\"");
    println!("    value  = \"user-id-1001\"");
    println!("    ttl    = 600s");
    println!("    key    = {}", invite_key);
    assert!(invite_key.starts_with("garrison:temp:invite:"));
    println!("    ✓ 前缀匹配 garrison:temp:invite:\n");

    // 场景：生成密码重置链接凭证，TTL 300 秒
    let reset_key = handler.issue("reset", "reset-token-xyz", 300).await?;
    println!("    reset key = {}...", &reset_key[..24]);
    assert!(reset_key.starts_with("garrison:temp:reset:"));
    println!("    ✓ 不同 prefix 产生不同命名空间\n");

    // ----------------------------------------------------------------
    // 3. get 读取凭据（不删除，可多次读取）
    // ----------------------------------------------------------------
    let v1 = handler.get(&invite_key).await?;
    let v2 = handler.get(&invite_key).await?;
    println!("[3] get（多次读取不删除）:");
    println!("    第一次读取 = {:?}", v1);
    println!("    第二次读取 = {:?}", v2);
    assert_eq!(v1, Some("user-id-1001".to_string()));
    assert_eq!(v2, Some("user-id-1001".to_string()));
    println!("    ✓ 两次读取结果一致\n");

    // ----------------------------------------------------------------
    // 4. consume 消费凭据（一次性，读后即删）
    // ----------------------------------------------------------------
    let consumed = handler.consume(&invite_key).await?;
    let again = handler.consume(&invite_key).await?;
    println!("[4] consume（一次性消费）:");
    println!("    第一次消费 = {:?}", consumed);
    println!("    第二次消费 = {:?}", again);
    assert_eq!(consumed, Some("user-id-1001".to_string()));
    assert_eq!(again, None);
    println!("    ✓ 第一次返回值，第二次返回 None（已删除）\n");

    // ----------------------------------------------------------------
    // 5. revoke 撤销凭据（幂等）
    // ----------------------------------------------------------------
    // 先签发一个新凭据
    let verify_key = handler.issue("verify", "email-code-123456", 60).await?;
    println!("[5] revoke（撤销，幂等）:");
    println!("    签发 key = {}...", &verify_key[..24]);

    // 撤销存在的凭据
    handler.revoke(&verify_key).await?;
    let after_revoke = handler.get(&verify_key).await?;
    assert_eq!(after_revoke, None);
    println!("    撤销后 get → None ✓");

    // 撤销不存在的凭据（幂等，返回 Ok）
    handler.revoke(&verify_key).await?;
    handler.revoke("garrison:temp:invite:nonexistent").await?;
    println!("    撤销不存在的凭据 → Ok(())（幂等语义）✓\n");

    // ----------------------------------------------------------------
    // 6. 参数校验
    // ----------------------------------------------------------------
    println!("[6] 参数校验:");
    // prefix 包含 ':' → InvalidParam
    let bad_prefix = handler.issue("inv:ite", "data", 60).await;
    assert!(bad_prefix.is_err());
    println!("    prefix 含 ':' → Err(InvalidParam) ✓");

    // ttl_seconds <= 0 → InvalidParam
    let bad_ttl = handler.issue("invite", "data", 0).await;
    assert!(bad_ttl.is_err());
    println!("    ttl_seconds=0 → Err(InvalidParam) ✓");

    // value 为空字符串允许存储
    let empty_key = handler.issue("invite", "", 60).await?;
    let empty_val = handler.get(&empty_key).await?;
    assert_eq!(empty_val, Some("".to_string()));
    println!("    value=\"\"（空字符串）→ 允许存储 ✓\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
