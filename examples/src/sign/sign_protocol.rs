//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 签名协议示例：演示 SignHandler 的签名生成与校验（含防重放）。
//!
//! 对应模块：`src/protocol/sign/mod.rs`（feature: protocol-sign）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin sign_protocol --features protocol-sign
//! ```

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::sign::SignHandler;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

// ============================================================================
// 测试用 Mock DAO（用于存储 nonce，防重放）
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

/// 获取当前 Unix 时间戳（秒）。
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 运行 API 签名协议示例。
///
/// 演示 SignHandler 的 sign 生成签名、validate 校验签名（时间戳窗口 + nonce 防重放）、
/// nonce 重放被拒绝、签名不匹配被拒绝、时间戳超出窗口被拒绝。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark API 签名协议示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 SignHandler
    // ----------------------------------------------------------------
    // 签名算法：
    //   sign = base64(hmac_sha256(hkdf_key, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"))
    //   其中 hkdf_key = HKDF-SHA256(app_secret, salt=app_key, info="bulwark-sign-v2")
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    // app_secret 最小 32 字节（256 位）
    let handler = SignHandler::new("app-001", "my-secret-key-with-at-least-32-bytes!", dao)?
        .with_timestamp_window(300); // 默认 300 秒时间戳窗口
    println!("[1] SignHandler 构建完成");
    println!("    app_key          = {}", handler.app_key());
    println!("    timestamp_window = {}s\n", handler.timestamp_window());

    // ----------------------------------------------------------------
    // 2. sign 生成签名
    // ----------------------------------------------------------------
    let method = "POST";
    let path = "/api/v1/users";
    let timestamp = now_ts();
    let nonce = "nonce-abc-123";
    let body_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // 空请求体的 SHA-256

    let signature = handler.sign(method, path, timestamp, nonce, body_sha256);
    println!("[2] sign 生成签名:");
    println!("    method      = {}", method);
    println!("    path        = {}", path);
    println!("    timestamp   = {}", timestamp);
    println!("    nonce       = {}", nonce);
    println!("    body_sha256 = {}", body_sha256);
    println!(
        "    signature   = {}（Base64 编码的 HMAC-SHA256，HKDF 派生密钥）\n",
        signature
    );
    assert_eq!(signature.len(), 44); // 32 字节 → 44 字符 Base64（含 padding）

    // ----------------------------------------------------------------
    // 3. validate 校验签名（成功）
    // ----------------------------------------------------------------
    let result = handler
        .validate(method, path, timestamp, nonce, body_sha256, &signature)
        .await;
    println!("[3] validate 校验:");
    assert!(result.is_ok());
    println!("    结果 = Ok(())（签名匹配 + 时间戳在窗口内 + nonce 未使用）✓\n");

    // ----------------------------------------------------------------
    // 4. nonce 重放被拒绝
    // ----------------------------------------------------------------
    // 同一 nonce 再次校验 → InvalidToken 错误
    let replay = handler
        .validate(method, path, timestamp, nonce, body_sha256, &signature)
        .await;
    println!("[4] nonce 防重放:");
    match replay {
        Err(BulwarkError::InvalidToken(msg)) => {
            println!("    第二次校验同一 nonce → Err(InvalidToken)");
            println!("    消息: {}\n", msg);
        },
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }

    // ----------------------------------------------------------------
    // 5. 签名不匹配被拒绝
    // ----------------------------------------------------------------
    let forged = handler
        .validate(
            method,
            path,
            timestamp,
            "nonce-new",
            body_sha256,
            "forged-signature",
        )
        .await;
    println!("[5] 签名不匹配:");
    assert!(forged.is_err());
    println!("    伪造签名 → 被拒绝 ✓\n");

    // ----------------------------------------------------------------
    // 6. 时间戳超出窗口被拒绝
    // ----------------------------------------------------------------
    let old_ts = now_ts() - 600; // 超过 300 秒窗口
    let old_sig = handler.sign(method, path, old_ts, "nonce-old", body_sha256);
    let expired = handler
        .validate(method, path, old_ts, "nonce-old", body_sha256, &old_sig)
        .await;
    println!("[6] 时间戳超出窗口:");
    match expired {
        Err(BulwarkError::ExpiredToken(msg)) => {
            println!("    timestamp = {}（超出 ±300s 窗口）", old_ts);
            println!("    → Err(ExpiredToken): {}\n", msg);
        },
        other => panic!("期望 ExpiredToken，实际: {:?}", other),
    }

    println!("=== 示例执行完成 ===");
    Ok(())
}
