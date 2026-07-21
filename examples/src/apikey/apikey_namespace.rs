//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 多租户命名空间示例（v0.4.2 新增，依据 spec protocol-apikey-namespace）。
//!
//! 演示 `ApiKeyHandler` 的多租户命名空间 API：
//! - `generate_with_namespace`：在指定 namespace 下生成 key
//! - `verify_with_namespace`：严格 namespace 校验（不跨 namespace）
//! - `list_by_namespace`：列出 namespace 下所有未吊销 key
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin apikey_namespace --features "protocol-apikey cache-memory"
//! ```

use async_trait::async_trait;
use garrison::dao::GarrisonDao;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::protocol::apikey::ApiKeyHandler;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 内存 MockDao，支持 keys(pattern) 用于 namespace 扫描。
struct InMemoryDao {
    data: Mutex<HashMap<String, String>>,
}

impl InMemoryDao {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for InMemoryDao {
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

    /// 支持 namespace 扫描（pattern 为 glob，如 `garrison:apikey:tenant-A:*`）。
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let data = self.data.lock().await;
        let mut result = Vec::new();
        for key in data.keys() {
            if glob_match(pattern, key) {
                result.push(key.clone());
            }
        }
        Ok(result)
    }
}

/// 简单 glob 匹配（复制自 src/dao/mod.rs::tests::glob_match）。
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut p = 0;
    let mut t = 0;
    let mut star_p: Option<usize> = None;
    let mut star_t = 0;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// 运行 API Key 多租户命名空间示例。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison API Key 多租户命名空间示例 ===\n");

    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let handler = ApiKeyHandler::new(dao);

    // 1. 在 tenant-A namespace 下生成两个 key
    println!("[1] 在 tenant-A namespace 下生成 key");
    let key_a1 = handler
        .generate_with_namespace("1001", "tenant-A", vec!["read".into()], 3600)
        .await?;
    println!("    key_a1: {}...", &key_a1[..16]);
    let key_a2 = handler
        .generate_with_namespace("1002", "tenant-A", vec!["write".into()], 3600)
        .await?;
    println!("    key_a2: {}...", &key_a2[..16]);
    assert_eq!(key_a1.len(), 64);
    assert_ne!(key_a1, key_a2);

    // 2. 在 tenant-B namespace 下生成一个 key
    println!("\n[2] 在 tenant-B namespace 下生成 key");
    let key_b1 = handler
        .generate_with_namespace("2001", "tenant-B", vec!["admin".into()], 3600)
        .await?;
    println!("    key_b1: {}...", &key_b1[..16]);

    // 3. verify_with_namespace 严格校验（正确 namespace）
    println!("\n[3] verify_with_namespace 严格校验");
    let info_a1 = handler.verify_with_namespace(&key_a1, "tenant-A").await?;
    println!(
        "    verify(key_a1, tenant-A) → login_id={}, scopes={:?}",
        info_a1.login_id, info_a1.scopes
    );
    assert_eq!(info_a1.login_id, "1001");
    assert_eq!(info_a1.namespace, "tenant-A");

    // 4. 跨 namespace 校验失败（安全隔离）
    println!("\n[4] 跨 namespace 校验失败（安全隔离）");
    let cross = handler.verify_with_namespace(&key_a1, "tenant-B").await;
    assert!(cross.is_err(), "跨 namespace 校验应失败");
    match cross.unwrap_err() {
        GarrisonError::InvalidToken(msg) => {
            println!("    verify(key_a1, tenant-B) → Err(InvalidToken)");
            println!("    错误：{}", msg);
            println!("    ✓ tenant-A 的 key 不能在 tenant-B 中使用");
        },
        other => {
            return Err(format!("期望 InvalidToken，实际: {:?}", other).into());
        },
    }

    // 5. list_by_namespace 列出 namespace 下所有未吊销 key
    println!("\n[5] list_by_namespace 列出未吊销 key");
    let tenant_a_keys = handler.list_by_namespace("tenant-A").await?;
    println!("    tenant-A 未吊销 key 数量: {}", tenant_a_keys.len());
    assert_eq!(tenant_a_keys.len(), 2, "tenant-A 应有 2 个未吊销 key");
    let tenant_b_keys = handler.list_by_namespace("tenant-B").await?;
    println!("    tenant-B 未吊销 key 数量: {}", tenant_b_keys.len());
    assert_eq!(tenant_b_keys.len(), 1, "tenant-B 应有 1 个未吊销 key");

    // 6. 吊销 tenant-A 的一个 key，再次列出
    println!("\n[6] 吊销 key_a1 后重新列出 tenant-A");
    handler.revoke(&key_a1).await?;
    let tenant_a_keys_after = handler.list_by_namespace("tenant-A").await?;
    println!(
        "    tenant-A 未吊销 key 数量: {}",
        tenant_a_keys_after.len()
    );
    assert_eq!(
        tenant_a_keys_after.len(),
        1,
        "吊销后 tenant-A 应剩 1 个未吊销 key"
    );

    // 7. namespace 校验规则
    println!("\n[7] namespace 校验规则（长度 1-64，仅 [a-zA-Z0-9_-]）");
    let invalid_ns = handler
        .generate_with_namespace("3001", "invalid namespace!", vec![], 3600)
        .await;
    assert!(invalid_ns.is_err(), "包含空格和感叹号的 namespace 应失败");
    println!("    generate(namespace=\"invalid namespace!\") → Err（预期）");
    println!("    ✓ namespace 校验规则生效");

    println!("\n=== 示例完成 ===");
    println!("\n多租户场景：");
    println!("  - SaaS 平台 → 每个客户使用独立 namespace，key 隔离");
    println!("  - 微服务网关 → 不同服务使用不同 namespace，权限隔离");
    println!("  - 灰度发布 → 测试/生产 namespace 隔离");
    Ok(())
}
