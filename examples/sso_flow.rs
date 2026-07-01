//! SSO 单点登录示例：演示 `SsoClient` ticket 签发 / 校验 / 销毁完整流程（依据 spec protocol-sso）。
//!
//! 运行方式：
//! ```sh
//! cargo run --example sso_flow --features protocol-sso
//! ```
//!
//! 本示例内联一个最小化的内存 `BulwarkDao` 实现，用于演示 `SsoClient` 的完整流程。
//! 生产环境应使用 `BulwarkDaoOxcache`（启用 `cache-memory` / `cache-redis`）或
//! `dbnexus` 实现（启用 `db-sqlite`）。

#[cfg(not(feature = "protocol-sso"))]
fn main() {
    eprintln!("此示例需要启用 protocol-sso 特性：");
    eprintln!("  cargo run --example sso_flow --features protocol-sso");
}

#[cfg(feature = "protocol-sso")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use async_trait::async_trait;
    use bulwark::dao::BulwarkDao;
    use bulwark::error::{BulwarkError, BulwarkResult};
    use bulwark::protocol::sso::SsoClient;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    println!("=== Bulwark SSO 单点登录示例 ===\n");

    // ---- 最小化内存 DAO 实现（仅供示例，生产环境用 oxcache / dbnexus）----
    struct InMemoryDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl InMemoryDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for InMemoryDao {
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
                }
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
                }
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
                }
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ---- 示例主流程 ----

    // 1. 创建 SsoClient，注入 DAO（ticket TTL 默认 60 秒）
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let sso = SsoClient::new(dao);

    // 2. 模拟子系统 A 已登录用户 1001，签发 SSO ticket 供子系统 B 登录
    let login_id: i64 = 1001;
    let client_id: i64 = 200;
    let ticket = sso.issue_ticket(login_id, client_id).await?;
    println!("[签发] 用户 {} 的 SSO ticket：{}", login_id, ticket);
    println!("       （ticket TTL 60 秒，一次性使用）");

    // 3. 子系统 B 用 ticket 校验并完成登录
    let validated_login_id = sso.validate_ticket(&ticket, client_id).await?;
    println!(
        "[校验] 校验成功，返回 login_id={}",
        validated_login_id
    );
    assert_eq!(validated_login_id, login_id);

    // 4. 验证 ticket 一次性语义：再次校验应失败
    match sso.validate_ticket(&ticket, client_id).await {
        Ok(_) => println!("[一次性] 不应再次校验通过"),
        Err(e) => println!("[一次性] 重复校验失败（预期）：{}", e),
    }

    // 5. 演示 client_id 不匹配的拒绝
    let ticket2 = sso.issue_ticket(login_id, client_id).await?;
    let wrong_client_id: i64 = 999;
    match sso.validate_ticket(&ticket2, wrong_client_id).await {
        Ok(_) => println!("[校验] 不应校验通过"),
        Err(e) => println!("[校验] client_id 不匹配被拒（预期）：{}", e),
    }

    // 6. 销毁 ticket（幂等）
    let ticket3 = sso.issue_ticket(login_id, client_id).await?;
    sso.destroy_ticket(&ticket3).await?;
    sso.destroy_ticket(&ticket3).await?; // 幂等，不报错
    println!("[销毁] ticket 销毁成功（幂等调用不报错）");

    println!("\n=== 示例完成 ===");
    Ok(())
}
