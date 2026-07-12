//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SSO Server 独立抽象示例（依据 spec protocol-sso-server，0.4.0 新增）。
//!
//! 演示 `DefaultSsoServer` + `CenterIdConverter` + `SsoChannel`：
//! 1. 创建 `DefaultSsoServer::new(dao)` + `with_ticket_ttl` + `with_converter`
//! 2. 实现 `CenterIdConverter`（`OffsetConverter` 做 login_id + 10000 映射）
//! 3. `issue_ticket` + `validate_ticket` 往返（验证 center_id 转换）
//! 4. 演示 `SsoServer` 与 `SsoClient` 通过共享 DAO 间接通信
//! 5. 实现自定义 `SsoChannel`（`CountingChannel` 计数 push 调用）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin sso_server --features protocol-sso-server
//! ```

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::sso::server::{CenterIdConverter, DefaultSsoServer, SsoChannel, SsoServer};
use bulwark::protocol::sso::SsoClient;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 最小化内存 DAO 实现（仅供示例，生产环境用 oxcache / dbnexus）。
pub struct InMemoryDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl InMemoryDao {
    /// 创建 InMemoryDao 实例。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryDao {
    fn default() -> Self {
        Self::new()
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

/// 偏移转换器：login_id + 10000 = center_id（模拟多子系统 ID 映射）。
struct OffsetConverter;

impl CenterIdConverter for OffsetConverter {
    fn to_center_id(&self, login_id: &str) -> String {
        format!("center_{}", login_id)
    }

    fn to_login_id(&self, center_id: &str) -> String {
        center_id
            .strip_prefix("center_")
            .unwrap_or(center_id)
            .to_string()
    }
}

/// 计数通道：记录 push 调用次数（演示自定义 SsoChannel 实现）。
struct CountingChannel {
    count: AtomicUsize,
}

#[async_trait]
impl SsoChannel for CountingChannel {
    async fn push(&self, _topic: &str, _message: &str) -> BulwarkResult<()> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn subscribe(
        &self,
        _topic: &str,
        _handler: Box<dyn Fn(&str) + Send + Sync>,
    ) -> BulwarkResult<()> {
        Ok(())
    }
}

/// 运行 SSO Server 示例。
///
/// 演示 DefaultSsoServer 的 issue_ticket / validate_ticket 完整流程，
/// 包括 CenterIdConverter 双向转换、SsoServer 与 SsoClient 共享 DAO 通信、
/// 自定义 SsoChannel 消息推送计数。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark SSO Server 示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 创建 DefaultSsoServer（注入 DAO + TTL + 自定义 converter + channel）
    // ----------------------------------------------------------------
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let channel = Arc::new(CountingChannel {
        count: AtomicUsize::new(0),
    });
    let server = DefaultSsoServer::new(dao.clone(), "test-sso-secret-key")
        .with_ticket_ttl(120)
        .with_converter(Arc::new(OffsetConverter))
        .with_channel(channel.clone());

    println!("[配置] DefaultSsoServer:");
    println!("    ticket_ttl = 120s");
    println!("    converter  = OffsetConverter（login_id + 10000 = center_id）");
    println!("    channel    = CountingChannel\n");

    // ----------------------------------------------------------------
    // 2. issue_ticket + validate_ticket 往返（验证 center_id 转换）
    // ----------------------------------------------------------------
    let login_id = "1001";
    let client_id: i64 = 200;
    let ticket = server.issue_ticket(login_id, client_id).await?;
    println!(
        "[签发] SsoServer 签发 ticket（login_id={}）: {}...",
        login_id,
        &ticket[..16]
    );

    let validated = server.validate_ticket(&ticket, client_id).await?;
    println!("[校验] SsoServer 校验成功，返回 login_id={}", validated);
    assert_eq!(
        validated, login_id,
        "validate_ticket 应返回原始 login_id（经 converter 转回）"
    );

    // ----------------------------------------------------------------
    // 3. 验证 ticket 一次性语义
    // ----------------------------------------------------------------
    match server.validate_ticket(&ticket, client_id).await {
        Ok(_) => println!("[一次性] 不应再次校验通过"),
        Err(e) => println!("[一次性] 重复校验失败（预期）：{}", e),
    }

    // ----------------------------------------------------------------
    // 4. SsoServer 与 SsoClient 通过共享 DAO 间接通信
    //
    //    注意：此场景使用 identity converter 的 server（不带 OffsetConverter）。
    //    因为 SsoClient 不持有 CenterIdConverter，无法将 center_id 转回 login_id，
    //    所以 cross-communication 场景下 server 端也不做 ID 偏移，保证往返一致。
    //    （参考 src/protocol/sso/server.rs 的 server_and_client_communicate_via_shared_dao 测试）
    // ----------------------------------------------------------------
    println!("\n[共享 DAO] SsoServer 签发的 ticket 由 SsoClient 校验:");
    let identity_server = DefaultSsoServer::new(dao.clone(), "test-sso-secret-key");
    let server_ticket = identity_server.issue_ticket(login_id, client_id).await?;
    let sso_client = SsoClient::new(dao.clone(), "test-sso-secret-key");
    let client_validated = sso_client
        .validate_ticket(&server_ticket, client_id)
        .await?;
    println!(
        "    SsoServer 签发 → SsoClient 校验，login_id={}",
        client_validated
    );
    assert_eq!(client_validated, login_id);

    println!("\n[共享 DAO] SsoClient 签发的 ticket 由 SsoServer 校验:");
    let client_ticket = sso_client.issue_ticket(login_id, client_id).await?;
    let server_validated = identity_server
        .validate_ticket(&client_ticket, client_id)
        .await?;
    println!(
        "    SsoClient 签发 → SsoServer 校验，login_id={}",
        server_validated
    );
    assert_eq!(server_validated, login_id);

    // ----------------------------------------------------------------
    // 5. 自定义 SsoChannel 计数 push 调用
    // ----------------------------------------------------------------
    println!("\n[Channel] CountingChannel 计数 push 调用:");
    server.push_message(login_id, "登录通知").await?;
    server.push_message(login_id, "权限变更").await?;
    let push_count = channel.count.load(Ordering::SeqCst);
    println!(
        "    push_message 调用 {} 次后，channel.count = {}",
        2, push_count
    );
    assert_eq!(push_count, 2);

    // ----------------------------------------------------------------
    // 6. 销毁 ticket（幂等）
    // ----------------------------------------------------------------
    let ticket3 = server.issue_ticket(login_id, client_id).await?;
    server.destroy_ticket(&ticket3).await?;
    server.destroy_ticket(&ticket3).await?; // 幂等
    println!("\n[销毁] ticket 销毁成功（幂等调用不报错）");

    println!("\n=== 示例完成 ===");
    Ok(())
}
