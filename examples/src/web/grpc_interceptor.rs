//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! grpc_interceptor 示例（grpc feature）。
//!
//! 演示 tonic gRPC 框架集成：
//! 1. `BulwarkGrpcInterceptor::new()` 创建拦截器
//! 2. `extract_token` 从 gRPC metadata 提取 Authorization Bearer token
//! 3. `Interceptor::call()` 同步拦截器行为（仅提取 token，不执行 async 鉴权）
//! 4. `with_current_token` + `BulwarkUtil::check_login()` 完整 async 鉴权模式
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin grpc_interceptor --features grpc
//! ```

use async_trait::async_trait;
use bulwark::config::BulwarkConfig;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::grpc::BulwarkGrpcInterceptor;
use bulwark::manager::BulwarkManager;
use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkUtil};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;

// ============================================================================
// InMemoryDao（HashMap + Instant 模拟 TTL，参考 alone_cache.rs 模式）
// ============================================================================

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

// ============================================================================
// MyInterface（预置 login_id=1001 的 admin 角色 + data:read 权限）
// ============================================================================

/// 示例接口实现，仅提供 login_id=1001 的权限与角色。
pub struct MyInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MyInterface {
    /// 创建 MyInterface 实例。
    ///
    /// 预置数据：login_id=1001 持有 `["data:read"]` 权限 + `["admin"]` 角色。
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert("1001".to_string(), vec!["data:read".to_string()]);
        let mut roles = HashMap::new();
        roles.insert("1001".to_string(), vec!["admin".to_string()]);
        Self { permissions, roles }
    }
}

impl Default for MyInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkInterface for MyInterface {
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}

// ============================================================================
// setup / 演示函数 / run
// ============================================================================

/// 初始化全局 BulwarkManager（注入 InMemoryDao + MyInterface），并登录获取 token。
///
/// 返回 `(config, token)`，token 用于演示 gRPC metadata 注入。
pub async fn setup() -> (Arc<BulwarkConfig>, String) {
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let config = Arc::new(config);
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    BulwarkManager::init(dao, config.clone(), interface).expect("BulwarkManager 初始化失败");

    let token = BulwarkUtil::login("1001").await.expect("login 失败");
    (config, token)
}

/// 构造包含 Authorization Bearer token 的 tonic metadata。
///
/// 模拟 gRPC 客户端在请求中携带的 metadata。
pub fn build_metadata_with_token(token: &str) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    metadata
}

/// 模拟 gRPC service handler 内的 async 鉴权流程。
///
/// 实际 tonic 应用中，此函数对应 service handler 内的逻辑：
/// 1. 从请求 metadata 提取 token（通常在 Interceptor 中完成）
/// 2. 用 `with_current_token` 设置 task_local 上下文
/// 3. 调用 `BulwarkUtil::check_login()` 执行异步鉴权
///
/// # 参数
/// - `token`: 从 metadata 提取的 token 字符串
///
/// # 返回
/// - `Ok(())`: 鉴权通过
/// - `Err(BulwarkError)`: 鉴权失败（未登录 / token 无效等）
pub async fn authenticate_request(token: String) -> BulwarkResult<()> {
    with_current_token(token, async {
        let logged_in = BulwarkUtil::check_login().await?;
        if !logged_in {
            return Err(BulwarkError::NotLogin("未登录".to_string()));
        }
        Ok(())
    })
    .await
}

/// 运行 grpc_interceptor 示例。
///
/// 演示完整的 gRPC 鉴权流程：
/// 1. 创建 `BulwarkGrpcInterceptor`
/// 2. 从 metadata 提取 token
/// 3. `Interceptor::call()` 同步拦截（仅提取 token）
/// 4. `with_current_token` + `check_login` 完整 async 鉴权
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark gRPC Interceptor 示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 初始化 BulwarkManager
    // ----------------------------------------------------------------
    let (_config, token) = setup().await;
    println!("[初始化] BulwarkManager 已就绪");
    println!("    账号 1001 角色: [admin]");
    println!("    账号 1001 权限: [data:read]");
    println!("    token: {}...", &token[..16.min(token.len())]);
    println!();

    // ----------------------------------------------------------------
    // 2. 创建 BulwarkGrpcInterceptor
    // ----------------------------------------------------------------
    println!("[Interceptor] BulwarkGrpcInterceptor::new():");
    let interceptor = BulwarkGrpcInterceptor::new();
    println!("    创建拦截器实例（Default + Clone + Debug）");
    let _cloned = interceptor.clone();
    println!("    clone() 成功（可在多个 tonic Server 间共享）");
    println!("    Debug: {:?}", interceptor);
    println!();

    // ----------------------------------------------------------------
    // 3. 从 metadata 提取 token
    // ----------------------------------------------------------------
    println!("[extract_token] 从 gRPC metadata 提取 Authorization Bearer token:");

    let metadata = build_metadata_with_token(&token);
    let extracted = BulwarkGrpcInterceptor::extract_token(&metadata)?;
    println!(
        "    metadata[\"authorization\"] = \"Bearer {}...\"",
        &extracted[..16.min(extracted.len())]
    );
    println!(
        "    extract_token() → Ok(\"{}...\")",
        &extracted[..16.min(extracted.len())]
    );
    assert_eq!(extracted, token);
    println!();

    // ----------------------------------------------------------------
    // 4. Interceptor::call() 同步拦截（仅提取 token，不执行 async 鉴权）
    // ----------------------------------------------------------------
    println!("[Interceptor::call] 同步拦截器行为（仅提取 token）:");

    let mut interceptor = BulwarkGrpcInterceptor::new();
    let mut request = tonic::Request::new(());
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    let result = interceptor.call(request);
    println!(
        "    Interceptor::call(request with Bearer token) → {:?}",
        if result.is_ok() { "Ok" } else { "Err" }
    );
    assert!(result.is_ok(), "合法 token 应通过拦截器");
    println!();

    // 测试缺失 metadata → UNAUTHENTICATED
    let request_no_auth = tonic::Request::new(());
    let result = interceptor.call(request_no_auth);
    println!("    Interceptor::call(request without metadata) → Err(UNAUTHENTICATED)");
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    println!("    status.code() = Unauthenticated (code=16)");
    println!();

    // ----------------------------------------------------------------
    // 5. with_current_token + check_login 完整 async 鉴权
    // ----------------------------------------------------------------
    println!("[async 鉴权] with_current_token + BulwarkUtil::check_login():");

    // 合法 token → 鉴权通过
    let result = authenticate_request(token.clone()).await;
    println!(
        "    authenticate_request(valid_token) → {:?}",
        if result.is_ok() { "Ok" } else { "Err" }
    );
    assert!(result.is_ok(), "合法 token 应鉴权通过");
    println!();

    // 非法 token → 鉴权失败
    let result = authenticate_request("invalid-token-xxx".to_string()).await;
    println!("    authenticate_request(\"invalid-token-xxx\") → Err(NotLogin/InvalidToken)");
    assert!(result.is_err(), "非法 token 应鉴权失败");
    println!("    错误类型: {:?}", result.unwrap_err());
    println!();

    // ----------------------------------------------------------------
    // 6. 总结：完整 gRPC 鉴权推荐模式
    // ----------------------------------------------------------------
    println!("[总结] 完整 gRPC 鉴权推荐模式:");
    println!("    1. tonic Interceptor 提取 token（同步，仅格式校验）");
    println!("    2. tonic service handler 内 with_current_token(token, async {{");
    println!("         BulwarkUtil::check_login().await?");
    println!("         // 业务逻辑...");
    println!("       }}).await");
    println!();

    println!("=== 示例完成 ===");
    Ok(())
}
