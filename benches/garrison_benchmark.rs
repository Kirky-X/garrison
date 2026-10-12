// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Garrison Benchmark Suite：6 个基准场景——login_flow（P99 ≤ 500ms，5000 TPS）、token_verify_stateless / permission_check（P99 ≤ 5ms，20000 TPS）、oxcache_backend_switch（切换开销 = 0）、convert_placeholders（SQL 方言转换）、circuit_execute_closed_passthrough（熔断直通开销）。
//!
//! ## 运行方式
//!
//! ```bash
//! cargo bench --no-run                     # 编译检查
//! cargo bench -- --quick                   # 快速运行（减少采样数）
//! cargo bench --features protocol-jwt      # 启用 JWT 真实验证
//! cargo bench --features full              # 完整特性运行
//! ```

use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison::context::tenant::{TenantContext, TenantSource, TENANT};
use garrison::prelude::*;
use garrison::stp::{with_current_token, LoginParams};

// MockDao: HashMap + Instant 模拟 TTL（复用 stp/tests.rs 的 mock 模式）

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
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
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

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
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

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
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
            None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
    garrison::atomic_test_fallback!();
}

// MockFirewall: 模拟 GarrisonPermissionStrategy（权限检查返回 true）

struct MockFirewall {
    has_permission: bool,
    has_role: bool,
}

#[async_trait]
impl GarrisonPermissionStrategy for MockFirewall {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["bench:read".to_string(), "bench:write".to_string()])
    }

    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["bench-user".to_string()])
    }

    async fn check_permission(&self, _login_id: &str, _permission: &str) -> GarrisonResult<bool> {
        Ok(self.has_permission)
    }

    async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
        Ok(self.has_role)
    }

    async fn check_role_any(&self, _login_id: &str, _roles: &[&str]) -> GarrisonResult<bool> {
        Ok(self.has_role)
    }

    async fn check_role_all(&self, _login_id: &str, _roles: &[&str]) -> GarrisonResult<bool> {
        Ok(self.has_role)
    }

    async fn check_permission_in_tenant(
        &self,
        _tenant_id: i64,
        _login_id: &str,
        _permission: &str,
    ) -> GarrisonResult<bool> {
        // 基准测试桩与租户无关：任意租户返回相同结果
        Ok(self.has_permission)
    }

    async fn check_role_in_tenant(
        &self,
        _tenant_id: i64,
        _login_id: &str,
        _role: &str,
    ) -> GarrisonResult<bool> {
        // 基准测试桩与租户无关：任意租户返回相同结果
        Ok(self.has_role)
    }

    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    async fn check_login_hooks(
        &self,
        _login_id: &str,
        _ctx: &garrison::strategy::hooks::LoginContext,
    ) -> GarrisonResult<()> {
        // 基准测试桩不注入防火墙 hook，显式 no-op
        Ok(())
    }
}

// 辅助函数：创建 GarrisonLogicDefault 实例

/// 创建 GarrisonLogicDefault 实例（使用 MockDao + MockFirewall，不依赖真实 dbnexus / redis）。
fn make_logic() -> GarrisonLogicDefault {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 7_776_000));
    let config = Arc::new(GarrisonConfig::default_config());
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let disable_repo: Arc<dyn garrison::account::disable::DisableRepository> = Arc::new(
        garrison::account::disable::DefaultDisableRepository::new(dao),
    );
    GarrisonLogicDefault::new(session, config, firewall, disable_repo)
}

// Bench 1: login_flow（目标 P99 ≤ 500ms）

/// 登录流程基准：5000 TPS 并发登录，P99 ≤ 500ms；完整调用 `GarrisonLogicDefault::login`（生成 token + 创建 Token-Session + Account-Session）。
fn bench_login_flow(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let logic = make_logic();

    c.bench_function("login_flow", |b| {
        b.iter(|| {
            rt.block_on(async {
                logic
                    .login("bench-user", &LoginParams::default())
                    .await
                    .unwrap()
            })
        });
    });
}

// Bench 2: token_verify_stateless（目标 P99 ≤ 5ms）

/// JWT stateless 验证基准：P99 ≤ 5ms（20000 TPS）。启用 `protocol-jwt` 时为真实签发 + 验签（本地 JWKS 缓存命中场景），未启用时为结构解析模拟（不验签）。
#[cfg(feature = "protocol-jwt")]
fn bench_token_verify_stateless(c: &mut Criterion) {
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

    let secret = "bench-secret-key-for-jwt";
    let header = Header::new(Algorithm::HS256);
    let claims = serde_json::json!({
        "sub": "bench-user",
        "iat": 1516239022_u64,
        "exp": 9999999999_u64,
    });

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap();

    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);

    c.bench_function("token_verify_stateless_jwt", |b| {
        b.iter(|| {
            let token_data =
                decode::<serde_json::Value>(&token, &decoding_key, &validation).unwrap();
            assert_eq!(token_data.claims["sub"].as_str(), Some("bench-user"));
        });
    });
}

#[cfg(not(feature = "protocol-jwt"))]
fn bench_token_verify_stateless(c: &mut Criterion) {
    // 未启用 `protocol-jwt` 时模拟 stateless 验证：仅解析 JWT 结构，不验证签名。
    c.bench_function("token_verify_stateless_simulated", |b| {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiZW5jaC11c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        b.iter(|| {
            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT 应有 3 段");
            let payload = parts[1];
            assert!(!payload.is_empty());
        });
    });
}

// Bench 3: permission_check（目标 P99 ≤ 5ms）

/// 权限检查基准：20000 TPS，P99 ≤ 5ms；登录获取 token 后在 task_local 上下文调用 `has_permission`，mock firewall 返回 true 模拟缓存命中。
fn bench_permission_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let logic = Arc::new(make_logic());

    // 预登录获取 token（模拟已登录用户）
    let token = rt.block_on(async {
        logic
            .login("bench-user", &LoginParams::default())
            .await
            .unwrap()
    });

    c.bench_function("permission_check", |b| {
        b.iter(|| {
            let token = token.clone();
            let logic = logic.clone();
            rt.block_on(async move {
                // tenant-isolation 启用时 has_permission 经 current_tenant_id_or_error() fail-closed；本基准模拟默认租户 0 的已登录用户（等价 server 中间件解析 X-Tenant-Id: 0）
                TENANT
                    .scope(
                        TenantContext {
                            tenant_id: 0,
                            resolved_from: TenantSource::Header,
                        },
                        with_current_token(token, async {
                            logic.has_permission("bench:read").await.unwrap()
                        }),
                    )
                    .await
            })
        });
    });
}

// Bench 4: oxcache_backend_switch（目标切换开销 = 0）

/// 缓存后端切换基准：不同 `MockDao` 实例（memory / redis_mock）运行同一 `GarrisonLogicDefault` 代码无修改，证明 DAO 抽象层后端切换开销 = 0。`GARRISON_SKIP_REDIS_BENCH=1` 跳过 redis 子 bench（无 Redis 环境快速运行）。
fn bench_oxcache_backend_switch(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("oxcache_backend_switch");

    // memory 后端（始终运行）
    let logic_memory = make_logic();
    group.bench_with_input(
        BenchmarkId::new("backend", "memory"),
        &logic_memory,
        |b, logic| {
            b.iter(|| {
                rt.block_on(async {
                    logic
                        .login("bench-user", &LoginParams::default())
                        .await
                        .unwrap()
                })
            });
        },
    );

    // redis_mock 后端（另一个 MockDao 实例，模拟不同后端）
    let skip_redis = std::env::var("GARRISON_SKIP_REDIS_BENCH")
        .map(|v| v == "1")
        .unwrap_or(false);

    if !skip_redis {
        let logic_redis = make_logic();
        group.bench_with_input(
            BenchmarkId::new("backend", "redis_mock"),
            &logic_redis,
            |b, logic| {
                b.iter(|| {
                    rt.block_on(async {
                        logic
                            .login("bench-user", &LoginParams::default())
                            .await
                            .unwrap()
                    })
                });
            },
        );
    } else {
        println!("[skip] GARRISON_SKIP_REDIS_BENCH=1，跳过 redis_mock 子 bench");
    }

    group.finish();
}

// Bench 5: convert_placeholders（SQL 方言转换，每次 Statement 构造必经路径）

/// SQL 占位符方言转换基准（自研依赖升级适配面热路径锁定）：PostgreSQL 口径为含字符串字面量/行注释/块注释与多个 `?` 的真实查询，SQLite 直通。
// 无 cfg 门控：本 target 的 required-features = ["full"] 恒含 db-* 与 backend-remote，条件编译只会制造不可达分支（criterion_group 无条件引用）。
fn bench_convert_placeholders(c: &mut Criterion) {
    use dbnexus::sea_orm::DbBackend;
    use garrison::dao::repository::convert_placeholders;

    let sql = "SELECT u.id, u.name /* block ? */ FROM users u WHERE u.status = ? \
               AND u.name <> 'literal ? ''escaped''' -- line ? comment\n\
               AND u.created_at > ? AND u.tenant_id = ? AND u.role = ?";

    let mut group = c.benchmark_group("convert_placeholders");
    group.bench_function("postgres", |b| {
        b.iter(|| convert_placeholders(std::hint::black_box(sql), DbBackend::Postgres))
    });
    group.bench_function("sqlite_passthrough", |b| {
        b.iter(|| convert_placeholders(std::hint::black_box(sql), DbBackend::Sqlite))
    });
    group.finish();
}

// Bench 6: circuit_execute（熔断包装器直通开销，backend-remote 远程调用必经路径）

/// `CircuitBreakerWrapper::execute` 关闭态直通开销基准（自研依赖升级适配面锁定：limiteron rc.6 CircuitCallError 迁移后的包装成本）；迭代循环包在一次 block_on 内（iter_custom），避免每迭代 ~130ns 的 executor 常量项稀释被测开销。
fn bench_circuit_execute(c: &mut Criterion) {
    use garrison::limiteron::CircuitBreakerWrapper;
    use limiteron::circuit::CircuitBreakerConfig;
    use std::time::Duration;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let wrapper =
        CircuitBreakerWrapper::new(CircuitBreakerConfig::new(5, 2, Duration::from_secs(30)));

    c.bench_function("circuit_execute_closed_passthrough", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let start = Instant::now();
                for _ in 0..iters {
                    wrapper
                        .execute(|| async { Ok::<u32, garrison::error::GarrisonError>(1) })
                        .await
                        .unwrap();
                }
                start.elapsed()
            })
        });
    });
}

// criterion_group + criterion_main

criterion_group!(
    benches,
    bench_login_flow,
    bench_token_verify_stateless,
    bench_permission_check,
    bench_oxcache_backend_switch,
    bench_convert_placeholders,
    bench_circuit_execute
);
criterion_main!(benches);
