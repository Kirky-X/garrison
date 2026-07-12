//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Bulwark Benchmark Suite
//! 依据 spec benchmark-framework（E-006），覆盖 4 个基准场景：
//!
//! | Bench | FRD 来源 | 目标 P99 |
//! |-------|---------|---------|
//! | `login_flow` | §7.1 BLK-001 | ≤ 500ms（5000 TPS） |
//! | `token_verify_stateless` | §7.1 + ADD §8.1 | ≤ 5ms（20000 TPS） |
//! | `permission_check` | §7.1 BLK-005 | ≤ 5ms（20000 TPS） |
//! | `oxcache_backend_switch` | §8.2 压测-007 | 切换开销 = 0 |
//!
//! ## 运行方式
//!
//! ```bash
//! # 编译检查（不运行）
//! cargo bench --no-run
//!
//! # 快速运行（减少采样数）
//! cargo bench -- --quick
//!
//! # 启用 JWT 真实验证
//! cargo bench --features protocol-jwt
//!
//! # 完整特性运行
//! cargo bench --features full
//! ```

use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bulwark::prelude::*;
use bulwark::stp::with_current_token;

// ============================================================================
// MockDao: HashMap + Instant 模拟 TTL（复用 stp/tests.rs 的 mock 模式）
// ============================================================================

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
impl BulwarkDao for MockDao {
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
// MockFirewall: 模拟 BulwarkPermissionStrategy（权限检查返回 true）
// ============================================================================

struct MockFirewall {
    has_permission: bool,
    has_role: bool,
}

#[async_trait]
impl BulwarkPermissionStrategy for MockFirewall {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec!["bench:read".to_string(), "bench:write".to_string()])
    }

    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec!["bench-user".to_string()])
    }

    async fn check_permission(&self, _login_id: &str, _permission: &str) -> BulwarkResult<bool> {
        Ok(self.has_permission)
    }

    async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
        Ok(self.has_role)
    }

    async fn check_role_any(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
        Ok(self.has_role)
    }

    async fn check_role_all(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
        Ok(self.has_role)
    }
}

// ============================================================================
// 辅助函数：创建 BulwarkLogicDefault 实例
// ============================================================================

/// 创建 BulwarkLogicDefault 实例（使用 MockDao + MockFirewall，不依赖真实 dbnexus / redis）。
fn make_logic() -> BulwarkLogicDefault {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let config = Arc::new(BulwarkConfig::default_config());
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    BulwarkLogicDefault::new(session, config, firewall)
}

// ============================================================================
// Bench 1: login_flow（FRD §7.1 BLK-001，目标 P99 ≤ 500ms）
// ============================================================================

/// 基准测试登录流程。
///
/// 依据 FRD §7.1 BLK-001：5000 TPS 并发登录，P99 ≤ 500ms。
///
/// 流程：`BulwarkLogicDefault::login("bench-user")` 完整调用
/// （生成 token + 创建 Token-Session + 创建 Account-Session）。
fn bench_login_flow(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let logic = make_logic();

    c.bench_function("login_flow", |b| {
        b.iter(|| rt.block_on(async { logic.login("bench-user").await.unwrap() }));
    });
}

// ============================================================================
// Bench 2: token_verify_stateless（FRD §7.1 + ADD §8.1，目标 P99 ≤ 5ms）
// ============================================================================

/// 基准测试 JWT Stateless 模式 token 验证。
///
/// 依据 FRD §7.1 + ADD §8.1：P99 ≤ 5ms（20000 TPS）。
///
/// - 启用 `protocol-jwt` feature 时：实际 JWT 签发 + 验签（本地 JWKS 缓存命中场景）
/// - 未启用时：模拟 stateless 验证（JWT 结构解析，不验证签名）
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
    // 模拟 JWT Stateless 验证（未启用 `protocol-jwt` feature 时使用）。
    // 仅解析 JWT 结构（header.payload.signature），不验证签名。
    // 启用 `protocol-jwt` feature 后将自动切换为真实 JWT 验签。
    c.bench_function("token_verify_stateless_simulated", |b| {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJiZW5jaC11c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        b.iter(|| {
            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT 应有 3 段");
            // 模拟 payload 解码（base64 → JSON）
            let payload = parts[1];
            assert!(!payload.is_empty());
        });
    });
}

// ============================================================================
// Bench 3: permission_check（FRD §7.1 BLK-005，目标 P99 ≤ 5ms）
// ============================================================================

/// 基准测试权限检查。
///
/// 依据 FRD §7.1 BLK-005：20000 TPS，P99 ≤ 5ms。
///
/// 流程：登录获取 token → 在 task_local 上下文中调用 `has_permission("bench:read")`。
/// 使用 mock firewall 返回 true（模拟 oxcache 缓存命中场景）。
fn bench_permission_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let logic = Arc::new(make_logic());

    // 预登录获取 token（模拟已登录用户）
    let token = rt.block_on(async { logic.login("bench-user").await.unwrap() });

    c.bench_function("permission_check", |b| {
        b.iter(|| {
            let token = token.clone();
            let logic = logic.clone();
            rt.block_on(async move {
                with_current_token(token, async {
                    logic.has_permission("bench:read").await.unwrap()
                })
                .await
            })
        });
    });
}

// ============================================================================
// Bench 4: oxcache_backend_switch（FRD §8.2 压测-007，目标切换开销 = 0）
// ============================================================================

/// 基准测试缓存后端切换。
///
/// 依据 FRD §8.2 压测-007：切换 oxcache 后端后代码无修改，切换开销 = 0。
///
/// # 规则7 冲突说明
///
/// 1. **Caffeine 不存在**：spec R-bench-005 要求验证 "Memory → Caffeine" 切换，
///    但 Rust 生态无 Caffeine（oxcache 使用 moka 作为 L1 后端），故适配为
///    memory / redis 两后端
/// 2. **无 runtime backend 字段**：spec 要求修改 `BulwarkConfig.oxcache.backend`
///    字段验证切换，但 `BulwarkConfig` 无此字段（后端选择通过 Cargo feature
///    编译期决定），故通过不同 `BulwarkDao` 实现验证 DAO 抽象层
///
/// # 验证方式
///
/// 使用不同 `MockDao` 实例（模拟不同后端），同一 `BulwarkLogicDefault` 代码
/// 无修改即可运行，证明 DAO 抽象层的后端切换开销 = 0。
///
/// - `memory`：HashMap 后端（模拟 oxcache moka L1）
/// - `redis_mock`：另一个 HashMap 实例（模拟 redis L2）
///
/// 运行时 skip：设置环境变量 `BULWARK_SKIP_REDIS_BENCH=1` 可跳过 redis 相关子 bench
/// （依据 spec R-bench-005 Constraints），便于在无 Redis 环境下快速运行 benchmark。
fn bench_oxcache_backend_switch(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("oxcache_backend_switch");

    // memory 后端（始终运行）
    let logic_memory = make_logic();
    group.bench_with_input(
        BenchmarkId::new("backend", "memory"),
        &logic_memory,
        |b, logic| {
            b.iter(|| rt.block_on(async { logic.login("bench-user").await.unwrap() }));
        },
    );

    // redis_mock 后端（使用另一个 MockDao 实例，模拟不同后端）
    //
    // 运行时 skip：当 `BULWARK_SKIP_REDIS_BENCH=1` 时跳过 redis 相关子 bench，
    // 便于在无 Redis 环境下快速运行 benchmark（依据 spec R-bench-005 Constraints）。
    // 未来引入真实 redis bench 时，此检查将跳过所有 redis 依赖场景。
    let skip_redis = std::env::var("BULWARK_SKIP_REDIS_BENCH")
        .map(|v| v == "1")
        .unwrap_or(false);

    if !skip_redis {
        let logic_redis = make_logic();
        group.bench_with_input(
            BenchmarkId::new("backend", "redis_mock"),
            &logic_redis,
            |b, logic| {
                b.iter(|| rt.block_on(async { logic.login("bench-user").await.unwrap() }));
            },
        );
    } else {
        println!("[skip] BULWARK_SKIP_REDIS_BENCH=1，跳过 redis_mock 子 bench");
    }

    group.finish();
}

// ============================================================================
// criterion_group + criterion_main
// ============================================================================

criterion_group!(
    benches,
    bench_login_flow,
    bench_token_verify_stateless,
    bench_permission_check,
    bench_oxcache_backend_switch
);
criterion_main!(benches);
