// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `rate-limit-redis` 真 Redis 验收：双实例共享计数 / 滑动窗口 / TTL / 前缀清理。
//!
//! 运行方式：
//!
//! ```bash
//! GARRISON_TEST_REDIS_URL=redis://127.0.0.1:6379/15 \
//!   cargo test --features full --test redis_limiter_backend -- --nocapture
//! ```
//!
//! Redis 不可达时用例显式跳过（打印 `SKIP`），CI 集成 job 已带 Redis service。

use garrison::config::GarrisonConfig;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::limiteron::LimiterRuntime;
use garrison::strategy::firewall::rate_limit::{
    RateLimitConfig, RateLimitScope, RateLimitStrategy,
};
use garrison::strategy::firewall::{CaptchaChallenge, FirewallContext, GarrisonFirewallStrategy};
use garrison::strategy::hooks::{GarrisonFirewallCheckHook, GarrisonFirewallCheckHookDefault};
use garrison::strategy::rate_limiter_backend::RateLimitBackend;
use serial_test::serial;
use std::sync::{Arc, Once};
use std::time::Duration;
use uuid::Uuid;

/// oxcache 默认拒绝非 TLS Redis；开发/测试实例显式放行（生产应使用 `rediss://`）。
fn ensure_insecure_redis_allowed() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var("OXCACHE_ALLOW_INSECURE_REDIS").is_err() {
            std::env::set_var("OXCACHE_ALLOW_INSECURE_REDIS", "I_UNDERSTAND_THE_RISKS");
        }
    });
}

/// 测试 Redis URL：默认 DB 15，避免与其它验收用例的 DB 0 混用。
fn redis_url() -> String {
    std::env::var("GARRISON_TEST_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379/15".to_string())
}

/// TCP 探活：Redis 不可达时跳过（CI 集成 job 提供 service）。
fn redis_available(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("redis://") else {
        return false;
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    // 去掉 userinfo（密码可能含未转义的 '@'，取最后一个 '@'）
    let hostport = hostport.rsplit('@').next().unwrap_or(hostport);
    let Some((host, port)) = hostport.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let Ok(addr) = format!("{host}:{port}").parse() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// 构造应用配置（`rate_limit_backend=redis`）。
fn app_config(url: &str) -> GarrisonConfig {
    let mut config = GarrisonConfig::default_config();
    config.rate_limit_backend = RateLimitBackend::Redis {
        redis_url: url.to_string(),
    };
    config
}

/// 构造一个独立运行时（模拟一个进程实例）；Redis 不可达时返回 `None`。
async fn runtime() -> Option<LimiterRuntime> {
    ensure_insecure_redis_allowed();
    let url = redis_url();
    if !redis_available(&url) {
        eprintln!("SKIP: redis unavailable at {url}");
        return None;
    }
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    Some(
        LimiterRuntime::from_config(&app_config(&url), dao)
            .await
            .expect("redis 探活通过后运行时必须构造成功"),
    )
}

fn dummy_dao() -> Arc<dyn GarrisonDao> {
    Arc::new(InMemoryDao::new())
}

/// 双实例共享 IP / 账号失败计数：实例 A 写入，实例 B 读取并触发阻断。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn two_instances_share_login_failure_count() {
    let Some(runtime_a) = runtime().await else {
        return;
    };
    let Some(runtime_b) = runtime().await else {
        return;
    };

    let uuid = Uuid::new_v4();
    let ip = format!("ip-{uuid}");
    let login_id = format!("user-{uuid}");

    let hook_a = GarrisonFirewallCheckHookDefault::new()
        .with_dao(dummy_dao())
        .with_limiter_backend(runtime_a.limiter());
    let hook_b = GarrisonFirewallCheckHookDefault::new()
        .with_dao(dummy_dao())
        .with_limiter_backend(runtime_b.limiter());

    let ctx = garrison::strategy::hooks::LoginContext::new(&login_id).with_ip(&ip);
    for _ in 0..3 {
        hook_a.record_failure(&ctx).await.unwrap();
    }

    assert_eq!(
        hook_b.ip_failure_count(&ip).await,
        3,
        "实例 B 必须看到实例 A 写入的 IP 计数"
    );
    assert_eq!(
        hook_b.account_failure_count(&login_id).await,
        3,
        "实例 B 必须看到实例 A 写入的账号计数"
    );

    // 补到阈值（IP 10 / 账号 5），验证阻断判定也跨实例共享。
    for _ in 0..7 {
        hook_a.record_failure(&ctx).await.unwrap();
    }
    assert!(
        hook_b.check_login_frequency(&ctx).await.is_err(),
        "IP 计数达 10 后实例 B 必须阻断"
    );
    assert!(
        hook_b.check_brute_force(&ctx).await.is_err(),
        "账号计数达 5 后实例 B 必须阻断"
    );

    runtime_b
        .limiter()
        .reset_prefix(&format!("fw:ip:{ip}"))
        .await
        .unwrap();
    runtime_b
        .limiter()
        .reset_prefix(&format!("fw:acct:{login_id}"))
        .await
        .unwrap();
}

/// 双实例共享滑动窗口：A/B 合计超过阈值后拦截。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn two_instances_share_sliding_window() {
    let Some(runtime_a) = runtime().await else {
        return;
    };
    let Some(runtime_b) = runtime().await else {
        return;
    };

    let uuid = Uuid::new_v4();
    let login_id = format!("rl-{uuid}");
    let ctx = FirewallContext {
        ip: format!("ip-{uuid}"),
        login_id: Some(login_id.clone()),
        tenant_id: None,
    };
    let config = RateLimitConfig {
        max_requests: 5,
        window_seconds: 10,
        scope: RateLimitScope::User,
        dynamic_threshold: None,
    };
    let strategy_a = RateLimitStrategy::with_runtime(config.clone(), runtime_a.clone());
    let strategy_b = RateLimitStrategy::with_runtime(config, runtime_b.clone());

    for strategy in [
        &strategy_a,
        &strategy_a,
        &strategy_b,
        &strategy_b,
        &strategy_a,
    ] {
        strategy.check(&ctx).await.unwrap();
    }
    let blocked = strategy_b.check(&ctx).await;
    assert!(
        matches!(
            blocked,
            Err(garrison::error::GarrisonError::FirewallBlocked(_))
        ),
        "第 6 次请求必须被跨实例窗口拦截，实际: {:?}",
        blocked
    );

    runtime_b
        .limiter()
        .reset_prefix(&format!("rl:user:{login_id}"))
        .await
        .unwrap();
}

/// TTL 过期后计数归零。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn ttl_expiry_resets_counter() {
    let Some(runtime) = runtime().await else {
        return;
    };
    let key = format!("test:ttl:{}", Uuid::new_v4());

    let count = runtime
        .limiter()
        .incr_with_ttl(&key, 1, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(count, 1);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        runtime.limiter().get_count(&key).await.unwrap(),
        0,
        "TTL 过期后计数必须归零"
    );
}

/// `hook.reset()` 经 `LimiterBackend::reset_prefix` 清理 Redis 计数：实例 B 读取归零。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn hook_reset_clears_cross_instance_counters() {
    let Some(runtime_a) = runtime().await else {
        return;
    };
    let Some(runtime_b) = runtime().await else {
        return;
    };

    let uuid = Uuid::new_v4();
    let ip = format!("ip-reset-{uuid}");
    let login_id = format!("user-reset-{uuid}");
    let hook_a = GarrisonFirewallCheckHookDefault::new()
        .with_dao(dummy_dao())
        .with_limiter_backend(runtime_a.limiter());
    let hook_b = GarrisonFirewallCheckHookDefault::new()
        .with_dao(dummy_dao())
        .with_limiter_backend(runtime_b.limiter());

    let ctx = garrison::strategy::hooks::LoginContext::new(&login_id).with_ip(&ip);
    for _ in 0..3 {
        hook_a.record_failure(&ctx).await.unwrap();
    }
    assert_eq!(hook_b.ip_failure_count(&ip).await, 3);

    hook_a.reset().await.unwrap();

    assert_eq!(
        hook_b.ip_failure_count(&ip).await,
        0,
        "reset 后实例 B 的 IP 计数必须归零"
    );
    assert_eq!(
        hook_b.account_failure_count(&login_id).await,
        0,
        "reset 后实例 B 的账号计数必须归零"
    );
}

/// `Storage::set` 的 TTL 映射：`None` / `Some(0)` 永久，`Some(1)` 1 秒后过期。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn storage_ttl_mapping_roundtrip() {
    let Some(runtime) = runtime().await else {
        return;
    };
    let prefix = format!("test:storage:{}", Uuid::new_v4());
    let permanent = format!("{prefix}:permanent");
    let zero = format!("{prefix}:zero");
    let expiring = format!("{prefix}:expiring");

    runtime.storage().set(&permanent, "v", None).await.unwrap();
    runtime.storage().set(&zero, "v", Some(0)).await.unwrap();
    runtime
        .storage()
        .set(&expiring, "v", Some(1))
        .await
        .unwrap();

    assert_eq!(
        runtime.storage().get(&permanent).await.unwrap().as_deref(),
        Some("v")
    );
    assert_eq!(
        runtime.storage().get(&zero).await.unwrap().as_deref(),
        Some("v")
    );
    assert_eq!(
        runtime.storage().get(&expiring).await.unwrap().as_deref(),
        Some("v")
    );

    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        runtime.storage().get(&expiring).await.unwrap(),
        None,
        "Some(1) 应在 1 秒后过期"
    );
    assert_eq!(
        runtime.storage().get(&permanent).await.unwrap().as_deref(),
        Some("v"),
        "None 应永久驻留"
    );
    assert_eq!(
        runtime.storage().get(&zero).await.unwrap().as_deref(),
        Some("v"),
        "Some(0) 应永久驻留"
    );

    runtime.storage().delete(&permanent).await.unwrap();
    runtime.storage().delete(&zero).await.unwrap();
    runtime.storage().delete(&expiring).await.unwrap();
}

/// 验证码答案跨实例：A 写入，B 校验并消费。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn captcha_answer_cross_instance() {
    let Some(runtime_a) = runtime().await else {
        return;
    };
    let Some(runtime_b) = runtime().await else {
        return;
    };

    let uuid = Uuid::new_v4();
    let login_id = format!("captcha-{uuid}");
    let ctx = FirewallContext {
        ip: format!("ip-{uuid}"),
        login_id: Some(login_id.clone()),
        tenant_id: None,
    };
    let config = RateLimitConfig {
        max_requests: 100,
        window_seconds: 10,
        scope: RateLimitScope::User,
        dynamic_threshold: None,
    };
    let strategy_a = RateLimitStrategy::with_runtime(config.clone(), runtime_a);
    let strategy_b = RateLimitStrategy::with_runtime(config, runtime_b.clone());

    strategy_a.set_expected_answer(&ctx, "42").await.unwrap();
    assert!(
        strategy_b.verify_challenge(&ctx, "42").await.unwrap(),
        "实例 B 必须能校验实例 A 写入的答案"
    );
    assert!(
        !strategy_b.verify_challenge(&ctx, "42").await.unwrap(),
        "答案消费后必须失效"
    );

    runtime_b
        .limiter()
        .reset_prefix(&format!("rl:user:{login_id}"))
        .await
        .unwrap();
}

/// `reset_prefix` 只清理匹配前缀的键。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn reset_prefix_clears_only_matching_keys() {
    let Some(runtime) = runtime().await else {
        return;
    };
    let uuid = Uuid::new_v4();
    let prefix = format!("test:reset:{uuid}:");
    let keep = format!("test:keep:{uuid}");

    for key in [format!("{prefix}a"), format!("{prefix}b")] {
        runtime
            .limiter()
            .incr_with_ttl(&key, 1, Duration::from_secs(60))
            .await
            .unwrap();
    }
    runtime
        .limiter()
        .incr_with_ttl(&keep, 1, Duration::from_secs(60))
        .await
        .unwrap();

    runtime.limiter().reset_prefix(&prefix).await.unwrap();

    assert_eq!(
        runtime
            .limiter()
            .get_count(&format!("{prefix}a"))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        runtime
            .limiter()
            .get_count(&format!("{prefix}b"))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        runtime.limiter().get_count(&keep).await.unwrap(),
        1,
        "非目标前缀不得被清理"
    );

    runtime.limiter().reset_prefix(&keep).await.unwrap();
}

/// Redis 不可达时构造失败（fail-closed），且错误文本不泄露 URL 凭据。
#[tokio::test(flavor = "multi_thread")]
async fn unreachable_redis_fails_closed_without_leaking_credentials() {
    let url = "rediss://user:secret@127.0.0.1:1/0";
    ensure_insecure_redis_allowed();
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        LimiterRuntime::from_config(&app_config(url), dao),
    )
    .await
    .expect("连接失败必须在超时内返回");

    let err = match result {
        Ok(_) => panic!("不可达 Redis 必须构造失败"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("config-rate-limit-redis-connect"),
        "错误应带统一前缀码，实际: {msg}"
    );
    assert!(
        !msg.contains("secret"),
        "错误文本不得包含 URL 凭据，实际: {msg}"
    );
}
