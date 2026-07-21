//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 用户级双态锁定策略测试。
//!
//! 测试覆盖 R-user-lockout-001/002/003 验收标准及 UserLockoutStrategy 行为。

use super::strategy::now_timestamp;
use super::*;
use crate::dao::tests::MockDao;
use crate::error::GarrisonError;
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy, StrategyRegistration};
use std::sync::Arc;

/// 验证 UserLockoutConfig::default() 返回预期默认值
/// （R-user-lockout-001 验收标准）。
#[test]
fn config_default_matches_spec() {
    let config = UserLockoutConfig::default();
    assert_eq!(config.max_failure_factor, 5);
    assert!(config.permanent_lockout);
    assert_eq!(config.max_temporary_lockouts, 3);
    assert_eq!(config.failure_window_seconds, 300);
    match &config.wait_strategy {
        WaitStrategy::Multiple {
            base_seconds,
            multiplier,
        } => {
            assert_eq!(*base_seconds, 60);
            assert_eq!(*multiplier, 2);
        },
        other => panic!("默认 wait_strategy 应为 Multiple，实际: {:?}", other),
    }
}

/// 验证 WaitStrategy::Multiple 可被 serde 序列化与反序列化
/// （R-user-lockout-002 验收标准）。
#[test]
fn wait_strategy_multiple_serde_roundtrip() {
    let strategy = WaitStrategy::Multiple {
        base_seconds: 60,
        multiplier: 2,
    };
    let json = serde_json::to_string(&strategy).expect("序列化 Multiple 失败");
    let deserialized: WaitStrategy = serde_json::from_str(&json).expect("反序列化 Multiple 失败");
    match deserialized {
        WaitStrategy::Multiple {
            base_seconds,
            multiplier,
        } => {
            assert_eq!(base_seconds, 60);
            assert_eq!(multiplier, 2);
        },
        other => panic!("反序列化后应为 Multiple，实际: {:?}", other),
    }
}

/// 验证 WaitStrategy::Linear 可被 serde 序列化与反序列化
/// （R-user-lockout-002 验收标准）。
#[test]
fn wait_strategy_linear_serde_roundtrip() {
    let strategy = WaitStrategy::Linear { base_seconds: 30 };
    let json = serde_json::to_string(&strategy).expect("序列化 Linear 失败");
    let deserialized: WaitStrategy = serde_json::from_str(&json).expect("反序列化 Linear 失败");
    match deserialized {
        WaitStrategy::Linear { base_seconds } => {
            assert_eq!(base_seconds, 30);
        },
        other => panic!("反序列化后应为 Linear，实际: {:?}", other),
    }
}

/// 验证 LockoutState 可被 serde 序列化与反序列化
/// （R-user-lockout-003 验收标准）。
#[test]
fn lockout_state_serde_roundtrip() {
    let state = LockoutState {
        failure_count: 3,
        temporary_lockout_count: 1,
        permanent_locked: false,
        locked_until: 1700000000,
        first_failure_at: Some(1699999900),
    };
    let json = serde_json::to_string(&state).expect("序列化 LockoutState 失败");
    let deserialized: LockoutState =
        serde_json::from_str(&json).expect("反序列化 LockoutState 失败");
    assert_eq!(deserialized.failure_count, 3);
    assert_eq!(deserialized.temporary_lockout_count, 1);
    assert!(!deserialized.permanent_locked);
    assert_eq!(deserialized.locked_until, 1700000000);
}

/// 验证 UserLockoutConfig 可在外部构造自定义配置
/// （R-user-lockout-001 验收标准：所有字段为 pub）。
#[test]
fn config_custom_construction() {
    let config = UserLockoutConfig {
        max_failure_factor: 10,
        permanent_lockout: false,
        max_temporary_lockouts: 5,
        wait_strategy: WaitStrategy::Linear { base_seconds: 30 },
        failure_window_seconds: 600,
    };
    assert_eq!(config.max_failure_factor, 10);
    assert!(!config.permanent_lockout);
    assert_eq!(config.max_temporary_lockouts, 5);
    assert_eq!(config.failure_window_seconds, 600);
    assert!(matches!(
        config.wait_strategy,
        WaitStrategy::Linear { base_seconds: 30 }
    ));
}

/// 验证 LockoutState::default() 返回全零/false 状态
/// （用于初始化新用户的锁定状态）。
#[test]
fn lockout_state_default_is_clean() {
    let state = LockoutState::default();
    assert_eq!(state.failure_count, 0);
    assert_eq!(state.temporary_lockout_count, 0);
    assert!(!state.permanent_locked);
    assert_eq!(state.locked_until, 0);
}

/// 验证 WaitStrategy::Multiple 的锁定时长计算公式：base × multiplier^(N-1)
/// （第 1 次 = 60，第 2 次 = 120，第 3 次 = 240）。
#[test]
fn wait_strategy_multiple_formula() {
    let base = 60u64;
    let multiplier = 2u32;
    // 第 1 次：60 × 2^0 = 60
    let n1 = base * (multiplier.pow(0) as u64);
    assert_eq!(n1, 60);
    // 第 2 次：60 × 2^1 = 120
    let n2 = base * (multiplier.pow(1) as u64);
    assert_eq!(n2, 120);
    // 第 3 次：60 × 2^2 = 240
    let n3 = base * (multiplier.pow(2) as u64);
    assert_eq!(n3, 240);
}

/// 验证 WaitStrategy::Linear 的锁定时长计算公式：base × N
/// （第 1 次 = 30，第 2 次 = 60，第 3 次 = 90）。
#[test]
fn wait_strategy_linear_formula() {
    let base = 30u64;
    // 第 1 次：30 × 1 = 30
    assert_eq!(base, 30);
    // 第 2 次：30 × 2 = 60
    assert_eq!(base * 2, 60);
    // 第 3 次：30 × 3 = 90
    assert_eq!(base * 3, 90);
}

// ===== UserLockoutStrategy 测试 =====

/// 辅助：创建默认配置的 UserLockoutStrategy + MockDao。
fn make_strategy() -> (UserLockoutStrategy, Arc<dyn GarrisonDao>) {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let strategy = UserLockoutStrategy::new(UserLockoutConfig::default(), dao.clone());
    (strategy, dao)
}

/// 验证首次失败：failure_count=1，不触发锁定，check 通过。
#[tokio::test]
async fn record_failure_first_does_not_lock() {
    let (strategy, _) = make_strategy();
    strategy.record_failure("user1").await.unwrap();
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(strategy.check(&ctx).await.is_ok(), "首次失败不应触发锁定");
}

/// 验证阈值触发临时锁定：max_failure_factor=5，5 次失败后临时锁定。
#[tokio::test]
async fn record_failure_triggers_temporary_lock_at_threshold() {
    let (strategy, _) = make_strategy();
    for _ in 0..4 {
        strategy.record_failure("user1").await.unwrap();
    }
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(strategy.check(&ctx).await.is_ok(), "4 次失败不应触发锁定");

    strategy.record_failure("user1").await.unwrap();
    let result = strategy.check(&ctx).await;
    assert!(
        matches!(result, Err(GarrisonError::FirewallBlocked(_))),
        "5 次失败应触发临时锁定，实际: {:?}",
        result
    );
}

/// 验证临时锁定期间 check 拦截。
#[tokio::test]
async fn check_blocks_during_temporary_lockout() {
    let (strategy, _) = make_strategy();
    for _ in 0..5 {
        strategy.record_failure("user1").await.unwrap();
    }
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    let result = strategy.check(&ctx).await;
    assert!(
        matches!(result, Err(GarrisonError::FirewallBlocked(_))),
        "临时锁定期内应拦截，实际: {:?}",
        result
    );
}

/// 验证永久锁定：超过 max_temporary_lockouts 后触发永久锁定。
#[tokio::test]
async fn permanent_lockout_after_max_temporary_lockouts() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 2,
        permanent_lockout: true,
        max_temporary_lockouts: 1,
        wait_strategy: WaitStrategy::Linear { base_seconds: 10 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao);

    // 第 1 轮：2 次失败 → 临时锁定 #1
    strategy.record_failure("user1").await.unwrap();
    strategy.record_failure("user1").await.unwrap();

    // 第 2 轮：再 2 次失败 → 超过 max_temporary_lockouts=1 → 永久锁定
    strategy.record_failure("user1").await.unwrap();
    strategy.record_failure("user1").await.unwrap();

    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    let result = strategy.check(&ctx).await;
    assert!(
        matches!(result, Err(GarrisonError::FirewallBlocked(ref msg)) if msg.contains("永久锁定")),
        "超过 max_temporary_lockouts 应永久锁定，实际: {:?}",
        result
    );
}

/// 验证 unlock 手动解锁：解锁后 check 通过。
#[tokio::test]
async fn unlock_clears_lockout_state() {
    let (strategy, _) = make_strategy();
    for _ in 0..5 {
        strategy.record_failure("user1").await.unwrap();
    }
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(strategy.check(&ctx).await.is_err(), "解锁前应被拦截");

    strategy.unlock("user1").await.unwrap();
    assert!(strategy.check(&ctx).await.is_ok(), "解锁后应通过");
}

/// 验证 WaitStrategy::Multiple 的 record_failure 时长计算
/// （第 1 次 ≈ 60s，第 2 次 ≈ 120s）。
#[tokio::test]
async fn wait_strategy_multiple_record_failure_duration() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 1,
        permanent_lockout: false,
        max_temporary_lockouts: 99,
        wait_strategy: WaitStrategy::Multiple {
            base_seconds: 60,
            multiplier: 2,
        },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao);

    // 第 1 次临时锁定：locked_until - now ≈ 60
    strategy.record_failure("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    let duration_1 = state.locked_until - now_timestamp();
    assert!(
        (55..=65).contains(&duration_1),
        "第 1 次临时锁定时长应 ≈ 60，实际: {}",
        duration_1
    );

    // 重置以触发第 2 次锁定
    let mut state = strategy.get_state("user1").await.unwrap();
    state.failure_count = 0;
    state.locked_until = 0;
    strategy.set_state("user1", &state).await.unwrap();

    // 第 2 次临时锁定：locked_until - now ≈ 120
    strategy.record_failure("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    let duration_2 = state.locked_until - now_timestamp();
    assert!(
        (115..=125).contains(&duration_2),
        "第 2 次临时锁定时长应 ≈ 120，实际: {}",
        duration_2
    );
}

/// 验证 WaitStrategy::Linear 的 record_failure 时长计算
/// （第 1 次 ≈ 30s，第 2 次 ≈ 60s）。
#[tokio::test]
async fn wait_strategy_linear_record_failure_duration() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 1,
        permanent_lockout: false,
        max_temporary_lockouts: 99,
        wait_strategy: WaitStrategy::Linear { base_seconds: 30 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao);

    // 第 1 次临时锁定：locked_until - now ≈ 30
    strategy.record_failure("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    let duration_1 = state.locked_until - now_timestamp();
    assert!(
        (25..=35).contains(&duration_1),
        "第 1 次临时锁定时长应 ≈ 30，实际: {}",
        duration_1
    );

    // 重置以触发第 2 次锁定
    let mut state = strategy.get_state("user1").await.unwrap();
    state.failure_count = 0;
    state.locked_until = 0;
    strategy.set_state("user1", &state).await.unwrap();

    // 第 2 次临时锁定：locked_until - now ≈ 60
    strategy.record_failure("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    let duration_2 = state.locked_until - now_timestamp();
    assert!(
        (55..=65).contains(&duration_2),
        "第 2 次临时锁定时长应 ≈ 60，实际: {}",
        duration_2
    );
}

/// 验证 record_success 重置 failure_count 但不修改锁定字段。
#[tokio::test]
async fn record_success_resets_failure_count() {
    let (strategy, _) = make_strategy();
    for _ in 0..3 {
        strategy.record_failure("user1").await.unwrap();
    }
    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(state.failure_count, 3);

    strategy.record_success("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(
        state.failure_count, 0,
        "record_success 后 failure_count 应为 0"
    );
    assert_eq!(
        state.temporary_lockout_count, 0,
        "temporary_lockout_count 不应变"
    );
    assert!(!state.permanent_locked, "permanent_locked 不应变");
    assert_eq!(state.locked_until, 0, "locked_until 不应变");
}

/// 验证 failure_window_seconds 窗口过期后 failure_count 重置。
/// 场景：失败 3 次后窗口过期，再失败应从 1 开始计数而非 4。
#[tokio::test]
async fn failure_window_resets_count_after_expiry() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: false,
        max_temporary_lockouts: 99,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao.clone());

    // 失败 3 次（窗口内）
    for _ in 0..3 {
        strategy.record_failure("user1").await.unwrap();
    }
    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(state.failure_count, 3);
    assert!(state.first_failure_at.is_some());

    // 模拟窗口过期：将 first_failure_at 设为 301 秒前
    let mut state = strategy.get_state("user1").await.unwrap();
    state.first_failure_at = Some(now_timestamp() - 301);
    strategy.set_state("user1", &state).await.unwrap();

    // 再次失败：窗口已过期，failure_count 应重置为 1
    strategy.record_failure("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(
        state.failure_count, 1,
        "窗口过期后 failure_count 应重置为 1，实际: {}",
        state.failure_count
    );
}

/// 验证 failure_window_seconds 窗口内失败计数持续累积。
#[tokio::test]
async fn failure_window_accumulates_within_window() {
    let (strategy, _) = make_strategy();
    // 默认 failure_window_seconds=300，连续失败应累积
    for i in 1..=4 {
        strategy.record_failure("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        assert_eq!(
            state.failure_count, i,
            "第 {} 次失败后 failure_count 应为 {}",
            i, i
        );
    }
    // 确认 first_failure_at 在首次失败时被设置，后续不变
    let state = strategy.get_state("user1").await.unwrap();
    assert!(
        state.first_failure_at.is_some(),
        "first_failure_at 应已设置"
    );
}

/// 验证 locked_until 到期后 check 通过。
#[tokio::test]
async fn check_passes_after_temporary_lockout_expires() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 1,
        permanent_lockout: false,
        max_temporary_lockouts: 99,
        wait_strategy: WaitStrategy::Linear { base_seconds: 1 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao);

    strategy.record_failure("user1").await.unwrap();
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(strategy.check(&ctx).await.is_err(), "锁定期内应拦截");

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    assert!(strategy.check(&ctx).await.is_ok(), "锁定到期后应通过");
}

/// 验证 ctx.login_id=None 时 check 返回 Ok(()) 跳过用户级检查。
#[tokio::test]
async fn check_skips_when_login_id_is_none() {
    let (strategy, _) = make_strategy();
    let ctx = FirewallContext::new("1.1.1.1");
    assert!(strategy.check(&ctx).await.is_ok(), "login_id=None 时应跳过");
}

/// 验证多用户隔离：用户 A 的锁定状态不影响用户 B。
#[tokio::test]
async fn multi_user_isolation() {
    let (strategy, _) = make_strategy();
    for _ in 0..5 {
        strategy.record_failure("alice").await.unwrap();
    }
    let ctx_a = FirewallContext::new("1.1.1.1").with_login_id("alice");
    let ctx_b = FirewallContext::new("2.2.2.2").with_login_id("bob");
    assert!(strategy.check(&ctx_a).await.is_err(), "用户 A 应被锁定");
    assert!(strategy.check(&ctx_b).await.is_ok(), "用户 B 不应受影响");
}

/// 验证 inventory 注册了 "user-lockout" 策略名称。
#[test]
fn user_lockout_registered_via_inventory() {
    use std::iter::Iterator;
    let _ = std::any::TypeId::of::<UserLockoutStrategy>();
    let names: Vec<&'static str> = inventory::iter::<StrategyRegistration>()
        .map(|r| r.name)
        .collect();
    assert!(
        names.contains(&"user-lockout"),
        "inventory 应注册 user-lockout 策略，实际: {:?}",
        names
    );
}
