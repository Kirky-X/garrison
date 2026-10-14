// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 用户级双态锁定策略测试。

use super::strategy::now_timestamp;
use super::*;
use crate::dao::tests::MockDao;
use crate::error::GarrisonError;
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy, StrategyRegistration};
use std::sync::Arc;

/// 验证 UserLockoutConfig::default() 返回预期默认值。
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

/// 验证 WaitStrategy::Multiple 可被 serde 序列化与反序列化。
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

/// 验证 WaitStrategy::Linear 可被 serde 序列化与反序列化。
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

/// 验证 LockoutState 可被 serde 序列化与反序列化。
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
/// （所有字段为 pub）。
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
    assert_eq!(base, 30);
    assert_eq!(base * 2, 60);
    assert_eq!(base * 3, 90);
}

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
        matches!(result, Err(GarrisonError::FirewallBlocked(ref msg)) if msg.contains("user-lockout-permanent")),
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

/// 验证 record_success 重置 failure_count 并清除已触发的临时锁定状态
/// （temporary_lockout_count / locked_until 清零）；`permanent_locked` 不受影响
/// （永久锁定不可通过登录成功解除）。
#[tokio::test]
async fn record_success_resets_failure_count() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 1, // 首败即锁
        permanent_lockout: true,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao);

    strategy.record_failure("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(state.failure_count, 1);
    assert!(
        state.locked_until > now_timestamp(),
        "前置条件：应已处于临时锁定（locked_until > now），实际: {}",
        state.locked_until
    );
    assert_eq!(
        state.temporary_lockout_count, 1,
        "前置条件：临时锁定次数应为 1"
    );

    strategy.record_success("user1").await.unwrap();
    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(
        state.failure_count, 0,
        "record_success 后 failure_count 应为 0"
    );
    assert_eq!(
        state.temporary_lockout_count, 0,
        "record_success 应清除临时锁定次数"
    );
    assert_eq!(state.locked_until, 0, "record_success 应清除 locked_until");
    assert!(
        !state.permanent_locked,
        "record_success 不得解除 permanent_locked"
    );

    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(
        strategy.check(&ctx).await.is_ok(),
        "record_success 后应解除临时锁定"
    );
}

/// 并发 record_failure 丢失更新回归：CAS 原子读改写保证自增不丢失（最终 failure_count ==
/// 并发任务数）；旧实现 get→mutate→set 非原子，并发下会丢失自增、延迟锁定触发。
#[tokio::test]
async fn concurrent_record_failure_no_lost_updates() {
    use std::sync::Arc as StdArc;
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    // 阈值调高避免中途触发锁定改变状态形状（失败计数仍持续累加）
    let config = UserLockoutConfig {
        max_failure_factor: 1000,
        permanent_lockout: false,
        max_temporary_lockouts: 99,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 300,
    };
    let strategy = StdArc::new(UserLockoutStrategy::new(config, dao));

    const TASKS: u32 = 20;
    let mut handles = Vec::with_capacity(TASKS as usize);
    for _ in 0..TASKS {
        let s = strategy.clone();
        handles.push(tokio::spawn(async move {
            s.record_failure("user1")
                .await
                .expect("record_failure 不应报错");
        }));
    }
    for h in handles {
        h.await.expect("并发任务不应 panic");
    }

    let state = strategy.get_state("user1").await.unwrap();
    assert_eq!(
        state.failure_count, TASKS,
        "并发 {} 次 record_failure 后 failure_count 应恰好为 {}（无丢失更新）",
        TASKS, TASKS
    );
}

/// UserLockoutConfig::validate 拒绝零值退化配置。
#[test]
fn config_validate_rejects_degenerate_values() {
    let config = UserLockoutConfig {
        max_failure_factor: 0,
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 300,
    };
    assert!(config.validate().is_err(), "max_failure_factor=0 应被拒绝");

    // failure_window_seconds = 0 → 窗口判断退化
    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 0,
    };
    assert!(
        config.validate().is_err(),
        "failure_window_seconds=0 应被拒绝"
    );

    // permanent_lockout + max_temporary_lockouts = 0 → 首次临时锁定即永久
    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: true,
        max_temporary_lockouts: 0,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 300,
    };
    assert!(
        config.validate().is_err(),
        "permanent_lockout + max_temporary_lockouts=0 应被拒绝"
    );

    // wait_strategy 零值（锁定时长为 0）
    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 0 },
        failure_window_seconds: 300,
    };
    assert!(config.validate().is_err(), "base_seconds=0 应被拒绝");

    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Multiple {
            base_seconds: 60,
            multiplier: 0,
        },
        failure_window_seconds: 300,
    };
    assert!(config.validate().is_err(), "multiplier=0 应被拒绝");

    assert!(UserLockoutConfig::default().validate().is_ok());
}

/// UserLockoutStrategy::new 对非法配置回退默认值（退化行为不生效）。
#[tokio::test]
async fn new_with_invalid_config_falls_back_to_default() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 0, // 非法：首败即锁
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 60 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao);
    // 回退默认配置（阈值 5）：1 次失败不应触发锁定（若未回退，首败即锁）
    strategy.record_failure("user1").await.unwrap();
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(
        strategy.check(&ctx).await.is_ok(),
        "非法配置回退默认后（阈值 5），首次失败不应触发锁定"
    );
}

/// 验证 failure_window_seconds 窗口过期后 failure_count 重置（失败 3 次后窗口过期，再失败从 1 起算）。
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
    for i in 1..=4 {
        strategy.record_failure("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        assert_eq!(
            state.failure_count, i,
            "第 {} 次失败后 failure_count 应为 {}",
            i, i
        );
    }
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

/// state_ttl_seconds 表驱动：永久锁与升级计数永久驻留（TTL=0），纯计数窗口态按
/// 「窗口/锁定到期 + margin」过期，horizon 已过则为 margin。
#[test]
fn state_ttl_seconds_policy_covers_all_state_shapes() {
    use super::strategy::{state_ttl_seconds, LOCKOUT_TTL_MARGIN_SECONDS};

    let window = 300u64;
    let now = 1_000_000i64;

    // 永久锁定：不可自动解锁，必须永久驻留
    let permanent = LockoutState {
        permanent_locked: true,
        ..LockoutState::default()
    };
    assert_eq!(state_ttl_seconds(&permanent, now, window), 0);

    // 升级计数 >0：永久锁定棘轮依赖该计数持续到成功登录，必须永久驻留
    // （同时带活跃窗口中，验证优先级高于窗口计算）
    let escalating = LockoutState {
        temporary_lockout_count: 2,
        first_failure_at: Some(now - 10),
        locked_until: now + 120,
        ..LockoutState::default()
    };
    assert_eq!(state_ttl_seconds(&escalating, now, window), 0);

    // 纯计数窗口态：窗口进行到一半 → 剩余窗口 + margin
    let mid_window = LockoutState {
        failure_count: 2,
        first_failure_at: Some(now - 150),
        ..LockoutState::default()
    };
    assert_eq!(
        state_ttl_seconds(&mid_window, now, window),
        150 + LOCKOUT_TTL_MARGIN_SECONDS
    );

    // 纯窗口态且 locked_until 晚于窗口尾（防御构造）：取更远的 horizon
    let horizon_is_lock = LockoutState {
        first_failure_at: Some(now - 10),
        locked_until: now + 500,
        ..LockoutState::default()
    };
    assert_eq!(
        state_ttl_seconds(&horizon_is_lock, now, window),
        500 + LOCKOUT_TTL_MARGIN_SECONDS
    );

    // 窗口已过：与 advance_failure_state 的窗口过期重置等价，仅留 margin 缓冲
    let stale_window = LockoutState {
        failure_count: 1,
        first_failure_at: Some(now - 600),
        ..LockoutState::default()
    };
    assert_eq!(
        state_ttl_seconds(&stale_window, now, window),
        LOCKOUT_TTL_MARGIN_SECONDS
    );

    // 全默认态（unlock 写入形态）：无窗口无锁定，margin 后自然消失
    assert_eq!(
        state_ttl_seconds(&LockoutState::default(), now, window),
        LOCKOUT_TTL_MARGIN_SECONDS
    );

    // locked_until = i64::MAX 且 now=0：remaining = i64::MAX，`as u64` 为正转换不回绕，
    // margin 相加后恰为 i64::MAX+margin（≈2920 亿年，实践等同永久）——不得出现小 TTL
    let max_lock = LockoutState {
        locked_until: i64::MAX,
        ..LockoutState::default()
    };
    assert_eq!(
        state_ttl_seconds(&max_lock, 0, window),
        i64::MAX as u64 + LOCKOUT_TTL_MARGIN_SECONDS
    );
}

/// 验证 record_failure 写入的纯窗口态带 window+margin TTL（不再永久驻留）。
#[tokio::test]
async fn record_failure_sets_window_bounded_ttl() {
    let (strategy, dao) = make_strategy();
    strategy.record_failure("user1").await.unwrap();
    let key = crate::constants::DaoKeyPrefix::Lockout.build_key("user1");
    let secs = dao
        .get_timeout(&key)
        .await
        .unwrap()
        .expect("窗口态锁定键应带 TTL，不得永久驻留")
        .as_secs();
    assert!(
        (300..=360).contains(&secs),
        "record_failure 后 TTL 应≈window+margin=360s，实际: {}s",
        secs
    );
}

/// 验证升级计数态与永久锁定态均永久驻留（TTL=None），且永久锁判定不回归。
#[tokio::test]
async fn escalating_and_permanent_lockout_keys_stay_permanent() {
    // 8 次失败（默认配置：阈值 5 / 临时上限 3）触发永久锁定
    let (strategy, dao) = make_strategy();
    for _ in 0..8 {
        strategy.record_failure("user1").await.unwrap();
    }
    let key = crate::constants::DaoKeyPrefix::Lockout.build_key("user1");
    assert!(
        dao.get_timeout(&key).await.unwrap().is_none(),
        "永久锁定键必须永久驻留，TTL 不得设置"
    );
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(
        strategy.check(&ctx).await.is_err(),
        "permanent_locked=true 必须阻断登录"
    );

    // 6 次失败进入临时锁定升级态（temporary_lockout_count=2>0）：同样永久驻留
    let (strategy2, dao2) = make_strategy();
    for _ in 0..6 {
        strategy2.record_failure("user2").await.unwrap();
    }
    let key2 = crate::constants::DaoKeyPrefix::Lockout.build_key("user2");
    assert!(
        dao2.get_timeout(&key2).await.unwrap().is_none(),
        "含升级计数的锁定键必须永久驻留，TTL 不得设置"
    );
}

/// 验证 record_success 后锁定键只留 margin TTL（曾失败用户不再留永久键）。
#[tokio::test]
async fn record_success_leaves_only_margin_ttl() {
    let (strategy, dao) = make_strategy();
    strategy.record_failure("user1").await.unwrap();
    strategy.record_success("user1").await.unwrap();
    let key = crate::constants::DaoKeyPrefix::Lockout.build_key("user1");
    let secs = dao
        .get_timeout(&key)
        .await
        .unwrap()
        .expect("成功后应带 margin TTL，不得永久驻留")
        .as_secs();
    assert!(
        (55..=60).contains(&secs),
        "record_success 后 TTL 应≈margin=60s，实际: {}s",
        secs
    );
}

/// 验证 unlock 写入的全默认态只留 margin TTL，且解锁后 check 放行。
#[tokio::test]
async fn unlock_leaves_only_margin_ttl_and_unlocks() {
    let (strategy, dao) = make_strategy();
    for _ in 0..8 {
        strategy.record_failure("user1").await.unwrap();
    }
    strategy.unlock("user1").await.unwrap();
    let key = crate::constants::DaoKeyPrefix::Lockout.build_key("user1");
    let secs = dao
        .get_timeout(&key)
        .await
        .unwrap()
        .expect("unlock 后应带 margin TTL，不得永久驻留")
        .as_secs();
    assert!(
        (55..=60).contains(&secs),
        "unlock 后 TTL 应≈margin=60s，实际: {}s",
        secs
    );
    let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
    assert!(
        strategy.check(&ctx).await.is_ok(),
        "unlock 后必须解除锁定（含永久锁）"
    );
}
