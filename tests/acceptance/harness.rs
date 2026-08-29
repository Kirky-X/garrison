//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! harness 自检测试（ACC-HARNESS-NNN）。
//!
//! 验证 `common::harness` 的 [`GarrisonTestHarness`] / [`MockInterface`] / [`with_tenant`]。
//! `GarrisonManager` 为进程级全局单例，全部用例以 `#[serial]` 串行。
//!
//! 场景编号约定：`ACC-<域>-NNN（正常|异常）`，本域为 `harness`。

use crate::common::harness::{with_tenant, GarrisonTestHarness, MockInterface};
use garrison::error::GarrisonError;
use garrison::manager::GarrisonManager;
use garrison::stp::{with_current_token, GarrisonUtil, LoginParams};
use serial_test::serial;

/// ACC-HARNESS-001（正常+异常）：默认 `init()` 后 `GarrisonUtil::login` 可用、
/// 签发 token 可通过 `check_login` 并解析回原主体；伪造 token 必须被拒。
#[tokio::test]
#[serial]
async fn acc_harness_001_init_supports_login_and_check_login() {
    let _harness = GarrisonTestHarness::builder()
        .init()
        .await
        .expect("默认 harness init 应成功");

    let token = GarrisonUtil::login("1001", &LoginParams::default())
        .await
        .expect("login 应签发 token");
    assert!(!token.is_empty(), "签发的 token 不应为空串");

    let (logged_in, login_id) = with_current_token(token.clone(), async {
        (
            GarrisonUtil::check_login()
                .await
                .expect("有效 token 不应报错"),
            GarrisonUtil::get_login_id()
                .await
                .expect("get_login_id 不应报错"),
        )
    })
    .await;
    assert!(logged_in, "有效 token 的 check_login 应为 true");
    assert_eq!(login_id.as_deref(), Some("1001"), "应解析回登录主体");

    let forged =
        with_current_token("not-a-real-token".to_string(), GarrisonUtil::check_login()).await;
    assert!(forged.is_err(), "伪造 token 不应通过 check_login");
}

/// ACC-HARNESS-002（正常+异常）：`allow()` 声明的权限可命中，`deny_all()` 后全部不命中。
#[tokio::test]
#[serial]
async fn acc_harness_002_permission_grant_then_deny_all() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &["user"]);
    let _harness = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .init()
        .await
        .expect("注入 interface 后 init 应成功");

    let token = GarrisonUtil::login("1001", &LoginParams::default())
        .await
        .expect("login 应签发 token");

    let granted = with_current_token(
        token.clone(),
        with_tenant(1, GarrisonUtil::has_permission("user:read")),
    )
    .await
    .expect("已声明权限的查询不应报错");
    assert!(granted, "allow 声明的权限应命中");

    let not_granted = with_current_token(
        token.clone(),
        with_tenant(1, GarrisonUtil::has_permission("user:write")),
    )
    .await
    .expect("未声明权限的查询不应报错");
    assert!(!not_granted, "未声明的权限不应命中");

    interface.deny_all();
    let after_deny = with_current_token(
        token,
        with_tenant(1, GarrisonUtil::has_permission("user:read")),
    )
    .await
    .expect("deny_all 后查询本身不应报错");
    assert!(!after_deny, "deny_all 后原权限应失效");
}

/// ACC-HARNESS-003（异常）：`fail_with` 注入的错误必须原样上抛，不得被降级为 `Ok(false)`。
#[tokio::test]
#[serial]
async fn acc_harness_003_injected_interface_error_propagates() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &["user"]);
    let _harness = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login("1001", &LoginParams::default())
        .await
        .expect("login 应签发 token");

    interface.fail_with(|| GarrisonError::Dao("harness-selfcheck-injected".to_string()));
    let result = with_current_token(
        token,
        with_tenant(1, GarrisonUtil::has_permission("user:read")),
    )
    .await;
    match result {
        Err(GarrisonError::Dao(msg)) => assert!(
            msg.contains("harness-selfcheck-injected"),
            "应透传注入的错误码，实际: {msg}"
        ),
        other => panic!("注入错误应原样上抛，实际: {other:?}"),
    }

    interface.clear_failure();
    let fresh_token = GarrisonUtil::login("1001", &LoginParams::default())
        .await
        .expect("清除错误后应能再次登录");
    let recovered = with_current_token(
        fresh_token,
        with_tenant(1, GarrisonUtil::has_permission("user:read")),
    )
    .await;
    assert!(
        recovered.expect("clear_failure 后查询应恢复"),
        "清除错误注入后权限查询应恢复正常"
    );
}

/// ACC-HARNESS-004（异常）：单例被占用期间的第二次 `init()` 必须显性报错，
/// 而不是静默覆盖（`src/stp/session.rs` 的 brute-force flaky 即源于此类串扰）。
#[tokio::test]
#[serial]
async fn acc_harness_004_second_init_while_harness_alive_is_rejected() {
    let _harness = GarrisonTestHarness::builder()
        .init()
        .await
        .expect("首次 init 应成功");

    let second = GarrisonTestHarness::builder().init().await;
    match second {
        Err(GarrisonError::Config(msg)) => assert!(
            msg.contains("harness-concurrent-init"),
            "应报并发 init 错误，实际: {msg}"
        ),
        other => panic!(
            "占用期间的第二次 init 应报 Config 错误，实际 is_ok={}",
            other.is_ok()
        ),
    }
}

/// ACC-HARNESS-005（正常+异常）：`reset()` 后全局单例回到未初始化，
/// 重新 `init()` 后上一个主体的旧 token 不再有效（连续 init/reset 不串扰）。
#[cfg(feature = "testing")]
#[tokio::test]
#[serial]
async fn acc_harness_005_reset_then_reinit_does_not_cross_talk() {
    let harness = GarrisonTestHarness::builder()
        .init()
        .await
        .expect("首次 init 应成功");
    let token = GarrisonUtil::login("1001", &LoginParams::default())
        .await
        .expect("login 应签发 token");
    assert!(GarrisonManager::is_initialized(), "init 后单例应已就绪");

    harness.reset().expect("testing feature 下 reset 应成功");
    assert!(
        !GarrisonManager::is_initialized(),
        "reset 后全局单例应恢复为未初始化"
    );

    let _second = GarrisonTestHarness::builder()
        .init()
        .await
        .expect("reset 后再次 init 应成功");
    let stale = with_current_token(token, GarrisonUtil::check_login()).await;
    assert!(
        stale.is_err(),
        "旧 token 在新单例下不应继续有效，实际: {stale:?}"
    );
}
