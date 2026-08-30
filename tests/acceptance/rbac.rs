//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! rbac 域验收（spec `acceptance-matrix` R-acceptance-matrix-002，
//! 任务 T022）。权限 / 角色 / 层级继承 / 组合语义 / web 注解路由 / 策略热替换 /
//! 数据源故障，「正常 + 异常」成对覆盖，场景编号 `ACC-RBAC-NNN`。
//!
//! 经 `GarrisonTestHarness` 全局单例的用例（001-004、007-009）标注 `#[serial]`；
//! 层级与组合用例（005-006）直构 `GarrisonPermissionStrategyDefault`
//! （无全局状态，可并行）；008 策略注册表热替换使用 `multi_thread` flavor
//! （与 tests/integration/strategy_registry.rs 一致）。
//!
//! # API 偏差记录
//!
//! `Annotation::CheckOr/CheckAnd/CheckNot` 在 `DefaultGarrisonInterceptor::pre_handle`
//! 中为文档化 no-op（src/router/interceptor.rs:59-67），无法经 router 断言组合短路
//! 语义；故 Or/And/Not 短路语义在策略层断言（`check_role_any` = Or 命中其一即过、
//! `check_role_all` = And 全部满足、未持有即拒绝 = Not 反转），web 层仅覆盖
//! `CheckPermission` / `CheckRole` 注解路由（200/403）。
//!
//! `full` 含 `tenant-isolation`：权限 / 角色校验路径 fail-closed，需要
//! `with_tenant` 作用域（tests/common/harness.rs 的 `with_tenant`）。

use crate::common::harness::{with_tenant, GarrisonTestHarness, MockInterface};
use garrison::config::GarrisonConfig;
use garrison::error::GarrisonError;
use garrison::stp::{with_current_token, GarrisonUtil};
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;

/// 测试统一配置：`throw_on_not_login = false`（与仓库集成测试 `make_config()`
/// 惯例一致；本域断言均在登录后执行，该开关仅兜底未登录降级路径）。
fn test_config() -> Arc<GarrisonConfig> {
    let mut c = GarrisonConfig::default_config();
    c.throw_on_not_login = false;
    Arc::new(c)
}

// ------------------------------------------------------------------------
// ACC-RBAC-001..004：权限 / 角色（正常 + 异常）
// ------------------------------------------------------------------------

/// ACC-RBAC-001（正常）：权限通过——`MockInterface.allow` 注入 → `login_simple`
/// → `with_current_token` + `GarrisonUtil::check_permission` 返回 Ok、`has_permission`
/// 返回 true、`get_permission_list` 可读回注入的权限。
#[tokio::test]
#[serial]
async fn acc_rbac_001_permission_granted_passes() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read", "user:write"], &[]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface)
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");

    with_tenant(0, async {
        with_current_token(token, async {
            GarrisonUtil::check_permission("user:read")
                .await
                .expect("注入 user:read 后 check_permission 应通过");
            GarrisonUtil::check_permission("user:write")
                .await
                .expect("注入 user:write 后 check_permission 应通过");
            assert!(
                GarrisonUtil::has_permission("user:read")
                    .await
                    .expect("has_permission 不应报错"),
                "持有权限时 has_permission 应为 true"
            );
            let list = GarrisonUtil::get_permission_list()
                .await
                .expect("get_permission_list 不应报错");
            assert!(
                list.iter().any(|p| p == "user:read") && list.iter().any(|p| p == "user:write"),
                "权限列表应读回注入值，实际: {list:?}"
            );
        })
        .await;
    })
    .await;
}

/// ACC-RBAC-002（正常）：角色通过——`MockInterface.allow` 注入角色 →
/// `check_role` 返回 Ok、`has_role` 返回 true、`get_role_list` 可读回注入角色。
#[tokio::test]
#[serial]
async fn acc_rbac_002_role_granted_passes() {
    let interface = MockInterface::new();
    interface.allow("1001", &[], &["admin", "ops"]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface)
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");

    with_tenant(0, async {
        with_current_token(token, async {
            GarrisonUtil::check_role("admin")
                .await
                .expect("注入 admin 后 check_role 应通过");
            assert!(
                GarrisonUtil::has_role("ops")
                    .await
                    .expect("has_role 不应报错"),
                "持有角色时 has_role 应为 true"
            );
            let list = GarrisonUtil::get_role_list()
                .await
                .expect("get_role_list 不应报错");
            assert!(
                list.iter().any(|r| r == "admin") && list.iter().any(|r| r == "ops"),
                "角色列表应读回注入值，实际: {list:?}"
            );
        })
        .await;
    })
    .await;
}

/// ACC-RBAC-003（异常）：无权限——未注入权限的主体 `check_permission` 返回
/// `Err(GarrisonError::NotPermission)`（显性拒绝），`has_permission` 降级为
/// `Ok(false)`（布尔查询不抛异常）。
#[tokio::test]
#[serial]
async fn acc_rbac_003_permission_denied_returns_not_permission() {
    let interface = MockInterface::new();
    interface.allow("1001", &[], &[]); // 无任何权限
    let _h = GarrisonTestHarness::builder()
        .interface(interface)
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");

    with_tenant(0, async {
        with_current_token(token, async {
            let err = GarrisonUtil::check_permission("user:read").await;
            assert!(
                matches!(err, Err(GarrisonError::NotPermission(_))),
                "无权限应返回 NotPermission，实际: {err:?}"
            );
            assert!(
                !GarrisonUtil::has_permission("user:read")
                    .await
                    .expect("has_permission 不应报错"),
                "无权限时 has_permission 应为 false（非异常）"
            );
        })
        .await;
    })
    .await;
}

/// ACC-RBAC-004（异常）：无角色——未注入角色的主体 `check_role` 返回
/// `Err(GarrisonError::NotRole)`，`has_role` 降级为 `Ok(false)`。
#[tokio::test]
#[serial]
async fn acc_rbac_004_role_denied_returns_not_role() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &[]); // 有权限但无角色
    let _h = GarrisonTestHarness::builder()
        .interface(interface)
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");

    with_tenant(0, async {
        with_current_token(token, async {
            let err = GarrisonUtil::check_role("admin").await;
            assert!(
                matches!(err, Err(GarrisonError::NotRole(_))),
                "无角色应返回 NotRole，实际: {err:?}"
            );
            assert!(
                !GarrisonUtil::has_role("admin")
                    .await
                    .expect("has_role 不应报错"),
                "无角色时 has_role 应为 false（非异常）"
            );
        })
        .await;
    })
    .await;
}

// ------------------------------------------------------------------------
// ACC-RBAC-005..006：角色层级继承 / Or-And-Not 组合语义（直构策略）
// ------------------------------------------------------------------------

/// ACC-RBAC-005（正常+异常）：角色层级继承——`with_role_hierarchy` 注入
/// `{"admin": ["user"], "superadmin": ["admin"]}` 后，持有 `superadmin` 的主体
/// 经传递展开可继承 `admin` 与 `user`（多层传递）；未注入层级时同数据源
/// `check_role("user")` 为 false（注入路径确实生效）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_rbac_005_role_hierarchy_transitive_inheritance() {
    use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};

    let hierarchy = HashMap::from([
        ("admin".to_string(), vec!["user".to_string()]),
        ("superadmin".to_string(), vec!["admin".to_string()]),
    ]);

    // 对照组：未注入层级，直接匹配（不继承）
    let plain = MockInterface::new();
    plain.allow("1001", &[], &["superadmin"]);
    let strategy_plain = GarrisonPermissionStrategyDefault::new(plain);
    assert!(
        !strategy_plain.check_role("1001", "user").await.unwrap(),
        "未注入层级时 superadmin 不应隐含 user"
    );

    // 实验组：注入层级 → 两层传递继承
    let hierarchical = MockInterface::new();
    hierarchical.allow("1001", &[], &["superadmin"]);
    let strategy =
        GarrisonPermissionStrategyDefault::new(hierarchical).with_role_hierarchy(hierarchy);
    assert!(
        strategy.check_role("1001", "user").await.unwrap(),
        "superadmin 应经 admin 传递继承 user（两层）"
    );
    assert!(
        strategy.check_role("1001", "admin").await.unwrap(),
        "superadmin 应直接继承 admin"
    );
    assert!(
        strategy.check_role("1001", "superadmin").await.unwrap(),
        "superadmin 持有自身角色"
    );
    assert!(
        !strategy.check_role("1001", "staff").await.unwrap(),
        "无关角色不应被继承"
    );
}

/// ACC-RBAC-006（正常+异常）：Or/And/Not 组合短路语义——`check_role_any` 命中
/// 其一即过（Or）；`check_role_all` 全部满足才过（And）；`check_role` 对未持有
/// 角色返回 false（Not 反转：负面断言成立）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_rbac_006_combination_short_circuit_semantics() {
    use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};

    let interface = MockInterface::new();
    interface.allow("1001", &[], &["user", "readonly"]);
    let hierarchy = HashMap::from([("admin".to_string(), vec!["user".to_string()])]);
    let strategy = GarrisonPermissionStrategyDefault::new(interface).with_role_hierarchy(hierarchy);

    // Or：命中其一即过（含层级隐含命中）
    assert!(
        strategy
            .check_role_any("1001", &["admin", "user"])
            .await
            .unwrap(),
        "Or 组合命中 user 即通过"
    );
    assert!(
        strategy
            .check_role_any("1001", &["ops", "readonly"])
            .await
            .unwrap(),
        "Or 组合命中 readonly 即通过"
    );
    assert!(
        !strategy
            .check_role_any("1001", &["admin", "owner"])
            .await
            .unwrap(),
        "Or 组合一个都不命中时应拒绝（admin 仅隐含未持有）"
    );

    // And：全部满足才行
    assert!(
        strategy
            .check_role_all("1001", &["user", "readonly"])
            .await
            .unwrap(),
        "And 组合全部持有应通过"
    );
    assert!(
        !strategy
            .check_role_all("1001", &["admin", "user"])
            .await
            .unwrap(),
        "And 组合缺 admin 时应拒绝（admin 是目标而非持有）"
    );
    assert!(
        !strategy
            .check_role_all("1001", &["readonly", "owner"])
            .await
            .unwrap(),
        "And 组合任一缺失时应拒绝"
    );

    // Not：反转——持有 user 的同时未持有 admin，负面断言成立
    assert!(
        strategy.check_role("1001", "user").await.unwrap(),
        "持有 user 的正面断言通过"
    );
    assert!(
        !strategy.check_role("1001", "admin").await.unwrap(),
        "NOT(admin)：未持有 admin（层级只做单向展开）"
    );
    assert!(
        !strategy.check_role("1001", "owner").await.unwrap(),
        "NOT(owner)：未持有 owner"
    );
}

// ------------------------------------------------------------------------
// ACC-RBAC-007：web 注解路由（正常 + 异常）
// ------------------------------------------------------------------------

/// ACC-RBAC-007（正常+异常）：`GarrisonRouter::route_protected` + tower
/// `ServiceExt::oneshot`——`CheckPermission` / `CheckRole` 注解路由：持有方返回
/// 200，未持有方返回 403 且响应体带结构化错误码（`NOT_PERMISSION` / `NOT_ROLE`）。
#[cfg(feature = "web-axum")]
#[tokio::test]
#[serial]
async fn acc_rbac_007_web_route_annotations_grant_and_deny() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use garrison::annotation::Annotation;
    use garrison::router::GarrisonRouter;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &["admin"]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface)
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");

    let app = GarrisonRouter::new(test_config())
        .route_protected(
            "/perm",
            || async { "perm ok" },
            Annotation::CheckPermission("user:read".to_string()),
        )
        .route_protected(
            "/role",
            || async { "role ok" },
            Annotation::CheckRole("admin".to_string()),
        )
        .build();

    let make_request = |path: &str, token: &str| {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };

    with_tenant(0, async {
        // 正常：持有权限 / 角色 → 200
        let token = GarrisonUtil::login_simple("1001")
            .await
            .expect("login 应签发 token");
        let resp = app
            .clone()
            .oneshot(make_request("/perm", &token))
            .await
            .expect("请求不应失败");
        assert_eq!(resp.status(), StatusCode::OK, "持有权限访问 /perm 应 200");
        let resp = app
            .clone()
            .oneshot(make_request("/role", &token))
            .await
            .expect("请求不应失败");
        assert_eq!(resp.status(), StatusCode::OK, "持有角色访问 /role 应 200");

        // 异常：无权限 / 无角色主体 → 403 + 结构化错误码
        let ghost = GarrisonUtil::login_simple("ghost-1002")
            .await
            .expect("login 应签发 token");
        let resp = app
            .clone()
            .oneshot(make_request("/perm", &ghost))
            .await
            .expect("请求不应失败");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "无权限访问 /perm 应 403"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body_str.contains("\"error_code\":\"NOT_PERMISSION\""),
            "403 响应体应含 NOT_PERMISSION，实际: {body_str}"
        );

        let resp = app
            .oneshot(make_request("/role", &ghost))
            .await
            .expect("请求不应失败");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "无角色访问 /role 应 403"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body_str.contains("\"error_code\":\"NOT_ROLE\""),
            "403 响应体应含 NOT_ROLE，实际: {body_str}"
        );
    })
    .await;
}

// ------------------------------------------------------------------------
// ACC-RBAC-008：策略注册表热替换（异常侧：默认拒绝被替换为放行）
// ------------------------------------------------------------------------

/// 放行一切权限 / 角色的自定义 `PermissionHandler`（热替换注入物）。
struct AllowAllPermissionHandler;

#[async_trait::async_trait]
impl garrison::strategy::PermissionHandler for AllowAllPermissionHandler {
    async fn handle_check_permission(
        &self,
        _permission: &str,
    ) -> garrison::error::GarrisonResult<()> {
        Ok(())
    }
    async fn handle_check_role(&self, _role: &str) -> garrison::error::GarrisonResult<()> {
        Ok(())
    }
}

/// ACC-RBAC-008（异常+正常）：策略热替换后立即生效——默认（无授权数据）下
/// `PermissionHandler::handle_check_permission` 拒绝（`NotPermission`）；
/// `register_permission_handler(AllowAll)` 后同一调用立即放行；
/// `remove_permission_handler` 后恢复默认拒绝。全程不重建 manager（运行时替换）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_rbac_008_strategy_hot_swap_takes_effect_immediately() {
    use garrison::manager::GarrisonManager;

    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");

    let strategy = GarrisonManager::strategy().expect("init 后应能获取 strategy");
    // 非 async 闭包：捕获外层 strategy 引用做 clone，返回持有自身 Arc 的 future，
    // 使闭包为 Fn 可多次调用（strategy 外层仍可继续 write 热替换）。
    let check = |token: String| {
        let strategy = strategy.clone();
        async move {
            with_tenant(0, async move {
                with_current_token(token, async move {
                    strategy
                        .read()
                        .permission_handler()
                        .clone()
                        .handle_check_permission("user:read")
                        .await
                })
                .await
            })
            .await
        }
    };

    // 默认：无授权数据 → 拒绝
    let default_result = check(token.clone()).await;
    assert!(
        matches!(default_result, Err(GarrisonError::NotPermission(_))),
        "默认策略应拒绝未授权权限，实际: {default_result:?}"
    );

    // 热替换：立即放行（无需重新 init）
    strategy
        .write()
        .register_permission_handler(Arc::new(AllowAllPermissionHandler));
    let swapped = check(token.clone()).await;
    assert!(
        swapped.is_ok(),
        "register 后同一调用应立即放行，实际: {swapped:?}"
    );

    // 移除：恢复默认拒绝
    strategy.write().remove_permission_handler();
    let restored = check(token).await;
    assert!(
        matches!(restored, Err(GarrisonError::NotPermission(_))),
        "remove 后应恢复默认拒绝，实际: {restored:?}"
    );
}

// ------------------------------------------------------------------------
// ACC-RBAC-009：interface 故障显性化（异常）
// ------------------------------------------------------------------------

/// ACC-RBAC-009（异常+正常）：`MockInterface::fail_with` 注入数据源故障后，
/// `check_permission` / `has_permission` 均把 `Err` 显性上抛（`GarrisonError::Dao`），
/// 不得静默降级为 `Ok(false)`；`clear_failure` 后恢复放行。
#[tokio::test]
#[serial]
async fn acc_rbac_009_interface_error_fails_loud_and_recovers() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &["admin"]);
    interface.fail_with(|| GarrisonError::Dao("rbac-interface-down".to_string()));
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应签发 token");

    // 故障期：check_permission 与 has_permission 都必须上抛，禁止静默当无权限
    let perm_err = with_tenant(0, async {
        with_current_token(token.clone(), async {
            GarrisonUtil::check_permission("user:read").await
        })
        .await
    })
    .await;
    assert!(
        matches!(&perm_err, Err(GarrisonError::Dao(m)) if m == "rbac-interface-down"),
        "数据源故障应显性上抛 Dao 错误，实际: {perm_err:?}"
    );
    let has_err = with_tenant(0, async {
        with_current_token(token.clone(), async {
            GarrisonUtil::has_permission("user:read").await
        })
        .await
    })
    .await;
    assert!(
        matches!(&has_err, Err(GarrisonError::Dao(m)) if m == "rbac-interface-down"),
        "has_permission 在数据源故障时也不得静默降级 Ok(false)，实际: {has_err:?}"
    );

    // 故障解除：立即恢复放行
    interface.clear_failure();
    let recovered = with_tenant(0, async {
        with_current_token(token, async {
            GarrisonUtil::check_permission("user:read").await
        })
        .await
    })
    .await;
    assert!(
        recovered.is_ok(),
        "clear_failure 后授权校验应恢复放行，实际: {recovered:?}"
    );
}
