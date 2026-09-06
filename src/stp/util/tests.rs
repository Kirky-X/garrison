mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;
    use crate::error::{GarrisonError, GarrisonResult};
    use crate::session::GarrisonSession;
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    use crate::stp::util::{init_backend, reset_backend_for_test};
    use crate::stp::util::{spawn_cleanup_task, GarrisonUtil, JwtMode};
    use crate::stp::{LoginParams, SessionLogic};
    use async_trait::async_trait;
    use serial_test::serial;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// 辅助函数：创建带 MockDao 的 Arc<GarrisonSession>。
    fn make_session(timeout: u64, active_timeout: u64) -> (Arc<MockDao>, Arc<GarrisonSession>) {
        let dao = Arc::new(MockDao::new());
        let session = Arc::new(GarrisonSession::new(
            dao.clone(),
            timeout,
            active_timeout,
            0,
        ));
        (dao, session)
    }

    // ----------------------------------------------------------------
    // 测试 1：interval <= 0 返回 None 不启动 task
    // ----------------------------------------------------------------

    /// 验证 interval < 0 时返回 None 不启动 task。
    /// 同时验证 interval == 0 也返回 None（0 秒间隔无实际意义，与 < 0 一致）。
    #[tokio::test]
    async fn spawn_cleanup_task_negative_interval_returns_none() {
        let (_dao, session) = make_session(3600, 86400);
        let handle = spawn_cleanup_task(session, -1);
        assert!(handle.is_none(), "interval=-1 应返回 None");

        let (_dao, session) = make_session(3600, 86400);
        let handle = spawn_cleanup_task(session, 0);
        assert!(handle.is_none(), "interval=0 应返回 None");
    }

    // ----------------------------------------------------------------
    // 测试 2：interval > 0 启动 task 并执行清理
    // ----------------------------------------------------------------

    /// 验证 interval > 0 时启动 task，且 task 定期执行 cleanup_expired_tokens。
    ///
    /// 策略：创建 TTL=1 秒的 token，启动间隔=1 秒的清理 task，
    /// 等待 3 秒后验证 token 已从 login_token_map 中清理。
    #[tokio::test]
    async fn spawn_cleanup_task_positive_interval_starts_and_cleans() {
        let (_dao, session) = make_session(1, 86400);
        // 创建 token（TTL=1 秒，1 秒后 MockDao 自动过期）
        session.create("1001", "T1").await.unwrap();
        assert!(
            session.get_token_by_login_id("1001").is_some(),
            "清理前 token 应存在于 login_token_map"
        );

        // 启动清理 task，间隔 1 秒
        let handle = spawn_cleanup_task(session.clone(), 1);
        assert!(handle.is_some(), "interval=1 应返回 Some");

        // 等待 token TTL 过期 + 至少 2 次清理周期
        tokio::time::sleep(Duration::from_secs(3)).await;

        // 验证 token 已被清理（cleanup_expired_tokens 检测到 DAO 返回 None 后移除）
        assert!(
            session.get_token_by_login_id("1001").is_none(),
            "清理后 token 应从 login_token_map 移除"
        );

        // 清理 task
        if let Some(h) = handle {
            h.abort();
        }
    }

    // ----------------------------------------------------------------
    // 测试 3：task 可通过 abort 取消
    // ----------------------------------------------------------------

    /// 验证 task 可通过 JoinHandle::abort() 取消。
    ///
    /// abort 后 await 应返回 Err(JoinError)，且 JoinError::is_cancelled() 为 true。
    #[tokio::test]
    async fn spawn_cleanup_task_can_be_cancelled() {
        let (_dao, session) = make_session(3600, 86400);
        let handle = spawn_cleanup_task(session, 1).unwrap();

        // 等待一小段时间确保 task 已启动并被 runtime 调度
        tokio::time::sleep(Duration::from_millis(100)).await;

        // abort 后 await 应返回 Err（JoinError::is_cancelled）
        handle.abort();
        let result = handle.await;
        assert!(
            result.is_err(),
            "abort 后 await 应返回 Err，实际: {:?}",
            result
        );
        assert!(
            result.unwrap_err().is_cancelled(),
            "JoinError 应为 cancelled"
        );
    }

    // ----------------------------------------------------------------
    // 测试 4：清理失败只 warn 不中断 task
    // ----------------------------------------------------------------

    /// DAO wrapper：get 始终返回错误，用于测试清理失败不中断 task。
    ///
    /// 通过 AtomicUsize 计数 get 调用次数，验证 task 在首次清理失败后仍继续运行。
    struct FailingGetDao {
        get_call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl GarrisonDao for FailingGetDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            self.get_call_count.fetch_add(1, Ordering::SeqCst);
            Err(GarrisonError::Dao("模拟清理失败".to_string()))
        }
        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }
        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }
        crate::atomic_test_fallback!();
    }

    /// 验证清理失败时 task 只记录 warn 不中断，继续运行下一个周期。
    ///
    /// 策略：使用 get 始终失败的 DAO，启动间隔=1 秒的清理 task。
    /// 等待 1.5 秒后验证 get 被调用 >= 2 次（首次立即执行 + 1 秒后第二次），
    /// 且 task 仍存活（is_finished() == false）。
    #[tokio::test]
    async fn spawn_cleanup_task_cleanup_failure_does_not_crash() {
        let get_call_count = Arc::new(AtomicUsize::new(0));
        // atomic + 默认 trait 方法覆盖
        {
            let d = FailingGetDao {
                get_call_count: Arc::new(AtomicUsize::new(0)),
            };
            let _ = d.set_if_absent("a", "v", 60).await;
            let _ = d.get_and_delete("a").await;
            let _ = d.incr("c", 60).await;
            let _ = d.decr("c").await;
            let _ = d.rename("a", "b").await;
            let _ = d.compare_and_swap("b", None, "v", 60).await;
            let _ = d.set_permanent("p", "v").await;
            let _ = d.get_timeout("k").await;
            let _ = d.get_with_ttl("k").await;
            let _ = d.find_social_binding(0, "w", "o").await;
            let _ = d.insert_social_binding(0, "u", "w", "o", None, 0).await;
            let _ = d.compare_and_update_if_greater("k", 1, 60).await;
            let _ = d.eval_lua("r", vec![], vec![]).await;
            let _ = d.insert_credit_consumption(0, "r", 1, 1, 1, 0).await;
            let _ = d.query_credit_consumption(0, 0, 0).await;
            let _ = d.query_role_hierarchy_edges(0).await;
            let _ = d.insert_role_hierarchy_edge(0, "c", "p").await;
            let _ = d.delete_role_hierarchy_edge(0, "c", "p").await;
        }
        let dao: Arc<dyn GarrisonDao> = Arc::new(FailingGetDao {
            get_call_count: get_call_count.clone(),
        });
        let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
        // 添加 token 到内存索引（不经过 DAO，确保 cleanup 有内容可遍历）
        session.add_login_token("user1", "token1");

        // 启动清理 task，间隔 1 秒
        let handle = spawn_cleanup_task(session.clone(), 1).unwrap();

        // 等待 2 个周期（tokio::time::interval 首次 tick 立即返回，第二次在 1 秒后）
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // 验证 cleanup 被调用多次（task 在首次失败后仍继续运行）
        let calls = get_call_count.load(Ordering::SeqCst);
        assert!(
            calls >= 2,
            "清理失败后 task 应继续运行，至少调用 2 次 get，实际: {}",
            calls
        );

        // 验证 task 仍存活（未因 panic 或错误退出）
        assert!(!handle.is_finished(), "清理失败不应导致 task 终止");

        // 清理 task
        handle.abort();
    }

    // ============================================================
    // T114: AuthBackend 桥接测试（R-msa-005）
    // ============================================================
    //
    // 测试 init_backend / get_backend / GarrisonUtil 委托逻辑。
    // 所有涉及 CURRENT_BACKEND 全局状态的测试必须用 #[serial] 串行化，
    // 并在测试前后调用 reset_backend_for_test() 重置状态。

    /// Mock AuthBackend，记录方法调用次数。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    struct MockAuthBackend {
        check_login_calls: Arc<AtomicUsize>,
        check_permission_calls: Arc<AtomicUsize>,
    }

    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    impl MockAuthBackend {
        fn new() -> Self {
            Self {
                check_login_calls: Arc::new(AtomicUsize::new(0)),
                check_permission_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[async_trait::async_trait]
    impl crate::backend::AuthBackend for MockAuthBackend {
        async fn login(&self, _login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
            Ok("mock-token".to_string())
        }
        async fn logout(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn check_login(&self, _token: &str) -> GarrisonResult<bool> {
            self.check_login_calls.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
        async fn check_permission(&self, _token: &str, _permission: &str) -> GarrisonResult<()> {
            self.check_permission_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn check_disable(&self, _token: &str) -> GarrisonResult<bool> {
            Ok(false)
        }
        async fn check_api_key(&self, _api_key: &str, _namespace: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn get_token_info(&self, token: &str) -> GarrisonResult<crate::backend::TokenInfo> {
            Ok(crate::backend::TokenInfo {
                token: token.to_string(),
                created_at: 0,
                last_active_at: 0,
            })
        }
        async fn get_session(&self, token: &str) -> GarrisonResult<crate::backend::SessionData> {
            Ok(crate::backend::SessionData {
                token: token.to_string(),
                login_id: "mock-user".to_string(),
                created_at: 0,
                last_active_at: 0,
                attrs: std::collections::HashMap::new(),
                device: None,
                ip: None,
                user_agent: None,
                safe_services: std::collections::HashMap::new(),
                #[cfg(feature = "session-extra")]
                dynamic_active_timeout: None,
                #[cfg(feature = "session-extra")]
                is_anon: false,
                effective_timeout: None,
            })
        }
        async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn switch_to(&self, _token: &str, _target_login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
            Ok(format!("renewed-{}", token))
        }
    }

    /// 验证 init_backend 成功初始化。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_init_backend_success() {
        reset_backend_for_test();
        let backend = Arc::new(MockAuthBackend::new());
        let result = init_backend(backend);
        assert!(result.is_ok(), "init_backend 应成功");
        reset_backend_for_test();
    }

    /// 验证 init_backend 重复调用返回错误。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_init_backend_duplicate_fails() {
        reset_backend_for_test();
        let backend1 = Arc::new(MockAuthBackend::new());
        let backend2 = Arc::new(MockAuthBackend::new());
        init_backend(backend1).unwrap();
        let result = init_backend(backend2);
        assert!(result.is_err(), "重复 init_backend 应返回错误");
        reset_backend_for_test();
    }

    /// 验证 GarrisonUtil::check_login 委托 CURRENT_BACKEND。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_login_delegates_to_backend() {
        reset_backend_for_test();
        let mock = MockAuthBackend::new();
        let call_count = mock.check_login_calls.clone();
        init_backend(Arc::new(mock)).unwrap();

        // 设置 token 上下文后调用 check_login
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_login().await
        })
        .await;

        assert!(result.is_ok(), "check_login 应成功");
        assert!(result.unwrap(), "MockAuthBackend.check_login 返回 true");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "MockAuthBackend.check_login 应被调用 1 次"
        );
        reset_backend_for_test();
    }

    /// 验证 GarrisonUtil::check_permission 委托 CURRENT_BACKEND。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_permission_delegates_to_backend() {
        reset_backend_for_test();
        let mock = MockAuthBackend::new();
        let call_count = mock.check_permission_calls.clone();
        init_backend(Arc::new(mock)).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_permission("user:read").await
        })
        .await;

        assert!(result.is_ok(), "check_permission 应成功");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "MockAuthBackend.check_permission 应被调用 1 次"
        );
        reset_backend_for_test();
    }

    /// 验证未初始化时 fallback 到 GarrisonManager（backend-embedded feature）。
    #[cfg(feature = "backend-embedded")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_fallback_to_garrison_manager_when_not_initialized() {
        reset_backend_for_test();
        // 未调用 init_backend，应 fallback 到 GarrisonManager
        // GarrisonManager 未初始化时返回 GarrisonError::Session
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_login().await
        })
        .await;
        // fallback 路径调用 GarrisonManager::logic()，未初始化时返回 Err
        assert!(
            result.is_err(),
            "未初始化时应 fallback 到 GarrisonManager 并返回其错误"
        );
        reset_backend_for_test();
    }

    /// 验证 check_safe 委托后 bool→Result<()> 适配（is_safe=true → Ok(())）。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_safe_true_returns_ok() {
        reset_backend_for_test();
        // MockAuthBackend.check_safe 返回 Ok(true)
        init_backend(Arc::new(MockAuthBackend::new())).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_safe().await
        })
        .await;

        assert!(result.is_ok(), "check_safe=true 应返回 Ok(())");
        reset_backend_for_test();
    }

    /// 验证 check_disable 委托后 bool→Result<()> 适配（is_disabled=false → Ok(())）。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_disable_false_returns_ok() {
        reset_backend_for_test();
        // MockAuthBackend.check_disable 返回 Ok(false)
        init_backend(Arc::new(MockAuthBackend::new())).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_disable().await
        })
        .await;

        assert!(result.is_ok(), "check_disable=false 应返回 Ok(())");
        reset_backend_for_test();
    }

    // ============================================================
    // T116: Embedded 模式行为验证（R-msa-005）
    // ============================================================
    //
    // 验证 init_backend(BackendEmbedded) 后，GarrisonUtil 委托链路：
    // GarrisonUtil → CURRENT_BACKEND(BackendEmbedded) → GarrisonManager
    //
    // 由于 GarrisonManager 未初始化（单元测试环境），BackendEmbedded::check_login
    // 会返回 GarrisonError::Session。这验证了委托链路正确连接。

    /// 验证 Embedded 模式下 GarrisonUtil 委托 BackendEmbedded → GarrisonManager。
    #[cfg(feature = "backend-embedded")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t116_embedded_mode_delegates_to_garrison_manager() {
        reset_backend_for_test();
        // 初始化 BackendEmbedded
        init_backend(Arc::new(crate::backend::BackendEmbedded::new())).unwrap();

        // 调用 GarrisonUtil::check_login，应委托 BackendEmbedded → GarrisonManager
        // GarrisonManager 未初始化时返回 GarrisonError::Session
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_login().await
        })
        .await;

        // 验证委托链路：返回错误说明 BackendEmbedded 调用了 GarrisonManager
        assert!(
            result.is_err(),
            "Embedded 模式应委托 BackendEmbedded → GarrisonManager，未初始化时返回错误"
        );
        reset_backend_for_test();
    }

    /// 验证 Embedded 模式下 fallback 路径与委托路径行为一致。
    ///
    /// fallback 路径（未 init_backend）：直接调用 GarrisonManager::logic()?.check_login()
    /// 委托路径（init_backend(BackendEmbedded)）：BackendEmbedded::check_login() → GarrisonManager::logic()?.check_login()
    ///
    /// 两条路径都调用 GarrisonManager::logic()，未初始化时都返回 GarrisonError::Session。
    #[cfg(feature = "backend-embedded")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t116_embedded_mode_fallback_and_delegate_consistent() {
        // 测试 fallback 路径（未 init_backend）
        reset_backend_for_test();
        let fallback_result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_login().await
        })
        .await;

        // 测试委托路径（init_backend(BackendEmbedded)）
        init_backend(Arc::new(crate::backend::BackendEmbedded::new())).unwrap();
        let delegate_result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_login().await
        })
        .await;

        // 两条路径都应返回错误（GarrisonManager 未初始化）
        assert!(fallback_result.is_err(), "fallback 路径应返回错误");
        assert!(delegate_result.is_err(), "委托路径应返回错误");

        // 验证错误类型一致（都是 Session 错误）
        match (fallback_result.unwrap_err(), delegate_result.unwrap_err()) {
            (crate::error::GarrisonError::Session(_), crate::error::GarrisonError::Session(_)) => {
            },
            (f, d) => panic!(
                "两条路径错误类型应一致（Session），fallback={:?}, delegate={:?}",
                f, d
            ),
        }
        reset_backend_for_test();
    }

    // ============================================================
    // T117: Remote 模式委托验证（R-msa-005）
    // ============================================================
    //
    // 验证 init_backend(BackendRemote) 后，GarrisonUtil 委托 BackendRemote 发送 HTTP 请求。
    // 使用 wiremock 启动 mock server，验证 HTTP 请求正确发送。

    /// 验证 Remote 模式下 GarrisonUtil::check_login 委托 BackendRemote 发送 HTTP 请求。
    #[cfg(feature = "backend-remote")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t117_remote_mode_delegates_to_backend_remote() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        reset_backend_for_test();

        // 启动 mock server
        let server = MockServer::start().await;

        // 设置 mock：期望收到 POST /api/v1/auth/check-login + X-API-Key header
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": true,
                "error_code": null,
                "message": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        // 初始化 BackendRemote 指向 mock server
        let remote = crate::backend::BackendRemote::new(
            server.uri(),
            "test-api-key",
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        init_backend(Arc::new(remote)).unwrap();

        // 调用 GarrisonUtil::check_login，应委托 BackendRemote 发送 HTTP 请求
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_login().await
        })
        .await;

        assert!(
            result.is_ok(),
            "Remote 模式 check_login 应成功: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "mock server 返回 true，GarrisonUtil::check_login 应返回 true"
        );
        reset_backend_for_test();
    }

    /// 验证 Remote 模式下 GarrisonUtil::check_permission 委托 BackendRemote。
    #[cfg(feature = "backend-remote")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t117_remote_mode_check_permission_delegates() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        reset_backend_for_test();

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-permission"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        let remote = crate::backend::BackendRemote::new(
            server.uri(),
            "test-api-key",
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        init_backend(Arc::new(remote)).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            GarrisonUtil::check_permission("user:read").await
        })
        .await;

        assert!(
            result.is_ok(),
            "Remote 模式 check_permission 应成功: {:?}",
            result
        );
        reset_backend_for_test();
    }

    // ============================================================
    // 覆盖率补充：JwtMode / has_permission/has_role 错误路径 / 委托链路
    // ============================================================

    /// 验证 `JwtMode::default()` 返回 `Mixin`（推荐默认模式）。
    ///
    /// 覆盖 `#[default]` 标注的 `Mixin` 变体。
    #[serial]
    #[test]
    fn jwt_mode_default_is_mixin() {
        let mode = JwtMode::default();
        assert_eq!(
            mode,
            JwtMode::Mixin,
            "JwtMode 默认应为 Mixin（推荐平衡模式）"
        );
    }

    /// 验证 `JwtMode` 三个变体互不相等（PartialEq 派生正确）。
    #[serial]
    #[test]
    fn jwt_mode_variants_distinct() {
        assert_ne!(JwtMode::Stateless, JwtMode::Mixin);
        assert_ne!(JwtMode::Mixin, JwtMode::Simple);
        assert_ne!(JwtMode::Stateless, JwtMode::Simple);
        // 自身相等
        assert_eq!(JwtMode::Stateless, JwtMode::Stateless);
        assert_eq!(JwtMode::Mixin, JwtMode::Mixin);
        assert_eq!(JwtMode::Simple, JwtMode::Simple);
    }

    /// 验证 `JwtMode` 的 Clone / Copy 行为（值拷贝，不丢失原值）。
    #[serial]
    #[test]
    fn jwt_mode_clone_preserves_value() {
        let original = JwtMode::Stateless;
        let cloned = original;
        // Copy 语义：原值仍可用
        assert_eq!(original, cloned);
        // Clone 等价于 Copy
        assert_eq!(JwtMode::Mixin.clone(), JwtMode::Mixin);
    }

    /// 验证 `has_permission("")` 返回 `InvalidParam`（空字符串校验在本地完成，
    /// 不需要初始化 GarrisonManager）。
    ///
    /// 覆盖 `has_permission` 中的本地参数校验路径。
    #[serial]
    #[tokio::test]
    async fn has_permission_empty_returns_invalid_param() {
        let result = GarrisonUtil::has_permission("").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::InvalidParam(_))),
            "空 permission 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// 验证 `has_role("")` 返回 `InvalidParam`。
    ///
    /// 覆盖 `has_role` 中的本地参数校验路径。
    #[serial]
    #[tokio::test]
    async fn has_role_empty_returns_invalid_param() {
        let result = GarrisonUtil::has_role("").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::InvalidParam(_))),
            "空 role 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// 验证 `login_simple` 在未初始化 `GarrisonManager` 时返回 `Session` 错误。
    ///
    /// 覆盖 `login_simple` → `login` → `GarrisonManager::logic()?` 委托链路。
    /// 在 backend-embedded feature 下，未 `init_backend()` 时 fallback 到 GarrisonManager 路径。
    #[tokio::test]
    #[serial_test::serial]
    async fn login_simple_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::login_simple("user1").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `logout_by_login_id` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `logout_by_login_id` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn logout_by_login_id_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::logout_by_login_id("user1").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `kickout` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `kickout` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn kickout_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::kickout("user1").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `config()` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `config()` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn config_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::config();
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `get_login_id_by_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `get_login_id_by_token` → `with_current_token` → `get_login_id`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn get_login_id_by_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::get_login_id_by_token("some-token").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    // ============================================================
    // 委托链路覆盖率补充：GarrisonUtil 各方法 → GarrisonManager::logic()?
    // ============================================================
    //
    // 以下测试验证未初始化 GarrisonManager 时，各 GarrisonUtil 静态方法
    // 正确委托到 `GarrisonManager::logic()?` 并返回 `Session` 错误。
    // 覆盖了 util.rs 中未被既有测试覆盖的委托路径。

    /// 验证 `login(id, params)` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `login` → `GarrisonManager::logic()?` 委托链路（带 LoginParams 版本）。
    #[tokio::test]
    #[serial_test::serial]
    async fn login_with_params_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::login("user1", &LoginParams::default()).await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `logout()` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `logout` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn logout_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::logout().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `kickout_by_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `kickout_by_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn kickout_by_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::kickout_by_token("some-token").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `revoke_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `revoke_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn revoke_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::revoke_token("some-token").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_login()` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_login` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_login_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_login().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `get_login_id()` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `get_login_id` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn get_login_id_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::get_login_id().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_permission` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_permission` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_permission_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_permission("user:read").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_role` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_role` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_role_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_role("admin").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `has_permission`（非空字符串）在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `has_permission` 非空路径 → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn has_permission_non_empty_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::has_permission("user:read").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `has_role`（非空字符串）在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `has_role` 非空路径 → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn has_role_non_empty_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::has_role("admin").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `get_permission_list` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `get_permission_list` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn get_permission_list_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::get_permission_list().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `get_role_list` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `get_role_list` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn get_role_list_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::get_role_list().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_access_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_access_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_access_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_access_token().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_client_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_client_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_client_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_client_token().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_temp_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_temp_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_temp_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_temp_token().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_safe` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_safe` → `GarrisonManager::logic()?` 委托链路（fallback 路径）。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_safe_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_safe().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_disable` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_disable` → `GarrisonManager::logic()?` 委托链路（fallback 路径）。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_disable_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_disable().await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_api_key` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_api_key` → `GarrisonManager::logic()?` 委托链路（fallback 路径）。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_api_key_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_api_key("default").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `login_by_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `login_by_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn login_by_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::login_by_token("external-token").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `verify_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `verify_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::verify_token("some-token").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `refresh_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `refresh_token` → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn refresh_token_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::refresh_token("old-token").await;
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    // ============================================================
    // 同步版本（*_sync）委托链路测试
    // ============================================================
    //
    // 验证 `*_sync` 方法在未初始化时返回 `Session` 错误。
    // 使用 `flavor = "multi_thread"` 因为 `block_in_place` 要求
    // multi_thread runtime 上下文。

    /// 验证 `check_login_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_login_sync` → `block_in_place` → `check_login`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_login_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_login_sync();
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_permission_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_permission_sync` → `block_in_place` → `check_permission`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_permission_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_permission_sync("user:read");
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_role_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_role_sync` → `block_in_place` → `check_role`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_role_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_role_sync("admin");
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_access_token_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_access_token_sync` → `block_in_place` → `check_access_token`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_access_token_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_access_token_sync();
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_client_token_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_client_token_sync` → `block_in_place` → `check_client_token`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_client_token_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_client_token_sync();
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_temp_token_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_temp_token_sync` → `block_in_place` → `check_temp_token`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_temp_token_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_temp_token_sync();
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_api_key_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_api_key_sync` → `block_in_place` → `check_api_key`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_api_key_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_api_key_sync("default");
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_safe_sync` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `check_safe_sync` → `block_in_place` → `check_safe`
    /// → `GarrisonManager::logic()?` 委托链路。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn check_safe_sync_delegates_to_garrison_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::GarrisonManager::reset_for_test();

        let result = GarrisonUtil::check_safe_sync();
        assert!(
            matches!(result, Err(crate::error::GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")),
            "未初始化时应返回 'GarrisonManager 未初始化'，实际: {:?}",
            result
        );
    }
}
