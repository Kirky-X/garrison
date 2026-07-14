//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! MfaLogic trait — 二级认证（MFA）与账号禁用校验契约。
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接 MFA 校验与
//! 账号禁用检查 2 个方法。super-trait 为 [`SessionLogic`]
//! （MFA 检查依赖当前登录状态）。

use super::current_token;
use super::BulwarkLogicDefault;
use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// MFA 逻辑 trait，定义二级认证与账号禁用校验契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 的 `checkSafe` / `checkDisable` 部分。
///
/// # 默认实现（向后兼容）
///
/// - [`check_safe`](Self::check_safe)：默认调用 `is_safe("default")`，未通过时返回
///   `Err(NotSafe("SAFE_EXPIRED"))`；未覆写 `is_safe` 时仍返回 `Ok(())`（兼容 0.2.x）。
/// - [`check_disable`](Self::check_disable)：默认返回 `Ok(())`（未实现禁用账号库，兼容 0.2.x）。
///   业务方覆写以查询当前 login_id 是否在禁用列表中。
#[async_trait]
pub trait MfaLogic: SessionLogic {
    /// 检查二级认证（MFA）状态。
    ///
    /// 默认实现调用 `is_safe("default")` 检查 "default" service 的二级认证状态：
    /// - `Ok(true)` → 返回 `Ok(())`
    /// - `Ok(false)` → 返回 `Err(Self::not_safe("SAFE_EXPIRED"))`
    /// - `Err(e)` → 透传错误
    ///
    /// # 向后兼容
    ///
    /// 未覆写 `is_safe` 的实现者（如未启用 `safe-auth` feature 时），
    /// `is_safe` 默认返回 `Ok(true)`，因此 `check_safe` 仍返回 `Ok(())`。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(BulwarkError::NotSafe)`: 未通过二级认证（service 未开启或已过期）。
    async fn check_safe(&self) -> BulwarkResult<()> {
        if !self.is_safe("default").await? {
            return Err(Self::not_safe("SAFE_EXPIRED"));
        }
        Ok(())
    }

    /// 检查账号是否被禁用。
    ///
    /// trait 默认实现返回 `Ok(())`（向后兼容 0.2.x）；`BulwarkLogicDefault` 自 v0.6.5 起覆写：
    /// 注入 `DisableRepository` 后，从当前 token 取 login_id 并查询封禁状态，被封禁则返回
    /// `DisableService` 错误。未注入 repository 或未登录时返回 `Ok(())`。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用 / 未注入 DisableRepository / 未登录。
    /// - `Err(BulwarkError::DisableService)`: 账号已封禁（0.6.1 起推荐使用专用异常）。
    async fn check_disable(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 开启指定 service 的二级认证（瞬态标记）。
    ///
    /// 在当前 TokenSession 的 `safe_services` 中记录 service → 过期时间戳。
    /// 调用后 `is_safe(service)` 在过期前返回 `true`。
    ///
    /// # 参数
    /// - `service`: 服务名称（如 "default" / "payment"）。
    /// - `duration_secs`: 有效时长（秒）；过期后 `is_safe` 返回 `false`。
    ///
    /// # 返回
    /// - `Ok(())`: 成功开启。
    /// - `Err`: 未登录或 session 不存在。
    ///
    /// # 默认实现
    /// 返回 `Ok(())`（no-op，向后兼容 0.6.4 之前）。
    /// `safe-auth` feature 启用时由 `BulwarkLogicDefault` 覆写。
    async fn open_safe(&self, _service: &str, _duration_secs: u64) -> BulwarkResult<()> {
        Ok(())
    }

    /// 检查指定 service 是否处于二级认证有效期内。
    ///
    /// # 参数
    /// - `service`: 服务名称。
    ///
    /// # 返回
    /// - `Ok(true)`: service 已开启且未过期。
    /// - `Ok(false)`: service 未开启或已过期。
    ///
    /// # 默认实现
    /// 返回 `Ok(true)`（始终安全，向后兼容 0.6.4 之前）。
    /// `safe-auth` feature 启用时由 `BulwarkLogicDefault` 覆写。
    async fn is_safe(&self, _service: &str) -> BulwarkResult<bool> {
        Ok(true)
    }

    /// 关闭指定 service 的二级认证（移除瞬态标记）。
    ///
    /// # 参数
    /// - `service`: 服务名称。
    ///
    /// # 返回
    /// - `Ok(())`: 成功关闭（或 service 本就未开启，幂等）。
    /// - `Err`: 未登录或 session 不存在。
    ///
    /// # 默认实现
    /// 返回 `Ok(())`（no-op，向后兼容 0.6.4 之前）。
    /// `safe-auth` feature 启用时由 `BulwarkLogicDefault` 覆写。
    async fn close_safe(&self, _service: &str) -> BulwarkResult<()> {
        Ok(())
    }

    /// 构造账号被封禁异常。
    ///
    /// 业务方在自定义 `check_disable` 实现中调用此关联函数抛出专用异常：
    ///
    /// ```ignore
    /// async fn check_disable(&self) -> BulwarkResult<()> {
    ///     if account_is_banned().await {
    ///         return Err(Self::disable_service("default", None));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # 参数
    /// - `service`: 被封禁的服务名（如 "default" / "oidc"）。
    /// - `until`: 定时解封时间；`None` 表示永久封禁。
    fn disable_service(
        service: &str,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> BulwarkError {
        BulwarkError::DisableService {
            service: service.to_string(),
            until,
        }
    }

    /// 构造未完成二次认证异常。
    ///
    /// 业务方在自定义 `check_safe` 实现中调用此关联函数抛出专用异常：
    ///
    /// ```ignore
    /// async fn check_safe(&self) -> BulwarkResult<()> {
    ///     if !mfa_completed().await {
    ///         return Err(Self::not_safe("MFA_TOTP_REQUIRED"));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # 参数
    /// - `reason`: 未完成认证的原因标识（如 "MFA_TOTP_REQUIRED" / "WEBAUTHN_REQUIRED"）。
    fn not_safe(reason: &str) -> BulwarkError {
        BulwarkError::NotSafe {
            reason: reason.to_string(),
        }
    }
}

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

#[async_trait]
impl MfaLogic for BulwarkLogicDefault {
    /// 检查二级认证（MFA）状态。
    ///
    /// `BulwarkLogicDefault` 覆写实现（v0.6.5 T025）：
    /// 调用 `is_safe("default")` 检查 "default" service 的二级认证状态。
    ///
    /// # 为什么覆写 trait default？
    ///
    /// `async_trait` 宏将 trait default 方法编译为泛型代码，`self` 类型为 `&Self`（泛型）。
    /// 在泛型上下文中，编译器无法解析到 inherent method（safe.rs 中的 `is_safe`），
    /// 只能解析到 trait default `is_safe`（返回 `Ok(true)`）。
    /// 在 impl 块中，`self` 是 `&BulwarkLogicDefault`（具体类型），编译器能解析到
    /// inherent method（当 `safe-auth` feature 启用时）。
    ///
    /// # 行为
    /// - 无 `safe-auth` feature：`is_safe` 使用 trait default（`Ok(true)`）→ 返回 `Ok(())`
    /// - 有 `safe-auth` feature：`is_safe` 使用 inherent method（检查 `safe_services`）
    ///   - `Ok(true)` → 返回 `Ok(())`
    ///   - `Ok(false)` → 返回 `Err(Self::not_safe("SAFE_EXPIRED"))`
    ///   - `Err(e)` → 透传错误
    async fn check_safe(&self) -> BulwarkResult<()> {
        if !self.is_safe("default").await? {
            return Err(Self::not_safe("SAFE_EXPIRED"));
        }
        Ok(())
    }

    /// 检查当前登录账号是否被封禁。
    ///
    /// `BulwarkLogicDefault` 覆写实现（v0.6.5 T019）：
    /// 1. 无 `disable_repository` 注入 → 返回 `Ok(())`（向后兼容 0.6.4 之前）
    /// 2. 无当前 token（未登录）→ 返回 `Ok(())`
    /// 3. token 对应的 TokenSession 不存在 → 返回 `Ok(())`
    /// 4. 调用 `DisableRepository::is_disable(login_id, "default")`，未封禁 → `Ok(())`
    /// 5. 已封禁 → 返回 `Err(Self::disable_service("default", until))`，
    ///    `until` 来自 `get_disable_time`（None=永久封禁，Some=定时解封）
    ///
    /// # 错误
    /// - `BulwarkError::DisableService`: 账号已封禁。
    /// - DAO/反序列化失败：透传 `BulwarkError`。
    async fn check_disable(&self) -> BulwarkResult<()> {
        // 无 disable_repository 时返回 Ok（向后兼容 0.6.4 之前）
        let repo = match &self.disable_repository {
            Some(r) => r,
            None => return Ok(()),
        };
        // 获取当前 token（未登录时返回 Ok）
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => return Ok(()),
        };
        // 获取 login_id（TokenSession 不存在时返回 Ok）
        let ts = match self.session.get_token_session(&token).await? {
            Some(ts) => ts,
            None => return Ok(()),
        };
        // 检查封禁状态
        if repo.is_disable(&ts.login_id, "default").await? {
            let until = repo.get_disable_time(&ts.login_id, "default").await?;
            return Err(Self::disable_service("default", until));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
    use crate::stp::session::SessionLogic;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + `SessionLogic`（9 必需方法）。
    /// `MfaLogic` 2 个方法均有默认实现，空 impl 即可获得全部默认行为。
    struct MockMfa {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockMfa {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockMfa {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    #[async_trait]
    impl MfaLogic for MockMfa {}

    #[tokio::test]
    async fn check_safe_default_ok() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.check_safe().await.unwrap();
    }

    #[tokio::test]
    async fn check_disable_default_ok() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.check_disable().await.unwrap();
    }

    // ========================================================================
    // disable_service / not_safe 构造方法测试
    // ========================================================================

    /// 验证 `disable_service` 构造正确的 `BulwarkError::DisableService` 变体。
    ///
    /// 覆盖 spec R-error-005：service 字段正确传递，until=None 表示永久封禁。
    #[test]
    fn disable_service_constructs_correct_error() {
        let err = MockMfa::disable_service("default", None);
        match err {
            BulwarkError::DisableService { service, until } => {
                assert_eq!(service, "default");
                assert!(until.is_none(), "until=None 表示永久封禁");
            },
            other => panic!("期望 DisableService 变体，实际: {:?}", other),
        }
    }

    /// 验证 `disable_service` 带 until 时间戳时正确传递。
    #[test]
    fn disable_service_with_until_timestamp() {
        let until = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = MockMfa::disable_service("oidc", Some(until));
        match err {
            BulwarkError::DisableService { service, until: u } => {
                assert_eq!(service, "oidc");
                assert!(u.is_some(), "until 应为 Some");
                assert_eq!(u.unwrap().to_rfc3339(), "2026-12-31T23:59:59+00:00");
            },
            other => panic!("期望 DisableService 变体，实际: {:?}", other),
        }
    }

    /// 验证 `not_safe` 构造正确的 `BulwarkError::NotSafe` 变体。
    ///
    /// 覆盖 spec R-error-005：reason 字段正确传递。
    #[test]
    fn not_safe_constructs_correct_error() {
        let err = MockMfa::not_safe("MFA_TOTP_REQUIRED");
        match err {
            BulwarkError::NotSafe { reason } => {
                assert_eq!(reason, "MFA_TOTP_REQUIRED");
            },
            other => panic!("期望 NotSafe 变体，实际: {:?}", other),
        }
    }

    /// 验证 `not_safe` 可构造 Display 输出包含 reason。
    #[test]
    fn not_safe_display_includes_reason() {
        let err = MockMfa::not_safe("WEBAUTHN_REQUIRED");
        let display = err.to_string();
        assert!(
            display.contains("WEBAUTHN_REQUIRED"),
            "Display 应包含 reason，实际: {}",
            display
        );
        assert!(
            display.contains("未完成二次认证"),
            "Display 应包含中文描述，实际: {}",
            display
        );
    }

    /// 验证 `open_safe` trait 默认实现返回 Ok(())（no-op，向后兼容 0.6.4 之前）。
    ///
    /// 覆盖 trait default 路径（lines 78-80）：未覆写的实现者调用 open_safe 应直接返回 Ok。
    #[tokio::test]
    async fn open_safe_default_returns_ok() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.open_safe("default", 3600).await.unwrap();
    }

    /// 验证 `close_safe` trait 默认实现返回 Ok(())（no-op，向后兼容 0.6.4 之前）。
    ///
    /// 覆盖 trait default 路径（lines 110-112）：未覆写的实现者调用 close_safe 应直接返回 Ok。
    #[tokio::test]
    async fn close_safe_default_returns_ok() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.close_safe("default").await.unwrap();
    }

    // ========================================================================
    // T025: check_safe 默认实现向后兼容测试
    // ========================================================================

    /// T025: 不启用 safe-auth 时，MockMfa（只实现 trait defaults）的 check_safe 返回 Ok。
    ///
    /// is_safe 默认返回 Ok(true) → check_safe 返回 Ok(())（向后兼容 0.6.4 之前）。
    #[tokio::test]
    async fn t025_check_safe_backward_compat_without_safe_auth() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.check_safe().await.unwrap();
    }

    /// T025: MockMfa 不覆写 is_safe，使用 trait default Ok(true)。
    ///
    /// 验证 check_safe 默认调用 is_safe("default")，因 is_safe=true，返回 Ok(())。
    #[tokio::test]
    async fn t025_check_safe_default_uses_is_safe_default() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        // is_safe 默认返回 Ok(true)
        assert!(
            mock.is_safe("default").await.unwrap(),
            "is_safe 默认应返回 Ok(true)"
        );
        // check_safe 调用 is_safe，因 is_safe=true，返回 Ok(())
        assert!(mock.check_safe().await.is_ok(), "check_safe 应返回 Ok(())");
    }

    // ========================================================================
    // check_safe 默认实现：is_safe 覆写场景测试
    // 覆盖 trait default check_safe（lines 42-47）的 false / Err 分支
    // ========================================================================

    /// 可配置 is_safe 返回值的 mock，用于测试 check_safe trait default 的各分支。
    ///
    /// `safe_result` 为 is_safe 预设返回值，覆盖 Ok(true)/Ok(false)/Err 三类分支。
    struct MockMfaSafe {
        config: Arc<BulwarkConfig>,
        safe_result: BulwarkResult<bool>,
    }

    impl BulwarkCore for MockMfaSafe {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockMfaSafe {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    #[async_trait]
    impl MfaLogic for MockMfaSafe {
        // 覆写 is_safe 返回预设值，测试 check_safe trait default 各分支
        async fn is_safe(&self, _service: &str) -> BulwarkResult<bool> {
            match &self.safe_result {
                Ok(b) => Ok(*b),
                Err(BulwarkError::Dao(s)) => Err(BulwarkError::Dao(s.clone())),
                Err(BulwarkError::Internal(s)) => Err(BulwarkError::Internal(s.clone())),
                Err(e) => panic!("MockMfaSafe 不支持此错误变体: {:?}", e),
            }
        }
    }

    /// check_safe + is_safe 返回 Ok(false) → 返回 Err(NotSafe("SAFE_EXPIRED"))。
    ///
    /// 覆盖 mfa.rs 第 43-45 行 `!is_safe → Err(Self::not_safe("SAFE_EXPIRED"))` 分支。
    #[tokio::test]
    async fn check_safe_is_safe_false_returns_not_safe() {
        let mock = MockMfaSafe {
            config: Arc::new(BulwarkConfig::default()),
            safe_result: Ok(false),
        };
        let result = mock.check_safe().await;
        match result {
            Err(BulwarkError::NotSafe { reason }) => {
                assert_eq!(
                    reason, "SAFE_EXPIRED",
                    "is_safe=false 时 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                );
            },
            other => panic!(
                "is_safe=false 时 check_safe 应返回 Err(NotSafe)，实际: {:?}",
                other
            ),
        }
    }

    /// check_safe + is_safe 返回 Ok(true) → 返回 Ok(())。
    ///
    /// 覆盖 mfa.rs 第 46 行 `Ok(())` 分支（通过覆写 is_safe 而非 trait default）。
    #[tokio::test]
    async fn check_safe_is_safe_true_returns_ok() {
        let mock = MockMfaSafe {
            config: Arc::new(BulwarkConfig::default()),
            safe_result: Ok(true),
        };
        mock.check_safe().await.unwrap();
    }

    /// check_safe + is_safe 返回 Err(Dao) → 透传错误。
    ///
    /// 覆盖 mfa.rs 第 43 行 `is_safe(...).await?` 错误传播路径。
    #[tokio::test]
    async fn check_safe_is_safe_error_propagates() {
        let mock = MockMfaSafe {
            config: Arc::new(BulwarkConfig::default()),
            safe_result: Err(BulwarkError::Dao("数据源连接失败".to_string())),
        };
        let result = mock.check_safe().await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(ref s)) if s.contains("数据源连接失败")),
            "is_safe 返回 Dao 错误时应透传，实际: {:?}",
            result
        );
    }

    /// check_safe + is_safe 返回 Err(Internal) → 透传错误。
    ///
    /// 覆盖 mfa.rs 第 43 行 `is_safe(...).await?` 错误传播路径（Internal 变体）。
    #[tokio::test]
    async fn check_safe_is_safe_internal_error_propagates() {
        let mock = MockMfaSafe {
            config: Arc::new(BulwarkConfig::default()),
            safe_result: Err(BulwarkError::Internal("内部错误".to_string())),
        };
        let result = mock.check_safe().await;
        assert!(
            matches!(result, Err(BulwarkError::Internal(ref s)) if s.contains("内部错误")),
            "is_safe 返回 Internal 错误时应透传，实际: {:?}",
            result
        );
    }

    /// 验证 `disable_service` Display 输出包含 service 名称。
    ///
    /// 覆盖 mfa.rs disable_service 关联函数 + Display 实现。
    #[test]
    fn disable_service_display_includes_service() {
        let err = MockMfa::disable_service("payment", None);
        let display = err.to_string();
        assert!(
            display.contains("payment"),
            "Display 应包含 service 名称，实际: {}",
            display
        );
    }

    // ========================================================================
    // T019: DisableRepository 集成测试（BulwarkLogicDefault.check_disable）
    // ========================================================================

    mod t019_disable_integration {
        use super::*;
        use crate::account::disable::{DefaultDisableRepository, DisableRepository};
        use crate::config::BulwarkConfig;
        use crate::dao::tests::MockDao;
        use crate::dao::BulwarkDao;
        use crate::session::BulwarkSession;
        use crate::stp::with_current_token;
        use crate::stp::LoginParams;
        use crate::strategy::BulwarkPermissionStrategy;
        use async_trait::async_trait;
        use chrono::Utc;
        use std::sync::Arc;

        // --------------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // --------------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl BulwarkPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建不带 disable_repository 的 BulwarkLogicDefault（向后兼容场景）。
        fn make_logic_without_repo() -> BulwarkLogicDefault {
            let dao: Arc<MockDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
        }

        /// 创建带 disable_repository 的 BulwarkLogicDefault，返回 (logic, repo) 便于测试。
        fn make_logic_with_repo() -> (
            BulwarkLogicDefault,
            Arc<DefaultDisableRepository>,
            Arc<MockDao>,
        ) {
            let dao = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(
                dao.clone() as Arc<dyn BulwarkDao>,
                3600,
                86400,
            ));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            let repo = Arc::new(DefaultDisableRepository::new(
                dao.clone() as Arc<dyn BulwarkDao>
            ));
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_disable_repository(repo.clone() as Arc<dyn DisableRepository>);
            (logic, repo, dao)
        }

        // --------------------------------------------------------------------
        // 6 个集成测试
        // --------------------------------------------------------------------

        /// 未注入 disable_repository，check_disable 返回 Ok（向后兼容 0.6.4 之前）。
        #[tokio::test]
        async fn test_check_disable_no_repository_returns_ok() {
            let logic = make_logic_without_repo();
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            assert!(
                result.is_ok(),
                "未注入 disable_repository 时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 注入 repository 但未封禁，check_disable 返回 Ok。
        #[tokio::test]
        async fn test_check_disable_not_disabled_returns_ok() {
            let (logic, _repo, _dao) = make_logic_with_repo();
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            assert!(
                result.is_ok(),
                "未封禁时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 注入 repository 且已封禁，check_disable 返回 DisableService 错误。
        #[tokio::test]
        async fn test_check_disable_disabled_returns_error() {
            let (logic, repo, _dao) = make_logic_with_repo();
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            // 封禁该用户（定时封禁）
            let until = Utc::now() + chrono::Duration::seconds(3600);
            repo.disable("1001", "default", Some(until), 0, 3600)
                .await
                .unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            match result {
                Err(BulwarkError::DisableService { service, .. }) => {
                    assert_eq!(
                        service, "default",
                        "DisableService 错误的 service 字段应为 'default'"
                    );
                },
                other => panic!(
                    "已封禁时 check_disable 应返回 Err(DisableService)，实际: {:?}",
                    other
                ),
            }
        }

        /// 永久封禁（until=None），错误中 until 字段为 None。
        #[tokio::test]
        async fn test_check_disable_permanent_ban_until_none() {
            let (logic, repo, _dao) = make_logic_with_repo();
            let token = logic.login("1002", &LoginParams::default()).await.unwrap();

            // 永久封禁（until=None, duration_secs=0）
            repo.disable("1002", "default", None, 0, 0).await.unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            match result {
                Err(BulwarkError::DisableService { service, until }) => {
                    assert_eq!(service, "default");
                    assert!(
                        until.is_none(),
                        "永久封禁 until 应为 None，实际: {:?}",
                        until
                    );
                },
                other => panic!(
                    "永久封禁应返回 Err(DisableService {{ until: None }})，实际: {:?}",
                    other
                ),
            }
        }

        /// 定时封禁（until=Some），错误中 until 字段为 Some 且精确匹配。
        #[tokio::test]
        async fn test_check_disable_timed_ban_until_some() {
            let (logic, repo, _dao) = make_logic_with_repo();
            let token = logic.login("1003", &LoginParams::default()).await.unwrap();

            // 定时封禁（until=Some(future), duration_secs=7200）
            let until = Utc::now() + chrono::Duration::seconds(7200);
            repo.disable("1003", "default", Some(until), 0, 7200)
                .await
                .unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            match result {
                Err(BulwarkError::DisableService { service, until: u }) => {
                    assert_eq!(service, "default");
                    assert!(u.is_some(), "定时封禁 until 应为 Some");
                    assert_eq!(
                        u.unwrap(),
                        until,
                        "定时封禁 until 应精确匹配 disable 时设置的值"
                    );
                },
                other => panic!(
                    "定时封禁应返回 Err(DisableService {{ until: Some(_) }})，实际: {:?}",
                    other
                ),
            }
        }

        /// 未设置 current_token（未登录），check_disable 返回 Ok（不抛错）。
        #[tokio::test]
        async fn test_check_disable_no_token_returns_ok() {
            let (logic, _repo, _dao) = make_logic_with_repo();
            // 不调用 login，也不设置 task_local current_token

            // 直接调用 check_disable（无 task_local 上下文）
            let result = logic.check_disable().await;

            assert!(
                result.is_ok(),
                "未登录（无 current_token）时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 设置 current_token 但对应 TokenSession 不存在，check_disable 返回 Ok（幂等）。
        ///
        /// 覆盖 lines 219-222：token 存在但 session.get_token_session 返回 None → Ok(())。
        #[tokio::test]
        async fn test_check_disable_token_session_not_found_returns_ok() {
            let (logic, _repo, _dao) = make_logic_with_repo();
            // 不调用 login，直接设置一个不存在的 token
            let result = with_current_token("nonexistent-token-xyz".to_string(), async {
                logic.check_disable().await
            })
            .await;

            assert!(
                result.is_ok(),
                "token 对应的 TokenSession 不存在时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }
    }

    // ========================================================================
    // T025: check_safe 默认实现集成测试（需要 safe-auth feature）
    // ========================================================================

    /// T025 集成测试：验证 check_safe 默认实现与 BulwarkLogicDefault inherent method
    /// （open_safe / is_safe / close_safe）的交互。
    ///
    /// 仅在 `safe-auth` feature 启用时编译，因为测试需要 inherent method 支持。
    #[cfg(feature = "safe-auth")]
    mod t025_check_safe_integration {
        use super::*;
        use crate::config::BulwarkConfig;
        use crate::dao::tests::MockDao;
        use crate::dao::BulwarkDao;
        use crate::error::BulwarkError;
        use crate::session::BulwarkSession;
        use crate::stp::session::SessionLogic;
        use crate::stp::with_current_token;
        use crate::stp::LoginParams;
        use crate::strategy::BulwarkPermissionStrategy;
        use async_trait::async_trait;
        use std::sync::Arc;

        // ----------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // ----------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl BulwarkPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> BulwarkResult<bool> {
                Ok(true)
            }
        }

        // ----------------------------------------------------------------
        // 辅助函数
        // ----------------------------------------------------------------

        /// 创建 BulwarkLogicDefault 并返回 (logic, dao) 便于测试。
        fn make_logic() -> (BulwarkLogicDefault, Arc<MockDao>) {
            let dao = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(
                dao.clone() as Arc<dyn BulwarkDao>,
                3600,
                86400,
            ));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall);
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);
            (logic, dao)
        }

        // ----------------------------------------------------------------
        // 4 个集成测试
        // ----------------------------------------------------------------

        /// login → open_safe("default", 3600) → check_safe 返回 Ok(())。
        ///
        /// 验证 open_safe 开启二级认证后，check_safe 默认实现（调用 is_safe）
        /// 能正确识别已认证状态并返回 Ok。
        #[tokio::test]
        async fn t025_check_safe_passes_after_open_safe() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4001", &LoginParams::default())
                .await
                .unwrap();

            let result = with_current_token(token.clone(), async {
                logic.open_safe("default", 3600).await.unwrap();
                logic.check_safe().await
            })
            .await;

            assert!(
                result.is_ok(),
                "open_safe 后 check_safe 应返回 Ok(())，实际: {:?}",
                result
            );
        }

        /// login → check_safe（未 open_safe）→ 返回 Err(NotSafe { reason: "SAFE_EXPIRED" })。
        ///
        /// 验证未开启二级认证时，check_safe 默认实现（调用 is_safe）能正确识别
        /// 未认证状态并返回 NotSafe 错误。
        #[tokio::test]
        async fn t025_check_safe_fails_without_open_safe() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4002", &LoginParams::default())
                .await
                .unwrap();

            let result =
                with_current_token(token.clone(), async { logic.check_safe().await }).await;

            match result {
                Err(BulwarkError::NotSafe { reason }) => {
                    assert_eq!(
                        reason, "SAFE_EXPIRED",
                        "未 open_safe 时 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                    );
                },
                other => panic!(
                    "未 open_safe 时 check_safe 应返回 Err(NotSafe {{ reason: \"SAFE_EXPIRED\" }})，实际: {:?}",
                    other
                ),
            }
        }

        /// login → open_safe("default", 0)（立即过期）→ check_safe → 返回 Err(NotSafe)。
        ///
        /// 验证 duration_secs=0 导致立即过期后，check_safe 能正确识别过期状态。
        #[tokio::test]
        async fn t025_check_safe_fails_after_expiry() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4003", &LoginParams::default())
                .await
                .unwrap();

            let result = with_current_token(token.clone(), async {
                logic.open_safe("default", 0).await.unwrap();
                logic.check_safe().await
            })
            .await;

            match result {
                Err(BulwarkError::NotSafe { reason }) => {
                    assert_eq!(
                        reason, "SAFE_EXPIRED",
                        "过期后 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                    );
                },
                other => panic!(
                    "过期后 check_safe 应返回 Err(NotSafe {{ reason: \"SAFE_EXPIRED\" }})，实际: {:?}",
                    other
                ),
            }
        }

        /// login → open_safe("default") → close_safe("default") → check_safe → 返回 Err(NotSafe)。
        ///
        /// 验证 close_safe 关闭二级认证后，check_safe 能正确识别未认证状态。
        #[tokio::test]
        async fn t025_check_safe_fails_after_close_safe() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4004", &LoginParams::default())
                .await
                .unwrap();

            let result = with_current_token(token.clone(), async {
                logic.open_safe("default", 3600).await.unwrap();
                logic.close_safe("default").await.unwrap();
                logic.check_safe().await
            })
            .await;

            match result {
                Err(BulwarkError::NotSafe { reason }) => {
                    assert_eq!(
                        reason, "SAFE_EXPIRED",
                        "close_safe 后 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                    );
                },
                other => panic!(
                    "close_safe 后 check_safe 应返回 Err(NotSafe {{ reason: \"SAFE_EXPIRED\" }})，实际: {:?}",
                    other
                ),
            }
        }
    }
}
