//! 二级认证（Safe Auth）瞬态标记实现。
//!
//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 本模块在 `safe-auth` feature 启用时，为 `BulwarkLogicDefault` 提供
//! `open_safe` / `is_safe` / `close_safe` 的 inherent method 实现，
//! 基于 `TokenSession.safe_services` 实现 service 级二级认证瞬态标记。
//!
//! # 设计说明：inherent method vs trait 覆写
//!
//! 任务原计划在 safe.rs 中覆写 `MfaLogic` trait 的 `open_safe` 方法，
//! 但 Rust（E0119）禁止同一类型对同一 trait 有多个 impl 块，
//! 而 mfa.rs 已有 `impl MfaLogic for BulwarkLogicDefault`（覆写 `check_disable`）。
//!
//! 因此本模块采用 inherent method 模式：为 `BulwarkLogicDefault` 添加
//! `pub async fn open_safe` inherent method。Rust 方法解析规则保证 inherent method
//! 优先于 trait default method，因此：
//! - `safe-auth` 启用：`logic.open_safe(...)` 调用 inherent method（本模块实现）
//! - `safe-auth` 禁用：safe.rs 不编译，`logic.open_safe(...)` 调用 trait default（`Ok(())`）
//!
//! # 已知限制
//!
//! 通过 trait 引用调用（如 `<BulwarkLogicDefault as MfaLogic>::open_safe`）
//! 会使用 trait default 而非 inherent method。当前所有调用方均通过
//! `BulwarkLogicDefault` 实例直接调用，不受此限制影响。

use super::current_token;
use super::BulwarkLogicDefault;
use crate::error::{BulwarkError, BulwarkResult};

impl BulwarkLogicDefault {
    /// 开启指定 service 的二级认证。
    ///
    /// 在当前 TokenSession 的 safe_services 中记录 service → 过期时间戳。
    ///
    /// # 并发安全
    /// 使用 per-token 锁保护 read-modify-write 序列，避免并发 `open_safe` 调用
    /// 导致 lost update（CRIT-001）。
    ///
    /// # 错误
    /// - `BulwarkError::Session`: 未设置 current_token（未登录）。
    /// - `BulwarkError::InvalidToken`: token 对应的 TokenSession 不存在。
    /// - DAO 读写失败：透传 BulwarkError。
    pub async fn open_safe(&self, service: &str, duration_secs: u64) -> BulwarkResult<()> {
        if service.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "service 参数不能为空".to_string(),
            ));
        }
        let token = current_token()?;
        let token_prefix = if token.len() >= 8 {
            &token[..8]
        } else {
            &token
        };
        let service = service.to_string();
        self.session
            .with_token_session_lock(&token, async {
                let mut ts = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .ok_or_else(|| {
                        BulwarkError::InvalidToken(format!("token 不存在: {}", token_prefix))
                    })?;
                let now = chrono::Utc::now().timestamp();
                let expire_at = now + duration_secs as i64;
                ts.safe_services.insert(service.clone(), expire_at);
                self.session.save_token_session(&token, &ts).await
            })
            .await
    }

    /// 检查指定 service 是否处于二级认证有效期内。
    ///
    /// # 返回
    /// - `Ok(true)`: service 已开启且未过期。
    /// - `Ok(false)`: service 未开启、已过期、或未登录/无 session。
    /// - `Err`: DAO 读取失败。
    ///
    /// # 设计
    /// 未登录或无 session 时返回 `Ok(false)` 而非 `Err`，因为 is_safe 是查询方法，
    /// "未认证" = "不安全" = `Ok(false)` 是合理的语义。只有 DAO 读写失败才返回 `Err`。
    pub async fn is_safe(&self, service: &str) -> BulwarkResult<bool> {
        if service.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "service 参数不能为空".to_string(),
            ));
        }
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };
        let ts = match self.session.get_token_session(&token).await? {
            Some(ts) => ts,
            None => return Ok(false),
        };
        let now = chrono::Utc::now().timestamp();
        match ts.safe_services.get(service) {
            Some(expire_at) => Ok(*expire_at > now),
            None => Ok(false),
        }
    }

    /// 关闭指定 service 的二级认证（移除瞬态标记）。
    ///
    /// 从当前 TokenSession 的 safe_services 中移除 service 条目。
    /// 移除后 `is_safe(service)` 返回 `false`。
    ///
    /// # 并发安全
    /// 使用 per-token 锁保护 read-modify-write 序列，避免并发 `close_safe` 调用
    /// 导致 lost update（CRIT-001）。
    ///
    /// # 参数
    /// - `service`: 服务名称。
    ///
    /// # 返回
    /// - `Ok(())`: 成功关闭（或 service 本就未开启，幂等）。
    /// - `Err`: 未登录或 session 不存在。
    ///
    /// # 错误
    /// - `BulwarkError::Session`: 未设置 current_token（未登录）。
    /// - `BulwarkError::InvalidToken`: token 对应的 TokenSession 不存在。
    /// - DAO 读写失败：透传 BulwarkError。
    pub async fn close_safe(&self, service: &str) -> BulwarkResult<()> {
        if service.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "service 参数不能为空".to_string(),
            ));
        }
        let token = current_token()?;
        let token_prefix = if token.len() >= 8 {
            &token[..8]
        } else {
            &token
        };
        let service = service.to_string();
        self.session
            .with_token_session_lock(&token, async {
                let mut ts = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .ok_or_else(|| {
                        BulwarkError::InvalidToken(format!("token 不存在: {}", token_prefix))
                    })?;
                ts.safe_services.remove(&service);
                self.session.save_token_session(&token, &ts).await
            })
            .await
    }
}

#[cfg(test)]
mod tests {
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
        async fn check_role_any(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn check_role_all(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(true)
        }
    }

    // --------------------------------------------------------------------
    // 辅助函数
    // --------------------------------------------------------------------

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

    // --------------------------------------------------------------------
    // 6 个单元测试
    // --------------------------------------------------------------------

    /// open_safe 后 TokenSession.safe_services 包含对应 service 和正确的过期时间。
    #[tokio::test]
    async fn t022_open_safe_sets_safe_marker() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-1001", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
        })
        .await;

        // 验证 safe_services 已设置
        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        let expire = ts
            .safe_services
            .get("default")
            .expect("default 应在 safe_services 中");
        let now = chrono::Utc::now().timestamp();
        assert!(
            *expire > now,
            "过期时间应在未来，实际: expire={}, now={}",
            expire,
            now
        );
        assert!(
            *expire <= now + 3601,
            "过期时间应在 now+3600 附近，实际: expire={}, now={}",
            expire,
            now
        );
    }

    /// open_safe("default") + open_safe("payment") 后 safe_services 包含 2 个 entry。
    #[tokio::test]
    async fn t022_open_safe_multiple_services_coexist() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-1002", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            logic.open_safe("payment", 7200).await.unwrap();
        })
        .await;

        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ts.safe_services.len(),
            2,
            "应有 2 个 service 标记，实际: {:?}",
            ts.safe_services
        );

        let default_expire = ts.safe_services.get("default").expect("default 应存在");
        let payment_expire = ts.safe_services.get("payment").expect("payment 应存在");
        let now = chrono::Utc::now().timestamp();
        assert!(
            *default_expire > now && *default_expire <= now + 3601,
            "default 过期时间应在 now+3600 附近，实际: {}, now={}",
            default_expire,
            now
        );
        assert!(
            *payment_expire > now && *payment_expire <= now + 7201,
            "payment 过期时间应在 now+7200 附近，实际: {}, now={}",
            payment_expire,
            now
        );
    }

    /// open_safe("default", 100) 后再 open_safe("default", 200) 后，过期时间更新为 now+200。
    #[tokio::test]
    async fn t022_open_safe_overwrites_existing_marker() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-1003", &LoginParams::default())
            .await
            .unwrap();

        // 第一次 open_safe，duration=100
        with_current_token(token.clone(), async {
            logic.open_safe("default", 100).await.unwrap();
        })
        .await;
        let ts1 = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        let expire1 = *ts1
            .safe_services
            .get("default")
            .expect("第一次 open_safe 后 default 应存在");

        // 第二次 open_safe 同一 service，duration=200
        with_current_token(token.clone(), async {
            logic.open_safe("default", 200).await.unwrap();
        })
        .await;
        let ts2 = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        let expire2 = *ts2
            .safe_services
            .get("default")
            .expect("第二次 open_safe 后 default 应存在");
        let now = chrono::Utc::now().timestamp();

        // 验证过期时间更新为 now+200 附近，而非保留 expire1
        assert!(
            expire2 > expire1,
            "第二次 open_safe 应覆盖第一次，过期时间应更新，实际: expire1={}, expire2={}",
            expire1,
            expire2
        );
        assert!(
            expire2 >= now + 199 && expire2 <= now + 201,
            "过期时间应在 now+200 附近，实际: expire2={}, now={}",
            expire2,
            now
        );
        // safe_services 仍只有 1 个 entry（覆盖而非新增）
        assert_eq!(
            ts2.safe_services.len(),
            1,
            "覆盖后 safe_services 应仍为 1 个 entry，实际: {:?}",
            ts2.safe_services
        );
    }

    /// duration_secs=0 时 safe_services 中有标记但过期时间为 now（已过期）。
    #[tokio::test]
    async fn t022_open_safe_duration_zero_immediate_expiry() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-1004", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token.clone(), async {
            logic.open_safe("default", 0).await.unwrap();
        })
        .await;

        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        let expire = ts
            .safe_services
            .get("default")
            .expect("default 应在 safe_services 中");
        let now = chrono::Utc::now().timestamp();
        // duration_secs=0 → expire_at = now + 0 = now（已过期）
        // 允许 ±5 秒偏差（测试执行耗时）
        assert!(
            *expire <= now,
            "duration=0 时过期时间应 <= now（已过期），实际: expire={}, now={}",
            expire,
            now
        );
        assert!(
            *expire >= now - 5,
            "过期时间应在 now 附近（允许 5 秒偏差），实际: expire={}, now={}",
            expire,
            now
        );
    }

    /// 不 login 直接调用 open_safe，返回 Err（Session 错误 - 未设置 current_token）。
    #[tokio::test]
    async fn t022_open_safe_no_session_returns_err() {
        let (logic, _dao) = make_logic();
        // 不 login，不设置 current_token，直接调用 open_safe
        let result = logic.open_safe("default", 3600).await;

        match result {
            Err(BulwarkError::Session(msg)) => {
                assert!(
                    msg.contains("未设置") || msg.contains("with_current_token"),
                    "Session 错误消息应说明未设置 current_token，实际: {}",
                    msg
                );
            },
            other => panic!("期望 Err(BulwarkError::Session)，实际: {:?}", other),
        }
    }

    /// login 后手动删除 token session，再调用 open_safe 返回 InvalidToken。
    #[tokio::test]
    async fn t022_open_safe_token_not_exist_returns_err() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-1006", &LoginParams::default())
            .await
            .unwrap();

        // 删除 token session 模拟 token 不存在
        logic.session.logout(&token).await.unwrap();

        let result = with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await
        })
        .await;

        match result {
            Err(BulwarkError::InvalidToken(msg)) => {
                // token 脱敏：错误消息只包含前 8 字符
                let expected_prefix = if token.len() >= 8 {
                    &token[..8]
                } else {
                    &token
                };
                assert!(
                    msg.contains(expected_prefix),
                    "InvalidToken 错误消息应包含 token 前缀，实际: {}",
                    msg
                );
                assert!(
                    !msg.contains(&token) || token.len() <= 8,
                    "InvalidToken 错误消息不应包含完整 token（脱敏），实际: {}",
                    msg
                );
            },
            other => panic!("期望 Err(BulwarkError::InvalidToken)，实际: {:?}", other),
        }
    }

    // --------------------------------------------------------------------
    // T023: is_safe 单元测试
    // --------------------------------------------------------------------

    /// open_safe("default", 3600) 后 is_safe("default") 返回 Ok(true)。
    #[tokio::test]
    async fn t023_is_safe_returns_true_within_validity() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-2001", &LoginParams::default())
            .await
            .unwrap();

        let result = with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            logic.is_safe("default").await
        })
        .await;

        assert_eq!(
            result.unwrap(),
            true,
            "open_safe 后 3600 秒内 is_safe 应返回 true"
        );
    }

    /// open_safe("default", 0) 后 is_safe("default") 返回 Ok(false)（duration=0 立即过期）。
    #[tokio::test]
    async fn t023_is_safe_returns_false_after_expiry() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-2002", &LoginParams::default())
            .await
            .unwrap();

        let result = with_current_token(token.clone(), async {
            logic.open_safe("default", 0).await.unwrap();
            logic.is_safe("default").await
        })
        .await;

        assert_eq!(
            result.unwrap(),
            false,
            "duration=0 立即过期，is_safe 应返回 false"
        );
    }

    /// open_safe("default") 后 is_safe("payment") 返回 Ok(false)（payment 未开启）。
    #[tokio::test]
    async fn t023_is_safe_returns_false_without_marker() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-2003", &LoginParams::default())
            .await
            .unwrap();

        let result = with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            logic.is_safe("payment").await
        })
        .await;

        assert_eq!(
            result.unwrap(),
            false,
            "payment 未 open_safe，is_safe 应返回 false"
        );
    }

    /// 多 service 独立：default + payment 都 open_safe 后两者都 true；
    /// 手动让 payment 过期后，default 仍 true，payment 变 false。
    #[tokio::test]
    async fn t023_is_safe_multi_service_independent() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-2004", &LoginParams::default())
            .await
            .unwrap();

        // 两个 service 都开启
        with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            logic.open_safe("payment", 7200).await.unwrap();
        })
        .await;

        // 两者都应处于有效期内
        let (safe_default, safe_payment) = with_current_token(token.clone(), async {
            (
                logic.is_safe("default").await.unwrap(),
                logic.is_safe("payment").await.unwrap(),
            )
        })
        .await;
        assert!(safe_default, "default 应处于有效期内");
        assert!(safe_payment, "payment 应处于有效期内");

        // 修改 safe_services 模拟 payment 过期
        let now = chrono::Utc::now().timestamp();
        let mut ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        ts.safe_services.insert("payment".to_string(), now - 100);
        logic.session.save_token_session(&token, &ts).await.unwrap();

        // default 仍 true，payment 变 false（独立性验证）
        let (safe_default_after, safe_payment_after) = with_current_token(token.clone(), async {
            (
                logic.is_safe("default").await.unwrap(),
                logic.is_safe("payment").await.unwrap(),
            )
        })
        .await;
        assert!(
            safe_default_after,
            "payment 过期不应影响 default，default 应仍为 true"
        );
        assert!(!safe_payment_after, "payment 过期后 is_safe 应返回 false");
    }

    /// open_safe("default") 后手动删除 safe_services 中的 default 条目（模拟 close_safe），
    /// is_safe("default") 返回 Ok(false)。
    #[tokio::test]
    async fn t023_is_safe_returns_false_after_marker_removed() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-2005", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
        })
        .await;

        // 删除 default 条目模拟 close_safe 效果
        let mut ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        ts.safe_services.remove("default");
        logic.session.save_token_session(&token, &ts).await.unwrap();

        let result =
            with_current_token(token.clone(), async { logic.is_safe("default").await }).await;

        assert_eq!(
            result.unwrap(),
            false,
            "删除 safe_services 标记后 is_safe 应返回 false"
        );
    }

    /// 不 login 直接调用 is_safe，返回 Ok(false)（不报错）。
    #[tokio::test]
    async fn t023_is_safe_returns_false_when_not_logged_in() {
        let (logic, _dao) = make_logic();
        // 不 login，不设置 current_token，直接调用 is_safe
        let result = logic.is_safe("default").await;

        assert!(
            result.is_ok(),
            "未登录时 is_safe 应返回 Ok(false) 而非 Err，实际: {:?}",
            result
        );
        assert_eq!(result.unwrap(), false, "未登录时 is_safe 应返回 Ok(false)");
    }

    /// is_safe("") 返回 Err(InvalidParam) — service 参数不能为空。
    #[tokio::test]
    async fn t023_is_safe_empty_service_returns_err() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-2007", &LoginParams::default())
            .await
            .unwrap();

        let result = with_current_token(token, async { logic.is_safe("").await }).await;

        match result {
            Err(BulwarkError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("service"),
                    "InvalidParam 错误消息应说明 service 参数问题，实际: {}",
                    msg
                );
            },
            other => panic!("期望 Err(InvalidParam)，实际: {:?}", other),
        }
    }

    // --------------------------------------------------------------------
    // T024: close_safe 单元测试
    // --------------------------------------------------------------------

    /// open_safe("default") 后 close_safe("default")，safe_services 中 default 条目被移除（len=0）。
    #[tokio::test]
    async fn t024_close_safe_removes_existing_marker() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-3001", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            logic.close_safe("default").await.unwrap();
        })
        .await;

        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ts.safe_services.len(),
            0,
            "close_safe 后 default 条目应被移除，safe_services 应为空，实际: {:?}",
            ts.safe_services
        );
        assert!(
            !ts.safe_services.contains_key("default"),
            "default 不应仍在 safe_services 中"
        );
    }

    /// 直接 close_safe("default")（未 open_safe），返回 Ok(())，safe_services 仍为空（幂等）。
    #[tokio::test]
    async fn t024_close_safe_nonexistent_marker_is_noop() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-3002", &LoginParams::default())
            .await
            .unwrap();

        let result =
            with_current_token(token.clone(), async { logic.close_safe("default").await }).await;

        assert!(
            result.is_ok(),
            "close_safe 不存在的标记应幂等返回 Ok(())，实际: {:?}",
            result
        );
        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ts.safe_services.len(),
            0,
            "未 open_safe 直接 close_safe 后 safe_services 应仍为空，实际: {:?}",
            ts.safe_services
        );
    }

    /// open_safe("default") 后 is_safe=true，close_safe("default") 后 is_safe=false。
    #[tokio::test]
    async fn t024_close_safe_then_is_safe_returns_false() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-3003", &LoginParams::default())
            .await
            .unwrap();

        let (before, after) = with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            let before = logic.is_safe("default").await.unwrap();
            logic.close_safe("default").await.unwrap();
            let after = logic.is_safe("default").await.unwrap();
            (before, after)
        })
        .await;

        assert!(before, "open_safe 后 is_safe 应返回 true");
        assert!(!after, "close_safe 后 is_safe 应返回 false");
    }

    /// open_safe("default") + open_safe("payment") 后 close_safe("default")，
    /// safe_services 中只剩 payment（default 被移除），is_safe("default")=false, is_safe("payment")=true。
    #[tokio::test]
    async fn t024_close_safe_only_removes_specified_service() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-3004", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.unwrap();
            logic.open_safe("payment", 7200).await.unwrap();
            logic.close_safe("default").await.unwrap();
        })
        .await;

        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ts.safe_services.len(),
            1,
            "close_safe(default) 后应只剩 1 个 service 标记，实际: {:?}",
            ts.safe_services
        );
        assert!(
            !ts.safe_services.contains_key("default"),
            "default 应已被 close_safe 移除"
        );
        assert!(
            ts.safe_services.contains_key("payment"),
            "payment 应仍存在，未被 close_safe(default) 影响"
        );

        // 验证 is_safe 的语义一致性
        let (safe_default, safe_payment) = with_current_token(token.clone(), async {
            (
                logic.is_safe("default").await.unwrap(),
                logic.is_safe("payment").await.unwrap(),
            )
        })
        .await;
        assert!(
            !safe_default,
            "close_safe(default) 后 is_safe(default) 应返回 false"
        );
        assert!(
            safe_payment,
            "close_safe(default) 不应影响 payment，is_safe(payment) 应仍返回 true"
        );
    }

    /// close_safe("") 返回 Err(InvalidParam) — service 参数不能为空。
    #[tokio::test]
    async fn t024_close_safe_empty_service_returns_err() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-3005", &LoginParams::default())
            .await
            .unwrap();

        let result = with_current_token(token, async { logic.close_safe("").await }).await;

        match result {
            Err(BulwarkError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("service"),
                    "InvalidParam 错误消息应说明 service 参数问题，实际: {}",
                    msg
                );
            },
            other => panic!("期望 Err(InvalidParam)，实际: {:?}", other),
        }
    }

    // --------------------------------------------------------------------
    // T026: Feature gate 注册验证（编译测试）
    // --------------------------------------------------------------------

    /// T026: safe-auth feature 启用时，open_safe/is_safe/close_safe inherent methods
    /// 可访问且行为正确。
    ///
    /// 验证 feature gate 配置：safe-auth 启用 → safe.rs 编译 → inherent methods 可调用。
    /// 本测试在 `--features safe-auth` 或 `--features full` 下编译并运行。
    #[cfg(feature = "safe-auth")]
    #[tokio::test]
    async fn t026_safe_auth_feature_compiles_when_enabled() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-t026-001", &LoginParams::default())
            .await
            .unwrap();

        // 验证 3 个 inherent methods 均可调用且行为正确
        with_current_token(token, async {
            // open_safe: 开启二级认证
            logic.open_safe("default", 3600).await.unwrap();
            // is_safe: 验证已开启
            assert!(
                logic.is_safe("default").await.unwrap(),
                "open_safe 后 is_safe 应返回 true（inherent method 可访问）"
            );
            // close_safe: 关闭二级认证
            logic.close_safe("default").await.unwrap();
            // is_safe: 验证已关闭
            assert!(
                !logic.is_safe("default").await.unwrap(),
                "close_safe 后 is_safe 应返回 false（inherent method 可访问）"
            );
        })
        .await;
    }

    /// T026: safe-auth feature 禁用时，BulwarkLogicDefault 没有 open_safe inherent method，
    /// 调用解析到 MfaLogic trait default（open_safe=Ok(()), is_safe=Ok(true), close_safe=Ok(())）。
    ///
    /// 注意：本测试位于 safe.rs（`#[cfg(feature = "safe-auth")]` 门控）内部，
    /// `#[cfg(not(feature = "safe-auth"))]` 使其在任何配置下都不会编译。
    /// 此测试作为 feature gate 配置正确性的文档化验证：
    /// 若将本测试移至非 feature-gated 模块并在 `--lib`（无 safe-auth）下运行，
    /// 应验证 trait default 行为（open_safe=Ok, is_safe=Ok(true), close_safe=Ok）。
    #[cfg(not(feature = "safe-auth"))]
    #[tokio::test]
    async fn t026_safe_auth_not_in_scope_when_disabled() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-t026-002", &LoginParams::default())
            .await
            .unwrap();

        // safe-auth 禁用时，open_safe/is_safe/close_safe 解析到 MfaLogic trait default
        with_current_token(token, async {
            // open_safe trait default: Ok(()) (no-op)
            assert!(
                logic.open_safe("default", 3600).await.is_ok(),
                "safe-auth 禁用时 open_safe 应走 trait default 返回 Ok(())"
            );
            // is_safe trait default: Ok(true) (always safe)
            assert!(
                logic.is_safe("default").await.unwrap_or(false),
                "safe-auth 禁用时 is_safe 应走 trait default 返回 Ok(true)"
            );
            // close_safe trait default: Ok(()) (no-op)
            assert!(
                logic.close_safe("default").await.is_ok(),
                "safe-auth 禁用时 close_safe 应走 trait default 返回 Ok(())"
            );
        })
        .await;
    }

    /// T026: full feature 启用时 safe-auth 也启用（Cargo.toml full 列表包含 "safe-auth"）。
    ///
    /// 验证 Cargo.toml 配置正确性：full → safe-auth 依赖关系。
    /// 本测试在 `--features full` 下编译并运行（full 隐含 safe-auth）。
    #[cfg(all(feature = "full", feature = "safe-auth"))]
    #[tokio::test]
    async fn t026_full_feature_includes_safe_auth() {
        let (logic, _dao) = make_logic();
        let token = logic
            .login("user-t026-003", &LoginParams::default())
            .await
            .unwrap();

        // full feature 启用时 safe-auth 也应启用，inherent methods 可访问
        with_current_token(token, async {
            logic.open_safe("default", 3600).await.unwrap();
            assert!(
                logic.is_safe("default").await.unwrap(),
                "full feature 启用时 safe-auth 也启用，is_safe inherent method 应可访问"
            );
            logic.close_safe("default").await.unwrap();
        })
        .await;
    }

    // --------------------------------------------------------------------
    // CRIT-001: open_safe/close_safe 并发竞态测试
    // --------------------------------------------------------------------

    /// SlowDao wrapper：在 `get` token session key 后插入延迟，
    /// 放大 TokenSession read-modify-write 窗口，使 CRIT-001 竞态可靠复现。
    ///
    /// 无锁时：两个并发 `open_safe` 都会在对方的 `save_token_session` 之前读到
    /// 旧的 TokenSession，导致 lost update（最终 safe_services 只剩 1 个 service 而非 2 个）。
    struct SlowDao {
        inner: Arc<MockDao>,
        delay: std::time::Duration,
    }

    #[async_trait]
    impl BulwarkDao for SlowDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let result = self.inner.get(key).await;
            // 仅对 token:session:* key 插入延迟，放大 read-modify-write 窗口
            if key.starts_with("token:session:") {
                tokio::time::sleep(self.delay).await;
            }
            result
        }
        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.inner.delete(key).await
        }
    }

    /// 创建使用 SlowDao 的 BulwarkSession，放大 token session 读写延迟。
    fn make_slow_session(delay: std::time::Duration) -> (Arc<MockDao>, Arc<BulwarkSession>) {
        let inner = Arc::new(MockDao::new());
        let dao: Arc<dyn BulwarkDao> = Arc::new(SlowDao {
            inner: inner.clone(),
            delay,
        });
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        (inner, session)
    }

    /// 模拟 open_safe 的 read-modify-write 操作（不依赖 task_local current_token）。
    ///
    /// 直接调用 `with_token_session_lock` 包裹的 read-modify-write 序列，
    /// 等价于 `open_safe` 的核心逻辑，用于测试并发安全性。
    async fn simulate_open_safe(
        session: &BulwarkSession,
        token: &str,
        service: &str,
        duration_secs: u64,
    ) -> BulwarkResult<()> {
        let service = service.to_string();
        session
            .with_token_session_lock(token, async {
                let mut ts = session
                    .get_token_session(token)
                    .await?
                    .ok_or_else(|| BulwarkError::InvalidToken("token 不存在".to_string()))?;
                let now = chrono::Utc::now().timestamp();
                let expire_at = now + duration_secs as i64;
                ts.safe_services.insert(service.clone(), expire_at);
                session.save_token_session(token, &ts).await
            })
            .await
    }

    /// 模拟 close_safe 的 read-modify-write 操作（不依赖 task_local current_token）。
    async fn simulate_close_safe(
        session: &BulwarkSession,
        token: &str,
        service: &str,
    ) -> BulwarkResult<()> {
        let service = service.to_string();
        session
            .with_token_session_lock(token, async {
                let mut ts = session
                    .get_token_session(token)
                    .await?
                    .ok_or_else(|| BulwarkError::InvalidToken("token 不存在".to_string()))?;
                ts.safe_services.remove(&service);
                session.save_token_session(token, &ts).await
            })
            .await
    }

    /// CRIT-001 修复验证：两个并发 `open_safe` 不同 service，safe_services 应包含两个 service。
    ///
    /// 修复前（无 per-token 锁）：两个并发 open_safe 的 read-modify-write 交错，
    /// 后写入的 TokenSession 覆盖先写入的，导致丢失一个 service（lost update）。
    /// 修复后（per-token 锁）：两个 open_safe 串行化，safe_services 完整保留两个 service。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crit001_concurrent_open_safe_different_services_no_lost_update() {
        let (_dao, session) = make_slow_session(std::time::Duration::from_millis(50));
        session.create("user-crit001-001", "T1").await.unwrap();

        // 并发执行两次 open_safe 不同 service（用 tokio::join! 确保并发）
        let (r1, r2) = tokio::join!(
            simulate_open_safe(&session, "T1", "default", 3600),
            simulate_open_safe(&session, "T1", "payment", 7200),
        );
        r1.expect("open_safe default 应成功");
        r2.expect("open_safe payment 应成功");

        // 验证 safe_services 包含两个 service（修复前会丢失一个）
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(
            ts.safe_services.len(),
            2,
            "并发 open_safe 后 safe_services 应包含 2 个 service（修复前 lost update 导致只剩 1 个），实际: {:?}",
            ts.safe_services
        );
        assert!(
            ts.safe_services.contains_key("default"),
            "default 应在 safe_services 中，实际: {:?}",
            ts.safe_services
        );
        assert!(
            ts.safe_services.contains_key("payment"),
            "payment 应在 safe_services 中，实际: {:?}",
            ts.safe_services
        );
    }

    /// CRIT-001 修复验证：两个并发 `close_safe` 不同 service，safe_services 应清空。
    ///
    /// 修复前（无 per-token 锁）：两个并发 close_safe 的 read-modify-write 交错，
    /// 后写入的 TokenSession 覆盖先写入的，导致已关闭的 service 被恢复（lost update）。
    /// 修复后（per-token 锁）：两个 close_safe 串行化，两个 service 都被正确移除。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crit001_concurrent_close_safe_different_services_no_lost_update() {
        let (_dao, session) = make_slow_session(std::time::Duration::from_millis(50));
        session.create("user-crit001-002", "T1").await.unwrap();

        // 先顺序添加两个 service
        simulate_open_safe(&session, "T1", "default", 3600)
            .await
            .unwrap();
        simulate_open_safe(&session, "T1", "payment", 7200)
            .await
            .unwrap();

        // 验证两个 service 都已添加
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(ts.safe_services.len(), 2, "前置条件：应有 2 个 service");

        // 并发执行两次 close_safe 不同 service
        let (r1, r2) = tokio::join!(
            simulate_close_safe(&session, "T1", "default"),
            simulate_close_safe(&session, "T1", "payment"),
        );
        r1.expect("close_safe default 应成功");
        r2.expect("close_safe payment 应成功");

        // 验证 safe_services 已清空（修复前会因 lost update 残留 1 个 service）
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(
            ts.safe_services.len(),
            0,
            "并发 close_safe 后 safe_services 应为空（修复前 lost update 导致残留 1 个），实际: {:?}",
            ts.safe_services
        );
    }
}
