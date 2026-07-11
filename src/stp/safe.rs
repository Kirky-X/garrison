//! 二级认证（Safe Auth）瞬态标记实现。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
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
    /// # 错误
    /// - `BulwarkError::Session`: 未设置 current_token（未登录）。
    /// - `BulwarkError::InvalidToken`: token 对应的 TokenSession 不存在。
    /// - DAO 读写失败：透传 BulwarkError。
    pub async fn open_safe(&self, service: &str, duration_secs: u64) -> BulwarkResult<()> {
        let token = current_token()?;
        let mut ts = self
            .session
            .get_token_session(&token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken(format!("token 不存在: {}", token)))?;
        let now = chrono::Utc::now().timestamp();
        let expire_at = now + duration_secs as i64;
        ts.safe_services.insert(service.to_string(), expire_at);
        self.session.save_token_session(&token, &ts).await
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
                assert!(
                    msg.contains(&token),
                    "InvalidToken 错误消息应包含 token，实际: {}",
                    msg
                );
            },
            other => panic!("期望 Err(BulwarkError::InvalidToken)，实际: {:?}", other),
        }
    }
}
