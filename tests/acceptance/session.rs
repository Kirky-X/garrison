//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! session 域验收（spec `acceptance-matrix` R-acceptance-matrix-002，
//! 任务 T021）。双模会话读写 / TTL 续期 / 过期监听 / IP 安全监听 / 设备绑定 MFA /
//! 匿名会话边界 / 过期读取为空，「正常 + 异常」成对覆盖，场景编号 `ACC-SESS-NNN`。
//!
//! 全部场景基于独立 `GarrisonSession` / `GarrisonLogicDefault` 实例构造，
//! 不触碰 `GarrisonManager` 全局单例，故不加 `#[serial]`；并发场景统一使用
//! `multi_thread` flavor（与 tests/integration/strategy_registry.rs 的 make_logic
//! 直构惯例一致）。
//!
//! Phase 4 测试迁移（T040/T043）：
//! - ACC-SESS-019 自 tests/e2e（login device/ip/ua 写入 + get-token-info/get-session）移植；
//! - ACC-SESS-017 自 tests/acceptance_criteria.rs **BW-AC-003** 移植（编号注释保留）；
//! - ACC-SESS-018 自 tests/acceptance_criteria.rs **BW-AC-001** 移植（编号注释保留）；
//! - 去重注释：BW-AC-002 → ACC-SESS-003（touch/renew 重置 TTL 语义等价）、
//!   BW-AC-009 的 Token-Session 删除部分 → ACC-SESS-001。

use garrison::constants::DaoKeyPrefix;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::session::{
    GarrisonSession, SessionExpiryListener, SessionSecurityListener, TokenSession,
};
use garrison::stp::{GarrisonInterface, GarrisonLogicDefault, LoginParams, SessionLogic};
use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};
use serial_test::serial;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 空授权 `GarrisonInterface` 替身（仅满足策略构造，不参与断言）。
struct NoopInterface;

#[async_trait::async_trait]
impl GarrisonInterface for NoopInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

// ============================================================================
// 辅助：TTL 盲读 DAO（ACC-SESS-003 续期语义观察）
// ============================================================================

/// 对 `get_with_ttl` 隐藏剩余 TTL 的 DAO 包装。
///
/// `GarrisonSession::touch`（`renew` 的底层实现）优先读取旧键剩余 TTL 回写；
/// 本包装令 `get_with_ttl` 返回 `(value, None)`，使续期落入「重置为完整 timeout」
/// 语义（与 src 单元测试 MockDao 语义一致），从而可观察「renew 重置 TTL」契约
/// （见 T021 报告中的 API 偏差说明：TTL 感知型 DAO 下 touch 保留剩余 TTL）。
struct TtlBlindDao {
    inner: Arc<InMemoryDao>,
}

#[async_trait::async_trait]
impl GarrisonDao for TtlBlindDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.inner.get(key).await
    }
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        self.inner.set(key, value, ttl_seconds).await
    }
    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.inner.update(key, value).await
    }
    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        self.inner.expire(key, seconds).await
    }
    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.inner.delete(key).await
    }
    /// 隐藏剩余 TTL（返回 `None`），驱动 touch 走「重置完整 timeout」分支。
    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>> {
        Ok(self.inner.get(key).await?.map(|v| (v, None)))
    }
    /// 剩余 TTL 观察仍委托真实实现（供 `get_token_timeout` 断言）。
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
        self.inner.get_timeout(key).await
    }

    garrison::atomic_test_fallback!();
}

// ============================================================================
// 辅助：过期监听器替身（ACC-SESS-004）
// ============================================================================

/// 会话过期监听器替身：记录回调次数与最近一次 (login_id, token)。
struct RecordingExpiryListener {
    calls: AtomicUsize,
    last_login: Mutex<Option<String>>,
    last_token: Mutex<Option<String>>,
}

impl RecordingExpiryListener {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            last_login: Mutex::new(None),
            last_token: Mutex::new(None),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_call(&self) -> (Option<String>, Option<String>) {
        (
            self.last_login.lock().unwrap().clone(),
            self.last_token.lock().unwrap().clone(),
        )
    }
}

#[async_trait::async_trait]
impl SessionExpiryListener for RecordingExpiryListener {
    async fn on_session_expired(&self, login_id: &str, token: &str) -> GarrisonResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_login.lock().unwrap() = Some(login_id.to_string());
        *self.last_token.lock().unwrap() = Some(token.to_string());
        Ok(())
    }
}

// ------------------------------------------------------------------------
// ACC-SESS-001..003：双模会话读写 / 登录链路写入 / TTL 续期（正常）
// ------------------------------------------------------------------------

/// ACC-SESS-001（正常）：Account/Token 双模会话读写——`create` 双写两套会话，
/// 可读回 `login_id` / 自定义属性；`logout` 后 Token-Session 删除、Account-Session
/// 保留历史（token 列表为空）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_001_dual_mode_session_read_write() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = GarrisonSession::new(dao, 3600, 86400, 0);

    session.create("1001", "T1").await.unwrap();

    // Token-Session：双写读回
    let ts = session
        .get_token_session("T1")
        .await
        .unwrap()
        .expect("Token-Session 应存在");
    assert_eq!(ts.login_id, "1001", "Token-Session 应绑定登录主体 1001");
    assert_eq!(ts.token, "T1", "Token-Session 应记录 token 值");
    assert_eq!(
        ts.created_at, ts.last_active_at,
        "创建时 last_active_at 应等于 created_at"
    );

    // Account-Session：tokens 列表含 T1
    let as_ = session
        .get_account_session("1001")
        .await
        .unwrap()
        .expect("Account-Session 应存在");
    assert_eq!(as_.login_id, "1001", "Account-Session 主体应为 1001");
    assert_eq!(as_.tokens.len(), 1, "Account-Session 应记录 1 个 token");
    assert_eq!(
        as_.tokens[0].token, "T1",
        "Account-Session 的 token 列表应包含 T1"
    );

    // 会话级自定义属性读写
    session.set("T1", "ip", "192.168.1.10").await.unwrap();
    assert_eq!(
        session.get("T1", "ip").await.unwrap(),
        Some("192.168.1.10".to_string()),
        "自定义属性应可读回"
    );

    // logout：Token-Session 删除，Account-Session 保留历史
    session.logout("T1").await.unwrap();
    assert!(
        session.get_token_session("T1").await.unwrap().is_none(),
        "logout 后 Token-Session 应删除"
    );
    let as_after = session
        .get_account_session("1001")
        .await
        .unwrap()
        .expect("Account-Session 保留历史不应删除");
    assert!(
        as_after.tokens.is_empty(),
        "Account-Session 的 token 列表应清空但保留会话本身"
    );
}

/// ACC-SESS-002（正常）：经登录链路写入双模会话——`GarrisonLogicDefault::login`
/// 签发 token 后，`GarrisonSession::get_token_session` 可反查主体，
/// Account-Session 同步记录。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_002_login_writes_dual_mode_sessions() {
    let session = Arc::new(GarrisonSession::new(
        Arc::new(InMemoryDao::new()),
        3600,
        86400,
        0,
    ));
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );
    let logic = GarrisonLogicDefault::new(
        session.clone(),
        Arc::new(garrison::config::GarrisonConfig::default_config()),
        firewall,
    );

    let token = logic
        .login("1001", &LoginParams::default())
        .await
        .expect("login 应成功");
    assert!(!token.is_empty(), "login 应签发非空 token");

    let ts = session
        .get_token_session(&token)
        .await
        .unwrap()
        .expect("登录后 Token-Session 应存在");
    assert_eq!(ts.login_id, "1001", "按 token 反查应绑定登录主体 1001");

    let as_ = session
        .get_account_session("1001")
        .await
        .unwrap()
        .expect("登录后 Account-Session 应存在");
    assert!(
        as_.tokens.iter().any(|t| t.token == token),
        "Account-Session 的 token 列表应包含新签发 token"
    );
}

/// ACC-SESS-003（正常+异常）：TTL 续期——`renew` 将剩余 TTL 重置为完整 timeout
///（`get_token_timeout` 观察：续期后剩余 TTL 明显大于续期前），续期后跨过原超时
/// 点仍有效；异常侧：续期不存在的 token 返回 `InvalidToken`。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_003_renew_resets_ttl() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(TtlBlindDao {
        inner: Arc::new(InMemoryDao::new()),
    });
    let session = GarrisonSession::new(dao, 3, 86400, 0); // token TTL=3s

    session.create("1001", "T1").await.unwrap();

    let ttl0 = session
        .get_token_timeout("T1")
        .await
        .unwrap()
        .expect("创建后应有剩余 TTL");
    assert!(
        ttl0 >= Duration::from_secs(2),
        "创建后剩余 TTL 应接近完整 timeout=3s，实际: {ttl0:?}"
    );

    // 消耗 1s → 剩余 ≈2s
    tokio::time::sleep(Duration::from_secs(1)).await;
    let ttl_before = session
        .get_token_timeout("T1")
        .await
        .unwrap()
        .expect("续期前应有剩余 TTL");

    // renew 重置 TTL 为完整 timeout
    session.renew("T1").await.unwrap();
    let ttl_after = session
        .get_token_timeout("T1")
        .await
        .unwrap()
        .expect("续期后应有剩余 TTL");
    assert!(
        ttl_after > ttl_before,
        "续期后剩余 TTL（{ttl_after:?}）应大于续期前（{ttl_before:?}）——TTL 已被重置"
    );
    assert!(
        ttl_after >= Duration::from_secs(2),
        "续期后剩余 TTL 应重置回完整 timeout=3s，实际: {ttl_after:?}"
    );

    // 续期后跨过原超时点（create 后 1+2.2=3.2s > 3s）仍有效
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(
        session.is_valid("T1").await.unwrap(),
        "renew 后 token 应跨过原超时点仍有效（TTL 已重置）"
    );

    // 异常侧：续期不存在的 token → InvalidToken
    let err = session.renew("ghost-token").await.unwrap_err();
    assert!(
        matches!(err, GarrisonError::InvalidToken(_)),
        "续期不存在的 token 应返回 InvalidToken，实际: {err:?}"
    );
}

// ------------------------------------------------------------------------
// ACC-SESS-004：过期监听器（正常）
// ------------------------------------------------------------------------

/// ACC-SESS-004（正常）：`SessionExpiryListener` 触发——Token-Session 过期被
/// `get_token_session` 发现时回调（携带 login_id/token），并从 DAO 清理；
/// 活跃会话不触发回调。
#[cfg(feature = "listener")]
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_004_expiry_listener_fires_on_expired_session() {
    let dao = Arc::new(InMemoryDao::new());
    let mut session = GarrisonSession::new(dao.clone(), 3600, 86400, 0);
    let listener = RecordingExpiryListener::new();
    session.add_expiry_listener(listener.clone());

    session.create("1001", "T1").await.unwrap();

    // 改写 DAO 中 Token-Session 的 last_active_at 到过去 → 模拟 session 级过期
    let key = format!("{}session:T1", DaoKeyPrefix::Token);
    let json = dao
        .get(&key)
        .await
        .unwrap()
        .expect("Token-Session 应已写入 DAO");
    let mut ts: TokenSession = serde_json::from_str(&json).expect("应能解析 TokenSession JSON");
    ts.last_active_at = chrono::Utc::now().timestamp() - 3601; // 超过 timeout=3600
    let rewritten = serde_json::to_string(&ts).unwrap();
    dao.set(&key, &rewritten, 3600).await.unwrap();

    // 过期读取为空 + 触发回调
    let got = session.get_token_session("T1").await.unwrap();
    assert!(got.is_none(), "过期会话读取应返回 None");
    assert_eq!(listener.calls(), 1, "过期会话应触发 1 次回调");
    let (login, token) = listener.last_call();
    assert_eq!(login.as_deref(), Some("1001"), "回调应携带 login_id=1001");
    assert_eq!(token.as_deref(), Some("T1"), "回调应携带 token=T1");
    assert!(
        dao.get(&key).await.unwrap().is_none(),
        "过期会话触发回调后应从 DAO 清理"
    );

    // 活跃会话不触发回调
    session.create("1001", "T2").await.unwrap();
    assert!(
        session.get_token_session("T2").await.unwrap().is_some(),
        "活跃会话应正常读取"
    );
    assert_eq!(listener.calls(), 1, "活跃会话不应触发过期回调");
}

// ------------------------------------------------------------------------
// ACC-SESS-005..008：IP 安全监听 / 设备绑定 MFA / 匿名边界 / 过期（异常）
// ------------------------------------------------------------------------

/// ACC-SESS-005（异常）：IP 变更触发 `SessionSecurityListener`——跨 /24 网段
/// 返回告警（含初始 IP 与当前 IP），同网段 / 无记录不告警。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_005_ip_change_triggers_security_listener() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let listener = SessionSecurityListener::new(dao);

    listener
        .record_login_ip("T1", "1001", "192.168.1.100")
        .await
        .unwrap();

    // 同 IP / 同网段：不告警
    assert!(
        listener
            .check_ip_change("T1", "192.168.1.100")
            .await
            .unwrap()
            .is_none(),
        "同 IP 不应告警"
    );
    assert!(
        listener
            .check_ip_change("T1", "192.168.1.200")
            .await
            .unwrap()
            .is_none(),
        "同 /24 网段不应告警"
    );

    // 跨网段：触发告警，内容包含初始 IP 与当前 IP
    let warning = listener
        .check_ip_change("T1", "203.0.113.7")
        .await
        .unwrap()
        .expect("跨网段应返回 Some(warning)");
    assert!(
        warning.contains("192.168.1.100") && warning.contains("203.0.113.7"),
        "告警应包含初始 IP 与当前 IP，实际: {warning}"
    );

    // 无记录：首次访问不告警（不阻断主流程）
    assert!(
        listener
            .check_ip_change("ghost-token", "10.0.0.1")
            .await
            .unwrap()
            .is_none(),
        "无 IP 记录不应告警"
    );
}

/// ACC-SESS-006（异常）：设备绑定 strict 模式——新设备登录要求 MFA
///（hard block：`NotPermission("secondary auth required")`），且不创建孤儿会话；
/// 历史已绑定设备免 MFA 放行。
#[cfg(feature = "device-binding")]
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_006_device_binding_strict_requires_mfa_on_new_device() {
    use garrison::strategy::device_binding::StrictBinding;

    let session = Arc::new(GarrisonSession::new(
        Arc::new(InMemoryDao::new()),
        3600,
        86400,
        0,
    ));
    let mut config = garrison::config::GarrisonConfig::default_config();
    config.throw_on_not_login = false;
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );
    let logic = GarrisonLogicDefault::new(session.clone(), Arc::new(config), firewall)
        .with_device_binding_policy(Arc::new(StrictBinding::new(session.clone())));

    // 新设备（无历史会话）→ 要求 MFA：login 被 hard block
    let new_device = LoginParams {
        device: Some("mobile-ios".to_string()),
        ..Default::default()
    };
    let blocked = logic.login("1001", &new_device).await;
    assert!(
        matches!(
            blocked,
            Err(GarrisonError::NotPermission(ref m)) if m == "secondary auth required"
        ),
        "strict 模式新设备 login 应要求 MFA（NotPermission），实际: {blocked:?}"
    );
    assert!(
        session.get_tokens_by_login_id("1001").is_empty(),
        "MFA 阻断后不应创建孤儿会话"
    );

    // 预置历史会话绑定该设备 → 已知设备免 MFA 放行
    session
        .create_token_session("1001", "pre-token", &new_device)
        .await
        .unwrap();
    let token = logic
        .login("1001", &new_device)
        .await
        .expect("已知设备 login 应免 MFA 成功");
    assert!(!token.is_empty(), "已知设备应签发非空 token");
    let ts = session
        .get_token_session(&token)
        .await
        .unwrap()
        .expect("已知设备会话应已创建");
    assert_eq!(
        ts.device.as_deref(),
        Some("mobile-ios"),
        "新会话应记录设备标识"
    );
}

/// ACC-SESS-007（异常）：匿名会话边界——匿名 Session 独立 key 空间
///（`token:session:anon:*`），与同字符串登录 Session 共存互不干扰；
/// `logout` 只销毁匿名空间，登录会话保留。
#[cfg(feature = "session-extra")]
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_007_anon_session_boundary_isolation() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = GarrisonSession::new(dao, 3600, 86400, 0);

    // 匿名 Session：login_id 为空、is_anon=true
    let anon = session.get_anon_token_session("tok-1").await.unwrap();
    assert!(anon.is_anon, "匿名 Session 的 is_anon 应为 true");
    assert!(anon.login_id.is_empty(), "匿名 Session 的 login_id 应为空");

    // 同一 token 字符串的登录会话可共存（key 空间隔离）
    session.create("1001", "tok-1").await.unwrap();
    let login_ts = session
        .get_token_session("tok-1")
        .await
        .unwrap()
        .expect("登录会话应存在");
    assert_eq!(login_ts.login_id, "1001", "登录会话主体应为 1001");
    assert!(!login_ts.is_anon, "登录会话 is_anon 应为 false");
    assert!(
        session.is_anon("tok-1").await.unwrap(),
        "匿名空间与登录空间应共存（is_anon 由匿名 key 空间判定）"
    );

    // 匿名不参与 login_token_map（空 login_id 无账号会话索引）
    assert!(
        session.get_tokens_by_login_id("").is_empty(),
        "匿名 session 不应写入 login_token_map"
    );

    // logout 路由到匿名空间：仅销毁匿名 key，登录会话保留
    session.logout("tok-1").await.unwrap();
    assert!(
        !session.is_anon("tok-1").await.unwrap(),
        "logout 后匿名空间应销毁"
    );
    assert!(
        session.get_token_session("tok-1").await.unwrap().is_some(),
        "logout 匿名会话不应影响同字符串的登录会话"
    );
}

/// ACC-SESS-008（异常）：过期后读取为空——`timeout=1s` + sleep 超过超时后，
/// `get_token_session` 返回 None、`is_valid=false`、剩余 TTL 无。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_008_expired_token_reads_empty() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = GarrisonSession::new(dao, 1, 86400, 0); // token TTL=1s

    session.create("1001", "T1").await.unwrap();
    assert!(
        session.get_token_timeout("T1").await.unwrap().is_some(),
        "未过期前读取应有剩余 TTL"
    );

    tokio::time::sleep(Duration::from_millis(1300)).await;

    assert!(
        session.get_token_session("T1").await.unwrap().is_none(),
        "超过 timeout 后 get_token_session 应返回 None"
    );
    assert!(
        !session.is_valid("T1").await.unwrap(),
        "超过 timeout 后 is_valid 应为 false"
    );
    assert!(
        session.get_token_timeout("T1").await.unwrap().is_none(),
        "过期后剩余 TTL 应不可读"
    );
}

// ------------------------------------------------------------------------
// ACC-SESS-009..011：Phase 4 测试迁移（T040/T043）
// ------------------------------------------------------------------------

/// ACC-SESS-019（正常）：登录元数据写入 Token-Session——携带 device/ip/user_agent
/// 登录后，`TokenSession` 对应字段完整写入（get-session 语义）；created_at /
/// last_active_at 为正（get-token-info 语义）；按 token 反查 login_id 一致。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/e2e/auth_flow.rs `test_e2e_login_with_device_ip_ua` 移植，并合并
/// tests/e2e/api_happy.rs `test_api_happy_get_token_info_and_session`（T020）与
/// tests/e2e/session_flow.rs `test_e2e_get_token_info_returns_correct_data` /
/// `test_e2e_get_session_returns_login_id`：原版经 HTTP get-token-info/get-session
/// 断言字段，本场景在逻辑层直接断言 TokenSession 存储内容（不可弱化）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_019_login_metadata_written_to_token_session() {
    let session = Arc::new(GarrisonSession::new(
        Arc::new(InMemoryDao::new()),
        3600,
        86400,
        0,
    ));
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );
    let logic = GarrisonLogicDefault::new(
        session.clone(),
        Arc::new(garrison::config::GarrisonConfig::default_config()),
        firewall,
    );

    let params = LoginParams {
        device: Some("iPhone 15".to_string()),
        ip: Some("192.168.1.100".to_string()),
        user_agent: Some("Mozilla/5.0".to_string()),
        ..Default::default()
    };
    let token = logic
        .login("user-device", &params)
        .await
        .expect("携带元数据登录应成功");

    // get-token-info 语义：created_at / last_active_at 为正整数
    let ts = session
        .get_token_session(&token)
        .await
        .unwrap()
        .expect("登录后 Token-Session 应存在");
    assert!(
        ts.created_at > 0 && ts.last_active_at > 0,
        "created_at / last_active_at 应为正整数，实际: created_at={} last_active_at={}",
        ts.created_at,
        ts.last_active_at
    );

    // get-session 语义：device / ip / user_agent 与登录时一致
    assert_eq!(
        ts.device.as_deref(),
        Some("iPhone 15"),
        "Token-Session 应记录设备标识"
    );
    assert_eq!(
        ts.ip.as_deref(),
        Some("192.168.1.100"),
        "Token-Session 应记录登录 IP"
    );
    assert_eq!(
        ts.user_agent.as_deref(),
        Some("Mozilla/5.0"),
        "Token-Session 应记录 User-Agent"
    );
    assert_eq!(
        ts.login_id, "user-device",
        "session 的 login_id 应与登录时一致"
    );
}

/// ACC-SESS-017（异常）：**BW-AC-003** 超设备上限踢出最早会话（语义偏差记录：
/// 代码库无自动 device-limit 踢出（推迟 v0.7.0），以 `kickout_by_device` 手动
/// 设备级踢出验证同语义）——被踢设备 token 失效、另一设备 token 仍有效。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/acceptance_criteria.rs `bw_ac_003_concurrent_login_kicks_earliest_session`
///（FRD §8.1 **BW-AC-003**）原样移植，断言语义与编号注释保留。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_017_bw_ac_003_kickout_by_device_isolates_device() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = GarrisonSession::new(dao, 3600, 86400, 0);

    // Given: 用户登录设备 A 和设备 B（并按设备登记）
    session
        .create("user-003", "token-a")
        .await
        .expect("create token-a 应成功");
    session
        .set_device("token-a", "device-a")
        .await
        .expect("set_device 应成功");
    session
        .create("user-003", "token-b")
        .await
        .expect("create token-b 应成功");
    session
        .set_device("token-b", "device-b")
        .await
        .expect("set_device 应成功");

    // 两个 token 初始均有效
    assert!(
        session.is_valid("token-a").await.expect("is_valid token-a"),
        "device-a 的 token 应初始有效"
    );
    assert!(
        session.is_valid("token-b").await.expect("is_valid token-b"),
        "device-b 的 token 应初始有效"
    );

    // When: 踢出设备 A 的会话
    session
        .kickout_by_device("user-003", "device-a")
        .await
        .expect("kickout_by_device 应成功");

    // Then: 设备 A token 失效；设备 B token 仍有效
    assert!(
        !session
            .is_valid("token-a")
            .await
            .expect("is_valid token-a after kickout"),
        "device-a 的 token 应已失效"
    );
    assert!(
        session
            .is_valid("token-b")
            .await
            .expect("is_valid token-b after kickout"),
        "device-b 的 token 应仍有效"
    );
}

/// ACC-SESS-018（正常）：**BW-AC-001** OIDC 登录创建新账号并返回有效 Token——
/// 登录链路（所有登录方式共享）双写 Account-Session 与 Token-Session，DAO key
/// 格式对齐 E-001（`account:session:` / `token:session:` 前缀）。
///
/// # 规则 7 冲突（原版注释保留）
/// OIDC 登录流程需网络调用 Keycloak/OIDC provider，集成测试不依赖外部服务；
/// 本测试验证 OIDC 登录的核心产出——会话创建（`account:session:{login_id}` +
/// `token:session:{token}`），该逻辑由所有登录方式共享的登录链路实现。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/acceptance_criteria.rs `bw_ac_001_oidc_login_creates_account_and_token`
///（FRD §8.1 **BW-AC-001**）原样移植，断言语义与编号注释保留。
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_018_bw_ac_001_login_creates_account_and_token_keys() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );
    let logic = GarrisonLogicDefault::new(
        session.clone(),
        Arc::new(garrison::config::GarrisonConfig::default_config()),
        firewall,
    );

    // When: 用户完成登录（原版以 GarrisonUtil::login 模拟 OIDC 认证后的会话创建）
    let token = logic
        .login("oidc-user-001", &LoginParams::default())
        .await
        .expect("登录应成功");
    assert!(!token.is_empty(), "登录应返回非空 token");

    // Then: Account-Session 存在（E-001 key 格式）
    let account_key = format!("account:session:{}", "oidc-user-001");
    assert!(
        account_key.starts_with("account:session:"),
        "Account key 应带 E-001 前缀"
    );
    assert!(
        dao.get(&account_key)
            .await
            .expect("DAO get 应成功")
            .is_some(),
        "Account-Session 应存在 (key={account_key})"
    );

    // Then: Token-Session 存在（E-001 key 格式）
    let token_key = format!("token:session:{}", token);
    assert!(
        token_key.starts_with("token:session:"),
        "Token key 应带 E-001 前缀"
    );
    assert!(
        dao.get(&token_key).await.expect("DAO get 应成功").is_some(),
        "Token-Session 应存在 (key={token_key})"
    );
}

// ------------------------------------------------------------------------
// ACC-SESS-010..016：Plugin / Listener 扩展点（T041 迁移自
// tests/integration/plugin_listener.rs，`listener` 门控）
// ------------------------------------------------------------------------
//
// 计数器与 inventory 注册为测试二进制全局状态，全部用例 `#[serial]`；
// 015-016 中经 `GarrisonManager` 全局单例的用例使用 `GarrisonTestHarness`
//（其余直接构造管理器，无全局状态）。

/// 测试用 Plugin（计数器记录钩子调用）。
#[cfg(feature = "listener")]
struct CountingPlugin;

#[cfg(feature = "listener")]
impl garrison::plugin::GarrisonPlugin for CountingPlugin {
    fn name(&self) -> &str {
        "counting-plugin"
    }
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        PLUGIN_LOGIN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        PLUGIN_LOGOUT_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        PLUGIN_PERM_CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(feature = "listener")]
fn counting_plugin_factory() -> Arc<dyn garrison::plugin::GarrisonPlugin> {
    Arc::new(CountingPlugin)
}

#[cfg(feature = "listener")]
inventory::submit! {
    garrison::plugin::GarrisonPluginEntry { factory: counting_plugin_factory }
}

/// 测试用 Listener（计数器记录事件广播）。
#[cfg(feature = "listener")]
struct CountingListener;

#[cfg(feature = "listener")]
#[async_trait::async_trait]
impl garrison::listener::GarrisonListener for CountingListener {
    async fn on_event(&self, event: &garrison::listener::GarrisonEvent) -> GarrisonResult<()> {
        match event {
            garrison::listener::GarrisonEvent::Login { .. } => {
                LISTENER_LOGIN_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            garrison::listener::GarrisonEvent::Logout { .. } => {
                LISTENER_LOGOUT_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            garrison::listener::GarrisonEvent::PermissionCheck { .. } => {
                LISTENER_PERM_CHECK_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            _ => {},
        }
        Ok(())
    }
}

#[cfg(feature = "listener")]
fn counting_listener_factory() -> Arc<dyn garrison::listener::GarrisonListener> {
    Arc::new(CountingListener)
}

#[cfg(feature = "listener")]
inventory::submit! {
    garrison::listener::GarrisonListenerEntry { factory: counting_listener_factory }
}

#[cfg(feature = "listener")]
static PLUGIN_LOGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "listener")]
static PLUGIN_LOGOUT_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "listener")]
static PLUGIN_PERM_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "listener")]
static LISTENER_LOGIN_EVENTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "listener")]
static LISTENER_LOGOUT_EVENTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "listener")]
static LISTENER_PERM_CHECK_EVENTS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "listener")]
fn reset_plugin_listener_counters() {
    PLUGIN_LOGIN_CALLS.store(0, Ordering::SeqCst);
    PLUGIN_LOGOUT_CALLS.store(0, Ordering::SeqCst);
    PLUGIN_PERM_CHECK_CALLS.store(0, Ordering::SeqCst);
    LISTENER_LOGIN_EVENTS.store(0, Ordering::SeqCst);
    LISTENER_LOGOUT_EVENTS.store(0, Ordering::SeqCst);
    LISTENER_PERM_CHECK_EVENTS.store(0, Ordering::SeqCst);
}

/// ACC-SESS-010（正常）：`GarrisonPluginManager` 收集 inventory 注册的插件
///（编译期注册 → 运行期收集，spec plugin-system Scenario）。
#[cfg(feature = "listener")]
#[test]
#[serial]
fn acc_sess_010_plugin_manager_collects_registered_plugins() {
    let manager = garrison::plugin::GarrisonPluginManager::new();
    assert!(
        manager.count() >= 1,
        "应至少收集到 1 个测试插件（CountingPlugin）"
    );
}

/// ACC-SESS-011（正常+异常）：plugin 三大钩子被调用且可累计——
/// `on_login` / `on_logout` / `on_permission_check` 各触发 ≥1 次，5 次 `on_login`
/// 累计 ≥5（无状态可重入；原 plugin_on_*_invoked + plugin_multiple_calls 合并）。
#[cfg(feature = "listener")]
#[tokio::test]
#[serial]
async fn acc_sess_011_plugin_hooks_invoked_and_accumulate() {
    reset_plugin_listener_counters();
    let manager = garrison::plugin::GarrisonPluginManager::new();

    manager.on_login("1001", "token-xyz");
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_login 应被调用至少 1 次"
    );
    manager.on_logout("1001", "token-xyz");
    assert!(
        PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_logout 应被调用至少 1 次"
    );
    manager.on_permission_check("1001", "user:read");
    assert!(
        PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_permission_check 应被调用至少 1 次"
    );

    reset_plugin_listener_counters();
    for _ in 0..5 {
        manager.on_login("1001", "t");
    }
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 5,
        "5 次 on_login 应使计数器 >= 5"
    );
}

/// ACC-SESS-012（正常）：`GarrisonListenerManager` 收集 inventory 注册的 listener
///（spec listener-system Scenario）。
#[cfg(feature = "listener")]
#[test]
#[serial]
fn acc_sess_012_listener_manager_collects_registered_listeners() {
    let manager = garrison::listener::GarrisonListenerManager::new();
    assert!(
        manager.count() >= 1,
        "应至少收集到 1 个测试 listener（CountingListener）"
    );
}

/// ACC-SESS-013（正常）：`broadcast` 将 Login / Logout / PermissionCheck 事件
/// 分发到 listener 且可累计——三种事件各 ≥1 次，3 次 Login 广播 ≥3
///（原 listener_receives_*_event + listener_multiple_broadcasts 合并）。
#[cfg(feature = "listener")]
#[tokio::test]
#[serial]
async fn acc_sess_013_listener_receives_events_and_accumulates() {
    use garrison::listener::GarrisonEvent;
    use garrison::listener::GarrisonListenerManager;

    reset_plugin_listener_counters();
    let manager = GarrisonListenerManager::new();

    manager
        .broadcast(&GarrisonEvent::Login {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            device: Some("web".to_string()),
            request_context: None,
        })
        .await;
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 Login 事件"
    );

    manager
        .broadcast(&GarrisonEvent::Logout {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            request_context: None,
        })
        .await;
    assert!(
        LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 Logout 事件"
    );

    manager
        .broadcast(&GarrisonEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: "user:delete".to_string(),
            request_context: None,
        })
        .await;
    assert!(
        LISTENER_PERM_CHECK_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 PermissionCheck 事件"
    );

    reset_plugin_listener_counters();
    for _ in 0..3 {
        manager
            .broadcast(&GarrisonEvent::Login {
                login_id: "1".to_string(),
                token: "t".to_string(),
                device: None,
                request_context: None,
            })
            .await;
    }
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 3,
        "3 次 Login 广播应使计数器 >= 3"
    );
}

/// ACC-SESS-014（正常）：完整生命周期 plugin + listener 协同——login →
/// permission_check → logout 各钩子与各事件全部触发；PermissionCheck 事件只进
/// listener 不经过 plugin 钩子之外的通道（原 full_lifecycle 与
/// permission_check_event_only_goes_to_listener 合并）。
#[cfg(feature = "listener")]
#[tokio::test]
#[serial]
async fn acc_sess_014_full_lifecycle_plugin_and_listener_cooperate() {
    use garrison::listener::{GarrisonEvent, GarrisonListenerManager};
    use garrison::plugin::GarrisonPluginManager;

    reset_plugin_listener_counters();
    let plugin_manager = GarrisonPluginManager::new();
    let listener_manager = GarrisonListenerManager::new();

    // 1. 模拟登录：plugin on_login + Login 事件
    plugin_manager.on_login("1001", "T1");
    listener_manager
        .broadcast(&GarrisonEvent::Login {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            device: Some("web".to_string()),
            request_context: None,
        })
        .await;

    // 2. 模拟权限校验：plugin on_permission_check + PermissionCheck 事件
    plugin_manager.on_permission_check("1001", "user:read");
    listener_manager
        .broadcast(&GarrisonEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: "user:delete".to_string(),
            request_context: None,
        })
        .await;

    // 3. 模拟登出：plugin on_logout + Logout 事件
    plugin_manager.on_logout("1001", "T1");
    listener_manager
        .broadcast(&GarrisonEvent::Logout {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            request_context: None,
        })
        .await;

    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_login"
    );
    assert!(
        PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_permission_check"
    );
    assert!(
        PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_logout"
    );
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener Login 事件"
    );
    assert!(
        LISTENER_PERM_CHECK_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener PermissionCheck 事件"
    );
    assert!(
        LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener Logout 事件"
    );
}

/// ACC-SESS-015（正常）：auto-wire——`GarrisonManager` 构建后 `login_simple` 自动
/// 触发 plugin `on_login` 钩子并广播 Login 事件到 listener（0.2.1 起 builder
/// 自动注入两组管理器；原 auto_wire_login_triggers_plugin_on_login +
/// auto_wire_login_broadcasts_listener_login_event 合并）。
#[cfg(feature = "listener")]
#[tokio::test]
#[serial]
async fn acc_sess_015_auto_wire_login_triggers_plugin_and_listener() {
    use crate::common::harness::GarrisonTestHarness;
    use garrison::stp::GarrisonUtil;

    reset_plugin_listener_counters();
    let _h = GarrisonTestHarness::builder()
        .init()
        .await
        .expect("harness init 应成功");

    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty(), "login 应签发非空 token");

    let calls = PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst);
    assert!(
        calls >= 1,
        "auto-wire: GarrisonUtil::login 应触发 plugin on_login，实际调用次数: {}",
        calls
    );
    let events = LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst);
    assert!(
        events >= 1,
        "auto-wire: GarrisonUtil::login 应广播 Login 事件，实际事件数: {}",
        events
    );
}

/// ACC-SESS-016（正常）：auto-wire logout——`with_current_token` 内
/// `GarrisonUtil::logout` 自动触发 plugin `on_logout` 钩子 + listener Logout 事件
///（原 auto_wire_logout_triggers_hooks）。
#[cfg(feature = "listener")]
#[tokio::test]
#[serial]
async fn acc_sess_016_auto_wire_logout_triggers_hooks() {
    use crate::common::harness::GarrisonTestHarness;
    use garrison::stp::{with_current_token, GarrisonUtil};

    reset_plugin_listener_counters();
    let _h = GarrisonTestHarness::builder()
        .init()
        .await
        .expect("harness init 应成功");

    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let login_before = PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst);
    with_current_token(token, async {
        GarrisonUtil::logout().await.unwrap();
    })
    .await;

    let logout_calls = PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst);
    assert!(
        logout_calls >= 1,
        "auto-wire: GarrisonUtil::logout 应触发 plugin on_logout，实际调用次数: {}",
        logout_calls
    );
    assert!(login_before >= 1, "login 钩子应已触发");
    let logout_events = LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst);
    assert!(
        logout_events >= 1,
        "auto-wire: GarrisonUtil::logout 应广播 Logout 事件，实际事件数: {}",
        logout_events
    );
}

// ------------------------------------------------------------------------
// ACC-SESS-020：多租户隔离 + 审计日志 + 决策溯源端到端
//（T041 迁移自 tests/integration/tenant_isolation.rs，`audit-log` 门控）
// ------------------------------------------------------------------------

/// ACC-SESS-016（正常）：租户 42 用户 1001 的权限校验全链路——
/// `check_permission` → `authorize` → `Decision`（ExplicitAllow）→ 广播
/// `PermissionCheck` → `AuditLogListener` 写入 `audit_logs` 表
///（tenant_id=42 / event_type=permission_check / login_id=1001）。
#[cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
#[tokio::test(flavor = "multi_thread")]
async fn acc_sess_020_tenant_isolation_with_audit_log_and_decision_trace() {
    use garrison::context::tenant::{TenantContext, TenantSource, TENANT};
    use garrison::core::permission::{
        AuthRequest, DecisionReason, PermissionChecker, PermissionCheckerDefault,
    };
    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
    use garrison::listener::audit::{AuditConfig, AuditQuery};
    use garrison::listener::GarrisonListenerManager;
    use garrison::stp::{with_current_token, GarrisonLogicDefault, LoginParams};
    use garrison::AuditLogListener;
    use garrison::{PermissionLogic, SessionLogic};

    use crate::common::setup_db;

    struct TenantMockInterface;
    #[async_trait::async_trait]
    impl GarrisonInterface for TenantMockInterface {
        async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            if login_id == "1001" {
                Ok(vec!["user:read".to_string()])
            } else {
                Ok(vec![])
            }
        }
        async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    let pool = setup_db().await;
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));

    let mut config = garrison::config::GarrisonConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;

    let interface: Arc<dyn GarrisonInterface> = Arc::new(TenantMockInterface);
    let pc: Arc<dyn PermissionChecker> = Arc::new(PermissionCheckerDefault::new(interface.clone()));
    let firewall = Arc::new(garrison::strategy::GarrisonPermissionStrategyDefault::new(
        interface,
    ));

    let lm = Arc::new(GarrisonListenerManager::new());
    let audit_config = AuditConfig {
        mask_fields: vec![],
        retain_days: 0,
        async_write: false,
        signing_key: None,
        audit_mask_mode: garrison::config::AuditMaskMode::default(),
    };
    let audit_listener = Arc::new(AuditLogListener::new(pool.clone(), audit_config));
    lm.register(audit_listener.clone() as Arc<dyn garrison::listener::GarrisonListener>);

    let logic = Arc::new(
        GarrisonLogicDefault::new(session, Arc::new(config), firewall)
            .with_permission_checker(pc.clone())
            .with_listener_manager(lm),
    );

    let tenant_ctx = TenantContext {
        tenant_id: 42,
        resolved_from: TenantSource::Header,
    };

    // 1. 租户作用域内登录
    let token = TENANT
        .scope(tenant_ctx.clone(), async {
            logic
                .login("1001", &LoginParams::default())
                .await
                .expect("login 应成功")
        })
        .await;
    assert!(!token.is_empty(), "token 不应为空");

    // 2. check_permission 全链路通过
    let check_result = TENANT
        .scope(
            tenant_ctx,
            with_current_token(token.clone(), async {
                logic.check_permission("user:read").await
            }),
        )
        .await;
    assert!(
        check_result.is_ok(),
        "check_permission 应成功: {:?}",
        check_result.err()
    );

    // 3. authorize 返回 ExplicitAllow Decision
    let auth_request = AuthRequest {
        login_id: "1001".to_string(),
        tenant_id: 42,
        action: "user:read".to_string(),
        resource: None,
        context: serde_json::Value::Null,
    };
    let decision = pc.authorize(&auth_request).await.expect("authorize 应成功");
    assert!(decision.allowed, "Decision.allowed 应为 true");
    assert_eq!(
        decision.reason,
        DecisionReason::ExplicitAllow,
        "Decision.reason 应为 ExplicitAllow"
    );

    // 4. 审计日志落库：tenant_id=42 / event_type=permission_check / login_id=1001
    let query = AuditQuery {
        tenant_id: Some(42),
        event_type: Some("permission_check".to_string()),
        ..Default::default()
    };
    let logs = audit_listener
        .query_audit_logs(query)
        .await
        .expect("query_audit_logs 应成功");
    assert!(
        !logs.is_empty(),
        "audit_logs 应存在 tenant_id=42, event_type=permission_check 的记录"
    );
    let entry = &logs[0];
    assert_eq!(entry.tenant_id, 42, "audit_logs tenant_id 应为 42");
    assert_eq!(
        entry.event_type, "permission_check",
        "audit_logs event_type 应为 permission_check"
    );
    assert_eq!(
        entry.login_id,
        Some("1001".to_string()),
        "audit_logs login_id 应为 1001"
    );
}
