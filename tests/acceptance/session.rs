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

use garrison::constants::DaoKeyPrefix;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::session::{
    GarrisonSession, SessionExpiryListener, SessionSecurityListener, TokenSession,
};
use garrison::stp::{GarrisonInterface, GarrisonLogicDefault, LoginParams, SessionLogic};
use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};
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
