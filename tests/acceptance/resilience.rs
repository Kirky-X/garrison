//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! resilience 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，
//! 任务 T031）。异常韧性场景，编号 `ACC-RES-NNN`：
//! oxcache 故障时 JWT 无状态降级 / 配置错误 fail-fast / auth-server 内网
//! API Key 错误 401 / 限流 429 / BackendRemote 500 与超时的错误传播及
//! 熔断打开-恢复。
//!
//! - ACC-RES-001 不经 GarrisonManager（独立 `GarrisonLogicDefault` 双实例：
//!   健康 DAO 签发 + FailingDao 故障验证），无需 `#[serial]`。
//! - ACC-RES-002/003 只构造配置与 builder，不触碰全局单例，无需 `#[serial]`。
//! - ACC-RES-004/005 使用 `MockAuthBackend` 双端口服务器（镜像
//!   tests/auth_server_integration.rs 的已知良好装配），无全局状态。
//! - ACC-RES-006..008 使用 wiremock 直测 `BackendRemote`（README 熔断/
//!   降级公共 API，见 src/backend/remote.rs）。

use async_trait::async_trait;
use garrison::backend::types::LoginParams;
use garrison::backend::{AuthBackend, BackendRemote};
use garrison::config::GarrisonConfig;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::limiteron::CircuitBreakerWrapper;
use garrison::server::GarrisonAuthServer;
use garrison::session::GarrisonSession;
use garrison::stp::context::with_current_token;
use garrison::stp::{GarrisonInterface, GarrisonLogicDefault, JwtMode, SessionLogic};
use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};
use limiteron::circuit::CircuitBreakerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// 统一「错误即失败」断言：调用返回 `Ok` 即 panic，并透传实际值。
macro_rules! assert_err {
    ($res:expr, $contains:expr, $msg:expr) => {
        match $res {
            Ok(v) => panic!("{}（不应成功，实际: {:?}）", $msg, v),
            Err(e) => {
                let text = format!("{e}");
                assert!(
                    text.contains($contains),
                    "{}（期望错误含 {:?}，实际: {text}）",
                    $msg,
                    $contains
                );
            },
        }
    };
}

/// JWT 无状态降级场景的共享 secret（≥32 字节，满足 HS256 强度校验）。
const RES_JWT_SECRET: &str = "resilience-stateless-jwt-secret-0123456789abcdef";

// ------------------------------------------------------------------------
// ACC-RES-001：oxcache 故障时 JWT 无状态降级
// ------------------------------------------------------------------------

/// FailingDao：所有操作返回 `Err(GarrisonError::Dao)`（模拟 oxcache 故障）。
///
/// 六原子方法由 `garrison::atomic_test_fallback!()` 宏展开（与
/// tests/unit/acceptance_criteria.rs 的 FailingDao 同一构造），覆写 `get`
/// 返回 Err 以保证任何 DAO 读取都显性失败。
struct FailingDao;

#[async_trait]
impl GarrisonDao for FailingDao {
    async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn delete(&self, _key: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    garrison::atomic_test_fallback!();
}

/// 空接口（仅满足 `GarrisonPermissionStrategyDefault` 构造要求）。
struct EmptyInterface;

#[async_trait]
impl GarrisonInterface for EmptyInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

/// JWT 无状态模式配置：`token_style=jwt` + `jwt_mode=Stateless`，显式风险接受
/// 开关 `allow_stateless_jwt_no_revocation=true`（关闭撤销黑名单，使
/// `check_login_stateless` 纯签名校验、不读 DAO——T017 互斥校验的三选一出口）。
fn jwt_stateless_config() -> GarrisonConfig {
    let mut c = GarrisonConfig::default_config();
    c.token_style = "jwt".to_string();
    c.jwt_algorithm = "HS256".to_string();
    c.jwt_secret = RES_JWT_SECRET.to_string().into();
    c.timeout = 3600;
    c.active_timeout = -1;
    c.throw_on_not_login = false;
    c.enable_jwt_revocation = false;
    c.allow_stateless_jwt_no_revocation = true;
    c
}

/// 构造默认防火墙（空接口 + 无 hook 注入，登录/校验路径不触发防火墙阻断）。
fn default_firewall() -> Arc<dyn GarrisonPermissionStrategy> {
    Arc::new(GarrisonPermissionStrategyDefault::new(Arc::new(
        EmptyInterface,
    )))
}

/// ACC-RES-001（异常韧性）：oxcache 故障时 JWT 无状态降级——DAO 故障下
/// 已签发 token 仍可验证（签名校验不依赖 DAO），新登录失败显性传播（规则 12）。
///
/// 装配：同一份 `jwt_mode=Stateless` 配置 + 同一 secret 构造两个独立
/// `GarrisonLogicDefault` 实例——健康实例（InMemoryDao）签发 JWT 作为正常
/// 锚点，故障实例（FailingDao，模拟 oxcache 故障）验证该 token 且尝试新登录。
#[tokio::test]
async fn acc_res_001_oxcache_failure_jwt_stateless_token_still_verifiable() {
    let config = Arc::new(jwt_stateless_config());

    // 正常锚点：健康 DAO 下登录签发 JWT 并可验证
    let dao_healthy: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let logic_healthy = GarrisonLogicDefault::new(
        Arc::new(GarrisonSession::new(dao_healthy, 3600, 86400, 0)),
        config.clone(),
        default_firewall(),
    )
    .with_jwt_mode(JwtMode::Stateless);
    let token = logic_healthy
        .login("res-001", &LoginParams::default())
        .await
        .expect("健康 DAO 下登录应成功");
    with_current_token(token.clone(), async {
        assert!(
            logic_healthy.check_login().await.unwrap(),
            "健康 DAO 下 token 应可验证"
        );
    })
    .await;

    // DAO 故障注入：新登录显性失败（GarrisonError::Dao 传播，不吞错）
    let dao_failing: Arc<dyn GarrisonDao> = Arc::new(FailingDao);
    let logic_failing = GarrisonLogicDefault::new(
        Arc::new(GarrisonSession::new(dao_failing, 3600, 86400, 0)),
        config,
        default_firewall(),
    )
    .with_jwt_mode(JwtMode::Stateless);
    let login_err = logic_failing
        .login("res-001", &LoginParams::default())
        .await
        .expect_err("DAO 故障时登录应显性失败");
    assert!(
        matches!(login_err, GarrisonError::Dao(_)),
        "DAO 故障时 login 应返回 Dao 错误，实际: {:?}",
        login_err
    );

    // 故障降级：已签发 JWT 仍可通过无状态签名校验（不依赖 DAO 可用性）
    with_current_token(token, async {
        assert!(
            logic_failing.check_login().await.unwrap(),
            "DAO 故障下 JWT 无状态校验仍应验证通过（签名校验不读 DAO）"
        );
    })
    .await;
}

// ------------------------------------------------------------------------
// ACC-RES-002..003：配置错误 fail-fast
// ------------------------------------------------------------------------

/// ACC-RES-002（异常）：`GarrisonConfig::validate()` 对非法值 fail-fast——
/// 负/零 timeout、非法 token_style、空 jwt_secret、非法 jwt_algorithm、
/// 越界 auto_renewal_threshold、is_share 与 is_concurrent 冲突、
/// 非法 cookie_same_site、超限 session_hover_timeout 均返回 Config 错误。
#[test]
fn acc_res_002_config_validate_fail_fast() {
    // timeout 必须 > 0（负值与零值均拒绝）
    for bad_timeout in [0i64, -1, -3600] {
        let mut c = GarrisonConfig::default_config();
        c.timeout = bad_timeout;
        assert_err!(
            c.validate(),
            "timeout",
            format!("timeout={bad_timeout} 应被校验拒绝")
        );
    }

    // token_style 必须是 TOKEN_STYLES 中的合法值
    let mut c = GarrisonConfig::default_config();
    c.token_style = "bogus".to_string();
    assert_err!(
        c.validate(),
        "unknown token_style",
        "非法 token_style 应被拒绝"
    );

    // cookie_same_site 必须是 Lax/Strict/None
    let mut c = GarrisonConfig::default_config();
    c.cookie_same_site = "Bogus".to_string();
    assert_err!(
        c.validate(),
        "unknown cookie_same_site",
        "非法 cookie_same_site 应被拒绝"
    );

    // token_style=jwt 时 jwt_secret 不能为空
    let mut c = GarrisonConfig::default_config();
    c.token_style = "jwt".to_string();
    c.jwt_secret = String::new().into();
    assert_err!(c.validate(), "jwt_secret", "空 jwt_secret 应被拒绝");

    // 非法 jwt_algorithm（白名单 HS256/HS384/HS512）
    let mut c = GarrisonConfig::default_config();
    c.token_style = "jwt".to_string();
    c.jwt_algorithm = "HS999".to_string();
    c.jwt_secret = RES_JWT_SECRET.to_string().into();
    assert_err!(c.validate(), "jwt_algorithm", "非法 jwt_algorithm 应被拒绝");

    // jwt_secret 强度不足（HS256 需 ≥32 字节）
    let mut c = GarrisonConfig::default_config();
    c.token_style = "jwt".to_string();
    c.jwt_secret = "too-short".to_string().into();
    assert_err!(c.validate(), "jwt_secret", "过短 jwt_secret 应被拒绝");

    // auto_renewal_threshold 越界（合法值 -1 或 0..=100）
    let mut c = GarrisonConfig::default_config();
    c.auto_renewal_threshold = 101;
    assert_err!(
        c.validate(),
        "auto_renewal_threshold",
        "auto_renewal_threshold=101 应被拒绝"
    );

    // is_share=true 必须搭配 is_concurrent=true
    let mut c = GarrisonConfig::default_config();
    c.is_share = true;
    c.is_concurrent = false;
    assert_err!(
        c.validate(),
        "is_share",
        "is_share=true 且 is_concurrent=false 应被拒绝"
    );

    // session_hover_timeout 上界（10 年）
    let mut c = GarrisonConfig::default_config();
    c.session_hover_timeout = 315_360_001;
    assert_err!(
        c.validate(),
        "session_hover_timeout",
        "session_hover_timeout 超上界应被拒绝"
    );
}

/// ACC-RES-003（异常）：`GarrisonManager::builder().build()` 装配路径
/// fail-fast——非法配置在触碰全局单例之前即返回 Config 错误（fail-closed）。
#[tokio::test]
async fn acc_res_003_builder_build_fail_fast() {
    let mut c = GarrisonConfig::default_config();
    c.timeout = -5;
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let result = garrison::manager::GarrisonManager::builder()
        .dao(dao)
        .config(Arc::new(c))
        .interface(Arc::new(EmptyInterface))
        .build()
        .await;
    assert_err!(
        result,
        "timeout",
        "builder 对非法配置应 fail-fast（不初始化全局单例）"
    );
}

// ------------------------------------------------------------------------
// ACC-RES-004..005：auth-server 内网 API Key / 限流（镜像
// tests/auth_server_integration.rs 的 MockAuthBackend 双端口装配）
// ------------------------------------------------------------------------

/// 测试用 Mock AuthBackend（in-memory token 表，镜像
/// tests/auth_server_integration.rs 的已知良好装配，注释见该文件 NEEDS CLARIFICATION）。
struct MockAuthBackend {
    tokens: parking_lot::Mutex<HashMap<String, String>>,
}

impl MockAuthBackend {
    fn new() -> Self {
        Self {
            tokens: parking_lot::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AuthBackend for MockAuthBackend {
    async fn login(&self, login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
        let token = format!("token-{}-{}", login_id, uuid_like());
        self.tokens
            .lock()
            .insert(token.clone(), login_id.to_string());
        Ok(token)
    }

    async fn logout(&self, token: &str) -> GarrisonResult<()> {
        self.tokens.lock().remove(token);
        Ok(())
    }

    async fn check_login(&self, token: &str) -> GarrisonResult<bool> {
        Ok(self.tokens.lock().contains_key(token))
    }

    async fn check_permission(&self, token: &str, _permission: &str) -> GarrisonResult<()> {
        if !self.tokens.lock().contains_key(token) {
            return Err(GarrisonError::InvalidToken("token 无效".to_string()));
        }
        Ok(())
    }

    async fn check_role(&self, token: &str, _role: &str) -> GarrisonResult<()> {
        if !self.tokens.lock().contains_key(token) {
            return Err(GarrisonError::InvalidToken("token 无效".to_string()));
        }
        Ok(())
    }

    async fn check_safe(&self, _token: &str) -> GarrisonResult<bool> {
        Ok(false)
    }

    async fn check_disable(&self, _token: &str) -> GarrisonResult<bool> {
        Ok(false)
    }

    async fn check_api_key(&self, _api_key: &str, _namespace: &str) -> GarrisonResult<()> {
        Ok(())
    }

    async fn get_token_info(
        &self,
        token: &str,
    ) -> GarrisonResult<garrison::backend::types::TokenInfo> {
        if !self.tokens.lock().contains_key(token) {
            return Err(GarrisonError::InvalidToken("token 无效".to_string()));
        }
        Ok(garrison::backend::types::TokenInfo {
            token: token.to_string(),
            created_at: 1000,
            last_active_at: 2000,
        })
    }

    async fn get_session(
        &self,
        token: &str,
    ) -> GarrisonResult<garrison::backend::types::SessionData> {
        let login_id = self
            .tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| GarrisonError::InvalidToken("token 无效".to_string()))?;
        Ok(garrison::backend::types::SessionData {
            token: token.to_string(),
            login_id,
            created_at: 1000,
            last_active_at: 2000,
            attrs: HashMap::new(),
            device: None,
            ip: None,
            user_agent: None,
            safe_services: HashMap::new(),
            #[cfg(feature = "session-extra")]
            dynamic_active_timeout: None,
            #[cfg(feature = "session-extra")]
            is_anon: false,
            effective_timeout: None,
        })
    }

    async fn kickout(&self, login_id: &str) -> GarrisonResult<()> {
        let mut tokens = self.tokens.lock();
        tokens.retain(|_, v| v != login_id);
        Ok(())
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()> {
        let mut tokens = self.tokens.lock();
        if let Some(v) = tokens.get_mut(token) {
            *v = target_login_id.to_string();
            Ok(())
        } else {
            Err(GarrisonError::InvalidToken("token 无效".to_string()))
        }
    }

    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
        let login_id = self
            .tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| GarrisonError::InvalidToken("token 无效".to_string()))?;
        let new_token = format!("token-{}-{}", login_id, uuid_like());
        let mut tokens = self.tokens.lock();
        tokens.remove(token);
        tokens.insert(new_token.clone(), login_id);
        Ok(new_token)
    }
}

/// 生成一个简单的伪 UUID（不依赖 uuid crate，镜像 auth_server_integration.rs）。
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}

/// 启动双端口测试服务器（外网 + 内网），返回 (external_url, internal_url, handle)。
async fn start_test_server(
    rate_limit: u32,
    api_key: &str,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend::new());

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(api_key);

    let external_router = server.external_router();
    let internal_router = server.internal_router();

    let handle = tokio::spawn(async move {
        let (ext_res, int_res) = tokio::join!(
            axum::serve(external_listener, external_router),
            axum::serve(internal_listener, internal_router)
        );
        if let Err(e) = ext_res {
            eprintln!("外网服务器异常: {}", e);
        }
        if let Err(e) = int_res {
            eprintln!("内网服务器异常: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    (external_url, internal_url, handle)
}

/// ACC-RES-004（异常）：auth-server 内网端口 API Key 校验 fail-closed——
/// 缺失或错误 X-API-Key 均返回 401，正确 Key 放行（200）。
#[tokio::test]
async fn acc_res_004_internal_api_key_wrong_rejected_401() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "secret-key").await;
    let client = reqwest::Client::new();

    // 缺失 X-API-Key → 401
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "缺失 API Key 应返回 401");

    // 错误 X-API-Key → 401
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "错误 API Key 应返回 401");

    // 正确 X-API-Key → 200（正常锚点）
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "正确 API Key 应放行");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], "ok");
}

/// ACC-RES-005（异常）：auth-server 外网限流——速率上限内放行（200），
/// 超限返回 429（令牌桶 per-IP）。
#[tokio::test]
async fn acc_res_005_auth_server_rate_limit_returns_429() {
    // 限速 2 req/s
    let (external_url, _internal_url, _handle) = start_test_server(2, "test-key").await;
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });

    for _ in 0..2 {
        let resp = client
            .post(format!("{}/api/v1/auth/login", external_url))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "限速额度内登录应放行");
    }

    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "超限第 3 个请求应被限流 429");
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        resp_body["error"], "rate_limited",
        "429 响应体应携带 rate_limited 错误码"
    );
}

// ------------------------------------------------------------------------
// ACC-RES-006..008：BackendRemote 错误传播 / 超时 / 熔断打开与恢复
// ------------------------------------------------------------------------

/// ACC-RES-006（异常）：BackendRemote 收到上游 HTTP 500 → 错误显性传播为
/// `GarrisonError::Network`（含 HTTP 状态码），不吞错。
#[tokio::test]
async fn acc_res_006_backend_remote_500_error_propagates() {
    let server = MockServer::start().await;
    let remote = BackendRemote::new(server.uri(), "api-key", Duration::from_secs(5)).unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/check-login"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let result = remote.check_login("some-token").await;
    let err = result.expect_err("上游 500 时应显性返回错误");
    assert!(
        matches!(err, GarrisonError::Network(_)),
        "上游 500 应映射为 Network 错误，实际: {:?}",
        err
    );
    assert!(
        format!("{err}").contains("HTTP 500"),
        "错误信息应包含 HTTP 状态码，实际: {err}"
    );
}

/// ACC-RES-007（异常）：BackendRemote 上游响应超时（wiremock 延迟注入）→
/// 客户端超时显性传播为 `GarrisonError::Network`（传输层错误），且耗时落在
/// 客户端超时窗口内（wiremock 延迟 3s vs 客户端 300ms），排除立即失败与
/// 慢速成功路径。
#[tokio::test]
async fn acc_res_007_backend_remote_timeout_error_propagates() {
    let server = MockServer::start().await;
    // 客户端超时 300ms；上游延迟 3s → 必然超时
    let remote = BackendRemote::new(server.uri(), "api-key", Duration::from_millis(300)).unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/check-login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(serde_json::json!({
                    "data": true,
                    "error_code": null,
                    "message": null
                })),
        )
        .mount(&server)
        .await;

    let started = std::time::Instant::now();
    let result = remote.check_login("some-token").await;
    let elapsed = started.elapsed();
    let err = result.expect_err("上游超时应显性返回错误");
    assert!(
        matches!(err, GarrisonError::Network(_)),
        "超时应映射为 Network 错误，实际: {:?}",
        err
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("error sending request"),
        "错误信息应包含传输层失败原因，实际: {msg}"
    );
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(2),
        "应在客户端超时窗口内失败（wiremock 延迟 3s vs 客户端 300ms），实际耗时: {elapsed:?}"
    );
}

/// ACC-RES-008（异常+恢复）：BackendRemote 熔断——连续失败达阈值后打开并
/// 快速拒绝（不再发起真实 HTTP 请求），打开超时后探活成功自动恢复关闭。
#[tokio::test]
async fn acc_res_008_backend_remote_circuit_breaker_opens_and_recovers() {
    let server = MockServer::start().await;
    // failure_threshold=3, success_threshold=2（半开需 2 次成功才关闭）, 打开 700ms
    let breaker = Arc::new(CircuitBreakerWrapper::new(CircuitBreakerConfig::new(
        3,
        2,
        Duration::from_millis(700),
    )));
    let remote = BackendRemote::new(server.uri(), "api-key", Duration::from_secs(5))
        .unwrap()
        .with_circuit_breaker(breaker.clone());

    // 故障阶段：连续 3 次 500
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/check-login"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    for _ in 0..3 {
        let result = remote.check_login("some-token").await;
        assert!(
            matches!(result, Err(GarrisonError::Network(_))),
            "上游 500 应向熔断器计入失败，实际: {:?}",
            result
        );
    }
    assert!(breaker.is_open().await, "3 次连续失败后熔断器应打开");

    // 熔断打开：后续请求快速拒绝（circuit-limited/circuit-open），不再发起
    // 真实 HTTP 请求。注：limiteron 打开态经 `CircuitBreakerWrapper` 映射为
    // `GarrisonError::FirewallBlocked("circuit-limited::...")`
    // （src/limiteron/circuit.rs `to_garrison_error`），Network("circuit-open")
    // 为 Guard 变体，二者均为熔断拒绝语义。
    let before = server
        .received_requests()
        .await
        .expect("应能获取请求记录")
        .len();
    let fast_fail = remote.check_login("some-token").await.unwrap_err();
    let fast_msg = format!("{fast_fail}");
    assert!(
        matches!(
            fast_fail,
            GarrisonError::FirewallBlocked(_) | GarrisonError::Network(_)
        ),
        "熔断打开后应快速拒绝，实际: {fast_msg}"
    );
    assert!(
        fast_msg.contains("circuit-"),
        "熔断拒绝错误信息应包含 circuit 标记，实际: {fast_msg}"
    );
    let after = server
        .received_requests()
        .await
        .expect("应能获取请求记录")
        .len();
    assert_eq!(
        before, after,
        "熔断打开期间不应再发起真实 HTTP 请求（快速失败）"
    );

    // 恢复阶段：上游恢复 200（先清空全部 mock，再挂载成功响应），等待打开
    // 超时后进入半开探活
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/check-login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": true,
            "error_code": null,
            "message": null
        })))
        .mount(&server)
        .await;
    tokio::time::sleep(Duration::from_millis(900)).await; // > 700ms 打开超时 → 半开

    for _ in 0..2 {
        let ok = remote
            .check_login("some-token")
            .await
            .expect("半开探活/关闭后请求应成功");
        assert!(ok, "恢复后 check_login 应返回 true");
    }
    assert!(!breaker.is_open().await, "探活成功后熔断器应恢复关闭");

    let ok = remote
        .check_login("some-token")
        .await
        .expect("关闭后请求应正常");
    assert!(ok, "熔断恢复后 check_login 应返回 true");
}
