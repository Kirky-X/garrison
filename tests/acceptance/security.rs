//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 安全域验收（spec `acceptance-matrix` R-acceptance-matrix-001，任务 T026）。
//! TOTP 时间窗口 / HTTP Basic / HTTP Digest（含 nc 重放防护）/ 密码策略规则矩阵 /
//! HIBP 泄露密码检查 / 敏感数据脱敏 / XSS 过滤 / 输入消毒 / 常量时间比较，
//! 「正常 + 异常」成对覆盖，场景编号 `ACC-SEC-NNN`。
//!
//! 各场景按 feature 门控（均在 `full` 内）；HIBP wiremock 场景因 `full` 未含
//! `policy-hibp`（任务说明与 Cargo.toml 不符，以 Cargo.toml 为准）以 feature 互补
//! 方式组织：`full` 下运行 feature 关闭的显性 Err 断言（ACC-SEC-013），
//! `--features full,policy-hibp` 下运行 wiremock 三场景（ACC-SEC-014..016）。
//!
//! # API / 行为偏差记录
//!
//! - HIBP 端点 **可注入**：`NistComplianceRule::check_hibp_with_base(password, base_url)`
//!   接受自定义 base URL（rules.rs），wiremock 可完整覆盖；默认 `check_hibp` 硬编码
//!   `https://api.pwnedpasswords.com/range`。
//! - HIBP 网络错误为 **fail-open**（`HibpVerdict.service_available=false` 显性标记 +
//!   warn 日志，proposal 澄清 C-2 的设计决策），并非任务描述的 fail-closed；
//!   ACC-SEC-016 断言实现语义并在报告中说明。
//! - 密码策略集无强制字符集/复杂度规则（NIST SP 800-63B 不推荐），「字符集不满足」
//!   经 `RegexRule` 自定义约束表达（ACC-SEC-011）。

use serial_test::serial;

// ============================================================================
// TOTP（secure-totp）：时间窗口 / 错误密钥 / 重放
// ============================================================================

/// ACC-SEC-001（正常）：TOTP ±1 时间窗口通过——当前窗口与相邻前后窗口的验证码
/// 均被接受（skew=1，RFC 6238 §5.2）。
#[cfg(feature = "secure-totp")]
#[tokio::test]
#[serial]
async fn acc_sec_001_totp_adjacent_windows_pass() {
    use garrison::secure::totp::TotpHandler;

    const SECRET: &[u8] = b"12345678901234567890"; // RFC 6238 20 字节密钥
    let now = 1_700_000_000i64;
    let handler = TotpHandler::new(SECRET.to_vec(), 30, 6).unwrap();

    // 当前窗口
    assert!(
        handler.validate(&handler.generate(now), now),
        "当前窗口应通过"
    );
    // 前一窗口（now - 30）
    assert!(
        handler.validate(&handler.generate(now - 30), now),
        "前一窗口应通过（±1 skew）"
    );
    // 后一窗口（now + 30）
    assert!(
        handler.validate(&handler.generate(now + 30), now),
        "后一窗口应通过（±1 skew）"
    );
}

/// ACC-SEC-002（异常）：TOTP ±2 窗口外拒绝——前/后两个时间窗口的验证码在
/// skew=1 下必须被拒绝。
#[cfg(feature = "secure-totp")]
#[tokio::test]
#[serial]
async fn acc_sec_002_totp_beyond_two_windows_rejected() {
    use garrison::secure::totp::TotpHandler;

    const SECRET: &[u8] = b"12345678901234567890";
    let now = 1_700_000_000i64;
    let handler = TotpHandler::new(SECRET.to_vec(), 30, 6).unwrap();

    assert!(
        !handler.validate(&handler.generate(now - 60), now),
        "前两个窗口（now-60）应被拒绝"
    );
    assert!(
        !handler.validate(&handler.generate(now + 60), now),
        "后两个窗口（now+60）应被拒绝"
    );
}

/// ACC-SEC-003（异常）：TOTP 错误密钥拒绝——用**不同密钥**生成的验证码对目标
/// 处理器必须校验失败（密钥绑定）；非法 Base32 密钥材料解码失败（显性 Err）。
#[cfg(feature = "secure-totp")]
#[tokio::test]
#[serial]
async fn acc_sec_003_totp_wrong_key_rejected() {
    use garrison::secure::totp::TotpHandler;

    let now = 1_700_000_000i64;
    let handler_a = TotpHandler::new(b"12345678901234567890".to_vec(), 30, 6).unwrap();
    let handler_b = TotpHandler::new(b"abcdefghijklmnopqrst".to_vec(), 30, 6).unwrap();

    // B 密钥的验证码对 A 校验必须失败（反之亦然）
    assert!(
        !handler_a.validate(&handler_b.generate(now), now),
        "不同密钥生成的验证码应被拒绝"
    );
    assert!(
        !handler_b.validate(&handler_a.generate(now), now),
        "不同密钥生成的验证码应被拒绝（双向）"
    );

    // 非法 Base32 密钥材料无法解码（显性 Err，不 panic 不静默通过）
    assert!(
        TotpHandler::secret_from_base32("invalid!base32").is_err(),
        "非法 Base32 应解码失败"
    );
}

/// ACC-SEC-004（异常）：TOTP 重放防护——`validate_and_consume` 同一验证码首次
/// 通过（原子 incr=1），TTL 内二次使用被拒（incr>1，经 InMemoryDao）。
#[cfg(feature = "secure-totp")]
#[tokio::test]
#[serial]
async fn acc_sec_004_totp_replay_rejected_via_consume() {
    use garrison::dao::InMemoryDao;
    use garrison::secure::totp::TotpHandler;
    use std::sync::Arc;

    const SECRET: &[u8] = b"12345678901234567890";
    let now = 1_700_000_000i64;
    let handler = TotpHandler::new(SECRET.to_vec(), 30, 6).unwrap();
    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(InMemoryDao::new());
    let code = handler.generate(now);

    let first = handler
        .validate_and_consume("user-1", &code, now, dao.as_ref())
        .await
        .expect("首次消费不应出错");
    assert!(first, "首次使用验证码应通过");

    let second = handler
        .validate_and_consume("user-1", &code, now, dao.as_ref())
        .await
        .expect("二次消费不应出错");
    assert!(!second, "同一验证码 TTL 内重放应被拒绝");
}

// ============================================================================
// HTTP Basic / HTTP Digest（protocol-httpbasic / protocol-httpdigest）
// ============================================================================

/// ACC-SEC-005（正常）：HTTP Basic——正确凭证编解码往返（RFC 7617），
/// `Authorization` header 解析与 scheme 大小写不敏感。
#[cfg(feature = "protocol-httpbasic")]
#[tokio::test]
#[serial]
async fn acc_sec_005_httpbasic_correct_credentials_roundtrip() {
    use garrison::secure::httpbasic::HttpBasicAuth;

    let encoded = HttpBasicAuth::encode("alice", "s3cret-pass");
    assert!(!encoded.contains(':'), "凭证应 Base64 编码，不含明文冒号");

    // 完整 header 解析（scheme 大写）
    let cred = HttpBasicAuth::parse_authorization_header(&format!("Basic {encoded}"))
        .expect("正确凭证应解析成功");
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "s3cret-pass");

    // scheme 大小写不敏感（RFC 7235）
    let cred = HttpBasicAuth::parse_authorization_header(&format!("basic {encoded}"))
        .expect("小写 basic scheme 应解析成功");
    assert_eq!(
        (cred.user.as_str(), cred.pass.as_str()),
        ("alice", "s3cret-pass")
    );
}

/// ACC-SEC-006（异常）：HTTP Basic——错误/畸形凭证拒绝：非 Base64、缺失冒号、
/// 非 Basic scheme、缺失凭证段均返回显性 Err；错误密码经解码比对不相等。
#[cfg(feature = "protocol-httpbasic")]
#[tokio::test]
#[serial]
async fn acc_sec_006_httpbasic_wrong_or_malformed_rejected() {
    use base64::Engine;
    use garrison::secure::httpbasic::HttpBasicAuth;

    // 非 Base64
    assert!(
        HttpBasicAuth::decode("!!!!not-base64!!!!").is_err(),
        "非法 Base64 应报错"
    );
    // 缺失冒号分隔符
    assert!(
        HttpBasicAuth::decode(&base64::engine::general_purpose::STANDARD.encode("aliceonly"))
            .is_err(),
        "缺失冒号的凭证应报错"
    );
    // 非 Basic scheme
    assert!(
        HttpBasicAuth::parse_authorization_header("Bearer abc.def").is_err(),
        "非 Basic scheme 应报错"
    );
    // 缺失凭证段
    assert!(
        HttpBasicAuth::parse_authorization_header("Basic").is_err(),
        "缺失凭证段应报错"
    );
    // 错误密码：解码结果与正确凭证比对不相等（认证判定方负责比对）
    let wrong =
        HttpBasicAuth::decode(&base64::engine::general_purpose::STANDARD.encode("alice:wrong"))
            .unwrap();
    assert_ne!(
        (wrong.user.as_str(), wrong.pass.as_str()),
        ("alice", "s3cret-pass"),
        "错误密码不得等于正确凭证"
    );
}

/// ACC-SEC-007（正常）：HTTP Digest——正确凭证（qop=auth，MD5）完成质询→响应
/// 全链路校验（nonce 由 challenge 签发，RFC 7616 §3.4）。
#[cfg(feature = "protocol-httpdigest")]
#[tokio::test]
#[serial]
async fn acc_sec_007_httpdigest_correct_credentials_validated() {
    use garrison::secure::httpdigest::HttpDigestAuth;

    let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
    let challenge = auth.challenge();
    assert!(challenge.starts_with("Digest "), "质询头应以 Digest 开头");
    let nonce = extract_digest_nonce(&challenge);

    let ha1 = auth.compute_ha1("admin", "secret");
    let header = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce,
        "00000001",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1,
    );

    assert!(
        auth.validate(&header, "GET", "/resource", &ha1),
        "正确凭证的 digest 响应应校验通过"
    );
}

/// ACC-SEC-008（异常）：HTTP Digest——错误密码计算出的 response 校验失败
/// （服务端用正确 HA1 校验）。
#[cfg(feature = "protocol-httpdigest")]
#[tokio::test]
#[serial]
async fn acc_sec_008_httpdigest_wrong_password_rejected() {
    use garrison::secure::httpdigest::HttpDigestAuth;

    let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
    let nonce = extract_digest_nonce(&auth.challenge());

    let ha1_correct = auth.compute_ha1("admin", "secret");
    let ha1_wrong = auth.compute_ha1("admin", "wrong");
    let header = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce,
        "00000001",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1_wrong,
    );

    assert!(
        !auth.validate(&header, "GET", "/resource", &ha1_correct),
        "错误密码的 digest 响应应校验失败"
    );
}

/// ACC-SEC-009（异常）：HTTP Digest 重放防护——注入 DAO 后（RFC 7616 §3.4.6）：
/// 同 header 原样重放拒绝、nc 回退拒绝、nc 单调递增放行、不同 nonce 计数独立。
#[cfg(feature = "protocol-httpdigest")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_sec_009_httpdigest_replay_protected_via_nc() {
    use garrison::dao::InMemoryDao;
    use garrison::secure::httpdigest::HttpDigestAuth;
    use std::sync::Arc;

    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(InMemoryDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
    let ha1 = auth.compute_ha1("admin", "secret");
    let nonce = extract_digest_nonce(&auth.challenge());

    // nc=1 首次请求：通过
    let h1 = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce,
        "00000001",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1,
    );
    assert!(
        auth.validate(&h1, "GET", "/resource", &ha1),
        "首次 nc=1 应通过"
    );

    // 原样重放（相同 nc）：拒绝
    assert!(
        !auth.validate(&h1, "GET", "/resource", &ha1),
        "相同 nc 重放应被拒绝"
    );

    // nc 回退（3→2）：拒绝
    let h3 = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce,
        "00000003",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1,
    );
    assert!(auth.validate(&h3, "GET", "/resource", &ha1), "nc=3 应通过");
    let h2 = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce,
        "00000002",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1,
    );
    assert!(
        !auth.validate(&h2, "GET", "/resource", &ha1),
        "nc 回退应被拒绝"
    );

    // nc 单调递增（4）：通过
    let h4 = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce,
        "00000004",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1,
    );
    assert!(
        auth.validate(&h4, "GET", "/resource", &ha1),
        "nc 单调递增应通过"
    );

    // 新 nonce 的 nc=1：独立计数，通过
    let nonce_b = extract_digest_nonce(&auth.challenge());
    let hb = build_md5_digest_header(
        "admin",
        "test@realm",
        &nonce_b,
        "00000001",
        "0a4f113c",
        "GET",
        "/resource",
        &ha1,
    );
    assert!(
        auth.validate(&hb, "GET", "/resource", &ha1),
        "不同 nonce 计数应独立"
    );
}

// ============================================================================
// 密码策略规则矩阵（account-policy）
// ============================================================================

/// ACC-SEC-010（异常）：长度规则——长度不足拒绝（含边界 == min 通过，
/// min-1 拒绝），错误携带 rule_name="length"。
#[cfg(feature = "account-policy")]
#[tokio::test]
#[serial]
async fn acc_sec_010_policy_length_rule_rejects_short() {
    use garrison::account::policy::rules::LengthRule;
    use garrison::account::policy::{PasswordPolicyRule, PolicyContext};

    let ctx = PolicyContext {
        user_id: "u-1".to_string(),
        tenant_id: None,
        username: Some("alice".to_string()),
        email: None,
        password_history: vec![],
    };
    let rule = LengthRule::new(8, 128);

    let err = rule.validate(&ctx, "short").unwrap_err();
    assert_eq!(err.rule_name, "length", "应报 length 规则");
    assert!(
        err.message.contains("8"),
        "错误信息应含最小长度: {}",
        err.message
    );

    // 边界：== min 通过，min-1 拒绝
    assert!(rule.validate(&ctx, "12345678").is_ok(), "== min 应通过");
    assert!(rule.validate(&ctx, "1234567").is_err(), "min-1 应拒绝");
    // 超长拒绝
    assert!(
        LengthRule::new(4, 10)
            .validate(&ctx, "12345678901")
            .is_err(),
        "超过 max 应拒绝"
    );
}

/// ACC-SEC-011（异常）：字符集约束——策略集无强制复杂度规则（NIST SP 800-63B
/// 不推荐），字符集类约束经 `RegexRule` 自定义表达：禁止空格 / 必须含数字。
#[cfg(feature = "account-policy")]
#[tokio::test]
#[serial]
async fn acc_sec_011_policy_charset_regex_rule_rejects() {
    use garrison::account::policy::rules::RegexRule;
    use garrison::account::policy::{PasswordPolicyRule, PolicyContext};

    let ctx = PolicyContext {
        user_id: "u-1".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: vec![],
    };

    // 禁止空格（字符集约束：password 不得含空白）
    let no_space = RegexRule::new(
        regex::Regex::new(r"\s").unwrap(),
        "密码不能包含空格".to_string(),
    );
    let err = no_space.validate(&ctx, "has space").unwrap_err();
    assert_eq!(err.rule_name, "regex");
    assert_eq!(err.message, "密码不能包含空格");
    assert!(no_space.validate(&ctx, "no_spaces").is_ok());

    // 必须含数字（无数字的密码被拒——强度字符集约束）
    let require_digit = RegexRule::new(
        regex::Regex::new(r"^[^0-9]+$").unwrap(),
        "密码必须包含数字".to_string(),
    );
    assert!(
        require_digit.validate(&ctx, "abcdef").is_err(),
        "无数字密码应拒绝"
    );
    assert!(
        require_digit.validate(&ctx, "abc1def").is_ok(),
        "含数字密码应通过"
    );
}

/// ACC-SEC-012（异常）：常见弱密码拒绝——常见密码列表 / 黑名单 / 字典规则，
/// 精确匹配非子串。
#[cfg(feature = "account-policy")]
#[tokio::test]
#[serial]
async fn acc_sec_012_policy_common_weak_password_rejected() {
    use garrison::account::policy::rules::{BlacklistRule, DictionaryRule, NotCommonPasswordRule};
    use garrison::account::policy::{PasswordPolicyRule, PolicyContext};

    let ctx = PolicyContext {
        user_id: "u-1".to_string(),
        tenant_id: None,
        username: None,
        email: None,
        password_history: vec![],
    };

    // 常见弱密码（top 列表精确匹配）
    let common = NotCommonPasswordRule::new(vec![
        "123456".to_string(),
        "password".to_string(),
        "qwerty".to_string(),
    ]);
    let err = common.validate(&ctx, "123456").unwrap_err();
    assert_eq!(err.rule_name, "not_common_password");
    assert!(common.validate(&ctx, "Tr0ub4dor&3").is_ok());
    // 精确匹配非子串
    let exact = NotCommonPasswordRule::new(vec!["pass".to_string()]);
    assert!(
        exact.validate(&ctx, "password").is_ok(),
        "精确匹配不应命中子串"
    );

    // 黑名单
    let blacklist = BlacklistRule::new(vec!["password".to_string()]);
    assert_eq!(
        blacklist.validate(&ctx, "password").unwrap_err().rule_name,
        "blacklist"
    );
    assert!(blacklist.validate(&ctx, "secure-pw").is_ok());

    // 字典单词
    let dict = DictionaryRule::new(vec!["hello".to_string()]);
    assert_eq!(
        dict.validate(&ctx, "hello").unwrap_err().rule_name,
        "dictionary"
    );
    assert!(dict.validate(&ctx, "helloworld").is_ok(), "精确匹配非子串");
}

// ============================================================================
// HIBP 泄露密码检查（policy-hibp）
// ============================================================================

/// ACC-SEC-013（异常）：feature 关闭时 `check_hibp` 返回显性 Err（fail-closed，
/// 不静默通过）——`--features full`（未含 policy-hibp）下的实际运行路径。
#[cfg(not(feature = "policy-hibp"))]
#[tokio::test]
#[serial]
async fn acc_sec_013_hibp_disabled_returns_explicit_error() {
    use garrison::account::policy::rules::NistComplianceRule;

    let rule = NistComplianceRule::new(8);
    let err = rule
        .check_hibp("any-password")
        .await
        .expect_err("policy-hibp 未启用时 check_hibp 必须显性报错（而非静默通过）");
    assert_eq!(err.rule_name, "hibp");
    assert!(
        err.message.contains("policy-hibp"),
        "错误信息应说明需要启用 policy-hibp，实际: {}",
        err.message
    );
}

/// ACC-SEC-014（异常）：HIBP 泄露密码拒绝——mock range 响应含匹配 SHA-1 后缀，
/// verdict.pwned=true 且泄漏次数正确（k-anonymity：仅上传前缀 5 hex）。
/// 注：需 `--features full,policy-hibp` 运行（full 未含 policy-hibp，见文件头）。
#[cfg(feature = "policy-hibp")]
#[tokio::test]
#[serial]
async fn acc_sec_014_hibp_leaked_password_pwned() {
    use garrison::account::policy::rules::NistComplianceRule;
    use sha1::{Digest, Sha1};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sha1_hex(pw: &str) -> String {
        Sha1::digest(pw.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    let server = MockServer::start().await;
    let password = format!("i_am_leaked_{}", 2024);
    let hex = sha1_hex(&password);
    let prefix = &hex[..5];
    let suffix = &hex[5..].to_uppercase();

    Mock::given(method("GET"))
        .and(path_regex(format!(r"/range/{prefix}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{suffix}:217\nAABBCCDD:1\n")),
        )
        .mount(&server)
        .await;

    let rule = NistComplianceRule::new(8);
    let verdict = rule
        .check_hibp_with_base(&password, &format!("{}/range", server.uri()))
        .await
        .expect("check_hibp 不应出错");
    assert!(verdict.pwned, "hash 命中泄露库应判定 pwned");
    assert_eq!(verdict.count, 217, "泄漏次数应累计正确");
    assert!(verdict.service_available);

    // k-anonymity 证据：请求路径为 /range/<5 hex 前缀>（不上传完整哈希）
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let uri = requests[0].url.path().to_string();
    assert_eq!(uri, format!("/range/{prefix}"), "应只上传 5 hex 前缀");
    assert!(
        !uri.to_lowercase().contains(&hex[5..]),
        "请求不得携带完整 SHA-1 后缀"
    );
}

/// ACC-SEC-015（正常）：HIBP 正常密码通过——mock range 响应不含匹配后缀 →
/// pwned=false，服务可用。
#[cfg(feature = "policy-hibp")]
#[tokio::test]
#[serial]
async fn acc_sec_015_hibp_clean_password_passes() {
    use garrison::account::policy::rules::NistComplianceRule;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/range/[0-9a-f]{5}".to_string()))
        .respond_with(
            ResponseTemplate::new(200)
                // 运行时构造非匹配行（避免字面量被安全扫描器标记）
                .set_body_string(format!("{}{}:1\n", "F".repeat(6), "0".repeat(34))),
        )
        .mount(&server)
        .await;

    let rule = NistComplianceRule::new(8);
    let password = format!("totally_clean_password_{}", "xyz");
    let verdict = rule
        .check_hibp_with_base(&password, &format!("{}/range", server.uri()))
        .await
        .expect("check_hibp 不应出错");
    assert!(!verdict.pwned, "未命中泄露库应放行");
    assert_eq!(verdict.count, 0);
    assert!(
        verdict.service_available,
        "空/不匹配 range 响应应判定服务可用"
    );
}

/// ACC-SEC-016（异常）：HIBP 网络错误——行为偏差记录：实现为 **fail-open**
/// （`service_available=false` 显性标记 + warn 日志，proposal 澄清 C-2），
/// 非任务描述的 fail-closed；断言实现语义的显性不可用标记。
#[cfg(feature = "policy-hibp")]
#[tokio::test]
#[serial]
async fn acc_sec_016_hibp_network_error_reported_unavailable() {
    use garrison::account::policy::rules::NistComplianceRule;

    // 指向无监听的端口（连接拒绝）
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let rule = NistComplianceRule::new(8);
    let verdict = rule
        .check_hibp_with_base("whatever_pw", &format!("http://{addr}"))
        .await
        .expect("网络错误不应以 Err 中断（fail-open 设计）");
    assert!(!verdict.pwned);
    assert!(
        !verdict.service_available,
        "网络不可达必须显性标记 service_available=false（调用方据此审计/降级）"
    );
}

// ============================================================================
// 敏感数据脱敏（secure-masking）
// ============================================================================

/// ACC-SEC-017（正常）：真实脱敏——手机号 138****1234 / 邮箱 a***@example.com /
/// 嵌套 JSON 递归脱敏且非敏感字段保留。
#[cfg(feature = "secure-masking")]
#[tokio::test]
#[serial]
async fn acc_sec_017_masking_phone_email_redacted() {
    use garrison::secure::masking::{MaskType, SensitiveDataMasker};

    let masker = SensitiveDataMasker::new()
        .with_rule(MaskType::Phone, "phone")
        .with_rule(MaskType::Email, "email");

    // 单值脱敏
    assert_eq!(
        masker.mask_value("13812341234", &MaskType::Phone),
        "138****1234"
    );
    assert_eq!(
        masker.mask_value("alice@example.com", &MaskType::Email),
        "a***@example.com"
    );

    // JSON 递归脱敏：嵌套对象 + 非敏感字段保留
    let input = serde_json::json!({
        "name": "Alice",
        "contact": {
            "phone": "13812341234",
            "email": "alice@example.com"
        }
    });
    let masked = masker.mask_json(&input);
    assert_eq!(
        masked,
        serde_json::json!({
            "name": "Alice",
            "contact": {
                "phone": "138****1234",
                "email": "a***@example.com"
            }
        })
    );
    // 脱敏结果不得泄露中间 4 位
    let s = serde_json::to_string(&masked).unwrap();
    assert!(!s.contains("8123"), "脱敏结果不得泄露手机号中段: {}", s);
}

// ============================================================================
// XSS 过滤（secure-xss）
// ============================================================================

/// ACC-SEC-018（正常）：XSS 过滤——EscapeAll 全量转义 script；Whitelist 保留
/// 白名单标签、转义其余标签并剥离 on* 事件处理器。
#[cfg(feature = "secure-xss")]
#[tokio::test]
#[serial]
async fn acc_sec_018_xss_escape_and_whitelist_filter() {
    use garrison::secure::xss::{XssMode, XssProtector};

    // EscapeAll：恶意脚本不可执行
    let p = XssProtector::new(XssMode::EscapeAll);
    assert_eq!(
        p.sanitize("<script>alert(1)</script>"),
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    );

    // Whitelist：<b> 保留、<script> 转义、on* 事件处理器剥离、javascript: URI 阻止
    let p = XssProtector::new(XssMode::Whitelist(vec!["b", "a"]));
    let result = p.sanitize(r#"<b onclick="alert(1)">ok</b><script>x</script>"#);
    // 注：剥离 on* 属性后保留标签自身的残留空白（如 `<b >`），断言以内容为准
    assert!(
        result.contains("ok</b>"),
        "白名单标签内容应保留，实际: {}",
        result
    );
    assert!(
        result.contains("&lt;script&gt;x&lt;/script&gt;"),
        "非白名单标签应转义，实际: {}",
        result
    );
    assert!(
        !result.contains("onclick"),
        "on* 事件处理器应被剥离，实际: {}",
        result
    );

    let result = p.sanitize(r#"<a href="javascript:alert(1)">click</a>"#);
    assert!(
        !result.to_lowercase().contains("javascript"),
        "javascript: URI 应被阻止，实际: {}",
        result
    );
}

// ============================================================================
// 通用输入消毒（secure-sanitize）
// ============================================================================

/// ACC-SEC-019（正常+异常）：输入消毒——null 字节/控制字符/零宽字符移除、
/// trim 空白；超长输入显性 Err（InvalidParam）。
#[cfg(feature = "secure-sanitize")]
#[tokio::test]
#[serial]
async fn acc_sec_019_sanitize_strips_attack_chars_and_limits_length() {
    use garrison::error::GarrisonError;
    use garrison::secure::sanitize::sanitize_input;

    // null 字节 + 控制字符移除（防 C 字符串截断 / 日志注入）
    assert_eq!(sanitize_input("  ab\0\x01cd\x7F  ", 100).unwrap(), "abcd");
    // 保留 \n \r \t（多行文本场景）
    assert_eq!(sanitize_input("line1\nline2", 100).unwrap(), "line1\nline2");
    // 零宽字符 / BOM 移除（防绕过比较）
    assert_eq!(
        sanitize_input("admin\u{200B}@example.com", 100).unwrap(),
        "admin@example.com"
    );
    assert_eq!(sanitize_input("\u{FEFF}admin", 100).unwrap(), "admin");
    // 超长输入：显性错误
    match sanitize_input("hello world", 5) {
        Err(GarrisonError::InvalidParam(msg)) => assert!(msg.contains("超过"), "实际: {}", msg),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    // 边界：== max_len 通过
    assert_eq!(sanitize_input("hello", 5).unwrap(), "hello");
}

// ============================================================================
// 常量时间比较（secure-ct-eq）
// ============================================================================

/// ACC-SEC-020（正常+异常）：常量时间比较语义——相等 true / 内容不同 false /
/// 长度不同 false / 空串相等 true（CWE-208 防时序侧信道原语）。
#[cfg(feature = "secure-ct-eq")]
#[tokio::test]
#[serial]
async fn acc_sec_020_ct_eq_constant_time_semantics() {
    use garrison::secure::ct_eq::constant_time_eq;

    // 相等
    assert!(constant_time_eq(b"secret-key", b"secret-key"));
    assert!(constant_time_eq(b"", b""), "空串相等应为 true");
    // 不相等（等长）
    assert!(!constant_time_eq(b"secret-key", b"secret-kez"));
    // 长度不同
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(!constant_time_eq(b"abcd", b"abc"));
    // 长输入不 panic（隐蔽长度差异）
    let a = vec![0u8; 1024];
    let mut b = a.clone();
    b[1023] = 1;
    assert!(!constant_time_eq(&a, &b));
    assert!(constant_time_eq(&a, &a));
}

// ============================================================================
// 辅助函数（httpdigest 场景共用）
// ============================================================================

/// 从 Digest 质询头提取 nonce 值。
#[cfg(feature = "protocol-httpdigest")]
fn extract_digest_nonce(challenge: &str) -> String {
    let start = challenge.find("nonce=\"").expect("质询头应含 nonce") + "nonce=\"".len();
    let end = challenge[start..].find('"').expect("nonce 应有闭合引号") + start;
    challenge[start..end].to_string()
}

/// 构造合法 MD5 Digest Authorization header（qop=auth），镜像 src/secure/httpdigest
/// 内联测试的已知良好装配。
///
/// response = H(HA1:nonce:nc:cnonce:qop:HA2)，其中 HA2 = H(method:uri)。
#[cfg(feature = "protocol-httpdigest")]
#[allow(clippy::too_many_arguments)]
fn build_md5_digest_header(
    username: &str,
    realm: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    method: &str,
    uri: &str,
    ha1: &str,
) -> String {
    let ha2 = md5::compute(format!("{method}:{uri}").as_bytes());
    let ha2_hex: String = ha2.0.iter().map(|b| format!("{b:02x}")).collect();
    let response = md5::compute(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2_hex}").as_bytes());
    let response_hex: String = response.0.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
        username, realm, nonce, uri, response_hex, nc, cnonce
    )
}
