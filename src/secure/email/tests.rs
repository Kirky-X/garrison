//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邮箱验证码模块单元测试。

use super::rate_limiter::{normalize_email, validate_email};
use super::service::{constant_time_eq, generate_code};
use super::*;
use crate::dao::tests::MockDao;
use crate::error::GarrisonError;
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================
// normalize_email 测试
// ============================================================

#[test]
fn normalize_email_trims_and_lowercases() {
    assert_eq!(normalize_email(" Foo@Example.COM "), "foo@example.com");
    assert_eq!(normalize_email("USER@DOMAIN.ORG"), "user@domain.org");
    assert_eq!(normalize_email("  a@b.c  "), "a@b.c");
}

#[test]
fn normalize_email_empty_string() {
    assert_eq!(normalize_email(""), "");
    assert_eq!(normalize_email("   "), "");
}

// ============================================================
// validate_email 测试
// ============================================================

#[test]
fn validate_email_valid() {
    assert!(validate_email("user@example.com").is_ok());
    assert!(validate_email("a@b.c").is_ok());
    assert!(validate_email("test+tag@domain.org").is_ok());
}

#[test]
fn validate_email_empty_rejected() {
    let err = validate_email("").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-empty"))
    );
}

#[test]
fn validate_email_colon_rejected() {
    let err = validate_email("a:b@c.com").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-no-colon"))
    );
}

#[test]
fn validate_email_control_char_rejected() {
    let err = validate_email("user\x00@example.com").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-no-control-char"))
    );
}

#[test]
fn validate_email_too_long_rejected() {
    let long = format!("{}@b.com", "a".repeat(250));
    let err = validate_email(&long).unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-invalid-format"))
    );
}

#[test]
fn validate_email_no_at_rejected() {
    let err = validate_email("userexample.com").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-invalid-format"))
    );
}

// ============================================================
// generate_code 测试
// ============================================================

#[test]
fn generate_code_returns_six_digits() {
    for _ in 0..100 {
        let code = generate_code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(code, "000000");
        // 范围 100000..1000000
        let num: u32 = code.parse().unwrap();
        assert!(num >= 100000 && num < 1000000);
    }
}

// ============================================================
// constant_time_eq 测试
// ============================================================

#[test]
fn constant_time_eq_equal_strings() {
    assert!(constant_time_eq("123456", "123456"));
}

#[test]
fn constant_time_eq_different_strings() {
    assert!(!constant_time_eq("123456", "654321"));
    assert!(!constant_time_eq("123456", "123457"));
}

#[test]
fn constant_time_eq_different_lengths() {
    assert!(!constant_time_eq("123456", "12345"));
    assert!(!constant_time_eq("12", "123456"));
}

// ============================================================
// SmtpConfig 测试（仅 email-verification-smtp feature）
// ============================================================

#[cfg(feature = "email-verification-smtp")]
#[test]
fn smtp_config_defaults() {
    let config = super::smtp::SmtpConfig::default();
    assert_eq!(config.port, 587);
    assert_eq!(config.from_name, "Garrison");
    assert!(config.use_tls);
    assert!(config.host.is_empty());
    assert!(config.username.is_empty());
}

// ============================================================================
// EmailVerificationService 服务级行为测试（对齐 sms/tests.rs 模式）
// ============================================================================

/// 仅记录不实际发送的 Noop 实现（测试用）。
struct NoopEmailSender;

#[async_trait]
impl EmailSender for NoopEmailSender {
    async fn send(&self, _to: &str, _subject: &str, _body: &str) -> GarrisonResult<()> {
        Ok(())
    }
}

/// 捕获最近一次邮件（to, subject, body）的测试实现。
struct CapturingEmailSender {
    mail: parking_lot::Mutex<Option<(String, String, String)>>,
}

#[async_trait]
impl EmailSender for CapturingEmailSender {
    async fn send(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()> {
        *self.mail.lock() = Some((to.to_string(), subject.to_string(), body.to_string()));
        Ok(())
    }
}

/// 始终发送失败的测试实现（模拟 SMTP 网关不可达）。
struct FailingEmailSender;

#[async_trait]
impl EmailSender for FailingEmailSender {
    async fn send(&self, _to: &str, _subject: &str, _body: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Network(
            "email-smtp-send-failed::mock-network-down".to_string(),
        ))
    }
}

/// 构造测试用 EmailVerificationService（默认配置：5/h、10/d、3 次尝试、阈值 100、TTL 600s）。
fn make_service() -> EmailVerificationService {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    make_service_with(dao, 3, 100)
}

/// 以自定义 DAO 与阈值构造服务（限速 5/h、10/d，TTL 600s）。
fn make_service_with(
    dao: Arc<dyn GarrisonDao>,
    max_attempts: u32,
    unverified_threshold: u32,
) -> EmailVerificationService {
    let rate_limiter = EmailRateLimiter::new(dao.clone(), 5, 10);
    EmailVerificationService::new(
        rate_limiter,
        Arc::new(NoopEmailSender),
        dao,
        max_attempts,
        unverified_threshold,
        600,
    )
}

/// 测试 1：小时限速 5/h 放行（前 5 次成功）。
#[tokio::test]
async fn hourly_limit_allows_first_5() {
    let service = make_service();
    for i in 0..5 {
        let result = service.send_code("user@example.com").await;
        assert!(
            result.is_ok(),
            "第 {} 次发送应成功，实际: {:?}",
            i + 1,
            result
        );
    }
}

/// 测试 2：小时限速 5/h 拦截第 6 次。
#[tokio::test]
async fn hourly_limit_blocks_6th() {
    let service = make_service();
    for _ in 0..5 {
        service.send_code("user1@example.com").await.unwrap();
    }
    let result = service.send_code("user1@example.com").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailRateLimitExceeded { ref window }) if window == "hourly"),
        "第 6 次应被小时限速拦截，实际: {:?}",
        result
    );
}

/// 测试 3：天限速 10/d 拦截第 11 次（小时窗口调大以隔离验证天窗口）。
#[tokio::test]
async fn daily_limit_blocks_11th() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let service = EmailVerificationService::new(
        EmailRateLimiter::new(dao.clone(), 100, 10),
        Arc::new(NoopEmailSender),
        dao.clone(),
        3,
        100,
        600,
    );
    for _ in 0..10 {
        service.send_code("user2@example.com").await.unwrap();
    }
    let result = service.send_code("user2@example.com").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailRateLimitExceeded { ref window }) if window == "daily"),
        "第 11 次应被天限速拦截，实际: {:?}",
        result
    );
}

/// 测试 4：验证码验证失败 3 次后失效（第 4 次返回 EmailVerifyMaxAttempts）。
#[tokio::test]
async fn verify_max_attempts_after_3_failures() {
    let service = make_service_with(Arc::new(MockDao::new()), 3, 100);
    service.send_code("user3@example.com").await.unwrap();
    for _ in 0..3 {
        let r = service.verify_code("user3@example.com", "000000").await;
        assert!(
            matches!(r, Err(GarrisonError::InvalidParam(_))),
            "前 3 次错误应返回 InvalidParam"
        );
    }
    let result = service.verify_code("user3@example.com", "000000").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailVerifyMaxAttempts)),
        "第 4 次应返回 EmailVerifyMaxAttempts，实际: {:?}",
        result
    );
}

/// 测试 5：正确验证码验证通过后清除 code/unverified/attempts 全部状态；
/// 同时断言邮件收件人为规范化地址、本地化正文包含验证码（文案透传）。
#[tokio::test]
async fn correct_code_verifies_and_clears_state() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let sender = Arc::new(CapturingEmailSender {
        mail: parking_lot::Mutex::new(None),
    });
    let service = EmailVerificationService::new(
        EmailRateLimiter::new(dao.clone(), 5, 10),
        sender.clone(),
        dao.clone(),
        3,
        3,
        600,
    );
    service.send_code("User@Example.COM").await.unwrap();
    let (to, subject, body) = sender.mail.lock().clone().unwrap();
    assert_eq!(to, "user@example.com", "收件人应为规范化（小写）地址");
    assert!(!subject.is_empty(), "邮件主题不应为空");
    let code = dao
        .get("email:code:user@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(body.contains(&code), "邮件正文应包含验证码 {}", code);

    let result = service.verify_code("user@example.com", &code).await;
    assert!(result.is_ok(), "正确验证码应验证通过");
    assert!(
        dao.get("email:code:user@example.com")
            .await
            .unwrap()
            .is_none(),
        "验证后验证码应被删除"
    );
    assert!(
        dao.get("email:unverified:user@example.com")
            .await
            .unwrap()
            .is_none(),
        "验证后未验证计数应被清零"
    );
    assert!(
        dao.get("email:attempts:user@example.com")
            .await
            .unwrap()
            .is_none(),
        "验证后尝试计数应被清零"
    );
}

/// 测试 6：错误验证码递增尝试计数。
#[tokio::test]
async fn wrong_code_increments_attempts() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let service = make_service_with(dao.clone(), 3, 3);
    service.send_code("user4@example.com").await.unwrap();
    service
        .verify_code("user4@example.com", "wrong1")
        .await
        .unwrap_err();
    let attempts = dao.get("email:attempts:user4@example.com").await.unwrap();
    assert_eq!(attempts, Some("1".to_string()));
    service
        .verify_code("user4@example.com", "wrong2")
        .await
        .unwrap_err();
    let attempts = dao.get("email:attempts:user4@example.com").await.unwrap();
    assert_eq!(attempts, Some("2".to_string()));
}

/// 测试 7：验证码不存在返回 EmailCodeNotFound。
#[tokio::test]
async fn missing_code_returns_not_found() {
    let service = make_service();
    let result = service.verify_code("user5@example.com", "123456").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailCodeNotFound)),
        "不存在的验证码应返回 EmailCodeNotFound，实际: {:?}",
        result
    );
}

/// 测试 8：限速 key 格式验证（email:rate:{addr}:hour:{bucket}）。
#[tokio::test]
async fn rate_key_format_hour() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let service = make_service_with(dao.clone(), 3, 3);
    service.send_code("user6@example.com").await.unwrap();
    let keys = dao
        .keys("email:rate:user6@example.com:hour:*")
        .await
        .unwrap();
    assert!(
        !keys.is_empty(),
        "应存在 email:rate:{{addr}}:hour:{{bucket}} 格式的 key"
    );
}

/// 测试 9：验证码 key 使用规范化地址（email:code:{addr}）。
#[tokio::test]
async fn code_key_format_is_normalized() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let service = make_service_with(dao.clone(), 3, 3);
    service.send_code("User7@Example.COM").await.unwrap();
    let stored = dao.get("email:code:user7@example.com").await.unwrap();
    assert!(stored.is_some(), "应存在小写规范化 email:code:{{addr}} key");
}

/// 测试 10：并发发送不超限（MockDao 原子 incr 保证）。
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_send_does_not_exceed_limit() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let rate_limiter = EmailRateLimiter::new(dao.clone(), 5, 10);
    let service = Arc::new(EmailVerificationService::new(
        rate_limiter,
        Arc::new(NoopEmailSender),
        dao.clone(),
        3,
        100,
        600,
    ));
    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = service.clone();
        handles.push(tokio::spawn(async move {
            s.send_code("user8@example.com").await
        }));
    }
    let mut success = 0;
    let mut rate_limited = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => success += 1,
            Err(GarrisonError::EmailRateLimitExceeded { .. }) => rate_limited += 1,
            Err(e) => panic!("不应返回其他错误: {:?}", e),
        }
    }
    assert_eq!(success, 5, "仅 5 次发送应成功（小时限速 5/h）");
    assert_eq!(rate_limited, 5, "其余 5 次应被限速");
}

/// 测试 11：异常发送检测（连续未验证超过阈值后回收通道）。
#[tokio::test]
async fn unverified_threshold_recycles_channel() {
    let service = make_service_with(Arc::new(MockDao::new()), 3, 3);
    for i in 0..3 {
        let r = service.send_code("user9@example.com").await;
        assert!(r.is_ok(), "第 {} 次发送应成功", i + 1);
    }
    let result = service.send_code("user9@example.com").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailChannelRecycled)),
        "第 4 次发送应触发 EmailChannelRecycled，实际: {:?}",
        result
    );
    let result = service.send_code("user9@example.com").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailChannelRecycled)),
        "通道回收后应继续返回 EmailChannelRecycled"
    );
}

/// 测试 12（email 特有）：发送失败应回滚全部状态——
/// 验证码删除、限速计数回退、未验证计数回退，错误原样透传。
#[tokio::test]
async fn send_failure_rolls_back_all_state() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let service = EmailVerificationService::new(
        EmailRateLimiter::new(dao.clone(), 5, 10),
        Arc::new(FailingEmailSender),
        dao.clone(),
        3,
        100,
        600,
    );
    let result = service.send_code("user10@example.com").await;
    assert!(
        matches!(&result, Err(GarrisonError::Network(msg)) if msg.contains("email-smtp-send-failed")),
        "发送失败应透传 Network 错误，实际: {:?}",
        result
    );
    assert!(
        dao.get("email:code:user10@example.com")
            .await
            .unwrap()
            .is_none(),
        "发送失败后验证码应被删除"
    );
    let hour_keys = dao
        .keys("email:rate:user10@example.com:hour:*")
        .await
        .unwrap();
    assert!(hour_keys.is_empty(), "发送失败后小时限速计数应回滚删除");
    assert!(
        dao.get("email:unverified:user10@example.com")
            .await
            .unwrap()
            .is_none(),
        "发送失败后未验证计数应回滚删除"
    );
}

/// 测试 13（email 特有）：大小写变体共享同一限速预算与验证码。
#[tokio::test]
async fn case_variants_share_rate_budget() {
    let service = make_service();
    let variants = [
        "User@Example.COM",
        "USER@example.com",
        "user@example.com",
        "User@example.com",
        "USER@EXAMPLE.COM",
    ];
    for (i, v) in variants.iter().enumerate() {
        let r = service.send_code(v).await;
        assert!(r.is_ok(), "变体 {} 第 {} 次发送应成功: {:?}", v, i + 1, r);
    }
    // 第 6 个变体（同一规范化地址）应被小时限速拦截
    let result = service.send_code("user@Example.com").await;
    assert!(
        matches!(result, Err(GarrisonError::EmailRateLimitExceeded { ref window }) if window == "hourly"),
        "大小写变体应共享限速预算：第 6 次应被拦截，实际: {:?}",
        result
    );
}

/// 测试 14：邮箱长度边界——254 放行、255 拒绝（RFC 5321 上限）。
#[test]
fn validate_email_boundary_254() {
    let ok = format!("{}@b.com", "a".repeat(248));
    assert_eq!(ok.len(), 254);
    assert!(validate_email(&ok).is_ok(), "恰好 254 字符应放行");
    let too_long = format!("{}@b.com", "a".repeat(249));
    assert_eq!(too_long.len(), 255);
    assert!(validate_email(&too_long).is_err(), "255 字符应拒绝");
}

/// 测试 15：回滚入口对非法邮箱前置校验（key 注入防护）。
#[tokio::test]
async fn rollback_invalid_email_returns_invalid_param() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let limiter = EmailRateLimiter::new(dao, 100, 100);
    let result = limiter.rollback("a:b@c.com").await;
    assert!(
        matches!(&result, Err(GarrisonError::InvalidParam(msg)) if msg.starts_with("secure-email-no-colon")),
        "回滚含冒号邮箱应返回 InvalidParam（secure-email-no-colon），实际: {:?}",
        result
    );
}

/// 测试 16：限速入口对规范化后为空的邮箱前置校验。
#[tokio::test]
async fn check_and_increment_rejects_blank_email() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let limiter = EmailRateLimiter::new(dao, 100, 100);
    let result = limiter.check_and_increment("   ").await;
    assert!(
        matches!(&result, Err(GarrisonError::InvalidParam(msg)) if msg.starts_with("secure-email-empty")),
        "空白邮箱应返回 InvalidParam（secure-email-empty），实际: {:?}",
        result
    );
}
