//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SmsVerificationService / SmsRateLimiter / constant_time_eq 单元测试。

use super::service::constant_time_eq;
use super::*;
use crate::dao::tests::MockDao;
use crate::error::BulwarkError;
use std::sync::Arc;

/// 构造测试用 SmsVerificationService（默认配置）。
fn make_service() -> SmsVerificationService {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let rate_limiter = SmsRateLimiter::new(dao.clone(), 5, 10);
    let sender: Arc<dyn SmsSender> = Arc::new(NoopSmsSender);
    SmsVerificationService::new(rate_limiter, sender, dao, 3, 100)
}

/// 测试 1：小时限速 5/h 放行（前 5 次成功）。
#[tokio::test]
async fn hourly_limit_allows_first_5() {
    let service = make_service();
    for i in 0..5 {
        let result = service.send_code("13800138000").await;
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
        service.send_code("13800138001").await.unwrap();
    }
    let result = service.send_code("13800138001").await;
    assert!(
        matches!(result, Err(BulwarkError::SmsRateLimitExceeded { ref window }) if window == "hourly"),
        "第 6 次应被小时限速拦截，实际: {:?}",
        result
    );
}

/// 测试 3：天限速 10/d 拦截第 11 次。
///
/// 通过手动递增小时窗口计数器绕过小时限速，验证天窗口独立拦截。
#[tokio::test]
async fn daily_limit_blocks_11th() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let service = SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 100, 10),
        Arc::new(NoopSmsSender),
        dao.clone(),
        3,
        100,
    );
    for _ in 0..10 {
        service.send_code("13800138002").await.unwrap();
    }
    let result = service.send_code("13800138002").await;
    assert!(
        matches!(result, Err(BulwarkError::SmsRateLimitExceeded { ref window }) if window == "daily"),
        "第 11 次应被天限速拦截，实际: {:?}",
        result
    );
}

/// 测试 4：验证码验证 3 次后失效（第 4 次返回 SmsVerifyMaxAttempts）。
#[tokio::test]
async fn verify_max_attempts_after_3_failures() {
    let service = make_service();
    service.send_code("13800138003").await.unwrap();
    // 前 3 次错误验证返回 InvalidParam
    for _ in 0..3 {
        let r = service.verify_code("13800138003", "000000").await;
        assert!(
            matches!(r, Err(BulwarkError::InvalidParam(_))),
            "前 3 次错误应返回 InvalidParam"
        );
    }
    // 第 4 次应返回 SmsVerifyMaxAttempts
    let result = service.verify_code("13800138003", "000000").await;
    assert!(
        matches!(result, Err(BulwarkError::SmsVerifyMaxAttempts)),
        "第 4 次应返回 SmsVerifyMaxAttempts，实际: {:?}",
        result
    );
}

/// 测试 5：正确验证码验证通过（验证后验证码被删除）。
#[tokio::test]
async fn correct_code_verifies_and_deletes() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    // 用自定义 sender 捕获验证码
    struct CapturingSender {
        code: parking_lot::Mutex<Option<String>>,
    }
    #[async_trait]
    impl SmsSender for CapturingSender {
        async fn send(&self, _phone: &str, code: &str) -> BulwarkResult<()> {
            *self.code.lock() = Some(code.to_string());
            Ok(())
        }
    }
    let sender = Arc::new(CapturingSender {
        code: parking_lot::Mutex::new(None),
    });
    let service = SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 5, 10),
        sender.clone(),
        dao.clone(),
        3,
        3,
    );
    service.send_code("13800138004").await.unwrap();
    let code = sender.code.lock().as_ref().cloned().unwrap();
    // 验证通过
    let result = service.verify_code("13800138004", &code).await;
    assert!(result.is_ok(), "正确验证码应验证通过");
    // 验证码已被删除
    let stored = dao.get("sms:code:13800138004").await.unwrap();
    assert!(stored.is_none(), "验证后验证码应被删除");
}

/// 测试 6：错误验证码计数增加。
#[tokio::test]
async fn wrong_code_increments_attempts() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let service = SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 5, 10),
        Arc::new(NoopSmsSender),
        dao.clone(),
        3,
        3,
    );
    service.send_code("13800138005").await.unwrap();
    // 第一次错误
    service
        .verify_code("13800138005", "wrong")
        .await
        .unwrap_err();
    let attempts = dao.get("sms:attempts:13800138005").await.unwrap();
    assert_eq!(attempts, Some("1".to_string()));
    // 第二次错误
    service
        .verify_code("13800138005", "wrong")
        .await
        .unwrap_err();
    let attempts = dao.get("sms:attempts:13800138005").await.unwrap();
    assert_eq!(attempts, Some("2".to_string()));
}

/// 测试 7：验证码不存在返回 SmsCodeNotFound。
#[tokio::test]
async fn missing_code_returns_not_found() {
    let service = make_service();
    let result = service.verify_code("13800138006", "123456").await;
    assert!(
        matches!(result, Err(BulwarkError::SmsCodeNotFound)),
        "不存在的验证码应返回 SmsCodeNotFound，实际: {:?}",
        result
    );
}

/// 测试 8：限速 key 格式验证（sms:rate:{phone}:hour:{bucket}）。
#[tokio::test]
async fn rate_key_format_hour() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let service = SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 5, 10),
        Arc::new(NoopSmsSender),
        dao.clone(),
        3,
        3,
    );
    service.send_code("13800138007").await.unwrap();
    // 验证 key 存在
    let keys = dao.keys("sms:rate:13800138007:hour:*").await.unwrap();
    assert!(
        !keys.is_empty(),
        "应存在 sms:rate:{{phone}}:hour:{{bucket}} 格式的 key"
    );
}

/// 测试 9：验证码 key 格式验证（sms:code:{phone}）。
#[tokio::test]
async fn code_key_format() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let service = SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 5, 10),
        Arc::new(NoopSmsSender),
        dao.clone(),
        3,
        3,
    );
    service.send_code("13800138008").await.unwrap();
    let stored = dao.get("sms:code:13800138008").await.unwrap();
    assert!(stored.is_some(), "应存在 sms:code:{{phone}} 格式的 key");
}

/// 测试 10：并发发送不超限（用 MockDao 的原子 incr 保证）。
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_send_does_not_exceed_limit() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let service = Arc::new(SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 5, 10),
        Arc::new(NoopSmsSender),
        dao.clone(),
        3,
        100,
    ));
    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = service.clone();
        handles.push(tokio::spawn(
            async move { s.send_code("13800138009").await },
        ));
    }
    let mut success = 0;
    let mut rate_limited = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => success += 1,
            Err(BulwarkError::SmsRateLimitExceeded { .. }) => rate_limited += 1,
            Err(e) => panic!("不应返回其他错误: {:?}", e),
        }
    }
    assert_eq!(success, 5, "仅 5 次发送应成功（小时限速 5/h）");
    assert_eq!(rate_limited, 5, "其余 5 次应被限速");
}

/// 测试 11：SmsSender mock（NoopSmsSender 不报错）。
#[tokio::test]
async fn noop_sms_sender_does_not_error() {
    let sender = NoopSmsSender;
    let result = sender.send("13800138010", "123456").await;
    assert!(result.is_ok(), "NoopSmsSender 不应报错");
}

/// 测试 12：异常发送检测（连续未验证 3 次后回收通道）。
#[tokio::test]
async fn unverified_threshold_recycles_channel() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    // unverified_threshold = 3：第 4 次未验证发送应触发回收
    let service = SmsVerificationService::new(
        SmsRateLimiter::new(dao.clone(), 100, 100),
        Arc::new(NoopSmsSender),
        dao.clone(),
        3,
        3,
    );
    // 前 3 次发送成功（unverified 计数 1, 2, 3）
    for i in 0..3 {
        let r = service.send_code("13800138011").await;
        assert!(r.is_ok(), "第 {} 次发送应成功", i + 1);
    }
    // 第 4 次发送应触发通道回收
    let result = service.send_code("13800138011").await;
    assert!(
        matches!(result, Err(BulwarkError::SmsChannelRecycled)),
        "第 4 次发送应触发 SmsChannelRecycled，实际: {:?}",
        result
    );
    // 通道已回收，后续发送直接被拒
    let result = service.send_code("13800138011").await;
    assert!(
        matches!(result, Err(BulwarkError::SmsChannelRecycled)),
        "通道回收后应继续返回 SmsChannelRecycled"
    );
}

// ============================================================================
// 常量时间比较测试（时序攻击防护）
// ============================================================================

/// 验证 constant_time_eq 对相同字符串返回 true。
#[test]
fn constant_time_eq_same_string_returns_true() {
    assert!(constant_time_eq("123456", "123456"));
    assert!(constant_time_eq("", ""));
    assert!(constant_time_eq("abcdef", "abcdef"));
}

/// 验证 constant_time_eq 对不同字符串返回 false。
#[test]
fn constant_time_eq_different_string_returns_false() {
    assert!(!constant_time_eq("123456", "000000"));
    assert!(!constant_time_eq("123456", "123457"));
    assert!(!constant_time_eq("abcdef", "abcdeF"));
}

/// 验证 constant_time_eq 对不同长度字符串返回 false。
#[test]
fn constant_time_eq_different_length_returns_false() {
    assert!(!constant_time_eq("12345", "123456"));
    assert!(!constant_time_eq("1234567", "123456"));
    assert!(!constant_time_eq("", "123456"));
}

/// 验证 constant_time_eq 对仅首位不同的字符串返回 false（覆盖首字节差异）。
#[test]
fn constant_time_eq_first_byte_diff_returns_false() {
    assert!(!constant_time_eq("023456", "123456"));
}

/// 验证 constant_time_eq 对仅末位不同的字符串返回 false（覆盖末字节差异）。
#[test]
fn constant_time_eq_last_byte_diff_returns_false() {
    assert!(!constant_time_eq("123450", "123456"));
}

// ============================================================================
// 验证码生成范围测试（21a6/vuln-0009：排除 000000）
// ============================================================================

/// 验证 generate_code 返回 6 位字符串。
#[test]
fn generate_code_returns_6_char_string() {
    let code = super::service::generate_code().expect("生成验证码不应失败");
    assert_eq!(code.len(), 6, "验证码必须是 6 位字符: {}", code);
}

/// 验证 generate_code 永不返回 "000000"（弱验证码）。
///
/// 生成 10000 次，断言无 "000000" 且所有结果均为 6 位数字字符。
/// 旧实现 `gen_range(0..1000000)` 有 1/1000000 概率生成 0，
/// 虽然单次概率低，但在高频发送场景下累积风险不可忽视。
#[test]
fn generate_code_never_returns_000000() {
    for _ in 0..10000 {
        let code = super::service::generate_code().expect("生成验证码不应失败");
        assert_ne!(code, "000000", "验证码不应为 000000（弱验证码）");
        assert_eq!(code.len(), 6, "验证码必须是 6 位字符: {}", code);
    }
}

/// 验证 generate_code 所有结果均为 [100000, 999999] 范围内的 6 位数字。
///
/// 此测试在旧实现（`gen_range(0..1000000)`）下会失败：
/// 旧实现 ~10% 概率生成 < 100000 的值（格式化后首位为 '0'），
/// 10000 次迭代中全部 >= 100000 的概率约为 0.9^10000 ≈ 0（必然失败）。
#[test]
fn generate_code_always_in_6_digit_range() {
    for _ in 0..10000 {
        let code = super::service::generate_code().expect("生成验证码不应失败");
        let parsed: u32 = code
            .parse()
            .unwrap_or_else(|_| panic!("验证码必须是纯数字: {}", code));
        assert!(
            (100000..1000000).contains(&parsed),
            "验证码必须在 [100000, 999999] 范围内: {}",
            code
        );
        // 首位字符不应为 '0'（与 000000 弱验证码防护一致）
        assert_ne!(
            code.chars().next().unwrap(),
            '0',
            "验证码首位不应为 0: {}",
            code
        );
    }
}
