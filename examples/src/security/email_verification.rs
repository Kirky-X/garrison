//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邮箱验证码示例：演示 EmailVerificationService 的发送/验证/限速全链路。
//!
//! 对应模块：`src/secure/email/`（feature: email-verification）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin email_verification --features email-verification
//! ```

use async_trait::async_trait;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::secure::email::{EmailRateLimiter, EmailSender, EmailVerificationService};
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// NoopEmailSender：示例用邮件发送器（捕获发送内容，不实际投递）
// ============================================================================

/// 示例用邮件发送器，将发送内容存入内存列表供验证。
///
/// 生产环境中业务方可实现 `EmailSender` trait 接入 SMTP / HTTP 邮件网关，
/// 或直接启用 `email-verification-smtp` feature 使用框架内置 `SmtpEmailSender`。
struct NoopEmailSender {
    sent: Mutex<Vec<(String, String, String)>>,
}

#[async_trait]
impl EmailSender for NoopEmailSender {
    async fn send(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()> {
        self.sent
            .lock()
            .await
            .push((to.to_string(), subject.to_string(), body.to_string()));
        Ok(())
    }
}

/// 运行邮箱验证码示例。
///
/// 演示 send_code（发送）/ verify_code（验证正确码/错误码/超最大尝试）与
/// 邮箱规范化（大小写/空白归一）防绕过。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 邮箱验证码示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 EmailVerificationService
    // ----------------------------------------------------------------
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let sender = Arc::new(NoopEmailSender {
        sent: Mutex::new(Vec::new()),
    });
    let rate_limiter = EmailRateLimiter::new(dao.clone(), 5, 10);
    let service = EmailVerificationService::new(
        rate_limiter,
        sender.clone(),
        dao.clone(),
        3,   // max_verify_attempts: 最多 3 次错误尝试
        3,   // unverified_threshold: 连续 3 次未验证触发通道回收
        600, // code_ttl: 验证码 600 秒（10 分钟）有效
    );
    println!("[1] EmailVerificationService 构建完成");
    println!("    限速：5 次/小时、10 次/天");
    println!("    验证码 TTL：600 秒，最大验证尝试：3 次\n");

    // ----------------------------------------------------------------
    // 2. send_code 发送验证码
    // ----------------------------------------------------------------
    let email = "user@example.com";
    service.send_code(email).await?;
    println!("[2] send_code(\"{}\") → 验证码已发送", email);
    let sent = sender.sent.lock().await;
    assert_eq!(sent.len(), 1);
    println!("    收件人: {}", sent[0].0);
    println!("    主题: {}", sent[0].1);
    println!("    正文: {}", sent[0].2);
    // 提取验证码（从 DAO 中读取，仅供示例演示）
    let code = dao
        .get(&format!("email:code:{}", email))
        .await?
        .expect("验证码应存在于 DAO 中");
    drop(sent);
    println!("    （示例从 DAO 取出验证码: {}）\n", code);

    // ----------------------------------------------------------------
    // 3. verify_code 正确码 → 成功
    // ----------------------------------------------------------------
    service.verify_code(email, &code).await?;
    println!("[3] verify_code(\"{}\", \"{}\") → 验证成功 ✓", email, code);
    // 验证成功后验证码已从 DAO 删除
    let deleted = dao.get(&format!("email:code:{}", email)).await?;
    assert!(deleted.is_none());
    println!("    验证码已从 DAO 清除\n");

    // ----------------------------------------------------------------
    // 4. verify_code 错误码 → InvalidParam
    // ----------------------------------------------------------------
    service.send_code(email).await?;
    let wrong_code = "000000";
    let err = service.verify_code(email, wrong_code).await.unwrap_err();
    println!("[4] verify_code(\"{}\", \"{}\") → Err", email, wrong_code);
    assert!(matches!(err, GarrisonError::InvalidParam(_)));
    println!("    错误类型: InvalidParam（验证码错误）✓\n");

    // ----------------------------------------------------------------
    // 5. 超过最大验证尝试 → EmailVerifyMaxAttempts
    // ----------------------------------------------------------------
    // 再发一次新码，然后连续输错 3 次（已达 max_verify_attempts=3）
    service.send_code(email).await?;
    let code2 = dao
        .get(&format!("email:code:{}", email))
        .await?
        .expect("验证码应存在");
    println!("[5] 连续输错 3 次（max_verify_attempts=3）:");
    for i in 0..3 {
        let err = service.verify_code(email, "000000").await.unwrap_err();
        if i < 2 {
            assert!(matches!(err, GarrisonError::InvalidParam(_)));
            println!("    第 {} 次: InvalidParam（验证码错误）", i + 1);
        } else {
            // 第 3 次超过阈值 → EmailVerifyMaxAttempts
            assert!(matches!(err, GarrisonError::EmailVerifyMaxAttempts));
            println!(
                "    第 {} 次: EmailVerifyMaxAttempts（超限，验证码失效）✓",
                i + 1
            );
        }
    }
    // 验证码已被删除，即使知道正确码也无法验证
    let err = service.verify_code(email, &code2).await.unwrap_err();
    assert!(matches!(err, GarrisonError::EmailCodeNotFound));
    println!("    此后即使提供正确码 → EmailCodeNotFound ✓\n");

    // ----------------------------------------------------------------
    // 6. 邮箱规范化：大小写/空白归一防绕过
    // ----------------------------------------------------------------
    service.send_code("  User@Example.COM  ").await?;
    println!("[6] 邮箱规范化:");
    println!("    send_code(\"  User@Example.COM  \") 已规范化为 user@example.com");
    // 用不同大小写验证同样命中
    let code3 = dao
        .get("email:code:user@example.com")
        .await?
        .expect("验证码应存在");
    service.verify_code("USER@EXAMPLE.COM", &code3).await?;
    println!("    verify_code(\"USER@EXAMPLE.COM\", ...) → 成功（同一 key）✓\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
