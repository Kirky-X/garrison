//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! 数学验证码提供商（基础 CAPTCHA 实现）。
//!
//! [`MathCaptchaProvider`](crate::strategy::firewall::captcha_provider::MathCaptchaProvider) 生成 `"a ± b = ?"` 形式的数学挑战题，
//! 将答案存入 DAO（key = `captcha:math:{challenge_id}`），验证后一次性删除防止复用。
//!
//! # 算法
//!
//! 1. 随机生成两个 1-20 的整数 `a` 和 `b`（用 `rand::rng()`，ChaCha12 CSPRNG）。
//! 2. 随机选择运算符 `+` 或 `-`；若选 `-` 但 `a < b`（结果为负），回退到 `+` 确保结果非负。
//! 3. 生成 `challenge_id = UUID v4`，计算答案，存入 DAO（TTL = `self.ttl`）。
//! 4. 返回 `(challenge_id, "a op b = ?")`。
//!
//! # 一次性使用 + 暴力破解防护
//!
//! - `verify` 用 `dao.get_and_delete`（GETDEL 原子语义，与 SSO ticket 防回放同款）
//!   取出答案，并发同 challenge_id 的 verify 仅有一个能取到值，
//!   消除 get→compare→delete 的 TOCTOU（一次性语义并发下不再被双通过）。
//! - `verify` 匹配成功后 challenge 已被原子删除，防止同一 challenge_id 被复用。
//! - `verify` 匹配失败时用 `dao.incr` 原子递增尝试计数器
//!   （key = `captcha:attempts:{challenge_id}`，消除 get→add→set 读改写竞态），
//!   超过 `max_attempts`（默认 5）后废弃 challenge（不再回写），防止暴力穷举；
//!   未超限则回写 challenge 允许重试。
//! - 不匹配或 key 不存在返回 `Ok(false)`，不报错。
//!
//! # 与 [`CaptchaChallenge`](crate::strategy::firewall::CaptchaChallenge) trait 的区分
//!
//! `CaptchaChallenge` 绑定 `FirewallContext`（按 IP/login_id 定位期望答案），
//! `MathCaptchaProvider` 用 challenge_id 定位，不依赖上下文，是独立的验证码生成/验证组件。

use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use rand::RngExt;
use std::sync::Arc;
use uuid::Uuid;

/// 默认 TTL（秒），challenge 答案在 DAO 中的存活时间。
const DEFAULT_TTL: u64 = 300;

/// 默认最大验证尝试次数，超过后 challenge 自动废弃。
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// 数学验证码提供商，生成 `"a ± b = ?"` 形式的挑战题。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::dao::GarrisonDao;
/// use garrison::strategy::firewall::captcha_provider::MathCaptchaProvider;
///
/// let dao: Arc<dyn GarrisonDao> = /* oxcache 实现 */;
/// let provider = MathCaptchaProvider::new(dao);          // TTL=300s, max_attempts=5
/// let provider = MathCaptchaProvider::with_ttl(dao, 600); // TTL=600s
/// let provider = MathCaptchaProvider::with_max_attempts(dao, 3); // max_attempts=3
/// ```
pub struct MathCaptchaProvider {
    /// DAO（用于存储 challenge 答案）。
    dao: Arc<dyn GarrisonDao>,
    /// 答案在 DAO 中的存活时间（秒）。
    ttl: u64,
    /// 最大验证尝试次数，超过后 challenge 自动废弃（防暴力穷举）。
    max_attempts: u32,
}

impl MathCaptchaProvider {
    /// 创建数学验证码提供商，TTL 默认 300 秒，最大尝试次数 5。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            dao,
            ttl: DEFAULT_TTL,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// 创建数学验证码提供商，自定义 TTL。
    pub fn with_ttl(dao: Arc<dyn GarrisonDao>, ttl: u64) -> Self {
        Self {
            dao,
            ttl,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// 创建数学验证码提供商，自定义最大验证尝试次数。
    pub fn with_max_attempts(dao: Arc<dyn GarrisonDao>, max_attempts: u32) -> Self {
        Self {
            dao,
            ttl: DEFAULT_TTL,
            max_attempts,
        }
    }

    /// 生成一道数学挑战题，返回 `(challenge_id, 题目字符串)`。
    ///
    /// 题目格式为 `"a op b = ?"`（如 `"3 + 5 = ?"`），答案存入 DAO 供 [`verify`](Self::verify) 比对。
    pub async fn generate(&self) -> GarrisonResult<(String, String)> {
        let mut rng = rand::rng();
        let a: i32 = rng.random_range(1..=20);
        let b: i32 = rng.random_range(1..=20);
        // 随机选 + 或 -；选 - 但 a < b 时回退到 + 确保结果非负
        let (op, answer) = if rng.random_bool(0.5) || a < b {
            ('+', a + b)
        } else {
            ('-', a - b)
        };
        let challenge_id = Uuid::new_v4().to_string();
        let key = format!("{}math:{}", DaoKeyPrefix::Captcha, challenge_id);
        self.dao.set(&key, &answer.to_string(), self.ttl).await?;
        let question = format!("{} {} {} = ?", a, op, b);
        Ok((challenge_id, question))
    }

    /// 验证用户提交的答案。
    ///
    /// - 用 `dao.get_and_delete`（GETDEL 原子）取出存储答案：并发同 challenge_id
    ///   的 verify 仅有一个取到值，保证一次性使用语义（消除 get→delete TOCTOU）。
    /// - 匹配则 challenge 已删除（一次性使用，防止复用）。
    /// - 不匹配时用 `dao.incr` 原子递增尝试计数器（消除 get→add→set 竞态），
    ///   超过 `max_attempts` 后废弃 challenge（防暴力穷举）；
    ///   未超限则回写 challenge（TTL 重置），允许继续重试。
    /// - challenge_id 不存在（已被消费/过期）返回 `Ok(false)`。
    ///
    /// # 并发说明
    ///
    /// GETDEL 先删、错误答案未超限时后回写，两者之间存在短暂窗口：
    /// 并发请求在该窗口内会取到 `None` 返回 `Ok(false)`（安全方向失败），
    /// 不会出现双通过。
    pub async fn verify(&self, challenge_id: &str, answer: &str) -> GarrisonResult<bool> {
        let key = format!("{}math:{}", DaoKeyPrefix::Captcha, challenge_id);
        // 原子 GETDEL：取值同时删除，消除 get→compare→delete 的 TOCTOU
        // （并发同 challenge_id 仅一个调用取到答案，一次性保证不被并发绕过）
        let stored = self.dao.get_and_delete(&key).await?;
        let stored = match stored {
            Some(s) => s,
            None => return Ok(false),
        };

        let attempts_key = format!("{}attempts:{}", DaoKeyPrefix::Captcha, challenge_id);

        if stored.trim() == answer.trim() {
            // 匹配：challenge 已被 GETDEL 原子删除；清理尝试计数器（非致命）
            let _ = self.dao.delete(&attempts_key).await.map_err(|e| {
                tracing::warn!(
                    challenge_id,
                    error = %e,
                    "CAPTCHA attempts key delete failed (non-fatal, TTL will clean it up)"
                );
            });
            return Ok(true);
        }

        // 错误答案：dao.incr 原子递增尝试计数器
        // （替代 get→parse→add→set 读改写，并发下不会少记、可超 max_attempts）
        let new_count = self.dao.incr(&attempts_key, self.ttl).await?;

        if new_count >= self.max_attempts as u64 {
            // 超限：challenge 已被 GETDEL 删除，不再回写（废弃）；清理计数器
            let _ = self.dao.delete(&attempts_key).await.map_err(|e| {
                tracing::warn!(
                    challenge_id,
                    error = %e,
                    "CAPTCHA attempts key delete failed (non-fatal, TTL will clean it up)"
                );
            });
            tracing::warn!(
                challenge_id,
                attempts = new_count,
                max = self.max_attempts,
                "CAPTCHA challenge discarded due to exceeding max attempts"
            );
            return Ok(false);
        }

        // 未超限：回写 challenge 允许重试（TTL 重置为 self.ttl）。
        // 回写与 GETDEL 之间的窗口内并发请求取到 None → 安全方向失败。
        self.dao.set(&key, &stored, self.ttl).await?;

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    /// generate 返回非空 challenge_id 和非空题目。
    #[tokio::test]
    async fn generate_returns_nonempty_id_and_question() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, question) = provider.generate().await.expect("generate 不应报错");
        assert!(!id.is_empty(), "challenge_id 不应为空");
        assert!(!question.is_empty(), "题目不应为空");
    }

    /// generate + verify 正确答案通过。
    #[tokio::test]
    async fn verify_correct_answer_passes() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, question) = provider.generate().await.expect("generate 不应报错");

        // 从题目解析出正确答案
        let parts: Vec<&str> = question.split(' ').collect();
        assert_eq!(parts.len(), 5, "题目应为 'a op b = ?' 格式");
        let a: i32 = parts[0].parse().expect("a 应为整数");
        let b: i32 = parts[2].parse().expect("b 应为整数");
        let expected = match parts[1] {
            "+" => a + b,
            "-" => a - b,
            other => panic!("未知运算符: {}", other),
        };

        let ok = provider
            .verify(&id, &expected.to_string())
            .await
            .expect("verify 不应报错");
        assert!(ok, "正确答案应通过验证");
    }

    /// generate + verify 错误答案返回 false。
    #[tokio::test]
    async fn verify_incorrect_answer_returns_false() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, _question) = provider.generate().await.expect("generate 不应报错");

        // 999 不可能是 1-20 范围运算的结果
        let ok = provider.verify(&id, "999").await.expect("verify 不应报错");
        assert!(!ok, "错误答案应返回 false");
    }

    /// verify 不存在的 challenge_id 返回 false。
    #[tokio::test]
    async fn verify_nonexistent_id_returns_false() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);

        let ok = provider
            .verify("nonexistent-id", "42")
            .await
            .expect("verify 不应报错");
        assert!(!ok, "不存在的 challenge_id 应返回 false");
    }

    /// 验证通过后再次 verify 返回 false（一次性使用）。
    #[tokio::test]
    async fn verify_is_one_time_use() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, question) = provider.generate().await.expect("generate 不应报错");

        // 解析正确答案
        let parts: Vec<&str> = question.split(' ').collect();
        let a: i32 = parts[0].parse().unwrap();
        let b: i32 = parts[2].parse().unwrap();
        let expected = if parts[1] == "+" { a + b } else { a - b };

        // 第一次正确答案通过
        let first = provider
            .verify(&id, &expected.to_string())
            .await
            .expect("首次 verify 不应报错");
        assert!(first, "首次正确答案应通过");

        // 第二次同一答案应失败（key 已被删除）
        let second = provider
            .verify(&id, &expected.to_string())
            .await
            .expect("二次 verify 不应报错");
        assert!(
            !second,
            "验证通过后应一次性删除，二次 verify 同一答案应返回 false"
        );
    }

    /// generate 生成的题目格式正确（含运算符和 "= ?"）。
    #[tokio::test]
    async fn generate_produces_well_formed_question() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);

        // 多次生成验证格式稳定性（随机性不应破坏格式）
        for _ in 0..20 {
            let (_id, question) = provider.generate().await.expect("generate 不应报错");
            let parts: Vec<&str> = question.split(' ').collect();
            assert_eq!(
                parts.len(),
                5,
                "题目应为 5 段 'a op b = ?'，实际: {:?}",
                question
            );
            // 第 2 段是运算符
            assert!(
                parts[1] == "+" || parts[1] == "-",
                "运算符应为 + 或 -，实际: {:?}",
                parts[1]
            );
            // 第 4 段是 "="，第 5 段是 "?"
            assert_eq!(parts[3], "=", "第 4 段应为 =，实际: {:?}", parts[3]);
            assert_eq!(parts[4], "?", "第 5 段应为 ?，实际: {:?}", parts[4]);
            // a 和 b 应在 1-20 范围内
            let a: i32 = parts[0].parse().expect("a 应为整数");
            let b: i32 = parts[2].parse().expect("b 应为整数");
            assert!((1..=20).contains(&a), "a 应在 1-20，实际: {}", a);
            assert!((1..=20).contains(&b), "b 应在 1-20，实际: {}", b);
            // 减法时结果应非负
            if parts[1] == "-" {
                assert!(a >= b, "减法时 a >= b 确保非负，实际: {} - {}", a, b);
            }
        }
    }

    /// with_ttl 允许自定义 TTL。
    #[tokio::test]
    async fn with_ttl_sets_custom_ttl() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::with_ttl(dao, 1);
        let (id, _question) = provider.generate().await.expect("generate 不应报错");

        // TTL=1s，等待 2s 后应过期
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // 解析答案后 verify（key 已过期，应返回 false）
        let ok = provider.verify(&id, "0").await.expect("verify 不应报错");
        assert!(!ok, "TTL 过期后 verify 应返回 false");
    }

    /// verify 对答案做 trim（容忍前后空白）。
    #[tokio::test]
    async fn verify_trims_whitespace() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, question) = provider.generate().await.expect("generate 不应报错");

        let parts: Vec<&str> = question.split(' ').collect();
        let a: i32 = parts[0].parse().unwrap();
        let b: i32 = parts[2].parse().unwrap();
        let expected = if parts[1] == "+" { a + b } else { a - b };

        // 带空白的答案也应通过
        let ok = provider
            .verify(&id, &format!("  {}  ", expected))
            .await
            .expect("verify 不应报错");
        assert!(ok, "带前后空白的答案应通过（trim）");
    }

    /// 超过最大尝试次数后 challenge 自动废弃（防暴力穷举）。
    #[tokio::test]
    async fn verify_invalidates_after_max_attempts() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::with_max_attempts(dao, 3);
        let (id, _question) = provider.generate().await.expect("generate 不应报错");

        // 3 次错误答案（第 3 次触发废弃）
        for _ in 0..3 {
            let ok = provider.verify(&id, "999").await.expect("verify 不应报错");
            assert!(!ok, "错误答案应返回 false");
        }

        // 第 4 次即使正确答案也返回 false（challenge 已被删除）
        let ok = provider.verify(&id, "0").await.expect("verify 不应报错");
        assert!(!ok, "超过最大尝试次数后 challenge 应已失效");
    }

    /// 默认最大尝试次数为 5。
    #[tokio::test]
    async fn default_max_attempts_is_5() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, _question) = provider.generate().await.expect("generate 不应报错");

        // 5 次错误答案触发废弃
        for _ in 0..5 {
            let ok = provider.verify(&id, "999").await.expect("verify 不应报错");
            assert!(!ok);
        }

        // 第 6 次正确答案也返回 false
        let ok = provider.verify(&id, "0").await.expect("verify 不应报错");
        assert!(!ok, "默认 5 次后 challenge 应已失效");
    }

    /// 正确答案在未超过 max_attempts 时通过。
    #[tokio::test]
    async fn correct_answer_passes_before_max_attempts() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::with_max_attempts(dao, 3);
        let (id, question) = provider.generate().await.expect("generate 不应报错");

        // 2 次错误答案（未超过 3 次）
        for _ in 0..2 {
            provider.verify(&id, "999").await.expect("verify 不应报错");
        }

        // 解析正确答案
        let parts: Vec<&str> = question.split(' ').collect();
        let a: i32 = parts[0].parse().unwrap();
        let b: i32 = parts[2].parse().unwrap();
        let expected = if parts[1] == "+" { a + b } else { a - b };

        // 第 3 次正确答案应通过
        let ok = provider
            .verify(&id, &expected.to_string())
            .await
            .expect("verify 不应报错");
        assert!(ok, "未超过 max_attempts 时正确答案应通过");
    }
}
