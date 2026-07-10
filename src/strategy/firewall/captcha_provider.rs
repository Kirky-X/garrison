//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 数学验证码提供商（基础 CAPTCHA 实现）。
//!
//! [`MathCaptchaProvider`] 生成 `"a ± b = ?"` 形式的数学挑战题，
//! 将答案存入 DAO（key = `captcha:math:{challenge_id}`），验证后一次性删除防止复用。
//!
//! # 算法
//!
//! 1. 随机生成两个 1-20 的整数 `a` 和 `b`（用 `rand::rngs::OsRng`，与项目其他模块一致）。
//! 2. 随机选择运算符 `+` 或 `-`；若选 `-` 但 `a < b`（结果为负），回退到 `+` 确保结果非负。
//! 3. 生成 `challenge_id = UUID v4`，计算答案，存入 DAO（TTL = `self.ttl`）。
//! 4. 返回 `(challenge_id, "a op b = ?")`。
//!
//! # 一次性使用
//!
//! `verify` 匹配成功后立即删除 DAO key，防止同一 challenge_id 被复用。
//! 不匹配或 key 不存在返回 `Ok(false)`，不报错。
//!
//! # 与 [`CaptchaChallenge`](crate::strategy::firewall::CaptchaChallenge) trait 的区分
//!
//! `CaptchaChallenge` 绑定 `FirewallContext`（按 IP/login_id 定位期望答案），
//! `MathCaptchaProvider` 用 challenge_id 定位，不依赖上下文，是独立的验证码生成/验证组件。

use crate::dao::BulwarkDao;
use crate::error::BulwarkResult;
use rand::rngs::OsRng;
use rand::Rng;
use std::sync::Arc;
use uuid::Uuid;

/// 默认 TTL（秒），challenge 答案在 DAO 中的存活时间。
const DEFAULT_TTL: u64 = 300;

/// 数学验证码提供商，生成 `"a ± b = ?"` 形式的挑战题。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::dao::BulwarkDao;
/// use bulwark::strategy::firewall::captcha_provider::MathCaptchaProvider;
///
/// let dao: Arc<dyn BulwarkDao> = /* oxcache 实现 */;
/// let provider = MathCaptchaProvider::new(dao);          // TTL=300s
/// let provider = MathCaptchaProvider::with_ttl(dao, 600); // TTL=600s
/// ```
pub struct MathCaptchaProvider {
    /// DAO（用于存储 challenge 答案）。
    dao: Arc<dyn BulwarkDao>,
    /// 答案在 DAO 中的存活时间（秒）。
    ttl: u64,
}

impl MathCaptchaProvider {
    /// 创建数学验证码提供商，TTL 默认 300 秒。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self {
            dao,
            ttl: DEFAULT_TTL,
        }
    }

    /// 创建数学验证码提供商，自定义 TTL。
    pub fn with_ttl(dao: Arc<dyn BulwarkDao>, ttl: u64) -> Self {
        Self { dao, ttl }
    }

    /// 生成一道数学挑战题，返回 `(challenge_id, 题目字符串)`。
    ///
    /// 题目格式为 `"a op b = ?"`（如 `"3 + 5 = ?"`），答案存入 DAO 供 [`verify`](Self::verify) 比对。
    pub async fn generate(&self) -> BulwarkResult<(String, String)> {
        let mut rng = OsRng;
        let a: i32 = rng.gen_range(1..=20);
        let b: i32 = rng.gen_range(1..=20);
        // 随机选 + 或 -；选 - 但 a < b 时回退到 + 确保结果非负
        let (op, answer) = if rng.gen_bool(0.5) || a < b {
            ('+', a + b)
        } else {
            ('-', a - b)
        };
        let challenge_id = Uuid::new_v4().to_string();
        let key = format!("captcha:math:{}", challenge_id);
        self.dao.set(&key, &answer.to_string(), self.ttl).await?;
        let question = format!("{} {} {} = ?", a, op, b);
        Ok((challenge_id, question))
    }

    /// 验证用户提交的答案。
    ///
    /// 匹配则删除 DAO key（一次性使用，防止复用）；不匹配或 challenge_id 不存在返回 `Ok(false)`。
    pub async fn verify(&self, challenge_id: &str, answer: &str) -> BulwarkResult<bool> {
        let key = format!("captcha:math:{}", challenge_id);
        let stored = self.dao.get(&key).await?;
        let matched = stored
            .as_deref()
            .map(|s| s.trim() == answer.trim())
            .unwrap_or(false);
        if matched {
            self.dao.delete(&key).await?;
        }
        Ok(matched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    /// generate 返回非空 challenge_id 和非空题目。
    #[tokio::test]
    async fn generate_returns_nonempty_id_and_question() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, question) = provider.generate().await.expect("generate 不应报错");
        assert!(!id.is_empty(), "challenge_id 不应为空");
        assert!(!question.is_empty(), "题目不应为空");
    }

    /// generate + verify 正确答案通过。
    #[tokio::test]
    async fn verify_correct_answer_passes() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
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
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let provider = MathCaptchaProvider::new(dao);
        let (id, _question) = provider.generate().await.expect("generate 不应报错");

        // 999 不可能是 1-20 范围运算的结果
        let ok = provider.verify(&id, "999").await.expect("verify 不应报错");
        assert!(!ok, "错误答案应返回 false");
    }

    /// verify 不存在的 challenge_id 返回 false。
    #[tokio::test]
    async fn verify_nonexistent_id_returns_false() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
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
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
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
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
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
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
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
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
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
}
