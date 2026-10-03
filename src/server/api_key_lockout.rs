// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 内网 API Key 认证失败锁定（GAR-25）。
//!
//! 同一源 IP 的连续认证失败（缺失 / 错误 / 重复 `X-API-Key`）达到阈值后，
//! 窗口期内一律返回 429 + `Retry-After`（fail-closed）；任一次成功认证即清零。
//!
//! # 设计
//!
//! - 纯内存 `DashMap`（与 [`crate::server::middleware::RateLimitState`] 同一取舍：
//!   不引入 Redis 依赖）；进程重启即重置。跨实例的全局封禁应启用
//!   `firewall-bruteforce` / `ban-sync` feature（见 `src/server` 模块文档）。
//! - `threshold = 0` 显式禁用锁定（不记账、不判定）。
//! - `max_entries` 上限防内存耗尽：超限时先清过期窗口，仍超限则淘汰
//!   window_start 最旧的记录（本记录不淘汰，保证当前请求语义正确）。

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// 单源 IP 的失败记录。
#[derive(Debug)]
struct FailureRecord {
    /// 当前窗口内的连续失败次数。
    count: u32,
    /// 当前窗口起点（窗口内首次失败时刻）。
    window_start: Instant,
}

/// `record_failure` 的结果：携带是否触发锁定与建议的 Retry-After 秒数，
/// 供调用方在同一次响应中直接生效（第 N 次失败即锁定，不等下一次请求）。
#[derive(Debug, Clone, Copy)]
pub struct FailureOutcome {
    /// 记账后的连续失败次数。
    pub count: u32,
    /// 本次失败是否触发锁定（count 达到阈值）。
    pub locked: bool,
    /// 锁定状态下建议的 Retry-After（delta-seconds，下限 1）。
    pub retry_after_secs: u64,
}

/// API Key 认证失败锁定状态（内存态，按源 IP 记账）。
#[derive(Debug)]
pub struct ApiKeyLockout {
    records: DashMap<String, FailureRecord>,
    /// 锁定阈值（连续失败次数），0 = 禁用。
    threshold: u32,
    /// 锁定窗口时长。
    window: Duration,
    /// 记录条目上限（防 DoS 内存耗尽）。
    max_entries: usize,
}

/// 默认记录条目上限（与 RateLimitState 的 DEFAULT_MAX_ENTRIES 同量级）。
const DEFAULT_MAX_ENTRIES: usize = 100_000;

impl ApiKeyLockout {
    /// 创建锁定状态。
    ///
    /// # 参数
    /// - `threshold`：连续失败阈值；`0` 禁用锁定
    /// - `window_secs`：窗口时长（秒）
    pub fn new(threshold: u32, window_secs: u64) -> Self {
        Self {
            records: DashMap::with_capacity(64),
            threshold,
            window: Duration::from_secs(window_secs),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// 锁定阈值（0 = 禁用）。
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// 判定源 IP 是否处于锁定中。
    ///
    /// 锁定中返回 `Some(retry_after_secs)`（建议等待秒数，下限 1）；
    /// 窗口已过期的残留记录在此顺带清除。
    pub fn check_locked(&self, source: &str) -> Option<u64> {
        if self.threshold == 0 {
            return None;
        }
        let record = self.records.get(source)?;
        let elapsed = record.window_start.elapsed();
        if elapsed >= self.window {
            drop(record);
            self.records.remove(source);
            return None;
        }
        if record.count >= self.threshold {
            Some(self.window.saturating_sub(elapsed).as_secs().max(1))
        } else {
            None
        }
    }

    /// 记账一次认证失败（缺失 / 错误 / 重复 `X-API-Key`）。
    ///
    /// 窗口已过期时重新开窗（计数从 1 开始）；达到阈值即返回 `locked=true`。
    pub fn record_failure(&self, source: &str) -> FailureOutcome {
        if self.threshold == 0 {
            return FailureOutcome {
                count: 0,
                locked: false,
                retry_after_secs: 0,
            };
        }
        let outcome = {
            let mut entry = self
                .records
                .entry(source.to_string())
                .or_insert(FailureRecord {
                    count: 0,
                    window_start: Instant::now(),
                });
            if entry.window_start.elapsed() >= self.window {
                entry.count = 0;
                entry.window_start = Instant::now();
            }
            entry.count += 1;
            FailureOutcome {
                count: entry.count,
                locked: entry.count >= self.threshold,
                retry_after_secs: self.window.as_secs().max(1),
            }
        };
        self.evict_if_over_capacity(source);
        outcome
    }

    /// 成功认证：清零该源 IP 的失败记录。
    pub fn record_success(&self, source: &str) {
        self.records.remove(source);
    }

    /// 条目超限清理：先移除窗口已过期的记录；仍超限则淘汰 window_start
    /// 最旧的一条（跳过 `current`，避免丢失本次记账）。
    ///
    /// 与 RateLimitState 的 LRU 淘汰同一纪律：迭代不持 entry 写锁
    /// （DashMap iter 会锁各分片，跨 guard 持锁迭代会死锁）。
    fn evict_if_over_capacity(&self, current: &str) {
        if self.records.len() <= self.max_entries {
            return;
        }
        let expired: Vec<String> = self
            .records
            .iter()
            .filter(|e| e.value().window_start.elapsed() >= self.window)
            .map(|e| e.key().clone())
            .collect();
        for key in expired {
            self.records.remove(&key);
        }
        if self.records.len() <= self.max_entries {
            return;
        }
        if let Some(oldest) = self
            .records
            .iter()
            .filter(|e| e.key() != current)
            .min_by_key(|e| e.value().window_start)
            .map(|e| e.key().clone())
        {
            self.records.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 未达阈值时不锁定。
    #[test]
    fn below_threshold_never_locks() {
        let lockout = ApiKeyLockout::new(3, 300);
        assert!(lockout.check_locked("1.2.3.4").is_none());
        lockout.record_failure("1.2.3.4");
        lockout.record_failure("1.2.3.4");
        assert!(lockout.check_locked("1.2.3.4").is_none(), "2 < 3 不应锁定");
    }

    /// 达到阈值即锁定，check_locked 给出建议等待秒数。
    #[test]
    fn reaches_threshold_locks_with_retry_after() {
        let lockout = ApiKeyLockout::new(2, 300);
        assert!(!lockout.record_failure("ip-a").locked);
        let outcome = lockout.record_failure("ip-a");
        assert!(outcome.locked, "第 2 次失败应触发锁定");
        assert_eq!(outcome.retry_after_secs, 300);
        let retry = lockout.check_locked("ip-a").expect("达阈值后应处于锁定中");
        assert!(
            (1..=300).contains(&retry),
            "Retry-After 应在 1..=300，实际 {retry}"
        );
    }

    /// 成功认证清零记录：失败-成功-失败 不触发锁定。
    #[test]
    fn success_resets_count() {
        let lockout = ApiKeyLockout::new(2, 300);
        lockout.record_failure("ip-b");
        lockout.record_success("ip-b");
        let outcome = lockout.record_failure("ip-b");
        assert!(!outcome.locked, "成功清零后重新计数，count=1 不应锁定");
        assert!(lockout.check_locked("ip-b").is_none());
    }

    /// 窗口过期后锁定解除，新失败重新开窗计数。
    #[test]
    fn window_expiry_unlocks_and_restarts() {
        let lockout = ApiKeyLockout::new(1, 1);
        assert!(lockout.record_failure("ip-c").locked);
        assert!(lockout.check_locked("ip-c").is_some());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(lockout.check_locked("ip-c").is_none(), "窗口过期应解除锁定");
        let outcome = lockout.record_failure("ip-c");
        assert!(outcome.locked, "过期后重新开窗，第 1 次失败即达阈值 1");
    }

    /// threshold=0 显式禁用：不记账、不锁定。
    #[test]
    fn zero_threshold_disables() {
        let lockout = ApiKeyLockout::new(0, 300);
        for _ in 0..100 {
            let outcome = lockout.record_failure("ip-d");
            assert!(!outcome.locked);
            assert_eq!(outcome.count, 0, "禁用态不应记账");
        }
        assert!(lockout.check_locked("ip-d").is_none());
    }

    /// 不同源 IP 相互隔离。
    #[test]
    fn sources_are_isolated() {
        let lockout = ApiKeyLockout::new(2, 300);
        lockout.record_failure("ip-e");
        lockout.record_failure("ip-e");
        assert!(lockout.check_locked("ip-e").is_some());
        assert!(lockout.check_locked("ip-f").is_none());
    }
}
