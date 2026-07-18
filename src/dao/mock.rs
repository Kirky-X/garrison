//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DAO 层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `HashMap` + `Instant` 模拟 TTL）与 `glob_match` helper，
//! 供 `dao::tests` 契约测试及跨模块测试复用。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------
// Mock 实现：基于 HashMap + Instant 模拟 TTL，严格按 spec 语义
// ------------------------------------------------------------------------

/// 测试用 mock DAO，用于验证 trait 契约本身（与具体后端无关）。
///
/// 语义：
/// - `set(ttl=0)`: 永久驻留（expire_at = None）
/// - `set(ttl=N)`: N 秒后过期（expire_at = Some(now + N)）
/// - `update`: 保留原 expire_at，仅更新 value
/// - `expire`: 重置 expire_at
///
/// `pub` 供跨模块测试（如 `strategy::hooks`）复用，仅在 `cfg(test)` 下编译。
pub struct MockDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl Default for MockDao {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDao {
    /// 创建空的 mock DAO 实例（无任何键值）。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        let mut store = self.store.lock();
        match store.get(key) {
            Some((value, expire_at)) => {
                if let Some(deadline) = expire_at {
                    if Instant::now() >= *deadline {
                        store.remove(key);
                        return Ok(None);
                    }
                }
                Ok(Some(value.clone()))
            },
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
        let expire_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), expire_at));
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("dao-key-missing::{}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((_, expire_at)) => {
                *expire_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("dao-key-missing::{}", key))),
        }
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }

    /// set_permanent 设置 expire_at = None（永久驻留）。
    async fn set_permanent(&self, key: &str, value: &str) -> BulwarkResult<()> {
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), None));
        Ok(())
    }

    /// get_timeout 返回剩余 TTL。
    ///
    /// - `Some(remaining)`: 键存在且设置了 TTL（expire_at - now）
    /// - `None`: 键不存在，或永久键（expire_at = None）
    async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
        let store = self.store.lock();
        match store.get(key) {
            Some((_, Some(deadline))) => {
                let now = Instant::now();
                if *deadline <= now {
                    // 已过期（但还未被 get 清理）
                    Ok(None)
                } else {
                    Ok(Some(*deadline - now))
                }
            },
            _ => Ok(None),
        }
    }

    /// keys 按 glob pattern 扫描 key（支持 `*` 与 `?`）。
    ///
    /// 遍历所有 key，过滤已过期的，然后用 glob_match 匹配 pattern。
    ///
    /// # L7 复杂度说明
    ///
    /// O(n) 遍历是预期行为：`MockDao` 是测试用实现，store 容量小（通常 < 1000 entry），
    /// 无需索引优化。生产环境应使用 `BulwarkDaoOxcache`（Redis SCAN）或 dbnexus（SQL LIKE），
    /// 它们的 keys() 实现委托后端原生 scan API，不在此 O(n) 路径上。
    async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
        let mut result = Vec::new();
        let now = Instant::now();
        let store = self.store.lock();
        for (key, (_, expire_at)) in store.iter() {
            // 跳过已过期的 key
            if let Some(deadline) = expire_at {
                if *deadline <= now {
                    continue;
                }
            }
            if glob_match(pattern, key) {
                result.push(key.clone());
            }
        }
        Ok(result)
    }

    /// rename 重命名 key，保留原 TTL（非原子）。
    async fn rename(&self, old_key: &str, new_key: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get(old_key).cloned() {
            Some((value, expire_at)) => {
                store.insert(new_key.to_string(), (value, expire_at));
                store.remove(old_key);
                Ok(())
            },
            None => Err(BulwarkError::InvalidParam(format!(
                "dao-key-not-found::{}",
                old_key
            ))),
        }
    }

    /// get_and_delete 用 `parking_lot::Mutex` 保护原子性。
    ///
    /// 在单个 `lock()` 作用域内完成 get + remove，保证进程内原子。
    /// TTL 语义与 `get` 一致：已过期的 key 视为不存在（返回 None）。
    async fn get_and_delete(&self, key: &str) -> BulwarkResult<Option<String>> {
        let mut store = self.store.lock();
        match store.remove(key) {
            Some((_value, Some(deadline))) if Instant::now() >= deadline => {
                // 已过期，视为不存在（value 已丢弃）
                Ok(None)
            },
            Some((value, _)) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    /// incr 用 Mutex 保护原子性（进程内原子）。
    ///
    /// 在单个 lock() 作用域内完成 get → parse → update/set，保证进程内原子。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> BulwarkResult<u64> {
        let mut store = self.store.lock();
        let now = Instant::now();
        // 清理已过期的 key
        let should_init = match store.get(key) {
            Some((_, Some(deadline))) => *deadline <= now, // 已过期
            Some((_, None)) => false,                      // 永久键
            None => true,                                  // 不存在
        };
        if should_init {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(now + Duration::from_secs(ttl_seconds))
            };
            store.insert(key.to_string(), ("1".to_string(), expire_at));
            Ok(1)
        } else {
            let (val_str, _) = store.get(key).cloned().unwrap();
            let new_val = val_str.parse::<u64>().unwrap_or(0) + 1;
            // 保留原 expire_at（不重置 TTL）
            let expire_at = store.get(key).and_then(|(_, e)| *e);
            store.insert(key.to_string(), (new_val.to_string(), expire_at));
            Ok(new_val)
        }
    }

    /// compare_and_update_if_greater 用 Mutex 保护原子性（进程内原子）。
    ///
    /// 在单个 lock() 作用域内完成 get → parse → compare → set，消除 TOCTOU 竞态。
    /// 用于 HTTP Digest nc 单调性校验（RFC 7616 §3.4.6）。
    /// - key 不存在或已过期：current_val = 0，new_value > 0 时初始化并设置 TTL
    /// - key 已存在且 new_value > current_val：保留原 expire_at（不重置 TTL）
    /// - key 已存在但 new_value <= current_val：不修改，返回 false
    async fn compare_and_update_if_greater(
        &self,
        key: &str,
        new_value: u64,
        ttl_seconds: u64,
    ) -> BulwarkResult<bool> {
        let mut store = self.store.lock();
        let now = Instant::now();
        // M1 修复：parse 失败必须显式报错（与 incr 方法一致，Rule 12 错误显性化），
        // 禁止 unwrap_or(0) 静默返回 0 导致 nc 计数器被错误重置
        let (current_val, existing_expire_at) = match store.get(key) {
            Some((v, Some(deadline))) if *deadline > now => (
                v.parse::<u64>().map_err(|_| {
                    BulwarkError::Dao(format!("dao-compare-and-update-parse-u64::{}::{}", key, v))
                })?,
                Some(*deadline),
            ),
            Some((v, None)) => (
                v.parse::<u64>().map_err(|_| {
                    BulwarkError::Dao(format!("dao-compare-and-update-parse-u64::{}::{}", key, v))
                })?,
                None,
            ),
            // 已过期或不存在
            _ => (0, None),
        };
        if new_value > current_val {
            // 保留原 TTL：键已存在用原 expire_at；新键用 ttl_seconds
            let expire_at = if existing_expire_at.is_some() {
                existing_expire_at
            } else if ttl_seconds == 0 {
                None
            } else {
                Some(now + Duration::from_secs(ttl_seconds))
            };
            store.insert(key.to_string(), (new_value.to_string(), expire_at));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// eval_lua 内存模拟实现（识别两类脚本模式）。
    ///
    /// MockDao 不支持真正的 Lua 脚本，但用 `parking_lot::Mutex` 保证进程内原子性。
    ///
    /// # 支持的脚本模式
    ///
    /// 1. **INCR + EXPIRE**（limiteron BruteForceStrategy 用）：
    ///    识别脚本中含 `INCR` + `EXPIRE`，提取 `KEYS[1]` 与 `ARGV[2]`（TTL），
    ///    委托 `self.incr`，返回 `vec![count.to_string()]`。
    ///
    /// 2. **rate_limit_sliding_window**（RateLimitStrategy 用，vuln-0009 修复）：
    ///    识别脚本中含标记 `rate_limit_sliding_window`，在单次 `lock()` 作用域内
    ///    原子执行 read → filter → check → write（消除 TOCTOU）。
    ///    - `KEYS[1]`：时间戳列表 key
    ///    - `ARGV[1]`：now_ms（u64）
    ///    - `ARGV[2]`：window_start_ms（u64，此时刻之前的时间戳被滑出）
    ///    - `ARGV[3]`：threshold（usize，>= 即拦截）
    ///    - `ARGV[4]`：ttl_seconds（u64，窗口 TTL）
    ///    - 返回 `vec!["1"]` 表示允许（已追加时间戳），`vec!["0"]` 表示拦截（未修改）
    async fn eval_lua(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> BulwarkResult<Vec<String>> {
        // 模式 1：INCR + EXPIRE（limiteron BruteForceStrategy）
        if script.contains("INCR") && script.contains("EXPIRE") {
            let key = keys.first().ok_or_else(|| {
                BulwarkError::InvalidParam("dao-eval-lua-missing-keys-1".to_string())
            })?;
            // ARGV[2] 是 TTL（ARGV[1] 是 threshold，由调用方处理）
            let ttl: u64 = args
                .get(1)
                .ok_or_else(|| {
                    BulwarkError::InvalidParam("dao-eval-lua-missing-argv-2-ttl".to_string())
                })?
                .parse()
                .map_err(|e| {
                    BulwarkError::InvalidParam(format!("dao-eval-lua-argv-2-parse-failed::{}", e))
                })?;
            let count = self.incr(key, ttl).await?;
            return Ok(vec![count.to_string()]);
        }

        // 模式 2：rate_limit_sliding_window（RateLimitStrategy vuln-0009 修复）
        // 在单次 lock() 内原子执行 read-filter-check-write，消除 TOCTOU。
        if script.contains("rate_limit_sliding_window") {
            let key = keys.first().ok_or_else(|| {
                BulwarkError::InvalidParam("dao-eval-lua-rl-missing-keys-1".to_string())
            })?;
            let now_ms: u64 = args
                .first()
                .ok_or_else(|| {
                    BulwarkError::InvalidParam("dao-eval-lua-rl-missing-argv-1-now-ms".to_string())
                })?
                .parse()
                .map_err(|e| {
                    BulwarkError::InvalidParam(format!(
                        "dao-eval-lua-rl-argv-1-parse-failed::{}",
                        e
                    ))
                })?;
            let window_start_ms: u64 = args
                .get(1)
                .ok_or_else(|| {
                    BulwarkError::InvalidParam(
                        "dao-eval-lua-rl-missing-argv-2-window-start".to_string(),
                    )
                })?
                .parse()
                .map_err(|e| {
                    BulwarkError::InvalidParam(format!(
                        "dao-eval-lua-rl-argv-2-parse-failed::{}",
                        e
                    ))
                })?;
            let threshold: usize = args
                .get(2)
                .ok_or_else(|| {
                    BulwarkError::InvalidParam(
                        "dao-eval-lua-rl-missing-argv-3-threshold".to_string(),
                    )
                })?
                .parse()
                .map_err(|e| {
                    BulwarkError::InvalidParam(format!(
                        "dao-eval-lua-rl-argv-3-parse-failed::{}",
                        e
                    ))
                })?;
            let ttl_seconds: u64 = args
                .get(3)
                .ok_or_else(|| {
                    BulwarkError::InvalidParam("dao-eval-lua-rl-missing-argv-4-ttl".to_string())
                })?
                .parse()
                .map_err(|e| {
                    BulwarkError::InvalidParam(format!(
                        "dao-eval-lua-rl-argv-4-parse-failed::{}",
                        e
                    ))
                })?;

            // 原子 read-filter-check-write（单次 lock 作用域内）
            let mut store = self.store.lock();
            let now = Instant::now();
            // 读取并过滤过期时间戳，收集到 Vec
            let mut timestamps: Vec<u64> = match store.get(key) {
                Some((raw, Some(deadline))) if *deadline > now => raw
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse::<u64>().ok())
                    .filter(|&t| t > window_start_ms)
                    .collect(),
                Some((raw, None)) => raw
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse::<u64>().ok())
                    .filter(|&t| t > window_start_ms)
                    .collect(),
                // 已过期或不存在：空列表
                _ => Vec::new(),
            };

            // 阈值检查
            if timestamps.len() >= threshold {
                return Ok(vec!["0".to_string()]);
            }

            // 追加当前时间戳并回写
            timestamps.push(now_ms);
            let new_raw = timestamps
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(now + Duration::from_secs(ttl_seconds))
            };
            store.insert(key.to_string(), (new_raw, expire_at));
            return Ok(vec!["1".to_string()]);
        }

        Err(BulwarkError::NotImplemented(format!(
            "dao-eval-lua-unsupported-script::{}",
            script
        )))
    }
}

// ------------------------------------------------------------------------
// glob 匹配 helper（用于 keys 方法，支持 `*` 与 `?`）
// ------------------------------------------------------------------------

/// 简单 glob 匹配：`*` 匹配 0+ 字符，`?` 匹配 1 字符。
///
/// 使用经典双指针算法（O(n+m) 时间复杂度）。
///
/// 改为 `pub(crate)` 以供 `protocol::apikey` 模块的 `list_by_namespace` 复用
/// 。
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut p = 0; // pattern index
    let mut t = 0; // text index
    let mut star_p: Option<usize> = None; // 上一个 '*' 在 pattern 中的位置
    let mut star_t = 0; // 上一个 '*' 匹配开始时的 text 位置

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            // 回溯：让上一个 '*' 多匹配一个字符
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    // 跳过 pattern 末尾的 '*'
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}
