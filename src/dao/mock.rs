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
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
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
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
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
            None => Err(BulwarkError::InvalidParam(format!("键不存在: {}", old_key))),
        }
    }

    /// get_and_delete 用 `parking_lot::Mutex` 保护原子性。
    ///
    /// 在单个 `lock()` 作用域内完成 get + remove，保证进程内原子。
    async fn get_and_delete(&self, key: &str) -> BulwarkResult<Option<String>> {
        let mut store = self.store.lock();
        Ok(store.remove(key).map(|(value, _)| value))
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

    /// eval_lua 内存模拟实现（识别 INCR + EXPIRE 模式，委托 incr）。
    ///
    /// MockDao 不支持真正的 Lua 脚本，但 `incr` 已用 Mutex 保证进程内原子性。
    /// 识别脚本中的 INCR + EXPIRE 模式后，提取 KEYS[1] 和 ARGV[2]（TTL），
    /// 委托 `self.incr` 实现，返回 `vec![count.to_string()]`。
    async fn eval_lua(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> BulwarkResult<Vec<String>> {
        if script.contains("INCR") && script.contains("EXPIRE") {
            let key = keys
                .first()
                .ok_or_else(|| BulwarkError::InvalidParam("eval_lua 缺少 KEYS[1]".to_string()))?;
            // ARGV[2] 是 TTL（ARGV[1] 是 threshold，由调用方处理）
            let ttl: u64 = args
                .get(1)
                .ok_or_else(|| {
                    BulwarkError::InvalidParam("eval_lua 缺少 ARGV[2] (TTL)".to_string())
                })?
                .parse()
                .map_err(|e| {
                    BulwarkError::InvalidParam(format!("eval_lua ARGV[2] parse 失败: {}", e))
                })?;
            let count = self.incr(key, ttl).await?;
            return Ok(vec![count.to_string()]);
        }
        Err(BulwarkError::NotImplemented(format!(
            "eval_lua 不支持的脚本模式: {}（MockDao 仅支持 INCR+EXPIRE）",
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
