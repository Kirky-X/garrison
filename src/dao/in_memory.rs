// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO 进程内实现（HashMap + Instant 模拟 TTL）：测试 mock + 单实例部署内存模式
//!（PasswordRateLimiter / GarrisonFirewallCheckHookDefault 的内存后端）；**不跨实例共享**，多节点部署须用共享存储后端。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------
// Mock 实现：HashMap + Instant 模拟 TTL
// ------------------------------------------------------------------------

/// 进程内内存 DAO（HashMap 后端）：`set(ttl=0)` 永久驻留、`set(ttl=N)` N 秒后过期、
/// `update` 保留原 expire_at、`expire` 重置 expire_at。
/// `pub` 供跨模块测试与生产内存模式复用（`cfg(test)` 下亦编译）。
pub struct InMemoryDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl Default for InMemoryDao {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDao {
    /// 创建空的进程内 DAO（无任何键值）。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for InMemoryDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
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

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
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

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        // 过期键视为不存在（与 get()/keys() 一致），避免被 update 改值「复活」
        let expired = match store.get(key) {
            Some((_, Some(deadline))) => Instant::now() >= *deadline,
            _ => false,
        };
        if expired {
            store.remove(key);
            return Err(GarrisonError::Dao(format!("dao-key-missing::{}", key)));
        }
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("dao-key-missing::{}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        // 过期键视为不存在（与 get()/keys() 一致），避免被 expire 续期「复活」
        let expired = match store.get(key) {
            Some((_, Some(deadline))) => Instant::now() >= *deadline,
            _ => false,
        };
        if expired {
            store.remove(key);
            return Err(GarrisonError::Dao(format!("dao-key-missing::{}", key)));
        }
        match store.get_mut(key) {
            Some((_, expire_at)) => {
                *expire_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("dao-key-missing::{}", key))),
        }
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }

    /// set_permanent 设置 expire_at = None（永久驻留）。
    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), None));
        Ok(())
    }

    /// 返回剩余 TTL；永久键与不存在的键均返回 None。
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
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

    /// keys 按 glob pattern 扫描（支持 `*` / `?`），过滤已过期项。
    ///
    /// O(n) 遍历是预期行为：测试用实现 store 容量小（通常 < 1000 entry）；生产环境用
    /// `GarrisonDaoOxcache` / dbnexus 的原生 scan 实现，不走此路径。
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let mut result = Vec::new();
        let now = Instant::now();
        let store = self.store.lock();
        for (key, (_, expire_at)) in store.iter() {
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

    /// 重命名 key，保留原 TTL。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        match store.get(old_key).cloned() {
            Some((value, expire_at)) => {
                store.insert(new_key.to_string(), (value, expire_at));
                store.remove(old_key);
                Ok(())
            },
            None => Err(GarrisonError::InvalidParam(format!(
                "dao-key-not-found::{}",
                old_key
            ))),
        }
    }

    /// 单锁作用域内 get + remove（进程内原子）；过期 key 视为不存在返回 None。
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
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

    /// 单锁作用域内 get → set（进程内原子，并发同 key 仅一个返回 true）；TTL 语义同 `set`。
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let mut store = self.store.lock();
        let now = Instant::now();
        // 检查 key 是否存在（含过期清理）
        let exists = match store.get(key) {
            Some((_, Some(deadline))) if *deadline <= now => {
                store.remove(key);
                false
            },
            Some(_) => true,
            None => false,
        };
        if exists {
            return Ok(false);
        }
        let expire_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        store.insert(key.to_string(), (value.to_string(), expire_at));
        Ok(true)
    }

    /// 单锁作用域内 get → parse → update/set（进程内原子）；解析失败显式报错，禁止静默按 0 重置计数器。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
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
            // 解析失败显式报错，禁止静默按 0 处理导致限速计数器重置
            //（与 decr/compare_and_update_if_greater 对齐）
            let cur_val: u64 = val_str.parse().map_err(|_| {
                GarrisonError::Dao(format!("dao-incr-parse-u64::{}::{}", key, val_str))
            })?;
            let new_val = cur_val
                .checked_add(1)
                .ok_or_else(|| GarrisonError::Dao(format!("dao-incr-overflow-u64::{}", key)))?;
            // 保留原 expire_at（不重置 TTL）
            let expire_at = store.get(key).and_then(|(_, e)| *e);
            store.insert(key.to_string(), (new_val.to_string(), expire_at));
            Ok(new_val)
        }
    }

    /// 单锁作用域内 get → parse → update/delete（进程内原子，消除 TOCTOU）：
    /// 不存在/已过期→0；值为 0→0；>0 递减，到 0 删 key，否则保留原 expire_at。
    ///
    /// 该原子性修复了 `concurrent_send_does_not_exceed_limit` flaky（SMS 限速「跨越式递减」，见 `SmsRateLimiter::decrement_counter`）。
    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        let mut store = self.store.lock();
        let now = Instant::now();
        let (cur_val, expire_at) = match store.get(key) {
            Some((v, Some(deadline))) => {
                if *deadline <= now {
                    store.remove(key);
                    return Ok(0);
                }
                let val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!("dao-decr-parse-u64::{}::{}", key, v))
                })?;
                (val, Some(*deadline))
            },
            Some((v, None)) => {
                let val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!("dao-decr-parse-u64::{}::{}", key, v))
                })?;
                (val, None)
            },
            None => return Ok(0),
        };
        if cur_val == 0 {
            return Ok(0);
        }
        let new_val = cur_val - 1;
        if new_val == 0 {
            store.remove(key);
        } else {
            // 保留原 expire_at（不重置 TTL，与 incr 语义对称）
            store.insert(key.to_string(), (new_val.to_string(), expire_at));
        }
        Ok(new_val)
    }

    /// 单锁作用域内 get → parse → compare → set（进程内原子）：不存在视 0，> current 时写入并保留原 expire_at；
    /// 用于 HTTP Digest nc 单调性校验（RFC 7616 §3.4.6）。
    async fn compare_and_update_if_greater(
        &self,
        key: &str,
        new_value: u64,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let mut store = self.store.lock();
        let now = Instant::now();
        // parse 失败必须显式报错（与 incr 方法一致，错误显性化），
        // 禁止 unwrap_or(0) 静默返回 0 导致 nc 计数器被错误重置
        let (current_val, existing_expire_at) = match store.get(key) {
            Some((v, Some(deadline))) if *deadline > now => (
                v.parse::<u64>().map_err(|_| {
                    GarrisonError::Dao(format!("dao-compare-and-update-parse-u64::{}::{}", key, v))
                })?,
                Some(*deadline),
            ),
            Some((v, None)) => (
                v.parse::<u64>().map_err(|_| {
                    GarrisonError::Dao(format!("dao-compare-and-update-parse-u64::{}::{}", key, v))
                })?,
                None,
            ),
            _ => (0, None),
        };
        if new_value > current_val {
            // 保留原 TTL：键已存在用原 expire_at；新键/永久键用 ttl_seconds。
            //
            //【已知行为不一致，记录不改逻辑】existing_expire_at=None（永久键或新键）会落入
            // ttl_seconds 分支，把永久键「升级」为 TTL 键，与 incr/decr 对永久键保留 None 的语义不一致。
            // 影响：调用方（Digest nc 校验）始终传非零 ttl，当前不引发功能问题；统一语义需区分
            //「已存在的永久键」与「键不存在」，并同步更新 mod.rs 的 compare_and_update matrix 测试断言。
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

    /// 单锁作用域内 get → compare → set（进程内原子）；用于备份码消费等 CAS 场景。
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let mut store = self.store.lock();
        let now = Instant::now();
        let current = match store.get(key) {
            Some((v, Some(deadline))) if *deadline <= now => {
                store.remove(key);
                None
            },
            Some((v, _)) => Some(v.as_str()),
            None => None,
        };
        if current == expected {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            store.insert(key.to_string(), (new_value.to_string(), expire_at));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// eval_lua 内存模拟（`parking_lot::Mutex` 内原子），识别两类 limiteron 脚本模式：
    ///
    /// 1. **INCR + EXPIRE**（BruteForceStrategy）：取 `KEYS[1]` 与 `ARGV[2]`（TTL）委托 `self.incr`，返回 `vec![count]`。
    /// 2. **ZREMRANGEBYSCORE**（`SLIDING_WINDOW_SCRIPT`，RateLimitStrategy）：单锁内 remove-outdated → count → check → add；
    ///    `KEYS[1]`=Sorted Set（score=毫秒时间戳，member=时间戳:seq）、`KEYS[2]`=seq 键、
    ///    `ARGV[1]`=窗口 ms、`ARGV[2]`=最大请求数；rc.6 起脚本内取 Redis TIME，模拟器取系统墙钟；
    ///    返回 `[allowed, count, reset_time]`（reset_time 为近似值，调用方仅消费 allowed 位）。
    async fn eval_lua(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> GarrisonResult<Vec<String>> {
        // 模式 1（滑窗）必须先判：rc.6 起滑窗脚本含 INCR+EXPIRE 与 ZREMRANGEBYSCORE
        // 双特征（INCR seq_key 生成成员唯一序号），反转判序会被误派发到 INCR 模式。
        // 注意：上游 FIXED_WINDOW_SCRIPT 同样含 INCR+EXPIRE 且无滑窗特征，会共享
        // INCR 模式派发（行为恰为 INCR 语义）；新增消费 oxcache_lua 脚本前须先核对本派发特征表。
        if script.contains("ZREMRANGEBYSCORE") {
            return self.eval_lua_sliding_window_mode(&keys, &args).await;
        }

        // 模式 2：INCR + EXPIRE（limiteron BruteForceStrategy）
        if script.contains("INCR") && script.contains("EXPIRE") {
            return self.eval_lua_incr_mode(&keys, &args).await;
        }

        Err(GarrisonError::NotImplemented(format!(
            "dao-eval-lua-unsupported-script::{}",
            script
        )))
    }
}

impl InMemoryDao {
    /// INCR + EXPIRE 模式：原子递增 + TTL。
    async fn eval_lua_incr_mode(
        &self,
        keys: &[String],
        args: &[String],
    ) -> GarrisonResult<Vec<String>> {
        let key = keys.first().ok_or_else(|| {
            GarrisonError::InvalidParam("dao-eval-lua-missing-keys-1".to_string())
        })?;
        let ttl: u64 = parse_lua_arg(args, 1, "dao-eval-lua-argv-2-ttl")?;
        let count = self.incr(key, ttl).await?;
        Ok(vec![count.to_string()])
    }

    /// ZREMRANGEBYSCORE（limiteron SLIDING_WINDOW_SCRIPT，rc.6 契约）：原子 remove→count→check→add。
    /// rc.6 契约：KEYS=[窗口键, seq 键]、ARGV=[window_ms, max_requests]；时钟源在脚本内取 Redis TIME；
    /// seq 键生成成员唯一序号，模拟器以「追加时间戳列表」计数，天然区分同毫秒请求。
    async fn eval_lua_sliding_window_mode(
        &self,
        keys: &[String],
        args: &[String],
    ) -> GarrisonResult<Vec<String>> {
        let key = keys.first().ok_or_else(|| {
            GarrisonError::InvalidParam("dao-eval-lua-rl-missing-keys-1".to_string())
        })?;
        if keys.len() < 2 {
            return Err(GarrisonError::InvalidParam(
                "dao-eval-lua-rl-missing-keys-2-seq".to_string(),
            ));
        }
        let window_ms: u64 = parse_lua_arg(args, 0, "dao-eval-lua-rl-argv-1-window-ms")?;
        let max_requests: usize = parse_lua_arg(args, 1, "dao-eval-lua-rl-argv-2-max")?;
        // 时钟源对齐 rc.6 脚本语义（Redis TIME → 模拟器取系统墙钟毫秒）
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let window_start_ms = now_ms.saturating_sub(window_ms);

        // 单次 lock 内原子 remove-outdated → count → check → add；member=score=毫秒时间戳，
        // `parse_timestamps` 的 `t > window_start` 过滤与 `ZREMRANGEBYSCORE -inf window_start` 语义一致。
        let mut store = self.store.lock();
        let now = Instant::now();
        let mut members: Vec<u64> = match store.get(key) {
            Some((raw, Some(deadline))) if *deadline > now => {
                parse_timestamps(raw, window_start_ms)
            },
            Some((raw, None)) => parse_timestamps(raw, window_start_ms),
            _ => Vec::new(),
        };

        let current_count = members.len();
        let allowed = current_count < max_requests;
        if allowed {
            members.push(now_ms);
            // limiteron 脚本：EXPIRE key ceil(window_ms / 1000) + 1
            let ttl_secs = window_ms.div_ceil(1000) + 1;
            let expire_at = Some(now + Duration::from_secs(ttl_secs));
            let new_raw = members
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(",");
            store.insert(key.to_string(), (new_raw, expire_at));
        }
        let reset_time = window_start_ms + window_ms;
        Ok(vec![
            if allowed { "1" } else { "0" }.to_string(),
            current_count.to_string(),
            reset_time.to_string(),
        ])
    }
}

// ------------------------------------------------------------------------
// eval_lua 辅助函数
// ------------------------------------------------------------------------

/// 解析 Lua 脚本参数（消除重复的 missing/parse 错误处理）。
fn parse_lua_arg<T: std::str::FromStr>(
    args: &[String],
    index: usize,
    name: &str,
) -> GarrisonResult<T>
where
    T::Err: std::fmt::Display,
{
    let val = args
        .get(index)
        .ok_or_else(|| GarrisonError::InvalidParam(format!("dao-eval-lua-missing-{}", name)))?;
    val.parse().map_err(|e: T::Err| {
        GarrisonError::InvalidParam(format!("dao-eval-lua-{}-parse-failed::{}", name, e))
    })
}

/// 从逗号分隔的字符串中解析时间戳并过滤过期项。
fn parse_timestamps(raw: &str, window_start_ms: u64) -> Vec<u64> {
    raw.split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u64>().ok())
        .filter(|&t| t > window_start_ms)
        .collect()
}

// ------------------------------------------------------------------------
// glob 匹配 helper（用于 keys 方法，支持 `*` 与 `?`）
// ------------------------------------------------------------------------

/// glob 匹配：`*` 匹配 0+ 字符、`?` 匹配 1 字符（经典双指针，O(n+m)）；
/// `pub(crate)` 供 `protocol::apikey::list_by_namespace` 复用。
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

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

// ------------------------------------------------------------------------
// glob_match 单元测试（共享原语：keys() 与 oxcache_impl 复用，只测不改）
// ------------------------------------------------------------------------

#[cfg(test)]
mod glob_match_tests {
    use super::glob_match;

    /// 精确匹配（无通配符）：相等为 true，不等为 false。
    #[test]
    fn glob_match_exact() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "xyz"));
        // pattern 长于 text → false
        assert!(!glob_match("abcdef", "abc"));
    }

    /// `*` 匹配 0 个或多个字符：前缀 / 中缀 / 后缀 / 零字符。
    #[test]
    fn glob_match_star_variants() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("garrison:*", "garrison:apikey:abc"));
        assert!(glob_match("*:abc", "garrison:apikey:abc"));
        assert!(glob_match("a*bc", "abc")); // * 匹配 0 字符
        assert!(glob_match("a*bc", "aXXXbc")); // * 匹配多字符
        assert!(!glob_match("a*bc", "aXXXbd")); // 尾部不匹配
    }

    /// 回溯分支：`*` 贪心匹配过头后需回溯再尝试（经典双指针核心路径）。
    #[test]
    fn glob_match_star_backtracking() {
        // * 先吞掉 "XX"，遇 'c' 失败 → 回溯让 * 少吞一个字符
        assert!(glob_match("ab*cd", "abXXcd"));
        assert!(glob_match("*aab", "xaab"));
        // 回溯后仍无法匹配 → false
        assert!(!glob_match("ab*cd", "abXXce"));
    }

    /// 连续多个 `*` 等价于单个 `*`。
    #[test]
    fn glob_match_multiple_stars() {
        assert!(glob_match("a**b", "aXXb"));
        assert!(glob_match("**", "whatever"));
        assert!(glob_match("a*b*c", "a1b2c"));
        assert!(!glob_match("a*b*c", "a1b2d"));
    }

    /// `?` 精确匹配单个字符：任意字符可配，但不可配空 / 不可配多字符。
    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("key?", "key1"));
        assert!(!glob_match("key?", "key")); // ? 不可配空
        assert!(!glob_match("key?", "key12")); // ? 只配 1 字符
        assert!(glob_match("??", "ab"));
    }

    /// 末尾 `*` 跳过分支：text 耗尽后 pattern 仅剩 `*` → 匹配成功。
    #[test]
    fn glob_match_trailing_star_after_text_exhausted() {
        assert!(glob_match("abc*", "abc"));
        assert!(glob_match("a*", "a"));
    }

    /// 空输入边界：空 pattern 只匹配空 text。
    #[test]
    fn glob_match_empty_inputs() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
        assert!(glob_match("*", ""));
    }

    /// Unicode 按字符（而非字节）匹配：多字节字符可被 `?` 匹配单个字符。
    #[test]
    fn glob_match_unicode_chars() {
        assert!(glob_match("用户?", "用户A"));
        assert!(glob_match("*:租户:*", "garrison:租户:42"));
        assert!(!glob_match("用户?", "用户AB"));
    }
}

// ------------------------------------------------------------------------
// TTL 语义测试（update / expire 对已过期键视为不存在）
// ------------------------------------------------------------------------

#[cfg(test)]
mod ttl_semantics_tests {
    use super::*;

    /// update 对已过期 key 报 dao-key-missing 且不改值（与 `get()`/`keys()` 一致，不复活过期键）。
    #[tokio::test]
    async fn update_expired_key_returns_missing_without_reviving() {
        let dao = InMemoryDao::new();
        dao.set("upd_expired", "old", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = dao.update("upd_expired", "new").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-key-missing")),
            "已过期 key 的 update 应返回 dao-key-missing，实际: {:?}",
            result
        );
        assert!(
            dao.get("upd_expired").await.unwrap().is_none(),
            "update 过期键后键应保持不存在（不得复活）"
        );
    }

    /// expire 对已过期 key 报 dao-key-missing 且不续期（与 `get()`/`keys()` 一致，不复活过期键）。
    #[tokio::test]
    async fn expire_expired_key_returns_missing_without_reviving() {
        let dao = InMemoryDao::new();
        dao.set("exp_expired", "v", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = dao.expire("exp_expired", 3600).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-key-missing")),
            "已过期 key 的 expire 应返回 dao-key-missing，实际: {:?}",
            result
        );
        assert!(
            dao.get("exp_expired").await.unwrap().is_none(),
            "expire 过期键后键应保持不存在（不得复活）"
        );
    }

    /// 存活键的 update / expire 行为不受影响（回归：过期检查不误伤未过期键）。
    #[tokio::test]
    async fn update_and_expire_still_work_for_alive_keys() {
        let dao = InMemoryDao::new();
        dao.set("alive", "old", 3600).await.unwrap();
        dao.update("alive", "new").await.unwrap();
        assert_eq!(dao.get("alive").await.unwrap().as_deref(), Some("new"));
        dao.expire("alive", 120).await.unwrap();
        let ttl = dao.get_timeout("alive").await.unwrap();
        assert!(
            ttl.is_some() && ttl.unwrap() <= Duration::from_secs(120),
            "expire 应重置存活键 TTL"
        );
    }
}
