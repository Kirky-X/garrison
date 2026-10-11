// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 速率限制策略。
//!
//! `RateLimitStrategy` 实现 [`GarrisonFirewallStrategy`] trait，
//! 用 oxcache key `rl:{scope}:{id}` 以 Redis Sorted Set 存储请求时间戳
//! （member=score=毫秒时间戳），滑动窗口过滤过期时间戳后判断是否超阈值。
//! Lua 脚本取自 limiteron `oxcache_lua::SLIDING_WINDOW_SCRIPT`（库维护，
//! Sorted Set 版：每条目 O(1) 内存，替代早期手写的逗号时间戳串方案）。
//!
//! # 算法（滑动窗口，非固定窗口）
//!
//! 1. 根据 scope 构造 key：`rl:ip:{ip}` / `rl:user:{login_id}` / `rl:tenant:{tenant_id}`
//! 2. Lua 脚本内 `ZREMRANGEBYSCORE` 移除窗口外时间戳 → `ZCARD` 计数
//! 3. 计数 >= max_requests → 返回 `FirewallBlocked`
//! 4. 否则 `ZADD` 当前时间戳并 `EXPIRE`（窗口大小 + 1s，窗口无请求时自动过期）
//!
//! # 存储格式迁移
//!
//! 早期版本以逗号拼接时间戳字符串存储（`GET/SETEX`）。升级到 Sorted Set
//! 后旧格式 key 与 ZSET 命令不兼容（WRONGTYPE），存量 key 会在
//! `window_seconds + 1s` 内自然过期；过渡窗口内命中旧 key 的请求将收到
//! 错误（fail-close，不误放行）。
//!
//! # 与 BruteForce 的区别
//!
//! - BruteForce：固定窗口计数（update 保留 TTL，不重置窗口）
//! - RateLimit：滑动窗口（每次请求追加时间戳，过滤过期）
//! - 滑动窗口避免边界突刺（固定窗口在窗口边界处可能瞬间放过 2× max_requests）
//!
//! # 原子性保证
//!
//! `check` 方法优先调用 `GarrisonDao::eval_lua` 执行原子 read-filter-check-write
//! （Lua 脚本由 Redis 后端原子执行，`crate::dao::tests::MockDao` 也模拟此模式）。
//! 当后端不支持 Lua（返回 `GarrisonError::NotImplemented`，如 `GarrisonDaoOxcache`）时，
//! 降级到 `atomic_lock`（`parking_lot::Mutex`）保护的非原子路径，仅保证**进程内原子**。
//!
//! ## 跨进程限制
//!
//! 降级路径（oxcache 等不支持 Lua 的后端）仅进程内原子：
//! 多进程共享同一后端时仍存在 TOCTOU——`atomic_lock` 是
//! 进程内 `tokio::sync::Mutex`，各进程独立持锁，跨进程的 read-modify-write
//! 互相不可见，每个进程都可能在自己的写入可见前通过阈值检查。
//! 运行时无跨进程强制，缓解手段（二选一，文档化设计）：
//! - 启用 `rate-limit-redis` feature 切换 Redis 后端（支持 Lua 脚本）
//! - 或改用 [`crate::strategy::firewall::BruteForceStrategy`]（固定窗口，原子计数）
//!
//! # 与 BruteForce 的对比
//!
//! `BruteForceStrategy` 用 [`limiteron::limiters::DistributedLimiter`] 的 `incr_with_ttl`
//! 原子递增计数器，无 TOCTOU 风险。但 `incr_with_ttl` 是**固定窗口**计数器，
//! 无法满足滑动窗口语义（每次请求需过滤已过期的时间戳）。
//! 滑动窗口的过滤操作本质上是 read-modify-write，需要 Lua 脚本或锁保护。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::limiteron::distributed::GarrisonDaoDistributedLimiter;
use crate::limiteron::GarrisonDaoStorage;
use crate::strategy::firewall::{CaptchaChallenge, FirewallContext, GarrisonFirewallStrategy};
use async_trait::async_trait;
use limiteron::error::LimiteronError;
use limiteron::limiters::adaptive_threshold::{
    AdaptiveThresholdConfig, AdaptiveThresholdLimiter, Feedback,
};
use limiteron::storage::Storage;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// 自适应阈值观测窗样本数（错误率/延迟分位的统计基数）。
const ADAPTIVE_WINDOW_SAMPLES: usize = 20;
/// 触发调整所需最小样本数（冷启动期不抖动；1..=window_samples）。
const ADAPTIVE_MIN_SAMPLES: usize = 5;
/// 调整后冷却样本数（防振荡； garrison 原规则无冷却，库侧最小防抖）。
const ADAPTIVE_COOLDOWN_SAMPLES: usize = 5;

/// 速率限制作用域。
///
/// 决定计数 key 的构造维度：
/// - `Ip`：按请求 IP 计数（`rl:ip:{ip}`）
/// - `User`：按登录主体计数（`rl:user:{login_id}`）
/// - `Tenant`：按租户计数（`rl:tenant:{tenant_id}`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    /// 按请求 IP 计数。
    Ip,
    /// 按登录主体 login_id 计数。
    User,
    /// 按租户 tenant_id 计数。
    Tenant,
}

/// 速率限制配置。
///
/// 所有阈值显式配置（确定性逻辑），不交给模型判断。
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// 窗口内最大请求数（超阈值后拦截）。
    pub max_requests: u32,
    /// 窗口大小（秒），超过此时间的请求时间戳被滑出窗口。
    pub window_seconds: u64,
    /// 计数作用域（Ip / User / Tenant）。
    pub scope: RateLimitScope,
    /// 动态阈值上限。
    ///
    /// - `None`：禁用动态调整，固定使用 `max_requests` 作为阈值。
    /// - `Some(upper)`：允许 [`RateLimitStrategy::current_threshold`] 在
    ///   `[max_requests, upper]` 区间内根据历史流量动态调整。
    ///
    /// 调整规则见 [`RateLimitStrategy::adjust_threshold`]。
    pub dynamic_threshold: Option<usize>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        }
    }
}

impl RateLimitConfig {
    /// 校验配置合法性。
    ///
    /// # 错误
    /// - `max_requests` 为 0：Lua 脚本阈值比较恒拦截（所有请求被拒）。
    /// - `window_seconds` 为 0：Lua `SETEX` TTL=0 在 Redis 报错（写入丢失）。
    pub fn validate(&self) -> GarrisonResult<()> {
        if self.max_requests == 0 {
            return Err(GarrisonError::InvalidParam(
                "firewall-ratelimit-max-requests-zero::".to_string(),
            ));
        }
        if self.window_seconds == 0 {
            return Err(GarrisonError::InvalidParam(
                "firewall-ratelimit-window-seconds-zero::".to_string(),
            ));
        }
        Ok(())
    }
}

/// 速率限制策略，用 limiteron `Storage` trait 滑动窗口实现。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::dao::GarrisonDao;
/// use garrison::strategy::firewall::rate_limit::{RateLimitConfig, RateLimitScope, RateLimitStrategy};
///
/// let dao: Arc<dyn GarrisonDao> = /* oxcache 实现 */;
/// let config = RateLimitConfig {
/// max_requests: 10,
/// window_seconds: 1,
/// scope: RateLimitScope::Ip,
/// dynamic_threshold: None,
/// };
/// let strategy = RateLimitStrategy::new(config, dao);
/// ```
pub struct RateLimitStrategy {
    /// 配置（阈值 + 窗口 + 作用域）。
    config: RateLimitConfig,
    /// 存储（limiteron Storage 适配器，替换 dao 的 get/set/delete）。
    storage: Arc<dyn Storage>,
    /// 滑窗判定桥接（limiteron `DistributedLimiter` 适配器的
    /// `allow_sliding_window`）：Lua 主路径的脚本契约（KEYS/ARGV 形状、
    /// hash-tag seq 键、响应解析）收敛在此，策略层不再直连裸 `eval_lua`。
    limiter: Arc<GarrisonDaoDistributedLimiter>,
    /// 动态阈值内核（limiteron `AdaptiveThresholdLimiter`，AIMD）：
    /// `dynamic_threshold=Some` 时构造并承载阈值观测环与调整；`None` 时
    /// 为 None，阈值恒为 `max_requests`。进程内语义（per-instance 本地
    /// 视图），H-5 TOCTOU 窗口随 DAO RMW 的删除而消除。
    adaptive: Option<AdaptiveThresholdLimiter>,
    /// 进程内原子锁（降级路径）：保护 `eval_lua` 不可用时的
    /// read-modify-write。仅进程内原子，跨进程仍存在 TOCTOU（见模块文档）。
    ///
    /// # 已知限制：全局串行瓶颈
    ///
    /// 整个策略实例仅此一把锁，`check_fallback` 每请求必获取：不同 key
    /// （不同 IP/用户/租户）的降级路径检查相互**串行阻塞**，高吞吐下
    /// 丧失并发能力。这是正确性换吞吐的取舍：按 key 分锁（如 keyed mutex 池）
    /// 可缓解，但会显著增加复杂度，当前版本不做（保持降级路径简单可靠）。
    /// 需要并发吞吐的场景应启用支持 Lua 的后端（走原子滑窗路径，无锁）。
    atomic_lock: Mutex<()>,
}

impl RateLimitStrategy {
    /// 创建速率限制策略实例。
    ///
    /// 内部创建 [`GarrisonDaoStorage`] 适配器（get/set/delete）与
    /// [`GarrisonDaoDistributedLimiter`] 桥接（滑窗 Lua 判定）。
    ///
    /// # 参数
    /// - `config`: 配置（阈值 + 窗口 + 作用域 + 动态阈值上限）。
    /// - `dao`: DAO（oxcache 抽象，用于时间戳列表存储）。
    pub fn new(config: RateLimitConfig, dao: Arc<dyn GarrisonDao>) -> Self {
        let storage = Arc::new(GarrisonDaoStorage::new(dao.clone()));
        let adaptive = config.dynamic_threshold.map(|upper| {
            AdaptiveThresholdConfig {
                base_limit: u64::from(config.max_requests),
                // 下界/上界钉死配置区间； garrison 80%/20% 交通量带映射为
                // 库 Feedback 的 ok 槽位（见 adjust_threshold 文档）。
                min_limit: u64::from(config.max_requests),
                max_limit: upper as u64,
                window_samples: ADAPTIVE_WINDOW_SAMPLES,
                min_samples_for_adjust: ADAPTIVE_MIN_SAMPLES,
                // error_rate = 低负载样本比：≥0.8 持续低负载 → 降；
                // ≤0.2 持续高负载 → 升（与 garrison 20%/80% 带对应）。
                error_rate_increase_threshold: 0.8,
                error_rate_decrease_threshold: 0.2,
                // 无延迟信号：延迟通道恒不触发调整（latency_ms 恒 0）。
                latency_increase_ms: u64::MAX,
                latency_decrease_ms: u64::MAX,
                // garrison 线性步长（max/10，至少 1）；乘性减取 0.9 近似
                // 其降步区间 [upper/10, max/10]，防振荡由冷却期承载。
                increase_step: (u64::from(config.max_requests) / 10).max(1),
                decrease_ratio: 0.9,
                cooldown_samples: ADAPTIVE_COOLDOWN_SAMPLES,
            }
        });
        Self {
            config,
            storage,
            limiter: Arc::new(GarrisonDaoDistributedLimiter::new(dao)),
            adaptive: adaptive
                .map(AdaptiveThresholdLimiter::with_validation)
                .transpose()
                .unwrap_or_else(|e| {
                    // 配置由 garrison 侧显式构造（区间已保证 min<=base<=max），
                    // 库校验失败属配置构造缺陷，fail-loud 不静默降级。
                    panic!("rate_limit: AdaptiveThresholdConfig invalid: {e}")
                }),
            atomic_lock: Mutex::new(()),
        }
    }

    /// 设置期望的验证码答案，供后续 [`CaptchaChallenge::verify_challenge`] 比对。
    ///
    /// 存储在 DAO 中（key 由 scope+id 派生，与计数 key 同前缀），TTL 与窗口一致，
    /// 窗口无后续请求时自动过期。
    ///
    /// # 参数
    /// - `ctx`: 防火墙上下文。
    /// - `answer`: 期望答案（明文，由调用方负责生成 captcha 图像）。
    pub async fn set_expected_answer(
        &self,
        ctx: &FirewallContext,
        answer: &str,
    ) -> GarrisonResult<()> {
        let (key, _) = self.build_key(ctx)?;
        // key 形如 `rl:ip:{ip}`，答案 key 复用前缀并追加 `:answer`
        let answer_key = format!("{}:answer", key);
        self.storage
            .set(&answer_key, answer, Some(self.config.window_seconds))
            .await
            .map_err(|e| GarrisonError::Dao(format!("strategy-limiter-storage::{}", e)))
    }

    /// 返回当前生效的速率阈值。
    ///
    /// - `dynamic_threshold=None` 时恒返回 `max_requests`。
    /// - `dynamic_threshold=Some(_)` 时返回自适应阈值器当前限额
    ///   （区间 `[max_requests, dynamic_threshold]`，由 limiteron
    ///   `AdaptiveThresholdLimiter` 的配置校验承载钳制）。
    ///
    /// 进程内语义：阈值为策略实例的本地视图（多实例部署各节点按自身流量
    /// 调整，与 Envoy / Netflix concurrency-limits 的 per-node 口径一致）；
    /// 调整由 [`adjust_threshold`](Self::adjust_threshold) 的反馈驱动。
    pub async fn current_threshold(&self, ctx: &FirewallContext) -> GarrisonResult<usize> {
        let max = self.config.max_requests as usize;
        let Some(_upper) = self.config.dynamic_threshold else {
            return Ok(max);
        };
        let (_, _) = self.build_key(ctx)?;
        // `ctx` 仅用于签名兼容与调用方校验（scope 缺省仍显性失败）；
        // 阈值不再按 key 持久化（进程内自适应），故不参与取值。
        Ok(self
            .adaptive
            .as_ref()
            .map_or(max, |a| a.current_limit() as usize))
    }

    /// 根据观测到的历史流量调整阈值（委托 limiteron `AdaptiveThresholdLimiter`）。
    ///
    /// garrison 历史规则（`traffic_count >= current × 80%` 升一步、`< 20%`
    /// 降一步，步长 `max/10`）映射为库的 AIMD 反馈：**`ok` 槽位借用 garrison
    /// 高负载带语义**——`ok = traffic_count >= current × 80%`；`latency_ms`
    /// 恒 0（garrison 限流路径无延迟信号，交付纯交通量驱动）。据此：
    /// - 「低负载样本比」= 库的 `error_rate`；`error_rate ≥ 0.8`
    ///   （持续低负载）→ 降，`error_rate ≤ 0.2`（持续高负载）→ 升，
    ///   与 garrison 80%/20% 带逐带对应；
    /// - `increase_step = max(1, max_requests/10)`（ garrison 步长原值），
    ///   `decrease_ratio = 0.9`（乘性减，近似 garrison 线性降步的
    ///   `[upper/10, max/10]` 步长区间，防振荡语义由库冷却期承载）。
    ///
    /// **行为差异（显式声明）**：调整节拍从 garrison 的「每次调用即判」
    /// 变为库的「每 `min_samples_for_adjust` 个样本 + 冷却期」——平滑性
    /// 增强、单次调用到生效有采样滞后，测试按新节拍语义钉住。
    ///
    /// H-5 TOCTOU 窗口随 DAO read-modify-write 的删除而消除（进程内原子
    /// 观测环；`AdaptiveThresholdLimiter::report` 单锁完成入环与判定）。
    ///
    /// # 返回
    /// 调整后的当前阈值（`dynamic_threshold=None` 时恒为 `max_requests`）。
    pub async fn adjust_threshold(
        &self,
        ctx: &FirewallContext,
        traffic_count: usize,
    ) -> GarrisonResult<usize> {
        let max = self.config.max_requests as usize;
        let Some(adaptive) = &self.adaptive else {
            return Ok(max);
        };
        // scope 缺省仍显性失败（与 check/current_threshold 一致的前置校验）
        let (_, _) = self.build_key(ctx)?;

        let current = adaptive.current_limit() as usize;
        // garrison 高负载带（`traffic_count × 5 >= current × 4`，整数运算免浮点）
        // 映射为库 Feedback 的 ok 槽位（借用语义，见方法文档）。
        let feedback = Feedback {
            ok: traffic_count.saturating_mul(5) >= current.saturating_mul(4),
            latency_ms: 0,
        };
        adaptive.report(feedback);
        Ok(adaptive.current_limit() as usize)
    }

    /// 根据作用域构造计数 key 并返回作用域标识（用于错误消息）。
    ///
    /// # 错误
    /// - `scope=User` 且 `ctx.login_id` 为 None → `InvalidParam`（显性失败）
    /// - `scope=Tenant` 且 `ctx.tenant_id` 为 None → `InvalidParam`
    fn build_key(&self, ctx: &FirewallContext) -> GarrisonResult<(String, String)> {
        match self.config.scope {
            RateLimitScope::Ip => Ok((format!("rl:ip:{}", ctx.ip), ctx.ip.clone())),
            RateLimitScope::User => match &ctx.login_id {
                Some(id) => Ok((format!("rl:user:{}", id), id.clone())),
                None => Err(GarrisonError::InvalidParam(
                    "firewall-ratelimit-user-none::".to_string(),
                )),
            },
            RateLimitScope::Tenant => match ctx.tenant_id {
                Some(id) => Ok((format!("rl:tenant:{}", id), id.to_string())),
                None => Err(GarrisonError::InvalidParam(
                    "firewall-ratelimit-tenant-none::".to_string(),
                )),
            },
        }
    }
}

#[async_trait]
impl GarrisonFirewallStrategy for RateLimitStrategy {
    async fn check(&self, ctx: &FirewallContext) -> GarrisonResult<()> {
        // 配置守卫：window/threshold 为 0 时 Lua 路径 SETEX TTL=0 会报错、
        // 阈值 0 会恒拦截，显性返回 InvalidParam（fail-fast）
        self.config.validate()?;
        let (key, scope_id) = self.build_key(ctx)?;

        // 阈值提前读取（Lua 路径与降级路径共用）
        // 已知限制（同族 TOCTOU）：阈值读取在 eval_lua 原子边界之外，
        // 与并发的 adjust_threshold 之间存在竞争窗口——若 adjust 恰在此间隙持久化
        // 新阈值，本次 Lua/降级判断仍用旧值（偏高或偏低一个步长，自愈于下一次请求）。
        // 将阈值读取纳入 Lua 脚本内（KEYS/ARGV 之外读 Dao）超出 Redis 脚本能力，
        // 当前版本保留该窗口（与 adjust_threshold 的 同类处理一致：文档声明，不修复）。
        let threshold = self.current_threshold(ctx).await?;

        // 滑窗判定经桥接件（`allow_sliding_window`）：脚本契约（KEYS=[窗口键,
        // {窗口键}:seq]、ARGV=[window_ms, threshold]、响应 {allowed,count,reset}）
        // 与 hash tag 共置语义收敛在 `GarrisonDaoDistributedLimiter`，策略层
        // 不再直连裸 `eval_lua`。Redis 后端 / MockDao 支持此模式，在单次
        // 原子操作内完成 read-filter-check-write。
        let lua_result = self
            .limiter
            .allow_sliding_window(&key, self.config.window_seconds * 1000, threshold as u64)
            .await;
        match lua_result {
            Ok((true, _, _)) => Ok(()),
            Ok((false, _, _)) => {
                // 空结果/解析异常由桥接件 fail-close（allowed=false），不误放行
                Err(GarrisonError::FirewallBlocked(format!(
                    "strategy-firewall-ratelimit-blocked::{}::{}::lua::{}",
                    scope_id,
                    format!("{:?}", self.config.scope).to_lowercase(),
                    threshold
                )))
            },
            Err(e) if is_lua_unsupported(&e) => {
                // 后端不支持 Lua：降级到 atomic_lock 保护的非原子路径（进程内原子）
                tracing::debug!(
                    "rate_limit: sliding window unsupported by backend, falling back to atomic_lock path (in-process atomic only)"
                );
                self.check_fallback(&key, &scope_id, threshold).await
            },
            Err(e) => {
                // 其他错误（存储/配置）显性抛出
                Err(GarrisonError::Dao(format!(
                    "strategy-limiter-eval-lua::{}",
                    e
                )))
            },
        }
    }
}

/// 判定桥接错误是否为「后端不支持 Lua」。
///
/// `map_to_limiter_err` 将 `GarrisonError::NotImplemented` 压平为
/// `LimiteronError::StorageError(QueryError)`（Debug 形式保留在消息内），
/// 故按消息特征识别——策略层据此选择 atomic_lock 降级路径。
fn is_lua_unsupported(e: &LimiteronError) -> bool {
    matches!(e, LimiteronError::StorageError(_)) && format!("{e}").contains("NotImplemented")
}

impl RateLimitStrategy {
    /// 降级路径：`eval_lua` 不可用时，用 `atomic_lock` 保护 read-modify-write。
    ///
    /// **仅进程内原子**：跨进程共享同一 DAO 后端时仍存在 TOCTOU（见模块文档）。
    ///
    /// 与 `check` 主体共享算法（read → filter → check → write），但在
    /// `let _guard = self.atomic_lock.lock()` 作用域内执行，保证同进程内
    /// 不会有并发调用穿插。
    async fn check_fallback(
        &self,
        key: &str,
        scope_id: &str,
        threshold: usize,
    ) -> GarrisonResult<()> {
        // 进程内原子锁：保护 read-modify-write
        // tokio::sync::Mutex 可跨 await 持有（parking_lot::Mutex 不可跨 await）。
        let _guard = self.atomic_lock.lock().await;

        let timestamps = self.read_window(key).await?;

        // 剩余数量 >= 当前阈值 → 拦截
        if timestamps.len() >= threshold {
            return Err(GarrisonError::FirewallBlocked(format!(
                "strategy-firewall-ratelimit-blocked::{}::{}::{}::{}",
                scope_id,
                format!("{:?}", self.config.scope).to_lowercase(),
                timestamps.len(),
                threshold
            )));
        }

        // 追加当前时间戳，回写（TTL=window_seconds，窗口无请求时自动过期）。
        // 时钟与 Lua 主路径同源语义（墙钟毫秒；Redis 后端下脚本内 TIME）。
        let now_ms = self.now_ms()?;
        let mut timestamps = timestamps;
        timestamps.push(now_ms);
        let serialized: String = timestamps
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.storage
            .set(key, &serialized, Some(self.config.window_seconds))
            .await
            .map_err(|e| GarrisonError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        Ok(())
    }

    /// 读取窗口内未过期的时间戳列表（降级路径与验证码挑战共用的唯一计数实现）。
    ///
    /// 存储格式与 Lua 主路径一致（逗号分隔毫秒时间戳，`storage` 读写同一 key），
    /// 降级路径追加写、`should_challenge` 只读计数——两份消费方共享本方法，
    /// 不再各自维护一份过滤/解析逻辑。
    async fn read_window(&self, key: &str) -> GarrisonResult<Vec<u64>> {
        let now_ms = self.now_ms()?;
        let window_start = now_ms.saturating_sub(self.config.window_seconds * 1000);
        let stored = self
            .storage
            .get(key)
            .await
            .map_err(|e| GarrisonError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        // parse 失败时 warn 记录脏数据，不静默丢弃
        Ok(stored
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| match s.parse::<u64>() {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(key = %key, raw = %s, "rate_limit: timestamp parse failed, skipping entry (possible storage layer concurrent write truncation)");
                    None
                }
            })
            .filter(|&t| t > window_start)
            .collect())
    }

    /// 当前墙钟毫秒（降级路径时钟；Lua 主路径时钟由脚本内 Redis TIME 承担）。
    fn now_ms(&self) -> GarrisonResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| GarrisonError::Dao(format!("strategy-system-time::{}", e)))
    }
}

#[async_trait]
impl CaptchaChallenge for RateLimitStrategy {
    async fn should_challenge(&self, ctx: &FirewallContext) -> GarrisonResult<bool> {
        // 同 check：0 值配置显性拒绝
        self.config.validate()?;
        let (key, _) = self.build_key(ctx)?;

        // 与降级路径共用唯一的窗口计数实现（read_window，只读不消费配额）；
        // 早期此处曾维护第三份时间戳解析/过滤副本，已收敛。
        let count = self.read_window(&key).await?.len();

        let threshold = self.current_threshold(ctx).await?;
        // 80% 阈值触发挑战（整数运算避免浮点）
        // count >= threshold * 4/5 <=> count * 5 >= threshold * 4
        Ok(count.saturating_mul(5) >= threshold.saturating_mul(4))
    }

    async fn verify_challenge(&self, ctx: &FirewallContext, answer: &str) -> GarrisonResult<bool> {
        let (key, _) = self.build_key(ctx)?;
        let answer_key = format!("{}:answer", key);
        let stored = self
            .storage
            .get(&answer_key)
            .await
            .map_err(|e| GarrisonError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        let matched = stored.as_deref() == Some(answer);
        if matched {
            self.storage
                .delete(&answer_key)
                .await
                .map_err(|e| GarrisonError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        }
        Ok(matched)
    }
}

inventory::submit! {
    crate::strategy::firewall::StrategyRegistration {
        name: "ratelimit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::GarrisonError;

    /// 验证速率限制：max_requests=10, window_seconds=1 时，
    /// 1 秒内前 10 次返回 Ok，第 11 次返回 FirewallBlocked
    #[tokio::test]
    async fn ratelimit_blocks_after_max_requests() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 1,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        for i in 1..=10 {
            assert!(strategy.check(&ctx).await.is_ok(), "第 {} 次应通过", i);
        }

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(&result, Err(GarrisonError::FirewallBlocked(msg)) if msg.contains("strategy-firewall-ratelimit-blocked")),
            "第 11 次应返回 FirewallBlocked（错误串含 strategy-firewall-ratelimit-blocked），实际: {:?}",
            result
        );
    }

    /// 滑窗桥接路径的错误串契约：被拒时含作用域标识与 `lua` 路径标记
    /// （`strategy-firewall-ratelimit-blocked::{scope_id}::{scope}::lua::{threshold}`）。
    #[tokio::test]
    async fn ratelimit_block_error_string_contract() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 2,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("203.0.113.9");

        strategy.check(&ctx).await.unwrap();
        strategy.check(&ctx).await.unwrap();
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(&result, Err(GarrisonError::FirewallBlocked(msg))
                if msg.contains("strategy-firewall-ratelimit-blocked::203.0.113.9::ip::lua::2")),
            "错误串应含 scope_id/scope/lua/阈值，实际: {:?}",
            result
        );
    }

    /// 验证 scope=User 时按 login_id 计数，不同用户互不影响。
    #[tokio::test]
    async fn ratelimit_scope_user_isolates_by_login_id() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 2,
            window_seconds: 60,
            scope: RateLimitScope::User,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);

        let ctx_a = FirewallContext::new("192.168.1.1").with_login_id("1001");
        let ctx_b = FirewallContext::new("192.168.1.2").with_login_id("1002");

        assert!(strategy.check(&ctx_a).await.is_ok());
        assert!(strategy.check(&ctx_a).await.is_ok());
        assert!(matches!(
            strategy.check(&ctx_a).await,
            Err(GarrisonError::FirewallBlocked(_))
        ));
        // 用户 B 仍有额度
        assert!(strategy.check(&ctx_b).await.is_ok());
    }

    /// 验证 scope=User 且 login_id=None 时返回 InvalidParam（显性失败）。
    #[tokio::test]
    async fn ratelimit_scope_user_without_login_id_fails() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::User,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1"); // 无 login_id

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "scope=User 且 login_id=None 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // 验证码挑战 + 动态阈值测试
    // ========================================================================

    /// 接近阈值时 should_challenge 返回 true（80% 阈值触发挑战）。
    ///
    /// max_requests=10，调用 check 8 次后到达 80%，应触发挑战。
    #[tokio::test]
    async fn captcha_challenge_should_trigger_when_rate_limit_near() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 消耗 8/10 = 80% 配额（每次失败都显性 panic 并携带错误上下文）
        for k in 0..8 {
            if let Err(e) = strategy.check(&ctx).await {
                panic!("第 {k} 次调用失败: {e:?}");
            }
        }

        let should = strategy
            .should_challenge(&ctx)
            .await
            .expect("should_challenge 不应报错");
        assert!(should, "达到 80% 阈值时应触发验证码挑战，实际: {}", should);
    }

    /// 远低于阈值时 should_challenge 返回 false。
    ///
    /// max_requests=10，仅 1 次请求（10%），不应触发挑战。
    #[tokio::test]
    async fn captcha_challenge_should_not_trigger_when_below_threshold() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 仅 1 次请求（10%），远低于 80% 阈值
        strategy.check(&ctx).await.expect("check 不应报错");

        let should = strategy
            .should_challenge(&ctx)
            .await
            .expect("should_challenge 不应报错");
        assert!(!should, "远低于阈值时不应触发挑战，实际: {}", should);
    }

    /// 正确答案通过 verify_challenge 验证。
    #[tokio::test]
    async fn captcha_challenge_verify_correct_answer() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig::default();
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        strategy
            .set_expected_answer(&ctx, "abc123")
            .await
            .expect("set_expected_answer 不应报错");

        let ok = strategy
            .verify_challenge(&ctx, "abc123")
            .await
            .expect("verify_challenge 不应报错");
        assert!(ok, "正确答案应通过验证");
    }

    /// 错误答案验证失败。
    #[tokio::test]
    async fn captcha_challenge_verify_incorrect_answer() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig::default();
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        strategy
            .set_expected_answer(&ctx, "abc123")
            .await
            .expect("set_expected_answer 不应报错");

        let ok = strategy
            .verify_challenge(&ctx, "wrong-answer")
            .await
            .expect("verify_challenge 不应报错");
        assert!(!ok, "错误答案应验证失败");
    }

    /// C-6: 验证码验证通过后立即删除，防止复用。
    #[tokio::test]
    async fn captcha_challenge_verify_deletes_answer_after_success() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig::default();
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        strategy
            .set_expected_answer(&ctx, "abc123")
            .await
            .expect("set_expected_answer 不应报错");

        let first = strategy
            .verify_challenge(&ctx, "abc123")
            .await
            .expect("首次 verify_challenge 不应报错");
        assert!(first, "首次正确答案应通过");

        // 第二次同一答案应失败（验证码已被删除，C-6 修复）
        let second = strategy
            .verify_challenge(&ctx, "abc123")
            .await
            .expect("二次 verify_challenge 不应报错");
        assert!(
            !second,
            "验证码验证通过后应被删除，二次使用同一答案应失败（C-6）"
        );
    }

    /// 流量持续高时阈值上调（limiteron AIMD 节拍：每 min_samples+冷却一次调整）。
    ///
    /// max_requests=10, dynamic_threshold=Some(20)。初始阈值 10；持续高负载
    /// 反馈（ok=true，error_rate=0 ≤ 0.2）经库判定点逐步升到上限 20。
    #[tokio::test]
    async fn dynamic_threshold_increases_when_traffic_high() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 初始阈值 = max_requests = 10
        let initial = strategy
            .current_threshold(&ctx)
            .await
            .expect("current_threshold 不应报错");
        assert_eq!(initial, 10, "初始阈值应为 max_requests");

        // 高负载带持续反馈直到封顶 20：feedback 的 traffic 取当前阈值本身
        //（threshold >= 80% of threshold 恒成立，模拟「负载随容量同比」的
        // 高负载带）；节拍为采样驱动（min_samples=5 + 冷却 5，每 5 样本判定）。
        let mut current = initial;
        for _ in 0..300 {
            current = strategy
                .adjust_threshold(&ctx, current)
                .await
                .expect("adjust_threshold 不应报错");
            assert!(current <= 20, "阈值不得超过 dynamic_threshold 上限");
        }
        assert_eq!(current, 20, "持续高负载应最终封顶到 20，实际: {}", current);
    }

    /// AIMD 节拍契约：冷启动 min_samples 内不调整，判定点才升/降。
    ///
    /// min_samples_for_adjust=5：前 4 次反馈不产生调整，第 5 次（判定点）
    /// 高负载样本触发第一次上调。
    #[tokio::test]
    async fn dynamic_threshold_adjusts_only_at_decision_points() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        for i in 1..=4 {
            let t = strategy.adjust_threshold(&ctx, 9).await.unwrap();
            assert_eq!(t, 10, "第 {i} 次反馈（< min_samples）不应调整");
        }
        let at_decision = strategy.adjust_threshold(&ctx, 9).await.unwrap();
        assert!(
            at_decision > 10,
            "第 5 次反馈（判定点）高负载应上调，实际: {}",
            at_decision
        );
    }

    /// 流量持续低时阈值下调。
    ///
    /// 先用高负载把阈值推到上限，再用低负载（traffic=0）持续反馈，
    /// 乘性减（×0.9）+ 下限钳制（max_requests）最终触底。
    #[tokio::test]
    async fn dynamic_threshold_decreases_when_traffic_low() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 先用高负载把阈值推到封顶 20（traffic 取当前阈值：恒在高负载带）
        let mut current = 10;
        for _ in 0..300 {
            current = strategy.adjust_threshold(&ctx, current).await.unwrap();
        }
        let peaked = strategy.current_threshold(&ctx).await.unwrap();
        assert_eq!(peaked, 20, "高负载应将阈值推到上限，实际: {}", peaked);

        // 低负载（0 < 20% of 20）持续反馈直到下限 10
        let mut current = peaked;
        for _ in 0..300 {
            current = strategy.adjust_threshold(&ctx, 0).await.unwrap();
            assert!(current >= 10, "阈值不得低于 max_requests");
        }
        assert_eq!(current, 10, "持续低负载应触底到 10，实际: {}", current);
    }

    /// 动态阈值上调后 check 使用新阈值而非 max_requests（回归测试）。
    ///
    /// max_requests=10, dynamic_threshold=Some(20)。持续高负载反馈把阈值推到
    /// 20 后，check 应使用 current_threshold=20：前 20 次通过、第 21 次拦截
    /// （旧 bug：check 恒用 max_requests=10 会提前拦截）。
    #[tokio::test]
    async fn check_uses_dynamic_threshold_not_max_requests() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 持续高负载反馈直到阈值封顶 20（traffic 取当前阈值：恒在高负载带）
        let mut current = 10;
        for _ in 0..300 {
            current = strategy.adjust_threshold(&ctx, current).await.unwrap();
        }
        let current = strategy.current_threshold(&ctx).await.unwrap();
        assert_eq!(current, 20, "阈值应已上调到 20，实际: {}", current);

        // 前 20 次 check 全部通过（第 N 次成功后列表 N 个时间戳，N<20 通过）
        for i in 1..=20 {
            assert!(
                strategy.check(&ctx).await.is_ok(),
                "动态阈值=20 时第 {} 次 check 应通过（旧 bug 会在此拦截）",
                i
            );
        }

        // 第 21 次应被拦截（timestamps.len()=20 >= threshold=20）
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "动态阈值=20 时第 21 次 check 应被拦截，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // 并发 check 同一 key 仅 max_requests 个返回 Ok
    // ========================================================================

    /// 并发 check 同一 key 仅 max_requests 个返回 Ok（Lua 原子路径）。
    ///
    /// 场景：max_requests=5，并发发起 20 个 check 请求。
    /// 修复前（非原子 read-modify-write）：多个线程读到相同 timestamps 列表，
    /// 各自通过阈值检查后回写，可能放过远超 max_requests 的请求（最坏 ~2× 并发数）。
    /// 修复后（eval_lua 原子路径）：MockDao 在单次 lock() 内执行 read-filter-check-write，
    /// 仅 max_requests 个返回 Ok，其余返回 FirewallBlocked。
    ///
    /// MockDao 支持 eval_lua 滑动窗口模式（识别 limiteron 脚本的 `ZREMRANGEBYSCORE` 特征）。
    #[tokio::test(flavor = "multi_thread")]
    async fn check_concurrent_only_max_requests_allowed_lua_path() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 5,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = Arc::new(RateLimitStrategy::new(config, dao));
        let ctx = Arc::new(FirewallContext::new("10.0.0.1"));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let s = strategy.clone();
            let c = ctx.clone();
            handles.push(tokio::spawn(async move { s.check(&c).await }));
        }

        let mut allowed = 0;
        let mut blocked = 0;
        for handle in handles {
            match handle.await.expect("tokio task panicked") {
                Ok(()) => allowed += 1,
                Err(GarrisonError::FirewallBlocked(_)) => blocked += 1,
                Err(e) => {
                    panic!("check 不应返回非 FirewallBlocked 错误: {:?}", e);
                },
            }
        }
        assert_eq!(
            allowed, 5,
            "Lua 路径：并发 check 仅 max_requests=5 个返回 Ok（防 TOCTOU 绕过），实际: {}",
            allowed
        );
        assert_eq!(blocked, 15, "其余 15 个应被拦截");
    }

    /// 并发 check 同一 key 仅 max_requests 个返回 Ok（降级路径）。
    ///
    /// 使用 `MinimalDao`（不重写 `eval_lua`，默认返回 `NotImplemented`）触发降级路径，
    /// 验证 `atomic_lock` 保护的 read-modify-write 在进程内原子。
    ///
    /// 场景同上：max_requests=5，并发 20 个 check，仅 5 个 Ok。
    #[tokio::test(flavor = "multi_thread")]
    async fn check_concurrent_only_max_requests_allowed_fallback_path() {
        use crate::dao::tests::MinimalDao;

        let dao: Arc<dyn GarrisonDao> = Arc::new(MinimalDao::new());
        let config = RateLimitConfig {
            max_requests: 5,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = Arc::new(RateLimitStrategy::new(config, dao));
        let ctx = Arc::new(FirewallContext::new("10.0.0.2"));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let s = strategy.clone();
            let c = ctx.clone();
            handles.push(tokio::spawn(async move { s.check(&c).await }));
        }

        let mut allowed = 0;
        let mut blocked = 0;
        for handle in handles {
            match handle.await.expect("tokio task panicked") {
                Ok(()) => allowed += 1,
                Err(GarrisonError::FirewallBlocked(_)) => blocked += 1,
                Err(e) => {
                    panic!("check 不应返回非 FirewallBlocked 错误: {:?}", e);
                },
            }
        }
        assert_eq!(
            allowed, 5,
            "降级路径：atomic_lock 保护下并发 check 仅 max_requests=5 个返回 Ok，实际: {}",
            allowed
        );
        assert_eq!(blocked, 15, "其余 15 个应被拦截");
    }

    /// 验证 Lua 路径下单次 check 行为与原有非原子路径一致。
    ///
    /// max_requests=3，串行 check 4 次：前 3 次通过，第 4 次拦截。
    /// 确保 eval_lua 路径不破坏既有串行语义。
    #[tokio::test]
    async fn check_lua_path_preserves_serial_semantics() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 3,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("10.0.0.3");

        assert!(strategy.check(&ctx).await.is_ok(), "第 1 次 check 应通过");
        assert!(strategy.check(&ctx).await.is_ok(), "第 2 次 check 应通过");
        assert!(strategy.check(&ctx).await.is_ok(), "第 3 次 check 应通过");
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "第 4 次 check 应被拦截，实际: {:?}",
            result
        );
    }

    /// 0 值配置显性拒绝：max_requests=0 / window_seconds=0
    /// 时 check 返回 InvalidParam，而非恒拦截 / SETEX TTL=0 报错。
    #[tokio::test]
    async fn zero_config_values_rejected_with_invalid_param() {
        let ctx = FirewallContext::new("10.0.1.1");

        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let strategy = RateLimitStrategy::new(
            RateLimitConfig {
                max_requests: 0,
                window_seconds: 60,
                scope: RateLimitScope::Ip,
                dynamic_threshold: None,
            },
            dao,
        );
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "max_requests=0 应返回 InvalidParam，实际: {:?}",
            result
        );

        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let strategy = RateLimitStrategy::new(
            RateLimitConfig {
                max_requests: 10,
                window_seconds: 0,
                scope: RateLimitScope::Ip,
                dynamic_threshold: None,
            },
            dao,
        );
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "window_seconds=0 应返回 InvalidParam，实际: {:?}",
            result
        );
    }
}
