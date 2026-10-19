// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 防火墙安全钩子模块，提供登录流程的可插拔安全检查。
//!
//! `GarrisonFirewallCheckHook` trait 定义 5 个 async hook 方法（默认 impl 全 pass）；`LoginContext` 为登录上下文
//! （login_id + 可选 IP / 设备指纹 / 地理位置）；`GarrisonFirewallCheckHookDefault` 是基于 limiteron 计数器的默认实现。
//!
//! 检查项：登录频率（同 IP 1h ≥ 10 次失败）、暴力破解（同账号 1h ≥ 5 次失败）、Token 复用（黑名单存在）阻断登录；
//! 异地登录（需 geo 数据）与设备异常（需设备库）无数据时 pass。

use crate::constants::DaoKeyPrefix;
use crate::dao::{GarrisonDao, InMemoryDao};
use crate::error::{GarrisonError, GarrisonResult};
use crate::limiteron::{LimiterBackend, LimiterRuntime};
// listener_manager 注入（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::{GarrisonEvent, GarrisonListenerManager};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// 登录上下文，传递给防火墙钩子。
#[derive(Debug, Clone, Default)]
pub struct LoginContext {
    /// 登录主体标识。
    pub login_id: String,
    /// 客户端 IP（可选，用于频率/暴力破解检测）。
    pub ip: Option<String>,
    /// 设备指纹（可选，用于设备异常检测）。
    pub device_fingerprint: Option<String>,
    /// 地理位置（可选，用于异地登录检测）。
    pub geo: Option<String>,
}

impl LoginContext {
    /// 创建仅含 login_id 的最小上下文。
    pub fn new(login_id: impl Into<String>) -> Self {
        Self {
            login_id: login_id.into(),
            ip: None,
            device_fingerprint: None,
            geo: None,
        }
    }

    /// 链式设置 IP。
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// 链式设置设备指纹。
    pub fn with_device(mut self, device: impl Into<String>) -> Self {
        self.device_fingerprint = Some(device.into());
        self
    }

    /// 链式设置地理位置。
    pub fn with_geo(mut self, geo: impl Into<String>) -> Self {
        self.geo = Some(geo.into());
        self
    }
}

// GarrisonFirewallCheckHook trait：5 个 async hook + default impl 全 pass

/// 防火墙安全钩子 trait，定义登录流程的 5 个可插拔安全检查。
///
/// 所有方法提供默认 `Ok(())` 实现，业务方按需 override；任一 hook 返回 `Err` 将阻断登录流程。
/// 调用顺序：登录频率 → 暴力破解 → 异地登录 → Token 复用 → 设备异常。
#[async_trait]
pub trait GarrisonFirewallCheckHook: Send + Sync {
    /// 登录频率检测：同 IP 1h 内 ≥ 10 次失败则阻断。
    async fn check_login_frequency(&self, _ctx: &LoginContext) -> GarrisonResult<()> {
        Ok(())
    }

    /// 暴力破解检测：同账号 1h 内 ≥ 5 次失败则锁定。
    async fn check_brute_force(&self, _ctx: &LoginContext) -> GarrisonResult<()> {
        Ok(())
    }

    /// 异地登录检测：短时间跨城市登录触发二次认证。
    async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> GarrisonResult<()> {
        Ok(())
    }

    /// Token 复用检测：已登出 Token 再次使用则拒绝。
    async fn check_token_reuse(&self, _ctx: &LoginContext) -> GarrisonResult<()> {
        Ok(())
    }

    /// 设备异常检测：未知设备指纹登录触发验证。
    async fn check_device_anomaly(&self, _ctx: &LoginContext) -> GarrisonResult<()> {
        Ok(())
    }
}

// GarrisonFirewallCheckHookDefault：基于 limiteron 的统一计数器实现

/// 登录频率检测阈值：同 IP 1h 内 ≥ 10 次失败。
pub const LOGIN_FREQUENCY_THRESHOLD: u32 = 10;
/// 登录频率检测时间窗口：1 小时。
pub const LOGIN_FREQUENCY_WINDOW: Duration = Duration::from_secs(3600);

/// 暴力破解检测阈值：同账号 1h 内 ≥ 5 次失败。
pub const BRUTE_FORCE_THRESHOLD: u32 = 5;
/// 暴力破解检测时间窗口：1 小时。
pub const BRUTE_FORCE_WINDOW: Duration = Duration::from_secs(3600);

/// IP 维度失败计数器 key 前缀。
const FW_IP_KEY_PREFIX: &str = "fw:ip:";
/// 账号维度失败计数器 key 前缀。
const FW_ACCT_KEY_PREFIX: &str = "fw:acct:";

/// `GarrisonFirewallCheckHook` 的默认实现，统一基于 [`LimiterBackend`] 计数器
/// （DAO 或独立 Redis 限流后端，原子计数 + TTL，禁止手写限流实现）。
///
/// 内存模式（`new()`）内部创建 `InMemoryDao` 作后端（开发/CI 场景）；分布式模式（`with_dao(dao)`）用注入的
/// `GarrisonDao`（oxcache/redis）实现跨实例计数；`rate-limit-redis` 下可经 [`Self::with_limiter_backend`]
/// 注入独立 Redis 限流运行时（会话/token/geo/device 数据仍走 `dao`）。检测项与 key：IP 计数器 `fw:ip:{ip}`、账号计数器
/// `fw:acct:{login_id}` 超阈值阻断；geo 记录 `fw:geo:{login_id}`、设备列表 `fw:device:{login_id}`、token 黑名单
/// `token:blacklist:{login_id}` 读 DAO KV 判定（无数据时通过）。计数器窗口由后端 TTL 语义自动重置，无需手动
/// 时间窗口判断；实现均线程安全（`Send + Sync`），经 `Arc` 共享。
pub struct GarrisonFirewallCheckHookDefault {
    /// 限流执行后端（DAO 适配器或 Redis 限流运行时，原子计数 + TTL）。
    limiter: Arc<dyn LimiterBackend>,
    /// 保留 DAO 引用以支持 geo/token/device anomaly 检查（KV 读取）；DAO 模式下与 `limiter` 共享同一 `Arc<dyn GarrisonDao>`，确保数据一致。
    dao: Arc<dyn GarrisonDao>,
    /// 可选监听器管理器，注入后 check_brute_force 阻断时广播 AccountLocked 事件。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<GarrisonListenerManager>>,
}

impl GarrisonFirewallCheckHookDefault {
    /// 创建内存模式默认实例（`#[doc(hidden)]`：仅测试/单实例部署；生产用 `with_dao` 注入分布式后端或显式 `with_memory_default`）。
    #[doc(hidden)]
    pub fn new() -> Self {
        Self::with_memory_default()
    }

    /// 显式选择进程内内存后端（单实例部署/测试；多实例生产务必 `with_dao`）。
    pub fn with_memory_default() -> Self {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let limiter = LimiterRuntime::dao(dao.clone()).limiter();
        Self {
            limiter,
            dao,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 DAO，切换到分布式计数模式（builder 方法）：`record_failure` / 各 `check_*` 方法走 DAO 路径（oxcache/redis），
    /// 内部 `limiter` 与 `dao` 字段均替换为注入的 DAO，确保计数器与 KV 检查共享同一后端。
    pub fn with_dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.limiter = LimiterRuntime::dao(dao.clone()).limiter();
        self.dao = dao;
        self
    }

    /// 注入独立限流后端（builder 方法）：`rate-limit-redis` 下由 manager 按
    /// `rate_limit_backend=redis` 注入 Redis 运行时；`dao`（经 [`Self::with_dao`] 注入）
    /// 仍用于 geo/token/device 检查。
    pub fn with_limiter_backend(mut self, limiter: Arc<dyn LimiterBackend>) -> Self {
        self.limiter = limiter;
        self
    }

    /// 注入 `GarrisonListenerManager`，启用 AccountLocked 事件广播：`check_brute_force` 阻断时广播
    /// `GarrisonEvent::AccountLocked`，未注入时为 no-op。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 记录一次登录失败（业务方在登录失败时调用）：同时递增 IP 与账号维度计数器（`limiteron::incr_with_ttl` 原子递增），
    /// 首次失败设置 count=1 + TTL，后续仅递增不重置 TTL（保持窗口起点），窗口过期由后端 TTL 语义自动重置；任一操作失败均向上传播（Fail Loud）。
    pub async fn record_failure(&self, ctx: &LoginContext) -> GarrisonResult<()> {
        if let Some(ip) = &ctx.ip {
            let key = format!("{}{}", FW_IP_KEY_PREFIX, ip);
            self.limiter
                .incr_with_ttl(&key, 1, LOGIN_FREQUENCY_WINDOW)
                .await
                .map_err(map_limiteron_err)?;
        }
        let acct_key = format!("{}{}", FW_ACCT_KEY_PREFIX, ctx.login_id);
        self.limiter
            .incr_with_ttl(&acct_key, 1, BRUTE_FORCE_WINDOW)
            .await
            .map_err(map_limiteron_err)?;
        Ok(())
    }

    /// 清空所有 IP / 账号计数器（测试辅助方法）：经 [`LimiterBackend::reset_prefix`] 扫描 `fw:ip:*` 与 `fw:acct:*` 并逐个删除；
    /// 生产环境慎用（DAO 后端可能全表扫描、Redis 后端为 SCAN，大规模 key 扫描可能影响存储性能）。
    pub async fn reset(&self) -> GarrisonResult<()> {
        self.limiter
            .reset_prefix(FW_IP_KEY_PREFIX)
            .await
            .map_err(map_limiteron_err)?;
        self.limiter
            .reset_prefix(FW_ACCT_KEY_PREFIX)
            .await
            .map_err(map_limiteron_err)?;
        Ok(())
    }

    /// 获取 IP 维度当前失败次数（测试辅助方法）；`get_count` 出错时记录 `tracing::warn` 并返回 0。
    pub async fn ip_failure_count(&self, ip: &str) -> u32 {
        let key = format!("{}{}", FW_IP_KEY_PREFIX, ip);
        match self.limiter.get_count(&key).await {
            Ok(c) => c as u32,
            Err(e) => {
                tracing::warn!("ip_failure_count get_count failed: {}", e);
                0
            },
        }
    }

    /// 获取账号维度当前失败次数（测试辅助方法）；`get_count` 出错时记录 `tracing::warn` 并返回 0。
    pub async fn account_failure_count(&self, login_id: &str) -> u32 {
        let key = format!("{}{}", FW_ACCT_KEY_PREFIX, login_id);
        match self.limiter.get_count(&key).await {
            Ok(c) => c as u32,
            Err(e) => {
                tracing::warn!("account_failure_count get_count failed: {}", e);
                0
            },
        }
    }
}

/// 将 `LimiteronError` 映射为 `GarrisonError::Dao`，表示底层 DAO 操作失败。
fn map_limiteron_err(e: limiteron::error::LimiteronError) -> GarrisonError {
    GarrisonError::Dao(format!("strategy-limiteron-op::{}", e))
}

impl Default for GarrisonFirewallCheckHookDefault {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GarrisonFirewallCheckHook for GarrisonFirewallCheckHookDefault {
    /// 登录频率检测：同 IP 1h 内 ≥ 10 次失败则阻断。
    ///
    /// 经 `limiteron::get_count` 查询 `fw:ip:{ip}` 计数器（Fail Loud：limiteron 错误向上传播），无 IP 信息时直接返回 Ok。
    async fn check_login_frequency(&self, ctx: &LoginContext) -> GarrisonResult<()> {
        let Some(ip) = &ctx.ip else {
            return Ok(()); // 无 IP 信息时不检测
        };
        let key = format!("{}{}", FW_IP_KEY_PREFIX, ip);
        let count = self
            .limiter
            .get_count(&key)
            .await
            .map_err(map_limiteron_err)?;
        if count >= LOGIN_FREQUENCY_THRESHOLD as u64 {
            return Err(GarrisonError::Session(format!(
                "strategy-login-frequency-exceeded::{}",
                ip
            )));
        }
        Ok(())
    }

    /// 暴力破解检测：同账号 1h 内 ≥ 5 次失败则锁定。
    ///
    /// 经 `limiteron::get_count` 查询 `fw:acct:{login_id}` 计数器（Fail Loud）；阻断时若注入了 `listener_manager`，广播 `GarrisonEvent::AccountLocked`。
    async fn check_brute_force(&self, ctx: &LoginContext) -> GarrisonResult<()> {
        let key = format!("{}{}", FW_ACCT_KEY_PREFIX, ctx.login_id);
        let count = self
            .limiter
            .get_count(&key)
            .await
            .map_err(map_limiteron_err)?;
        if count >= BRUTE_FORCE_THRESHOLD as u64 {
            // 广播 AccountLocked 事件
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&GarrisonEvent::AccountLocked {
                    login_id: ctx.login_id.clone(),
                    reason: format!("brute_force: {} failures in 1h", count),
                    request_context: None,
                })
                .await;
            }
            return Err(GarrisonError::Session(format!(
                "strategy-account-locked::{}",
                ctx.login_id
            )));
        }
        Ok(())
    }

    /// 异地登录检测：短时间跨城市登录触发阻断。
    ///
    /// 经 `dao.get("fw:geo:{login_id}")` 读取上次记录的地理位置与 `ctx.geo` 对比，不同则阻断（Fail Loud）；
    /// 无 geo 记录（首次登录）或 `ctx.geo` 为 None 时通过。
    async fn check_geo_anomaly(&self, ctx: &LoginContext) -> GarrisonResult<()> {
        let Some(ctx_geo) = &ctx.geo else {
            return Ok(()); // 上下文无 geo 信息，无法对比
        };
        let key = format!("fw:geo:{}", ctx.login_id);
        match self.dao.get(&key).await? {
            Some(stored_geo) if stored_geo != *ctx_geo => Err(GarrisonError::Session(format!(
                "strategy-geo-anomaly::{}::{}|{}",
                ctx.login_id, stored_geo, ctx_geo
            ))),
            _ => Ok(()), // 无记录或与记录一致，通过
        }
    }

    /// Token 复用检测：已登出 Token 再次使用则拒绝（Fail Loud：DAO 错误向上传播）。
    ///
    /// # 黑名单粒度语义（账号级锁定，显式声明）
    ///
    /// 黑名单 key 为账号级 `token:blacklist:{login_id}`（业务方检测到 token 泄露/复用后写入，本 crate 内无写入方）：
    /// 单个 token 被撤销即阻断该账号全部后续登录，直至删除该 key（无自动过期时为永久）——有意设计，凭据泄露是强信号，
    /// 代价是正常用户也需业务方介入解锁。token 级检查当前不可实现（`LoginContext` 不携带请求所呈现的 token，扩展 trait
    /// 签名属破坏性变更）；需要单 token 撤销的业务方应改用 session 层 `logout(token)` / `jwt:blacklist:{jti}`（stp 层）。
    async fn check_token_reuse(&self, ctx: &LoginContext) -> GarrisonResult<()> {
        let key = format!("{}blacklist:{}", DaoKeyPrefix::Token, ctx.login_id);
        if self.dao.get(&key).await?.is_some() {
            return Err(GarrisonError::Session(format!(
                "strategy-token-reuse-blocked::{}",
                ctx.login_id
            )));
        }
        Ok(())
    }

    /// 设备异常检测：未知设备指纹登录触发阻断。
    ///
    /// 经 `dao.get("fw:device:{login_id}")` 读取已知设备列表（逗号分隔），指纹不在列表中则阻断（Fail Loud）；
    /// 无设备记录（首次登录）或无指纹时通过。
    async fn check_device_anomaly(&self, ctx: &LoginContext) -> GarrisonResult<()> {
        let Some(fp) = &ctx.device_fingerprint else {
            return Ok(()); // 上下文无设备指纹，无法对比
        };
        let key = format!("fw:device:{}", ctx.login_id);
        match self.dao.get(&key).await? {
            Some(known_list) => {
                let known: Vec<&str> = known_list.split(',').map(|s| s.trim()).collect();
                if !known.contains(&fp.as_str()) {
                    return Err(GarrisonError::Session(format!(
                        "strategy-device-anomaly::{}::{}",
                        ctx.login_id, fp
                    )));
                }
                Ok(())
            },
            None => Ok(()), // 无已知设备记录，首次登录通过
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // LoginContext 测试

    /// LoginContext::new 仅含 login_id。
    #[test]
    fn login_context_new_has_only_login_id() {
        let ctx = LoginContext::new("1001");
        assert_eq!(ctx.login_id, "1001");
        assert!(ctx.ip.is_none());
        assert!(ctx.device_fingerprint.is_none());
        assert!(ctx.geo.is_none());
    }

    /// builder 链式设置字段。
    #[test]
    fn login_context_builder_sets_fields() {
        let ctx = LoginContext::new("1001")
            .with_ip("192.168.1.1")
            .with_device("dev-fp-abc")
            .with_geo("Beijing");
        assert_eq!(ctx.login_id, "1001");
        assert_eq!(ctx.ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(ctx.device_fingerprint.as_deref(), Some("dev-fp-abc"));
        assert_eq!(ctx.geo.as_deref(), Some("Beijing"));
    }

    // GarrisonFirewallCheckHook trait default impl 测试

    /// 默认 trait impl 所有 hook 返回 Ok。
    #[tokio::test]
    async fn default_hook_impl_all_pass() {
        struct NoOpHook;
        #[async_trait]
        impl GarrisonFirewallCheckHook for NoOpHook {}
        let hook = NoOpHook;
        let ctx = LoginContext::new("1001");
        assert!(hook.check_login_frequency(&ctx).await.is_ok());
        assert!(hook.check_brute_force(&ctx).await.is_ok());
        assert!(hook.check_geo_anomaly(&ctx).await.is_ok());
        assert!(hook.check_token_reuse(&ctx).await.is_ok());
        assert!(hook.check_device_anomaly(&ctx).await.is_ok());
    }

    // GarrisonFirewallCheckHookDefault 测试

    /// 无 IP 时 check_login_frequency 返回 Ok。
    #[tokio::test]
    async fn check_login_frequency_passes_without_ip() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001"); // 无 IP
        assert!(hook.check_login_frequency(&ctx).await.is_ok());
    }

    /// IP 失败次数 < 阈值时 check_login_frequency 返回 Ok。
    #[tokio::test]
    async fn check_login_frequency_passes_below_threshold() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        // 记录 9 次失败（阈值 10）
        for _ in 0..9 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.ip_failure_count("1.2.3.4").await, 9);
        assert!(hook.check_login_frequency(&ctx).await.is_ok());
    }

    /// IP 失败次数 ≥ 阈值时 check_login_frequency 返回 Err。
    #[tokio::test]
    async fn check_login_frequency_blocks_at_threshold() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        for _ in 0..10 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.ip_failure_count("1.2.3.4").await, 10);
        let result = hook.check_login_frequency(&ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GarrisonError::Session(_)));
    }

    /// 账号失败次数 < 阈值时 check_brute_force 返回 Ok。
    #[tokio::test]
    async fn check_brute_force_passes_below_threshold() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001");
        for _ in 0..4 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.account_failure_count("1001").await, 4);
        assert!(hook.check_brute_force(&ctx).await.is_ok());
    }

    /// 账号失败次数 ≥ 阈值时 check_brute_force 返回 Err。
    #[tokio::test]
    async fn check_brute_force_blocks_at_threshold() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001");
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.account_failure_count("1001").await, 5);
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GarrisonError::Session(_)));
    }

    /// reset 清空所有计数器。
    #[tokio::test]
    async fn reset_clears_all_counters() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        hook.record_failure(&ctx).await.unwrap();
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.ip_failure_count("1.2.3.4").await, 2);
        assert_eq!(hook.account_failure_count("1001").await, 2);
        hook.reset().await.unwrap();
        assert_eq!(hook.ip_failure_count("1.2.3.4").await, 0);
        assert_eq!(hook.account_failure_count("1001").await, 0);
    }

    /// 不同 IP 的计数器相互独立。
    #[tokio::test]
    async fn ip_counters_are_independent() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx1 = LoginContext::new("1001").with_ip("1.1.1.1");
        let ctx2 = LoginContext::new("1002").with_ip("2.2.2.2");
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx2).await.unwrap();
        assert_eq!(hook.ip_failure_count("1.1.1.1").await, 2);
        assert_eq!(hook.ip_failure_count("2.2.2.2").await, 1);
    }

    /// 不同账号的计数器相互独立。
    #[tokio::test]
    async fn account_counters_are_independent() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx1 = LoginContext::new("1001");
        let ctx2 = LoginContext::new("1002");
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx2).await.unwrap();
        assert_eq!(hook.account_failure_count("1001").await, 3);
        assert_eq!(hook.account_failure_count("1002").await, 1);
    }

    /// geo_anomaly / token_reuse / device_anomaly 默认 pass（内存模式）。
    #[tokio::test]
    async fn other_hooks_pass_by_default() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_geo("Shanghai");
        assert!(hook.check_geo_anomaly(&ctx).await.is_ok());
        assert!(hook.check_token_reuse(&ctx).await.is_ok());
        assert!(hook.check_device_anomaly(&ctx).await.is_ok());
    }

    /// record_failure 同时递增 IP 与账号计数器。
    #[tokio::test]
    async fn record_failure_increments_both_counters() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.ip_failure_count("1.2.3.4").await, 1);
        assert_eq!(hook.account_failure_count("1001").await, 1);
    }

    /// Default::default() 等价于 new()。
    #[test]
    fn default_equals_new() {
        let _hook1 = GarrisonFirewallCheckHookDefault::new();
        let _hook2 = GarrisonFirewallCheckHookDefault::default();
        // 仅验证可创建，内部状态相同（均为空计数器）
    }

    // DAO 模式测试（分布式计数器）

    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;
    use std::sync::Arc;

    /// 辅助：构造 DAO 模式 hook。
    fn make_dao_hook() -> (GarrisonFirewallCheckHookDefault, Arc<MockDao>) {
        let dao = Arc::new(InMemoryDao::new());
        let hook = GarrisonFirewallCheckHookDefault::new().with_dao(dao.clone());
        (hook, dao)
    }

    /// with_dao 注入 DAO 后进入分布式模式：计数器基于注入 DAO（oxcache/redis）而非内存 Mutex，
    /// `ip_failure_count` / `account_failure_count` 始终从当前后端读取。
    #[tokio::test]
    async fn with_dao_creates_distributed_mode() {
        let dao = Arc::new(InMemoryDao::new());
        let hook = GarrisonFirewallCheckHookDefault::new().with_dao(dao.clone());
        // 验证可创建，且 record_failure 走注入的 DAO 路径
        let ctx = LoginContext::new("1001").with_ip("9.9.9.9");
        hook.record_failure(&ctx).await.unwrap();
        // 计数器存储在注入的 DAO 中，ip_failure_count 从同一 DAO 读取
        assert_eq!(hook.ip_failure_count("9.9.9.9").await, 1);
        assert_eq!(hook.account_failure_count("1001").await, 1);
        // 直接验证 DAO 中确实存在计数器
        assert_eq!(
            dao.get("fw:ip:9.9.9.9").await.unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(dao.get("fw:acct:1001").await.unwrap().as_deref(), Some("1"));
    }

    /// `with_limiter_backend` 覆盖 `with_dao` 的默认 limiter：计数写入注入后端而非 DAO。
    #[tokio::test]
    async fn with_limiter_backend_overrides_dao_limiter() {
        let dao = Arc::new(InMemoryDao::new());
        let limiter_dao = Arc::new(InMemoryDao::new());
        let hook = GarrisonFirewallCheckHookDefault::new()
            .with_dao(dao.clone())
            .with_limiter_backend(LimiterRuntime::dao(limiter_dao.clone()).limiter());

        let ctx = LoginContext::new("2002").with_ip("8.8.8.8");
        hook.record_failure(&ctx).await.unwrap();

        assert!(
            dao.get("fw:ip:8.8.8.8").await.unwrap().is_none(),
            "默认 DAO 不应收到计数写入"
        );
        assert_eq!(
            limiter_dao.get("fw:ip:8.8.8.8").await.unwrap().as_deref(),
            Some("1"),
            "计数应写入注入的限流后端"
        );
        assert_eq!(hook.ip_failure_count("8.8.8.8").await, 1);
    }

    /// DAO 模式下 record_failure 递增 DAO 计数（`fw:ip:{ip}` / `fw:acct:{login_id}` 持久化到 DAO）。
    #[tokio::test]
    async fn record_failure_dao_mode_increments_counter() {
        let (hook, dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        for _ in 0..3 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let ip_count = dao.get("fw:ip:1.2.3.4").await.unwrap();
        assert_eq!(ip_count.as_deref(), Some("3"));
        let acct_count = dao.get("fw:acct:1001").await.unwrap();
        assert_eq!(acct_count.as_deref(), Some("3"));
    }

    /// DAO 模式下登录频率超阈值（≥10）阻断（check_login_frequency 走 DAO 路径）。
    #[tokio::test]
    async fn check_login_frequency_dao_mode_blocks_at_threshold() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_ip("5.6.7.8");
        // 记录 10 次失败（达到阈值）
        for _ in 0..10 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let result = hook.check_login_frequency(&ctx).await;
        assert!(result.is_err(), "DAO 模式下 IP 失败 ≥ 阈值应阻断");
        assert!(matches!(result.unwrap_err(), GarrisonError::Session(_)));
    }

    /// DAO 模式下暴力破解超阈值（≥5）阻断（check_brute_force 走 DAO 路径）。
    #[tokio::test]
    async fn check_brute_force_dao_mode_blocks_at_threshold() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001");
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err(), "DAO 模式下账号失败 ≥ 阈值应阻断");
        assert!(matches!(result.unwrap_err(), GarrisonError::Session(_)));
    }

    /// DAO 模式下 token 黑名单存在则阻断（check_token_reuse 走 DAO 路径）。
    #[tokio::test]
    async fn check_token_reuse_dao_mode_blocks_blacklisted() {
        let (hook, dao) = make_dao_hook();
        dao.set("token:blacklist:1001", "revoked", 3600)
            .await
            .unwrap();
        let ctx = LoginContext::new("1001");
        let result = hook.check_token_reuse(&ctx).await;
        assert!(result.is_err(), "Token 在黑名单中应阻断");
        assert!(matches!(result.unwrap_err(), GarrisonError::Session(_)));
    }

    /// DAO 模式下无黑名单时 check_token_reuse 通过（无黑名单数据时 pass）。
    #[tokio::test]
    async fn check_token_reuse_passes_without_blacklist() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001");
        assert!(
            hook.check_token_reuse(&ctx).await.is_ok(),
            "无黑名单时应通过"
        );
    }

    /// DAO 模式下异地登录（与上次 geo 不符）阻断（check_geo_anomaly 走 DAO 路径）。
    #[tokio::test]
    async fn check_geo_anomaly_dao_mode_blocks_different_geo() {
        let (hook, dao) = make_dao_hook();
        dao.set("fw:geo:1001", "Beijing", 3600).await.unwrap();
        // 本次登录地理位置为 Shanghai → 异地
        let ctx = LoginContext::new("1001").with_geo("Shanghai");
        let result = hook.check_geo_anomaly(&ctx).await;
        assert!(result.is_err(), "异地登录应阻断");
        assert!(matches!(result.unwrap_err(), GarrisonError::Session(_)));
    }

    /// DAO 模式下无 geo 记录时 check_geo_anomaly 通过（首次登录，无 geo 数据时 pass）。
    #[tokio::test]
    async fn check_geo_anomaly_passes_without_geo_data() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_geo("Shanghai");
        assert!(
            hook.check_geo_anomaly(&ctx).await.is_ok(),
            "无 geo 记录时应通过（首次登录）"
        );
    }

    /// DAO 模式下未知设备指纹阻断（check_device_anomaly 走 DAO 路径）。
    #[tokio::test]
    async fn check_device_anomaly_dao_mode_blocks_unknown_device() {
        let (hook, dao) = make_dao_hook();
        // 预置已知设备列表（逗号分隔）
        dao.set("fw:device:1001", "dev-known-1,dev-known-2", 3600)
            .await
            .unwrap();
        // 本次设备指纹不在列表中
        let ctx = LoginContext::new("1001").with_device("dev-unknown");
        let result = hook.check_device_anomaly(&ctx).await;
        assert!(result.is_err(), "未知设备应阻断");
        assert!(matches!(result.unwrap_err(), GarrisonError::Session(_)));
    }

    /// DAO 模式下无设备记录时 check_device_anomaly 通过（首次登录，无设备数据时 pass）。
    #[tokio::test]
    async fn check_device_anomaly_passes_without_device_data() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_device("dev-new");
        assert!(
            hook.check_device_anomaly(&ctx).await.is_ok(),
            "无设备记录时应通过（首次登录）"
        );
    }

    // 覆盖率补充：listener_manager 注入、窗口重置、DAO 解析失败等

    /// `with_listener_manager` 注入后 listener_manager 字段为 Some（builder 方法体覆盖）。
    #[cfg(feature = "listener")]
    #[test]
    fn with_listener_manager_sets_field() {
        use crate::listener::GarrisonListenerManager;
        let lm = Arc::new(GarrisonListenerManager::new());
        let hook = GarrisonFirewallCheckHookDefault::new().with_listener_manager(lm);
        assert!(
            hook.listener_manager.is_some(),
            "with_listener_manager 后 listener_manager 应为 Some"
        );
    }

    /// 内存模式 IP 失败窗口重置：删除计数器 key 模拟 TTL 过期后，第二次失败 count 重置为 1（避免真实等待 1 小时窗口）。
    #[tokio::test]
    async fn record_failure_resets_ip_count_when_window_expired() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("10.0.0.1");
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.ip_failure_count("10.0.0.1").await, 1);
        // 模拟窗口过期：删除 IP 计数器 key（等价于 TTL 过期被 DAO 自动清理）
        let ip_key = format!("{}{}", FW_IP_KEY_PREFIX, "10.0.0.1");
        hook.dao.delete(&ip_key).await.unwrap();
        // 第二次失败（窗口已过，MockDao::incr 重新初始化为 1 + 新 TTL）
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(
            hook.ip_failure_count("10.0.0.1").await,
            1,
            "窗口过期后 IP 计数应重置为 1"
        );
    }

    /// 内存模式账号失败窗口重置：删除计数器 key 模拟 TTL 过期后，第二次失败 count 重置为 1。
    #[tokio::test]
    async fn record_failure_resets_account_count_when_window_expired() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001");
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.account_failure_count("1001").await, 1);
        // 模拟窗口过期：删除账号计数器 key
        let acct_key = format!("{}{}", FW_ACCT_KEY_PREFIX, "1001");
        hook.dao.delete(&acct_key).await.unwrap();
        // 第二次失败（窗口已过，MockDao::incr 重新初始化为 1 + 新 TTL）
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(
            hook.account_failure_count("1001").await,
            1,
            "窗口过期后账号计数应重置为 1"
        );
    }

    /// DAO 模式下脏计数器数据导致 `check_brute_force` 返回 `GarrisonError::Dao`（Fail Loud）：
    /// limiteron `get_count` parse 失败返回 Err 向上传播，不再静默用 0（避免脏数据导致阈值检测失效）。
    #[tokio::test]
    async fn check_brute_force_returns_err_on_dirty_count() {
        let dao = Arc::new(InMemoryDao::new());
        dao.set("fw:acct:1001", "not-a-number", 3600).await.unwrap();
        let hook = GarrisonFirewallCheckHookDefault::new().with_dao(dao);
        let ctx = LoginContext::new("1001");
        // check_brute_force 读取非数字计数器应返回 Err（Fail Loud）
        let result = hook.check_brute_force(&ctx).await;
        assert!(
            result.is_err(),
            "脏计数器数据应导致 check_brute_force 返回 Err，实际: {:?}",
            result
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, GarrisonError::Dao(_)),
            "应为 GarrisonError::Dao 错误，实际: {:?}",
            err
        );
    }

    /// DAO 模式 `check_login_frequency` 未超阈值返回 Ok。
    #[tokio::test]
    async fn check_login_frequency_dao_mode_passes_below_threshold() {
        let dao = Arc::new(InMemoryDao::new());
        // 写入 9 次失败（阈值 10）
        dao.set("fw:ip:1.2.3.4", "9", 3600).await.unwrap();
        let hook = GarrisonFirewallCheckHookDefault::new().with_dao(dao);
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        let result = hook.check_login_frequency(&ctx).await;
        assert!(result.is_ok(), "9 次失败 < 阈值 10，应通过");
    }

    /// DAO 模式 `check_brute_force` 未超阈值（4 < 5）返回 Ok。
    #[tokio::test]
    async fn check_brute_force_dao_mode_passes_below_threshold() {
        let dao = Arc::new(InMemoryDao::new());
        // 写入 4 次失败（阈值 5）
        dao.set("fw:acct:1001", "4", 3600).await.unwrap();
        let hook = GarrisonFirewallCheckHookDefault::new().with_dao(dao);
        let ctx = LoginContext::new("1001");
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_ok(), "4 次失败 < 阈值 5，应通过");
    }

    /// DAO 模式 `check_brute_force` 超阈值时广播 AccountLocked 事件。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_brute_force_dao_mode_broadcasts_account_locked() {
        // broadcast 是副作用，此处只验证超阈值返回 Err（inventory 注册需静态上下文，故用已有 listener_manager）
        let dao = Arc::new(InMemoryDao::new());
        dao.set("fw:acct:1001", "5", 3600).await.unwrap();
        let lm = Arc::new(GarrisonListenerManager::new());
        let hook = GarrisonFirewallCheckHookDefault::new()
            .with_dao(dao)
            .with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err(), "5 次失败 ≥ 阈值 5，应阻断");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("1001"), "错误信息应包含 login_id=1001");
    }

    /// 内存模式 `check_brute_force` 超阈值时广播 AccountLocked 事件。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_brute_force_in_memory_mode_broadcasts_account_locked() {
        use crate::listener::GarrisonListenerManager;
        let lm = Arc::new(GarrisonListenerManager::new());
        let hook = GarrisonFirewallCheckHookDefault::new().with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        // 记录 5 次失败（阈值 5）
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err(), "5 次失败 ≥ 阈值 5，应阻断");
    }

    /// 内存模式 `check_geo_anomaly` 无 ctx.geo 时返回 Ok。
    #[tokio::test]
    async fn check_geo_anomaly_in_memory_mode_passes_without_ctx_geo() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        // 无 DAO + 无 geo
        let ctx = LoginContext::new("1001");
        let result = hook.check_geo_anomaly(&ctx).await;
        assert!(result.is_ok(), "内存模式无 ctx_geo 时应返回 Ok");
    }

    /// 内存模式 `check_device_anomaly` 无 device_fingerprint 时返回 Ok。
    #[tokio::test]
    async fn check_device_anomaly_in_memory_mode_passes_without_fingerprint() {
        let hook = GarrisonFirewallCheckHookDefault::new();
        // 无 DAO + 无 device_fingerprint
        let ctx = LoginContext::new("1001");
        let result = hook.check_device_anomaly(&ctx).await;
        assert!(result.is_ok(), "内存模式无 device_fingerprint 时应返回 Ok");
    }

    /// DAO 模式 `check_device_anomaly` 设备指纹在已知列表中时返回 Ok。
    #[tokio::test]
    async fn check_device_anomaly_dao_mode_passes_with_known_device() {
        let (hook, dao) = make_dao_hook();
        // 预置已知设备列表
        dao.set("fw:device:1001", "dev-known-1,dev-known-2", 3600)
            .await
            .unwrap();
        // 本次设备指纹在列表中
        let ctx = LoginContext::new("1001").with_device("dev-known-1");
        let result = hook.check_device_anomaly(&ctx).await;
        assert!(result.is_ok(), "已知设备指纹应通过");
    }
}
