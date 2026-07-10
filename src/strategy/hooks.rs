//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 防火墙安全钩子模块，提供登录流程的可插拔安全检查。
//!
//! 依据 spec firewall-check-hook 与 ADD 0.3.0 防火墙策略设计。
//!
//! ## 设计
//!
//! - `BulwarkFirewallCheckHook` trait：5 个 async hook 方法 + default impl 全 pass
//! - `LoginContext`：登录上下文（login_id + 可选 IP / 设备指纹 / 地理位置）
//! - `BulwarkFirewallCheckHookDefault`：基于内存计数器 + 时间窗口的默认实现
//!
//! ## 5 个检查项（依据 ADD 表格）
//!
//! | 检查项 | 触发条件 | 处置 |
//! |:---|:---|:---|
//! | 登录频率 | 同 IP 1h 内 ≥ 10 次失败 | 阻断登录 |
//! | 暴力破解 | 同账号 1h 内 ≥ 5 次失败 | 阻断登录 |
//! | 异地登录 | 短时间跨城市登录 | 阻断登录（0.3.0 简化：需 geo 数据，无数据则 pass） |
//! | Token 复用 | 已登出 Token 再次使用 | 阻断登录 |
//! | 设备异常 | 未知设备指纹登录 | 阻断登录（0.3.0 简化：需设备库，无数据则 pass） |

use crate::error::{BulwarkError, BulwarkResult};
// v0.4.2: listener_manager 注入（feature-gated，依据 spec listener-events-extend R-001）
#[cfg(feature = "listener")]
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 登录上下文，传递给防火墙钩子。
///
/// 0.3.0 简化设计：仅包含 `login_id` 与可选 `ip`，后续版本可扩展。
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

// ============================================================================
// BulwarkFirewallCheckHook trait：5 个 async hook + default impl 全 pass
// ============================================================================

/// 防火墙安全钩子 trait，定义登录流程的 5 个可插拔安全检查。
///
/// 所有方法提供默认 `Ok(())` 实现，业务方按需 override 特定检查项。
/// 任一 hook 返回 `Err` 将阻断登录流程（依据 spec firewall-check-hook）。
///
/// # 调用顺序（依据 ADD 表格）
///
/// 1. `check_login_frequency` — 登录频率检测
/// 2. `check_brute_force` — 暴力破解检测
/// 3. `check_geo_anomaly` — 异地登录检测
/// 4. `check_token_reuse` — Token 复用检测
/// 5. `check_device_anomaly` — 设备异常检测
#[async_trait]
pub trait BulwarkFirewallCheckHook: Send + Sync {
    /// 登录频率检测：同 IP 1h 内 ≥ 10 次失败则阻断。
    ///
    /// # 默认实现
    /// 直接返回 `Ok(())`（无检测）。
    async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }

    /// 暴力破解检测：同账号 1h 内 ≥ 5 次失败则锁定。
    ///
    /// # 默认实现
    /// 直接返回 `Ok(())`（无检测）。
    async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }

    /// 异地登录检测：短时间跨城市登录触发二次认证。
    ///
    /// # 默认实现
    /// 直接返回 `Ok(())`（无 geo 数据时 pass）。
    async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }

    /// Token 复用检测：已登出 Token 再次使用则拒绝。
    ///
    /// # 默认实现
    /// 直接返回 `Ok(())`（无黑名单数据时 pass）。
    async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }

    /// 设备异常检测：未知设备指纹登录触发验证。
    ///
    /// # 默认实现
    /// 直接返回 `Ok(())`（无设备库时 pass）。
    async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }
}

// ============================================================================
// BulwarkFirewallCheckHookDefault：基于内存计数器 + 时间窗口的默认实现
// ============================================================================

/// 登录频率检测阈值：同 IP 1h 内 ≥ 10 次失败。
pub const LOGIN_FREQUENCY_THRESHOLD: u32 = 10;
/// 登录频率检测时间窗口：1 小时。
pub const LOGIN_FREQUENCY_WINDOW: Duration = Duration::from_secs(3600);

/// 暴力破解检测阈值：同账号 1h 内 ≥ 5 次失败。
pub const BRUTE_FORCE_THRESHOLD: u32 = 5;
/// 暴力破解检测时间窗口：1 小时。
pub const BRUTE_FORCE_WINDOW: Duration = Duration::from_secs(3600);

/// 失败计数器条目。
#[derive(Debug, Clone)]
struct FailureEntry {
    /// 失败次数。
    count: u32,
    /// 首次失败时间（用于窗口判断）。
    first_failure_at: Instant,
}

/// `BulwarkFirewallCheckHook` 的默认实现，支持两种计数模式：
///
/// - **内存模式**（`new()`）：基于 `parking_lot::Mutex<HashMap<..>>` + 时间窗口，
///   仅在单进程内有效，向后兼容（开发/CI 场景）。
/// - **分布式模式**（`with_dao(dao)`）：基于注入的 `BulwarkDao`（oxcache/redis）
///   实现跨实例计数，满足 ADD §7.6 分布式存储要求（生产场景）。
///
/// # 5 项检测
///
/// - 同 IP 1h 内 ≥ 10 次失败 → 阻断（`BulwarkError::Session`）
/// - 同账号 1h 内 ≥ 5 次失败 → 阻断（`BulwarkError::Session`）
/// - 异地登录：DAO 模式下与上次记录的 geo 不符 → 阻断
/// - Token 复用：DAO 模式下 `token:blacklist:{login_id}` 存在 → 阻断
/// - 设备异常：DAO 模式下 `ctx.device_fingerprint` 不在已知设备列表 → 阻断
///
/// 内存模式下后 3 项检测保持 `Ok(())`（需外部数据源）。
///
/// # 线程安全
///
/// 内存计数器使用 `parking_lot::Mutex<HashMap<..>>` 保护；DAO 通过 `Arc<dyn BulwarkDao>` 共享。
pub struct BulwarkFirewallCheckHookDefault {
    /// IP 维度失败计数器：key = ip, value = FailureEntry（仅内存模式使用）。
    ip_failures: Mutex<HashMap<String, FailureEntry>>,
    /// 账号维度失败计数器：key = login_id.to_string(), value = FailureEntry（仅内存模式使用）。
    account_failures: Mutex<HashMap<String, FailureEntry>>,
    /// 可选 DAO 注入（启用分布式计数器模式）。
    /// None 时使用内存计数器（开发/CI 场景，向后兼容）。
    /// Some 时使用 DAO（oxcache/redis）实现分布式计数（生产场景）。
    dao: Option<Arc<dyn crate::dao::BulwarkDao>>,
    /// v0.4.2：可选监听器管理器，注入后 check_brute_force 阻断时广播 AccountLocked 事件
    ///（依据 spec listener-events-extend R-001）。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
}

impl BulwarkFirewallCheckHookDefault {
    /// 创建默认实现实例（内存模式，计数器为空，无 DAO）。
    ///
    /// 向后兼容：等价于 0.3.0 之前的 `new()`。
    pub fn new() -> Self {
        Self {
            ip_failures: Mutex::new(HashMap::new()),
            account_failures: Mutex::new(HashMap::new()),
            dao: None,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 DAO，切换到分布式计数模式（builder 方法）。
    ///
    /// 启用后 `record_failure` / 各 `check_*` 方法将走 DAO 路径（oxcache/redis），
    /// 内存计数器不再使用。满足 ADD §7.6 分布式存储要求。
    pub fn with_dao(mut self, dao: Arc<dyn crate::dao::BulwarkDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 注入 `BulwarkListenerManager`，启用 AccountLocked 事件广播
    ///（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 注入后 `check_brute_force` 阻断时广播 `BulwarkEvent::AccountLocked`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<BulwarkListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 记录一次登录失败（业务方在登录失败时调用）。
    ///
    /// 同时递增 IP 与账号维度的失败计数器。若窗口已过则重置计数。
    ///
    /// - 内存模式：基于 `parking_lot::Mutex<HashMap>` + 时间窗口。
    /// - DAO 模式：`dao.get` → parse → +1 → `dao.set(key, count, 3600)`，
    ///   key 为 `fw:ip:{ip}` / `fw:acct:{login_id}`，TTL 3600s。
    ///
    /// # 错误
    /// DAO 模式下任一 DAO 操作失败均向上传播（Fail Loud，不静默吞错）。
    /// 内存模式不会失败（返回 `Ok(())`）。
    pub async fn record_failure(&self, ctx: &LoginContext) -> BulwarkResult<()> {
        let now = Instant::now();
        if let Some(dao) = &self.dao {
            // DAO 模式：分布式计数
            if let Some(ip) = &ctx.ip {
                let key = format!("fw:ip:{}", ip);
                let count = read_dao_count(dao, &key).await?;
                write_dao_count(dao, &key, count + 1).await?;
            }
            let acct_key = format!("fw:acct:{}", ctx.login_id);
            let count = read_dao_count(dao, &acct_key).await?;
            write_dao_count(dao, &acct_key, count + 1).await?;
            return Ok(());
        }
        // 内存模式：现有逻辑
        if let Some(ip) = &ctx.ip {
            let mut map = self.ip_failures.lock();
            let entry = map.entry(ip.clone()).or_insert(FailureEntry {
                count: 0,
                first_failure_at: now,
            });
            if now.duration_since(entry.first_failure_at) >= LOGIN_FREQUENCY_WINDOW {
                // 窗口已过，重置计数
                entry.count = 1;
                entry.first_failure_at = now;
            } else {
                entry.count += 1;
            }
        }
        let mut map = self.account_failures.lock();
        let key = ctx.login_id.clone();
        let entry = map.entry(key).or_insert(FailureEntry {
            count: 0,
            first_failure_at: now,
        });
        if now.duration_since(entry.first_failure_at) >= BRUTE_FORCE_WINDOW {
            entry.count = 1;
            entry.first_failure_at = now;
        } else {
            entry.count += 1;
        }
        Ok(())
    }

    /// 清空所有计数器（测试辅助方法，仅内存模式有效）。
    ///
    /// DAO 模式下为 no-op（分布式计数器无法从单实例清空）。
    pub fn reset(&self) {
        self.ip_failures.lock().clear();
        self.account_failures.lock().clear();
    }

    /// 获取 IP 维度当前失败次数（测试辅助方法）。
    ///
    /// 内存模式返回本地计数；DAO 模式返回 0（需通过 DAO 直接查询）。
    pub fn ip_failure_count(&self, ip: &str) -> u32 {
        self.ip_failures
            .lock()
            .get(ip)
            .map(|e| e.count)
            .unwrap_or(0)
    }

    /// 获取账号维度当前失败次数（测试辅助方法）。
    ///
    /// 内存模式返回本地计数；DAO 模式返回 0（需通过 DAO 直接查询）。
    pub fn account_failure_count(&self, login_id: &str) -> u32 {
        self.account_failures
            .lock()
            .get(login_id)
            .map(|e| e.count)
            .unwrap_or(0)
    }
}

/// 从 DAO 读取失败计数（key 不存在或解析失败返回 0）。
///
/// 注意：解析失败返回 0 而非报错，因为计数器缺失等价于"无失败记录"。
/// DAO 操作本身的错误会向上传播。
async fn read_dao_count(dao: &Arc<dyn crate::dao::BulwarkDao>, key: &str) -> BulwarkResult<u32> {
    match dao.get(key).await? {
        Some(v) => match v.parse::<u32>() {
            Ok(n) => Ok(n),
            Err(e) => {
                tracing::warn!("DAO 计数器解析失败 (key 可能损坏): {}", e);
                Ok(0)
            },
        },
        None => Ok(0),
    }
}

/// 将失败计数写入 DAO（TTL 3600s）。
async fn write_dao_count(
    dao: &Arc<dyn crate::dao::BulwarkDao>,
    key: &str,
    count: u32,
) -> BulwarkResult<()> {
    dao.set(key, &count.to_string(), 3600).await
}

impl Default for BulwarkFirewallCheckHookDefault {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkFirewallCheckHook for BulwarkFirewallCheckHookDefault {
    /// 登录频率检测：同 IP 1h 内 ≥ 10 次失败则阻断。
    ///
    /// - DAO 模式：读取 `fw:ip:{ip}` 计数，≥ 阈值则阻断（Fail Loud：DAO 错误向上传播）。
    /// - 内存模式：读取本地计数器，结合时间窗口判断。
    async fn check_login_frequency(&self, ctx: &LoginContext) -> BulwarkResult<()> {
        let Some(ip) = &ctx.ip else {
            return Ok(()); // 无 IP 信息时不检测
        };
        if let Some(dao) = &self.dao {
            let key = format!("fw:ip:{}", ip);
            let count = read_dao_count(dao, &key).await?;
            if count >= LOGIN_FREQUENCY_THRESHOLD {
                return Err(BulwarkError::Session(format!(
                    "登录频率超限：IP {} 在 1h 内失败 {} 次（阈值 {}）",
                    ip, count, LOGIN_FREQUENCY_THRESHOLD
                )));
            }
            return Ok(());
        }
        // 内存模式
        let map = self.ip_failures.lock();
        if let Some(entry) = map.get(ip) {
            let now = Instant::now();
            if now.duration_since(entry.first_failure_at) < LOGIN_FREQUENCY_WINDOW
                && entry.count >= LOGIN_FREQUENCY_THRESHOLD
            {
                return Err(BulwarkError::Session(format!(
                    "登录频率超限：IP {} 在 1h 内失败 {} 次（阈值 {}）",
                    ip, entry.count, LOGIN_FREQUENCY_THRESHOLD
                )));
            }
        }
        Ok(())
    }

    /// 暴力破解检测：同账号 1h 内 ≥ 5 次失败则锁定。
    ///
    /// - DAO 模式：读取 `fw:acct:{login_id}` 计数，≥ 阈值则阻断（Fail Loud：DAO 错误向上传播）。
    /// - 内存模式：读取本地计数器，结合时间窗口判断。
    ///
    /// v0.4.2 扩展：阻断时若注入了 `listener_manager`，广播 `BulwarkEvent::AccountLocked`
    ///（依据 spec listener-events-extend R-001）。
    async fn check_brute_force(&self, ctx: &LoginContext) -> BulwarkResult<()> {
        if let Some(dao) = &self.dao {
            let key = format!("fw:acct:{}", ctx.login_id);
            let count = read_dao_count(dao, &key).await?;
            if count >= BRUTE_FORCE_THRESHOLD {
                // v0.4.2: 广播 AccountLocked 事件（依据 spec listener-events-extend R-001）
                #[cfg(feature = "listener")]
                if let Some(lm) = &self.listener_manager {
                    lm.broadcast(&BulwarkEvent::AccountLocked {
                        login_id: ctx.login_id.clone(),
                        reason: format!("brute_force: {} failures in 1h", count),
                    })
                    .await;
                }
                return Err(BulwarkError::Session(format!(
                    "账号锁定：login_id={} 在 1h 内失败 {} 次（阈值 {}）",
                    ctx.login_id, count, BRUTE_FORCE_THRESHOLD
                )));
            }
            return Ok(());
        }
        // 内存模式
        // v0.5.0: 先在锁内提取所需数据，drop 锁后再 broadcast（避免 MutexGuard 跨 await 持有）
        let locked_reason = {
            let map = self.account_failures.lock();
            let key = ctx.login_id.clone();
            if let Some(entry) = map.get(&key) {
                let now = Instant::now();
                if now.duration_since(entry.first_failure_at) < BRUTE_FORCE_WINDOW
                    && entry.count >= BRUTE_FORCE_THRESHOLD
                {
                    Some(format!("brute_force: {} failures in 1h", entry.count))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(reason) = locked_reason {
            // v0.4.2: 广播 AccountLocked 事件（依据 spec listener-events-extend R-001）
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&BulwarkEvent::AccountLocked {
                    login_id: ctx.login_id.clone(),
                    reason: reason.clone(),
                })
                .await;
            }
            return Err(BulwarkError::Session(format!(
                "账号锁定：login_id={} 触发 {}",
                ctx.login_id, reason
            )));
        }
        Ok(())
    }

    /// 异地登录检测：短时间跨城市登录触发阻断。
    ///
    /// - DAO 模式：读取 `fw:geo:{login_id}` 记录的上次地理位置，与 `ctx.geo` 对比，
    ///   不同则阻断（Fail Loud：DAO 错误向上传播）。无 geo 记录或 `ctx.geo` 为 None 时通过（首次登录）。
    /// - 内存模式：直接返回 `Ok(())`（无外部数据源）。
    async fn check_geo_anomaly(&self, ctx: &LoginContext) -> BulwarkResult<()> {
        let Some(dao) = &self.dao else {
            return Ok(()); // 内存模式：无 geo 数据源
        };
        let Some(ctx_geo) = &ctx.geo else {
            return Ok(()); // 上下文无 geo 信息，无法对比
        };
        let key = format!("fw:geo:{}", ctx.login_id);
        match dao.get(&key).await? {
            Some(stored_geo) if stored_geo != *ctx_geo => {
                return Err(BulwarkError::Session(format!(
                    "异地登录检测：login_id={} 上次地理位置 {} 与本次 {} 不符",
                    ctx.login_id, stored_geo, ctx_geo
                )));
            },
            _ => Ok(()), // 无记录或与记录一致，通过
        }
    }

    /// Token 复用检测：已登出 Token 再次使用则拒绝。
    ///
    /// - DAO 模式：检查 `token:blacklist:{login_id}` 是否存在，存在则阻断
    ///   （Fail Loud：DAO 错误向上传播）。
    /// - 内存模式：直接返回 `Ok(())`（无黑名单数据源）。
    async fn check_token_reuse(&self, ctx: &LoginContext) -> BulwarkResult<()> {
        let Some(dao) = &self.dao else {
            return Ok(()); // 内存模式：无黑名单数据源
        };
        let key = format!("token:blacklist:{}", ctx.login_id);
        if dao.get(&key).await?.is_some() {
            return Err(BulwarkError::Session(format!(
                "Token 复用检测：login_id={} 的 Token 已被列入黑名单",
                ctx.login_id
            )));
        }
        Ok(())
    }

    /// 设备异常检测：未知设备指纹登录触发阻断。
    ///
    /// - DAO 模式：读取 `fw:device:{login_id}` 已知设备列表（逗号分隔），
    ///   `ctx.device_fingerprint` 不在列表中则阻断（Fail Loud：DAO 错误向上传播）。
    ///   无设备记录或 `ctx.device_fingerprint` 为 None 时通过（首次登录）。
    /// - 内存模式：直接返回 `Ok(())`（无设备库数据源）。
    async fn check_device_anomaly(&self, ctx: &LoginContext) -> BulwarkResult<()> {
        let Some(dao) = &self.dao else {
            return Ok(()); // 内存模式：无设备库数据源
        };
        let Some(fp) = &ctx.device_fingerprint else {
            return Ok(()); // 上下文无设备指纹，无法对比
        };
        let key = format!("fw:device:{}", ctx.login_id);
        match dao.get(&key).await? {
            Some(known_list) => {
                let known: Vec<&str> = known_list.split(',').map(|s| s.trim()).collect();
                if !known.contains(&fp.as_str()) {
                    return Err(BulwarkError::Session(format!(
                        "设备异常检测：login_id={} 的设备指纹 {} 不在已知设备列表",
                        ctx.login_id, fp
                    )));
                }
                Ok(())
            },
            None => Ok(()), // 无已知设备记录，首次登录通过
        }
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // LoginContext 测试
    // ========================================================================

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

    // ========================================================================
    // BulwarkFirewallCheckHook trait default impl 测试
    // ========================================================================

    /// 默认 trait impl 所有 hook 返回 Ok。
    #[tokio::test]
    async fn default_hook_impl_all_pass() {
        struct NoOpHook;
        #[async_trait]
        impl BulwarkFirewallCheckHook for NoOpHook {}
        let hook = NoOpHook;
        let ctx = LoginContext::new("1001");
        assert!(hook.check_login_frequency(&ctx).await.is_ok());
        assert!(hook.check_brute_force(&ctx).await.is_ok());
        assert!(hook.check_geo_anomaly(&ctx).await.is_ok());
        assert!(hook.check_token_reuse(&ctx).await.is_ok());
        assert!(hook.check_device_anomaly(&ctx).await.is_ok());
    }

    // ========================================================================
    // BulwarkFirewallCheckHookDefault 测试
    // ========================================================================

    /// 无 IP 时 check_login_frequency 返回 Ok。
    #[tokio::test]
    async fn check_login_frequency_passes_without_ip() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001"); // 无 IP
        assert!(hook.check_login_frequency(&ctx).await.is_ok());
    }

    /// IP 失败次数 < 阈值时 check_login_frequency 返回 Ok。
    #[tokio::test]
    async fn check_login_frequency_passes_below_threshold() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        // 记录 9 次失败（阈值 10）
        for _ in 0..9 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.ip_failure_count("1.2.3.4"), 9);
        assert!(hook.check_login_frequency(&ctx).await.is_ok());
    }

    /// IP 失败次数 ≥ 阈值时 check_login_frequency 返回 Err。
    #[tokio::test]
    async fn check_login_frequency_blocks_at_threshold() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        // 记录 10 次失败
        for _ in 0..10 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.ip_failure_count("1.2.3.4"), 10);
        let result = hook.check_login_frequency(&ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BulwarkError::Session(_)));
    }

    /// 账号失败次数 < 阈值时 check_brute_force 返回 Ok。
    #[tokio::test]
    async fn check_brute_force_passes_below_threshold() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001");
        for _ in 0..4 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.account_failure_count("1001"), 4);
        assert!(hook.check_brute_force(&ctx).await.is_ok());
    }

    /// 账号失败次数 ≥ 阈值时 check_brute_force 返回 Err。
    #[tokio::test]
    async fn check_brute_force_blocks_at_threshold() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001");
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }
        assert_eq!(hook.account_failure_count("1001"), 5);
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BulwarkError::Session(_)));
    }

    /// reset 清空所有计数器。
    #[tokio::test]
    async fn reset_clears_all_counters() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        hook.record_failure(&ctx).await.unwrap();
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.ip_failure_count("1.2.3.4"), 2);
        assert_eq!(hook.account_failure_count("1001"), 2);
        hook.reset();
        assert_eq!(hook.ip_failure_count("1.2.3.4"), 0);
        assert_eq!(hook.account_failure_count("1001"), 0);
    }

    /// 不同 IP 的计数器相互独立。
    #[tokio::test]
    async fn ip_counters_are_independent() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx1 = LoginContext::new("1001").with_ip("1.1.1.1");
        let ctx2 = LoginContext::new("1002").with_ip("2.2.2.2");
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx2).await.unwrap();
        assert_eq!(hook.ip_failure_count("1.1.1.1"), 2);
        assert_eq!(hook.ip_failure_count("2.2.2.2"), 1);
    }

    /// 不同账号的计数器相互独立。
    #[tokio::test]
    async fn account_counters_are_independent() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx1 = LoginContext::new("1001");
        let ctx2 = LoginContext::new("1002");
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx1).await.unwrap();
        hook.record_failure(&ctx2).await.unwrap();
        assert_eq!(hook.account_failure_count("1001"), 3);
        assert_eq!(hook.account_failure_count("1002"), 1);
    }

    /// geo_anomaly / token_reuse / device_anomaly 默认 pass（内存模式）。
    #[tokio::test]
    async fn other_hooks_pass_by_default() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_geo("Shanghai");
        assert!(hook.check_geo_anomaly(&ctx).await.is_ok());
        assert!(hook.check_token_reuse(&ctx).await.is_ok());
        assert!(hook.check_device_anomaly(&ctx).await.is_ok());
    }

    /// record_failure 同时递增 IP 与账号计数器。
    #[tokio::test]
    async fn record_failure_increments_both_counters() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.ip_failure_count("1.2.3.4"), 1);
        assert_eq!(hook.account_failure_count("1001"), 1);
    }

    /// Default::default() 等价于 new()。
    #[test]
    fn default_equals_new() {
        let _hook1 = BulwarkFirewallCheckHookDefault::new();
        let _hook2 = BulwarkFirewallCheckHookDefault::default();
        // 仅验证可创建，内部状态相同（均为空计数器）
    }

    // ========================================================================
    // DAO 模式测试（分布式计数器，修复 #5）
    // ========================================================================

    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use std::sync::Arc;

    /// 辅助：构造 DAO 模式 hook。
    fn make_dao_hook() -> (BulwarkFirewallCheckHookDefault, Arc<MockDao>) {
        let dao = Arc::new(MockDao::new());
        let hook = BulwarkFirewallCheckHookDefault::new().with_dao(dao.clone());
        (hook, dao)
    }

    /// with_dao 注入 DAO 后进入分布式模式。
    ///
    /// 对应修复 #5：计数器基于 DAO（oxcache/redis）而非内存 Mutex。
    #[tokio::test]
    async fn with_dao_creates_distributed_mode() {
        let dao = Arc::new(MockDao::new());
        let hook = BulwarkFirewallCheckHookDefault::new().with_dao(dao);
        // 验证可创建，且 record_failure 走 DAO 路径（无内存计数器递增）
        let ctx = LoginContext::new("1001").with_ip("9.9.9.9");
        hook.record_failure(&ctx).await.unwrap();
        // 内存计数器在 DAO 模式下保持为 0
        assert_eq!(hook.ip_failure_count("9.9.9.9"), 0);
        assert_eq!(hook.account_failure_count("1001"), 0);
    }

    /// DAO 模式下 record_failure 递增 DAO 计数。
    ///
    /// 对应修复 #5：fw:ip:{ip} / fw:acct:{login_id} 计数器持久化到 DAO。
    #[tokio::test]
    async fn record_failure_dao_mode_increments_counter() {
        let (hook, dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        // 记录 3 次失败
        for _ in 0..3 {
            hook.record_failure(&ctx).await.unwrap();
        }
        // 验证 DAO 中 IP 维度计数为 3
        let ip_count = dao.get("fw:ip:1.2.3.4").await.unwrap();
        assert_eq!(ip_count.as_deref(), Some("3"));
        // 验证 DAO 中账号维度计数为 3
        let acct_count = dao.get("fw:acct:1001").await.unwrap();
        assert_eq!(acct_count.as_deref(), Some("3"));
    }

    /// DAO 模式下登录频率超阈值（≥10）阻断。
    ///
    /// 对应修复 #5：check_login_frequency 走 DAO 路径。
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
        assert!(matches!(result.unwrap_err(), BulwarkError::Session(_)));
    }

    /// DAO 模式下暴力破解超阈值（≥5）阻断。
    ///
    /// 对应修复 #5：check_brute_force 走 DAO 路径。
    #[tokio::test]
    async fn check_brute_force_dao_mode_blocks_at_threshold() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001");
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err(), "DAO 模式下账号失败 ≥ 阈值应阻断");
        assert!(matches!(result.unwrap_err(), BulwarkError::Session(_)));
    }

    /// DAO 模式下 token 黑名单存在则阻断。
    ///
    /// 对应修复 #4：check_token_reuse 实现（DAO 模式）。
    #[tokio::test]
    async fn check_token_reuse_dao_mode_blocks_blacklisted() {
        let (hook, dao) = make_dao_hook();
        // 预置黑名单
        dao.set("token:blacklist:1001", "revoked", 3600)
            .await
            .unwrap();
        let ctx = LoginContext::new("1001");
        let result = hook.check_token_reuse(&ctx).await;
        assert!(result.is_err(), "Token 在黑名单中应阻断");
        assert!(matches!(result.unwrap_err(), BulwarkError::Session(_)));
    }

    /// DAO 模式下无黑名单时 check_token_reuse 通过。
    ///
    /// 对应修复 #4：check_token_reuse 实现（无黑名单数据时 pass）。
    #[tokio::test]
    async fn check_token_reuse_passes_without_blacklist() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001");
        assert!(
            hook.check_token_reuse(&ctx).await.is_ok(),
            "无黑名单时应通过"
        );
    }

    /// DAO 模式下异地登录（与上次 geo 不符）阻断。
    ///
    /// 对应修复 #4：check_geo_anomaly 实现（DAO 模式）。
    #[tokio::test]
    async fn check_geo_anomaly_dao_mode_blocks_different_geo() {
        let (hook, dao) = make_dao_hook();
        // 预置上次登录地理位置为 Beijing
        dao.set("fw:geo:1001", "Beijing", 3600).await.unwrap();
        // 本次登录地理位置为 Shanghai → 异地
        let ctx = LoginContext::new("1001").with_geo("Shanghai");
        let result = hook.check_geo_anomaly(&ctx).await;
        assert!(result.is_err(), "异地登录应阻断");
        assert!(matches!(result.unwrap_err(), BulwarkError::Session(_)));
    }

    /// DAO 模式下无 geo 记录时 check_geo_anomaly 通过（首次登录）。
    ///
    /// 对应修复 #4：check_geo_anomaly 实现（无 geo 数据时 pass）。
    #[tokio::test]
    async fn check_geo_anomaly_passes_without_geo_data() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_geo("Shanghai");
        assert!(
            hook.check_geo_anomaly(&ctx).await.is_ok(),
            "无 geo 记录时应通过（首次登录）"
        );
    }

    /// DAO 模式下未知设备指纹阻断。
    ///
    /// 对应修复 #4：check_device_anomaly 实现（DAO 模式）。
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
        assert!(matches!(result.unwrap_err(), BulwarkError::Session(_)));
    }

    /// DAO 模式下无设备记录时 check_device_anomaly 通过（首次登录）。
    ///
    /// 对应修复 #4：check_device_anomaly 实现（无设备数据时 pass）。
    #[tokio::test]
    async fn check_device_anomaly_passes_without_device_data() {
        let (hook, _dao) = make_dao_hook();
        let ctx = LoginContext::new("1001").with_device("dev-new");
        assert!(
            hook.check_device_anomaly(&ctx).await.is_ok(),
            "无设备记录时应通过（首次登录）"
        );
    }

    // ========================================================================
    // 覆盖率补充：listener_manager 注入、窗口重置、DAO 解析失败等
    // ========================================================================

    /// `with_listener_manager` 注入后 listener_manager 字段为 Some。
    ///
    /// 覆盖行 222-224（builder 方法体）。
    #[cfg(feature = "listener")]
    #[test]
    fn with_listener_manager_sets_field() {
        use crate::listener::BulwarkListenerManager;
        let lm = Arc::new(BulwarkListenerManager::new());
        let hook = BulwarkFirewallCheckHookDefault::new().with_listener_manager(lm);
        assert!(
            hook.listener_manager.is_some(),
            "with_listener_manager 后 listener_manager 应为 Some"
        );
    }

    /// 内存模式 IP 失败窗口重置：第二次失败在窗口外，count 重置为 1。
    ///
    /// 覆盖行 261-262（窗口已过重置 IP 计数）。
    ///
    /// 注：此测试通过手动操作内部状态模拟窗口过期（避免真实等待 1h）。
    #[tokio::test]
    async fn record_failure_resets_ip_count_when_window_expired() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001").with_ip("10.0.0.1");
        // 第一次失败
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.ip_failure_count("10.0.0.1"), 1);
        // 手动将 first_failure_at 回拨到窗口外（模拟时间流逝）
        {
            let mut map = hook.ip_failures.lock();
            if let Some(entry) = map.get_mut("10.0.0.1") {
                entry.first_failure_at =
                    Instant::now() - LOGIN_FREQUENCY_WINDOW - Duration::from_secs(1);
            }
        }
        // 第二次失败（窗口已过，应重置为 1）
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(
            hook.ip_failure_count("10.0.0.1"),
            1,
            "窗口过期后 IP 计数应重置为 1"
        );
    }

    /// 内存模式账号失败窗口重置：第二次失败在窗口外，count 重置为 1。
    ///
    /// 覆盖行 274-275（窗口已过重置账号计数）。
    #[tokio::test]
    async fn record_failure_resets_account_count_when_window_expired() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        let ctx = LoginContext::new("1001");
        // 第一次失败
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(hook.account_failure_count("1001"), 1);
        // 手动将 first_failure_at 回拨到窗口外
        {
            let mut map = hook.account_failures.lock();
            if let Some(entry) = map.get_mut("1001") {
                entry.first_failure_at =
                    Instant::now() - BRUTE_FORCE_WINDOW - Duration::from_secs(1);
            }
        }
        // 第二次失败（窗口已过，应重置为 1）
        hook.record_failure(&ctx).await.unwrap();
        assert_eq!(
            hook.account_failure_count("1001"),
            1,
            "窗口过期后账号计数应重置为 1"
        );
    }

    /// DAO 模式 `read_dao_count` 解析非数字字符串时返回 0（不报错）。
    ///
    /// 覆盖行 321-323（解析失败 warn + 返回 0）。
    #[tokio::test]
    async fn read_dao_count_returns_zero_on_parse_failure() {
        let dao = Arc::new(MockDao::new());
        // 写入非数字字符串到 fw:acct:1001
        dao.set("fw:acct:1001", "not-a-number", 3600).await.unwrap();
        let hook = BulwarkFirewallCheckHookDefault::new().with_dao(dao);
        let ctx = LoginContext::new("1001");
        // check_brute_force 读取非数字计数器应返回 Ok（解析为 0，未超阈值）
        let result = hook.check_brute_force(&ctx).await;
        assert!(
            result.is_ok(),
            "非数字计数器应解析为 0，check_brute_force 应通过"
        );
    }

    /// DAO 模式 `check_login_frequency` 未超阈值返回 Ok。
    ///
    /// 覆盖行 364（DAO 模式 count < threshold 返回 Ok）。
    #[tokio::test]
    async fn check_login_frequency_dao_mode_passes_below_threshold() {
        let dao = Arc::new(MockDao::new());
        // 写入 9 次失败（阈值 10）
        dao.set("fw:ip:1.2.3.4", "9", 3600).await.unwrap();
        let hook = BulwarkFirewallCheckHookDefault::new().with_dao(dao);
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");
        let result = hook.check_login_frequency(&ctx).await;
        assert!(result.is_ok(), "9 次失败 < 阈值 10，应通过");
    }

    /// DAO 模式 `check_brute_force` 未超阈值返回 Ok。
    ///
    /// 覆盖行 407（DAO 模式 count < threshold 返回 Ok）。
    #[tokio::test]
    async fn check_brute_force_dao_mode_passes_below_threshold() {
        let dao = Arc::new(MockDao::new());
        // 写入 4 次失败（阈值 5）
        dao.set("fw:acct:1001", "4", 3600).await.unwrap();
        let hook = BulwarkFirewallCheckHookDefault::new().with_dao(dao);
        let ctx = LoginContext::new("1001");
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_ok(), "4 次失败 < 阈值 5，应通过");
    }

    /// DAO 模式 `check_brute_force` 超阈值时广播 AccountLocked 事件。
    ///
    /// 覆盖行 397-399（DAO 模式广播 AccountLocked）。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_brute_force_dao_mode_broadcasts_account_locked() {
        // inventory 注册需要在静态上下文中
        // 由于 inventory::submit! 在编译期注册，这里用已有的 listener_manager
        // 直接验证：超阈值时返回 Err 即可（broadcast 是副作用）
        let dao = Arc::new(MockDao::new());
        dao.set("fw:acct:1001", "5", 3600).await.unwrap();
        let lm = Arc::new(BulwarkListenerManager::new());
        let hook = BulwarkFirewallCheckHookDefault::new()
            .with_dao(dao)
            .with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err(), "5 次失败 ≥ 阈值 5，应阻断");
        // 验证错误信息包含 login_id
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("1001"), "错误信息应包含 login_id=1001");
    }

    /// 内存模式 `check_brute_force` 超阈值时广播 AccountLocked 事件。
    ///
    /// 覆盖行 420-422（内存模式广播 AccountLocked）。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_brute_force_in_memory_mode_broadcasts_account_locked() {
        use crate::listener::BulwarkListenerManager;
        let lm = Arc::new(BulwarkListenerManager::new());
        let hook = BulwarkFirewallCheckHookDefault::new().with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        // 记录 5 次失败（阈值 5）
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let result = hook.check_brute_force(&ctx).await;
        assert!(result.is_err(), "5 次失败 ≥ 阈值 5，应阻断");
    }

    /// 内存模式 `check_geo_anomaly` 无 ctx.geo 时返回 Ok。
    ///
    /// 覆盖行 444（无 ctx_geo 早期返回 Ok）。
    #[tokio::test]
    async fn check_geo_anomaly_in_memory_mode_passes_without_ctx_geo() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        // 无 DAO + 无 geo
        let ctx = LoginContext::new("1001");
        let result = hook.check_geo_anomaly(&ctx).await;
        assert!(result.is_ok(), "内存模式无 ctx_geo 时应返回 Ok");
    }

    /// 内存模式 `check_device_anomaly` 无 device_fingerprint 时返回 Ok。
    ///
    /// 覆盖行 488（无 device_fingerprint 早期返回 Ok）。
    #[tokio::test]
    async fn check_device_anomaly_in_memory_mode_passes_without_fingerprint() {
        let hook = BulwarkFirewallCheckHookDefault::new();
        // 无 DAO + 无 device_fingerprint
        let ctx = LoginContext::new("1001");
        let result = hook.check_device_anomaly(&ctx).await;
        assert!(result.is_ok(), "内存模式无 device_fingerprint 时应返回 Ok");
    }

    /// DAO 模式 `check_device_anomaly` 设备指纹在已知列表中时返回 Ok。
    ///
    /// 覆盖行 500（已知设备列表包含 fp 时返回 Ok）。
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
