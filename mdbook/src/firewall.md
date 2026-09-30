# 防火墙安全钩子（0.3.0 新增）

0.3.0 引入 `GarrisonFirewallCheckHook`，提供登录流程的可插拔安全检查，返回 `Err` 即阻断登录。

注意：`strategy::hooks` 模块整体按 feature 编译，需启用 `firewall`（或 `firewall-ratelimit` / `firewall-bruteforce` / `firewall-ddos` / `sms-rate-limit` / `oauth2-server`）任一 feature 才可用；未启用任一 feature 时，本文的导入示例无法编译。

## 设计要点

- **`GarrisonFirewallCheckHook` trait**：5 个 async hook 方法，默认实现全 pass
- **`LoginContext`**：登录上下文（login_id + 可选 IP / 设备指纹 / 地理位置）
- **`GarrisonFirewallCheckHookDefault`**：基于 `GarrisonDaoDistributedLimiter`（limiteron 适配器）的默认实现，5 项检测全部实现
- **`with_firewall_hook` builder**：注入到 `GarrisonPermissionStrategyDefault`（启用 `firewall` feature 时 `GarrisonManager::builder()` 自动装配）
- **Hook 在 login 流程中调用**：任一返回 `Err` 阻止登录

## 5 个检查项

| 检查项 | hook 方法 | 触发条件 | 处置 |
|:---|:---|:---|:---|
| 登录频率 | `check_login_frequency` | 同 IP 1h 内 ≥ 10 次失败 | 阻断登录 |
| 暴力破解 | `check_brute_force` | 同账号 1h 内 ≥ 5 次失败 | 阻断登录 |
| 异地登录 | `check_geo_anomaly` | 短时间跨城市登录 | 阻断（无 geo 数据则 pass） |
| Token 复用 | `check_token_reuse` | 账号级黑名单 `token:blacklist:{login_id}` 存在（业务方检测到 token 泄露/复用后写入的账号级锁定；登出写的是 token 级 `jwt:blacklist:{jti}`，不触发本检查） | 阻断（无黑名单则 pass） |
| 设备异常 | `check_device_anomaly` | 未知设备指纹登录 | 阻断（无设备库则 pass） |

调用顺序：登录频率 → 暴力破解 → 异地登录 → Token 复用 → 设备异常。

## GarrisonFirewallCheckHook trait

```rust
#[async_trait]
pub trait GarrisonFirewallCheckHook: Send + Sync {
    async fn check_login_frequency(&self, ctx: &LoginContext) -> GarrisonResult<()> { Ok(()) }
    async fn check_brute_force(&self, ctx: &LoginContext) -> GarrisonResult<()> { Ok(()) }
    async fn check_geo_anomaly(&self, ctx: &LoginContext) -> GarrisonResult<()> { Ok(()) }
    async fn check_token_reuse(&self, ctx: &LoginContext) -> GarrisonResult<()> { Ok(()) }
    async fn check_device_anomaly(&self, ctx: &LoginContext) -> GarrisonResult<()> { Ok(()) }
}
```

所有方法提供默认 `Ok(())`，业务方按需 override 特定检查项。

## LoginContext

```rust
let ctx = LoginContext::new("1001")
    .with_ip("192.168.1.1")
    .with_device("dev-fp-abc")
    .with_geo("Beijing");
```

链式 builder 设置 IP / 设备指纹 / 地理位置，0.3.0 简化设计仅含这些字段。

## 默认实现

`GarrisonFirewallCheckHookDefault` 基于 `GarrisonDaoDistributedLimiter`（limiteron 适配器）实现，5 项检测全部覆盖：

```rust
use garrison::strategy::hooks::{GarrisonFirewallCheckHookDefault, GarrisonFirewallCheckHook, LoginContext};

let hook = GarrisonFirewallCheckHookDefault::new();
let ctx = LoginContext::new("1001").with_ip("1.2.3.4");

// 业务方在登录失败时调用 record_failure（async）
for _ in 0..10 { hook.record_failure(&ctx).await?; }

// 后续登录时，hook 自动检查
assert!(hook.check_login_frequency(&ctx).await.is_err());  // ≥10 次阻断
```

- IP 计数器与账号计数器相互独立
- 窗口（1h）由 limiteron TTL 自动重置
- 异地登录 / Token 复用 / 设备异常 3 项通过 DAO KV 读取实现（无数据时 pass）
- `record_failure` 为 async 方法（通过 limiteron 原子递增）

## 注入到权限策略层

通过 `with_firewall_hook` builder 注入 `GarrisonPermissionStrategyDefault`：

```rust
let strategy = GarrisonPermissionStrategyDefault::new(interface.clone())
    .with_firewall_hook(Arc::new(GarrisonFirewallCheckHookDefault::new()));
```

启用 `firewall` feature 时，`GarrisonManager::builder()` 会自动装配 `GarrisonFirewallCheckHookDefault`（共享 DAO 限流器），无需手动注入。

未注入时，login 流程跳过所有 hook（等同于全 pass）。

## 分布式模式

`GarrisonFirewallCheckHookDefault` 提供 3 个构造/builder 方法（前两个切换后端，第三个注入事件广播）：

- `new()`（`#[doc(hidden)]`，等价 `with_memory_default()`）：内存模式（内部 `InMemoryDao` 作为 limiteron 后端，开发/CI 与单实例场景）
- `with_dao(dao)`：分布式模式（注入 `GarrisonDao`，oxcache/redis 作为 limiteron 后端，生产场景）
- `with_listener_manager(lm)`：注入监听器管理器（需 `listener` feature），`check_brute_force` 阻断时广播 `AccountLocked` 事件

```rust
let hook = GarrisonFirewallCheckHookDefault::new()
    .with_dao(dao.clone())
    .with_listener_manager(lm);  // 需 listener feature
```

## 重要语义

- **强约束**：与 [插件系统](./plugin-system.md) 不同，防火墙 hook 返回 `Err` **会阻断登录**
- **分布式**：默认 `new()` 走 `InMemoryDao`（进程内）；生产环境用 `with_dao` 切换到 oxcache/redis，跨实例计数
- **错误类型**：阻断时返回 `GarrisonError::Session`（消息仅含 login_id / IP / geo / 设备指纹等冲突上下文，不含阈值与计数值）；limiteron 操作失败映射为 `GarrisonError::Dao`，DAO 操作失败原样向上传播（Fail Loud）

## 相关章节

- [插件系统](./plugin-system.md)（旁路增强，失败不阻断）
- [登录认证与会话](./auth-session.md)
