# 防火墙安全钩子（0.3.0 新增）

0.3.0 引入 `BulwarkFirewallCheckHook`，提供登录流程的可插拔安全检查，返回 `Err` 即阻断登录。

## 设计要点

- **`BulwarkFirewallCheckHook` trait**：5 个 async hook 方法，默认实现全 pass
- **`LoginContext`**：登录上下文（login_id + 可选 IP / 设备指纹 / 地理位置）
- **`BulwarkFirewallCheckHookDefault`**：基于内存计数器 + 时间窗口的默认实现
- **`with_firewall_hook` builder**：注入到 `BulwarkLogicDefault`
- **Hook 在 login 流程中调用**：任一返回 `Err` 阻止登录

## 5 个检查项

| 检查项 | hook 方法 | 触发条件 | 处置 |
|:---|:---|:---|:---|
| 登录频率 | `check_login_frequency` | 同 IP 1h 内 ≥ 10 次失败 | 阻断登录 |
| 暴力破解 | `check_brute_force` | 同账号 1h 内 ≥ 5 次失败 | 阻断登录 |
| 异地登录 | `check_geo_anomaly` | 短时间跨城市登录 | 阻断（无 geo 数据则 pass） |
| Token 复用 | `check_token_reuse` | 已登出 Token 再次使用 | 阻断（无黑名单则 pass） |
| 设备异常 | `check_device_anomaly` | 未知设备指纹登录 | 阻断（无设备库则 pass） |

调用顺序：登录频率 → 暴力破解 → 异地登录 → Token 复用 → 设备异常。

## BulwarkFirewallCheckHook trait

```rust
#[async_trait]
pub trait BulwarkFirewallCheckHook: Send + Sync {
    async fn check_login_frequency(&self, ctx: &LoginContext) -> BulwarkResult<()> { Ok(()) }
    async fn check_brute_force(&self, ctx: &LoginContext) -> BulwarkResult<()> { Ok(()) }
    async fn check_geo_anomaly(&self, ctx: &LoginContext) -> BulwarkResult<()> { Ok(()) }
    async fn check_token_reuse(&self, ctx: &LoginContext) -> BulwarkResult<()> { Ok(()) }
    async fn check_device_anomaly(&self, ctx: &LoginContext) -> BulwarkResult<()> { Ok(()) }
}
```

所有方法提供默认 `Ok(())`，业务方按需 override 特定检查项。

## LoginContext

```rust
let ctx = LoginContext::new(1001)
    .with_ip("192.168.1.1")
    .with_device("dev-fp-abc")
    .with_geo("Beijing");
```

链式 builder 设置 IP / 设备指纹 / 地理位置，0.3.0 简化设计仅含这些字段。

## 默认实现

`BulwarkFirewallCheckHookDefault` 仅实现前两项检测（基于 `parking_lot::Mutex<HashMap>` 内存计数器）：

```rust
use bulwark::strategy::hooks::{BulwarkFirewallCheckHookDefault, BulwarkFirewallCheckHook, LoginContext};

let hook = BulwarkFirewallCheckHookDefault::new();
let ctx = LoginContext::new(1001).with_ip("1.2.3.4");

// 业务方在登录失败时调用 record_failure
for _ in 0..10 { hook.record_failure(&ctx); }

// 后续登录时，hook 自动检查
assert!(hook.check_login_frequency(&ctx).await.is_err());  // ≥10 次阻断
```

- IP 计数器与账号计数器相互独立
- 窗口（1h）过后自动重置
- 其他 3 项检测保持默认 `Ok(())`（需外部数据源，0.3.0 简化）

## 注入到逻辑层

通过 `with_firewall_hook` builder 注入 `BulwarkLogicDefault`：

```rust
let logic = BulwarkLogicDefault::new(interface.clone())
    .with_firewall_hook(Arc::new(BulwarkFirewallCheckHookDefault::new()));
```

未注入时，login 流程跳过所有 hook（等同于全 pass）。

## 重要语义

- **强约束**：与 [插件系统](./plugin-system.md) 不同，防火墙 hook 返回 `Err` **会阻断登录**
- **单进程**：默认实现仅在单进程内有效；多实例部署需替换为基于 oxcache/redis 的分布式计数器
- **错误类型**：阻断时返回 `BulwarkError::Session`（含阈值与计数信息）

## 相关章节

- [插件系统](./plugin-system.md)（旁路增强，失败不阻断）
- [登录认证与会话](./auth-session.md)
