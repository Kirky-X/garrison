# 插件系统

Garrison 提供基于 `inventory` 编译期注册的插件系统，允许业务方在登录、登出、权限校验等关键流程注入自定义逻辑。

## 设计要点

- **`GarrisonPlugin` trait**：定义 `on_login` / `on_logout` / `on_permission_check` 等钩子
- **`inventory` 编译期注册**：插件通过 `inventory::submit!` 注册，无需运行时配置
- **`GarrisonPluginManager`**：管理所有已注册插件，按顺序调用钩子
- **失败策略**：插件钩子失败仅 `warn` 记录，不阻断主流程（保证认证可用性优先）

## GarrisonPlugin trait

```rust
pub trait GarrisonPlugin: Send + Sync {
    /// 插件名称，用于唯一标识（必需，无默认实现）
    fn name(&self) -> &str;

    /// 登录成功后调用（token 已生成）
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> { Ok(()) }

    /// 登出时调用（token 即将失效）
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> { Ok(()) }

    /// 权限校验时调用（在主校验之后）
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> { Ok(()) }
}
```

- trait 为**同步** trait（不使用 `#[async_trait]`），3 个钩子均返回 `GarrisonResult<()>`
- `login_id` 为 `&str`（v0.5.2 迁移：原 `i64` → `String`，与全局 login_id 迁移一致）
- `fn name(&self) -> &str` 为必需方法（无默认实现），用于唯一标识插件
- 其余 3 个钩子提供默认 `Ok(())` 实现，业务方按需 override

## 注册插件

通过 `inventory::submit!` 在编译期注册，`GarrisonPluginManager` 启动时通过 `inventory::iter` 收集所有插件：

```rust
use garrison::plugin::{GarrisonPlugin, GarrisonPluginEntry};
use std::sync::Arc;

struct AuditPlugin;

impl GarrisonPlugin for AuditPlugin {
    fn name(&self) -> &str { "audit-plugin" }

    fn on_login(&self, login_id: &str, _token: &str) -> GarrisonResult<()> {
        tracing::info!(login_id, "用户登录审计");
        Ok(())
    }
}

// 工厂函数：返回 Arc<dyn GarrisonPlugin>
fn audit_plugin_factory() -> Arc<dyn GarrisonPlugin> {
    Arc::new(AuditPlugin)
}

// 编译期注册（字段名为 factory，类型 fn() -> Arc<dyn GarrisonPlugin>）
inventory::submit! {
    GarrisonPluginEntry { factory: audit_plugin_factory }
}
```

## GarrisonPluginManager

- `GarrisonManager::init` 自动注入 `PluginManager`（0.2.1 auto-wire 修复）
- 也可通过 `GarrisonLogicDefault::with_plugin_manager` 手动注入
- 钩子按注册顺序调用；任一插件返回 `Err` 仅记录 `warn`，不中断后续插件与主流程

## 失败策略与边界

| 行为 | 结果 |
|:---|:---|
| 插件 `on_login` 返回 `Err` | `warn` 记录，登录仍成功 |
| 插件 `on_logout` 返回 `Err` | `warn` 记录，登出仍完成 |
| 插件 `on_permission_check` 返回 `Err` | `warn` 记录，权限校验结果由主流程决定 |
| 插件 panic | 不被捕获，会导致请求失败（应避免） |

> 注意：插件用于 **旁路增强**（审计、通知、缓存预热等），不适合用作强一致约束。强约束请使用 [防火墙钩子](./firewall.md)（返回 `Err` 阻断登录）。

## 与监听器的区别

`listener`（`GarrisonListenerManager`）提供事件订阅（Login / Logout / PermissionCheck / Kickout），是只读通知；插件可在钩子内执行写操作（如更新缓存、写审计表）。两者互补，监听器只读、插件可写但失败不阻断。
