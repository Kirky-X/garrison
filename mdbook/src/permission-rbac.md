# 权限与角色（RBAC）

Garrison 提供 RBAC 权限模型，通过 `GarrisonPermissionStrategy` trait 与默认实现 `GarrisonPermissionStrategyDefault` 编排权限/角色校验。

## 核心 API

```rust
use garrison::prelude::*;

// 权限校验：当前登录用户是否拥有 "user:create" 权限（未持有抛 NotPermission）
GarrisonUtil::check_permission("user:create").await?;

// 角色校验：当前登录用户是否拥有 "admin" 角色（未持有抛 NotRole）
GarrisonUtil::check_role("admin").await?;

// 布尔式查询：未持有或未登录返回 Ok(false)，不抛异常
let has = GarrisonUtil::has_permission("user:create").await?;
let has = GarrisonUtil::has_role("admin").await?;

// 获取当前登录主体的权限/角色列表（未登录返回空 Vec）
let perms = GarrisonUtil::get_permission_list().await?;
let roles = GarrisonUtil::get_role_list().await?;
```

校验结果受 `throw_on_not_login` 影响：默认未登录抛异常。`check_*` 失败返回 `GarrisonError::NotPermission` / `GarrisonError::NotRole`；`has_*` 将 `NotLogin` / `NotPermission` / `NotRole` 映射为 `Ok(false)`，其余错误透传。

## 权限来源

权限与角色列表由业务方在 `GarrisonInterface` 中实现，框架调用并缓存：

```rust
#[async_trait]
impl GarrisonInterface for MyInterface {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        // 从业务数据库查询用户权限码
        Ok(db.query_permissions(login_id).await?)
    }
    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(db.query_roles(login_id).await?)
    }
}
```

## GarrisonPermissionStrategy 与 GarrisonPermissionStrategyDefault

| 类型 | 职责 |
|:---|:---|
| `GarrisonPermissionStrategy` | 权限/角色校验的顶层策略抽象（trait） |
| `GarrisonPermissionStrategyDefault` | 默认实现，编排 interface 查询、缓存、插件钩子；0.2.0 扩展，支持 `with_permission_checker` / `with_role_hierarchy` / `with_plugin_manager` / `with_dao` / `with_firewall_hook` / `with_listener_manager` |

`GarrisonPermissionStrategyDefault` 通过 builder 注入依赖：

```rust
let strategy = GarrisonPermissionStrategyDefault::new(interface.clone())
    .with_permission_checker(checker)
    .with_role_hierarchy(hierarchy)
    .with_plugin_manager(plugin_mgr)
    .with_dao(dao.clone())               // 启用权限缓存
    .with_firewall_hook(fw_hook)         // 启用登录前 5 项防火墙检查（防火墙相关 feature 任一即可：sms-rate-limit / firewall-ratelimit / firewall-bruteforce / firewall-ddos / firewall / oauth2-server）
    .with_listener_manager(lm);          // 启用 FirewallBlock 事件广播（需 listener feature）
```

## 角色层级 hierarchy

`with_role_hierarchy` 注入角色层级映射，支持"继承"语义：拥有高级角色自动拥有低级角色的权限。例如 `admin` > `manager` > `user`，校验 `check_role("manager")` 时，`admin` 用户也通过。

> 角色层级基础映射自 0.2.0 起支持（`with_role_hierarchy` 注入）；0.5.0 新增 `role_hierarchy` 表（`child_role`/`parent_role`/`tenant_id` + TC 预计算），登录时缓存权限并集。

## 权限缓存

启用 `with_dao` 后，`GarrisonPermissionStrategyDefault` 会将权限校验结果（布尔值，而非权限/角色列表）缓存到注入的 `GarrisonDao`（如 oxcache），键为 `garrison:perm:cache:<tenant>:<login_id>:<permission>`（未配置 `with_tenant_id` 时租户位为占位符 `_`），避免每次校验都回源查询 `GarrisonInterface` 或委托 `PermissionChecker`。缓存 TTL 固定 300 秒，并非与会话一致；登出/踢出时会经 `invalidate_login_cache` 尽力失效（失败仅 warn，由 TTL 兜底），不经过登出的权限/角色变更需业务方显式调用 `invalidate_permission_cache`。角色校验（`check_role` 等）不读写该缓存。

## ABAC（属性级访问控制）

除 RBAC 外，Garrison 通过 `abac` feature 提供基于 `cedar-policy` 的 ABAC 引擎，作为 RBAC 的增量校验层（RBAC 通过后再检查 ABAC）：

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["abac"] }
```

> 注：当前版本为 pre-release（0.9.0-rc.2），`version = "0.8"` 不会匹配它——Cargo 要求显式写出完整 pre-release 版本号；待 0.9.0 正式发布后可再改为 `"0.9"`。

核心类型：

- `AbacEngine`：Cedar 策略求值器
- `EntityLoader` trait：Cedar Entities 数据源（内置 `EmptyEntityLoader` / `StaticEntityLoader`）
- `init_abac_engine`：初始化全局 AbacEngine
- `check_abac_with_policy`：宏入口，用于在 RBAC 通过后调用 ABAC 求值

`abac` feature 关闭时 `check_abac_with_policy` 降级为 fail-closed stub：端点声明了 `abac` 策略时默认返回 `Err(GarrisonError::Config)`，未声明策略（空 `abac_expr`）时为 no-op；可通过 `set_abac_missing_feature_policy(true)` 显式 opt-in 为放行 + warn。函数始终存在，确保宏生成的代码在任意 feature 组合下均可编译。详见 `src/abac/`。

## 校验流程

1. `get_login_id` 确认已登录（未登录时按 `throw_on_not_login` 抛 `NotLogin`，为 false 时降级抛 `NotPermission`）
2. 触发 `GarrisonPluginManager::on_permission_check` 插件钩子（权限判定前调用，缓存命中路径亦然；失败仅 warn）
3. 查询权限（命中 `with_dao` 权限缓存则跳过 `GarrisonInterface` 查询）
4. 权限码做精确字符串匹配，或委托注入的 `PermissionChecker`（角色层级展开仅用于角色校验，不参与权限匹配）
5. 通过 metrics 记录 `garrison_permission_query_total{result=allow|deny}`（需 `metrics-prometheus` feature）

## 相关章节

- [登录认证与会话](./auth-session.md)
- [插件系统](./plugin-system.md)
- [防火墙安全钩子](./firewall.md)（登录前 5 项安全检查）
