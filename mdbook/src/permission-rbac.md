# 权限与角色（RBAC）

Garrison 提供 RBAC 权限模型，通过 `GarrisonStrategy` 与 `GarrisonPermissionStrategy` 编排权限/角色校验。

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
    async fn get_permission_list(&self, login_id: i64) -> GarrisonResult<Vec<String>> {
        // 从业务数据库查询用户权限码
        Ok(db.query_permissions(login_id).await?)
    }
    async fn get_role_list(&self, login_id: i64) -> GarrisonResult<Vec<String>> {
        Ok(db.query_roles(login_id).await?)
    }
}
```

## GarrisonStrategy 与 GarrisonPermissionStrategy

| 类型 | 职责 |
|:---|:---|
| `GarrisonStrategy` | 权限/角色校验的顶层策略抽象 |
| `GarrisonPermissionStrategy` | 默认实现，编排 interface 查询、缓存、插件钩子 |
| `GarrisonPermissionStrategyDefault` | 0.2.0 扩展，支持 `with_permission_checker` / `with_role_hierarchy` / `with_plugin_manager` / `with_dao` / `with_firewall_hook` / `with_listener_manager` |

`GarrisonPermissionStrategyDefault` 通过 builder 注入依赖：

```rust
let strategy = GarrisonPermissionStrategyDefault::new(interface.clone())
    .with_permission_checker(checker)
    .with_role_hierarchy(hierarchy)
    .with_plugin_manager(plugin_mgr)
    .with_dao(dao.clone())               // 启用权限缓存
    .with_firewall_hook(fw_hook)         // 启用登录前 5 项防火墙检查（需 firewall feature）
    .with_listener_manager(lm);          // 启用 FirewallBlock 事件广播（需 listener feature）
```

## 角色层级 hierarchy

`with_role_hierarchy` 注入角色层级映射，支持"继承"语义：拥有高级角色自动拥有低级角色的权限。例如 `admin` > `manager` > `user`，校验 `check_role("manager")` 时，`admin` 用户也通过。

> 角色层级为 0.4.0 重点完善项，0.3.0 提供基础映射支持。

## 权限缓存

启用 `with_dao` 后，`GarrisonPermissionStrategyDefault` 会将权限/角色列表缓存到 oxcache，避免每次校验都查询 `GarrisonInterface`。缓存 TTL 与会话一致，登出时自动失效。

## ABAC（属性级访问控制）

除 RBAC 外，Garrison 通过 `abac` feature 提供基于 `cedar-policy` 的 ABAC 引擎，作为 RBAC 的增量校验层（RBAC 通过后再检查 ABAC）：

```toml
[dependencies]
garrison = { version = "0.7", features = ["abac"] }
```

核心类型：

- `AbacEngine`：Cedar 策略求值器
- `EntityLoader` trait：Cedar Entities 数据源（内置 `EmptyEntityLoader` / `StaticEntityLoader`）
- `init_abac_engine`：初始化全局 AbacEngine
- `check_abac_with_policy`：宏入口，用于在 RBAC 通过后调用 ABAC 求值

`abac` feature 关闭时 `check_abac_with_policy` 提供 no-op stub，确保宏生成的代码在任意 feature 组合下均可编译。详见 `src/abac/`。

## 校验流程

1. `check_login` 确认已登录（否则抛 `NotLogin`）
2. 调用 `GarrisonInterface::get_permission_list` 获取权限（命中缓存则跳过）
3. 检查权限码是否在列表中（考虑角色层级展开）
4. 触发 `GarrisonPlugin::on_permission_check` 钩子（失败仅 warn）
5. 通过 metrics 记录 `garrison_permission_query_total{result=allow|deny}`

## 相关章节

- [登录认证与会话](./auth-session.md)
- [插件系统](./plugin-system.md)
- [防火墙安全钩子](./firewall.md)（登录前 5 项安全检查）
