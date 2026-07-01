# 权限与角色（RBAC）

Bulwark 提供 RBAC 权限模型，通过 `BulwarkStrategy` 与 `BulwarkFirewallStrategy` 编排权限/角色校验。

## 核心 API

```rust
use bulwark::prelude::*;

// 权限校验：当前登录用户是否拥有 "user:create" 权限
let ok = BulwarkUtil::check_permission("user:create").await?;

// 角色校验：当前登录用户是否拥有 "admin" 角色
let ok = BulwarkUtil::check_role("admin").await?;
```

校验结果受 `throw_on_not_login` 影响：默认未登录抛异常。校验失败返回 `BulwarkError::NotPermission` / `BulwarkError::NotRole`。

## 权限来源

权限与角色列表由业务方在 `BulwarkInterface` 中实现，框架调用并缓存：

```rust
#[async_trait]
impl BulwarkInterface for MyInterface {
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        // 从业务数据库查询用户权限码
        Ok(db.query_permissions(login_id).await?)
    }
    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(db.query_roles(login_id).await?)
    }
}
```

## BulwarkStrategy 与 BulwarkFirewallStrategy

| 类型 | 职责 |
|:---|:---|
| `BulwarkStrategy` | 权限/角色校验的顶层策略抽象 |
| `BulwarkFirewallStrategy` | 默认实现，编排 interface 查询、缓存、插件钩子 |
| `BulwarkFirewallStrategyDefault` | 0.2.0 扩展，支持 `with_permission_checker` / `with_role_hierarchy` / `with_plugin_manager` / `with_dao`（权限缓存） |

`BulwarkFirewallStrategyDefault` 通过 builder 注入依赖：

```rust
let strategy = BulwarkFirewallStrategyDefault::new(interface.clone())
    .with_permission_checker(checker)
    .with_role_hierarchy(hierarchy)
    .with_plugin_manager(plugin_mgr)
    .with_dao(dao.clone());  // 启用权限缓存
```

## 角色层级 hierarchy

`with_role_hierarchy` 注入角色层级映射，支持"继承"语义：拥有高级角色自动拥有低级角色的权限。例如 `admin` > `manager` > `user`，校验 `check_role("manager")` 时，`admin` 用户也通过。

> 角色层级为 0.4.0 重点完善项，0.3.0 提供基础映射支持。

## 权限缓存

启用 `with_dao` 后，`BulwarkFirewallStrategyDefault` 会将权限/角色列表缓存到 oxcache，避免每次校验都查询 `BulwarkInterface`。缓存 TTL 与会话一致，登出时自动失效。

## 校验流程

1. `check_login` 确认已登录（否则抛 `NotLogin`）
2. 调用 `BulwarkInterface::get_permission_list` 获取权限（命中缓存则跳过）
3. 检查权限码是否在列表中（考虑角色层级展开）
4. 触发 `BulwarkPlugin::on_permission_check` 钩子（失败仅 warn）
5. 通过 metrics 记录 `bulwark_permission_query_total{result=allow|deny}`

## 相关章节

- [登录认证与会话](./auth-session.md)
- [插件系统](./plugin-system.md)
