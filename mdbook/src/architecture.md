# 整体架构

Garrison 采用 **双抽象层 + 全局单例** 架构，采用双抽象层设计哲学，将业务回调、持久化、缓存、逻辑编排解耦。

## 分层总览

```text
┌──────────────────────────────────────────────┐
│  业务方代码（axum / actix-web / warp handler）│
├──────────────────────────────────────────────┤
│  GarrisonUtil（静态 API：login/check_login…）  │  ← 使用者面向的入口
├──────────────────────────────────────────────┤
│  5 子 trait + GarrisonCore（基座）             │
│  ├─ SessionLogic / PermissionLogic            │
│  ├─ TokenLogic / MfaLogic / PasswordLogic     │
│  └─ GarrisonLogicDefault（默认实现 + builder） │  ← 编排层
├──────────────────────────────────────────────┤
│  GarrisonInterface（业务回调 trait）           │  ← 业务方实现
├──────────────────────────────────────────────┤
│  oxcache（L1 内存 + L2 redis）│ dbnexus（DB）│  ← 双抽象层
└──────────────────────────────────────────────┘
```

## GarrisonManager 单例

`GarrisonManager` 持有全局 `Arc<GarrisonLogicDefault>`（基于 `parking_lot::RwLock`），支持覆盖式 `init`：

- 业务方启动时调用 `GarrisonManager::init(dao, config, interface)` 注入依赖
- `GarrisonUtil::login` / `GarrisonUtil::check_login` 等静态方法委托到全局单例
- `init` 自动注入 `PluginManager` / `ListenerManager` / `AuthLogic` / `PermissionChecker`（0.2.1 auto-wire 修复）

> v0.5.2 起，原 `GarrisonLogic` 上帝 trait 已删除，拆分为 5 个子 trait（`SessionLogic` / `PermissionLogic` / `TokenLogic` / `MfaLogic` / `PasswordLogic`），super-trait 为 `GarrisonCore`。`GarrisonLogicDefault` 实现全部 5 个子 trait，Manager / Strategy / Factory 等持有方改为具体类型 `Arc<GarrisonLogicDefault>`，方法调用通过子 trait 解析。

## 三层逻辑结构

| 层 | 角色 | 职责 |
|:---|:---|:---|
| `GarrisonCore` + 5 子 trait | 接口抽象 | `SessionLogic`（login / logout / check_login）、`PermissionLogic`（check_permission / check_role）、`TokenLogic`（token 生成/校验/续期）、`MfaLogic`（二级认证）、`PasswordLogic`（密码校验） |
| `GarrisonLogicDefault` | 默认实现 | 编排 dao / interface / plugin / listener / metrics / firewall，实现全部 5 个子 trait，提供 `with_*` builder |
| `GarrisonInterface` | 业务回调 | 业务方实现，提供 `get_permission_list` / `get_role_list` / `get_device_info` 等 |
| `GarrisonUtil` | 静态 API | 面向使用者的便捷入口，委托到 `GarrisonManager` 全局单例 |

## inventory 编译期注册

`GarrisonLogicFactory` 通过 `inventory::submit!` 在编译期注册，运行时由 `inventory::iter` 选取。这样框架无需显式构造即可在 `init` 时找到默认 factory，业务方也可注册自定义 factory 覆盖默认实现。

```rust
// 框架内部注册默认 factory
inventory::submit! {
    GarrisonLogicFactory { /* 构造 GarrisonLogicDefault */ }
}
```

## 核心模块组织（always on）

以下模块无 feature flag，总是编译：

- **核心编排**：`core` / `stp` / `manager` / `strategy` / `plugin`
- **数据访问**：`dao` / `session` / `state` / `config` / `context`
- **基础设施**：`constants` / `error` / `exception` / `json` / `i18n` / `health` / `annotation` / `router`
- **业务能力**：`account` / `abac`
- **公共入口**：`prelude`

协议层、安全模块、Web 适配、可观测性、缓存三层架构、监听器等通过 feature 按需启用。

## 上下文传播

请求上下文通过 `GarrisonContext` + `task_local` 在异步任务间传播，承载当前 token、请求头、IP 等信息。web 中间件（如 `GarrisonLayer`）负责在请求进入时设置 task_local，`GarrisonUtil` 读取它来定位当前会话。

## 相关章节

- [双抽象层（oxcache + dbnexus）](./abstraction-layers.md)
- [插件系统](./plugin-system.md)
