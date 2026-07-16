# 整体架构

Bulwark 采用 **双抽象层 + 全局单例** 架构，采用双抽象层设计哲学，将业务回调、持久化、缓存、逻辑编排解耦。

## 分层总览

```text
┌──────────────────────────────────────────────┐
│  业务方代码（axum / actix-web / warp handler）│
├──────────────────────────────────────────────┤
│  BulwarkUtil（静态 API：login/check_login…）  │  ← 使用者面向的入口
├──────────────────────────────────────────────┤
│  BulwarkLogic（顶层逻辑 trait）               │
│  └─ BulwarkLogicDefault（默认实现 + builder） │  ← 编排层
├──────────────────────────────────────────────┤
│  BulwarkInterface（业务回调 trait）           │  ← 业务方实现
├──────────────────────────────────────────────┤
│  oxcache（L1 moka + L2 redis）│ dbnexus（DB）│  ← 双抽象层
└──────────────────────────────────────────────┘
```

## BulwarkManager 单例

`BulwarkManager` 持有全局 `Arc<dyn BulwarkLogic>`（基于 `parking_lot::RwLock`），支持覆盖式 `init`：

- 业务方启动时调用 `BulwarkManager::init(dao, config, interface)` 注入依赖
- `BulwarkUtil::login` / `BulwarkUtil::check_login` 等静态方法委托到全局单例
- `init` 自动注入 `PluginManager` / `ListenerManager` / `AuthLogic` / `PermissionChecker`（0.2.1 auto-wire 修复）

## 三层逻辑结构

| 层 | 角色 | 职责 |
|:---|:---|:---|
| `BulwarkLogic` | 顶层抽象 | 定义 login / logout / check_login / check_permission / check_role 等核心方法 |
| `BulwarkLogicDefault` | 默认实现 | 编排 dao / interface / plugin / listener / metrics / firewall，提供 `with_*` builder |
| `BulwarkInterface` | 业务回调 | 业务方实现，提供 `get_permission_list` / `get_role_list` / `get_device_info` 等 |
| `BulwarkUtil` | 静态 API | 面向使用者的便捷入口，委托到 `BulwarkManager` 全局单例 |

## inventory 编译期注册

`BulwarkLogicFactory` 通过 `inventory::submit!` 在编译期注册，运行时由 `inventory::iter` 选取。这样框架无需显式构造即可在 `init` 时找到默认 factory，业务方也可注册自定义 factory 覆盖默认实现。

```rust
// 框架内部注册默认 factory
inventory::submit! {
    BulwarkLogicFactory { /* 构造 BulwarkLogicDefault */ }
}
```

## 核心模块组织（always on）

`core` / `stp` / `annotation` / `router` / `dao` / `strategy` / `session` / `config` / `context` / `json` / `exception` / `manager` / `plugin` 这些模块无 feature flag，总是编译。协议层、安全模块、Web 适配、可观测性通过 feature 按需启用。

## 上下文传播

请求上下文通过 `BulwarkContext` + `task_local` 在异步任务间传播，承载当前 token、请求头、IP 等信息。web 中间件（如 `BulwarkLayer`）负责在请求进入时设置 task_local，`BulwarkUtil` 读取它来定位当前会话。

## 相关章节

- [双抽象层（oxcache + dbnexus）](./abstraction-layers.md)
- [插件系统](./plugin-system.md)
