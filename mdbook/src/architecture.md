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

`GarrisonManager` 持有全局 `Arc<GarrisonLogicDefault>`（基于 `arc_swap::ArcSwapOption`，读路径无锁、支持重复 init），支持覆盖式 `init`：

- 业务方启动时调用 `GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await` 注入依赖
- `GarrisonUtil::login` / `GarrisonUtil::check_login` 等静态方法委托到全局单例
- `init` 自动注入 `PluginManager` / `ListenerManager` / `AuthLogic` / `PermissionChecker`（0.2.1 auto-wire 修复）

> v0.5.2 起，原 `GarrisonLogic` 上帝 trait 已删除，拆分为 5 个子 trait（`SessionLogic` / `PermissionLogic` / `TokenLogic` / `MfaLogic` / `PasswordLogic`），super-trait 为 `GarrisonCore`。`GarrisonLogicDefault` 实现全部 5 个子 trait，Manager / Strategy / Factory 等持有方改为具体类型 `Arc<GarrisonLogicDefault>`，方法调用通过子 trait 解析。

## 三层逻辑结构

| 层 | 角色 | 职责 |
|:---|:---|:---|
| `GarrisonCore` + 5 子 trait | 接口抽象 | `SessionLogic`（login / logout / check_login）、`PermissionLogic`（check_permission / check_role）、`TokenLogic`（check_access_token / verify_token / refresh_token）、`MfaLogic`（二级认证）、`PasswordLogic`（密码校验） |
| `GarrisonLogicDefault` | 默认实现 | 编排 dao / interface / plugin / listener / metrics / firewall，实现全部 5 个子 trait，提供 `with_*` builder |
| `GarrisonInterface` | 业务回调 | 业务方实现，提供 `get_permission_list` / `get_role_list`（及 `get_permission_list_with_type` / `get_role_list_with_type` 变体）等 |
| `GarrisonUtil` | 静态 API | 面向使用者的便捷入口，委托到 `GarrisonManager` 全局单例 |

## inventory 编译期注册

`GarrisonLogicFactoryEntry`（含 `name` 与工厂函数指针）通过 `inventory::submit!` 在编译期注册，运行时由 `inventory::iter` 选取第一个 entry，框架默认注册的工厂函数为 `garrison_logic_factory_default`。这样框架无需显式构造即可在 `init` 时找到默认 factory。业务方如需自定义 factory，应通过 `GarrisonManagerBuilder::with_factory(&'static GarrisonLogicFactoryEntry)` 注入以覆盖默认实现——仅向 `inventory` 追加自定义 entry 并不能保证覆盖默认（运行时 selector 只取第一个 entry）。

```rust
// 框架内部注册默认 factory
inventory::submit! {
    GarrisonLogicFactoryEntry {
        name: "default",
        factory: garrison_logic_factory_default,
    }
}
```

## 核心模块组织（always on）

以下模块无 feature flag，总是编译：

- **核心编排**：`core` / `stp` / `manager` / `strategy` / `plugin`
- **数据访问**：`dao` / `session` / `state` / `config` / `context`
- **基础设施**：`constants` / `error` / `exception` / `json` / `i18n` / `health` / `annotation` / `router`
- **业务能力**：`account` / `abac`
- **公共入口**：`prelude`

协议层顶层模块始终编译，其中 oauth2 / sso / jwt / sign / apikey / temp 等重依赖子模块在 `protocol/mod.rs` 内按 feature 门控；安全模块、Web 适配、可观测性、缓存三层架构、监听器等通过 feature 按需启用。

## 上下文传播

请求上下文通过 `task_local` 在异步任务间传播，stp 核心 task_local 共 4 个：`CURRENT_TOKEN`（当前 token）、`CURRENT_IP`（客户端 IP）、`CURRENT_RENEWED_TOKEN`（续签结果）与 `CURRENT_LOGIN_ID`（请求级登录身份缓存）。task_local 不承载请求头：请求头读取走 `context::GarrisonContext` trait（`request()` 返回 `GarrisonRequest`，经 `header()` 访问）；`stp::GarrisonContext` 结构体仅持有 token，用于跨 `tokio::spawn` 捕获/恢复 `CURRENT_TOKEN`（与 `context::GarrisonContext` trait 同名但职责不同）。此外还有模块级 task_local，如 `TENANT`（租户上下文）、`REQUEST_ID`（request id）及 `session-hijack-detection` feature 下的 `CLIENT_IP` / `CLIENT_USER_AGENT`。web 中间件（如 `GarrisonLayer`）负责在请求进入时设置 task_local，`GarrisonUtil` 读取 `CURRENT_TOKEN` 定位当前会话。

## 相关章节

- [双抽象层（oxcache + dbnexus）](./abstraction-layers.md)
- [插件系统](./plugin-system.md)
