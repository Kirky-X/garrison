# 登录认证与会话

Garrison 提供基于 Token 的会话管理，核心 API 集中在 `GarrisonUtil` 静态方法。

## 核心 API

```rust
use garrison::prelude::*;
use garrison::stp::LoginParams;

// 登录：为 login_id 生成 token 并写入会话，返回 token 字符串
// 完整签名接收 LoginParams（device / ip / user_agent / remember_me / require_mfa）
let token = GarrisonUtil::login(1001, &LoginParams::default()).await?;

// 便捷登录：使用默认 LoginParams（向后兼容 0.6.2 前的单参数 login）
let token = GarrisonUtil::login_simple(1001).await?;

// 校验登录状态：依赖 task_local 中的当前 token（由 web 中间件设置）
let logged_in = GarrisonUtil::check_login().await?;  // 返回 bool

// 登出：销毁当前 token 对应的会话
GarrisonUtil::logout().await?;

// 获取当前登录 login_id（返回 Option<String>，未登录时取决于 throw_on_not_login）
let login_id: Option<String> = GarrisonUtil::get_login_id().await?;
```

`check_login` 行为受 `throw_on_not_login` 配置影响：`true`（默认）未登录抛出 `GarrisonError::NotLogin`；`false` 则返回 `false`。

## 双向映射：Token-Session + Account-Session

Garrison 维护两个方向的会话映射，承载于 oxcache：

| 映射 | key → value | 用途 |
|:---|:---|:---|
| Token-Session | `token:session:{token}` → `TokenSession` | 通过 token 定位会话（check_login 用） |
| Account-Session | `account:session:{login_id}` → `AccountSession` | 通过账号定位其所有 token（踢人、多端登录管理） |

- 登录时同时写入两个映射
- 登出时同时删除两个映射
- `kickout(login_id)` 可踢出某账号全部会话

## TokenSession

会话模型 `TokenSession` 承载登录态上下文，存储于 `token:session:{token}` key 下：

- `token`：token 字符串
- `login_id`：登录主体标识
- `created_at` / `last_active_at`：创建时间与最后活跃时间（Unix 秒）
- `attrs`：自定义属性（`HashMap<String, String>`）
- `device`：登录设备标识（由 `LoginParams.device` 写入，`kickout_by_device` 按此过滤）
- `ip` / `user_agent`：客户端 IP 与 User-Agent（由 `LoginParams.ip` / `LoginParams.user_agent` 写入）
- `safe_services`：二级认证（Safe Auth）瞬态标记（`HashMap<String, i64>`，key 为 service 名，value 为过期时间戳）
- `dynamic_active_timeout`：动态活跃超时（启用 `dynamic-active-timeout` feature 时存在）
- `is_anon`：是否为匿名 Session（启用 `anonymous-session` feature 时存在）

## 会话超时

- **Token 超时**：`config.timeout`（默认 30 天 = 2592000 秒），到期自动失效
- **活动超时**：`config.active_timeout`（默认 -1 不启用）；启用后长时间无活动会话失效
- TTL 在写入 oxcache 时设置，L1 内存与 L2 redis 共享同一 TTL 语义

## 会话续期

访问会话（如 `check_login`）会刷新 Token-Session 的 TTL（滑动过期），实现"活跃续期"。具体续期策略由 `GarrisonLogicDefault` 编排，可通过 `GarrisonInterface` 自定义。

## 多端登录与踢人

通过 Account-Session 可查询某账号的全部活跃 token，实现：

- **踢人**：`kickout(login_id)` 销毁该账号所有会话
- **多端互斥**：登录前检查 Account-Session，按策略踢出旧 token
- **会话列表**：列出某账号当前登录的所有设备

## 相关章节

- [权限与角色（RBAC）](./permission-rbac.md)
- [双抽象层](./abstraction-layers.md)
