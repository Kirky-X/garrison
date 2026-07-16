# 登录认证与会话

Bulwark 提供基于 Token 的会话管理，核心 API 集中在 `BulwarkUtil` 静态方法。

## 核心 API

```rust
use bulwark::prelude::*;

// 登录：为 login_id 生成 token 并写入会话，返回 token 字符串
let token = BulwarkUtil::login(1001).await?;

// 校验登录状态：依赖 task_local 中的当前 token（由 web 中间件设置）
let logged_in = BulwarkUtil::check_login().await?;  // 返回 bool

// 登出：销毁当前 token 对应的会话
BulwarkUtil::logout().await?;

// 获取当前登录 login_id
let login_id = BulwarkUtil::get_login_id().await?;
```

`check_login` 行为受 `throw_on_not_login` 配置影响：`true`（默认）未登录抛出 `BulwarkError::NotLogin`；`false` 则返回 `false`。

## 双向映射：Token-Session + Account-Session

Bulwark 维护两个方向的会话映射，承载于 oxcache：

| 映射 | key → value | 用途 |
|:---|:---|:---|
| Token-Session | token → `BulwarkSession` | 通过 token 定位会话（check_login 用） |
| Account-Session | login_id → token 列表 | 通过账号定位其所有 token（踢人、多端登录管理） |

- 登录时同时写入两个映射
- 登出时同时删除两个映射
- `kickout(login_id)` 可踢出某账号全部会话

## BulwarkSession

会话模型 `BulwarkSession` 承载登录态上下文，0.2.0 扩展了协议关联：

- `login_id`：登录主体标识
- `device`：设备信息（来自 `BulwarkInterface::get_device_info`）
- `login_time` / `expire_time`：登录与过期时间
- `link_sso_ticket` / `link_oauth2_token` / `link_temp_credential`：协议层关联（0.2.0 新增）

## 会话超时

- **Token 超时**：`config.timeout`（默认 30 天 = 2592000 秒），到期自动失效
- **活动超时**：`config.active_timeout`（默认 -1 不启用）；启用后长时间无活动会话失效
- TTL 在写入 oxcache 时设置，L1 内存与 L2 redis 共享同一 TTL 语义

## 会话续期

访问会话（如 `check_login`）会刷新 Token-Session 的 TTL（滑动过期），实现"活跃续期"。具体续期策略由 `BulwarkLogicDefault` 编排，可通过 `BulwarkInterface` 自定义。

## 多端登录与踢人

通过 Account-Session 可查询某账号的全部活跃 token，实现：

- **踢人**：`kickout(login_id)` 销毁该账号所有会话
- **多端互斥**：登录前检查 Account-Session，按策略踢出旧 token
- **会话列表**：列出某账号当前登录的所有设备

## 相关章节

- [权限与角色（RBAC）](./permission-rbac.md)
- [双抽象层](./abstraction-layers.md)
