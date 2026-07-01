# 双抽象层（oxcache + dbnexus）

Bulwark 的持久化与缓存能力由两个独立抽象层提供，二者均通过 `BulwarkDao` trait 统一暴露给逻辑层，业务方无需关心底层差异。

## 设计目标

- **可替换后端**：缓存与数据库可独立切换，不影响业务代码
- **分层存储**：热数据走缓存（低延迟），全量数据落库（持久化）
- **trait 屏蔽差异**：`BulwarkDao` 定义统一接口，oxcache / dbnexus 各自实现

## oxcache 缓存抽象层

`oxcache` 0.3 提供两级缓存：

| 层级 | 实现 | 用途 |
|:---|:---|:---|
| L1 | moka（进程内） | 低延迟热点访问，承载 Token-Session 与 Account-Session |
| L2 | redis（可选） | 多实例共享，跨进程会话一致性 |

特性要点：

- 支持 per-entry TTL 与 `ttl()` 查询（0.3 新增）
- 通过 `cache-memory` / `cache-redis` feature 启用（语义别名，均启用 oxcache）
- L1 用 moka（oxcache 无 caffeine feature，`cache-caffeine` 已移除）
- 承载 **Token-Session**（token → 会话）与 **Account-Session**（账号 → token 列表）双向映射

## dbnexus 数据库抽象层

`dbnexus` 0.2 提供数据库抽象，默认启用 `sqlite + permission + sql-parser + macros + config-env + with-time`：

| 后端 | 状态 | 说明 |
|:---|:---|:---|
| SQLite | ✅ 已支持 | 默认后端，`db-sqlite` feature 启用 auto-migrate |
| PostgreSQL | 📋 0.4.0+ | 待 dbnexus 0.3+ 暴露 postgres feature |
| MySQL | 📋 0.4.0+ | 待 dbnexus 0.3+ 暴露 mysql feature |

数据库层负责持久化 token、权限、角色等长期数据，并通过 `BulwarkMigration::run_migrations()` 提供幂等建表（首次启动自动执行）。

## BulwarkDao trait

`BulwarkDao` 屏蔽缓存与数据库差异，逻辑层只依赖此 trait：

```rust
#[async_trait]
pub trait BulwarkDao: Send + Sync {
    // Token-Session 双向映射
    async fn set_token_session(&self, token: &str, session: &BulwarkSession, ttl: i64) -> BulwarkResult<()>;
    async fn get_token_session(&self, token: &str) -> BulwarkResult<Option<BulwarkSession>>;
    async fn delete_token_session(&self, token: &str) -> BulwarkResult<()>;

    // Account-Session（账号 → token 列表）
    async fn set_account_session(&self, login_id: i64, tokens: &[String], ttl: i64) -> BulwarkResult<()>;
    async fn get_account_session(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    // 权限 / 角色（持久化于 dbnexus）
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;
    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;
    // ... 其余方法
}
```

## 典型组合

| 场景 | 推荐组合 |
|:---|:---|
| 开发调试 | `cache-memory` + `db-sqlite` |
| 单实例生产 | `cache-memory` + `db-sqlite` |
| 多实例生产 | `cache-redis` + `db-sqlite`（0.4.0 起支持 PostgreSQL/MySQL） |

## 注意事项

- oxcache 0.3 的 `Cache<K,V>::update` 无法保留 per-entry TTL，重置 TTL 时需显式指定
- 多实例部署必须启用 `cache-redis`，否则 Token-Session 不一致
- dbnexus 0.2 仅支持 SQLite，PostgreSQL/MySQL 待 0.4.0+
