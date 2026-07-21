# 双抽象层（oxcache + dbnexus）

Garrison 的持久化与缓存能力由两个独立抽象层提供，二者均通过 `GarrisonDao` trait 统一暴露给逻辑层，业务方无需关心底层差异。

## 设计目标

- **可替换后端**：缓存与数据库可独立切换，不影响业务代码
- **分层存储**：热数据走缓存（低延迟），全量数据落库（持久化）
- **trait 屏蔽差异**：`GarrisonDao` 定义统一接口，oxcache / dbnexus 各自实现

## oxcache 缓存抽象层

`oxcache` 0.3 提供两级缓存：

| 层级 | 实现 | 用途 |
|:---|:---|:---|
| L1 | oxcache 内存层 | 低延迟热点访问，承载 Token-Session 与 Account-Session |
| L2 | redis（可选） | 多实例共享，跨进程会话一致性 |

特性要点：

- 支持 per-entry TTL 与 `ttl()` 查询（0.3 新增）
- 通过 `cache-memory` / `cache-redis` feature 启用（语义别名，均启用 oxcache）
- L1 用 oxcache 内存后端（oxcache 无 caffeine feature，`cache-caffeine` 已移除）
- 承载 **Token-Session**（token → 会话）与 **Account-Session**（账号 → token 列表）双向映射

## dbnexus 数据库抽象层

`dbnexus` 0.4 提供数据库抽象，默认启用 `sqlite + permission + sql-parser + macros + config-env + with-time`：

| 后端 | 状态 | 说明 |
|:---|:---|:---|
| SQLite | ✅ 已支持 | 默认后端，`db-sqlite` feature 启用 auto-migrate |
| PostgreSQL | ✅ 已支持 | `db-postgres` feature 启用（委托 `dbnexus/postgres`） |
| MySQL | ✅ 已支持 | `db-mysql` feature 启用（委托 `dbnexus/mysql`） |

数据库层负责持久化 token、权限、角色等长期数据，并通过 `GarrisonMigration::run_migrations()` 提供幂等建表（首次启动自动执行）。

## GarrisonDao trait

`GarrisonDao` 屏蔽缓存与数据库差异，逻辑层只依赖此 trait：

```rust
#[async_trait]
pub trait GarrisonDao: Send + Sync {
    // 核心五元操作（必需实现）
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>>;
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()>;
    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()>;       // 保留原 TTL
    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()>;
    async fn delete(&self, key: &str) -> GarrisonResult<()>;

    // 扩展方法（含默认实现，后端可重写）
    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()>;           // 无 TTL 写入
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>>;            // 查询剩余 TTL
    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>>; // 原子 get + TTL
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>>;                    // glob pattern 扫描
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()>;

    // 原子操作（消除 TOCTOU 竞态，生产部署必须重写为后端原生原子）
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>>;           // 一次性消费
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64>;              // 计数器递增
    async fn decr(&self, key: &str) -> GarrisonResult<u64>;                                // 计数器递减
    async fn compare_and_update_if_greater(&self, key: &str, new_value: u64, ttl_seconds: u64) -> GarrisonResult<bool>;

    // SQL 抽象（默认返回 NotImplemented，供未来纯 KV 后端重写）
    async fn find_social_binding(&self, tenant_id: i64, provider: &str, provider_user_id: &str) -> GarrisonResult<Option<i64>>;
    async fn insert_social_binding(&self, tenant_id: i64, login_id: i64, provider: &str, provider_user_id: &str, union_id: Option<&str>, created_at: i64) -> GarrisonResult<()>;
    async fn eval_lua(&self, script: &str, keys: Vec<String>, args: Vec<String>) -> GarrisonResult<Vec<String>>;
}
```

会话层（`GarrisonSession`）基于 `GarrisonDao` 提供 Token-Session 与 Account-Session 双向映射，key 约定：

- `token:session:{token}` → `TokenSession`（JSON）
- `account:session:{login_id}` → `AccountSession`（JSON）

## 典型组合

| 场景 | 推荐组合 |
|:---|:---|
| 开发调试 | `cache-memory` + `db-sqlite` |
| 单实例生产 | `cache-memory` + `db-sqlite` / `db-postgres` / `db-mysql` |
| 多实例生产 | `cache-redis` + `db-sqlite` / `db-postgres` / `db-mysql` |

## 注意事项

- oxcache 0.3 的 `Cache<K,V>::update` 无法保留 per-entry TTL，重置 TTL 时需显式指定
- 多实例部署必须启用 `cache-redis`，否则 Token-Session 不一致
- dbnexus 0.4 已支持 SQLite / PostgreSQL / MySQL 三种后端，通过 `db-sqlite` / `db-postgres` / `db-mysql` feature 切换
- `keys()` 方法在 `GarrisonDaoOxcache` 上仅在启用 `anomalous-detector-dual` feature 时返回结果（依赖内部 key_index），否则返回 `NotImplemented`
