# 双抽象层（oxcache + dbnexus）

Garrison 的持久化与缓存能力由两个独立抽象层提供，二者均通过 `GarrisonDao` trait 统一暴露给逻辑层，业务方无需关心底层差异。

## 设计目标

- **可替换后端**：缓存与数据库可独立切换，不影响业务代码
- **分层存储**：热数据走缓存（低延迟），全量数据落库（持久化）
- **trait 屏蔽差异**：`GarrisonDao` 定义统一接口，oxcache / dbnexus 各自实现

## oxcache 缓存抽象层

`oxcache` 0.5 提供两级缓存：

| 层级 | 实现 | 用途 |
|:---|:---|:---|
| L1 | oxcache 内存层 | 低延迟热点访问，承载 Token-Session 与 Account-Session |
| L2 | redis（可选） | 多实例共享，跨进程会话一致性 |

特性要点：

- 支持 per-entry TTL 与 `ttl()` 查询
- 通过 `cache-memory` / `cache-redis` feature 启用（语义别名，均启用 oxcache）
- L1 用 oxcache 内存后端（oxcache 无 caffeine feature，`cache-caffeine` 已移除）
- 承载 **Token-Session**（token → 会话）与 **Account-Session**（账号 → token 列表）双向映射

## dbnexus 数据库抽象层

`dbnexus` 0.6 提供数据库抽象。garrison 以 `default-features = false` 引入（0.6 默认 feature 为空），公共能力由 `db-base` 为全部 `db-*` feature 统一启用（`runtime-tokio-rustls + permission + sql-parser + macros + config-env + with-time + auto-migrate` 等），数据库驱动则由 `db-sqlite` / `db-postgres` / `db-mysql` 分别显式启用：

| 后端 | 状态 | 说明 |
|:---|:---|:---|
| SQLite | ✅ 已支持 | 嵌入式驱动（非默认后端）；`db-sqlite` = `db-base` + `dbnexus/sqlite`，`auto-migrate` 等公共能力由 `db-base` 统一启用（db-postgres / db-mysql 同样具备） |
| PostgreSQL | ✅ 已支持 | `db-postgres` feature 启用（委托 `dbnexus/postgres`） |
| MySQL | ✅ 已支持 | `db-mysql` feature 启用（委托 `dbnexus/mysql`） |

数据库层负责持久化 token、权限、角色等长期数据，并通过 `GarrisonMigration` 提供幂等建表：`run_all()` 按 core→extensions→tenant 顺序执行全部迁移（`migrate_core()` 只跑核心表），幂等性由 dbnexus 的 `dbnexus_migrations` 版本表保证。迁移不会随服务启动自动执行，需业务方显式调用（garrison-cli 无独立迁移子命令，仅在 `one-time-access-token --migrate` 显式开启时执行 core 迁移）。

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
    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>>; // value + 剩余 TTL
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>>;                    // glob pattern 扫描

    // 原子操作（除注明外均为必需实现；消除 TOCTOU 竞态，禁止组合语义）
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()>;            // 原子重命名，保留原 TTL
    async fn set_if_absent(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<bool>; // SETNX 语义
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>>;           // 一次性消费
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64>;              // 计数器递增
    async fn decr(&self, key: &str) -> GarrisonResult<u64>;                                // 计数器递减
    async fn compare_and_swap(&self, key: &str, expected: Option<&str>, new_value: &str, ttl_seconds: u64) -> GarrisonResult<bool>; // CAS 语义
    async fn compare_and_update_if_greater(&self, key: &str, new_value: u64, ttl_seconds: u64) -> GarrisonResult<bool>; // 默认返回 NotImplemented，生产后端必须重写为原子 CAS

    // SQL 抽象（默认返回 NotImplemented，供未来纯 KV 后端重写）
    async fn find_social_binding(&self, tenant_id: i64, provider: &str, provider_user_id: &str) -> GarrisonResult<Option<String>>; // 返回 login_id（String，UUID）
    async fn insert_social_binding(&self, tenant_id: i64, login_id: &str, provider: &str, provider_user_id: &str, union_id: Option<&str>, created_at: i64) -> GarrisonResult<()>;
    async fn eval_lua(&self, script: &str, keys: Vec<String>, args: Vec<String>) -> GarrisonResult<Vec<String>>;

    // 以下方法仅在 db-sqlite / db-postgres / db-mysql feature 下编译（默认返回 NotImplemented）
    async fn query_role_hierarchy_edges(&self, tenant_id: i64) -> GarrisonResult<Vec<(String, String)>>;
    async fn insert_role_hierarchy_edge(&self, tenant_id: i64, child_role: &str, parent_role: &str) -> GarrisonResult<()>;
    async fn delete_role_hierarchy_edge(&self, tenant_id: i64, child_role: &str, parent_role: &str) -> GarrisonResult<()>;
    async fn insert_credit_consumption(&self, tenant_id: i64, resource: &str, cost: u64, credits: u64, total_consumed: u64, cycle_start: i64) -> GarrisonResult<()>;
    async fn query_credit_consumption(&self, tenant_id: i64, from_ts: i64, to_ts: i64) -> GarrisonResult<Vec<(i64, String, u64, u64, u64, i64, i64)>>;
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

- oxcache 0.5 无 `Cache<K,V>::update` 方法（不存在一步更新且保留 TTL 的原语），保留 per-entry TTL 需 `ttl()` + `set_with_ttl()` 组合（同步场景用 `ttl_sync()` + `set_with_ttl_sync()`，`GarrisonDaoOxcache::update` 即以后者实现）
- 多实例部署必须启用 `cache-redis`，否则 Token-Session 不一致
- dbnexus 0.6 已支持 SQLite / PostgreSQL / MySQL 三种后端，通过 `db-sqlite` / `db-postgres` / `db-mysql` feature 切换
- `keys()` 方法在 `GarrisonDaoOxcache` 上仅在启用 `dao-key-index` feature 时返回结果（依赖内部 key_index，由 `protocol-apikey` / `anomalous-detector-dual` 传递启用），否则返回 `NotImplemented`
