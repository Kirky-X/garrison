# A-010: `GarrisonDao::keys()` 性能评估结论

- **状态**：已被后续实现推翻（v0.5.2 defer → v0.6.7 采纳 key_index 方案）
- **决策日期**：2026-07-08（v0.5.2 评估）/ 2026-07-14（v0.6.7 修订实现）
- **相关变更**：v0-5-2-architecture-refactor / v0.6.7-waf-safe-defaults-cache-sms-anomalous
- **相关代码**：`src/dao/oxcache_impl.rs` `GarrisonDaoOxcache::keys()` / `src/dao/mod.rs` `GarrisonDao::keys()` 默认实现

## 背景

`GarrisonDao::keys(pattern)` 方法用于按 glob pattern 扫描 key（如 `ApiKeyHandler::list_by_namespace` 需要 `keys("garrison:apikey:<namespace>:*")`）。默认实现返回 `GarrisonError::NotImplemented`，`MockDao` 已实现。

## 评估依据

### oxcache 0.3.x API 限制（2026-07-08 验证，2026-07-20 复核当前 0.3.9）

- `Cache<K,V>` 仍未暴露 iter/scan/keys API
- `Cache.backend` 字段仍为 `pub(crate)`，外部无法访问底层 `DashMap`
- `CacheReader` trait 仅有 `get`/`exists`/`ttl`/`len`/`is_empty`/`capacity`/`stats`/`get_many`，无 iter/keys 方法
- `CacheBackend: CacheReader + CacheWriter + CacheConnector` 组合 trait，同样无 iter
- `len()` 仅返回条目数，不返回 key 列表

### 维护独立 key 索引的权衡（v0.6.7 已采纳）

在 `GarrisonDaoOxcache` 内部维护 `parking_lot::RwLock<std::collections::HashSet<String>>` 作为 key 索引。

- **优点**：立即实现 `keys()` 功能，支持 glob pattern 匹配
- **缺点**：
  - 内存开销翻倍（每个 key 在 oxcache Cache + 索引 HashSet 各存一份）
  - set/delete 需同步索引，引入竞态风险
  - 一致性复杂度增加（TTL 过期时索引需惰性清理，oxcache 的过期是惰性的）

### oxcache 上游路线图

- oxcache 上游路线图有 iter API 计划，但截至 0.3.9（crates.io 最新 0.3.x，2026-07-20 验证）仍未实现
- 原生支持后，`keys()` 可直接委托给 oxcache iter，无额外开销

## 决策

### v0.5.2 决策（已推翻）

**defer 到 oxcache 提供原生 iter API**。

理由：

1. 投入产出比低：维护独立索引的复杂度高，而 oxcache 原生 iter API 支持后可直接委托
2. 业务影响可控：`ApiKeyHandler::list_by_namespace` 是管理 API，非高频路径
3. 业务方临时方案已验证：`MockDao` 测试中已采用自行维护 key 集合的模式

### v0.6.7 修订决策（当前生效）

**采纳 key_index 方案**，在 `GarrisonDaoOxcache` 内部维护 `parking_lot::RwLock<HashSet<String>>` 实现 `keys()`。

理由：

1. `anomalous-detector-dual` feature 引入 `AnomalousLoginAnalyzer` 定时扫描引擎，需要 `keys("anomalous:login:*")` 扫描登录记录，`defer` 决策不再可行
2. 门控 `anomalous-detector-dual` feature：仅在需要 `keys()` 的场景启用，避免影响其他场景的内存开销
3. 惰性清理：`keys()` 调用时清理已过期 key，不引入后台清理线程
4. 进程内原子性已足够：`AnomalousLoginAnalyzer` 是单实例定时扫描，无跨进程需求

## 实现

`GarrisonDaoOxcache::keys()` 实现（`src/dao/oxcache_impl.rs`）：

1. `set` / `set_permanent` 时 `key_index.write().insert(actual_key)`
2. `delete` 时 `key_index.write().remove(&actual_key)`
3. `keys()` 遍历 `key_index`，过滤匹配 pattern 的 key，同时惰性清理已过期 key（通过 `cache.exists_sync` 检查）
4. pattern 支持 `*` 通配符（与 `MockDao::keys` 一致）
5. 去除 `tenant:` 前缀后返回原始 key

## 后续跟进条件

**oxcache 提供原生 iter API 后**：

- 升级 oxcache 依赖
- 在 `GarrisonDaoOxcache` 中重写 `keys()` 方法，委托给 oxcache iter API
- 移除 `key_index` 字段及其维护逻辑

## 验证

- `cargo test --features full --lib` 通过（含 `keys()` 默认 `NotImplemented` 测试 + `GarrisonDaoOxcache::keys()` 实现测试）
- `MockDao::keys()` 测试验证 glob pattern 匹配逻辑正确
- `GarrisonDaoOxcache::keys()` 测试验证 key_index 维护 + 惰性清理逻辑正确
