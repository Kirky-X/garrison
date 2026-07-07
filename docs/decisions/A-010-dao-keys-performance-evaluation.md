# A-010: `BulwarkDao::keys()` 性能评估结论

- **状态**：已采纳（v0.5.2，defer 到 oxcache 0.5+）
- **决策日期**：2026-07-08
- **相关变更**：v0-5-2-architecture-refactor
- **相关代码**：`src/dao/mod.rs` `BulwarkDao::keys()`

## 背景

`BulwarkDao::keys(pattern)` 方法用于按 glob pattern 扫描 key（如 `ApiKeyHandler::list_by_namespace` 需要 `keys("apikey:*")`）。当前默认实现返回 `BulwarkError::NotImplemented`，`MockDao` 已实现，但 `BulwarkDaoOxcache` 未重写。

## 评估依据

### oxcache 0.3 API 限制

- `Cache<K,V>` 未暴露 iter/scan API
- `Cache.backend` 字段为 `pub(crate)`，外部无法访问底层 `DashMap`
- `CacheReader`/`CacheBackend` trait 均无 iter 方法

### 维护独立 key 索引的权衡

考虑方案：在 `BulwarkDaoOxcache` 内部维护 `DashMap<String, ()>` 作为 key 索引。

- **优点**：立即实现 `keys()` 功能
- **缺点**：
  - 内存开销翻倍（每个 key 在 oxcache Cache + 索引 DashMap 各存一份）
  - set/delete 需同步索引，引入竞态风险
  - 一致性复杂度增加（TTL 过期时索引需同步清理，但 oxcache 的过期是惰性的）

### oxcache 上游路线图

- oxcache 0.5+ 路线图有 iter API 计划
- 原生支持后，`keys()` 可直接委托给 oxcache iter，无额外开销

## 决策

**defer 到 oxcache 0.5+**。

理由：

1. 投入产出比低：维护独立索引的复杂度高，而 oxcache 0.5+ 会原生支持
2. 业务影响可控：`ApiKeyHandler::list_by_namespace` 是管理 API，非高频路径
3. 业务方临时方案已验证：`MockDao` 测试中已采用自行维护 key 集合的模式

## 业务方临时方案

若生产环境需要 `keys()` 功能：

1. 自行维护 key 集合（如 `DashMap<String, ()>` 或数据库表）
2. 在 `set`/`delete` 时同步更新索引
3. 参考 `ApiKeyHandler::list_by_namespace` 的 `MockDao` 测试实现

## 后续跟进条件

**oxcache 0.5+ 发布后**：

- 升级 oxcache 依赖
- 在 `BulwarkDaoOxcache` 中重写 `keys()` 方法，委托给 oxcache iter API
- 移除业务方自行维护 key 索引的临时方案

## 验证

- `cargo test --features full --lib` 1322 passed（含 `keys()` 默认 `NotImplemented` 测试）
- `MockDao::keys()` 测试验证 glob pattern 匹配逻辑正确
