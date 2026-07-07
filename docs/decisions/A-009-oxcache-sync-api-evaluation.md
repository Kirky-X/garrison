# A-009: oxcache `_sync` API 评估结论

- **状态**：已采纳（v0.5.2）
- **决策日期**：2026-07-08
- **相关变更**：v0-5-2-architecture-refactor
- **相关代码**：`src/dao/mod.rs` `BulwarkDaoOxcache`

## 背景

`BulwarkDaoOxcache` 使用 oxcache 0.3 的 `_sync` API（`get_sync`/`set_with_ttl_sync`/`ttl_sync`/`expire_sync`/`delete_sync`）实现 `BulwarkDao` trait 的异步方法。这引发了"在 async 上下文中调用 sync API 是否合适"的疑问。

## 评估依据

### oxcache 0.3 sync mode 性能特征

- 基于 Moka 的 `DashMap` 后端（in-memory）
- 读操作（`get_sync`/`exists_sync`/`ttl_sync`）：无锁读，<100ns
- 写操作（`set_with_ttl_sync`/`delete_sync`/`expire_sync`）：短临界区，<1μs

### `tokio::task::spawn_blocking` 开销

- 线程池调度开销：~10-50μs
- 对于 <1μs 的 in-memory 操作，`spawn_blocking` 的调度开销远大于操作本身

## 决策

**保留现有 `_sync` API 实现**。

理由：

1. 对 in-memory backend，`_sync` 调用比 `spawn_blocking` 更快（<1μs vs 10-50μs）
2. `_sync` API 由 oxcache 0.3 官方支持，通过 `sync_mode(true)` builder 选项启用
3. `BulwarkDaoOxcache` 的所有操作均为 in-memory，无网络 I/O，不会阻塞 tokio worker 线程

## 后续跟进条件

**若未来引入 Redis/分布式 backend**：

- `_sync` API 在网络 I/O 场景下会阻塞 tokio worker 线程
- 届时需将 `_sync` API 改为 async API（`get`/`set_with_ttl`/`ttl`/`expire`/`delete`）
- 或在 `BulwarkDao` impl 内部使用 `spawn_blocking` 包装网络 I/O 调用

## 验证

- `cargo test --features full --lib` 1322 passed（含 oxcache sync API 测试）
- `#[tokio::test(flavor = "multi_thread")]` 标注的测试验证 sync mode 在 multi_thread runtime 下正常工作
