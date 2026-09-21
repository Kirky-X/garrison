# ⚡ Garrison 性能指南

本指南汇总 Garrison 的性能设计要点、基准测试方法与优化建议。Garrison 的性能目标以认证鉴权框架的热路径为口径：登录链路（含密码哈希）与每请求的无状态校验（token 验证、权限检查）。

> 适用版本：0.9.0-rc.2。本文不发布绝对耗时数字（criterion 区间估计随机器而异）；基准以本机运行 `cargo bench` 复现，验收性能基线以 `scripts/e2e_run.sh` 产出的 `logs/perf.jsonl` 为准。

## 📋 目录

- [性能目标](#-性能目标)
- [基准测试](#-基准测试)
- [验收性能基线（E2E）](#-验收性能基线e2e)
- [性能设计要点](#️-性能设计要点)
- [优化建议](#️-优化建议)
- [相关文档](#-相关文档)

---

## 🎯 性能目标

以下目标定义于 [`benches/garrison_benchmark.rs`](../benches/garrison_benchmark.rs) 文件头（设计验收口径）：

| 基准场景 | 目标 |
|----------|------|
| `login_flow` | ≤ 500ms（5000 TPS 口径） |
| `token_verify_stateless` | ≤ 5ms（20000 TPS 口径） |
| `permission_check` | ≤ 5ms（20000 TPS 口径） |
| `oxcache_backend_switch` | 后端切换开销 = 0 |

验收层另有 HTTP 端到端性能基线：**P99 < 200ms / 1000 RPS**（见下文「验收性能基线」）。

---

## 📊 基准测试

Criterion 基准位于 `benches/garrison_benchmark.rs`（`[[bench]]` 注册，`harness = false`），覆盖 4 个场景：`login_flow`、`token_verify_stateless`、`permission_check`、`oxcache_backend_switch`（memory ↔ redis_mock 后端切换）。

```bash
# 编译检查（不运行）
cargo bench --no-run

# 快速运行（减少采样数）
cargo bench -- --quick

# 启用 JWT 真实验证
cargo bench --features protocol-jwt

# 完整特性运行
cargo bench --features full

# e2e_matrix S6 阶段的实际调用（--bench 限定 criterion 目标；
# 裸 cargo bench 会连带以 bench profile 运行 lib unittest，不识别 criterion 参数）
cargo bench --bench garrison_benchmark --features full --locked -- \
    --quick --save-baseline e2e
```

通过标准：criterion 无 `Regressed` 判定；基线存于 `target/criterion` 供后续对比。注意：`permission_check` 在 `tenant-isolation`（full 面）下会显式进入默认租户 0 上下文（与 server 中间件行为等价），否则因无 `TENANT.scope` 而 panic。

> 各场景在本机的 criterion 区间估计数据**待补充**——请以上述命令在本机采集，不使用跨机器数字做结论。

---

## 📈 验收性能基线（E2E）

性能基线固化在验收套件的 `#[ignore]` 用例中（`tests/acceptance/concurrency.rs`，`perf_*` 前缀），打真实 HTTP 服务并经 `RecordingClient` 抓包：

```bash
# 方式一：一键执行（启动 auth_server_serve → 全量验收 → 性能基线 → 聚合报告）
EXAMPLE_INTERNAL_API_KEY=$(openssl rand -hex 16) bash scripts/e2e_run.sh

# 方式二：只跑性能基线（追加 logs/perf.jsonl）
cargo test --test acceptance --features "full testing" perf_ -- \
    --nocapture --test-threads=1 --ignored

# 方式三：聚合已有 JSONL 日志为 Markdown 报告
python3 scripts/e2e_analyze.py --log-dir logs
```

产物：`logs/perf.jsonl`（每行一个 JSON 采样）与 `logs/e2e_final_report.md`（综合报告）。

判定规则（`assert_perf_baseline`）：

- **debug 构建**：软警告——login 链路涉及 argon2/bcrypt，debug 下 P99 约 1.1s 不达标属预期；
- **release 构建**：硬失败（panic）。外部 release 服务的硬判定经 `GARRISON_E2E_EXTERNAL_URL` / `GARRISON_E2E_INTERNAL_URL` / `GARRISON_E2E_API_KEY` 注入（`RemoteContext::connect_env` 路径）。

方法论记录（`perf_login` 基线重校准，2026-09-11）：压测使用 100 账号轮转（`LoadRunner::with_body_fn`）度量多用户真实流量，而非单账号并发——登录路径存在 per-login_id 互斥锁（`SessionStore::with_login_lock`，TOCTOU 修复，设计如此：保护同账号 Account-Session 读改写原子性），单账号并发必然串行化（实测 P99 约 700ms）。同账号并发正确性由 concurrency 域竞争测试覆盖。

---

## 🏗️ 性能设计要点

以下要点均可在 CHANGELOG 与源码中追溯：

| 设计 | 位置 / 来源 | 说明 |
|------|-------------|------|
| 全局单例无锁化 | `GarrisonManager`（CHANGELOG PERF-01） | `logic` / `strategy` 字段由 `parking_lot::RwLock<Option<Arc<..>>>` 迁移为 `arc_swap::ArcSwapOption`；热路径 `GarrisonManager::logic()`（`backend/embedded.rs` 每请求调用）无锁原子加载，消除多核高 QPS 缓存行争用 |
| 全局后端引用无锁化 | `CURRENT_BACKEND`（T006） | `Mutex<Option<Arc<..>>>` → `ArcSwapOption`（`BackendHandle` Sized 包装），check_login / check_permission 热路径去全局锁，并发初始化保持 CAS 语义 |
| 慢哈希移出 async executor | `spawn_blocking`（T007） | bcrypt / Argon2 的 hash / verify 全部登录路径调用点包 `tokio::task::spawn_blocking`，登录风暴不阻塞 tokio worker |
| TokenSession 请求内复用 | T008 | `is_valid_with_session` 返回快照供 hover 复用，同一请求内重复读取由 3-4 次降为 1-2 次；task_local `CURRENT_LOGIN_ID` 缓存使 `get_login_id` / `check_permission` 缓存命中零 DAO 读取（logout / kickout / revoke 即时失效） |
| 编译期注册 | `inventory::submit!` | 插件 / 监听器工厂编译期注册，零运行时反射、零动态加载 |
| 三层缓存 + TTL 随机抖动 | `oxcache` 集成 | L1 内存层 per-entry TTL 精细化过期；L1 写入经 oxcache `CacheBuilder::ttl_jitter` 自动 ±10% 抖动，L2 经 `UserCacheService::l2_ttl_with_jitter` 同等抖动，防大量 key 同时过期的缓存雪崩 |
| L1 容量可配 | `l1_cache_capacity` | `UserCacheService::new_with_capacity` 接线 `GarrisonConfig::l1_cache_capacity`（曾静默无效，已修复） |
| 全量 feature 门控 | `Cargo.toml [features]` | 未启用的协议 / 防火墙 / Web 适配不参与编译，控制编译时间与二进制体积 |
| 分布式限流 | `limiteron` 透传 | 滑动窗口 Redis Sorted Set（Lua 脚本，每条目 O(1) 内存）；GCRA / 配额等经 limiteron 子特性 |

---

## 🛠️ 优化建议

1. **选对存储后端**：开发用 `development` 预设（内存 DAO）；生产用 `cache-redis` + `db-postgres`/`db-mysql`，L1 内存层兜住热路径读取。注意 dbnexus 互斥约束（sqlite ⊕ postgres/mysql）。
2. **调大 L1 缓存**：高读多写少场景显式配置 `l1_cache_capacity`（默认 10000），命中率越高 DAO 往返越少。
3. **release 构建跑性能验证**：`assert_perf_baseline` 仅在 release 下硬判定；密码哈希在 debug 构建下天然慢一个量级，不要用 debug 数据评估登录性能。
4. **保持 feature 面最小**：未启用的能力零开销（编译期剔除）；聚合 `full` 仅用于验证，生产按需组合。
5. **多租户场景复用请求内快照**：`get_login_id` / `check_permission` 在同一请求内命中 task_local 缓存（零 DAO 读取），避免在 handler 内重复手动解析 token。
6. **压测遵循多账号轮转**：对登录接口压测时不要用单一账号并发（会被 per-login_id 锁串行化，见上文方法论记录）；用 100 账号轮转模拟真实流量。
7. **建立基线对比**：提交可能影响热路径的改动前 `--save-baseline` 保存基线，改动后 criterion 自动对比 `Regressed`。

---

## 📚 相关文档

| 文档 | 说明 |
|------|------|
| [🧪 测试场景矩阵](TEST_SCENARIOS.md) | 验收场景穷举、性能基线用例与已知问题记录 |
| [🏗️ 架构文档](ARCHITECTURE.md) | 模块划分、数据流与设计决策 |
| [⚙️ 配置指南](CONFIGURATION.md) | 缓存 / 会话 / Token 策略配置项 |
| [🚀 部署指南](DEPLOYMENT.md) | 生产部署注意事项（TLS、连接池、缓存） |
