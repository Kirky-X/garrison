# 🧱 Garrison API 稳定性分级（v1.0 门禁启动）

> **定位声明**：本文是 v1.0「API 冻结」门禁的**启动材料**，不是冻结完成的宣告。当前版本仍为 `0.9.0-rc.x`，0.x 阶段按 [SemVer 策略](./ROADMAP.md) 允许破坏性变更；本文先把「哪些面在 1.0 后受 semver 保护、哪些仍是实验面」写成可评审清单，并给出公共面基线的采集方法。

## 📋 目录

- [稳定层级](#-稳定层级)
- [模块分级清单](#-模块分级清单)
- [冻结检查清单](#-冻结检查清单)
- [公共面基线采集](#-公共面基线采集)
- [弃用流程](#-弃用流程)
- [相关文档](#-相关文档)

---

## 🎯 稳定层级

| 层级 | 1.0 后承诺 | 典型对象 |
|------|-----------|---------|
| **Stable** | 受 semver 保护：破坏性变更仅在 major；minor 只增不改 | `GarrisonManager` / `GarrisonUtil` / `GarrisonConfig` / `GarrisonDao` / `GarrisonError` / 会话与权限核心 trait |
| **Stable-with-feature** | 同上，但仅在该 feature 启用时存在；feature 名本身视为 API | 协议层（`protocol-*`）、安全层（`secure-*`）、Web 适配（`web-*`）、`account-*`、`abac`、`oauth2-server` |
| **Experimental** | 可能在 minor 中调整；不承诺跨 minor 兼容 | `config-distributed` / `db-saga` / `firewall-*` 高级透传 / `backend-kit` / `garrison-testing` / `cli-ops` |
| **Internal** | 不作为 API；可能随时删除 | `#[doc(hidden)]` 项、`src/dao/testing`、`src/stp/mock`、`src/manager/mock` |

> 判定原则：**用户文档（README / API_REFERENCE / CONFIGURATION）中出现的入口 = Stable 候选**；仅在 CHANGELOG 或源码注释中出现的能力 = Experimental。

---

## 🧩 模块分级清单

| 模块 / 入口 | 层级 | 备注 |
|-------------|------|------|
| `manager`（`GarrisonManager` / builder） | Stable | `build` / `build_explicit` 签名冻结前需复核 |
| `stp`（登录 / 会话 / 权限 / Token 子 trait） | Stable | `GarrisonCore` 超 trait 已拆分 |
| `session`（`GarrisonSession`） | Stable | 落库 key 格式已摘要化，格式变更属 major |
| `dao`（`GarrisonDao` / `InMemoryDao` / `GarrisonDaoOxcache`） | Stable | trait 方法新增需默认实现，否则属 major |
| `config`（`GarrisonConfig` / `RateLimitBackend`） | Stable-with-feature | `rate_limit_backend` 受 `rate-limit-redis` 门控 |
| `error`（`GarrisonError` / `GarrisonResult`） | Stable | 错误码前缀与变体语义冻结清单见下 |
| `protocol::*` | Stable-with-feature | 单个协议模块的 feature 名视为 API |
| `secure::*` | Stable-with-feature | 常量时间比较原语 `secure::ct_eq` 为 Stable |
| `web_axum` / `web_actix` / `web_warp` | Stable-with-feature | 适配层 trait 与中间件名 |
| `account::*` | Stable-with-feature | Credential SPI / 密码策略 / 锁定策略 |
| `abac` / `oauth2_server` | Stable-with-feature | Cedar / OAuth2 Server |
| `limiteron`（`LimiterBackend` / `LimiterRuntime`） | Stable-with-feature | rc.4 新增；`RedisLimiterBackend` 受 `rate-limit-redis` 门控 |
| `strategy::firewall::*` | Stable-with-feature | `RateLimitStrategy` / `BruteForceStrategy` 等策略构造签名 |
| `cli-ops` | Experimental | 运维 bin，输出格式可能调整 |
| `config-distributed` / `db-saga` / `backend-kit` | Experimental | 自研库透传面 |
| `dao::testing` / `stp::mock` | Internal | 测试辅助，不承诺 |

---

## ✅ 冻结检查清单

1.0 前必须逐项结清；本轮只建立清单与基线，不批量改代码。

- [ ] **公共项清单**：用 `scripts/api_surface.sh` 生成基线，逐项标注 Stable / Experimental / Internal。
- [ ] **`#[non_exhaustive]` 审计**：对可能新增变体的公开 enum / struct（尤其 `GarrisonError`、配置枚举、`RateLimitBackend`）评估是否加 `#[non_exhaustive]`。
- [ ] **错误码冻结**：`GarrisonError::prefixed_code()` 的前缀码（`stp-*` / `config-*` / `strategy-*` 等）作为监控契约冻结；新增码只增不改。
- [ ] **配置键冻结**：`docs/CONFIGURATION.md` 中出现的键名冻结；弃用键经 R12 注册表迁移，1.0 起拒绝未迁移键。
- [ ] **feature 名冻结**：`Cargo.toml [features]` 的公开 feature 名视为 API；内部 `http` 桥接 feature 在文档中标注 `[INTERNAL]`。
- [ ] **存储 key 格式冻结**：会话 key（`token:session:{sha256}`）、限流 key（`fw:*` / `rl:*`）变更需 major + 迁移指南。
- [ ] **MSRV 策略**：`rust-version` 变更只在 minor；1.0 后至少保留一个 minor 的升级窗口。
- [ ] **trait 对象安全**：所有公开 trait 在 1.0 前复核 `dyn` 可用性；新增方法优先给默认实现。
- [ ] **prelude 冻结**：`garrison::prelude` 只增不减；移除需 major。

---

## 📏 公共面基线采集

```bash
# 需要 nightly（rustdoc JSON）
cargo +nightly rustdoc --features full --lib -- -Zunstable-options --output-format json
bash scripts/api_surface.sh                 # 输出 logs/api-surface.txt
bash scripts/api_surface.sh --diff <baseline>
```

- `scripts/api_surface.sh` 调用 `scripts/api_surface.py` 解析 rustdoc JSON，输出「kind + 公共路径」排序清单与计数。
- `.github/workflows/api-surface.yml` 每周 + 手动触发，上传 `api-surface.txt` 工件；**report-only**，不阻断 CI。
- 基线文件不提交仓库（`logs/` 已在 `.gitignore`）；发布前将当次工件归档到 release 资产或内部制品库。

---

## 🔁 弃用流程

1. 在 CHANGELOG `Deprecated` 段声明替代品与移除版本。
2. 代码加 `#[deprecated(since = "...", note = "...")]`，文档链接迁移指南。
3. 至少保留一个 minor 周期；1.0 后移除需 major。
4. 配置键走 R12 弃用配置键注册表（`config::deprecation`），启动期 warn，1.0 起拒绝。

---

## 📚 相关文档

| 文档 | 说明 |
|------|------|
| [🗺️ 路线图](ROADMAP.md) | v1.0 四项门禁状态与版本策略 |
| [📘 API 参考](API_REFERENCE.md) | 公开 API 的模块化速查 |
| [⚙️ 配置指南](CONFIGURATION.md) | 配置键清单与语义 |
| [📋 更新日志](CHANGELOG.md) | 破坏性变更与弃用记录 |
