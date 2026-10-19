# Garrison v1.0 API 冻结候选清单

> 本文是 [API_STABILITY.md](./API_STABILITY.md) 的配套评审材料：把「1.0 后受 semver 保护的面」与「仍可调整的实验面」逐项列出。它不是冻结完成的宣告；当前版本仍为 `0.9.0-rc.x`，0.x 阶段允许破坏性变更。

## 分级口径

| 分级 | 1.0 后承诺 | 判定依据 |
|------|-----------|---------|
| Stable | 破坏性变更仅限 major；minor 只增不改 | README / API_REFERENCE / CONFIGURATION / USER_GUIDE 中出现的入口 |
| Stable-with-feature | 同上，但仅在该 feature 启用时存在；feature 名本身视为 API | 文档中标注 feature 的协议/安全/适配层 |
| Experimental | 可能在 minor 调整，不承诺跨 minor 兼容 | 仅在 CHANGELOG、源码注释或高级配置中出现 |
| Internal | 不作为 API，可随时删除 | `#[doc(hidden)]`、测试 mock、testing 模块 |

## Stable 候选

| 模块 / 入口 | 关键公共项 | 冻结前必改 |
|-------------|-----------|-----------|
| `manager` | `GarrisonManager`、builder、`build` / `build_explicit` | 复核 builder 方法签名与默认值 |
| `stp` | `GarrisonCore` 及登录/会话/权限子 trait | 复核超 trait 拆分后的对象安全 |
| `session` | `GarrisonSession`、会话 key 格式 | 固化 `token:session:{sha256}` 格式 |
| `dao` | `GarrisonDao`、`InMemoryDao`、`GarrisonDaoOxcache` | 新增 trait 方法必须带默认实现 |
| `config` | `GarrisonConfig`、默认值、`COOKIE_SAME_SITE_VALUES` | 配置键名与默认值冻结 |
| `error` | `GarrisonError`、`GarrisonResult`、`prefixed_code()` | 错误前缀码只增不改；评估 `#[non_exhaustive]` |
| `prelude` | `garrison::prelude::*` | 只增不减 |

## Stable-with-feature 候选

| feature 族 | 模块 | 冻结前必改 |
|-----------|------|-----------|
| `protocol-*` | `protocol::{jwt, oauth2, sso, oidc, saml, webauthn, ...}` | feature 名与 trait 签名冻结；新增方法优先默认实现 |
| `secure-*` | `secure::{ct_eq, masking, totp, xss, sanitize, ...}` | 常量时间比较原语签名冻结 |
| `web-*` | `web_axum` / `web_actix` / `web_warp` | 三适配层 trait 与中间件名一致 |
| `account-*` | `account::{credential, policy, authflow, password_reset}` | Credential SPI 与策略签名冻结 |
| `abac` | `abac::{AbacEngine, EntityLoader}` | Cedar 版本与 policy 输入结构冻结 |
| `oauth2-server` | `oauth2_server::*` | scope/claim 契约冻结 |
| `rate-limit-redis` | `limiteron::{LimiterBackend, LimiterRuntime}` | 后端枚举与配置键冻结 |
| `firewall-*` | `strategy::firewall::*` | 策略构造签名与 key 前缀冻结 |

## Experimental / Internal

| 面 | 分级 | 说明 |
|----|------|------|
| `config-distributed` | Experimental | 分布式配置透传，minor 可调整 |
| `db-saga` / `db-sharding` | Experimental | 高级数据库编排，minor 可调整 |
| `backend-kit` | Experimental | trait-kit typestate DI，minor 可调整 |
| `cli-ops` | Experimental | `garrison-cli` 输出格式可能调整 |
| `firewall-{gcra,tower,admission,event,monitoring,parallel}` | Experimental | limiteron 高级透传面 |
| `dao::testing` / `stp::mock` / `manager::mock` | Internal | 测试辅助，不承诺 |
| `#[doc(hidden)]` 项 | Internal | 不作为 API |

## 冻结前必改清单

| # | 项 | 验收证据 | 状态 |
|---|----|---------|------|
| 1 | 公共项清单逐项分级 | `logs/api-surface.txt` + 本文表 | 进行中 |
| 2 | `#[non_exhaustive]` 审计 | `GarrisonError`、配置枚举、`RateLimitBackend` 评审记录 | 待办 |
| 3 | 错误码冻结 | `prefixed_code()` 前缀码清单 | 待办 |
| 4 | 配置键冻结 | `docs/CONFIGURATION.md` 键名清单 | 待办 |
| 5 | feature 名冻结 | `Cargo.toml [features]` 公开面清单 | 待办 |
| 6 | 存储 key 格式冻结 | 会话/限流 key 格式说明 | 待办 |
| 7 | MSRV 策略 | `rust-version` 变更窗口说明 | 待办 |
| 8 | trait 对象安全 | `cargo check` + `dyn` 用例 | 待办 |
| 9 | prelude 冻结 | prelude 只增不减评审 | 待办 |

## API 差异流程

```bash
# 生成当前公共面
bash scripts/api_surface.sh

# 与基线比较，输出结构化 JSON（logs/api-surface-diff.json）
bash scripts/api_surface.sh --diff logs/api-surface.baseline.txt
```

- PR 级 diff 由 `.github/workflows/api-surface-diff.yml` 自动执行，**report-only**，工件保留 30 天。
- 基线文件不提交仓库（`logs/` 已忽略）；发布前将当次工件归档到 release 资产或内部制品库。
- 冻结转 blocking 的时机：1.0-rc 阶段；0.x 仍保持 report-only。

## 相关文档

- [API_STABILITY.md](./API_STABILITY.md)：分级原则、冻结检查清单、弃用流程
- [ROADMAP.md](./ROADMAP.md)：v1.0 门禁状态
- [CHANGELOG.md](./CHANGELOG.md)：本轮 API 相关变更
