# 🧪 Garrison 测试场景矩阵

> 适用版本：Garrison **0.9.0-rc.2**（MSRV 1.85，`rust-toolchain.toml` 锁定 1.85.1）
> 编写依据（只读核对）：`Cargo.toml [features]` 与 `[[test]]` 注册、`tests/acceptance.rs` 域入口、`tests/acceptance/*.rs`、`tests/acceptance/migrated/*.rs`、`examples/tests/`、`.github/workflows/ci.yml`、`.github/workflows/feature-matrix.yml`、`scripts/e2e_matrix.sh`、`scripts/e2e_run.sh`、`benches/garrison_benchmark.rs`。
> 本文合并自原《E2E 特性组合测试套件》文档（`E2E_TESTING.md` 已删除），并补入基于真实测试套件的场景穷举。
> 规模数字均为 `#[test]` / `#[tokio::test]` 属性的 grep 统计（含 `#[tokio::test(flavor = ...)]` 形态），截至 2026-09-15。

## 📋 目录

- [阅读约定](#-阅读约定)
- [测试体系总览](#️-测试体系总览)
- [测试规模统计](#-测试规模统计)
- [验收场景矩阵](#-验收场景矩阵)
- [特性依赖分析](#-特性依赖分析)
- [测试矩阵设计](#-测试矩阵设计)
- [使用指南](#-使用指南)
- [质量门禁](#-质量门禁)
- [已知问题与处置记录](#-已知问题与处置记录)
- [相关文档](#-相关文档)

---

## 🎯 阅读约定

- 场景按「域」组织，每域对应 `tests/acceptance/` 下一个文件，域内「正常路径 + 异常路径」成对覆盖。
- 场景编号沿用代码内注释约定 `ACC-<域>-<序号>`（如 `ACC-ENV-001`，见 `tests/acceptance/environment.rs`）；本文表格中的「场景数」为 grep 统计的测试属性数，个别辅助用例（harness 自检）计入所在文件。
- `#[ignore]` 用例为性能基线（`perf_*` 前缀），需显式 `--ignored` 运行；外部服务门控用例在服务不可达时自动 `[SKIP]`（fail-skip），不会静默退化——`e2e_matrix.sh` 的 S0 阶段保证真服务在位。
- 特性面缩写：`full` = 全能力聚合；`testing` = 验收矩阵配套 feature（`garrison/testing` 门控测试辅助设施）；`S3kc` / `S3hibp` = 在 `full` 之上追加 `keycloak-oidc` / `policy-hibp` 面的 e2e_matrix 阶段。

---

## 🗺️ 测试体系总览

测试金字塔与三层质量防线：

| 层 | 位置 | 特性面 | 触发 |
|----|------|--------|------|
| 单元测试 | `src/` 内联 `#[cfg(test)]` 模块（237 处） | default 与 full 两种特性面 | `ci.yml` test job / `e2e_matrix.sh` S2 |
| 验收/集成测试 | `tests/acceptance`（主 target）+ `acceptance_db_postgres` / `acceptance_db_mysql`（db 专用 target）+ `macros_ui`（trybuild） | `full testing` 及各 db 面 | `ci.yml` integration-test job / S3 |
| 示例级集成测试 | `examples/tests/`（与 `examples/src/bin/` 一一对应） | `-p garrison-examples --all-features` | `e2e_matrix.sh` S4 |
| UI/编译失败测试 | `tests/ui/`（trybuild，经 `tests/macros_ui.rs`） | `annotation-macros` | `ci.yml`（Linux/MSRV 腿） |
| 基准测试 | `benches/garrison_benchmark.rs`（Criterion，harness = false） | full | `e2e_matrix.sh` S6 |
| 文档测试 | 公开 API rustdoc 示例（含 `lib.rs` 顶部可运行 doctest） | `full,audit-log` | `ci.yml`（Linux/MSRV 腿） |
| 特性组合编译矩阵 | `ci.yml` test-compile-guard + `feature-matrix.yml` + `e2e_matrix.sh` S5 | 聚合 + web×db 网格 + 定向组合 | PR 门禁 / 每周兜底 / 本地全量 |

三层质量防线：

| 层 | 触发 | 范围 |
|----|------|------|
| `.github/workflows/ci.yml` | push / PR | default/full/production 编译、fmt、clippy、三平台测试矩阵、guard 组合、doc、deny、集成测试（services: redis/postgres）、覆盖率 ≥85% |
| `.github/workflows/feature-matrix.yml` | 每周一 03:00 UTC | each-feature 全量 + 定向两两 + examples |
| `scripts/e2e_matrix.sh` | 手动 / 本地 / 发布前 | 上述全部的本地等价物 + **真服务验收**（compose 含健康检查与确定性清理）+ **性能基线** + **HTTP E2E 渗透** |

---

## 📊 测试规模统计

> 规模为 `#[test]` / `#[tokio::test]` 属性的 grep 统计，截至 2026-09-15（v0.9.0-rc.1 工作区）。

| 类别 | 位置 | 数量 |
|------|------|------|
| 单元测试 | `src/` 内联（237 个 `#[cfg(test)]` 模块） | 约 4800 |
| 验收 / 集成 / UI 测试 | `tests/`（acceptance 20 域 + migrated 11 文件 + db 专用 target + macros_ui） | 约 406 |
| 示例级集成测试 | `examples/tests/`（58 个文件，与示例 bin 一一对应） | 约 116 |
| 过程宏测试 | `macros/` | 8 |
| 合计 | — | **约 5330** |
| Criterion 基准 | `benches/garrison_benchmark.rs` | 4 场景 |
| 行覆盖率门禁 | `ci.yml` coverage job | `--fail-under-lines 85`（当前行覆盖率约 95.8%，见 CHANGELOG 0.8.1 TEST-01 记录） |

---

## 🧪 验收场景矩阵

`tests/acceptance.rs` 为验收矩阵入口，按域组织 `tests/acceptance/*.rs`，本 target 需 `full` + `testing` feature（`Cargo.toml` `required-features`）。各域场景数（grep 统计）：

### 正常路径域

| 域文件 | 场景数 | 覆盖内容 |
|--------|:------:|----------|
| `authentication.rs` | 19 | 登录认证主流程（login / logout / kickout / token 样式） |
| `session.rs` | 19 | 双模会话（Account-Session / Token-Session）、并发与共享策略 |
| `rbac.rs` | 18 | RBAC 权限校验与角色层级 |
| `protocol_jwt.rs` | 19 | JWT 签发 / 验证 / refresh 轮换 |
| `protocol_oauth2.rs` | 16 | OAuth2 四种 grant（打真实 Keycloak 26） |
| `protocol_mixed.rs` | 23 | 多协议混合场景（JWT/OAuth2/SSO 交叉） |
| `server.rs` | 22 | 独立认证服务器（auth-server 端点行为） |
| `web_axum.rs` | 25 | axum 路由拦截与注解 |
| `web_actix.rs` | 8 | actix-web 中间件 |
| `web_warp.rs` | 6 | warp 过滤器 |
| `bw_ac.rs` | 6 | ABAC（Cedar DSL）属性访问控制 |
| `repository.rs` | 30 | Repository 层（10 trait）CRUD 与租户隔离 |
| `keycloak_fixture.rs` | 3 | 真实 Keycloak 登录表单流夹具自检 |
| `web_smoke.rs` | 3 | 三 Web 框架冒烟 |
| `storage.rs` | 16 | 存储后端行为（TTL / 过期 / 持久化） |
| `harness.rs` | 5 | 验收 harness 自检 |

### 异常与边界域

| 域文件 | 场景数 | 覆盖内容 |
|--------|:------:|----------|
| `security.rs` | 30 | 渗透测试攻击面（Token 伪造 / 注入 / CSRF，原 pentest 套件 ACC-SEC-021..030 并入） |
| `resilience.rs` | 12 | 故障韧性（超时 / 断连 / 熔断 / fail-closed） |
| `concurrency.rs` | 9 | 竞争条件（含 8 个 `#[ignore]` 性能基线 `perf_*` 用例） |
| `environment.rs` | 8 | 外部服务环境门控（Redis DAO / Postgres 迁移 / MySQL testcontainers，不可达自动 [SKIP]） |

### 迁移归档域（`tests/acceptance/migrated/`）

| 文件 | 场景数 | 覆盖内容 |
|------|:------:|----------|
| `annotation_macros.rs` | 25 | 注解宏展开行为 |
| `strategy_registry.rs` | 19 | 策略注册表 |
| `axum.rs` | 11 | axum 集成（迁移用例） |
| `jwt_modes.rs` | 16 | JWT 三种模式 |
| `plugin_listener.rs` | 15 | 插件与监听器 |
| `login_password.rs` | 9 | 密码登录 |
| `annotation.rs` | 9 | 注解（迁移用例） |
| `refresh_token.rs` | 2 | RefreshToken 轮换 |
| `keycloak_oidc.rs` | 1 | OIDC RP 完整流程（真实 Keycloak） |
| `tenant_isolation.rs` | 1 | 多租户隔离 |

### db 专用验收 target

dbnexus 以 `compile_error!` 禁止 embedded（sqlite）与 server-side（postgres/mysql）驱动共存，而 `full` 聚合含 `db-sqlite`——因此数据库专用场景经独立 target 单独编译运行，补齐覆盖漏洞：

| Target | 特性面 | 覆盖内容 |
|--------|--------|----------|
| `acceptance_db_postgres` | `--no-default-features --features db-postgres` | 连接 + 10 张核心表迁移 + UserRepository CRUD（ACC-ENV-005..006） |
| `acceptance_db_mysql` | `--no-default-features --features db-mysql` | MySQL 迁移与 CRUD（ACC-ENV-007..008，testcontainers 动态拉起） |

### 示例级集成测试（`examples/tests/`）

58 个测试文件与 `examples/src/bin/` 一一对应（basic_login、axum_integration、oauth2_flow、sso_server、jwt_modes、firewall_defense、account_security 等），随 `cargo test -p garrison-examples --all-features` 执行，共约 116 个测试属性。其中 `readme_quickstart.rs` 与 README「最小示例」逐字对应，防止文档漂移。

---

## 🔀 特性依赖分析

### 规模概览

- `cargo metadata` 统计：**145 个 feature**（含 `dep:` 展开项），聚合特性
  `full` 传递启用 95 项、`production` 35 项、`config-full` 12 项、`db-base` 15 项。
- 模块分层：核心（无开关，总编译）+ 9 大可选功能域 + 3 个聚合特性。

### 功能域与依赖结构

```text
核心（always on）: core / stp / annotation / router / dao / strategy /
                   session / config / context / json / exception / manager / plugin

核心扩展 ── core-advanced ← authorize-api ← manager-explicit
         └─ tenant-isolation ⇒ limiteron/multi-tenant

配置增强 ── config-{encryption,validation,hot-reload,interpolation,dynamic,
             toggle,yaml,audit,consul,etcd,distributed,schema} → confers/* 透传
         └─ config-full = 以上 12 项

缓存后端 ── cache-memory ⇒ oxcache/{memory,serialization,metrics,bloom}
         ├─ cache-redis  ⇒ cache-memory + oxcache/{redis,lua,compression} + redis
         ├─ cache-lock   ⇒ cache-redis + oxcache/lock
         └─ cache-batch  ⇒ cache-memory + oxcache/batch

数据库后端 ── db-base（dbnexus + 15 项子特性 + sea-orm）
          ├─ db-sqlite   = db-base + dbnexus/sqlite            （embedded）
          ├─ db-postgres = db-base + dbnexus/postgres + embedded-migrations
          ├─ db-mysql    = db-base + dbnexus/mysql             （server-side）
          ├─ db-retry    = db-base + dbnexus/retry
          ├─ db-sharding = db-base + dbnexus/{sharding,distributed-id,scatter-gather}
          ├─ db-replica  = db-base + dbnexus/replica-routing
          └─ db-saga     = db-sharding + dbnexus/saga

协议层 ── protocol-oauth2（reqwest/sha2/base64/percent-encoding）
       ├─ protocol-jwt（jsonwebtoken）          [sso/oidc/oauth2-server 隐含]
       ├─ protocol-sso  ⇒ protocol-jwt          （OIDC id_token 强制验签，fail-closed）
       ├─ protocol-oidc ⇒ jwt + oauth2 + subtle
       ├─ protocol-saml ⇒ sso + rsa             （XML 签名验证）
       ├─ protocol-sign / apikey(⇒secure-ct-eq+dao-key-index) / temp / invitation
       ├─ protocol-httpbasic / httpdigest / zeroize
       ├─ oauth2-scope-handler ⇒ oauth2
       └─ protocol-sso-server ⇒ sso

安全模块 ── secure-totp / secure-sign / secure-confusable / secure-masking
         ├─ secure-xss / secure-sanitize / secure-ct-eq
         └─ sms-rate-limit / email-verification ⇒ email-verification-smtp

账号安全 ── account-credential（argon2/bcrypt/rand/sha2/base32）
         ├─ credential-zeroize ⇒ credential + zeroize
         ├─ account-policy ⇒ credential + regex
         ├─ account-lockout ⇒ firewall
         └─ account-authflow ⇒ credential + policy + lockout + ipnetwork

Web 适配 ── web-axum / web-actix / web-warp（三框架独立可共存）
         ├─ web-cors / csrf / security-headers ⇒ web-security（聚合）
         ├─ annotation-macros ⇒ web-axum（宏 wrapper 生成 axum Response）
         └─ tls ⇒ axum-server + auth-server

防火墙 ── firewall（基座）
       ├─ bruteforce(⇒ddos+limiteron/ban-manager) / ratelimit / anomalous
       ├─ geoip ⇒ limiteron/geo-matching；maxminddb ⇒ geoip+anomalous
       ├─ waf ⇒ web-axum；ddos；gcra/tower/quota/admission/event/monitoring/
       │  parallel ⇒ limiteron/* 透传
       ├─ rate-limit-redis ⇒ ratelimit + cache-redis
       └─ anomalous-detector-dual ⇒ listener + dao-key-index

Server ── http（sdforge 宏桥接，cfg-only，不可改名）
       ├─ auth-server-sdforge ⇒ http
       ├─ auth-server ⇒ web-axum + backend-embedded + sdforge + subtle
       │                + secure-simple-token + mimalloc
       └─ server-health-check / server-graceful-shutdown ⇒ auth-server

后端架构 ── backend-embedded（默认）/ backend-remote（reqwest + limiteron 熔断）
        ├─ backend-kit ⇒ trait-kit/{lifecycle,health,observer}；backend-shutdown ⇒ kit
        ├─ abac ⇒ cedar-policy + cache-memory
        └─ oauth2-server ⇒ oauth2 + jwt + argon2 + secure-ct-eq（SQLite 下
           RefreshTokenRotation 依赖 protocol-jwt，故隐含）

安全告警 ── security-extra ← security-alert（兼容别名）← device-binding /
         session-hijack-detection（后者还 ⇒ auth-server）

可观测性 ── listener ← credit-metering / audit-log(⇒masking+ct-eq)
        ├─ tracing-log / metrics-prometheus / otlp（独立重依赖隔离）
        ├─ grpc ⇒ tonic + tonic-health + tower + sdforge/grpc
        └─ audit-inklog ⇒ inklog/{fast-masking,compression}；-http ⇒ inklog/http

i18n ── i18n（基础层无条件编译，feature 仅门控测试）⇒ i18n-icu（ICU4X 7 crate）

聚合 ── full（95 项）/ production（35 项，db-postgres 面向）/ development
        （= cache-memory + db-sqlite + web-axum；default = backend-embedded）
```

### 硬约束（组合矩阵必须遵守）

| 约束 | 原因 |
|------|------|
| `db-sqlite` ⊕ `db-postgres`/`db-mysql` | dbnexus 0.4 以 `compile_error!` 禁止 embedded 与 server-side 驱动共存（多 DB 仅在「部署期选一个」语义下合法） |
| `--all-features` 不可用 | 上述互斥的推论；CI 一律用显式聚合（`full`/`production`） |
| `protocol-sso` ⇒ `protocol-jwt` | OIDC `exchange_code` 必须验签 `id_token`（安全审计 fail-open → fail-closed 修复） |
| `http` 桥接 feature 不可改名 | sdforge `#[forge]` 宏硬编码 `#[cfg(feature = "http")]`，改名 = 全部动态路由 404 |
| `security-alert` 必须落地 `security-extra` | 历史上为零依赖死 feature，导致 device-binding 单独启用编译失败 |
| MSRV | Cargo.toml 声明 1.85，但当前 lockfile 的 rc.2 兄弟 crate 要求 ≥1.97.1（以 lockfile 为准） |

---

## 🧩 测试矩阵设计

### 三维覆盖（对应用户场景维度）

| 维度 | 载体 | 规模 |
|------|------|------|
| **正常路径** | `acceptance/authentication`（JWT/OAuth2/SSO 登录流）、`rbac`、`session`、`protocol_jwt`/`protocol_oauth2`/`protocol_mixed`、`web_{axum,actix,warp}`、`server`、`bw_ac`（ABAC） | 验收场景 / 19 域（见上文矩阵） |
| **异常与边界** | `resilience`（超时/断连/熔断）、`security`（Token 伪造/注入/CSRF）、`concurrency`（竞争条件）、`environment`（服务不可达 fail-closed 门控）、`storage`/`repository`（存储故障与迁移） | 同上 |
| **组合场景** | `web_{axum,actix,warp}` × `db_{sqlite,postgres,mysql}` 编译级网格（见下）+ `full` 特性面下三 Web 框架运行时验收 | 15 网格组合 + 13 定向组合 |

### 运行时矩阵（真服务）

由 `S0` compose 自举 + `S3` 执行：

- **Redis**（compose :16379）：DAO 读写/TTL/原子方法防护（ACC-ENV-001..004）、
  分布式限流、cache-redis 后端。
- **PostgreSQL**（compose :15432，凭据与测试默认一致）：连接 + 10 张核心表迁移 +
  UserRepository CRUD（ACC-ENV-005..006）。
- **MySQL**（compose :13306 供手动验证；自动化经 testcontainers 动态拉起，
  ACC-ENV-007..008）：docker 探活门控，不可达自动 [SKIP]。
- **Keycloak 26**（compose :18090，S0 经 `scripts/keycloak_provision.py` 幂等供给
  realm `garrison`：客户端 `garrison-cli` / 用户 `alice`）：OAuth2 四种 grant、
  授权码 PKCE、introspection、RFC 7009 吊销与 OIDC RP（`keycloak-oidc` 面，
  S3kc）全部打真实 IdP；授权码经 keycloak_fixture 驱动真实登录表单流获取
  （2026-09 用户裁定：验收层禁止 mock，原 wiremock 模拟面移除/下沉单元层；
  不可达自动 [SKIP]）。
- **HIBP**（`policy-hibp` 面，S3hibp）：泄露/干净密码查询打真实
  api.pwnedpasswords.com（k-anonymity 仅上传 5 hex 前缀）；离线自动 [SKIP]。

> **db 专用验收 target**：dbnexus 以 `compile_error!` 禁止 embedded（sqlite）与
> server-side（postgres/mysql）驱动共存，而 `full` 聚合含 `db-sqlite`——因此
> ACC-ENV-005..008 在 full 面下被 cfg 剥离、历史上从未真正执行。套件 S3 阶段
> 经独立 target `acceptance_db_postgres` / `acceptance_db_mysql`
> （`--no-default-features --features db-postgres|db-mysql`）单独编译运行，
> 补齐该覆盖漏洞（`tests/acceptance_db_*.rs`）。

地址覆盖约定（默认值不变，向后兼容）：

| 环境变量 | 默认 | compose 值 |
|---|---|---|
| `GARRISON_TEST_REDIS_ADDR` | `127.0.0.1:6379` | `127.0.0.1:16379` |
| `GARRISON_TEST_REDIS_URL` | 由 ADDR 推导 | `redis://127.0.0.1:16379` |
| `GARRISON_TEST_POSTGRES_ADDR` | `127.0.0.1:5432` | `127.0.0.1:15432` |
| `GARRISON_TEST_POSTGRES_URL` | `postgres://garrison:garrison@localhost:5432/garrison_test` | 端口 `15432` |
| `GARRISON_TEST_KEYCLOAK_URL` | `http://127.0.0.1:18090` | 端口 `18090` |

### 编译级矩阵（组合冲突防线）

`S5` 阶段对每个组合执行 `cargo check` + `cargo test --lib --no-run`
（后者专防 2026-09 实录的「测试代码 feature 门控漂移」）：

1. **聚合特性**：`default` / `development` / `production` / `full` / 零特性 minimal；
2. **web × db 网格**：`{web-axum, web-actix, web-warp}` × `{db-sqlite, db-postgres,
   db-mysql}`（9 组）+ 三 web 共存 × 单 db（3 组）——遵守 dbnexus 互斥约束；
3. **定向两两组合**（13 组，源自历史事故面与 ci.yml guard 清单）：
   `db-mysql+embedded-migrations`、`db-sqlite+protocol-apikey`、
   `db-postgres+three-tier-cache`、`protocol-jwt+secure-ct-eq`、
   `protocol-saml+protocol-oidc`、`web-warp+annotation-macros`、
   `web-actix+web-security`、`auth-server+backend-remote`、
   `oauth2-server+cache-redis`、`tenant-isolation+firewall-bruteforce`、
   `db-web-policy-listener`、`email-credential-authflow`、`full+testing`；
4. **each-feature 全量扫描**（`--full-matrix`，约数百个组合×编译，耗时数小时）：
   `cargo hack check --each-feature --exclude-all-features` + 逐 feature 测试编译
   （排除聚合特性；CI `feature-matrix.yml` 每周兜底同款逻辑）。
   两个 cargo-hack 调用注意点（2026-09-10 实录）：
   - `--no-dev-deps` 会临时改写 manifest，与 `--locked` 互斥（lockfile 需更新）；
   - 必须加 `--exclude-all-features`——dbnexus 互斥使 all-features 基线必然失败，
     属预期约束而非回归（已同步修复 CI feature-matrix.yml 的每周编译 job）。
   本地验证记录：**130/130 特性组合独立编译全绿**（rustc 1.98.1 + `-D warnings`）。

> 全量 powerset 为 O(2^108)，数学上不可行；本套件按
> 「单 feature 独立 + 定向两两 + 聚合 + 网格」四层采样，与 CI 保持同一方法论。

---

## 📖 使用指南

```bash
# 日常全量（推荐）：compose 自举 + 静态门禁 + 全部测试 + 快速矩阵 + 基准 + HTTP E2E
bash scripts/e2e_matrix.sh

# 发布前深扫：追加 each-feature 全量编译扫描（数小时）
bash scripts/e2e_matrix.sh --full-matrix

# 快速迭代（跳过基准与 HTTP E2E）
bash scripts/e2e_matrix.sh --skip-bench --skip-e2e-http

# 调试：保留中间件环境
bash scripts/e2e_matrix.sh --keep-env
docker compose -f docker-compose.e2e.yml down -v --remove-orphans   # 手动清理
```

一键 HTTP E2E（外部 18080 / 内部 18081，auth_server_serve 进程级黑盒冒烟）：

```bash
EXAMPLE_INTERNAL_API_KEY=$(openssl rand -hex 16) bash scripts/e2e_run.sh
# 产物：logs/perf.jsonl + logs/e2e_final_report.md
```

报告输出：`logs/e2e_matrix_report.md`（各阶段日志在 `logs/e2e_matrix/`）。
退出码：`0` 全过；`1` 存在失败阶段（先看 `logs/e2e_matrix_report.md`，
再看 `logs/e2e_matrix/<stage>.log`）。

### 环境要求

- Rust stable ≥ 1.97.1（lockfile 约束；国内镜像滞后的镜像源可临时
  `RUSTUP_DIST_SERVER=https://static.rust-lang.org rustup update stable`）
- Docker（daemon 可达；testcontainers 拉取 MySQL 镜像需外网或本地缓存）
- protoc（sdforge 构建依赖）、cargo-hack（仅 `--full-matrix` 需要）

---

## 🚦 质量门禁

| 门禁 | 命令 | 通过标准 |
|------|------|---------|
| 格式 | `cargo fmt --all -- --check` | 零 diff |
| Lint | `cargo clippy --no-default-features --features "default" -- -D warnings`<br>`cargo clippy --features "full" -- -D warnings` | 零告警 |
| 依赖安全 | `cargo deny --all-features --locked check` | 漏洞/许可证/禁用源/重复依赖全过 |
| 测试 | S2~S4 | 全绿；服务门控场景不得静默退化（S0 保证真服务在位） |
| 覆盖率 | `cargo llvm-cov --features "full" --fail-under-lines 85` | 行覆盖率不低于 85%（CI coverage job） |
| 性能 | `cargo bench --bench garrison_benchmark --features full --locked -- --quick --save-baseline e2e` | criterion 无 `Regressed` 判定；基线存于 `target/criterion` 供后续对比 |
| HTTP E2E | `scripts/e2e_run.sh`（外部 18080 / 内部 18081） | happy path / errors / boundary / perf / pentest 全绿 + Markdown 报告生成 |

---

## 📝 已知问题与处置记录

- **工具链**：兄弟生态 crate（confers/dbnexus/oxcache/sdforge/limiteron/inklog/
  trait-kit rc.2）要求 rustc ≥1.97.1；aliyun 镜像源可能滞后，需从官方源更新 stable
  （`RUSTUP_DIST_SERVER=https://static.rust-lang.org rustup update stable`）。
- **e2e target 残留**：Phase 4 迁移删除了 examples 的 `--test e2e`
  target，但 `scripts/e2e_run.sh` 仍引用之——已重写指向现行 `tests/acceptance`
  （pentest→security 域、perf→concurrency 域 `#[ignore]` 用例），并保留
  auth_server_serve 进程级黑盒冒烟 + health 探活。
- **MySQL 迁移 1064**：`011_add_soft_delete.sql` 曾使用 `DELIMITER //` 存储过程
  实现 CLI 幂等——`DELIMITER` 是 mysql CLI 客户端指令而非 SQL，dbnexus/sqlx
  多语句批量执行路径直接报 1064；因 ACC-ENV-007/008 此前不可达而潜伏。
  已改为普通 DDL（迁移器按版本一次性应用，无需存储过程幂等）。
- **bench 租户上下文**：`benches/garrison_benchmark.rs` 的 permission_check
  在 `tenant-isolation` 启用（full 面）下因无 `TENANT.scope` 而 panic——
  基准现已显式进入默认租户 0 上下文（与 server 中间件行为等价）。
- **端口策略**：套件固定使用高位端口（16379/15432/13306/18080/18081/18090），
  与常用默认端口及开发机常驻容器零冲突；清理仅作用于 compose 项目 `garrison-e2e`。
- **bench 调用**：裸 `cargo bench` 会连带以 bench profile 运行 lib unittest，
  不识别 criterion 参数（`Unrecognized option: 'quick'`）——套件固定
  `cargo bench --bench garrison_benchmark`。
- **perf 基线的 debug/release 双模式**：`assert_perf_baseline` 在 debug 构建
  （`cfg!(debug_assertions)`）下为软警告（login 涉及 argon2/bcrypt，debug 下
  P99 ~1.1s 不达标属预期），release 构建下为硬 panic。release 硬判定需
  外部启动 release 服务并经 `GARRISON_E2E_EXTERNAL_URL/INTERNAL_URL/API_KEY`
  注入（`RemoteContext::connect_env` 路径）。
- **perf_login 基线重校准（2026-09-11）**：原测试用单一账号 `perf_user` 以
  并发 100 压测，撞上登录路径的 per-login_id 互斥锁
  （`SessionStore::with_login_lock`，TOCTOU 修复，**设计如此**——保护
  同账号 Account-Session 读改写原子性），单账号并发必然串行化（实测
  P99 ~700ms）。已改为 100 账号轮转（`LoadRunner::with_body_fn`），度量
  多用户真实流量下的系统吞吐；同账号并发正确性由 concurrency 域竞争测试
  覆盖。排障方法论存档：wchan 快照定位 futex 群等待 → gdb 符号化调用栈
  锁定 `with_login_lock` → 特性消除实验（minimal vs full 差 90 倍）排除
  中间件嫌疑 → 多用户对照实验证实。

---

## 📚 相关文档

| 文档 | 说明 |
|------|------|
| [📖 用户指南](USER_GUIDE.md) | 从安装到进阶的完整使用教程 |
| [📘 API 参考](API_REFERENCE.md) | 公开 API 与模块参考 |
| [🏗️ 架构文档](ARCHITECTURE.md) | 设计原则、模块划分与数据流 |
| [⚡ 性能指南](PERFORMANCE.md) | 性能目标、基准测试与优化建议 |
| [🛠️ 开发规范](DEVELOPMENT.md) | TDD 工作流、代码规范与调试技巧 |
| [🚀 部署指南](DEPLOYMENT.md) | 生产部署注意事项 |
