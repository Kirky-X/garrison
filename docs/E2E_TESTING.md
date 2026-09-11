# Garrison E2E 特性组合测试套件

> 一键命令：`bash scripts/e2e_matrix.sh`
> 报告输出：`logs/e2e_matrix_report.md`（各阶段日志在 `logs/e2e_matrix/`）

本套件把「特性组合测试 + 全量质量保障」固化为可重复执行的本地流水线，
与 `.github/workflows/ci.yml`（PR 门禁）、`feature-matrix.yml`（每周全量兜底）
构成三层质量防线。

---

## 1. 特性依赖分析

### 1.1 规模概览

- `cargo metadata` 统计：**145 个 feature**（含 `dep:` 展开项），聚合特性
  `full` 传递启用 95 项、`production` 35 项、`config-full` 12 项、`db-base` 15 项。
- 模块分层：核心（无开关，总编译）+ 9 大可选功能域 + 3 个聚合特性。

### 1.2 功能域与依赖结构

```
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

### 1.3 硬约束（组合矩阵必须遵守）

| 约束 | 原因 |
|------|------|
| `db-sqlite` ⊕ `db-postgres`/`db-mysql` | dbnexus 0.4 以 `compile_error!` 禁止 embedded 与 server-side 驱动共存（多 DB 仅在「部署期选一个」语义下合法） |
| `--all-features` 不可用 | 上述互斥的推论；CI 一律用显式聚合（`full`/`production`） |
| `protocol-sso` ⇒ `protocol-jwt` | OIDC `exchange_code` 必须验签 `id_token`（安全审计 fail-open → fail-closed 修复） |
| `http` 桥接 feature 不可改名 | sdforge `#[forge]` 宏硬编码 `#[cfg(feature = "http")]`，改名 = 全部动态路由 404 |
| `security-alert` 必须落地 `security-extra` | 历史上为零依赖死 feature，导致 device-binding 单独启用编译失败 |
| MSRV | Cargo.toml 声明 1.85，但当前 lockfile 的 rc.2 兄弟 crate 要求 ≥1.97.1（以 lockfile 为准） |

---

## 2. 测试矩阵设计

### 2.1 三维覆盖（对应用户场景维度）

| 维度 | 载体 | 规模 |
|------|------|------|
| **正常路径** | `acceptance/authentication`（JWT/OAuth2/SSO 登录流）、`rbac`（51 场景）、`session`（42）、`protocol_jwt`/`protocol_oauth2`/`protocol_mixed`、`web_{axum,actix,warp}`、`server`（49）、`bw_ac`（ABAC） | 223 个验收场景 / 19 域 |
| **异常与边界** | `resilience`（39：超时/断连/熔断）、`security`（35：Token 伪造/注入/CSRF）、`concurrency`（33：竞争条件）、`environment`（22：服务不可达 fail-closed 门控）、`storage`/`repository`（68：存储故障与迁移） | 同上 |
| **组合场景** | `web_{axum,actix,warp}` × `db_{sqlite,postgres,mysql}` 编译级网格（§2.3）+ `full` 特性面下三 Web 框架运行时验收 | 15 网格组合 + 13 定向组合 |

### 2.2 运行时矩阵（真服务）

由 `S0` compose 自举 + `S3` 执行：

- **Redis**（compose :16379）：DAO 读写/TTL/原子方法防护（ACC-ENV-001..004）、
  分布式限流、cache-redis 后端。
- **PostgreSQL**（compose :15432，凭据与测试默认一致）：连接 + 10 张核心表迁移 +
  UserRepository CRUD（ACC-ENV-005..006）。
- **MySQL**（compose :13306 供手动验证；自动化经 testcontainers 动态拉起，
  ACC-ENV-007..008）：docker 探活门控，不可达自动 [SKIP]。
- **Keycloak**：自动化路径经 wiremock 模拟 discovery/JWKS/token（production-mock-purge
  T024 用户裁定豁免；compose `--profile keycloak` 提供真例供手动 OIDC 联调）。

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

### 2.3 编译级矩阵（组合冲突防线）

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

### 2.4 质量门禁

| 门禁 | 命令 | 通过标准 |
|------|------|---------|
| 格式 | `cargo fmt --all -- --check` | 零 diff |
| Lint | `cargo clippy --no-default-features --features "default" -- -D warnings`<br>`cargo clippy --features "full" -- -D warnings` | 零告警 |
| 依赖安全 | `cargo deny --all-features --locked check` | 漏洞/许可证/禁用源/重复依赖全过 |
| 测试 | S2~S4 | 全绿；服务门控场景不得静默退化（S0 保证真服务在位） |
| 性能 | `cargo bench --features full -- --quick --save-baseline e2e` | criterion 无 `Regressed` 判定；基线存于 `target/criterion` 供后续对比 |
| HTTP E2E | `scripts/e2e_run.sh`（外部 18080 / 内部 18081） | happy path / errors / boundary / perf / pentest 全绿 + Markdown 报告生成 |

---

## 3. 使用指南

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

退出码：`0` 全过；`1` 存在失败阶段（先看 `logs/e2e_matrix_report.md`，
再看 `logs/e2e_matrix/<stage>.log`）。

### 环境要求

- Rust stable ≥ 1.97.1（lockfile 约束；国内镜像滞后的镜像源可临时
  `RUSTUP_DIST_SERVER=https://static.rust-lang.org rustup update stable`）
- Docker（daemon 可达；testcontainers 拉取 MySQL 镜像需外网或本地缓存）
- protoc（sdforge 构建依赖）、cargo-hack（仅 `--full-matrix` 需要）

### 与 CI 的关系

| 层 | 触发 | 范围 |
|----|------|------|
| `ci.yml` | push/PR | default/full/production 编译、fmt、clippy、三平台测试矩阵、guard 组合、doc、deny、集成测试（services: redis/postgres）、覆盖率 ≥85% |
| `feature-matrix.yml` | 每周一 03:00 UTC | each-feature 全量 + 定向两两 + examples |
| **`e2e_matrix.sh`（本套件）** | 手动/本地/发布前 | 上述全部的本地等价物 + **真服务验收**（compose 含健康检查与确定性清理）+ **性能基线** + **HTTP E2E 渗透** |

## 4. 已知问题与处置记录

- **工具链**：兄弟生态 crate（confers/dbnexus/oxcache/sdforge/limiteron/inklog/
  trait-kit rc.2）要求 rustc ≥1.97.1；aliyun 镜像源可能滞后，需从官方源更新 stable
  （`RUSTUP_DIST_SERVER=https://static.rust-lang.org rustup update stable`）。
- **e2e target 残留**：Phase 4 迁移（T040/T042/T043）删除了 examples 的 `--test e2e`
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
  （`SessionStore::with_login_lock`，T015 TOCTOU 修复，**设计如此**——保护
  同账号 Account-Session 读改写原子性），单账号并发必然串行化（实测
  P99 ~700ms）。已改为 100 账号轮转（`LoadRunner::with_body_fn`），度量
  多用户真实流量下的系统吞吐；同账号并发正确性由 concurrency 域竞争测试
  覆盖。排障方法论存档：wchan 快照定位 futex 群等待 → gdb 符号化调用栈
  锁定 `with_login_lock` → 特性消除实验（minimal vs full 差 90 倍）排除
  中间件嫌疑 → 多用户对照实验证实。
