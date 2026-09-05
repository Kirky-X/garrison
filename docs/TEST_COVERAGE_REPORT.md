# Garrison 功能分析与测试覆盖度审查报告

| 项目 | 内容 |
|---|---|
| 审查对象 | garrison v0.9.0-rc.1（commit `7920082`，main 分支） |
| 审查日期 | 2026-09-04 |
| 审查范围 | `docs/` 需求文档（PRD/FRD/ADD v0.2.0）、`src/`（333 文件 / 159,441 行）、`specmark/`（118 specs / 50 归档变更） |
| 验证命令 | `cargo test --features full`、`cargo llvm-cov --features full --fail-under-lines 85 --lcov`（与 CI `coverage` job 完全一致） |
| 需求基线 | `docs/origin/【Bulwark】产品需求文档(PRD).md` v0.2.0（13 特性域 / 167 项需求）、FRD §8.1 BW-AC-001~015 |

> **2026-09-04/05 已完成两轮按优先级修复（R-01~R-12 + §9.3 残余 + keys() 语义对齐），见 §9/§10。**
> 修复后关键指标：覆盖率 **94.51% → 95.73%**；测试总数 4,356 → **4,571（0 失败）**；
> 低于 85% 的文件 24 → **3**（均为低价值 mock 测试替身）；§1 摘要表中的部分数字已被 §9/§10 更新。

## 1. 执行摘要

**结论：全部验证通过，覆盖率门禁满足，但存在 1 处规格漂移与 24 个低覆盖文件。**

| 验证项 | 结果 | 证据 |
|---|---|---|
| `cargo test --features full` | ✅ **0 失败** | lib 3,962 通过 / 5 ignored；acceptance 380 通过 / 3 ignored；doc-tests 14 通过 / 127 ignored（共 4,356 通过） |
| CI 覆盖率门禁（行覆盖 ≥85%） | ✅ **94.51%**（59,019/62,450） | llvm-cov 退出码 0，报告 `/tmp/garrison_lcov.info` |
| specmark 规格一致性 | ⚠️ **1 处漂移** | `R-database-migration-001`（DuckDB 8 条 FK）已被 commit `73612f4` 回滚，delta spec 未同步；归档 `meta.json` 仍为 `synced: false` |
| 需求追溯（BW-AC-001~015） | ✅ 建立 | `tests/acceptance/bw_ac.rs` + FRD §8.1 + `specmark/specs/acceptance-criteria/spec.md` 三方对齐 |
| 低覆盖风险 | ⚠️ 24 个文件 <85% | 最严重：`src/credit/config.rs` 0%、`src/bin/auth_server.rs` 0%、`src/protocol/sso/channel.rs` 5.5% |

---

## 2. 功能穷举分析

### 2.1 源码模块清单（38 个顶层条目，7 层架构）

依据 `docs/ARCHITECTURE.md`（v0.9.0-rc.1）与 `src/` 实际目录对照：

| 层 | 模块（src/ 目录） | 说明 |
|---|---|---|
| **核心层**（always on） | `core/`、`stp/`、`annotation/`、`router/`、`dao/`、`strategy/`、`session/`、`config/`、`context/`、`json/`、`exception/`、`manager/`、`plugin/`、`state/`、`constants/`、`protocol/`(基础)、`account/`(基础)、`i18n.rs`、`error.rs` | 无 feature 开关，总是编译。核心 trait 拆分：`GarrisonCore` base + SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic 五子 trait |
| **账号安全引擎** | `account/`（credential、policy、lockout、authflow、disable、metrics） | Argon2/bcrypt 凭据、密码策略、锁定、认证流编排（IP 白名单） |
| **协议层** | `protocol/`：jwt、oauth2、sso（含 oidc、saml、channel）、sign、apikey、temp、social（wechat、alipay）、httpbasic、httpdigest | OIDC id_token 签验、SAML XML 签名验证（rsa）、API Key SHA-256 哈希存储 |
| **安全层** | `secure/`：totp、sign、masking、xss、sanitize、ct_eq、confusable、sms | 常量时间比较原语（CWE-208）、敏感数据脱敏（正则真实脱敏） |
| **防火墙/限流** | `strategy/firewall/`：brute_force、rate_limit、ddos、anomalous、geoip、waf（经 limiteron） | 统一 limiteron 分布式限流，禁止手写实现 |
| **Web 适配层** | `web/`（axum 中间件：cors、csrf、security_headers、waf）、`web_actix/`、`web_warp/` | 三框架提取器 + 宏 + guard |
| **服务器层** | `server/`（GarrisonAuthServer、sdforge_routes、oauth2_routes、middleware）、`oauth2_server/`（authorize/token/revoke/introspect）、`grpc/`、`backend/`（embedded/remote）、`bin/auth_server.rs` | 内外网双路由；backend-remote 带熔断/降级 |
| **可观测性** | `observability/`（metrics、otlp、inklog）、`listener/`（审计）、`health/`、`credit/`（计量）、`cache/`（三层缓存）、`abac/`（Cedar）、`limiteron/` | credit-metering 计量闭环 |

### 2.2 Cargo Features 清单（108 个）

聚合特性：`default = ["backend-embedded"]`、`full`（约 70 项传递依赖）、`production`（db-postgres 系）、`development`（= 原 all-defaults，v0.8.2 移除重名）。按族分组：

| Feature 族 | 成员 | 关键依赖约束 |
|---|---|---|
| 核心扩展 | core-advanced、authorize-api、manager-explicit、tenant-isolation、session-extra、three-tier-cache | tenant-isolation 同时透传 `limiteron/multi-tenant`；DAO SQL 过滤不门控（安全优先） |
| 配置增强 | config-encryption/validation/hot-reload/interpolation/dynamic/toggle、config-full | 全部透传 confers |
| 缓存后端 | cache-memory、cache-redis、cache-lock | cache-redis 隐含 cache-memory |
| 数据库后端 | db-base、db-sqlite、db-postgres、db-mysql、db-retry、embedded-migrations | dbnexus 0.4 强制至少一个驱动；dbnexus 禁止 embedded 与 server-side 混用 |
| 协议 | protocol-oauth2/sso/jwt/sign/apikey/temp/zeroize/oidc/saml/httpbasic/httpdigest、oauth2-scope-handler、protocol-sso-server、protocol-saml | protocol-oidc 依赖 jwt+oauth2+subtle；saml 隐含 sso+rsa |
| 安全 | secure-totp/sign/masking/xss/sanitize/confusable、secure-ct-eq、secure-simple-token、sms-rate-limit、policy-hibp | apikey 隐含 secure-ct-eq + dao-key-index（CWE-916 修复链） |
| 账号 | account-credential/policy/lockout/authflow、credential-zeroize | authflow 隐含 credential+policy+lockout |
| Web | web-axum/actix/warp、web-cors/csrf/security-headers/security、annotation-macros、tls | annotation-macros 隐含 web-axum |
| 防火墙 | firewall、firewall-bruteforce/ratelimit/ddos/anomalous/geoip/maxminddb/waf、rate-limit-redis | bruteforce 隐含 firewall-ddos + limiteron/ban-manager |
| 告警/会话 | security-alert、device-binding、session-hijack-detection、security-extra | hijack 复用 alert 广播链路 |
| 社交/外部 IdP | social-wechat、social-alipay、keycloak-oidc | alipay 隐含 rsa（RSA2 签名） |
| 后端/服务器 | backend-embedded/remote、backend-kit/shutdown、auth-server、auth-server-sdforge、http、abac、oauth2-server | `http` 是与 sdforge 宏的桥接 feature（cfg-only，命名不可改） |
| 可观测性 | listener、credit-metering、tracing-log、metrics-prometheus、otlp、grpc、audit-log、audit-inklog、i18n、i18n-icu、miette、api-docs | grpc 隐含 tonic+tower |

### 2.3 API 端点清单（20 个）

**外网路由**（`external_router`：path-filter → rate_limit → audit_log → tenant_resolution）与**内网路由**（`internal_router`：path-filter → api_key_auth → audit_log → tenant_resolution）共用同一批 `#[forge]` 声明式路由（`src/server/sdforge_routes.rs`，前缀 `/api/v1`）：

| # | 端点 | 方法 | 功能 |
|---|---|---|---|
| 1 | `/api/v1/auth/login` | POST | 统一登录（双模会话签发） |
| 2 | `/api/v1/auth/logout` | POST | 登出（Token/Token-Session 删除） |
| 3 | `/api/v1/auth/refresh` | POST | Token 刷新（轮换 + 链式吊销） |
| 4 | `/api/v1/auth/check-login` | POST | 登录校验 |
| 5 | `/api/v1/auth/check-permission` | POST | 权限校验 |
| 6 | `/api/v1/auth/check-role` | POST | 角色校验 |
| 7 | `/api/v1/auth/check-safe` | POST | 安全等级校验（MFA/safe-auth） |
| 8 | `/api/v1/auth/check-disable` | POST | 封禁/禁用校验 |
| 9 | `/api/v1/auth/check-api-key` | POST | API Key 校验（namespace 归属） |
| 10 | `/api/v1/auth/get-token-info` | POST | Token 信息查询 |
| 11 | `/api/v1/auth/get-session` | POST | 会话查询 |
| 12 | `/api/v1/auth/kickout` | POST | 踢出会话/设备 |
| 13 | `/api/v1/auth/switch-to` | POST | 身份切换 |
| 14 | `/api/v1/auth/renew-to-equivalent` | POST | 等价续期 |
| 15 | `/api/v1/auth/health` | GET | 健康探针 |
| 16 | `/api/v1/metrics` | GET | Prometheus 指标 |
| 17 | `/oauth2/authorize` | GET | OAuth2 授权端点（PKCE） |
| 18 | `/oauth2/token` | POST | OAuth2 令牌端点（4 grant） |
| 19 | `/oauth2/revoke` | POST | OAuth2 吊销 |
| 20 | `/oauth2/introspect` | POST | OAuth2 内省（仅内网路由） |

> 勘误：`server_impl.rs:213` 注释写「15 端点」，实际 `#[forge]` 路由为 16 个（含 `/metrics`），注释陈旧，见 §7 建议 R-06。

### 2.4 specmark 能力规格域分布（118 个 spec）

会话/登录（~15）、Token/JWT（~6）、协议（~9）、安全（~17）、ABAC/多租户（~4）、DAO/缓存（~9）、e2e/质量（~9）、架构/基础设施（~49）。每 spec 含 `R-<域>-NNN` 需求 + 验收标准，构成细粒度需求-验收追溯。

---

## 3. 现有测试资产盘点

### 3.1 数量与分布

| 位置 | 测试函数数 | 说明 |
|---|---|---|
| `src/` 内嵌单元测试 | 4,248（tokio::test 2,619 + test 1,630） | 250/333 文件有测试（75%） |
| `tests/acceptance/`（required-features=full） | 398 个定义 / 383 实际运行 | 3 个为外部服务门控（Redis/Postgres/MySQL 探活跳过） |
| `examples/tests/`（独立 workspace member） | 103 | **根目录 `cargo test --features full` 不运行**（独立 crate） |
| `macros/tests/` | 1（trybuild UI） | 宏编译失败用例 |
| doc-tests | 141 定义 / 14 运行 | 127 ignored 为代码示例 |

### 3.2 验收测试域矩阵（tests/acceptance/，场景编号 ACC-<域>-NNN 可追溯）

| 文件 | 数量 | 功能域 | 场景类型 |
|---|---|---|---|
| security.rs | 30 | TOTP/Basic/Digest/密码策略/HIBP/脱敏/XSS/CSRF/伪造 token/SQL 注入/暴力破解/会话劫持/跨租户隔离 | 正常+异常+**安全攻击** |
| repository.rs | 30 | 10 张核心表 CRUD + 迁移幂等 + 级联删除 + 10 个缺表错误路径 | 正常+异常 |
| web_axum.rs | 25 | 中间件/提取器/宏/WAF/CORS/CSRF/安全头/ABAC fail-closed | 正常+异常 |
| protocol_mixed.rs | 23 | SSO/Sign/ApiKey/Temp 四协议（ticket 销毁、非法签名、namespace 隔离、scope 越权） | 正常+异常 |
| session.rs / rbac.rs / protocol_jwt.rs / authentication.rs / server.rs | 各 18–21 | 双模会话、角色层级/组合器/热切换、JWT 刷新链轮换、锁定/溢出登出、内外网 API | 正常+异常 |
| storage.rs | 16 | 存储 SPI 原子语义（in-memory/oxcache **双后端对拍**） | **并发** |
| protocol_oauth2.rs | 16 | 4 grant + introspect/revoke（wiremock 模拟） | 正常+异常 |
| migrated/*（9 文件） | 97 | 注解宏 strict/loose 语义、Keycloak OIDC e2e、refresh 轮换重用检测、租户隔离+决策溯源 e2e | 正常+异常 |
| concurrency.rs | 9 | 并发登录/续期/踢出/刷新 exactly-once | **并发一致性** |
| resilience.rs | 12 | backend-remote 500/超时（3s vs 300ms）/熔断开闭/登录 ID 边界 | **故障注入** |
| bw_ac.rs / harness.rs / environment.rs / web_smoke.rs / web_actix.rs / web_warp.rs | 31 | BW-AC 验收标准移植、harness 自测、真实服务门控、三框架冒烟 | 正常+门控跳过 |

### 3.3 需求追溯机制

- **BW-AC-001~015**（FRD §8.1 Given-When-Then）→ `specmark/specs/acceptance-criteria/spec.md`（映射到测试文件与命名规范）→ `tests/acceptance/bw_ac.rs`、`authentication.rs`、`session.rs`、`resilience.rs` 实测。抽查 `bw_ac.rs`：BW-AC-002/004/005/006/007/009 等均有编号注释与 Gherkin 引用 ✅
- ACC-<域>-NNN 场景编号贯穿 acceptance 各文件（如 `acc_auth_010_wrong_password_and_unknown_user_indistinguishable`、`acc_sec_022_sql_injection_login_id_no_crash_no_leak`）。
- **无集中式 RTM 文件**（全仓 grep 无 traceability/matrix 命中），追溯靠命名约定，见 §7 R-07。

---

## 4. 场景全覆盖测试设计矩阵（穷举法）

图例：✅ 已有测试覆盖（附代表测试）；⚠️ 部分覆盖（存在缺口）；❌ 未覆盖（改进项）。

### D1 认证核心（stp/ + core/auth + manager）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 正确凭据登录 → 双模会话签发、Token 返回 | ✅ acc_auth_001、bw_ac(BW-AC-001) |
| Happy | 自动续期：低于阈值访问 → TTL 重置 + Token 轮换 | ✅ acc_auth_004 |
| Edge | 错误密码 vs 不存在用户 → 响应不可区分（防用户枚举） | ✅ acc_auth_010 |
| Edge | 登录数溢出 → 最旧 Token 被登出 | ✅ acc_auth_006 |
| Edge | 空 login_id / 超长 login_id 边界 → 无 5xx | ✅ acc_res_010 |
| 并发 | 并发续期/刷新/等价续期 exactly-once | ✅ acc_conc_003/005/006 |
| 安全 | 连续失败 → 锁定（CWE-307） | ✅ acc_auth_012 |
| 安全 | 密码修改后旧会话全部失效 | ✅ 单元 + `invalidate_sessions_after_password_change` |

### D2 会话管理（session/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | Account-Session/Token-Session 双模式读写、TTL、is_share/is_concurrent | ✅ acc_sess_001/002 |
| Happy | 过期监听器回调 | ✅ acc_sess（SessionExpiryListener） |
| Edge | TTL 过期后读取为空；MockClock 时间推进 | ✅ storage::ttl_expiry_reads_empty |
| Edge | 匿名会话、会话搜索、动态活跃超时（session-extra） | ✅ 单元 + migrated |
| 并发 | 同 key 并发 set-if-absent 仅一胜者 | ✅ storage::concurrency_set_if_absent |
| 安全 | 会话劫持：IP 变更 → 告警/踢出（CWE-613 关联） | ✅ acc_sec_029 |
| 安全 | 跨租户 Token 隔离 | ✅ acc_sec_025 |

### D3 RBAC/ABAC（strategy/ + abac/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 角色/权限授予后 check 通过；层级角色传递继承 | ✅ acc_rbac_005 |
| Happy | 组合器短路语义（AND/OR） | ✅ acc_rbac_006 |
| Edge | 无角色/无权限 → 403（BW-AC-004/005） | ✅ bw_ac |
| Edge | 策略热切换立即生效 | ✅ acc_rbac_008 |
| 安全 | ABAC 引擎缺失时 fail-closed | ✅ acc_wax_024 |

### D4 JWT 协议（protocol/jwt）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 签发/验证、refresh 轮换链保持 parent_hash | ✅ acc_jwt_004 |
| Edge | 篡改 payload 拒绝；算法不匹配拒绝（CWE-347） | ✅ acc_jwt_006/007 |
| 安全 | 旧 refresh token 重用 → 整链吊销 | ✅ acc_jwt_008 + migrated/refresh_token.rs e2e |
| Edge | 三种 JWT 模式（stateless/stateful/hybrid）切换语义 | ✅ migrated/jwt_modes.rs（16 例） |

### D5 OAuth2/OIDC/SAML（protocol/oauth2 + oauth2_server + sso）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 授权码 + PKCE 全流程（wiremock 模拟授权服务器） | ✅ acc_oauth2_001 |
| Happy | 本机 OAuth2 Server：4 grant、introspect、revoke（吊销后 introspect=inactive） | ✅ server.rs acc_srv_014~018 |
| Edge | 授权码重放拒绝、错 client secret 拒绝、PKCE verifier 不匹配拒绝 | ✅ acc_oauth2_007/008/010 |
| Happy | Keycloak OIDC RP 全流程 e2e | ✅ migrated/keycloak_oidc.rs |
| Edge | SAML Assertion 签名验证（rsa + 常量时间 DigestValue） | ✅ 单元（protocol-saml tests） |
| ❌ 缺口 | **SSO channel 路由/降级路径**（`protocol/sso/channel.rs` 覆盖率 5.5%，146 行仅 8 行命中） | ❌ |
| ⚠️ 缺口 | 社交登录网络故障路径（wechat/alipay service 68.6%；wiremock 仅用于 oauth2/HIBP，未覆盖 social 回调失败） | ⚠️ |

### D6 API Key / Temp Token（protocol/apikey + temp）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | API Key 生成/校验/吊销/轮换、namespace 列表 | ✅ protocol_mixed + apikey tests（CWE-916：仅存 SHA-256） |
| Edge | namespace 归属校验（防 IDOR/越权） | ✅ acc_mixed（apikey 命名空间隔离） |
| Edge | temp token scope 越权拒绝 | ✅ acc_mixed |
| ⚠️ 缺口 | `protocol/temp/handler.rs` 78.6%（错误路径部分未覆盖） | ⚠️ |

### D7 防火墙/限流（strategy/firewall + limiteron）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 固定窗口限流、WAF 拦截/放行、CORS 预检 | ✅ acc_sec_027（100 次暴破→429）、acc_wax_009/010 |
| Edge | Redis 分布式限流后端切换 | ✅ 单元 + environment 门控（真实 Redis 探活跳过 ⚠️） |
| Edge | 异常登录检测（双检测器） | ✅ anomalous-detector-dual tests |
| ⚠️ 缺口 | **GeoIP 查找失败/MaxMindDB 文件损坏路径**（`strategy/firewall/geo.rs` 77.8%；maxminddb 仅门控编译） | ⚠️ |
| ⚠️ 缺口 | SMS 限流器错误路径（`secure/sms/rate_limiter.rs` 80.2%） | ⚠️ |

### D8 Web 三框架适配（web/ + web_actix/ + web_warp/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | axum 中间件/提取器/宏全矩阵（strict/loose 语义 25 例） | ✅ web_axum.rs + migrated/annotation_macros.rs |
| Happy | actix 提取器 401 对齐、warp guard/rejection 恢复 | ✅ web_actix.rs / web_warp.rs |
| Edge | CSRF double-submit、安全响应头、无效 token 拒绝 | ✅ acc_wax_011/014 |
| ⚠️ 缺口 | `web_actix/router.rs` 77.1%（Actix 路由装配层） | ⚠️ |

### D9 存储层（dao/ + cache/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 10 张表 CRUD + 迁移幂等（sqlite）+ 级联删除 | ✅ repository.rs |
| Edge | 缺表错误路径 ×10 | ✅ acc_repo_013~022 |
| Happy | 三层缓存（L1/L2/TTL 抖动） | ✅ three-tier-cache tests |
| ❌ 缺口 | **`dao/oxcache_impl.rs` 43.9%、`dao/dbnexus_dao.rs` 34%**（生产后端实现层；验收层兜底但分支覆盖不足） | ❌ |
| ⚠️ 缺口 | Redis/Postgres 真实后端测试在 CI 环境被探活跳过（无 testcontainers，仅 MySQL 手动） | ⚠️ |

### D10 服务器与多后端（server/ + backend/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 内网 API Key 认证通过/缺失/错误拒绝 | ✅ acc_srv_007 |
| Happy | 外网限流 429 | ✅ acc_srv_010 |
| Edge | backend-remote 500/超时/熔断开闭恢复（wiremock） | ✅ acc_res_006/007/008 |
| 安全 | 内外网路由隔离（oauth2 introspect 仅内网） | ✅ server.rs |
| ❌ 缺口 | **`bin/auth_server.rs` 0%**（61 行启动逻辑无测试） | ❌ |
| ⚠️ 缺口 | `server/server_impl.rs` 81.1%（路由装配分支） | ⚠️ |

### D11 计量与可观测性（credit/ + observability/ + listener/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 审计日志脱敏输出（CWE-532）、决策溯源 | ✅ listener/audit tests + tenant_isolation e2e |
| ⚠️ 缺口 | **credit 模块整体 76.3%**：`credit/config.rs` 0%（34 行）、`credit/meter.rs` 71.5%、`credit/storage.rs` 74.4%、`credit/cycle.rs` 80.3% —— 计量闭环的边界（超额、周期翻转、幂次扣减）分支未穷举 | ⚠️ |
| ⚠️ 缺口 | `observability/inklog.rs` 57.1%、otlp.rs/metrics_impl.rs 无内嵌测试（OTLP 导出失败静默路径） | ⚠️ |

### D12 账号安全引擎（account/）

| 类别 | 场景 | 状态 |
|---|---|---|
| Happy | 密码哈希（Argon2/bcrypt）+ 策略引擎规则 | ✅ account tests（96.6% 模块覆盖） |
| Edge | HIBP 泄露密码检查（wiremock 模拟 pwned API） | ✅ acc_sec_014~016 |
| Edge | IP 白名单条件（authflow） | ✅ 单元（ipnetwork 求值） |
| Edge | credential-zeroize：Drop 清零 | ✅ 单元 |
| ⚠️ 缺口 | lockout/storage.rs、disable/mod.rs、policy/engine.rs 无内嵌测试（由 acceptance 兜底） | ⚠️ |

### D13 Feature 组合与编译矩阵

| 类别 | 场景 | 状态 |
|---|---|---|
| 组合 | default / full / production 三种聚合 check+build+clippy+test | ✅ CI（ci.yml 44–169 行） |
| 组合 | examples `--all-features` check | ✅ CI 92–93 行 |
| ❌ 缺口 | **无 powerset/两两组合测试**（cargo-hack 未引入）：如 `db-mysql`+`embedded-migrations`（后者仅随 db-postgres 传递启用）等 108 个 feature 的冲突矩阵靠人工约定 | ❌ |
| ✅ | 已知陷阱有文档化护栏：`http` 桥接 feature、dbnexus 驱动强制、panic=abort 对 catch_unwind 的影响均有注释/文档 | ✅ |

### CWE 防御映射（代码标注 ↔ 测试验证）

| CWE | 防御位置 | 测试证据 |
|---|---|---|
| CWE-770（资源分配超限） | session 上限/溢出登出 | ✅ acc_auth_006 + core/auth tests |
| CWE-916（凭据明文存储） | API Key 仅存 SHA-256 | ✅ protocol/apikey/tests.rs |
| CWE-362（竞态） | 原子 set-if-absent、exactly-once | ✅ storage/concurrency.rs |
| CWE-208（时序侧信道） | secure::ct_eq 常量时间比较 | ✅ secure/ct_eq tests + acc_sec |
| CWE-532（日志泄露凭据） | audit 脱敏（正则真实脱敏） | ✅ listener/audit tests |
| CWE-400（DoS） | 限流/DDoS/请求体上限 | ✅ acc_srv_010、DefaultBodyLimit |
| CWE-307（暴力破解） | bruteforce 锁定 + IP 提取防伪 | ✅ acc_auth_012、acc_sec_027 |
| CWE-613（会话过期失效） | TTL/活跃超时 | ✅ session tests |
| CWE-347（签名验证不当） | JWT 算法固定、SAML 常量时间摘要比对 | ✅ acc_jwt_007、saml tests |
| CWE-326（密钥强度不足） | JWT 密钥 ≥32 字节校验 | ✅ config/tests.rs |

---

## 5. 执行与验证结果

### 5.1 测试执行（`cargo test --features full`，与 CI `integration-test` job 同口径）

```text
lib:         3962 passed; 0 failed; 5 ignored
bin:         0 tests
acceptance:  380 passed; 0 failed; 3 ignored（Redis/Postgres/MySQL 门控跳过）
doc-tests:   14 passed; 0 failed; 127 ignored（示例代码）
合计:        4356 passed / 0 failed
```

> 测试输出中出现 3 次 `error: unclosed character class pattern="["`：为 `src/secure/masking.rs` 中 Custom 非法正则错误路径测试（第 323/607/633 行）打印的预期 stderr 噪音，断言均通过，属外观问题（可改为 `tracing::debug` 或 `#[ignore]` 静默）。

### 5.2 覆盖率（llvm-cov，与 CI 同命令）

**总行覆盖 94.51%（59,019/62,450），`--fail-under-lines 85` 门禁通过（退出码 0）。**

分模块（≥30 行文件口径）：

| 模块 | 覆盖率 | 模块 | 覆盖率 |
|---|---|---|---|
| constants | 100% | stp | 94.6% |
| exception | 98.9% | limiteron | 94.9% |
| grpc | 98.1% | error.rs | 94.9% |
| context | 99.2% | backend | 94.5% |
| oauth2_server | 97.0% | cache | 95.3% |
| web | 97.5% | dao | **92.9%** |
| account | 96.6% | protocol | **91.3%** |
| session | 96.4% | manager | 91.7% |
| abac / strategy | 96.3% | config | 91.8% |
| i18n.rs | 96.7% | web_actix / web_warp | 93.5% / 93.9% |
| server | 95.8% | health | **85.2%** |
| secure | 95.7% | observability | **79.8% ⚠️** |
| core | 96.2% | credit | **76.3% ⚠️** |

**24 个低于 85% 的文件（≥30 行）**：

| 覆盖率 | 文件 | 覆盖率 | 文件 |
|---|---|---|---|
| 0.0% | `src/credit/config.rs`（34 行） | 78.6% | `src/protocol/temp/handler.rs` |
| 0.0% | `src/bin/auth_server.rs`（61 行） | 80.0% | `src/health/checks.rs` |
| 5.5% | `src/protocol/sso/channel.rs`（146 行） | 80.2% | `src/secure/sms/rate_limiter.rs` |
| 34.0% | `src/dao/dbnexus_dao.rs` | 80.3% | `src/credit/cycle.rs` |
| 43.9% | `src/dao/oxcache_impl.rs` | 81.1% | `src/server/server_impl.rs` |
| 57.1% | `src/observability/inklog.rs` | 83.0% | `src/credit/metrics.rs` |
| 68.6% | `src/protocol/social/service.rs` | 83.3% | `src/health/warp_routes.rs` |
| 71.5% | `src/credit/meter.rs` | 83.5% | `src/core/auth/default.rs` |
| 74.4% | `src/credit/storage.rs` | 83.9% | `src/dao/defaults.rs` |
| 77.1% | `src/web_actix/router.rs` | 84.0% | `src/dao/in_memory.rs` |
| 77.8% | `src/strategy/firewall/geo.rs` | 84.6% | `src/{router,web_actix,web_warp}/mock.rs` |

> 注：CI 门禁为**行覆盖**；llvm-cov 未启用 `--fail-under-branches`，分支覆盖未纳管（`dao/oxcache_impl.rs` 等实现层行覆盖虚高的风险点，见 §7 R-02）。

---

## 6. specmark 变更管理一致性对照

流程状态：`specmark/specs/` 118 个能力规格；`archive/` 50 个已归档变更（2026-07-05 → 2026-09-04，42 个含 delta specs）；`changes/` 1 个残留空目录。八阶段流程（explore→clarify→propose→analyze→apply→converge→archive→status）由用户级 skill 定义，仓库内以确定性脚本（`scripts/merge_delta_spec.py`、check_phase/check_refs）+ 只读哨兵（`archive/.readonly`）+ 锁文件（`.locks/`，17 个）落地。

### 一致性核查结果

| 检查项 | 结果 | 证据 |
|---|---|---|
| BW-AC-001~015 追溯链（FRD §8.1 ↔ acceptance-criteria spec ↔ 测试） | ✅ 一致 | `bw_ac.rs` 逐条 BW-AC 编号注释 + Gherkin |
| 最新归档变更 `2026-09-04-migration-schema-optimization` R-002（009 refresh 过期索引） | ✅ 一致 | `migrations/{postgres,mysql,sqlite,duckdb}/core/009_refresh_tokens_expiry_index.sql` 四后端齐备 |
| 同上 R-003（010 审计复合索引） | ✅ 一致 | 四后端 `010_audit_logs_composite_index.sql` 齐备；DOWN 脚本恢复原索引 |
| 同上 **R-001（DuckDB 8 条 FOREIGN KEY）** | ❌ **漂移** | spec 验收标准要求 8 条 FK 与 postgres 对齐；commit `73612f4` 因 DuckDB Parser Error **回滚全部 FK**（`migrations/duckdb/core/001_init.sql` 中 `FOREIGN KEY`/`REFERENCES` 均为 0 命中），delta spec 未随之修订 |
| 归档同步标记 | ⚠️ | `meta.json` 为 `"synced": false`，两个 delta spec（database-migration、jwt-refresh）**未合并**进 `specmark/specs/`（无对应目录），spec 索引断链 |
| 变更目录清理 | ⚠️ | `specmark/changes/migration-schema-optimization/` 为空目录残留（与归档目录同名同日） |
| 文档内陈旧数字 | ⚠️ | `server_impl.rs:213/311`、`middleware.rs:300` 注释「15 端点」 vs 实际 16 个 `#[forge]` 路由 |

**结论**：实现与规格在功能层面高度一致（167 项需求 v0.7.0 已全部闭环，P0 缺口清零），但最新一次变更存在「代码先改、spec 未回写」的流程破洞——这正是 specmark converge 阶段应拦截的问题类。

---

## 7. 遗漏风险点与改进建议（按优先级）

### P1（覆盖缺口，建议下一变更立项）

- **R-01 credit 计量模块（76.3%）**：`credit/config.rs` 0%、`meter/storage/cycle` 71–80%。计量涉及计费正确性，建议穷举：超额扣减、周期边界翻转（cycle.rs）、幂次扣减去重、配置缺省值矩阵。
- **R-02 dao 生产后端实现层（34–44%）**：`dbnexus_dao.rs`、`oxcache_impl.rs` 依赖 acceptance 兜底，但错误分支（连接池耗尽、failover 切换、pool-warmup 失败）无对拍测试。建议补充 wiremock/模拟驱动错误注入；并为 CI 引入 `--fail-under-branches` 观察分支覆盖基线。
- **R-03 SSO channel（5.5%）**：`protocol/sso/channel.rs` 146 行几乎无覆盖（通道路由/降级/超时），为协议层最大单点盲区。
- **R-04 bin/auth_server.rs（0%）**：启动装配（TLS、mimalloc、路由挂载）无 smoke test；建议 `cargo run --bin` 级别的启动-探活-关停集成测试（server.rs 已有 HTTP 层，可复用 harness）。

### P2（流程与基建）

- **R-05 specmark 漂移修复**：修订 `R-database-migration-001`（改为「DuckDB 无 FK，应用层保证引用完整性」或降级为 ADR 记录），执行 `scripts/merge_delta_spec.py` 将两个 delta spec 合并进 `specmark/specs/` 并置 `synced: true`，清理 `specmark/changes/` 空目录。回滚决策（DuckDB 不支持 FK）应记入 ADR，避免后续变更再次引入。
- **R-06 注释勘误**：修正「15 端点」→ 16（3 处）。
- **R-07 建立集中式 RTM**：以 BW-AC-001~015 + R-<域>-NNN 为键生成 `docs/traceability-matrix.md`（可用脚本从 specmark specs + `#[test]` 命名约定自动生成），消除纯命名约定追溯的脆弱性。
- **R-08 外部服务测试进 CI**：Redis/Postgres 验收用例在 CI 恒为跳过（探活失败）。建议 GitHub Actions services 容器（redis:7、postgres:16）或 testcontainers 化，使 `GARRISON_TEST_REDIS=1` 路径在 CI 真实执行。

### P3（锦上添花）

- **R-09 feature powerset 抽样**：引入 `cargo-hack --each-feature` / 两两组合（重点：`db-*` × `embedded-migrations`、`protocol-*` × `secure-ct-eq`、`web-*` × `annotation-macros`）纳入 nightly CI job。
- **R-10 examples 测试并入根覆盖率**：`examples/tests/` 103 例不在根 `cargo test` 与 llvm-cov 范围内；可在 CI 增加 `cargo test -p garrison-examples` 与 `cargo llvm-cov --all-contrib`（或 workspace 模式）。
- **R-11 测试 stderr 静音**：masking 非法正则用例改用断言错误类型而非依赖 eprintln 噪音。
- **R-12 observability 低覆盖**：otlp.rs（导出失败静默）、inklog.rs（57.1%）补充 mock exporter 单测。

## 8. 审查方法附注

- 测试统计：`grep -c '#\[tokio::test\]|\[test\]'` 静态计数 + 运行时汇总双重口径。
- 覆盖率：`cargo llvm-cov --features full --fail-under-lines 85 --lcov`（cargo-llvm-cov 0.8.7），lcov 解析脚本按 `SF:`/`LF:`/`LH:` 汇总到模块/文件粒度；报告原件 `/tmp/garrison_lcov.info`。
- specmark 对照：遍历 `specmark/{specs,changes,archive}`，对最新归档变更逐条验证 R-001~R-004 于 `migrations/` 四后端落地情况，并结合 git 历史（`2856273` → `73612f4` → `bcffc84` → `7920082`）交叉核对。

---

## 9. 修复记录（2026-09-04 同日执行，按 §7 优先级）

### 9.1 修复后总指标

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 行覆盖率（llvm-cov，85% 门禁） | 94.51%（59,019/62,450） | **95.46%（61,455/64,380）**，门禁退出码 0 |
| `cargo test --features full` | 4,356 通过 / 0 失败 | **4,490 通过 / 0 失败**（lib 4,093 + acceptance 383 + doc 14） |
| 低于 85% 的文件（≥30 行） | 24 | **15** |
| credit 模块覆盖 | 76.3% | **98.5%** |
| masking 非法正则 stderr 噪音 | 每次全量跑 3 条 | **0** |
| BW-AC 静态追溯（RTM） | 10/15 | **15/15** |

### 9.2 逐项闭环

**P1-R01 credit 模块（76.3% → 98.5%）✅**
新增 105 个单元测试（credit/config.rs、meter.rs、storage.rs、cycle.rs、metrics.rs），覆盖：超额扣减与 remaining 饱和、周期边界、persist_history 异步落库与 SQL 失败非阻塞路径、window 元数据解析错误分支、租户计数器隔离、metrics 文本导出。`credit/config.rs` 0% → 100%，`cycle.rs` 80.3% → 100%。附带修复 1 处 clippy `type_complexity`（测试 DAO 类型别名化）。

**P1-R02 dao 生产后端实现层 ✅**
`dao/oxcache_impl.rs` 43.9% → **92.4%**（31 测：incr/decr/CAS/CAS-greater 全分支、TTL 过期、glob keys、dao-key-index 私有 helper、cache-redis M4 同步原子操作防护、`redis_value_to_strings` 全值型分支）；`dao/dbnexus_dao.rs` 34.0% → **92.8%**（16 测：KV 委托透传、role_hierarchy/social_bindings SQL 读写与错误路径，sqlite 内存池 + 项目迁移建表）。剩余未覆盖行均为 `map_err` 错误格式化闭包（内存后端无法触发，需故障注入）。
**附带发现（已固化测试、待裁决）**：`GarrisonDaoOxcache::keys()` 的 `?` 按字面量处理，与 trait 文档「支持 `*` 与 `?`」不一致（`InMemoryDao::glob_match` 支持 `?`）——建议对齐实现或修订文档。

**P1-R03 SSO channel（5.5% → 94.3%）✅**
`protocol/sso/channel.rs`：4 个 `#[ignore]` 测试改造为运行时探活门控（Redis 可达即真实执行，CI 经 R-08 services 恒可达），新增 3 个无 Redis 依赖的确定性错误路径测试（不可达端口 push → `Err` 前缀 `sso-redis-publish::`、subscribe 连接失败早退、非法 URL 快速失败）+ 1 个非 UTF-8 payload 解析失败分支测试（handler panic 恢复分支一并覆盖）。文件 10 测全过、0 ignored。

**P1-R04 auth_server bin（0% → 68.9%）✅**
`tests/acceptance/server.rs` 新增 `acc_srv_019~021`：通过 `CARGO_BIN_EXE_auth_server` 启动真实二进制做启动 smoke（探测空闲端口注入环境变量 → 内网 health 200 + `data=ok` → 外网按 path-filter 语义断言响应）、缺失/空串 `GARRISON_INTERNAL_API_KEY` 两条 fail-closed 退出码 1 路径。剩余未覆盖行为 `listen()` 返回 Err 后的 bin 内日志行（需注入端口冲突，属启动故障面）。

### P2-R05 specmark 漂移修复 ✅

- 补执行归档时遗漏的 `--sync` 步骤：`merge_delta_spec.py` 将 `database-migration`（4 需求）与 `jwt-refresh`（2 需求）合并进 `specmark/specs/`；
- `R-database-migration-001` 按实现现状修订为「三后端 8 条 FK + DuckDB 不定义（引擎不支持，commit `73612f4` 回滚），应用层保证引用完整性」，附修订说明；归档 delta spec 保持原样（`.readonly` append-only）；
- `meta.json` 的 `synced` 翻转为 `true`（归档脚本的同步簿记字段；这是对单字段的元数据更正，未改写归档内容）；
- 删除 `specmark/changes/migration-schema-optimization/` 空残留目录。
- 注：`specmark/` 目录本身被 `.gitignore` 排除（设计如此，本地变更管理状态），上述修复为工作区状态修复。

**P2-R06 注释勘误 ✅** `server_impl.rs` ×2、`middleware.rs` ×1 的「15 端点/15 个路由」→ 16（`middleware.rs:945` 测试 helper 的「15 个 auth 路由」计数准确，保留）。

**P2-R07 集中式 RTM ✅** 新增 `scripts/gen_traceability_matrix.py`（解析 specmark specs 的 R-ID + BW-AC，扫描 tests/src 静态引用，能力级关键词启发式标注 probable），生成 `docs/traceability-matrix.md`（581 需求条目）。为 BW-AC-011~015 的既有测试补充 ID 追溯注释（annotation_macros.rs 文件头、`acc_repo_009`、`default_factory_registered_via_inventory`、`same_login_id_different_login_type_different_permissions`、`tenant_isolation_..._e2e`），BW-AC 追溯 10/15 → **15/15**。其中 BW-AC-012 注明：FRD 原文的 `AnnotationHandler` trait 在实现中由 `GarrisonLogicFactoryEntry` inventory 注册承载（设计演进记录）。

**P2-R08 CI 外部服务 ✅** `ci.yml` 的 `integration-test` 与 `coverage` 两个 job 增加 `redis:7-alpine` / `postgres:16-alpine` services（健康检查 + 凭据与 `environment.rs` 的 `POSTGRES_URL` 常量对齐）+ `GARRISON_TEST_REDIS=1`，Redis DAO/Postgres 迁移/SSO channel pub/sub 用例在 CI 从「探活跳过」变为真实执行。

**P3-R09/R10 feature 矩阵与 examples ✅** 新增 `.github/workflows/feature-matrix.yml`（每周一 03:00 UTC + 手动触发，不占 PR 关键路径）：`cargo-hack --each-feature` 单 feature 编译 + 10 组定向两两组合（db-*×embedded-migrations、protocol-*×secure-ct-eq、web-*×annotation-macros、auth-server×backend-remote 等）；`cargo test -p garrison-examples --all-features --locked` 补齐 examples 103 个测试的 CI 盲区。

**P3-R11 stderr 噪音 ✅** 根因：`listener/tests.rs` 的 `try_init()` 全局注册 tracing subscriber，使 masking 非法正则 fail-closed 路径的 `tracing::error!` 在全量测试中输出。改为 `tracing::subscriber::with_default` 作用域 subscriber。修复后全量测试 `unclosed character class` 计数 **0**。

**P3-R12 observability ✅** `inklog.rs` 57.1% → **95.2%**（fallback 降级分支、guard/is_degraded、Err 路径均有测试）；`otlp.rs` 100%；`metrics_impl.rs` 93.0%。

### 9.3 残余风险（15 个低于 85% 的文件，多为错误注入面）

| 覆盖率 | 文件 | 说明 |
|---|---|---|
| 68.6% | `protocol/social/service.rs` | 微信/支付宝回调网络故障路径，需 wiremock 级模拟 |
| 68.9% | `bin/auth_server.rs` | `listen()` 返回 Err 的日志行（需端口冲突注入） |
| 77.1% | `web_actix/router.rs` | Actix 路由装配错误分支 |
| 77.8% | `strategy/firewall/geo.rs` | GeoIP 查找失败/库文件损坏路径 |
| 78.6% | `protocol/temp/handler.rs` | temp token 错误分支 |
| 80.0% | `health/checks.rs` | 健康检查依赖故障路径 |
| 80.2% | `secure/sms/rate_limiter.rs` | SMS 限流错误分支 |
| 81.1% | `server/server_impl.rs` | 路由装配/TLS 加载错误分支 |
| 83.3% | `health/warp_routes.rs` | Warp 健康路由 |
| 83.5% | `core/auth/default.rs` | 认证默认实现尾部分支 |
| 83.9% | `dao/defaults.rs` | 默认 DAO 工厂 |
| 84.0% | `dao/in_memory.rs` | glob 匹配边界 |
| <85% | `router/mock.rs`、`web_actix/mock.rs`、`web_warp/mock.rs` | 测试替身，低价值 |

总体行覆盖 95.46% 高于门禁 10.46 pp，以上文件不阻塞 CI，作为后续变更的测试增量候选。

### 9.4 修复执行口径

- 测试代码净增约 3,300 行（credit ~1,150、dao ~1,030、sso channel ~160、acceptance server ~150、其余为注释/配置），生产代码零行为变更（仅测试与注释）。
- 验证：`cargo test --features full` 4,490 通过 / 0 失败；`cargo clippy --features full --tests -- -D warnings` 0 警告；`cargo fmt --check` 通过；`cargo llvm-cov --features full --fail-under-lines 85` 退出码 0。
- 契合 Mimosa 安全约束：测试中仅使用明显占位凭据（`test-only-not-a-real-key`、CI 专用 `garrison:garrison` 测试账号），无真实凭据字面量。

---

## 10. 第二轮修复记录（2026-09-05，§9.3 残余 + keys() 语义对齐）

### 10.1 `GarrisonDaoOxcache::keys()` 通配符语义对齐（§9.2 R-02 附带发现的裁决）

按「对齐实现」方向修复：`matches_pattern` 改为委托 `InMemoryDao::glob_match`
（单一事实来源，O(n+m) 双指针），`keys()` 现支持 `?`（单字符）与任意位置 `*`，
与 `InMemoryDao::keys`、Redis `KEYS` 及 trait 文档承诺一致。

- **调用方审计**：生产调用方（`protocol-apikey` 的 `list_by_namespace`、
  `anomalous-detector-dual`）仅使用「前缀 + 尾部 `*`」pattern，行为不变，无迁移需求。
- 已更新 CHANGELOG `[Unreleased] → Fixed`；原「字面量行为」测试改写为通配语义测试
  （新增 `?` 单字符恰一匹配、中间 `*` 通配/空序列/回溯等 10+ 断言）。
- dao 全量 388 测试通过。

### 10.2 §9.3 残余低覆盖文件提升结果

新增 77 个测试（两轮代理合计），修复后 llvm-cov（`--features full`，与 CI 同命令）：

| 文件 | 修复前 | 修复后 |
|---|---|---|
| `protocol/social/service.rs` | 68.6% | **100%**（UNIQUE 冲突 4 特征行/回查 fail-closed/错误透传） |
| `protocol/temp/handler.rs` | 78.6% | **100%**（4 DAO 错误透传 + listener 广播两分支） |
| `strategy/firewall/geo.rs` | 77.8% | **100%**（经纬度越界/边界/NaN fail-closed/CSV 解析） |
| `health/checks.rs` | 80.0% | **100%**（Healthy/Unhealthy/Degraded 全分支） |
| `health/warp_routes.rs` | 83.3% | **100%** |
| `web_actix/router.rs` | 77.1% | **100%**（interceptor/tenant_resolver 两态） |
| `dao/defaults.rs` | 83.9% | **100%** |
| `dao/in_memory.rs` | 84.0% | **100%**（原子方法矩阵 + `glob_match` 原语直测） |
| `secure/sms/rate_limiter.rs` | 80.2% | **96.9%**（超限回滚/回滚失败仅告警/手机号校验边界） |
| `core/auth/default.rs` | 83.5% | **96.7%**（renew 三段失败注入：旧 token 保持/回滚/A9 契约；余 4 行为 `tracing::error!` 宏展开插桩残留） |
| `server/server_impl.rs` | 81.1% | **91.6%**（真实 bind 失败/validate 失败/oauth2 merge 租户注入；余 13 行为 accept loop 建立后失败的不可确定性分支） |
| `bin/auth_server.rs` | 68.9% | **90.2%**（新增 `acc_srv_022` 端口占用 → 非零退出的启动故障路径） |

**低于 85% 的文件从 15 个降至 3 个**（`router/mock.rs`、`web_actix/mock.rs`、
`web_warp/mock.rs`，均为 §9.3 已注明低价值的测试替身）。总体行覆盖
94.51%（审查基线）→ 95.46%（第一轮修复）→ **95.73%**，`--fail-under-lines 85` 门禁通过。

### 10.3 第二轮终验

- `cargo test --features full`：**4,571 通过 / 0 失败**（lib 4,173 + acceptance 384 + doc 14）
- `cargo clippy --features full --tests`：0 警告；`cargo fmt --check`：通过
- masking stderr 噪音计数：0

### 10.4 本轮新发现（已记录，待产品裁决，未改行为）

1. **`InMemoryDao::compare_and_update_if_greater` 永久键语义（低危）**：对无 TTL 的
   永久键执行该原子操作时会写入 TTL（"升级"为临时键），与 `incr`/`decr` 保留永久
   语义不一致。测试已按现状固化并注释；修复时应同步改断言。
2. **`src/dao/tests.rs` 为孤儿文件**：无任何 `mod tests;` 声明引用（实际编译的是
   `dao/mod.rs` 内联 tests 模块，内容高度重复），建议后续删除或接线。
3. `server/tests.rs` 原有两个「端口占用」测试因未设 api_key 实际被 validate 短路、
   从未触达 bind 失败——本轮已补真实 bind 失败测试，原测试命名/意图待修正。
