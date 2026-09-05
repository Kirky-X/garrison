# Garrison 需求追溯矩阵（RTM）

> 本文件由 `scripts/gen_traceability_matrix.py` 自动生成，请勿手改。
> 追溯链：`specmark/specs/<capability>/spec.md` 的 `R-<cap>-NNN` ↔ `tests/`、`src/` 中的静态引用；
> BW-AC-001~015 为 FRD §8.1 验收标准（需求基线 `docs/origin/`）。
> 「uncovered」仅表示无静态 ID 引用，需人工复核是否存在等价测试。

## abac-cedar

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/abac/engine.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-abac-001` | AbacEngine 核心求值 | uncovered | — |
| `R-abac-002` | 策略管理 CRUD | uncovered | — |
| `R-abac-003` | Decision 枚举复用 | uncovered | — |
| `R-abac-004` | 宏扩展 abac 参数 | uncovered | — |
| `R-abac-005` | ABAC 与 RBAC 共存 | uncovered | — |

## acceptance-criteria

> 关键词启发式：能力名在 5 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/resilience.rs`, `tests/acceptance/session.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-ac-001` | 测试文件创建与命名规范（E-007） | uncovered | — |
| `R-ac-002` | BW-AC-001 OIDC 登录测试（E-007） | uncovered | — |
| `R-ac-003` | BW-AC-002 受保护 API 访问测试（E-007） | uncovered | — |
| `R-ac-004` | BW-AC-003 并发登录踢出测试（E-007） | uncovered | — |
| `R-ac-005` | BW-AC-004 角色校验失败测试（E-007） | uncovered | — |
| `R-ac-006` | BW-AC-005 权限校验失败测试（E-007） | uncovered | — |
| `R-ac-007` | BW-AC-006 oxcache 后端切换测试（E-007） | uncovered | — |
| `R-ac-008` | BW-AC-007 dbnexus 后端切换测试（E-007） | uncovered | — |
| `R-ac-009` | BW-AC-008 oxcache 故障降级测试（E-007） | uncovered | — |
| `R-ac-010` | BW-AC-009 logout 后 Token 失效测试（E-007） | uncovered | — |
| `R-ac-011` | BW-AC-010 连续登录失败封禁测试（E-007） | uncovered | — |
| `R-ac-012` | 测试运行与覆盖（E-007） | uncovered | — |

## account

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-account-001` | execute_inner 流程路由行为不变 | uncovered | — |
| `R-account-002` | execute_login 凭证验证+会话创建行为不变 | uncovered | — |

## account-module

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-account-module-001` | src/account/ 目录结构 | uncovered | — |
| `R-account-module-002` | Cargo.toml feature 新增 | uncovered | — |
| `R-account-module-003` | src/lib.rs 注册 pub mod account | uncovered | — |
| `R-account-module-004` | secure/ 保留密码学原语并删除 password/ 子模块 | uncovered | — |
| `R-account-module-005` | full 聚合特性更新 | uncovered | — |

## annotation-check-api-key

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/migrated/annotation.rs`, `tests/acceptance/migrated/annotation_macros.rs`, `tests/acceptance/migrated/axum.rs`, `tests/acceptance/migrated/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-anno-001` | Annotation::CheckApiKey 枚举变体（E-004） | uncovered | — |
| `R-anno-002` | Annotation::Mode 枚举变体 + Mode enum（E-004） | uncovered | — |
| `R-anno-003` | #[check_api_key] 过程宏（E-004） | uncovered | — |
| `R-anno-004` | router 分发 CheckApiKey 注解（E-004） | uncovered | — |

## annotation-macros

> 关键词启发式：能力名在 3 个源文件命中（test 优先）→ `tests/acceptance/migrated/annotation_macros.rs`, `tests/acceptance/migrated/mod.rs`, `tests/acceptance/web_axum.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-annotation-macros-001` | garrison-macros crate | uncovered | — |
| `R-annotation-macros-002` | check_login 过程宏 | uncovered | — |
| `R-annotation-macros-003` | check_permission 过程宏 | uncovered | — |
| `R-annotation-macros-004` | check_role 过程宏 | uncovered | — |
| `R-annotation-macros-005` | 同步 check 方法 | uncovered | — |

## annotation-oauth2

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/annotation/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-annotation-oauth2-001` | CheckAccessToken 注解变体 | uncovered | — |
| `R-annotation-oauth2-002` | CheckClientToken 注解变体 | uncovered | — |
| `R-annotation-oauth2-003` | 拦截器分发错误处理 | uncovered | — |

## anomalous-detector-dual

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`, `src/dao/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-anomalous-detector-dual-001` | AnomalousLoginRecord 登录记录 | uncovered | — |
| `R-anomalous-detector-dual-002` | AnomalousLoginAnalyzer 定时分析器 | uncovered | — |
| `R-anomalous-detector-dual-003` | burst 登录检测 | uncovered | — |
| `R-anomalous-detector-dual-004` | 异地跳变检测 | uncovered | — |
| `R-anomalous-detector-dual-005` | 设备指纹突变检测 | uncovered | — |
| `R-anomalous-detector-dual-006` | AnomalousLoginDetected 事件 | uncovered | — |
| `R-anomalous-detector-dual-007` | 配置项 | uncovered | — |

## anonymous-session

> 关键词启发式：能力名在 6 个源文件命中（test 优先）→ `tests/acceptance/security.rs`, `src/config/impls.rs`, `src/config/mod.rs`, `src/session/anon.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-anonymous-session-001` | feature gate 注册 | uncovered | — |
| `R-anonymous-session-002` | 配置项 | uncovered | — |
| `R-anonymous-session-003` | get_anon_token_session | uncovered | — |
| `R-anonymous-session-004` | is_anon | uncovered | — |
| `R-anonymous-session-005` | logout_anon | uncovered | — |
| `R-anonymous-session-006` | 模块注册 | uncovered | — |

## apikey-protocol

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/protocol_mixed.rs`, `src/annotation/impls.rs`, `src/annotation/mod.rs`, `src/annotation/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-apikey-protocol-001` | API Key 可配置生命周期 | uncovered | — |
| `R-apikey-protocol-002` | gitleaks 误报消除 | uncovered | — |

## architecture-hardening

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-arch-001` | 统一错误类型 GarrisonError | uncovered | — |
| `R-arch-002` | mod.rs 只放接口 | uncovered | — |
| `R-arch-003` | mod 导入规范 | uncovered | — |
| `R-arch-004` | Mock 代码隔离 | uncovered | — |

## audit-log

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/migrated/tenant_isolation.rs`, `tests/acceptance/resilience.rs`, `tests/acceptance/session.rs`, `src/dao/dbnexus_impl.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-audit-log-001` | AuditEntry 携带正确 tenant_id（CRITICAL bug fix C1） | uncovered | — |
| `R-audit-log-002` | 多租户 strict 模式（H2） | uncovered | — |
| `R-audit-log-003` | 审计日志导出与签名（D4） | uncovered | — |

## auth-flow-dsl

> 关键词启发式：能力名在 5 个源文件命中（test 优先）→ `src/account/authflow/builder.rs`, `src/account/authflow/builtin.rs`, `src/account/authflow/mod.rs`, `src/account/authflow/registry.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-auth-flow-dsl-001` | AuthStep enum 定义 | uncovered | — |
| `R-auth-flow-dsl-002` | AuthCondition enum 定义 | uncovered | — |
| `R-auth-flow-dsl-003` | AuthenticationFlow struct 定义 | uncovered | — |
| `R-auth-flow-dsl-004` | AuthContext struct 定义 | uncovered | — |
| `R-auth-flow-dsl-005` | AuthResult enum 定义 | uncovered | — |
| `R-auth-flow-dsl-006` | FlowBuilder 流式构建 DSL | uncovered | — |
| `R-auth-flow-dsl-007` | FlowRegistry inventory 注册 | uncovered | — |
| `R-auth-flow-dsl-008` | AuthExecutor 定义 | uncovered | — |
| `R-auth-flow-dsl-009` | AuthExecutor::execute 方法逻辑 | uncovered | — |
| `R-auth-flow-dsl-010` | SocialProvider 步骤执行 | uncovered | — |
| `R-auth-flow-dsl-011` | SsoServer 步骤执行 | uncovered | — |
| `R-auth-flow-dsl-012` | 内置 flow 注册 | uncovered | — |
| `R-auth-flow-dsl-013` | account-authflow feature 依赖声明 | uncovered | — |
| `R-auth-flow-dsl-014` | DSL 使用 enum 而非 trait object | uncovered | — |

## auth-password-login

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `tests/acceptance/migrated/login_password.rs`, `src/stp/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-auth-password-login-001` | login_with_password 方法 | uncovered | — |
| `R-auth-password-login-002` | 集成 PasswordHasher + UserRepository | uncovered | — |
| `R-auth-password-login-003` | LoginFailure 事件广播 | uncovered | — |

## authorize-api

> 关键词启发式：能力名在 3 个源文件命中（test 优先）→ `src/core/permission/mod.rs`, `src/lib.rs`, `src/testing/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-authorize-api-001` | AuthRequest 请求对象 | uncovered | — |
| `R-authorize-api-002` | Decision 决策对象 | uncovered | — |
| `R-authorize-api-003` | Authorizer trait | uncovered | — |
| `R-authorize-api-004` | trace_id 自动生成（D5） | uncovered | — |

## benchmark-framework

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-bench-001` | criterion 依赖配置（E-006） | uncovered | — |
| `R-bench-002` | login_flow benchmark（E-006，FRD §7.1 BLK-001） | uncovered | — |
| `R-bench-003` | token_verify_stateless benchmark（E-006，FRD §7.1） | uncovered | — |
| `R-bench-004` | permission_check benchmark（E-006，FRD §7.1 BLK-005） | uncovered | — |
| `R-bench-005` | oxcache_backend_switch benchmark（E-006，FRD §8.2 压测-007） | uncovered | — |
| `R-bench-006` | criterion_group 注册（E-006） | uncovered | — |

## bulwark-logic-trait

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-garrison-logic-trait-001` | GarrisonCore base trait 定义 | uncovered | — |
| `R-garrison-logic-trait-002` | SessionLogic 子 trait 定义 | uncovered | — |
| `R-garrison-logic-trait-003` | PermissionLogic 子 trait 定义 | uncovered | — |
| `R-garrison-logic-trait-004` | TokenLogic 子 trait 定义 | uncovered | — |
| `R-garrison-logic-trait-005` | MfaLogic 子 trait 定义 | uncovered | — |
| `R-garrison-logic-trait-006` | PasswordLogic 子 trait 定义 | uncovered | — |
| `R-garrison-logic-trait-007` | ~~GarrisonLogic deprecated super-trait~~（已删除） | uncovered | — |
| `R-garrison-logic-trait-008` | GarrisonLogicDefault 实现 5 个子 trait | uncovered | — |

## bulwark-util-api

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-util-api-001` | has_permission 公共 API（E-002） | uncovered | — |
| `R-util-api-002` | has_role 公共 API（E-002） | uncovered | — |
| `R-util-api-003` | get_permission_list 公共 API（E-002） | uncovered | — |
| `R-util-api-004` | get_role_list 公共 API（E-002） | uncovered | — |

## cache

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-cache-001` | 缓存可观测性指标 | uncovered | — |
| `R-cache-002` | Bloom Filter 防缓存穿透 | uncovered | — |
| `R-cache-003` | Redis 缓存值压缩 | uncovered | — |

## cache-warmup

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/dao/warmup.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-warmup-001` | 角色权限预热 | uncovered | — |
| `R-warmup-002` | 租户配置预热 | uncovered | — |
| `R-warmup-003` | 空数据库不报错 | uncovered | — |

## concurrent-login

> 关键词启发式：能力名在 5 个源文件命中（test 优先）→ `tests/acceptance/concurrency.rs`, `tests/acceptance/security.rs`, `tests/acceptance/session.rs`, `src/session/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-concurrent-001` | 默认允许并发登录 | uncovered | — |
| `R-concurrent-002` | 默认不共享 Token | uncovered | — |
| `R-concurrent-003` | 默认不限制登录数量 | uncovered | — |
| `R-concurrent-004` | is_share 依赖 is_concurrent | uncovered | — |
| `R-concurrent-005` | is_share=true 复用现有 Token | uncovered | — |
| `R-concurrent-006` | is_concurrent=false 踢出现有会话 | uncovered | — |
| `R-concurrent-007` | is_concurrent=true 保留现有会话 | uncovered | — |
| `R-concurrent-008` | max_login_count 限制并发数 | uncovered | — |
| `R-concurrent-009` | login_token_map 维护 | uncovered | — |

## concurrent-login-policy

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/harness.rs`, `tests/acceptance/protocol_mixed.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-concurrent-login-policy-001` | ReplacedLoginExitMode 枚举 | uncovered | — |
| `R-concurrent-login-policy-002` | NewDevice 模式拒绝新登录 | uncovered | — |
| `R-concurrent-login-policy-003` | OldDevice 模式踢出旧设备 | uncovered | — |
| `R-concurrent-login-policy-004` | OverflowLogoutMode 枚举 | uncovered | — |
| `R-concurrent-login-policy-005` | Logout 模式登出最旧会话 | uncovered | — |
| `R-concurrent-login-policy-006` | Kickout 模式踢出最旧会话 | uncovered | — |
| `R-concurrent-login-policy-007` | Replaced 模式顶替最旧会话 | uncovered | — |

## config

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-config-001` | validate 校验规则不变 | uncovered | — |
| `R-config-002` | validate 错误消息格式不变 | uncovered | — |

## constants

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/session.rs`, `src/account/credential/backup_code.rs`, `src/account/credential/mod.rs`, `src/account/lockout/strategy.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-constants-001` | DaoKeyPrefix 枚举 | uncovered | — |
| `R-constants-002` | EventReason 枚举 | uncovered | — |
| `R-constants-003` | 替换源码中硬编码字符串 | uncovered | — |

## context

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/annotation.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-context-001` | get_token 三级提取优先级不变 | uncovered | — |
| `R-context-002` | actix 双实现差异保留 | uncovered | — |

## core-auth-extensions

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`, `tests/acceptance/migrated/login_password.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-auth-extensions-001` | switch_to 身份切换 | uncovered | — |
| `R-auth-extensions-002` | switch_to 审计日志 | uncovered | — |
| `R-auth-extensions-003` | renew_to_equivalent Token 置换 | uncovered | — |
| `R-auth-extensions-004` | renew_to_equivalent 原子性（VULN-0020 修复后） | uncovered | — |

## cors

> 关键词启发式：能力名在 7 个源文件命中（test 优先）→ `tests/acceptance/web_axum.rs`, `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-cors-001` | CorsConfig 配置 | uncovered | — |
| `R-cors-002` | Origin 匹配逻辑 | uncovered | — |
| `R-cors-003` | Preflight (OPTIONS) 处理 | uncovered | — |
| `R-cors-004` | 实际请求 CORS 头注入 | uncovered | — |
| `R-cors-005` | validate 校验 | uncovered | — |

## credential-model

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/account/authflow/executor.rs`, `src/account/credential/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-credential-model-001` | Credential trait 与 CredentialType 定义 | uncovered | — |
| `R-credential-model-002` | CredentialModel struct 定义 | uncovered | — |
| `R-credential-model-003` | CredentialRepository trait 定义 | uncovered | — |
| `R-credential-model-004` | PasswordCredential 实现与 PasswordHasher 迁移 | uncovered | — |
| `R-credential-model-005` | TotpCredential 实现 | uncovered | — |
| `R-credential-model-006` | DaoCredentialRepository 实现 | uncovered | — |
| `R-credential-model-007` | 破坏性迁移 secure-password → account-credential | uncovered | — |
| `R-credential-model-008` | account-credential-zeroize feature 集成 | uncovered | — |

## csrf

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/protocol_oauth2.rs`, `tests/acceptance/security.rs`, `tests/acceptance/web_axum.rs`, `src/account/authflow/executor.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-csrf-001` | CSRF Token 生成 | uncovered | — |
| `R-csrf-002` | CSRF Token 校验 | uncovered | — |
| `R-csrf-003` | CsrfConfig 配置 | uncovered | — |
| `R-csrf-004` | garrison_csrf_middleware | uncovered | — |

## dao-bulwark-dao

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-dao-garrison-dao-001` | set_permanent 方法 | uncovered | — |
| `R-dao-garrison-dao-002` | get_timeout 方法 | uncovered | — |
| `R-dao-garrison-dao-003` | keys 方法（默认返回 NotImplemented，v0.5.0+ 实现） | uncovered | — |
| `R-dao-garrison-dao-004` | rename 方法 | uncovered | — |

## dao-keys-performance

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-dao-keys-performance-001` | keys() 已知限制文档强化 | uncovered | — |
| `R-dao-keys-performance-002` | A-010 评估决策报告 | uncovered | — |
| `R-dao-keys-performance-003` | keys() 默认实现保持不变 | uncovered | — |

## dao-redis-modes

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-dao-redis-modes-001` | RedisDeploymentMode 枚举 | uncovered | — |
| `R-dao-redis-modes-002` | RedisConfig 结构 | uncovered | — |
| `R-dao-redis-modes-003` | with_redis_config builder | uncovered | — |

## database

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/environment.rs`, `src/dao/dbnexus_dao.rs`, `src/dao/dbnexus_impl.rs`, `src/dao/macros.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-database-001` | 连接池健康检查 | uncovered | — |
| `R-database-002` | SeaORM 类型桥接 | uncovered | — |
| `R-database-003` | 连接池预热 | uncovered | — |
| `R-database-004` | 故障转移 | uncovered | — |
| `R-database-005` | 数据库可观测性聚合 | uncovered | — |

## database-migration

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/environment.rs`, `src/dao/dbnexus_dao.rs`, `src/dao/dbnexus_impl.rs`, `src/dao/macros.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-database-migration-001` | 关系表外键约束完整性 | uncovered | — |
| `R-database-migration-002` | refresh_tokens 过期索引 | uncovered | — |
| `R-database-migration-003` | 审计日志三列覆盖索引 | uncovered | — |
| `R-database-migration-004` | 时间字段约定文档化 | uncovered | — |

## dependency-optimization

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/health/mock.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-dep-001` | oxcache 替换 moka 直接依赖 | uncovered | — |
| `R-dep-002` | limiteron 替换手写限速 | uncovered | — |
| `R-dep-003` | inklog 替换审计日志 | uncovered | — |
| `R-dep-004` | sdforge + trait-kit 集成 | uncovered | — |
| `R-dep-005` | 依赖版本格式 x.x | uncovered | — |

## device-binding

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/session.rs`, `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-device-binding-001` | DeviceBindingPolicy trait | uncovered | — |
| `R-device-binding-002` | StrictBinding 策略 | uncovered | — |
| `R-device-binding-003` | LooseBinding 策略 | uncovered | — |
| `R-device-binding-004` | Disabled 策略 | uncovered | — |
| `R-device-binding-005` | login 流程集成 | uncovered | — |
| `R-device-binding-006` | 配置项 | uncovered | — |

## device-mgmt

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/environment.rs`, `tests/acceptance/migrated/jwt_modes.rs`, `tests/acceptance/migrated/plugin_listener.rs`, `tests/acceptance/protocol_jwt.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-device-001` | TokenSession 存储 IP 和 User-Agent | uncovered | — |
| `R-device-002` | LoginParams struct 创建 + login 签名变更 | uncovered | — |
| `R-device-003` | 设备指纹生成 | uncovered | — |
| `R-device-004` | login 自动生成设备指纹 | uncovered | — |
| `R-device-005` | 查询用户设备列表 | uncovered | — |
| `R-device-006` | 踢出指定设备会话 | uncovered | — |
| `R-device-007` | DeviceSession 结构 | uncovered | — |

## disable-repository

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/common/harness.rs`, `src/backend/embedded.rs`, `src/manager/builder.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-disable-repository-001` | DisableEntry 数据结构 | uncovered | — |
| `R-disable-repository-002` | DisableRepository trait | uncovered | — |
| `R-disable-repository-003` | DefaultDisableRepository 实现 | uncovered | — |
| `R-disable-repository-004` | 阶梯封禁 | uncovered | — |
| `R-disable-repository-005` | MfaLogic::check_disable 修改 | uncovered | — |
| `R-disable-repository-006` | GarrisonManager 集成 | uncovered | — |

## dynamic-active-timeout

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/resilience.rs`, `tests/acceptance/server.rs`, `src/backend/tests.rs`, `src/core/auth/default.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-dynamic-active-timeout-001` | feature gate 注册 | uncovered | — |
| `R-dynamic-active-timeout-002` | TokenSession 字段 | uncovered | — |
| `R-dynamic-active-timeout-003` | set_active_timeout 方法 | uncovered | — |
| `R-dynamic-active-timeout-004` | check_active_timeout 优先级 | uncovered | — |

## e2e-authz-boundary

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-e2e-authz-boundary-001` | 无 token 请求拒绝 | uncovered | — |
| `R-e2e-authz-boundary-002` | kickout token 失效 | uncovered | — |
| `R-e2e-authz-boundary-003` | 跨租户 token 隔离 | uncovered | — |
| `R-e2e-authz-boundary-004` | 普通用户权限边界 | uncovered | — |
| `R-e2e-authz-boundary-005` | refresh 后旧 token 失效（过期 token 边界） | uncovered | — |
| `R-e2e-authz-boundary-006` | 角色不足拒绝 | uncovered | — |
| `R-e2e-authz-boundary-007` | disabled token 拒绝 | uncovered | — |
| `R-e2e-authz-boundary-008` | 匿名 token 越权拒绝 | uncovered | — |

## e2e-error-edge

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-e2e-error-edge-001` | 无效 token 8 种类型全拒绝 | uncovered | — |
| `R-e2e-error-edge-002` | 畸形 body 6 种类型全拒绝 | uncovered | — |
| `R-e2e-error-edge-003` | 超长字段拒绝 | uncovered | — |
| `R-e2e-error-edge-004` | login_id 长度边界 | uncovered | — |
| `R-e2e-error-edge-005` | 并发同 token refresh | uncovered | — |
| `R-e2e-error-edge-006` | refresh 链 50 次 | uncovered | — |

## e2e-functional

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-e2e-functional-001` | auth_server bin 真实进程部署 | uncovered | — |
| `R-e2e-functional-002` | 远程模式 RemoteContext 自动检测 | uncovered | — |
| `R-e2e-functional-003` | 11 端点 happy path 全覆盖 | uncovered | — |

## error

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-error-001` | miette Diagnostic 实现（M5） | uncovered | — |
| `R-error-002` | 响应体大小限制（P2.2） | uncovered | — |
| `R-error-003` | 错误不泄露敏感信息（P2.3 联动） | uncovered | — |

## error-exceptions

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-error-001` | DisableService 错误变体（E-003） | uncovered | — |
| `R-error-002` | NotSafe 错误变体（E-003） | uncovered | — |
| `R-error-003` | InvalidStateTransition 错误变体（E-005 预留） | uncovered | — |
| `R-error-004` | BW-ERR-009~012 错误码常量（E-003） | uncovered | — |
| `R-error-005` | check_disable / check_safe 联动专用异常（E-003 联动） | uncovered | — |

## feature-infrastructure

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-feature-001` | web-waf 废弃与 firewall-waf 统一 | uncovered | — |
| `R-feature-002` | 协议域命名一致性 | uncovered | — |
| `R-feature-003` | 空 Feature 聚合 | uncovered | — |
| `R-feature-004` | 名称缩短 | uncovered | — |
| `R-feature-005` | 聚合 Preset 新增 | uncovered | — |
| `R-feature-006` | 聚合 Feature 同步更新 | uncovered | — |
| `R-feature-007` | 内部 Feature 标记 | uncovered | — |

## firewall-maxminddb

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/strategy/firewall/geo.rs`, `src/strategy/firewall/geo/maxminddb.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-firewall-maxminddb-001` | firewall-maxminddb feature | uncovered | — |
| `R-firewall-maxminddb-002` | MaxMindDbGeoLookup 实现 | uncovered | — |
| `R-firewall-maxminddb-003` | MaxMindDbCountryLookup 实现 | uncovered | — |
| `R-firewall-maxminddb-004` | 集成测试 | uncovered | — |
| `R-firewall-maxminddb-005` | 测试数据下载脚本 | uncovered | — |

## firewall-waf

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/web_axum.rs`, `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-firewall-waf-001` | WafContext 请求内容快照 | uncovered | — |
| `R-firewall-waf-002` | WafVerdict 校验结果 | uncovered | — |
| `R-firewall-waf-003` | WafHook trait | uncovered | — |
| `R-firewall-waf-004` | WafHookChain 链式执行 | uncovered | — |
| `R-firewall-waf-005` | 9 个 Hook 实现 | uncovered | — |
| `R-firewall-waf-006` | axum middleware 适配器 | uncovered | — |
| `R-firewall-waf-007` | 配置项 | uncovered | — |
| `R-firewall-waf-008` | WAF 绕过测试覆盖 | uncovered | — |

## framework-enhancement

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-framework-001` | 日志压缩 | uncovered | — |
| `R-framework-002` | API 文档自动生成 | uncovered | — |
| `R-framework-003` | 模块级健康上报与构建诊断 | uncovered | — |
| `R-framework-004` | 流控互补能力 | uncovered | — |
| `R-framework-005` | 配置增强能力 | uncovered | — |

## frontend-separation

> 关键词启发式：能力名在 7 个源文件命中（test 优先）→ `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`, `src/context/helpers.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-frontend-001` | 默认 Cookie 模式 | uncovered | — |
| `R-frontend-002` | 环境变量覆盖 | uncovered | — |
| `R-frontend-003` | 分离模式日志提示 | uncovered | — |

## ghost-code-cleanup

> 关键词启发式：能力名在 6 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/protocol_mixed.rs`, `tests/acceptance/rbac.rs`, `tests/acceptance/server.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-gc-001` | 移除 oidc.rs 废弃 http_client() 方法 | uncovered | — |

## http-logging

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/annotation.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-http-logging-001` | RecordingClient 抓包所有 HTTP 交互 | uncovered | — |
| `R-http-logging-002` | RequestSnapshot 保存请求快照 | uncovered | — |
| `R-http-logging-003` | make_recording_client 工厂函数 | uncovered | — |
| `R-http-logging-004` | log_analyzer 统计汇总 | uncovered | — |
| `R-http-logging-005` | e2e_analyze.py 最终报告 | uncovered | — |

## industrial-standard

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-is-001` | NIST SP 800-63B 密码策略合规 | uncovered | — |
| `R-is-002` | Tracing #[instrument] span 创建 | uncovered | — |
| `R-is-003` | gRPC tonic-health 健康检查 | uncovered | — |
| `R-is-004` | ABAC 决策缓存 | uncovered | — |

## jwt-refresh

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `tests/acceptance/protocol_jwt.rs`, `src/protocol/jwt/refresh.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-jwt-refresh-001` | 过期 token 清理方法 | uncovered | — |
| `R-jwt-refresh-002` | 清理安全性 | uncovered | — |

## jwt-revocation

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/migrated/jwt_modes.rs`, `tests/acceptance/protocol_jwt.rs`, `tests/acceptance/resilience.rs`, `src/config/impls.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-revocation-001` | JWT 黑名单写入 | uncovered | — |
| `R-revocation-002` | Stateless 模式黑名单检查 | uncovered | — |
| `R-revocation-003` | JWT 撤销向后兼容 | uncovered | — |

## listener-events-extend

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/login_password.rs`, `tests/acceptance/migrated/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-listener-events-001` | 8 个新事件变体 | uncovered | — |
| `R-listener-events-002` | broadcast 集成 | uncovered | — |
| `R-listener-events-003` | 监听器接收 | uncovered | — |

## login-id-migration

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-login-id-migration-001` | trait 签名使用 `&str`（原计划 `impl Into<LoginId>`） | uncovered | — |
| `R-login-id-migration-002` | `get_login_id()` 返回 `Option<String>` | uncovered | — |
| `R-login-id-migration-003` | `verify_token()` 返回 `String` | uncovered | — |
| `R-login-id-migration-004` | 移除 `GarrisonUtil::login_id_to_i64` | uncovered | — |
| `R-login-id-migration-005` | `GarrisonInterface` 4 方法参数使用 `&str` | uncovered | — |

## login-id-type

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-login-id-type-001` | LoginId enum 定义 | uncovered | — |
| `R-login-id-type-002` | as_str / as_i64 转换 | uncovered | — |
| `R-login-id-type-003` | 向后兼容迁移 | uncovered | — |

## login-token-map-persistence

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/config/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-login-token-map-persistence-001` | feature gate 注册 | uncovered | — |
| `R-login-token-map-persistence-002` | 配置项 | uncovered | — |
| `R-login-token-map-persistence-003` | rebuild_login_token_map | uncovered | — |
| `R-login-token-map-persistence-004` | add_login_token_persistent | uncovered | — |
| `R-login-token-map-persistence-005` | remove_login_token_persistent | uncovered | — |
| `R-login-token-map-persistence-006` | create/logout 集成 | uncovered | — |

## login-type-multi-account

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/stp/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-login-type-001` | GarrisonInterface 扩展 | uncovered | — |
| `R-login-type-002` | 多账号隔离 | uncovered | — |
| `R-login-type-003` | with_login_type builder | uncovered | — |

## manager-explicit

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/manager/builder.rs`, `src/manager/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-manager-explicit-001` | Manager struct 构造 | uncovered | — |
| `R-manager-explicit-002` | Manager::authorize 方法 | uncovered | — |
| `R-manager-explicit-003` | Manager 生命周期 | uncovered | — |

## microservice-architecture

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-msa-001` | AuthBackend trait 定义 | uncovered | — |
| `R-msa-002` | BackendEmbedded 实现 | uncovered | — |
| `R-msa-003` | BackendRemote 实现 | uncovered | — |
| `R-msa-004` | GarrisonAuthServer 双端口 | uncovered | — |
| `R-msa-005` | GarrisonUtil 委托 AuthBackend | uncovered | — |
| `R-msa-006` | Feature gate 隔离 | uncovered | — |

## module-structure

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/manager/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-module-structure-001` | examples/src/ 子模块分组 | uncovered | — |
| `R-module-structure-002` | examples/src/bin/ 调用路径更新 | uncovered | — |
| `R-module-structure-003` | examples/tests/ use 路径更新 | uncovered | — |
| `R-module-structure-004` | tests/ 子模块分组 | uncovered | — |
| `R-module-structure-005` | tests/common/ 保持原位 | uncovered | — |

## multi-tenant-credit-metering

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`, `tests/acceptance/migrated/jwt_modes.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-credit-001` | CreditCycle 配额周期模型 | uncovered | — |
| `R-credit-002` | CreditSchedule 资源权重映射 | uncovered | — |
| `R-credit-003` | CreditConfig 配置 | uncovered | — |
| `R-credit-004` | CreditMeter 核心引擎 | uncovered | — |
| `R-credit-005` | KV 热数据存储层 | uncovered | — |
| `R-credit-006` | SQL 冷数据持久化 | uncovered | — |
| `R-credit-007` | 事件变体扩展 | uncovered | — |
| `R-credit-008` | CreditMeteringListener 可选自动扣减 | uncovered | — |
| `R-credit-009` | Feature Gate + 模块导出 | uncovered | — |
| `R-credit-010` | 错误处理 | uncovered | — |

## mysql-backend

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/environment.rs`, `tests/acceptance/security.rs`, `tests/acceptance/storage.rs`, `src/config/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-mysql-backend-001` | db-mysql feature 启用 | uncovered | — |
| `R-mysql-backend-002` | testcontainers 集成测试 | uncovered | — |
| `R-mysql-backend-003` | 三后端行为等价 | uncovered | — |

## oauth-2-1-upgrade

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`, `tests/acceptance/migrated/strategy_registry.rs`, `tests/acceptance/protocol_oauth2.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-oauth-2-1-001` | PKCE 支持方法 | uncovered | — |
| `R-oauth-2-1-002` | code_challenge 方法 | uncovered | — |
| `R-oauth-2-1-003` | 弃用 implicit grant | uncovered | — |

## oauth2

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`, `tests/acceptance/migrated/strategy_registry.rs`, `tests/acceptance/protocol_oauth2.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-oauth2-001` | PKCE 错误处理不泄露敏感信息（H1） | uncovered | — |
| `R-oauth2-002` | redirect_uri 校验（P2.3） | uncovered | — |
| `R-oauth2-003` | Keycloak PKCE 流程（D2） | uncovered | — |

## oauth2-server

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/protocol_oauth2.rs`, `tests/acceptance/server.rs`, `src/lib.rs`, `src/oauth2_server/authorize.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-oauth2-001` | OAuth2 客户端管理 | uncovered | — |
| `R-oauth2-002` | /oauth2/authorize 端点 | uncovered | — |
| `R-oauth2-003` | /oauth2/token 端点 | uncovered | — |
| `R-oauth2-004` | /oauth2/revoke 端点 | uncovered | — |
| `R-oauth2-005` | /oauth2/introspect 端点 | uncovered | — |
| `R-oauth2-006` | PKCE 强制 | uncovered | — |

## oxcache-decision-sync

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-oxcache-decision-sync-001` | oxcache 升级到 0.3.3 | uncovered | — |
| `R-oxcache-decision-sync-002` | A-010 决策文档更新 | uncovered | — |
| `R-oxcache-decision-sync-003` | src/dao/mod.rs 注释更新 | uncovered | — |
| `R-oxcache-decision-sync-004` | A-009 决策不变 | uncovered | — |

## oxcache-sync-api

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `tests/acceptance/environment.rs`, `src/dao/oxcache_impl.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-oxcache-sync-api-001` | _sync API 性能约束文档化 | uncovered | — |
| `R-oxcache-sync-api-002` | A-009 评估决策报告 | uncovered | — |
| `R-oxcache-sync-api-003` | 不修改 _sync 调用代码 | uncovered | — |

## p0-blocking-fixes

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-p0-001` | PCI-DSS 银行卡脱敏 first 6 + last 4 | uncovered | — |
| `R-p0-002` | OAuth2 authorize user_id 从 principal 提取 | uncovered | — |
| `R-p0-003` | Audit IP/UA 从 request_context 填充 | uncovered | — |
| `R-p0-004` | Metrics /metrics 端点 | uncovered | — |
| `R-p0-005` | HTTPS/TLS 终止 | uncovered | — |

## password-policy

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/account/policy/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-password-policy-001` | PasswordPolicyRule trait 定义 | uncovered | — |
| `R-password-policy-002` | PolicyContext struct 定义 | uncovered | — |
| `R-password-policy-003` | PasswordPolicyEngine 与 ErrorMode 定义 | uncovered | — |
| `R-password-policy-004` | PolicyError 定义 | uncovered | — |
| `R-password-policy-005` | 6 个核心规则实现 | uncovered | — |
| `R-password-policy-006` | 6 个扩展规则实现 | uncovered | — |
| `R-password-policy-007` | account-policy feature 依赖关系 | uncovered | — |

## pentest-attack

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `tests/acceptance/resilience.rs`, `tests/acceptance/security.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-pentest-attack-001` | SQL 注入防护 | uncovered | — |
| `R-pentest-attack-002` | XSS 防护 | uncovered | — |
| `R-pentest-attack-003` | CSRF 防护 | uncovered | — |
| `R-pentest-attack-004` | 认证绕过防护 | uncovered | — |
| `R-pentest-attack-005` | 权限提升防护 | uncovered | — |
| `R-pentest-attack-006` | 会话劫持防护 | uncovered | — |
| `R-pentest-attack-007` | 暴力破解防护 | uncovered | — |
| `R-pentest-attack-008` | PentestFinding 报告结构 | uncovered | — |

## perf-load

> 关键词启发式：能力名在 5 个源文件命中（test 优先）→ `tests/acceptance/concurrency.rs`, `src/manager/tests.rs`, `src/oauth2_server/token.rs`, `src/protocol/social/alipay.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-perf-load-001` | LoadRunner 自实现压测客户端 | uncovered | — |
| `R-perf-load-002` | login 端点性能基线 | uncovered | — |
| `R-perf-load-003` | check-login 端点性能基线 | uncovered | — |
| `R-perf-load-004` | check-permission 端点性能基线 | uncovered | — |

## permission-registry

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/core/permission/registry.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-permission-registry-001` | PermissionRegistry 注册与校验 | uncovered | — |
| `R-permission-registry-002` | 编译期注册支持 | uncovered | — |
| `R-permission-registry-003` | 启动时 confusable 扫描（L6 联动） | uncovered | — |

## protocol

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/jwt_modes.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-protocol-001` | SAML Response XML 解析行为不变 | uncovered | — |
| `R-protocol-002` | SAML 解析命名空间检查不变 | uncovered | — |

## protocol-apikey-namespace

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/jwt_modes.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-apikey-namespace-001` | ApiKeyInfo namespace 字段 | uncovered | — |
| `R-apikey-namespace-002` | key 格式变更 | uncovered | — |
| `R-apikey-namespace-003` | list_by_namespace 方法 | uncovered | — |
| `R-apikey-namespace-004` | namespace 隔离 | uncovered | — |

## protocol-jwt-modes

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `tests/acceptance/migrated/jwt_modes.rs`, `src/stp/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-jwt-modes-001` | JwtMode enum | uncovered | — |
| `R-jwt-modes-002` | Stateless 模式行为 | uncovered | — |
| `R-jwt-modes-003` | Mixin 模式行为 | uncovered | — |
| `R-jwt-modes-004` | Simple 模式行为 | uncovered | — |
| `R-jwt-modes-005` | with_jwt_mode builder | uncovered | — |

## protocol-sso-federation

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/migrated/jwt_modes.rs`, `tests/acceptance/migrated/keycloak_oidc.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-sso-federation-001` | SAML 2.0 数据结构 | uncovered | — |
| `R-sso-federation-002` | SamlProvider trait | uncovered | — |
| `R-sso-federation-003` | OIDC 数据结构 | uncovered | — |
| `R-sso-federation-004` | OidcProvider trait | uncovered | — |
| `R-sso-federation-005` | RedisPubSubSsoChannel | uncovered | — |

## protocol-sso-toctou

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/dao/mod.rs`, `src/dao/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-sso-toctou-001` | get_and_delete 原子方法 | uncovered | — |
| `R-sso-toctou-002` | validate_ticket 原子化 | uncovered | — |
| `R-sso-toctou-003` | oxcache 原子实现 | uncovered | — |

## quality-enhancement

> 关键词启发式：能力名在 4 个源文件命中（test 优先）→ `src/annotation/tests.rs`, `src/health/tests.rs`, `src/strategy/alert/tests.rs`, `src/strategy/rate_limiter_backend.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-qual-001` | 测试覆盖率 95%+ | uncovered | — |
| `R-qual-002` | 零 clippy 告警 | uncovered | — |
| `R-qual-003` | 零 doc 告警 | uncovered | — |
| `R-qual-004` | 特性组合测试 | uncovered | — |
| `R-qual-005` | cargo-audit 零漏洞 | uncovered | — |
| `R-qual-006` | 修复所有 medium/low 问题 | uncovered | — |

## rate-limiter

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `src/config/mod.rs`, `src/config/tests.rs`, `src/oauth2_server/token.rs`, `src/secure/sms/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-rate-limiter-001` | 令牌桶突发容量 | uncovered | — |
| `R-rate-limiter-002` | 令牌桶补充 | uncovered | — |
| `R-rate-limiter-003` | 多 key 隔离 | uncovered | — |
| `R-rate-limiter-004` | 批量获取 | uncovered | — |

## redis-rate-limiter

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/environment.rs`, `tests/acceptance/resilience.rs`, `src/account/credential/backup_code.rs`, `src/account/lockout/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-redis-ratelimit-001` | RateLimiterBackend trait | uncovered | — |
| `R-redis-ratelimit-002` | Redis Lua 脚本 | uncovered | — |
| `R-redis-ratelimit-003` | RedisRateLimiter struct | uncovered | — |
| `R-redis-ratelimit-004` | RateLimitBackend 配置 | uncovered | — |
| `R-redis-ratelimit-005` | feature gate | uncovered | — |

## refresh-rotation

> 关键词启发式：能力名在 3 个源文件命中（test 优先）→ `tests/acceptance/protocol_jwt.rs`, `src/constants/dao_keys.rs`, `src/oauth2_server/token.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-refresh-001` | SessionLogic trait 新增 refresh 方法 | uncovered | — |
| `R-refresh-002` | GarrisonUtil 实现 refresh（db-sqlite feature） | uncovered | — |
| `R-refresh-003` | 非 db-sqlite feature 返回 NotImplemented | uncovered | — |
| `R-refresh-004` | 已撤销 refresh_token 返回 TokenRevoked | uncovered | — |
| `R-refresh-005` | hash chain 完整性 | uncovered | — |

## repository-layer

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/authentication.rs`, `tests/acceptance/environment.rs`, `tests/acceptance/migrated/login_password.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-repository-layer-001` | UserRepository trait | uncovered | — |
| `R-repository-layer-002` | 9 个 Repository trait 定义 | uncovered | — |
| `R-repository-layer-003` | SqliteRepository 实现 | uncovered | — |
| `R-repository-layer-004` | 多租户过滤 | uncovered | — |
| `R-repository-layer-005` | SqliteRepository::create 生成 UUID v4（CRITICAL bug fix C2） | uncovered | — |
| `R-repository-layer-006` | RBAC 实体模型（M1） | uncovered | — |
| `R-repository-layer-007` | UserDevice 实体（M2） | uncovered | — |

## response-token

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/migrated/annotation.rs`, `tests/acceptance/migrated/annotation_macros.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-response-token-001` | task_local 操作函数 | uncovered | — |
| `R-response-token-002` | 配置项 | uncovered | — |
| `R-response-token-003` | middleware 响应 Token 写入 | uncovered | — |

## safe-auth

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/stp/mfa.rs`, `src/stp/safe.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-safe-auth-001` | TokenSession 新增 safe_services 字段 | uncovered | — |
| `R-safe-auth-002` | MfaLogic 新增 open_safe/is_safe/close_safe | uncovered | — |
| `R-safe-auth-003` | open_safe 默认实现 | uncovered | — |
| `R-safe-auth-004` | is_safe 默认实现 | uncovered | — |
| `R-safe-auth-005` | close_safe 默认实现 | uncovered | — |
| `R-safe-auth-006` | check_safe 默认实现修改 | uncovered | — |

## safe-defaults

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/core/permission/decision.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-safe-defaults-001` | DecisionReason 新增 Forbid 变体 | uncovered | — |
| `R-safe-defaults-002` | DecisionCombinator 组合规则 | uncovered | — |
| `R-safe-defaults-003` | authorize() Forbid 支持 | uncovered | — |
| `R-safe-defaults-004` | check_permission() 向后兼容 | uncovered | — |

## secure

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/migrated/login_password.rs`, `tests/acceptance/security.rs`, `src/account/credential/mod.rs`, `src/account/credential/password.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-secure-001` | XSS 事件处理器过滤行为不变 | uncovered | — |
| `R-secure-002` | XSS 危险 URI 过滤行为不变 | uncovered | — |
| `R-secure-003` | HTTP Digest 参数解析行为不变 | uncovered | — |

## secure-password

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `tests/acceptance/migrated/login_password.rs`, `src/account/credential/password.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-secure-password-001` | PasswordHasher trait | uncovered | — |
| `R-secure-password-002` | Argon2Hasher 实现 | uncovered | — |
| `R-secure-password-003` | BcryptHasher 实现 | uncovered | — |
| `R-secure-password-004` | PasswordVerifier 自动识别 | uncovered | — |
| `R-secure-password-005` | Argon2 预分配输出缓冲区（H4） | uncovered | — |
| `R-secure-password-006` | password 参数 zeroize（P2.1） | uncovered | — |

## security-alert

> 关键词启发式：能力名在 6 个源文件命中（test 优先）→ `src/stp/default_impl.rs`, `src/stp/mod.rs`, `src/stp/session.rs`, `src/strategy/alert/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-security-alert-001` | SecurityAlertEvent 枚举 | uncovered | — |
| `R-security-alert-002` | AlertListener trait | uncovered | — |
| `R-security-alert-003` | AnomalyDetector trait | uncovered | — |
| `R-security-alert-004` | AlertListenerManager | uncovered | — |
| `R-security-alert-005` | login/check_login 集成 | uncovered | — |
| `R-security-alert-006` | feature gate | uncovered | — |

## security-audit

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/protocol/sso/saml.rs`, `src/stp/default_impl.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-sec-001` | tiangang SAST 零 CRITICAL | uncovered | — |
| `R-sec-002` | diting 代码审查零 HIGH/MEDIUM/LOW | uncovered | — |
| `R-sec-003` | 输入消毒 | uncovered | — |
| `R-sec-004` | 重定向策略 | uncovered | — |
| `R-sec-005` | 响应体大小限制 | uncovered | — |
| `R-sec-006` | zeroize 敏感数据 | uncovered | — |
| `R-sec-007` | security.md 10 维度检查 | uncovered | — |

## security-confusable

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/migrated/annotation_macros.rs`, `tests/acceptance/resilience.rs`, `tests/acceptance/security.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-security-confusable-001` | check_confusable 函数 | uncovered | — |
| `R-security-confusable-002` | ConfusableWarning 结构 | uncovered | — |
| `R-security-confusable-003` | 启动时扫描 PermissionRegistry（M3 联动） | uncovered | — |

## sensitive-data-masking

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/security.rs`, `src/account/policy/rules.rs`, `src/config/mod.rs`, `src/config/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-masking-001` | 手机号脱敏 | uncovered | — |
| `R-masking-002` | 身份证号脱敏 | uncovered | — |
| `R-masking-003` | 邮箱脱敏 | uncovered | — |
| `R-masking-004` | 银行卡号脱敏 | uncovered | — |
| `R-masking-005` | JSON 字段脱敏 | uncovered | — |

## server-security

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/authentication.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/environment.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-server-security-001` | 客户端 IP 自动提取 | uncovered | — |
| `R-server-security-002` | IP 提取与设备指纹联动 | uncovered | — |
| `R-server-security-003` | SAML XXE 安全文档化 | uncovered | — |

## session-hover

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/resilience.rs`, `tests/common/harness.rs`, `src/config/impls.rs`, `src/config/mod.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-hover-001` | 默认不启用 | uncovered | — |
| `R-hover-002` | 活跃时间更新 | uncovered | — |
| `R-hover-003` | 悬停踢出 | uncovered | — |
| `R-hover-004` | 活跃会话不受影响 | uncovered | — |

## session-key

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/core/auth/tests.rs`, `src/protocol/social/wechat.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-session-key-001` | Account-Session Key 格式（E-001） | uncovered | — |
| `R-session-key-002` | Token-Session Key 格式（E-001） | uncovered | — |
| `R-session-key-003` | 残留硬编码清理（E-001） | uncovered | — |

## session-kickout-device

> 关键词启发式：能力名在 2 个源文件命中（test 优先）→ `src/session/mod.rs`, `src/session/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-session-kickout-001` | kickout_by_device 方法 | uncovered | — |
| `R-session-kickout-002` | Kickout 事件广播 | uncovered | — |
| `R-session-kickout-003` | account session 维护 | uncovered | — |

## session-lifecycle

> 关键词启发式：能力名在 3 个源文件命中（test 优先）→ `src/config/tests.rs`, `src/core/auth/default.rs`, `src/session/impl.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-session-lifecycle-001` | SessionExpiryListener trait | uncovered | — |
| `R-session-lifecycle-002` | GarrisonSession 持有 expiry_listeners | uncovered | — |
| `R-session-lifecycle-003` | 访问时过期检查 | uncovered | — |
| `R-session-lifecycle-004` | remember_me 配置字段 | uncovered | — |
| `R-session-lifecycle-005` | login 集成 remember_me | uncovered | — |

## session-management

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-session-001` | 密码修改联动会话失效 | uncovered | — |
| `R-session-002` | 会话劫持检测（IP 对比） | uncovered | — |
| `R-session-003` | 劫持检测向后兼容 | uncovered | — |
| `R-session-management-001` | safe_services 过期条目惰性清理 | uncovered | — |
| `R-session-management-002` | rsa 依赖安全升级 | uncovered | — |

## session-search

> 关键词启发式：能力名在 3 个源文件命中（test 优先）→ `src/session/impl.rs`, `src/session/mod.rs`, `src/session/search.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-session-search-001` | feature gate 注册 | uncovered | — |
| `R-session-search-002` | SearchSortType 枚举 | uncovered | — |
| `R-session-search-003` | search_token_value | uncovered | — |
| `R-session-search-004` | search_session_id | uncovered | — |
| `R-session-search-005` | search_token_session_id | uncovered | — |
| `R-session-search-006` | 模块注册 | uncovered | — |

## sms-rate-limit

> 关键词启发式：能力名在 3 个源文件命中（test 优先）→ `src/error.rs`, `src/i18n.rs`, `src/server/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-sms-rate-limit-001` | SmsSender trait | uncovered | — |
| `R-sms-rate-limit-002` | SmsRateLimiter 渐进式限速 | uncovered | — |
| `R-sms-rate-limit-003` | SmsVerificationService 发送验证码 | uncovered | — |
| `R-sms-rate-limit-004` | SmsVerificationService 验证码校验 | uncovered | — |
| `R-sms-rate-limit-005` | 配置项 | uncovered | — |
| `R-sms-rate-limit-006` | 异常发送检测 | uncovered | — |

## state-machine

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/lib.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-state-001` | TokenState enum 定义（E-005，FRD §4.3） | uncovered | — |
| `R-state-002` | TokenState 状态转换路径（E-005，FRD §4.3 严格遵循） | uncovered | — |
| `R-state-003` | TokenState::transition_to 方法（E-005） | uncovered | — |
| `R-state-004` | UserStatus enum 定义（E-005，FRD §4.1） | uncovered | — |
| `R-state-005` | UserStatus 状态转换路径（E-005，FRD §4.2 状态转换规则表） | uncovered | — |
| `R-state-006` | UserStatus::transition_to 方法（E-005） | uncovered | — |
| `R-state-007` | state 模块注册（E-005） | uncovered | — |

## stp

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/harness.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-stp-001` | login_inner 登录流程行为不变 | uncovered | — |
| `R-stp-002` | login_inner 锁内/锁外边界不变 | uncovered | — |

## stp-module-split

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-stp-module-split-001` | 文件拆分结构 | uncovered | — |
| `R-stp-module-split-002` | mod.rs re-exports | uncovered | — |
| `R-stp-module-split-003` | GarrisonManager 子 trait 访问路径 | uncovered | — |
| `R-stp-module-split-004` | Manager（explicit）类型更新 | uncovered | — |
| `R-stp-module-split-005` | 集成测试入口保留 | uncovered | — |

## stp-module-split-completion

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-stp-module-split-completion-001` | 新增 interface.rs | uncovered | — |
| `R-stp-module-split-completion-002` | 新增 util.rs | uncovered | — |
| `R-stp-module-split-completion-003` | 6 个 impl trait 块搬到对应子文件 | uncovered | — |
| `R-stp-module-split-completion-004` | 新增 tests.rs | uncovered | — |
| `R-stp-module-split-completion-005` | mod.rs 精简 | uncovered | — |
| `R-stp-module-split-completion-006` | 业务逻辑不变 | uncovered | — |

## strategy-registry

> 关键词启发式：能力名在 4 个源文件命中（test 优先）→ `tests/acceptance/migrated/mod.rs`, `tests/acceptance/migrated/strategy_registry.rs`, `tests/acceptance/rbac.rs`, `tests/acceptance/session.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-strategy-registry-001` | 6 个策略 trait | uncovered | — |
| `R-strategy-registry-002` | Strategy 注册表 | uncovered | — |
| `R-strategy-registry-003` | GarrisonManager 集成 | uncovered | — |
| `R-strategy-registry-004` | 策略可插拔 | uncovered | — |

## tech-debt-fixes

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-td-001` | Redis Lua 原子化限速 | uncovered | — |
| `R-td-002` | AnomalousLoginAnalyzer shutdown timeout | uncovered | — |
| `R-td-003` | 前后端分离行为变更 | uncovered | — |
| `R-td-004` | Audit 脱敏配置 Full/Partial | uncovered | — |
| `R-td-005` | 缓存 singleflight per-key RwLock | uncovered | — |
| `R-td-006` | Clock trait 可注入时钟 | uncovered | — |

## tenant-isolation

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/migrated/mod.rs`, `tests/acceptance/migrated/tenant_isolation.rs`, `tests/acceptance/repository.rs`, `tests/acceptance/security.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-tenant-isolation-001` | current_tenant_id_strict 函数（H2） | uncovered | — |
| `R-tenant-isolation-002` | 多租户场景强制使用 strict 版本 | uncovered | — |

## testing

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance.rs`, `tests/acceptance/harness.rs`, `tests/acceptance/migrated/annotation_macros.rs`, `tests/acceptance/web_actix.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-testing-001` | JsonTestSuite 解析 | uncovered | — |
| `R-testing-002` | JsonTestCase 结构 | uncovered | — |
| `R-testing-003` | JsonTestSuite 执行 | uncovered | — |
| `R-testing-004` | JSON 测试格式示例 | uncovered | — |

## three-tier-cache

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/stp/session.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-three-tier-cache-001` | UserCacheService 三层结构 | uncovered | — |
| `R-three-tier-cache-002` | get_permissions 账号权限缓存 | uncovered | — |
| `R-three-tier-cache-003` | get_roles 账号角色缓存 | uncovered | — |
| `R-three-tier-cache-004` | invalidate 缓存失效 | uncovered | — |
| `R-three-tier-cache-005` | logout 集成 | uncovered | — |
| `R-three-tier-cache-006` | TTL 配置 | uncovered | — |

## token-introspection

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/protocol/oauth2/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-token-introspection-001` | introspect_token 方法 | uncovered | — |
| `R-token-introspection-002` | TokenIntrospectionResponse struct | uncovered | — |
| `R-token-introspection-003` | active 字段语义 | uncovered | — |

## token-map-cleanup

> 关键词启发式：能力名在 7 个源文件命中（test 优先）→ `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`, `src/manager/builder.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-token-map-cleanup-001` | cleanup_expired_tokens 方法 | uncovered | — |
| `R-token-map-cleanup-002` | spawn_cleanup_task 函数 | uncovered | — |
| `R-token-map-cleanup-003` | 配置项 | uncovered | — |
| `R-token-map-cleanup-004` | GarrisonManager 集成 | uncovered | — |

## token-read-body

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/harness.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-token-read-body-001` | is_read_body 配置项 | uncovered | — |
| `R-token-read-body-002` | axum adapter body 读取 | uncovered | — |
| `R-token-read-body-003` | actix adapter body 读取 | uncovered | — |
| `R-token-read-body-004` | warp adapter body 读取 | uncovered | — |

## token-renewal

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/authentication.rs`, `tests/acceptance/bw_ac.rs`, `tests/acceptance/concurrency.rs`, `tests/acceptance/harness.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-token-001` | 默认不启用自动续签 | uncovered | — |
| `R-token-002` | 阈值配置范围校验 | uncovered | — |
| `R-token-003` | 环境变量覆盖 | uncovered | — |
| `R-token-004` | TTL 充足时不续签 | uncovered | — |
| `R-token-005` | 非 JWT 模式触发续签 | uncovered | — |
| `R-token-006` | JWT 模式触发续签 | uncovered | — |
| `R-token-007` | check_login 集成续签 | uncovered | — |

## user-lockout

> 关键词启发式：能力名在 1 个源文件命中（test 优先）→ `src/account/lockout/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-user-lockout-001` | UserLockoutConfig 配置类型定义 | uncovered | — |
| `R-user-lockout-002` | WaitStrategy enum 定义 | uncovered | — |
| `R-user-lockout-003` | LockoutState 状态类型定义 | uncovered | — |
| `R-user-lockout-004` | UserLockoutStrategy struct 与 GarrisonFirewallStrategy trait 实现 | uncovered | — |
| `R-user-lockout-005` | check 方法逻辑 | uncovered | — |
| `R-user-lockout-006` | record_failure 方法逻辑 | uncovered | — |
| `R-user-lockout-007` | record_success 方法逻辑 | uncovered | — |
| `R-user-lockout-008` | unlock 方法逻辑 | uncovered | — |
| `R-user-lockout-009` | 与 BruteForceStrategy 组合注册 | uncovered | — |
| `R-user-lockout-010` | FirewallContext.login_id 类型迁移 | uncovered | — |
| `R-user-lockout-011` | account-lockout feature 依赖声明 | uncovered | — |

## waf

> 关键词启发式：能力名在 8 个源文件命中（test 优先）→ `tests/acceptance/web_axum.rs`, `src/config/impls.rs`, `src/config/mod.rs`, `src/config/tests.rs`…

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-waf-001` | WafRule trait 抽象 | uncovered | — |
| `R-waf-002` | DangerousCharacter 规则 | uncovered | — |
| `R-waf-003` | DirectoryTraversal 规则 | uncovered | — |
| `R-waf-004` | PathWhitelist / PathBlacklist 规则 | uncovered | — |
| `R-waf-005` | HttpMethodWhitelist 规则 | uncovered | — |
| `R-waf-006` | garrison_waf_middleware | uncovered | — |

## web-context-adapters

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-web-context-001` | ActixContext 4 件套 | uncovered | — |
| `R-web-context-002` | WarpContext 4 件套 | uncovered | — |
| `R-web-context-003` | 三框架行为对齐 | uncovered | — |

## web-router-group

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-router-group-001` | group 方法签名 | uncovered | — |
| `R-router-group-002` | prefix 前缀合并 | uncovered | — |
| `R-router-group-003` | annotation 注解继承 | uncovered | — |
| `R-router-group-004` | RouteRule 同步 | uncovered | — |

## xss-protection

| 需求 ID | 标题 | 状态 | 引用位置 |
|---|---|---|---|
| `R-xss-001` | 全转义模式 | uncovered | — |
| `R-xss-002` | 白名单标签模式 | uncovered | — |
| `R-xss-003` | 空输入处理 | uncovered | — |

## BW-AC 验收标准（FRD §8.1）

| 验收标准 | 状态 | 测试位置 |
|---|---|---|
| `BW-AC-001` | covered | `tests/acceptance/bw_ac.rs`<br>`tests/acceptance/session.rs` |
| `BW-AC-002` | covered | `tests/acceptance/bw_ac.rs`<br>`tests/acceptance/session.rs` |
| `BW-AC-003` | covered | `tests/acceptance/session.rs` |
| `BW-AC-004` | covered | `tests/acceptance/authentication.rs`<br>`tests/acceptance/bw_ac.rs` |
| `BW-AC-005` | covered | `tests/acceptance/authentication.rs`<br>`tests/acceptance/bw_ac.rs` |
| `BW-AC-006` | covered | `tests/acceptance/authentication.rs`<br>`tests/acceptance/bw_ac.rs` |
| `BW-AC-007` | covered | `tests/acceptance/bw_ac.rs` |
| `BW-AC-008` | covered | `tests/acceptance/resilience.rs` |
| `BW-AC-009` | covered | `tests/acceptance/authentication.rs`<br>`tests/acceptance/bw_ac.rs`<br>`tests/acceptance/session.rs` |
| `BW-AC-010` | covered | `tests/acceptance/authentication.rs` |
| `BW-AC-011` | covered | `tests/acceptance/migrated/annotation_macros.rs` |
| `BW-AC-012` | covered | `src/manager/tests.rs` |
| `BW-AC-013` | covered | `tests/acceptance/repository.rs` |
| `BW-AC-014` | covered | `src/stp/tests.rs` |
| `BW-AC-015` | covered | `tests/acceptance/migrated/tenant_isolation.rs` |

## 统计

- 规格需求条目：581（specmark specs 566 + BW-AC 15）
- 有静态引用（covered）：15（2.6%）
- 无静态引用（uncovered，待人工复核）：566

### Gap 清单

- `R-abac-001`
- `R-abac-002`
- `R-abac-003`
- `R-abac-004`
- `R-abac-005`
- `R-ac-001`
- `R-ac-002`
- `R-ac-003`
- `R-ac-004`
- `R-ac-005`
- `R-ac-006`
- `R-ac-007`
- `R-ac-008`
- `R-ac-009`
- `R-ac-010`
- `R-ac-011`
- `R-ac-012`
- `R-account-001`
- `R-account-002`
- `R-account-module-001`
- `R-account-module-002`
- `R-account-module-003`
- `R-account-module-004`
- `R-account-module-005`
- `R-anno-001`
- `R-anno-002`
- `R-anno-003`
- `R-anno-004`
- `R-annotation-macros-001`
- `R-annotation-macros-002`
- `R-annotation-macros-003`
- `R-annotation-macros-004`
- `R-annotation-macros-005`
- `R-annotation-oauth2-001`
- `R-annotation-oauth2-002`
- `R-annotation-oauth2-003`
- `R-anomalous-detector-dual-001`
- `R-anomalous-detector-dual-002`
- `R-anomalous-detector-dual-003`
- `R-anomalous-detector-dual-004`
- `R-anomalous-detector-dual-005`
- `R-anomalous-detector-dual-006`
- `R-anomalous-detector-dual-007`
- `R-anonymous-session-001`
- `R-anonymous-session-002`
- `R-anonymous-session-003`
- `R-anonymous-session-004`
- `R-anonymous-session-005`
- `R-anonymous-session-006`
- `R-apikey-protocol-001`
- `R-apikey-protocol-002`
- `R-arch-001`
- `R-arch-002`
- `R-arch-003`
- `R-arch-004`
- `R-audit-log-001`
- `R-audit-log-002`
- `R-audit-log-003`
- `R-auth-flow-dsl-001`
- `R-auth-flow-dsl-002`
- `R-auth-flow-dsl-003`
- `R-auth-flow-dsl-004`
- `R-auth-flow-dsl-005`
- `R-auth-flow-dsl-006`
- `R-auth-flow-dsl-007`
- `R-auth-flow-dsl-008`
- `R-auth-flow-dsl-009`
- `R-auth-flow-dsl-010`
- `R-auth-flow-dsl-011`
- `R-auth-flow-dsl-012`
- `R-auth-flow-dsl-013`
- `R-auth-flow-dsl-014`
- `R-auth-password-login-001`
- `R-auth-password-login-002`
- `R-auth-password-login-003`
- `R-authorize-api-001`
- `R-authorize-api-002`
- `R-authorize-api-003`
- `R-authorize-api-004`
- `R-bench-001`
- `R-bench-002`
- `R-bench-003`
- `R-bench-004`
- `R-bench-005`
- `R-bench-006`
- `R-garrison-logic-trait-001`
- `R-garrison-logic-trait-002`
- `R-garrison-logic-trait-003`
- `R-garrison-logic-trait-004`
- `R-garrison-logic-trait-005`
- `R-garrison-logic-trait-006`
- `R-garrison-logic-trait-007`
- `R-garrison-logic-trait-008`
- `R-util-api-001`
- `R-util-api-002`
- `R-util-api-003`
- `R-util-api-004`
- `R-cache-001`
- `R-cache-002`
- `R-cache-003`
- `R-warmup-001`
- `R-warmup-002`
- `R-warmup-003`
- `R-concurrent-001`
- `R-concurrent-002`
- `R-concurrent-003`
- `R-concurrent-004`
- `R-concurrent-005`
- `R-concurrent-006`
- `R-concurrent-007`
- `R-concurrent-008`
- `R-concurrent-009`
- `R-concurrent-login-policy-001`
- `R-concurrent-login-policy-002`
- `R-concurrent-login-policy-003`
- `R-concurrent-login-policy-004`
- `R-concurrent-login-policy-005`
- `R-concurrent-login-policy-006`
- `R-concurrent-login-policy-007`
- `R-config-001`
- `R-config-002`
- `R-constants-001`
- `R-constants-002`
- `R-constants-003`
- `R-context-001`
- `R-context-002`
- `R-auth-extensions-001`
- `R-auth-extensions-002`
- `R-auth-extensions-003`
- `R-auth-extensions-004`
- `R-cors-001`
- `R-cors-002`
- `R-cors-003`
- `R-cors-004`
- `R-cors-005`
- `R-credential-model-001`
- `R-credential-model-002`
- `R-credential-model-003`
- `R-credential-model-004`
- `R-credential-model-005`
- `R-credential-model-006`
- `R-credential-model-007`
- `R-credential-model-008`
- `R-csrf-001`
- `R-csrf-002`
- `R-csrf-003`
- `R-csrf-004`
- `R-dao-garrison-dao-001`
- `R-dao-garrison-dao-002`
- `R-dao-garrison-dao-003`
- `R-dao-garrison-dao-004`
- `R-dao-keys-performance-001`
- `R-dao-keys-performance-002`
- `R-dao-keys-performance-003`
- `R-dao-redis-modes-001`
- `R-dao-redis-modes-002`
- `R-dao-redis-modes-003`
- `R-database-001`
- `R-database-002`
- `R-database-003`
- `R-database-004`
- `R-database-005`
- `R-database-migration-001`
- `R-database-migration-002`
- `R-database-migration-003`
- `R-database-migration-004`
- `R-dep-001`
- `R-dep-002`
- `R-dep-003`
- `R-dep-004`
- `R-dep-005`
- `R-device-binding-001`
- `R-device-binding-002`
- `R-device-binding-003`
- `R-device-binding-004`
- `R-device-binding-005`
- `R-device-binding-006`
- `R-device-001`
- `R-device-002`
- `R-device-003`
- `R-device-004`
- `R-device-005`
- `R-device-006`
- `R-device-007`
- `R-disable-repository-001`
- `R-disable-repository-002`
- `R-disable-repository-003`
- `R-disable-repository-004`
- `R-disable-repository-005`
- `R-disable-repository-006`
- `R-dynamic-active-timeout-001`
- `R-dynamic-active-timeout-002`
- `R-dynamic-active-timeout-003`
- `R-dynamic-active-timeout-004`
- `R-e2e-authz-boundary-001`
- `R-e2e-authz-boundary-002`
- `R-e2e-authz-boundary-003`
- `R-e2e-authz-boundary-004`
- `R-e2e-authz-boundary-005`
- `R-e2e-authz-boundary-006`
- `R-e2e-authz-boundary-007`
- `R-e2e-authz-boundary-008`
- `R-e2e-error-edge-001`
- `R-e2e-error-edge-002`
- `R-e2e-error-edge-003`
- `R-e2e-error-edge-004`
- `R-e2e-error-edge-005`
- `R-e2e-error-edge-006`
- `R-e2e-functional-001`
- `R-e2e-functional-002`
- `R-e2e-functional-003`
- `R-error-001`
- `R-error-002`
- `R-error-003`
- `R-error-001`
- `R-error-002`
- `R-error-003`
- `R-error-004`
- `R-error-005`
- `R-feature-001`
- `R-feature-002`
- `R-feature-003`
- `R-feature-004`
- `R-feature-005`
- `R-feature-006`
- `R-feature-007`
- `R-firewall-maxminddb-001`
- `R-firewall-maxminddb-002`
- `R-firewall-maxminddb-003`
- `R-firewall-maxminddb-004`
- `R-firewall-maxminddb-005`
- `R-firewall-waf-001`
- `R-firewall-waf-002`
- `R-firewall-waf-003`
- `R-firewall-waf-004`
- `R-firewall-waf-005`
- `R-firewall-waf-006`
- `R-firewall-waf-007`
- `R-firewall-waf-008`
- `R-framework-001`
- `R-framework-002`
- `R-framework-003`
- `R-framework-004`
- `R-framework-005`
- `R-frontend-001`
- `R-frontend-002`
- `R-frontend-003`
- `R-gc-001`
- `R-http-logging-001`
- `R-http-logging-002`
- `R-http-logging-003`
- `R-http-logging-004`
- `R-http-logging-005`
- `R-is-001`
- `R-is-002`
- `R-is-003`
- `R-is-004`
- `R-jwt-refresh-001`
- `R-jwt-refresh-002`
- `R-revocation-001`
- `R-revocation-002`
- `R-revocation-003`
- `R-listener-events-001`
- `R-listener-events-002`
- `R-listener-events-003`
- `R-login-id-migration-001`
- `R-login-id-migration-002`
- `R-login-id-migration-003`
- `R-login-id-migration-004`
- `R-login-id-migration-005`
- `R-login-id-type-001`
- `R-login-id-type-002`
- `R-login-id-type-003`
- `R-login-token-map-persistence-001`
- `R-login-token-map-persistence-002`
- `R-login-token-map-persistence-003`
- `R-login-token-map-persistence-004`
- `R-login-token-map-persistence-005`
- `R-login-token-map-persistence-006`
- `R-login-type-001`
- `R-login-type-002`
- `R-login-type-003`
- `R-manager-explicit-001`
- `R-manager-explicit-002`
- `R-manager-explicit-003`
- `R-msa-001`
- `R-msa-002`
- `R-msa-003`
- `R-msa-004`
- `R-msa-005`
- `R-msa-006`
- `R-module-structure-001`
- `R-module-structure-002`
- `R-module-structure-003`
- `R-module-structure-004`
- `R-module-structure-005`
- `R-credit-001`
- `R-credit-002`
- `R-credit-003`
- `R-credit-004`
- `R-credit-005`
- `R-credit-006`
- `R-credit-007`
- `R-credit-008`
- `R-credit-009`
- `R-credit-010`
- `R-mysql-backend-001`
- `R-mysql-backend-002`
- `R-mysql-backend-003`
- `R-oauth-2-1-001`
- `R-oauth-2-1-002`
- `R-oauth-2-1-003`
- `R-oauth2-001`
- `R-oauth2-002`
- `R-oauth2-003`
- `R-oauth2-001`
- `R-oauth2-002`
- `R-oauth2-003`
- `R-oauth2-004`
- `R-oauth2-005`
- `R-oauth2-006`
- `R-oxcache-decision-sync-001`
- `R-oxcache-decision-sync-002`
- `R-oxcache-decision-sync-003`
- `R-oxcache-decision-sync-004`
- `R-oxcache-sync-api-001`
- `R-oxcache-sync-api-002`
- `R-oxcache-sync-api-003`
- `R-p0-001`
- `R-p0-002`
- `R-p0-003`
- `R-p0-004`
- `R-p0-005`
- `R-password-policy-001`
- `R-password-policy-002`
- `R-password-policy-003`
- `R-password-policy-004`
- `R-password-policy-005`
- `R-password-policy-006`
- `R-password-policy-007`
- `R-pentest-attack-001`
- `R-pentest-attack-002`
- `R-pentest-attack-003`
- `R-pentest-attack-004`
- `R-pentest-attack-005`
- `R-pentest-attack-006`
- `R-pentest-attack-007`
- `R-pentest-attack-008`
- `R-perf-load-001`
- `R-perf-load-002`
- `R-perf-load-003`
- `R-perf-load-004`
- `R-permission-registry-001`
- `R-permission-registry-002`
- `R-permission-registry-003`
- `R-protocol-001`
- `R-protocol-002`
- `R-apikey-namespace-001`
- `R-apikey-namespace-002`
- `R-apikey-namespace-003`
- `R-apikey-namespace-004`
- `R-jwt-modes-001`
- `R-jwt-modes-002`
- `R-jwt-modes-003`
- `R-jwt-modes-004`
- `R-jwt-modes-005`
- `R-sso-federation-001`
- `R-sso-federation-002`
- `R-sso-federation-003`
- `R-sso-federation-004`
- `R-sso-federation-005`
- `R-sso-toctou-001`
- `R-sso-toctou-002`
- `R-sso-toctou-003`
- `R-qual-001`
- `R-qual-002`
- `R-qual-003`
- `R-qual-004`
- `R-qual-005`
- `R-qual-006`
- `R-rate-limiter-001`
- `R-rate-limiter-002`
- `R-rate-limiter-003`
- `R-rate-limiter-004`
- `R-redis-ratelimit-001`
- `R-redis-ratelimit-002`
- `R-redis-ratelimit-003`
- `R-redis-ratelimit-004`
- `R-redis-ratelimit-005`
- `R-refresh-001`
- `R-refresh-002`
- `R-refresh-003`
- `R-refresh-004`
- `R-refresh-005`
- `R-repository-layer-001`
- `R-repository-layer-002`
- `R-repository-layer-003`
- `R-repository-layer-004`
- `R-repository-layer-005`
- `R-repository-layer-006`
- `R-repository-layer-007`
- `R-response-token-001`
- `R-response-token-002`
- `R-response-token-003`
- `R-safe-auth-001`
- `R-safe-auth-002`
- `R-safe-auth-003`
- `R-safe-auth-004`
- `R-safe-auth-005`
- `R-safe-auth-006`
- `R-safe-defaults-001`
- `R-safe-defaults-002`
- `R-safe-defaults-003`
- `R-safe-defaults-004`
- `R-secure-001`
- `R-secure-002`
- `R-secure-003`
- `R-secure-password-001`
- `R-secure-password-002`
- `R-secure-password-003`
- `R-secure-password-004`
- `R-secure-password-005`
- `R-secure-password-006`
- `R-security-alert-001`
- `R-security-alert-002`
- `R-security-alert-003`
- `R-security-alert-004`
- `R-security-alert-005`
- `R-security-alert-006`
- `R-sec-001`
- `R-sec-002`
- `R-sec-003`
- `R-sec-004`
- `R-sec-005`
- `R-sec-006`
- `R-sec-007`
- `R-security-confusable-001`
- `R-security-confusable-002`
- `R-security-confusable-003`
- `R-masking-001`
- `R-masking-002`
- `R-masking-003`
- `R-masking-004`
- `R-masking-005`
- `R-server-security-001`
- `R-server-security-002`
- `R-server-security-003`
- `R-hover-001`
- `R-hover-002`
- `R-hover-003`
- `R-hover-004`
- `R-session-key-001`
- `R-session-key-002`
- `R-session-key-003`
- `R-session-kickout-001`
- `R-session-kickout-002`
- `R-session-kickout-003`
- `R-session-lifecycle-001`
- `R-session-lifecycle-002`
- `R-session-lifecycle-003`
- `R-session-lifecycle-004`
- `R-session-lifecycle-005`
- `R-session-001`
- `R-session-002`
- `R-session-003`
- `R-session-management-001`
- `R-session-management-002`
- `R-session-search-001`
- `R-session-search-002`
- `R-session-search-003`
- `R-session-search-004`
- `R-session-search-005`
- `R-session-search-006`
- `R-sms-rate-limit-001`
- `R-sms-rate-limit-002`
- `R-sms-rate-limit-003`
- `R-sms-rate-limit-004`
- `R-sms-rate-limit-005`
- `R-sms-rate-limit-006`
- `R-state-001`
- `R-state-002`
- `R-state-003`
- `R-state-004`
- `R-state-005`
- `R-state-006`
- `R-state-007`
- `R-stp-001`
- `R-stp-002`
- `R-stp-module-split-001`
- `R-stp-module-split-002`
- `R-stp-module-split-003`
- `R-stp-module-split-004`
- `R-stp-module-split-005`
- `R-stp-module-split-completion-001`
- `R-stp-module-split-completion-002`
- `R-stp-module-split-completion-003`
- `R-stp-module-split-completion-004`
- `R-stp-module-split-completion-005`
- `R-stp-module-split-completion-006`
- `R-strategy-registry-001`
- `R-strategy-registry-002`
- `R-strategy-registry-003`
- `R-strategy-registry-004`
- `R-td-001`
- `R-td-002`
- `R-td-003`
- `R-td-004`
- `R-td-005`
- `R-td-006`
- `R-tenant-isolation-001`
- `R-tenant-isolation-002`
- `R-testing-001`
- `R-testing-002`
- `R-testing-003`
- `R-testing-004`
- `R-three-tier-cache-001`
- `R-three-tier-cache-002`
- `R-three-tier-cache-003`
- `R-three-tier-cache-004`
- `R-three-tier-cache-005`
- `R-three-tier-cache-006`
- `R-token-introspection-001`
- `R-token-introspection-002`
- `R-token-introspection-003`
- `R-token-map-cleanup-001`
- `R-token-map-cleanup-002`
- `R-token-map-cleanup-003`
- `R-token-map-cleanup-004`
- `R-token-read-body-001`
- `R-token-read-body-002`
- `R-token-read-body-003`
- `R-token-read-body-004`
- `R-token-001`
- `R-token-002`
- `R-token-003`
- `R-token-004`
- `R-token-005`
- `R-token-006`
- `R-token-007`
- `R-user-lockout-001`
- `R-user-lockout-002`
- `R-user-lockout-003`
- `R-user-lockout-004`
- `R-user-lockout-005`
- `R-user-lockout-006`
- `R-user-lockout-007`
- `R-user-lockout-008`
- `R-user-lockout-009`
- `R-user-lockout-010`
- `R-user-lockout-011`
- `R-waf-001`
- `R-waf-002`
- `R-waf-003`
- `R-waf-004`
- `R-waf-005`
- `R-waf-006`
- `R-web-context-001`
- `R-web-context-002`
- `R-web-context-003`
- `R-router-group-001`
- `R-router-group-002`
- `R-router-group-003`
- `R-router-group-004`
- `R-xss-001`
- `R-xss-002`
- `R-xss-003`
