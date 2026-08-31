# Changelog

## [Unreleased]

> specmark change `acceptance-overhaul`：全量验收测试重构 + 缺陷全部修复。
>
> **终验统计（T061/T066 收口，证据 `target/gate-final.log` + 三维审查独立复测）**：
> - 验收测试矩阵 `--test acceptance`：**380 passed / 0 failed**（3 ignored），分域实测：
>   authentication 19 / session 18 / rbac 18 / protocol_jwt 19 / protocol_oauth2 15 /
>   protocol_mixed 23 / security 27 / web_axum 24 / web_actix 8 / web_warp 6 / storage 16 /
>   resilience 12 / concurrency 9 / server 18 / repository 30 / environment 4 / BW-AC 6 /
>   harness 4 + migrated 旧树 104（另有 keycloak_oidc/tenant_isolation 2 例与
>   environment testing 2 例受 feature 门控，见 T065 说明）
> - 全量 `--tests`：**4339 passed / 0 failed**（lib 3959 + acceptance 380，含 8 个
>   `#[ignore]` 门控项：perf 3 + 外部服务 5）——基线 4185 → 4339（+154）
> - 六门禁：fmt / clippy default / clippy full / clippy all-targets 全部 `-D warnings`
>   干净；`cargo doc --features full` 0 告警
> - 旧测试树全量迁移：e2e(59) / integration(108) / protocol(36) / repository(72) /
>   acceptance_criteria(9) / auth_server_integration(12) / unit(2) 并入验收矩阵，
>   根入口删除（`tests/` = acceptance.rs + acceptance/ + common/ + data/）
>
> **实证发现（验收首次真实验证 e2e 未验证声明）**：
> - FINDING-025：会话存储无租户作用域（`tenant_isolation.enabled` 无运行时消费点），
>   跨租户 check-login 返回 true；隔离强制点在 DAO 前缀层与审计层。后续 change 待定
> - XSS 硬化实测：auth-server 在 login_id 校验层 400 拒绝尖括号载荷（入口拒绝）
> - jsonwebtoken u64 秒边界：过期判定存在亚秒 flaky（测试已按 2.5s 跨秒修正）

### Breaking
- **`GarrisonDao` 六个原子方法收严为必需方法（T012）**：`rename` / `set_if_absent` /
  `get_and_delete` / `incr` / `decr` / `compare_and_swap` 移除非原子默认实现（TOCTOU
  竞态此前仅靠文档约束）。自定义实现方必须补齐这六个方法并以进程内锁或后端原语保证
  原子性，遗漏实现将在**编译期**报错（E0046）。内置实现（`InMemoryDao` / `GarrisonDaoOxcache`
  / `GarrisonDaoDbnexus` / `AloneCache`）均已满足契约；测试 mock 可用
  `garrison::atomic_test_fallback!()`（`#[doc(hidden)]`，组合语义，仅限测试环境）。
- **`GarrisonException.login_id` 类型对齐（T010）**：`Option<i64>` → `Option<String>`，
  与全局 login_id 的 String 迁移一致；`with_login_id` 改为接受 `impl Into<String>`。
- **`GarrisonError::Exception` 变体 `Box` 装载（T011 连带修复）**：
  `Exception(GarrisonException)` → `Exception(Box<GarrisonException>)`，控制枚举体积
  （login_id String 化曾使 `Result<_, GarrisonError>` 越过 clippy `result_large_err`
  阈值，引发 192 处告警）。构造点需 `Box::new(...)` 或使用既有 `From<GarrisonException>`。

### Added
- **`GarrisonGrpcAuthLayer`（T014，`grpc` feature）**：tower Layer/Service 形态的
  gRPC async 鉴权层——严格 Bearer 提取 → async `check_login` → 失败以
  `Status::UNAUTHENTICATED` 拒绝、成功在 `with_current_token` 作用域内放行。
  消除同步拦截器「仅提取 token 不鉴权」的 footgun；拦截器保留提取职责并更新文档指向。
- **`GarrisonError::code()`（T011）**：稳定机器可读错误码（与 HTTP `error_code` 同源，
  单一事实来源 `parts_and_msg_key`；`Exception` 变体级固定 `EXCEPTION`），供日志 /
  监控 / audit-log 等非 HTTP 场景按变体检索。
- **验收测试矩阵（T002-T005、T013，随 Phase 2-4 持续扩充）**：`tests/acceptance/`
  按域组织「正常 + 异常」成对验收（`ACC-<域>-NNN` 可追溯）：`GarrisonTestHarness`
  统一测试基建、三框架同构冒烟（axum/actix/warp 统一 401 JSON）、DAO 原子性并发
  （100 task 竞争断言）等盲区补齐；现有 tests/ 将全量迁移重构入矩阵。

### Fixed
- warp `GarrisonRejection` 缺统一错误 JSON 映射（T004）：新增 `Display` + `Reply` 实现
  与 `garrison_recover()` 守卫，三框架错误响应（状态码 + `error_code`/`message` body）
  完全一致。
- harness 实测修复：`throw_on_not_login` 默认 true 时未登录经 middleware 抛
  `Session` 错误 → 500 而非 401（web 冒烟以 `web_test_config()` 同源配置修复）。

### Changed
- 文档与代码事实同步（T015）：ARCHITECTURE.md 版本行 / lib.rs 示例版本 / bcrypt 注释 /
  state 模块 roadmap 表述 / SECURITY.md 增加 RUSTSEC-2023-0071 处置锚定。

## [0.9.0-rc.2] - 2026-08-26

### Breaking
- **`check_api_key` fail-closed（CRIT-008）**：当 `protocol-apikey` feature 关闭时，
  `#[check_api_key]` 生成的调用不再静默返回 `Ok(())`（此前所有携带任意字符串的请求均通过校验）。
  现返回 `Err(GarrisonError::Config("check_api_key requires protocol-apikey feature"))`。
  若宏已用于未启用该 feature 的构建，请启用 `protocol-apikey` 或移除注解。
- **`check_abac_with_policy` fail-closed（CRIT-009）**：当 `abac` feature 关闭、且端点声明了
  `abac` 策略（`abac = "..."`）时，返回 `Err(GarrisonError::Config)` 而非静默放行。
  未声明 `abac` 策略的端点保持 no-op 放行。
  逃生门：调用 `garrison::abac::set_abac_missing_feature_policy(true)` 可切换为 AllowWithWarn
  （放行 + `warn` 告警），默认 Deny（fail-closed）。
- **防火墙自动装配（CRIT-010）**：启用任一 `firewall-*` feature 时，`GarrisonManager::builder()`
  自动注入 `GarrisonFirewallCheckHookDefault`（共享 DAO 限流器），并新增 `login` / `check_login`
  失败路径的暴力破解计数（`record_failure`）、成功路径清零。此前该防护为 dead-code。

### Changed
- `session::dao()` 的 `pub(crate)` 可见性扩展至 `firewall-bruteforce` feature（供 login/check_login 计数使用）。
- `GarrisonPermissionStrategy::firewall_hook_injected()` 诊断方法新增（默认 `false`，默认实现返回实际注入状态）。

## [0.9.0-rc.1] - 2026-08-25

### Added
- authflow：`IpWhitelist`（CIDR 白名单，`IpNetwork::contains`）与 `CustomConditionEvaluator` 自定义条件求值器（运行期注册，未注册条件名返回显性错误）
- `policy-hibp` feature：HIBP k-anonymity 泄露密码检查（SHA-1 前 5 位 range 查询；关闭时 `check_hibp` 返回显性 `Err(HibpDisabled)`）
- `web-axum` 对接 guardrail：garrison 侧 `IpWhitelist`/evaluator 受 `axum` 面门控

### Changed
- `MockDao` 正名 `InMemoryDao`（`src/dao/in_memory.rs`；`deprecated` 别名过渡，下版本移除）
- oauth2_server/secure/totp/dao 测试与内部引用全面迁移至 `InMemoryDao`/`Totp` 新 API
- `totp-rs` 6.0 API 迁移（`Builder` 链式构造；`check()` 返回 `Option<u64>` 语义）
- `permission` provider `health_check` 语义真实化（memory：策略表容量 > 0；yaml：策略文件可读）+ 失败路径单测
- `session::dao()` 的 `pub(crate)` 门控扩展覆盖 `protocol-jwt` 面
- rustdoc：三处文档链接修复 + `invalid-rust-codeblocks` lint 显式声明

### Fixed
- `src/secure/totp/handler.rs` totp-rs 6 API 编译错误
- `jwt_modes` 集成测试 secret 长度对齐生产 32 字节校验阈值
- `oauth2_server` 测试引用 `MockDao` 别名正名
- `policy-hibp` 常量在 feature 关闭面无 unused 告警

### Breaking
- `MockDao` → `InMemoryDao`（迁移期 deprecated 别名）
- `policy-hibp` 关闭时 `check_hibp` 从静默通过改显性错误