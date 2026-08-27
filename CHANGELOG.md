# Changelog

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