# Changelog

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