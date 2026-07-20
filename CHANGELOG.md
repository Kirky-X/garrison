# Changelog

本文件记录 Bulwark 项目的所有显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.7.1] - 2026-07-21

### 概述

本期为 **strix 安全审计修复批次**，整合 3 轮 strix 渗透测试（`bulwark_21a6` / `bulwark_371b` / `bulwark_6704`）发现的 21 个安全漏洞修复，覆盖认证授权（A1–A11）、OAuth2/OIDC（B1–B10）、Web 安全（C1–C7）、密码学（D1–D6）、性能（E1–E4）与供应链（F1–F4）六大维度。共 21 个 commit，CRITICAL 漏洞全部修复并通过 Convergence 阶段代码-文档一致性审查。

### Security

- **CRITICAL**: 修复 ABAC 表达式注入漏洞（A3, b28ef5c）— `validate_abac_expr()` 拒绝 `true` / 策略终止符 / 空串
- **CRITICAL**: 修复 switch_to 权限提升 + AccountSession 自动创建（A6, 43ab79c）— 强制校验目标用户存在 + caller 所有权
- **CRITICAL**: 修复跨用户会话管理未授权漏洞（A7, a1d6e8b）— kickout 端点强制 caller 所有权校验
- **CRITICAL**: 修复 login_with_token 会话固定/劫持漏洞（A8, 5648f2a）— 入口校验目标 token 不存在
- **CRITICAL**: 修复 SimpleTokenStyle 伪造漏洞（A11, 2084933）— HMAC-SHA256 签名 + `subtle::ConstantTimeEq` 常量时间比较
- **CRITICAL**: 实现 OIDC id_token 验证（B1, 4e13b21）— KeycloakProvider JWKS 验签
- **CRITICAL**: 强制 OAuth2 scope 校验（B3, c5a325b）— ScopeHandler 注册表强制注册
- **CRITICAL**: 修复 KeycloakProvider aud/iss 校验缺失（B9, 4e13b21）— 严格 audience + issuer 双校验
- **HIGH**: 修复 ABAC 引擎使用 `Entities::empty()` 漏洞（A1）— 注入实际 entity 数据
- **HIGH**: 修复租户隔离 `tenant_id=0` fallback 漏洞（A4）— 显式拒绝无 tenant 上下文的请求
- **HIGH**: 修复 renew_to_equivalent 续期窗口漏洞（A9, 954ad49）— swap 顺序消除 DoS gap window
- **HIGH**: 修复设备指纹可欺骗漏洞（A10, 81feb09）— `device_fingerprint_rich()` UA + IP + Accept-Language 多维度
- **HIGH**: CSRF/WAF 默认启用 + Origin/Referer 校验（C1, 6960b53）
- **HIGH**: 修复速率限制器内存泄漏 + XFF 欺骗（C5）
- **HIGH**: 修复 API Key 时序侧信道（C6）
- **HIGH**: 添加 OAuth2 /token 端点速率限制（B5, 6a5c63b）— 按 client_id + username 双维度
- **HIGH**: reqwest 客户端添加超时（E1, 65cc6b6）— `build_safe_http_client()` helper
- **HIGH**: reqwest 响应体大小限制（E2, 65cc6b6）— 4 MiB 上限
- **HIGH**: TOTP 锁改用 oxcache 有界缓存（E3, accf1e1）— DashMap → 原子 DAO incr
- **HIGH**: API Key 反向索引避免全表扫描（E4, 811ee10）— O(1) verify
- **HIGH**: OAuth2 限速器添加 `with_dao()` 注入点（diting HIGH, 844eaef）— 生产部署可注入分布式 DAO
- **HIGH**: switch_to 清理原 Account-Session token 条目（H1, 24e1a1e）— 防止 `logout_by_login_id` 越权踢出已切换会话
- **HIGH**: SimpleTokenStyle 用 `\x1f` 分隔符支持含 `-` 的 login_id（H2, 235e98b）— email/UUID/kebab-case login_id 不再 verify 失败
- **HIGH**: OIDC id_token `aud` 支持数组形式（H3, b21478b）— 兼容 RFC 7519，支持 Google/Azure AD 多 audience 场景
- **HIGH**: `OidcClaims.aud` 类型从 `String` 改为 `OidcAudience` enum（破坏性 API 变更，H3, b21478b）— 兼容 RFC 7519，旧代码需改用 `aud.contains(&self.audience)` 比较

### Added

- 新增 `secure-simple-token` feature（A11）— SimpleTokenStyle HMAC-SHA256 签名
- 新增 `validate_abac_expr()` 函数（A3）— Cedar 策略注入防御
- 新增 `compose_security_stack()` 帮助函数（C4）— CORS preflight 绕过 WAF/CSRF 修复
- 新增 `cookie_domain` 配置项（C3）— CsrfConfig 字段
- 新增 `build_safe_http_client()` helper（E1）— 统一超时 + body 限制
- 新增 `device_fingerprint_rich()` 函数（A10）— 多维度设备指纹
- 新增 `dep:subtle` 加入 `secure-sign` feature（D1, b9312f0）— 常量时间 HMAC 验证

### Changed

- ABAC 引擎未初始化从 fail-open 改为 fail-closed（A2）
- SimpleTokenStyle 从 ZST 改为 `struct { secret: String }`，**破坏性 API 变更**
- `OidcClaims.aud` 类型从 `String` 改为 `OidcAudience` enum，**破坏性 API 变更**（旧代码 `claims.aud == self.audience` 需改用 `claims.aud.contains(&self.audience)`）
- `require_secondary_auth` 从软提示改为 hard block（A10）

### Fixed

- get-session 内部端点缺少所有权校验（A5, 0d7a8fe）
- get-token-info 内部端点缺少所有权校验（A5, 0d7a8fe）
- OIDC state 参数未校验（B2, 4e13b21）
- URL 编码器遗漏 % 字符（B4, 4e13b21）
- redirect_uri 未编码导致开放重定向（B6, 4e13b21）
- DAO fallback 路径 refresh token 未轮换（B7, 4e13b21）
- 不支持 HTTP Basic Auth 传输 client_secret（B8, 4e13b21）
- JWT 未校验 nbf（B10, 1944271）
- WAF 不检查 query 参数（C2, 04f8f66）— DangerousCharacter + DirectoryTraversal
- CORS preflight 绕过 CSRF/WAF（C4, 72975a5）
- JSON body token 注入（C7, 8903cd4）— body token 提取限制为 POST/PUT/PATCH
- Signer HMAC verify 时序侧信道（D1, 4476395）— `subtle::ConstantTimeEq`
- HMAC 密钥未做 HKDF 派生（D2, 1599858）
- HTTP Digest 默认 MD5（D3, 0229d3f）— 默认 SHA-256
- sanitize_input 未过滤 Unicode Cf 字符（D4, 80d2f08）
- XSS whitelist 未阻止 `javascript:` URL（D5, 45a3146）
- Custom mask 未真实脱敏（D6, a79b5a4）
- 移除 [patch.crates-io] 本地路径覆盖（F1）
- examples 中硬编码 API Key（F2, 8932f3e）— 改用 env var
- 升级 opentelemetry 修复 CVE-2026-48504（F3, 7037764）
- SMS 验证码范围排除 `000000`（F4, 87c62ba)

### v0.7.1 发布前修复（2026-07-21）

- **MEDIUM**: 修复 vuln-0011 TokenRateLimiter doc fail-open（544c92f）— 文档更正为 fail-closed
- **MEDIUM**: 修复 vuln-0012 HttpDigestAuth validate_nc fail-open（544c92f）— 三路径返回 false + log sampling + realm 参数
- **HIGH**: 修复 ABAC 集成测试 handler 使用纯字面量表达式（c4b9706）— `validate_abac_expr` 拒绝纯字面量，改用 `principal == principal` / `principal != principal`
- **MEDIUM**: 修复 `SensitiveDataMasker::mask_value` 类型不一致（c4b9706）— `mask_value` / `mask_field` / `mask_json` 统一返回 `String`，Custom regex 编译失败时返回 `"***"` 作为安全 fallback（fail-closed，避免泄露原值）
- **LOW**: 修复 sqlite repo session/connection phase 错误消息格式不统一（b1635ee）— 41 处 map_err 改为 kebab-case i18n 格式
- **LOW**: 修复 ci.yml deadlinks 检查（b1635ee）— 移除 continue-on-error，添加正则过滤内部 deadlinks
- **LOW**: 修复测试断言 i18n 化（f0622aa）— sign_edge_cases 测试从中文 "签名" 改为英文 "mismatch"
- **LOW**: 修复 auth_server_integration.rs kickout/switch_to API 调用缺少 caller_login_id 字段（f0622aa）

### 审查验证（Convergence 阶段）

- 代码-文档一致性审查完成
- tiangang SAST 扫描：0 CRITICAL，1 HIGH（rsa crate CVE-2023-49092，受 `social-alipay` feature gate 隔离，可接受）
- diting 架构+性能审查：HIGH #1（OAuth2 限速器硬编码 MockDao）已修复（844eaef）
- kueiku bug 分析：3 个 HIGH（H1/H2/H3）已修复（24e1a1e / 235e98b / b21478b）
- 全量测试：2593 passed, 0 failed, 1 ignored
- clippy：零告警（`-D warnings`）
- 修复 commit 范围：`811ee10`..`171b7bd`（25 个 commit）
- 修复日期：2026-07-18

### i18n 迁移补全（specmark `i18n-hardcoded-to-icu`）

**触发**：FIN1 全量复测后发现 250+ 处遗漏硬编码中文未迁移，用户要求"全部都实现国际化能力"。

**补修内容**（4 个 commit）：

- `4ae8b31` i18n(ftl-mock)：补全 `dao-key-not-found` FTL key（11 处代码引用但 FTL 缺失）+ `src/stp/mock.rs` 2 处中文迁移 + `src/protocol/{sign,apikey}/mock.rs` 2 处 dao-key-not-found 添加 `::` 后缀
- `c3935a7` i18n(stp-session-parameter)：`src/stp/session.rs` 17 处硬编码中文迁移到 stp-* FTL key + `src/stp/parameter.rs` 2 处 + `src/stp/session.rs` 4 处 stp-dao-find-by-id → dao-key-not-found 统一 + 1 处 unknown token_style → stp-unknown-token-style + `src/stp/{tests,token}.rs` 5 处 SimpleTokenStyle feature 门 + 2 处断言失效修复
- `93a9c23` fix(session)：`renew_resets_ttl` flaky test 修复（TTL 3→5, margin 1→3，sleep 总时间不变）
- `1bc963f` fix(i18n)：kueiku review 修复 — `src/stp/token.rs` 4 处 stp-token-invalid-or-* 缺 `::` 后缀 + `src/stp/safe.rs` 2 处 stp-token-not-found 缺 token 参数 + `src/protocol/temp/tests.rs` 1 处 dao-key-not-found 参数化

**3 维度审查结果**：

- tiangang SAST：0 CRITICAL + 0 HIGH = ✅ 通过
- diting 架构：HIGH-1（15 处 stp- key 缺 `::` 后缀）+ 4 MEDIUM，全部修复后通过
- diting 性能：HIGH-1（Box::leak 内存泄漏，已有问题，不阻断）+ 3 MEDIUM（可接受）
- kueiku bug 分析：3 个 i18n bug（1 MEDIUM + 2 LOW）已全部修复

**最终验证**：

- `cargo test --features "db-sqlite,protocol-jwt,secure-simple-token"`：1395 passed, 0 failed
- `cargo clippy --features "db-sqlite,protocol-jwt,secure-simple-token" -- -D warnings`：0 warnings
- zh/en FTL key 各 591，成对一致（迁移前 524，本次新增 67）
- 4 个 commit 全部 pre-commit hook 通过（fmt + clippy×2 + cargo-deny + codespell + markdownlint）

### strix bulwark_e024 安全审查修复批次

**触发**：strix 渗透测试报告 `strix_runs/bulwark_e024/` 中 9 个漏洞（4 CRITICAL + 3 HIGH + 2 MEDIUM）+ tiangang SAST 审查 3 MEDIUM + 7 LOW。

**修复内容**（单批多 subagent 并行）：

- **CRITICAL**: 实现 SAML 签名验证（vuln-0001）— 新增 `XmlSecSamlProvider` + `verify_saml_signature()`，RSA-SHA256 / ECDSA-SHA256 算法白名单，拒绝 `rsa-1_5`，新增 `secure-saml` feature（`rsa` + `dep:base64`）
- **CRITICAL**: 添加 SAML Destination/Audience 校验（vuln-0002）— `expected_destination` / `expected_audience` builder + fail-loud 校验，`build_authn_request` 新增 `idp_sso_endpoint` 参数
- **CRITICAL**: 修复 Credential Repository IDOR（vuln-0004）— `find_by_user` / `update` / `delete` 新增 `caller_login_id` 参数 + ownership 校验 + user_id 不可变约束 + `tracing::warn!` 审计日志
- **HIGH**: 修复 SAML Assertion Replay TOCTOU（vuln-0003）— `check_assertion_replay` 改用 `dao.get_and_delete` 原子操作
- **HIGH**: 修复 Temp Credential Consume TOCTOU（vuln-0005）— `consume` 改用 `dao.get_and_delete` 原子操作
- **HIGH**: 修复 Rate Limit 滑动窗口 TOCTOU（vuln-0009）— 优先 `dao.eval_lua` Redis Lua 脚本原子路径，降级 `atomic_lock` 保护 read-modify-write（仅进程内原子，文档说明跨进程限制）
- **MEDIUM**: `compare_and_update_if_greater` `unwrap_or(0)` 改为显式报错（违反 Rule 12）— oxcache / MockDao 实现同步更新
- **MEDIUM**: `compare_and_update_if_greater` trait 默认实现改为返回 `NotImplemented`（强制后端重写以提供原子 CAS）— `AloneCache` 添加 forward 到 inner
- **MEDIUM**: `fallback_counter` 添加容量限制 `MAX_FALLBACK_ENTRIES=10000` + LRU 驱逐（`FALLBACK_EVICT_BATCH=100`）— 防 DAO 故障期间无限增长
- **LOW**: `constant_time_eq` 改用 `subtle::ConstantTimeEq`（消除长度泄漏）
- **LOW**: `verify_id_token` nonce 比较改用 `subtle::ConstantTimeEq`
- **LOW**: `check_and_incr_fallback` 窗口边界文档说明（DashMap shard 锁保证实际安全）
- **LOW**: `entry_count` O(n) 遍历文档说明 + MAX 上限保护
- **LOW**: `validate_inner` 添加 `MAX_AUTHORIZATION_HEADER_LEN=8KB` 输入长度校验（DoS 防护）
- **LOW**: `verify_id_token` 错误消息不泄露 token claim 信息
- **LOW**: `MockDao::keys` 添加 O(n) 复杂度说明文档

**3 维度审查结果**：

- tiangang SAST：0 CRITICAL + 0 HIGH = ✅ 通过
- diting 架构：3 CRITICAL（误报）+ 1 HIGH（误报）+ 1 MEDIUM + 1 LOW — 误报原因为审查未识别所有调用方已更新
- diting 性能：3 HIGH（误报）+ 3 MEDIUM + 2 LOW — 误报原因为 evict_oldest 仅在容量上限时触发（摊销开销）

**最终验证**：

- `cargo test --features "full" --lib`：3756 passed, 0 failed, 5 ignored（比基线 3722 增加 34 个新测试）
- `cargo clippy --features "full" --lib --tests -- -D warnings`：0 warnings
- 27 个文件修改（5 个新文件、22 个现有文件）

### strix bulwark_0792 安全审查修复批次

**触发**：strix 渗透测试报告 `strix_runs/bulwark_0792/` 中 3 个漏洞（1 HIGH + 2 MEDIUM）。

**修复内容**：

- **HIGH (vuln-0011, CVSS 6.5, DOC)**：`oauth2_server::TokenRateLimiter` doc 误写为 "Fail-Open"（实际行为是 fail-closed，由 vuln-0007 fallback_counter 提供）— 修正 doc 表述为 "Fail-Closed"，消除文档与代码行为不一致
- **MEDIUM (vuln-0012, CVSS 6.5, CODE)**：`secure::httpdigest::HttpDigestAuth::validate_nc` 在 DAO 错误 / 无 tokio runtime / current_thread runtime 三条路径下 fail-open（返回 true 允许重放），违背 RFC 7616 §3.4.6 — 全部改为 fail-closed（返回 false 拒绝请求）；新增 no-runtime fail-closed 测试用例；应用日志采样（`DAO_ERROR_LOG_INTERVAL=100`）防止 DAO 持续故障期间日志洪水；补充 dao=None 路径安全代价说明、worker pool 容量规划、运维 P1 告警等文档
- **vuln-0001 (FALSE POSITIVE)**：strix 报告 `JwtHandler::with_algorithm` 接受 `Algorithm::None` 导致签名绕过 — 经核查 `jsonwebtoken 10.0.0` 的 `Algorithm` enum 不存在 `None` variant（仅有 HS256/HS384/HS512/ES256/ES384/RS256/RS384/RS512/PS256/PS384/PS512/EdDSA），无修复必要

**架构修复**（Rule 26 三维度审查发现）：

- HIGH-1：strix 编号 vuln-0002/vuln-0003 与既有 SAML vuln-0002/vuln-0003 冲突 — strix 发现重编号为 vuln-0011/vuln-0012
- MEDIUM-arch：移除 `oauth2_server::token::PasswordRateLimiter::check/record_failure` doc 中对 `HttpDigestAuth::validate_nc` 的跨层耦合引用（"Fail 策略说明"整段），每个模块只描述自身行为
- MEDIUM-arch：移除 mod.rs 中 `dao` 字段的实现细节 doc（Key 格式、TTL 策略），改为指向 `auth::validate_nc` 文档（规则 25 接口隔离）
- MEDIUM-perf：DAO 错误日志采样（每 100 次 warn 一次，其余降级 debug）
- LOW-arch：明确 dao=None 路径安全代价（300s 窗口内可重放）+ 容量规划 + 运维注意
- LOW-sec：补充 no-runtime fail-closed 测试用例

**3 维度审查结果**：

- tiangang SAST：0 CRITICAL + 0 HIGH = ✅ 通过
- diting 架构：HIGH-1（vuln 编号冲突）+ 2 MEDIUM（跨层耦合 + 接口层泄露）+ 1 LOW，全部修复后通过
- diting 性能：1 MEDIUM（日志洪水）已修复
- kueiku bug 分析：无新增 bug

**最终验证**：

- `cargo test --features "secure-httpdigest oauth2-server"`：所有测试通过
- `cargo clippy --features "secure-httpdigest oauth2-server" -- -D warnings`：0 warnings

### Changed (0.7.x Phase 1 - cargo feature 划分优化)

本期为 **cargo feature 划分优化 Phase 1（保守，0.7.x 兼容）**，基于 kueiku 决策分析（方案 B 分层重构 + 渐进式迁移）实施。无破坏性变更，0.7.x 内向后兼容。

#### Added

- 新增 `i18n` 基础 feature（空 stub）— API 语义占位，允许用户在 Cargo.toml 中显式声明 `features = ["i18n"]` 表达"启用基础国际化"语义。基础层（translate_error / loc! 宏 / FTL 文件加载）已无条件编译，此 feature 不改变编译行为。
- `i18n-icu` 现显式依赖 `i18n`（`i18n-icu = ["i18n", ...]`），形成清晰的"基础层 + 增强层"依赖关系。

#### Deprecated

- `all-defaults` 聚合特性标记为 DEPRECATED — 与 `development` 聚合特性完全重复（均 = `["cache-memory", "db-sqlite", "web-axum"]`）。0.8.0 将删除，请改用 `development`。

#### Documented

- 审查确认 `protocol-apikey` / `protocol-temp` / `secure-xss` / `secure-sanitize` 4 个 feature 均有实际 `#[cfg(feature = "...")]` 门控（如 `src/protocol/mod.rs:32,36` / `src/secure/mod.rs:108,124`），**不是占位特性**，启用后编译对应模块。原 Phase 1 草案误标为 PLACEHOLDER，已修正回正常 feature 注释。
- `i18n` feature 标注修正为"启用后编译 i18n 相关测试代码"（src 中有 8 处 `#[cfg(feature = "i18n")]` 测试门控，与运行时行为无关）。

### 0.8.0 重命名计划预告（破坏性变更）

0.8.0 将执行 cargo feature 重新划分 Phase 2（方案 B 分层重构），包含以下破坏性变更（旧名作为 alias 保留至 0.9.0）：

| 0.7.x 旧名 | 0.8.0 新名 | 理由 |
|-----------|-----------|------|
| `rate-limit-redis` | `firewall-ratelimit-redis` | 依赖 firewall-ratelimit，应统一命名空间 |
| `anomalous-detector-dual` | `firewall-anomalous-detector` | 依赖 firewall，应统一命名空间 |
| `secure-simple-token` | `auth-server-simple-token` | auth-server 专用，不应位于 secure-* 命名空间 |
| `oauth2-scope-handler` | `protocol-oauth2-scope-handler` | 应统一 protocol-* 命名空间 |
| `audit-log` | `audit-log-listener` | 与 `audit-inklog` 区分（事件监听 vs 日志管理） |
| `all-defaults` | （删除） | 与 `development` 重复 |
| `firewall-maxminddb` | （合并入 `firewall-geoip`） | 前者仅是后者生产后端 |

详见 `docs/decisions/A-011-cargo-feature-reorganization.md`（待 0.8.0 创建）。

### Fixed (0.7.1 CI/CD 修复批次)

**触发**：v0.7.1 预发布 CI 全量失败，根因涉及 cargo-audit/cargo-deny 配置漂移、rustc 1.85.1 编译器 bug、sdforge `#[forge]` 宏 cfg 上下文错配。

**修复内容**（6 个 commit）：

- `d5759d9`..`b4d8ada` — ci.yml workflow 重建：恢复完整 CI 流水线 + 修复 protoc 缺失 / cargo-deny-action SHA pin / cargo-audit `--ignore-source` 参数已移除 / `--test '*'` 改用 `--tests` 避免 required-features 报错
- `02a419b` — 删除冗余 audit job（cargo-deny 已覆盖漏洞检查）+ deny.toml 添加 RUSTSEC-2026-0173（proc-macro-error2 unmaintained）+ 移除 Unicode-DFS-2016（已被 Unicode-3.0 替代）+ sdforge_routes.rs 添加 `#![allow(dead_code)]` 抑制 lib 编译时 inventory 注册路由的 dead code 警告
- `f26c707` — Token::generate 改用 UFCS 完整路径调用，绕过 rustc 1.85.1 对 `use Trait as _` 的 unused import 误报（1.96.0 已修复）
- `6e1ba9a` — **CRITICAL** 修复 sdforge `#[forge]` 路由注册失效：`#[forge]` 宏生成的 `inventory::submit!(RouteRegistration::new(...))` 被 `#[cfg(feature = "http")]` 保护，此 cfg 在 bulwark 上下文求值（不是 sdforge）。bulwark 缺少 `http` feature → submit 调用被 cfg 剥离 → `sdforge::http::build()` 收集不到任何路由 → 所有 29 个 sdforge_routes 测试 HTTP 404（production 代码也受影响）。修复：在 `[features]` 添加 `http = []` 桥接 feature（cfg flag only），让 `auth-server-sdforge = ["http"]`。sdforge/http 已由依赖声明无条件启用，此 feature 仅作 bulwark 侧的 cfg 开关。

**最终验证**：

- `cargo test --features full --lib`：3787 passed, 0 failed, 5 ignored（之前 3755 passed / 32 failed）
- `RUSTFLAGS="-D warnings" cargo clippy --features full --lib --tests`：0 warnings
- `cargo fmt --check`：clean
- `cargo deny check`：advisories ok, bans ok, licenses ok, sources ok
- `cargo check --no-default-features --features default`：通过（无 sdforge 依赖回归）

## [0.7.0] - 2026-07-13

### 概述

v0.7.0 微服务架构 + ABAC/Cedar + OAuth2 Server + 依赖优化 + 架构加固。通过 specmark `v0.7.0-microservice-abac-oauth2-hardening` change 管理，252 个 TDD 任务覆盖 7 个能力域。tiangang SAST 0 CRITICAL，diting 88/100（0 CRITICAL + 0 HIGH），2968 测试通过，满足发布门禁。

### 新增

#### D1: 架构加固

- 错误类型统一：全代码库使用 `BulwarkError` / `BulwarkResult`，0 违规
- mod.rs 加固：Mock 代码迁移到独立 `mock.rs` 文件，impl 块迁移到 `impl.rs` / `*_impl.rs`
- `secure-sanitize` feature：通用输入消毒 `sanitize_input()` 函数（null 字节 / 控制字符移除 + 长度限制）

#### D3: 微服务架构

- `backend-remote` feature：远程后端适配器（HTTP API 调用）
- `server/external.rs` + `server/internal.rs`：外部/内部 API 服务器
- `src/bin/auth_server.rs`：独立认证服务器二进制
- `BulwarkAuthServer::with_tenant_resolver` builder：注入 `TenantResolver`，启用 `tenant_resolution_middleware`（`tenant-isolation` feature 门控）

#### D4: ABAC/Cedar DSL

- `abac` feature：基于 Cedar DSL 的属性访问控制引擎
- `src/abac/engine.rs`：ABAC 引擎核心
- `src/abac/policy.rs`：策略解析与评估

#### D5: OAuth2 Server

- `oauth2-server` feature：完整 OAuth2 Server 实现
- `/oauth2/authorize`：授权码流程 + PKCE 强制（S256）
- `/oauth2/token`：4 种 grant type（authorization_code / refresh_token / client_credentials / password）
- `/oauth2/revoke`：RFC 7009 token 撤销
- `/oauth2/introspect`：RFC 7662 token 内省
- redirect_uri 白名单精确匹配 + state 参数 CSRF 防护
- `register_oauth2_client` helper：e2e 测试辅助函数，封装 tenant 上下文 + `OAuth2ClientStore::create`（简化测试用例客户端注册）

#### D7: 安全审查

- tiangang SAST：0 CRITICAL（Semgrep 331 rules + cargo-audit）
- diting 代码审查：0 真实 HIGH（88/100 score）
- security.md 10 维度安全检查全部通过
- 输入消毒 `sanitize_input()` + 响应体 4KB 限制 + zeroize 敏感数据

### 优化

#### D2: 依赖优化

- clippy 零告警（全模式 + 特性组合）
- cargo doc 零告警
- 特性组合测试：10 种组合全部通过
- cargo-audit：rsa Marvin Attack 显式忽略（仅使用签名，非解密）

#### D6: 质量提升

- 特性组合测试：backend-embedded / backend-remote / auth-server / abac / oauth2-server 等组合
- clippy + doc 告警清理
- 2968 测试通过（lib + examples + integration + doc-tests）

### 修复

- 6 个 SessionData 初始化缺少 `dynamic_active_timeout` / `is_anon` 字段
- examples dbnexus 0.3→0.4 升级 + dbnexus/sqlite feature 传递
- examples oxcache/redis feature 传递
- 11 个 clippy bool_assert_comparison 告警（rust 1.96.0 新规则）
- `test_check_safe_default_returns_true` → `false`（safe-auth feature 下行为变更）
- GitHub Actions mutable tag 修复（docs.yml 固定 SHA + codeql.yml nosemgrep）

## [0.6.7] - 2026-07-13

### 概述

v0.6.7 安全与性能增强，实施 5 个能力域：forbid 优先语义、WAF 级防火墙、三层缓存架构、SMS 验证码渐进式限速、AnomalousLoginDetector 双引擎。通过 specmark `v0.6.7-waf-safe-defaults-cache-sms-anomalous` change 管理，31 个 TDD 任务 + Phase 2.1/4.1/5.1 审计修复 + Phase 6 一致性修复完成。Phase 6 一致性检查 91%（29/31 需求正确实现），修复 3 个不一致项（D3-1 logout 缓存失效集成 + D5-1 interval 校验 + D5-3 spec 同步）。diting 最终审计 88 分（0 CRITICAL + 0 HIGH），tiangang SAST 0 CRITICAL，满足发布门禁。

### 新增

#### D1: forbid 优先语义（`safe-defaults` feature）

- `DecisionCombinator::combine` 在空决策列表时返回 `Deny(NoMatchingPermission)`（fail-closed）
- `BulwarkPermissionStrategyDefault` 在 `check_permission` / `check_role` 无记录时返回 `Deny` 而非 `Allow`
- 安全默认语义：未明确授权的资源默认拒绝访问

#### D2: WAF 级防火墙（`firewall-waf` feature）

- 新建 `src/strategy/firewall/waf.rs` 模块：`WafEngine` + `WafContext` + `WafVerdict`
- 新建 `src/strategy/firewall/waf_hooks.rs` 模块：9 个 WAF Hook
  - `WhitePathHook` / `BlackPathHook`：路径白名单/黑名单
  - `HostHook`：Host 头白名单
  - `HttpMethodHook`：HTTP 方法白名单
  - `ParameterHook`：参数名黑名单
  - `BannedCharacterHook` / `DangerCharacterHook`：危险字符检测
  - `DirectoryTraversalHook`：路径遍历检测（`../`、`./`、`//`、`%2e`、`%2f`、`%00`）
  - `HeaderHook`：请求头黑名单检测
- `WafEngine::evaluate` 按 Hook 注册顺序执行，`AllowAndSkip` 短路
- Phase 2.1 审计修复：WhitePathHook 百分号编码兜底 + BlackPathHook 前缀混淆防护

#### D3: 三层缓存架构（`three-tier-cache` feature）

- 新建 `src/cache/three_tier.rs` 模块：`UserCacheService`
- L1（oxcache 内存缓存）→ L2（DAO 持久化缓存）→ L3（interface 回调）三层递进查询
- `get_permissions` / `get_roles` / `get_user` 三层缓存方法
- `invalidate(login_id)` 失效用户所有缓存（L1 + L2）
- `BulwarkConfig` 新增 `l1_cache_ttl_secs`（默认 30）/ `l2_cache_ttl_secs`（默认 300）/ `l1_cache_capacity`（默认 10000）
- `BulwarkLogicDefault` 新增 `user_cache_service` 字段 + `with_user_cache_service` builder
- `logout` / `logout_by_login_id` 在 `three-tier-cache` feature 启用时调用 `invalidate` 失效用户缓存
- `BulwarkManager::init` 自动构造 `UserCacheService` 并注入

#### D4: SMS 验证码渐进式限速（`sms-rate-limit` feature）

- 新建 `src/secure/sms/mod.rs` 模块：`SmsCodeService` + `SmsRateLimiter`
- 双窗口限速：分钟窗口（默认 1 次）+ 小时窗口（默认 5 次）
- 渐进式退避：超限后锁定时长递增（30s → 60s → 300s → 1800s）
- 通道回收：未验证验证码超阈值（默认 3）时回收通道
- `BulwarkDao::incr` 原子递增计数器（`BulwarkDaoOxcache` 用 `atomic_lock` 重写）
- 验证码使用 `OsRng` 密码学安全随机数生成
- Phase 4.1 审计修复：decrement_counter 容错 + phone 校验强化

#### D5: AnomalousLoginDetector 双引擎（`anomalous-detector-dual` feature）

- 新建 `src/strategy/firewall/anomalous_analyzer.rs` 模块：`AnomalousLoginAnalyzer`
- 定时分析引擎：`tokio::spawn` + `tokio::time::interval` + shutdown watch channel
- 三种异常检测：
  - burst 登录检测（1 小时窗口内登录次数 > `burst_threshold`）
  - 异地跳变检测（不同 geo > 2）
  - 设备指纹突变检测（不同 device > 3）
- `AnomalousLoginRecord` 登录记录持久化（TTL 24h，纳秒精度 key 避免同秒覆盖）
- `BulwarkEvent::AnomalousLoginDetected` 事件变体 + audit.rs 记录
- `BulwarkDaoOxcache` 新增 `key_index: RwLock<HashSet<String>>` 实现 `keys()` 方法（oxcache 0.3.3 无原生 iter API）
- `BulwarkConfig` 新增 `anomalous_analyzer_interval_secs`（默认 3600）/ `anomalous_analyzer_burst_threshold`（默认 5）
- `MAX_SCAN = 10000` DoS 防护 + 扫描耗时 > 1s 告警
- Phase 5.1 审计修复：CRIT-001 keys() 实现 + HIGH-001 扫描监控 + HIGH-002 纳秒 key

### 修复

- Phase 6 一致性检查修复：
  - D3-1 (P0): `logout` / `logout_by_login_id` 集成 `UserCacheService::invalidate()`（R-three-tier-cache-005）
  - D5-1 (P1): `anomalous_analyzer_interval_secs` 校验从 `== 0` 改为 `< 60`（对齐 spec R-007）
  - D5-3 (P2): spec R-001 存储键描述更新为纳秒精度
- `audit.rs` 处理 `AnomalousLoginDetected` 事件变体（`_` wildcard + `#[cfg] if let` 覆盖）
- `listener` 块 `login_id` 从 move 改为 `as_ref()` 避免 full feature 编译错误
- examples `sso_server.rs` subscribe 签名 `Fn(&str)` → `Fn(String)` 对齐 trait 定义

### 测试

- `cargo test --features full --lib` → 2404 passed, 0 failed
- 新增 6 个测试：3 个 three-tier-cache 集成测试 + 3 个 config validate 测试
- Phase 5 新增 27 个 anomalous_analyzer 测试

### 审计

- diting 最终审计：88/100（0 CRITICAL + 0 HIGH），满足发布门禁
- tiangang SAST：0 CRITICAL，满足 Rule 19 发布门禁
- kueiku FMEA 跨 phase 分析：12 个失效模式识别，WAF 大小写敏感问题记录为 v0.6.8 tech debt

## [0.6.6] - 2026-07-12

### 概述

v0.6.6 会话管理增强，实施 6 个能力域：并发登录策略细化、从请求体读取 Token、动态 Active-Timeout、login_token_map 持久化双层、匿名 Session、会话搜索。通过 specmark `v0.6.6-concurrent-login-session-search-anon-rotation` change 管理，33 个 TDD 任务 + Phase 审计修复完成。Phase 4 审计 2 个 HIGH（persistent 方法缺锁 + last_active_at 未更新）+ Phase 5 审计 2 个 HIGH（匿名 token 路由 + TOCTOU 竞态）+ Phase 6 审计 2 个 HIGH（DoS 防护 + 反序列化容错），均已修复。

### 新增

#### D1: 并发登录策略细化

- `ReplacedLoginExitMode` 枚举（`OldDevice`/`NewDevice`）：`is_concurrent=false` 时新设备登录的行为控制
- `OverflowLogoutMode` 枚举（`Logout`/`Kickout`/`Replaced`）：`max_login_count` 超限时的处理策略
- `BulwarkConfig` 新增 `replaced_login_exit_mode`（默认 `OldDevice`）+ `overflow_logout_mode`（默认 `Logout`）
- 环境变量覆盖 `BULWARK_REPLACED_LOGIN_EXIT_MODE` / `BULWARK_OVERFLOW_LOGOUT_MODE`

#### D2: 从请求体读取 Token

- `BulwarkConfig` 新增 `is_read_body: bool` 字段（默认 false，向后兼容）
- 环境变量覆盖 `BULWARK_IS_READ_BODY`
- axum/actix/warp 三个 adapter 的 `extract_token` 方法增加 body 读取分支
- `Content-Type: application/json` 时从 body JSON `{token_name}` 字段提取 token

#### D3: 动态 Active-Timeout（`dynamic-active-timeout` feature）

- `TokenSession` 新增 `dynamic_active_timeout: Option<i64>` 字段（feature-gated + `#[serde(default)]`）
- `set_active_timeout(token, timeout_secs)` 方法：per-token 自定义活跃超时
- `check_active_timeout` 优先使用 `dynamic_active_timeout`，`None` 时回退全局 `active_timeout`

#### D4: login_token_map 持久化双层（`login-token-map-persistence` feature）

- `BulwarkConfig` 新增 `login_token_map_persist_interval_secs: u64`（默认 0=同步写入）
- `rebuild_login_token_map()` 方法：从 DAO 重建内存 DashMap（重启恢复）
- `add_login_token_persistent` / `remove_login_token_persistent`：DAO + 内存双层写入
- `create` / `logout` 已实现双层写入（DAO AccountSession.tokens + 内存 DashMap）
- Phase 4 审计修复：persistent 方法用 `with_login_lock` 包裹 + 更新 `last_active_at`

#### D5: 匿名 Session（`anonymous-session` feature）

- 新建 `src/session/anon.rs` 模块
- `get_anon_token_session(token)`：获取或创建匿名 Session（`login_id=""`, `is_anon=true`）
- `is_anon(token)`：判断是否为匿名 Session
- `logout_anon(token)`：注销匿名 Session（幂等）
- Key 空间隔离：`token:session:anon:{token}` vs 登录 Session `token:session:{token}`
- `TokenSession` 新增 `is_anon: bool` 字段（feature-gated + `#[serde(default)]`）
- `BulwarkConfig` 新增 `anon_session_timeout: u64`（默认 1800=30 分钟）
- `logout` 方法入口检测匿名 token 并路由到 `logout_anon`
- Phase 5 审计修复：`get_anon_token_session` 用 `with_token_session_lock` 包裹 + 输入校验

#### D6: 会话搜索（`session-search` feature）

- 新建 `src/session/search.rs` 模块
- `SearchSortType` 枚举（`CreatedAsc`/`CreatedDesc`/`LastActiveAsc`/`LastActiveDesc`）
- `search_token_value(keyword, start, size, sort_type)`：按 token 值搜索 Token-Session
- `search_session_id(keyword, start, size, sort_type)`：按 login_id 搜索 Account-Session
- `search_token_session_id(keyword, start, size, sort_type)`：按 TokenSession.login_id 搜索 token
- 支持分页（start/size）和排序，排除匿名 Session
- Phase 6 审计修复：MAX_SCAN 上限防 DoS + 反序列化容错跳过 + 输入校验

### 审计记录

- **Phase 1 审计**（diting 92/100 Approved）
- **Phase 2 审计**（HIGH 已修复：body 读取安全）
- **Phase 3 审计**（diting 71/100 Approved with Changes）
- **Phase 4 审计**（diting 85/100，HIGH-001 persistent 方法缺锁 + MED-001 last_active_at 未更新，已修复）
- **Phase 5 审计**（diting 85/100，HIGH-001 匿名 token 路由 + tiangang HIGH-001 TOCTOU 竞态，已修复）
- **Phase 6 审计**（diting 66→修复后通过，HIGH-001 DoS 防护 + HIGH-002 反序列化容错，已修复）

## [0.6.5] - 2026-07-12

### 概述

v0.6.5 安全告警 + 设备绑定 + 封禁库 + 二级认证 + Token 清理，实施 5 个能力域：安全告警系统、设备绑定策略、封禁库实现、二级认证瞬态标记、login_token_map 自动清理。通过 specmark `v0.6.5-security-alert-device-binding-disable-safe-auth-cleanup` change 管理，30 个原始任务 + M-002 收敛修复完成。Phase 4 审计发现 2 个 HIGH（service 参数校验 + token 泄露）+ Phase 5 审计 3 个 MEDIUM，均已修复。

### 新增

#### D1: 安全告警系统（`security-alert` feature）

- 新建 `src/strategy/alert/mod.rs`，定义 `SecurityAlertEvent` 枚举（AnomalyLogin/NewDeviceLogin/DisableTriggered/PrivilegeEscalation/SensitiveOperation）+ `AnomalyType` 枚举（IpChanged/DeviceChanged/GeoJump/RapidSuccessiveLogin）
- `AlertListener` trait + `AlertListenerManager`：广播告警事件，单个 listener 失败只 warn 不中断
- `AnomalyDetector` trait + `IpChangeDetector`（IP 变更检测）+ `RapidSuccessiveDetector`（快速连续登录检测）
- `TracingAlertListener`：tracing::warn! 记录告警；`AuditAlertListener`：写入审计日志到 DAO
- 集成到 `session.rs` login/check_login，检测失败不中断主流程
- 34 个单元测试

#### D2: 设备绑定策略（`device-binding` feature，依赖 `security-alert`）

- 新建 `src/strategy/device_binding/mod.rs`，定义 `DeviceBindingPolicy` trait
- 3 种策略：`StrictBinding`（新设备触发 MFA）、`LooseBinding`（新设备告警不阻断）、`Disabled`（关闭）
- `LoginParams` 新增 `require_mfa: bool` 字段
- 集成到 login 流程：新设备 + require_secondary_auth=true 时设置 require_mfa
- `BulwarkConfig` 新增 `device_binding_mode`（默认 "disabled"）
- 24 个单元测试

#### D3: 封禁库实现

- 新建 `src/account/disable/mod.rs` + `repository.rs`，定义 `DisableEntry` struct + `DisableRepository` trait
- `DefaultDisableRepository`：`disable`/`untie_disable`/`is_disable`/`get_disable_time`/`get_disable_level`
- 阶梯封禁：`level` 字段支持分级阻断（level=0 普通，level=1/2/3 分级）
- key 格式 `disable:{service}:{login_id}`，永久封禁 duration_secs=0
- `MfaLogic::check_disable()` 默认实现：从 `DisableRepository` 查询封禁状态
- `BulwarkManager` 注册 `DisableRepository`，`disable_repository()` 方法获取实例
- 30 个单元测试

#### D4: 二级认证瞬态标记（`safe-auth` feature）

- `TokenSession` 新增 `safe_services: HashMap<String, i64>` 字段（service → 过期时间戳）
- `BulwarkLogicDefault` inherent method：`open_safe`/`is_safe`/`close_safe`
- service 级瞬态标记：多 service 独立、覆盖更新、duration_secs=0 立即过期
- `check_safe()` 默认实现改为调用 `is_safe("default")`
- Phase 4 审计修复：service 空值校验 + token 前缀脱敏（`&token[..8]`）
- 19 个单元测试

#### D5: login_token_map 自动清理

- `BulwarkSession::cleanup_expired_tokens()`：扫描 login_token_map，移除过期/已注销 token
- DashMap 策略：先 collect keys 快照，再逐个检查，retain 保留并发新增的 token
- `spawn_cleanup_task()`：tokio::spawn 后台定时清理，interval_secs<=0 不启动
- `BulwarkConfig` 新增 `token_map_cleanup_interval_secs`（默认 300，-1 禁用）
- `BulwarkManager::init` 集成：启动后台 task，Drop/reset_for_test 时 abort
- Phase 5 审计修复 M-002：abort 旧 task 移到 spawn 之前，消除重叠窗口
- 20 个单元测试

### 审查与修复

#### Phase 4 审计（diting + tiangang）

- **HIGH-001 修复**：`open_safe`/`is_safe`/`close_safe` 未校验 service 空值 → 新增 `InvalidParam` 校验
- **HIGH-002 修复**：错误消息暴露完整 token → 改为 `&token[..8]` 前缀脱敏（与 `core/auth/mod.rs` 一致）
- tiangang SAST：0 CRITICAL，0 findings

#### Phase 5 审计（diting + tiangang）

- **M-002 修复**：`init_with_factory_selector` 新旧 cleanup task 短暂重叠 → abort 移到 spawn 之前
- M-001/M-003 延后：cleanup 频率自适应 / 清理统计 metrics（非阻断优化）
- tiangang SAST：0 CRITICAL，0 HIGH

### Breaking Changes

无。所有新功能通过 feature gate 控制，默认不启用：

- `security-alert = []`
- `device-binding = ["security-alert"]`
- `safe-auth = []`

均已注册到 `full` feature 列表。

## [0.6.4] - 2026-07-11

### 概述

v0.6.4 Web 安全中间件 + 分布式限流，实施 5 个能力域：WAF 请求内容校验、CORS 跨域中间件、CSRF 防护、响应 Token 自动写入、Redis 限流后端。通过 specmark `v0.6.4-waf-cors-csrf-response-token-redis-ratelimit` change 管理，31 个原始任务 + 9 个 converge 收敛任务完成（共 40 个）。diting 审查发现 2 个 HIGH 问题（Cookie 安全配置缺失）+ 1 个 MEDIUM（环境变量静默忽略），已修复。

### 新增

#### D1: WAF 请求内容校验（`web-waf` feature）

- 新建 `src/web/waf.rs` 模块，定义 `WafRule` trait（`async fn check(&self, ctx: &WafContext) -> BulwarkResult<()>`）+ `WafContext` struct
- 5 个内置规则：`DangerousCharacter`（检测 `//`/`\`/`%2e`/`%2f`/`;`/`\0`/`\n`/`\r`）、`DirectoryTraversal`（`./`/`../`/`..%2f`/`..%5c`）、`PathWhitelist`、`PathBlacklist`、`HttpMethodWhitelist`
- `bulwark_waf_middleware` axum 中间件，遍历规则链，任一拒绝返回 400
- `BulwarkConfig` 新增 `waf_config: WafConfig`（enabled/path_whitelist/path_blacklist/check_dangerous_chars/check_directory_traversal/allowed_methods）
- 33 个单元测试

#### D2: CORS 跨域中间件（`web-cors` feature）

- 新建 `src/web/cors.rs` 模块，定义 `CorsConfig`（allowed_origins/allowed_methods/allowed_headers/exposed_headers/allow_credentials/max_age_secs）
- `bulwark_cors_middleware`：preflight（OPTIONS）请求注入 `Access-Control-Allow-*` 头返回 204；实际请求注入 `Access-Control-Allow-Origin/Expose-Headers`
- `CorsConfig::validate()`：`allow_credentials=true` 且 `allowed_origins` 含 `*` 时返回 Err
- `BulwarkConfig` 新增 `cors_config: CorsConfig`
- 29 个单元测试

#### D3: CSRF 防护（`web-csrf` feature）

- 新建 `src/web/csrf.rs` 模块，实现 Double-Submit Cookie 模式
- `generate_csrf_token()`：32 字节 OsRng → URL-safe Base64（~43 字符）
- `validate_csrf_token(header_token, cookie_token)`：常量时间比较（不提前返回，长度差异单独追踪）
- `bulwark_csrf_middleware`：安全方法（GET/HEAD/OPTIONS）懒生成 token 设置 Cookie；保护方法（POST/PUT/PATCH/DELETE）校验 header==cookie，不一致返回 403
- `CsrfConfig`：enabled/cookie_name/header_name/excluded_paths/protected_methods/cookie_secure
- `BulwarkConfig` 新增 `csrf_config: CsrfConfig`
- 25 个单元测试

#### D4: 响应 Token 自动写入

- `src/stp/context.rs` 新增 `get_renewed_token() -> Option<String>` + `clear_renewed_token()`
- `BulwarkConfig` 新增 `is_write_cookie: bool`（默认 false，`is_write_header` 已存在）
- `bulwark_middleware` 修复：handler 执行包裹 `with_renewed_token_scope`（v0.6.3 遗漏，导致续签 task_local 无效）
- 续签 Token 按 `is_write_header`/`is_write_cookie` 写入响应头（`config.token_name`）或 Set-Cookie（`HttpOnly; Path=/; SameSite=<config>; Secure=<config>`）
- 17 个单元测试

#### D5: Redis 限流后端（`rate-limit-redis` feature）

- 新建 `src/strategy/rate_limiter_backend.rs`，定义 `RateLimiterBackend` trait（`try_acquire` / `try_acquire_n`）
- `RateLimitBackend` 枚举（Memory / Redis { redis_url }）
- `TokenBucketRateLimiter` 实现 `RateLimiterBackend`（委托现有方法）
- 新建 `src/strategy/redis_rate_limiter.rs`，`RedisRateLimiter` 使用 Lua 脚本原子令牌桶（HMGET→refill→compare→HMSET→EXPIRE）
- `BulwarkConfig` 新增 `rate_limit_backend: RateLimitBackend`（默认 Memory）
- 30 个单元测试

### 审查与修复

#### diting Full Review

- **A1 [High] 修复**：`router/mod.rs` Cookie 写入硬编码 `SameSite=Lax`，忽略 `config.cookie_secure` / `config.cookie_same_site` → 改为读取 config
- **A2 [High] 修复**：`csrf.rs` `build_set_cookie` 硬编码无 `Secure` 标志 → `CsrfConfig` 新增 `cookie_secure` 字段，`build_set_cookie` 支持 Secure
- **A4 [Medium] 修复**：`redis_rate_limiter.rs` `prepare_script_args` 返回值被丢弃 + 时间戳不一致 → `try_acquire_n` 内联构建参数，`prepare_script_args` 标注 `#[cfg(test)]`
- **A3 [Medium] 延后**：WAF 每请求重建规则链的堆分配优化（非阻断）
- **MED-001 [Medium] 修复**：`BULWARK_RATE_LIMIT_BACKEND` 未知值静默忽略 → 改为返回 `BulwarkError::Config`（规则12：失败必须显性化）

#### specmark Converge（T032-T040）

第 1 轮 converge 发现 12 个缺口，追加 9 个收敛任务；第 2 轮 converge 无新缺口：

- **T032**：CSRF 空 token 返回 false（常量时间比较前显式检查）
- **T033**：HTTP method 大小写敏感（RFC 7230，移除 `to_uppercase()`）
- **T034**：CORS OPTIONS 短路返回 204（非匹配 Origin 不 passthrough）
- **T035**：WafConfig 支持 `custom_rules: Vec<Arc<dyn WafRule>>`
- **T036**：`validate()` 校验 Redis `redis_url` 非空
- **T037**：Redis 限流器错误类型改为 `BulwarkError::Dao`
- **T038**：Lua else 分支补充 EXPIRE 防止 key 内存泄漏
- **T039**：环境变量覆盖（CORS/CSRF/RateLimit 4 个变量）
- **T040**：spec 更新 Set-Cookie 含 SameSite/Secure（匹配更安全代码）

#### tiangang SAST

- 0 CRITICAL — 发布门禁通过
- 2 High 均为误报（oidc.rs 测试 mock JWT token）
- 18 Medium：17 个 GitHub Actions 供应链（预存）+ 1 个 RUSTSEC-2023-0071 rsa Marvin Attack（预存依赖漏洞）

### 验证

- 全量测试：2295 passed, 0 failed, 90 ignored（+377 新增 vs v0.6.3 的 1918）
- clippy：full + production features 零警告
- cargo doc：零警告（修复 26 个 unresolved link：17 v0.6.4 新增 + 9 pre-existing）
- pre-commit hooks：全部通过
- specmark converge：2 轮收敛，第 2 轮 0 缺口，已归档

### 已知限制

- WAF 中间件每请求重建规则链（Vec + Box 堆分配），高流量场景可优化为预构建 `Arc<Vec<Box<dyn WafRule>>>`
- Redis 限流器单元测试不依赖真实 Redis 连接，仅验证 Lua 脚本逻辑和参数组装
- RUSTSEC-2023-0071（rsa 0.9.10 Marvin Attack）为预存依赖漏洞，非 v0.6.4 引入，后续版本处理

## [0.6.3] - 2026-07-11

### 概述

v0.6.3 会话生命周期管理增强，实施 4 个能力域：Token 自动续签、并发登录控制、Refresh Token 轮换公共 API、设备管理。通过 specmark `v0.6.3-token-renewal-concurrency-refresh-device` change 管理，27 个任务完成。diting 审查发现 2 个 HIGH 问题（并发续签竞态 + enforce 失败会话泄漏），已修复。

### 新增

#### D1: Token 自动续签（`auto_renewal_threshold`）

- `BulwarkConfig` 新增 `auto_renewal_threshold: i64`（默认 -1 不启用，范围 -1 或 0-100）
- `BulwarkLogicDefault::check_and_renew` 在 `check_login` 路径中检查剩余 TTL 百分比，低于阈值时自动续签
- 非 JWT 模式调用 `renew_to_equivalent`，JWT 模式调用 `refresh_token`
- 续签结果通过 `CURRENT_RENEWED_TOKEN` task_local 传递给 Web 框架 middleware
- `BulwarkJwtClaims` 新增 `jti` (RFC 7519 §4.1.7) UUID 声明，保证同一秒内签发的 token 唯一
- 环境变量 `BULWARK_AUTO_RENEWAL_THRESHOLD` 覆盖支持

#### D2: 并发登录控制（`is_concurrent` / `is_share` / `max_login_count`）

- `BulwarkConfig` 新增 `is_concurrent: bool`（默认 true）/ `is_share: bool`（默认 false）/ `max_login_count: u32`（默认 0 不限制）
- `validate()` 校验 `is_share=true` 时 `is_concurrent` 必须为 true
- `is_share=true`：复用现有有效 token（touch + return），不创建新会话
- `is_concurrent=false`：登录前踢出所有现有会话
- `max_login_count > 0`：登录后强制最大数量，按 `last_active_at` 升序踢出最旧会话
- `BulwarkSession` 新增 `login_token_map: DashMap<String, Vec<String>>` 内存索引，支持快速查询

#### D3: Refresh Token 轮换公共 API

- `SessionLogic` trait 新增 `refresh_access_token(&self, refresh_token: &str) -> BulwarkResult<(String, String)>` 方法
- `BulwarkLogicDefault` 实现委托 `RefreshTokenRotation::rotate`（需 `protocol-jwt` + `db-sqlite` feature）
- `with_refresh_token_rotation` builder 方法注入 `RefreshTokenRotation` 实例
- 未注入时返回 `BulwarkError::NotImplemented`

#### D4: 设备管理

- 新建 `src/session/device.rs` 模块（feature-gated：需 sha2-enabling features）
- `DeviceSession` struct：device/login_id/token/ip/user_agent/last_active_at
- `DeviceManager`：`list_devices`（列出账号所有活跃设备）、`kickout_device`（按设备踢出）
- `device_fingerprint(user_agent, ip)`：SHA-256(UA+IP) 前 16 字节 hex = 32 字符指纹
- `login` 方法在 `LoginParams.device` 为 None 但 `user_agent` + `ip` 有值时自动生成指纹

### 破坏性变更

- `SessionLogic::login` 签名从 `login(&self, login_id: &str)` 改为 `login(&self, login_id: &str, params: &LoginParams)`
- 新增 `LoginParams` struct（device/ip/user_agent/remember_me，derive Default）
- `BulwarkUtil::login_simple(id)` 便捷方法用 `LoginParams::default()` 保持向后兼容
- 所有 mock impls 已同步更新

### 审查与修复

#### diting Full Review

- **HIGH-001 修复**：`check_and_renew` 并发竞态致"会话假活"——新增 per-login_id `renewal_locks`（独立于 `BulwarkSession::login_locks`），续签前获取锁 + 二次检查 TTL；独立锁避免 `renew_to_equivalent` → `logout` → `login_locks` 死锁
- **HIGH-002 修复**：`enforce_max_login_count` 失败致孤儿会话泄漏——`login_inner` 在 enforce 失败时回滚（logout 新创建的 token），回滚失败记 `tracing::error!`

#### tiangang SAST

- 0 CRITICAL, 0 HIGH — 发布门禁通过
- 2 MEDIUM（DeviceSession.token 暴露敏感信息 / 续签失败静默吞掉）+ 3 LOW 记录为已知限制

### 验证

- 全量测试：1918 passed, 0 failed, 4 ignored（+45 新增 vs v0.6.2 的 1873）
- clippy：full + production features 零警告
- pre-commit hooks：全部通过

### 已知限制

- `renewal_locks` 为内存态，多实例部署时并发续签保护仅限单实例内
- `device_fingerprint` 无 salt，相同 UA+IP 生成相同指纹（可被指纹伪造）
- `DeviceSession.token` 字段暴露 token 明文（CWE-200），应用层应避免序列化到客户端
- `max_login_count` 的 `enforce` 依赖 `AccountSession.tokens` 与 `login_token_map` 一致性，极端并发下可能短暂不一致

## [0.6.2] - 2026-07-11

### 概述

v0.6.x 系列第一批安全增强 Quick Wins，借鉴 cedar/QIdentity 两项目分析结果，实施 6 项安全增强功能。通过 specmark `v0.6.2-security-quick-wins` change 管理，21 个任务分 7 个 Phase 完成。

### 新增

#### D1: 敏感数据脱敏（`secure-masking` feature）

- `MaskType` 枚举（Phone/IdCard/Email/BankCard/Custom）
- `SensitiveDataMasker` struct，支持 `mask_value` 单值脱敏与 `mask_json` 递归 JSON 字段脱敏
- 19 个单元测试，含多字节字符安全处理

#### D2: 通用令牌桶限流器

- `TokenBucket` + `TokenBucketRateLimiter`，基于 `DashMap` + `AtomicU64` CAS 无锁实现
- `try_acquire` / `try_acquire_n` / `cleanup` 方法
- 7 个单元测试

#### D3: XSS 防护（`secure-xss` feature）

- `XssMode` 枚举（EscapeAll / Whitelist(Vec<&'static str>)）
- `XssProtector::sanitize` 方法，EscapeAll 转义 5 个 HTML 特殊字符
- Whitelist 模式保留白名单标签，移除 `on*` 事件处理器属性
- 零外部依赖，12 个单元测试

#### D4: 会话悬停超时踢出

- `BulwarkConfig` 新增 `session_hover_timeout`（默认 -1 不启用）
- `BulwarkSession` 新增 `last_active_time` + `check_hover_timeout` + `update_last_active`
- `check_login_mixin` / `check_login_simple` 集成懒检查，超时踢出并广播 `SessionTimeout`
- 10 个单元测试

#### D5: 缓存预热服务

- `CacheWarmupService::warmup()` 扫描 `role:*` 和 `tenant:*` 键触发缓存填充
- `DaoKeyPrefix` 新增 `Role` 变体
- 对不支持 `keys()` 的 DAO 后端（如 oxcache）降级返回零统计
- 5 个单元测试

#### D6: 前后端分离模式配置项

- `BulwarkConfig` 新增 `frontend_separation`（默认 false）
- `validate()` 在启用时打印 info 日志提示 Token Header 模式
- 环境变量 `BULWARK_FRONTEND_SEPARATION` 覆盖支持
- 3 个单元测试

### 审查与修复

#### diting Full Review + tiangang SAST

- **H-1 修复**：masking 字节切片改用 `chars()` 避免非 ASCII 字符 panic（DoS 风险）
- **H-2 修复**：warmup 捕获 `NotImplemented` 降级返回零统计，不再在生产环境报错
- **H-3 修复**：XSS 白名单模式移除 `on*` 事件处理器属性，防止无引号属性绕过
- **M-3 修复**：悬停检查提取 `check_and_update_hover` 辅助方法，消除 24 行重复代码
- **M-4 修复**：logout 错误改用 `tracing::warn!` 不再静默吞掉

### 验证

- 全量测试：1873 passed, 0 failed, 4 ignored
- clippy：full + production features 零警告
- pre-commit hooks：全部通过
- diting：0 Critical / 0 High（修复后）
- tiangang SAST：0 CRITICAL

### 已知限制

- `TokenBucketRateLimiter` 无 Redis 支持（defer 到 v0.6.3）
- `XssProtector` 白名单模式不支持属性白名单过滤
- `last_active_time` 为内存态，多实例部署需持久化到 DAO（defer 到 v0.6.3）
- `frontend_separation` 仅提供配置项与日志提示，Web 框架行为变更留待后续版本
- `MaskType::Custom` 变体存储模式但不实现脱敏逻辑

## [0.6.1] - 2026-07-11

### 概述

本版本包含两批变更：

1. **gap-closure-remaining**（T001-T011）：补齐 origin 文档与代码实现之间的 11 项 gap，覆盖 remember-me 配置、Redis 部署模式、身份切换、Token 置换、OAuth2 注解、路由分组、会话过期回调、SAML 2.0 骨架、OIDC RP 骨架、Redis pub/sub SsoChannel。**至此，所有 origin 文档与代码实现之间的 gap 已全部关闭，零残留。**

2. **v0.6.1-concurrency-syncfn-macro-enum**（T001-T016）：通过 specmark change 修复 4 项核心问题——并发安全、sync fn 宏支持、宏覆盖审计、字符串枚举化。

### 新增

#### T001/T008: remember-me 扩展会话超时

- `BulwarkConfig` 新增 `remember_me_enabled`（默认 false）与 `remember_me_timeout`（默认 7776000 秒 = 90 天）字段
- `login` 方法支持 `remember_me=true` 参数，启用后使用 `remember_me_timeout` 作为会话 TTL
- 环境变量 `BULWARK_REMEMBER_ME_ENABLED` / `BULWARK_REMEMBER_ME_TIMEOUT` 覆盖支持
- `validate()` 校验：`remember_me_enabled=true` 时 `remember_me_timeout` 必须 > `timeout`

#### T002: Redis 部署模式枚举

- 新增 `RedisDeploymentMode` 枚举（Single / Sentinel / Cluster / MasterSlave），覆盖生产环境常见 Redis 拓扑
- 新增 `RedisConfig` 聚合结构（mode + password + db + connection_timeout_secs + pool_size）
- `Display` 实现输出人类可读的部署模式描述

#### T003: 身份切换 switch_to

- `switch_to(login_id)` 方法：在当前会话中切换登录身份，保留原会话 token 与设备信息

#### T004: Token 置换 renew_to_equivalent

- `renew_to_equivalent()` 方法：生成等效新 Token 并迁移会话状态，旧 Token 失效

#### T005: OAuth2 注解 CheckAccessToken/CheckClientToken

- `Annotation` 枚举新增 `CheckAccessToken` 与 `CheckClientToken` 变体
- `pre_handle` 中返回 `NotImplemented`，提示用户使用 `protocol::oauth2::OAuth2Client` 或自定义拦截器

#### T006: 路由分组 group() 方法

- `BulwarkRouter::group(prefix, annotation, f)` 方法：支持路由分组与前缀挂载
- 子 router 继承父 router 的 interceptor 和 config
- `Annotation::Ignore` 时覆盖路由注解；否则保留路由自身注解

#### T007: 会话过期回调 SessionExpiryListener

- `SessionExpiryListener` trait：会话过期时触发异步回调
- `add_expiry_listener` / `trigger_expiry_listeners` 方法

#### T009: SAML 2.0 骨架

- `SamlProvider` trait：`build_authn_request` / `parse_response` / `validate_assertion`
- `DefaultSamlProvider` 实现：quick-xml pull reader 解析 SAML Response
- 数据结构：`SamlAssertion` / `SamlResponse` / `SamlRequest`
- Feature gate：`protocol-sso`

#### T010: OIDC RP 骨架

- `OidcProvider` trait：`get_authorization_url` / `exchange_code` / `get_user_info` / `validate_id_token`
- `DefaultOidcProvider` 实现：reqwest HTTP client + discovery config
- 数据结构：`OidcDiscoveryConfig` / `OidcUserInfo`
- 与 `OidcHandler` 区别：OidcHandler 是 Bulwark 作为 IdP，OidcProvider 是 Bulwark 作为 RP

#### T011: Redis pub/sub SsoChannel

- `RedisPubSubSsoChannel` 实现 `SsoChannel` trait
- `push(topic, message)`：通过 `redis::cmd("PUBLISH")` 发布消息
- `subscribe(topic, handler)`：spawn tokio task + `catch_unwind` 保护 handler panic
- Feature gate：`cache-redis` + `protocol-sso-server`
- Cargo.toml 新增 `futures` / `redis` / `quick-xml` 依赖

### S1: 并发安全修复（v0.6.1-concurrency-syncfn-macro-enum）

#### T001: 并发审计报告

- 输出 13 个竞态条件报告到 `specmark/changes/v0.6.1-concurrency-syncfn-macro-enum/concurrency-audit.md`
- 其中 R-001~R-004 为 HIGH（Account-Session read-modify-write 非原子序列）
- 根因：`BulwarkDao` 仅提供 per-key 原子操作，无跨 key 事务

#### T002: per-login_id 操作锁

- `BulwarkSession` 新增 `login_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>` 字段
- `with_login_lock` 异步闭包方法：按 login_id 串行化 create/logout/logout_by_login_id 操作
- `logout` 拆分为 `logout`（获取锁）+ `logout_inner`（无锁，供 `kickout_by_device` 调用避免死锁）
- 新增测试 `concurrent_login_same_user_creates_consistent_session`（SlowDao wrapper 放大竞态窗口）

#### T003: task_local 上下文传播

- 新增 `BulwarkContext` struct + `capture()` + `within(self, f)` 方法
- 使用 `CURRENT_TOKEN.scope(token, f).await` 实现 task_local 跨 spawn 传播
- 2 个测试：`task_local_propagates_across_spawn` / `bulwark_context_capture_without_token_propagates_none`

#### T004: Plugin/Listener 线程安全审计

- 输出审计报告到 `specmark/changes/v0.6.1-concurrency-syncfn-macro-enum/plugin-listener-thread-safety.md`
- 结论：0 竞态、0 死锁风险
- Plugin：init 后不可变（无 mutation 方法）
- Listener：RwLock + 快照模式（clone Vec 后释放锁再 iterate）

### S2: sync fn 宏支持

#### T005: detect_asyncness 枚举

- `require_async()` 替换为 `detect_asyncness(item_fn) -> Asyncness`（`Async`/`Sync` 两变体）
- 不再拒绝 sync fn，为后续 sync 路径生成铺路

#### T006: BulwarkUtil 同步方法

- 新增 7 个 `check_*_sync()` 方法：`check_login_sync` / `check_permission_sync(perm)` / `check_role_sync(role)` / `check_access_token_sync` / `check_client_token_sync` / `check_temp_token_sync` / `check_api_key_sync(ns)`
- 模式：`task::block_in_place(|| Handle::current().block_on(Self::check_login()))`
- 8 个测试覆盖成功路径 + 未认证路径

#### T007: expand_wrapper sync fn 分支

- `expand_wrapper` 新增 `asyncness: Asyncness` 参数
- Async 路径：生成 `async fn wrapper` + `.await` 调用
- Sync 路径：生成 `fn wrapper` + `check_*_sync()` 调用
- 新增 trybuild 编译测试：`sync_fn_pass.rs` + `async_fn_pass.rs`（各 8 个用例覆盖所有 7 个宏 + api_key namespace）

### S3: 宏覆盖审计

#### T008: 覆盖矩阵文档化

- 在 `bulwark-macros/src/lib.rs` 模块文档添加 `# 覆盖矩阵` 段落
- 7 个宏 × 13 个特性域的覆盖情况表格
- 不新增宏代码，仅文档化现状

### S4: 硬编码字符串枚举化

#### T009: DaoKeyPrefix 枚举

- 新建 `src/constants/mod.rs` + `src/constants/dao_keys.rs`
- `DaoKeyPrefix` 枚举 8 变体：Session / Token / Captcha / Saml / Cred / Lockout / BruteForce / Tenant
- `as_str()`（const fn）/ `build_key(id)` / `Display` 实现
- 3 个单元测试

#### T010: EventReason 枚举

- 新建 `src/constants/events.rs`
- `EventReason` 枚举 6 变体：InvalidCredentials / Expired / Revoked / Locked / Logout / Kickout
- `as_str()`（const fn）/ `Display` 实现
- 2 个单元测试

#### T011: DAO key 前缀替换

- 11 个文件共 20 处 `format!("prefix:{}", ...)` 替换为 `DaoKeyPrefix::Variant.build_key(...)`
- 涉及文件：session/security_listener、strategy/hooks、session/mod、firewall/captcha_provider、protocol/sso/saml、account/credential/{mod,backup_code}、account/lockout、firewall/brute_force、dao/repository/role_hierarchy、dao/mod

#### T012: 事件 reason 替换

- `src/stp/password.rs` 2 处 `"invalid_credentials"` 替换为 `EventReason::InvalidCredentials.to_string()`
- `src/stp/session.rs` 1 处 `"管理员强制下线"` **保留原样**（用户面向显示消息，非 reason code）
- diting HIGH Issue-001 捕获并修复了 silent behavior change（Chinese → English）

### 验证（v0.6.1-concurrency-syncfn-macro-enum）

- `cargo test --features full --lib`：1817 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`：零警告
- `cargo clippy --features production -- -D warnings`：零警告
- diting Full Review：0 Critical / 0 High（修复后）/ 3 Medium / 3 Low → Approved
- tiangang SAST：cargo-audit 0 CRITICAL（1 MEDIUM rsa 无修复）/ semgrep 0 CRITICAL（2 ERROR 误报：测试 JWT token）
- pre-commit hooks 全部通过

### 变更

- `Cargo.toml` version 0.6.0 → 0.6.1
- `bulwark-macros/Cargo.toml` version 0.5.0 → 0.5.1（sync fn 宏支持为功能新增）

### 已知限制

- `DashMap login_locks` 无清理机制，长期运行可能内存增长（diting MEDIUM Issue-002，defer 到后续版本）
- `block_in_place` 在单线程 runtime 不可用，4 个并发 sync fn 可能耗尽 worker（diting LOW Issue-006，文档化）
- SAML namespace 检查基于前缀而非 URI，defense-in-depth 非完整方案（diting LOW Issue-005）

## [0.6.0] - 2026-07-09

### 概述

Bulwark 0.6.0 是"账号安全引擎版"，通过 specmark change `v0-6-0-account-security-engine` 实施 4 项核心能力（E-001/E-002/E-003/E-004）+ 4 项技术债清理（B-001/B-002/C-001/D-001）。引入 `account/` 模块作为账号安全能力中枢，提供 Credential SPI、密码策略引擎、用户锁定策略、AuthenticationFlow DSL，并补齐 i18n 社交登录异常消息与 Prometheus 指标。

### 新增

#### E-001: account/ 模块骨架 + Credential SPI

- 新建 `account/` 顶层模块（`account/credential/` + `account/policy/` + `account/lockout/` + `account/authflow/` + `account/metrics.rs`）
- `Credential` trait 统一凭证模型 SPI：`verify` / `store` / `load` / `update` / `metadata`
- `PasswordCredential` 实现：基于 `PasswordHasher` 的密码凭证
- `TotpCredential` 实现：RFC 6238 TOTP 动态码凭证
- `DaoCredentialRepository` 基于 `BulwarkDao` 的凭证存储
- 迁移 `PasswordHasher` 从 `src/secure/` 到 `account/credential/password.rs`（删除 `secure-password` feature）

#### E-002: PasswordPolicyEngine

- `PasswordPolicyRule` trait + `PasswordPolicyEngine` + `PasswordPolicyContext`
- 6 个核心密码策略规则：长度 / 复杂度 / 历史 / 字典 / 用户名相似 / 序列检测
- 6 个扩展密码策略规则：重复字符 / 键盘模式 / 日期 / 常见密码 / 上下文敏感 / 唯一字符数

#### E-003: UserLockoutStrategy + BulwarkFirewallStrategy

- `UserLockoutConfig` + `WaitStrategy` + `LockoutState`
- `UserLockoutStrategy`：基于用户的登录锁定策略
- `BulwarkFirewallStrategy`：整合 UserLockoutStrategy 到 BulwarkFirewall 框架

#### E-004: AuthenticationFlow DSL

- `AuthStep` enum + `AuthenticationFlow` + `AuthContext` + `AuthResult`
- `FlowBuilder` 流式构建 DSL
- `FlowRegistry` 基于 inventory 编译期注册
- `AuthExecutor` 核心执行器（5 字段约束：builder/registry/dao/credential_repo/metrics）
- `SocialProvider` + `SsoServer` 步骤扩展
- 内置 `AuthenticationFlow`：username_password / username_password_totp / social_wechat / social_alipay / sso

#### C-001: 社交登录异常消息 fluent i18n

- 新增 `loc!` 宏：`#[cfg(feature = "i18n")]` 分支调用 `translate_detail`，未启用时返回 fallback
- 新增 `translate_detail` 函数（`src/i18n.rs`）：按 key 查询 fluent bundle
- 38 个 ftl key（wechat 12 + alipay 8 + keycloak 18）中英文双语
- 46 个错误构造点接入 `loc!` 宏（wechat 16 + alipay 12 + keycloak 18）

#### D-001: AccountMetrics Prometheus 指标

- `AccountMetrics` struct（`#[cfg(feature = "metrics-prometheus")]`）：4 个指标
  - `credential_verify_duration`（HistogramVec，label: credential_type）
  - `policy_validate_duration`（HistogramVec，label: rule_name）
  - `lockout_triggered_total`（CounterVec，label: lockout_type）
  - `authflow_execute_duration`（HistogramVec，label: flow_name）
- `register_to` / `observe_*` / `record_*` / `gather` 方法
- feature 未启用时 `type AccountMetrics = ()`

### 变更

- `Cargo.toml` version 0.5.0 → 0.6.0
- `AuthExecutor` 保持 5 字段约束：metrics 通过 `execute_with_metrics` 方法参数传入，非 struct 字段
- `UserLockoutStrategy` 加 `metrics: Option<Arc<AccountMetrics>>` 字段 + `with_metrics` builder
- `PasswordPolicyEngine` 加 `metrics` 字段 + `with_metrics` builder，`validate` 中 per-rule 计时
- `src/i18n.rs` 新增 `translate_detail` 函数
- `src/protocol/mod.rs` 新增 `loc!` 宏定义
- `locales/zh.ftl` + `locales/en.ftl` 新增 38 个 message key

### 破坏性变更

1. **`PasswordHasher` 迁移（T002）**：从 `src/secure/password.rs` 迁移到 `account/credential/password.rs`，`secure-password` feature 删除（功能合并到 `account` feature）
2. **`FirewallContext.login_id` 类型变更（T010）**：`i64` → `String`（所有 FirewallStrategy 实现需更新签名）

### 修复

#### B-001: cargo doc 10 个 warning 修复

- 8 个 broken intra-doc links（`decision` / `JsonTestCase` / `MaxMindDbGeoLookup` / `MaxMindDbCountryLookup` / `RefreshTokenRecord` 等）
- 2 个 unclosed HTML tags（`web_actix/mod.rs` / `web_warp/mod.rs` 中 `Bearer <token>` 改为 `` Bearer `<token>` ``）

#### B-002: tenant_isolation 集成测试修复

- `tests/integration/tenant_isolation.rs` 7 处修改：`login_id: i64` → `&str` 对齐 `BulwarkInterface` 签名
- 新增 `use bulwark::{PermissionLogic, SessionLogic};`（trait 方法需导入 trait）

### 验证

- `cargo test --features full --lib`：1463 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`：零警告
- `cargo doc --no-deps --features full`：零警告
- `cargo test --features "full audit-log" --test integration tenant_isolation`：1 passed

### 已知限制

- `AuthExecutor` metrics 仅通过 `execute_with_metrics` 显式传入，未集成到 `BulwarkManager` 自动注入链路（待 v0.7.0+ Manager 重构）
- `FlowRegistry` inventory 注册的 flow 在编译期固定，运行时动态注册需调用 `register` 方法（非自动发现）

## [0.5.3] - 2026-07-09

### 概述

Bulwark 0.5.3 是"功能补全版"，通过 specmark change `v0-5-3-feature-completion` 实施 4 项功能补全（A-015/A-014/A-012/A-013）。补齐 stp 模块拆分遗留、MySQL 后端、Firewall MaxMindDb 生产后端，并升级 oxcache。

### 变更

#### A-015: oxcache 升级 + 决策文档同步

- 升级 `oxcache` 依赖到 0.3.3（per-entry TTL + `ttl_sync()` 查询）
- 更新 `docs/decisions/A-010-dao-keys-performance-evaluation.md`：`CacheReader` trait 仍无 iter/keys 方法
- 更新 `src/dao/mod.rs` 注释：defer 到 oxcache 提供原生 iter API

#### A-014: stp/mod.rs 完整拆分

- 164KB `src/stp/mod.rs` 拆分为 11 个职责文件（新增 `tests.rs` + `interface.rs` + `util.rs`）
- 6 个 `impl trait for BulwarkLogicDefault` 块移至对应子文件
- 5 个 session helper 方法从 mod.rs 移至 session.rs（满足 mod.rs < 15KB 目标）
- mod.rs 最终：12.4KB / 284 行（原 164KB / 4035 行）

#### A-012: MySQL 后端启用 + testcontainers 集成测试

- 启用 `db-mysql` feature（`dbnexus/mysql`）
- 添加 `testcontainers = "0.27"` dev-dependency
- 新建 `tests/db_mysql_testcontainers.rs`：11 个 `#[serial]` 集成测试
- 新建 `migrations/mysql/core/` 6 个 MySQL 兼容迁移文件
- 新建 `src/dao/repository/mysql/mod.rs`：re-export sqlite 实现的 MySQL 命名别名
- 修复 `UserExtRepository::upsert` MySQL 兼容性（`ON DUPLICATE KEY UPDATE` 替代 `ON CONFLICT`）
- **偏离**：db-mysql 未加入 `full` 聚合 feature（dbnexus 禁止 db-sqlite 与 db-mysql 同时启用）

#### A-013: Firewall MaxMindDb 生产后端

- 添加 `maxminddb = "0.29"` 依赖 + `firewall-maxminddb` feature
- 实现 `MaxMindDbGeoLookup`（GeoIP2-City: IP → GeoCoord，供 AnomalousLoginStrategy）
- 实现 `MaxMindDbCountryLookup`（GeoIP2-Country: IP → ISO 国家码，供 GeoIPStrategy）
- 14 个测试：open/lookup/invalid_ip/private_ip + strategy 集成测试
- 下载 GeoLite2-City/Country-Test.mmdb 测试数据

### 验证结果

- `cargo test --features full --lib`：1336 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`：零警告
- `cargo test --features "db-mysql" --test db_mysql_testcontainers`：11 passed（需 Docker）
- `cargo test --features "firewall-maxminddb" --lib maxminddb`：14 passed

### 已知限制

- `cargo test --features full --workspace` 中 `tests/integration/tenant_isolation.rs` 有预存失败（v0.5.2 LoginId 迁移遗留，非 v0.5.3 引入）
- `cargo doc --no-deps --features full` 有 10 个预存 warning（`src/core/permission/decision.rs` broken intra-doc links 8 个 + `src/web_actix/mod.rs` / `src/web_warp/mod.rs` unclosed HTML tag 2 个，非 v0.5.3 引入）

## [0.5.2] - 2026-07-08

### 概述

Bulwark 0.5.2 是"架构重构版"，通过 specmark change `v0-5-2-architecture-refactor` 实施 5 项架构重构（A-002/A-004/A-009/A-010/A-011）。这是 v1.0 API 冻结前的最后重构窗口，彻底清零架构债务。

> **破坏性变更（无向后兼容）**：原计划用 `#[deprecated]` 周期过渡，apply 阶段用户决策直接删除，彻底清零技术债。

### 变更

#### A-002: BulwarkLogic trait 拆分

- 21 方法上帝 trait `BulwarkLogic` 拆分为 6 个子 trait：
  - `BulwarkCore`（base，1 方法）
  - `SessionLogic: BulwarkCore`（10 方法）
  - `PermissionLogic: SessionLogic`（2 方法）
  - `TokenLogic: SessionLogic`（5 方法）
  - `MfaLogic: SessionLogic`（2 方法）
  - `PasswordLogic: SessionLogic`（1 方法）
- **直接删除 `BulwarkLogic`**（无 `#[deprecated]` 过渡，无 type alias）
- Manager 持有具体类型 `Arc<BulwarkLogicDefault>`（非 trait 对象）
- 调用方需显式 `use crate::stp::SessionLogic` 等子 trait 以解析方法

#### A-004: LoginId 迁移

- **删除 `LoginId` newtype**，全栈使用 `String`/`&str`
- 所有 `login_id: i64` 签名迁移为 `login_id: &str`（对象安全，可作 `dyn`）
- `get_login_id()` 返回 `Option<String>`（原 `Option<i64>`）
- `verify_token()` 返回 `String`（原 `i64`）
- 移除 `BulwarkUtil::login_id_to_i64`（不再需要）
- `BulwarkUtil` 保留 `impl Into<String>` ergonomic 入口

#### A-009: oxcache `_sync` API 评估

- 评估结论：保留 `_sync` API（in-memory backend 下 <1μs vs `spawn_blocking` 10-50μs）
- 文档化 `BulwarkDaoOxcache` 性能约束（见 `docs/decisions/A-009-oxcache-sync-api-evaluation.md`）
- 后续跟进：引入 Redis/分布式 backend 时改用 async API

#### A-010: `keys()` 性能评估

- 评估结论：defer 到 oxcache 0.5+（`Cache.backend` 为 `pub(crate)`）
- 文档化 `BulwarkDao::keys()` 已知限制（见 `docs/decisions/A-010-dao-keys-performance-evaluation.md`）
- 业务方临时方案：自行维护 key 集合

#### A-011: `src/stp/mod.rs` 拆分

- 164KB/4035 行单文件拆分为 10 个职责文件：
  - `core.rs` / `session.rs` / `permission.rs` / `token.rs` / `mfa.rs` / `password.rs`
  - `interface.rs` / `util.rs` / `parameter.rs` / `mod.rs`（re-exports）
- 每个子文件包含 trait 定义 + `BulwarkLogicDefault` impl 块 + 单元测试

### 破坏性变更

1. **`BulwarkLogic` trait 删除**：所有 `Arc<dyn BulwarkLogic>` 使用者必须迁移到 `Arc<BulwarkLogicDefault>` + 显式 `use` 子 trait
2. **`LoginId` newtype 删除**：所有 `LoginId` 使用者必须迁移到 `String`/`&str`
3. **Manager 返回类型变更**：`BulwarkManager::logic()` 返回 `Arc<BulwarkLogicDefault>`（非 `Arc<dyn BulwarkLogic>`）
4. **`get_login_id()` 返回类型变更**：`Option<i64>` → `Option<String>`
5. **`verify_token()` 返回类型变更**：`i64` → `String`
6. **`login_id` 参数类型变更**：`i64` → `&str`（所有 trait 方法 + `BulwarkInterface`）

### 验证

- `cargo test --features full --lib`: 1322 passed, 0 failed
- `cargo test --features full --tests`: 72 passed, 0 failed
- `cargo test --features "full manager-explicit" --lib -- manager::explicit`: 6 passed
- `cargo clippy --features full --lib --tests -- -D warnings`: 零警告
- `cd examples && cargo check --features full`: 通过

---

## [0.5.0] - 2026-07-06

### 概述

Bulwark 0.5.0 是"生产刚需版"，通过 specmark change
`v0-5-0-production-essentials` 实施多租户隔离、社交登录、审计日志、
RefreshToken Rotation、安全防护套件、角色层级、决策溯源、Keycloak OIDC RP、
SSO TOCTOU 原子化、注解系统、PostgreSQL 后端适配等核心生产能力。

### 新增

#### 多租户隔离

- **`tenant-isolation` feature**：`TENANT` task_local + `TenantContext` +
  `prefixed_key` 函数自动为缓存 key 添加 `tenant:{id}:` 前缀，
  确保多租户数据隔离。`TenantResolution` middleware 从 Header/Query/Token
  解析租户 ID。

#### 社交登录

- **`social-wechat` feature**：`WechatProvider` 实现微信扫码登录，
  支持 access_token 端点 + 用户信息查询。
- **`SocialBindingService`**：社交账号绑定/解绑 + find_or_create 语义。

#### 审计日志

- **`audit-log` feature**：`AuditLogListener` 订阅 14 种 `BulwarkEvent`，
  写入 `audit_logs` 表（含 tenant_id/login_id/event_type/mask_fields 脱敏）。
  `AuditQuery` 支持复合条件查询。

#### RefreshToken Rotation

- **`protocol-jwt`（扩展）**：`RefreshTokenRotation` 服务提供
  `rotate()`（轮换）+ `detect_reuse()`（重用检测）+ `revoke_chain()`（链级吊销）。
  `refresh_tokens` 表使用 SHA-256 hash chain（token_hash + parent_token_hash）。

#### 决策溯源

- **`decision-trace` feature**：`PermissionChecker` trait + `authorize()` API
  返回 `Decision { allowed, reason, errors }`，`DecisionReason` 枚举包含
  `ExplicitAllow`/`ExplicitDeny`/`NoMatchingPermission`/`RoleBased` 等原因。

#### Keycloak OIDC RP

- **`keycloak-oidc` feature**：`KeycloakProvider` 实现 OIDC 依赖方，
  支持 `discover()`（discovery endpoint）+ `exchange_code()`（授权码交换）+
  `verify_id_token()`（JWKS 验签 + KeycloakClaims 解析）。

#### 安全防护套件

- **5 个 FirewallStrategy 实现**：`BruteForceStrategy`/`RateLimitStrategy`/
  `AnomalousLoginStrategy`/`DDoSStrategy`/`GeoIPStrategy`，
  复用 oxcache 作为计数后端。

#### 角色层级

- **`role_hierarchy` 表**：`parents`/`indirect_ancestors` + TC 预计算，
  登录时缓存权限并集。

#### 数据库后端

- **`db-postgres` feature**：PostgreSQL 后端适配，`make_statement`/
  `convert_placeholders` 实现 backend-agnostic SQL。

#### 集成测试

- **4 个端到端集成测试**（`tests/integration_v0_5_0.rs`）：
  多租户隔离+审计日志+决策溯源 / Keycloak OIDC RP 完整流程 /
  RefreshToken Rotation + Reuse Detection / RSA 密钥对 smoke 测试。

#### 示例

- **`v0_5_0_demo` 示例**：演示 v0.5.0 核心生产能力（多租户+审计日志+
  决策溯源+Keycloak RP+微信社交登录配置）。

### 验证

- `cargo test --features "full" --workspace` → 全绿
- `cargo clippy --features "full" --workspace -- -D warnings` → 零警告
- `cargo doc --no-deps --features full --workspace` → 完成

## [0.4.2] - 2026-07-05

### 概述

Bulwark 0.4.2 是 0.4.x 系列的 MINOR 版本，通过 specmark change
`v0-4-2-gap-closure-and-features` 实施 origin 文档与代码实现对齐 gap 闭合 + 新功能增强。
共完成 16 个 Phase（capability），覆盖：LoginId newtype、BulwarkDao 扩展、密码哈希、
Repository 层、密码登录、多账户隔离、JWT 三模式、API Key namespace、SSO TOCTOU 修复、
kickout_by_device、事件扩展、Web 适配器、Strategy 注册表、过程宏注解、OAuth 2.1 PKCE、
Token Introspection。

### 新增

#### 核心类型

- **LoginId newtype（Phase 1）**：`src/stp/login_id.rs` 新增 `LoginId` enum
  （`Numeric(i64)` / `String(String)`），实现 `From<i64>`/`From<String>`/`From<&str>`/
  `as_str`/`as_i64`/`Display`/`Serialize`/`Deserialize`。`stp`/`session`/
  `protocol/{jwt,oauth2,sso,apikey}` 公开方法签名改为 `impl Into<LoginId>`，保留 i64
  通过 `From<i64>` 兼容（`login_id_to_i64` 改 `pub(crate)` 复用）

#### DAO 层（Phase 2）

- **BulwarkDao 4 方法扩展**：新增 `set_permanent`（无 TTL）/`get_timeout`（查询剩余 TTL）/
  `keys`（glob pattern 扫描）/`rename`（重命名 key），均提供默认实现保持向后兼容。
  `BulwarkDaoOxcache` 重写 `set_permanent`/`get_timeout`/`rename` 使用 oxcache 原生 API
  保留 TTL（`set_with_ttl_sync(None)` / `ttl_sync()` / `get→ttl_sync→set_with_ttl_sync→delete`）

#### 安全模块

- **PasswordHasher（Phase 3）**：新增 `secure-password` feature + `PasswordHasher` trait +
  `Argon2Hasher` + `BcryptHasher` + `PasswordVerifier`（自动识别 hash 格式：argon2/bcrypt/BCrypt）。
  依赖 argon2 0.5 + bcrypt 0.15 + rand 0.8
- **JWT 三模式（Phase 7）**：`JwtMode` enum（`Stateless`/`Mixin`/`Simple`），
  `BulwarkLogicDefault::with_jwt_mode` builder，`check_login` 按模式分支：
  Stateless 仅 JWT verify / Mixin JWT+session / Simple 仅 session

#### 数据访问

- **Repository 层（Phase 4）**：`db-sqlite` 启用 `src/dao/repository/` 模块，定义 9 个
  Repository trait（UserRepository/RoleRepository/PermissionRepository/UserRoleRepository/
  RolePermissionRepository/AuthMethodRepository/SessionRepository/LoginLogRepository/
  UserExtRepository），所有方法首参 `tenant_id: i64`。9 个 SqliteRepository 基于 dbnexus
  DbPool + sea-orm 实现

#### 认证路径

- **密码登录（Phase 5）**：`BulwarkLogic::login_with_password(login_id, password)` 默认方法，
  整合 `UserRepository::find_by_username` + `PasswordHasher::verify` + `login`。
  `BulwarkLogicDefault::with_password_hasher` builder 注入 `Arc<dyn PasswordHasher>`
- **多账户 login_type（Phase 6）**：`BulwarkInterface` 新增
  `get_permission_list_with_type(login_id, login_type)` + `get_role_list_with_type`，
  旧方法默认委托（login_type="default"）。`with_login_type` builder

#### 协议层

- **API Key namespace（Phase 8）**：`ApiKeyInfo` 新增 `namespace: String` 字段
  （`#[serde(default = "default_namespace")]` 填充 "default"），key 格式升级为
  `bulwark:apikey:<namespace>:<key>`。`generate_with_namespace` 方法 +
  `list_by_namespace`（依赖 `BulwarkDao::keys`）。`verify` 兼容旧格式
- **SSO TOCTOU 修复（Phase 9）**：`BulwarkDao::get_and_delete(key)` 原子方法（默认实现
  get→delete 两步，`BulwarkDaoOxcache` 用 `parking_lot::Mutex` 保护进程内原子）。
  `SsoClient::validate_ticket` / `DefaultSsoServer::validate_ticket` 改用原子消费消除竞态
- **OAuth 2.1 PKCE（Phase 15）**：`OAuth2Client::generate_pkce_challenge`（S256 方法，
  RFC 7636 测试向量验证）+ `get_auth_url_with_pkce(state, code_verifier)` +
  `exchange_code_with_pkce(code, state, code_verifier)`。旧 `get_auth_url`/`exchange_code`
  标记 `#[deprecated]`
- **Token Introspection（Phase 16）**：`OAuth2Client::introspect_token(token)` 方法
  （RFC 7662），`TokenIntrospectionResponse` struct（12 字段：active/scope/client_id/
  username/token_type/exp/iat/nbf/sub/aud/iss/jti）。`with_introspect_url` builder，
  URL 推导（显式 → token_url 替换 `/token`→`/introspect` → 追加 `/introspect`）

#### 会话管理

- **kickout_by_device（Phase 10）**：`BulwarkSession::kickout_by_device(login_id, device)`
  方法，查询 account session → 过滤 device → 批量 logout_by_token

#### 事件与策略

- **BulwarkEvent 14 变体（Phase 11）**：新增 8 个事件（`LoginFailure`/`TokenRefresh`/
  `TokenRevoke`/`SessionTimeout`/`AccountLocked`/`FirewallBlock`/`ApiKeyRotate`/
  `TempCredentialConsumed`），8 个 broadcast 集成点（login_with_password
  失败/refresh_token/revoke_token/check_login session timeout/FirewallCheckHook 锁定/FirewallStrategy
  阻止/ApiKeyHandler::rotate/TempCredentialHandler::consume）。`BulwarkEvent` 派生
  `PartialEq`。`ConfigReload` 变体因 `ConfigLoader` 无 reload 方法未添加，待 v0.5.0+ 实现
- **Strategy Registry（Phase 13）**：`src/strategy/registry.rs` 新增 6 个策略 trait
  （`LoginHandler`/`LogoutHandler`/`PermissionHandler`/`TokenGenerator`/`SessionCreator`/
  `FirewallStrategy`）+ 6 个默认实现（委托 `Arc<dyn BulwarkLogic>`）+ `Strategy` 注册表
  struct（18 个 register/get/remove 方法）。`BulwarkManager` 持有
  `Arc<RwLock<Strategy>>`，`strategy()` getter + `with_strategy` builder

#### Web 适配器

- **ActixContext + WarpContext（Phase 12）**：新增 `web-actix` 启用
  `src/context/actix_adapter.rs`（`ActixContext`/`ActixRequest`/`ActixResponse`/
  `ActixStorage` 4 件套，34 测试，`ActixRequestWrapper` 私有结构体绕过生命周期限制）。
  新增 `web-warp` 启用 `src/context/warp_adapter.rs`（`WarpContext`/`WarpRequest`/
  `WarpResponse`/`WarpStorage` 4 件套，33 测试，持有 owned 数据）。`strip_bearer_prefix`
  大小写不敏感（RFC 7235）

#### 过程宏

- **bulwark-macros crate（Phase 14）**：新建 workspace member `bulwark-macros`，提供
  `#[check_login]`/`#[check_permission]`/`#[check_role]` 三个 `#[proc_macro_attribute]`。
  `annotation-macros` feature 启用（依赖 `web-axum`）。wrapper + inner function 模式：
  原 fn 重命名为 `__bulwark_inner_<name>`，wrapper 使用原名称返回 `axum::response::Response`。
  `check_login` 特殊处理：Ok(false) → 401，Err → forward。AND 语义：多参数生成多次调用。
  13 个集成测试覆盖 login/permission/role scenarios

### 变更

- `Cargo.toml` version 0.4.1 → 0.4.2
- `Cargo.toml` `[workspace].members` 新增 `"bulwark-macros"`
- `Cargo.toml` 新增 4 个 feature：`secure-password` / `annotation-macros` / `web-actix` /
  `web-warp`，均加入 `full` 聚合
- `Cargo.toml` 新增依赖：argon2 0.5 / bcrypt 0.15 / rand 0.8 / bulwark-macros path 依赖；
  `protocol-oauth2` feature 添加 `sha2` + `base64` 依赖（PKCE S256 复用）
- `BulwarkDao` trait 新增 5 个方法（4 个 Phase 2 + get_and_delete Phase 9），均提供默认
  实现保持向后兼容
- `SsoClient::validate_ticket` / `DefaultSsoServer::validate_ticket` 改用两步法
  （get 校验 client_id → get_and_delete 原子消费），client_id 不匹配时不消费 ticket
- `OAuth2Client::get_auth_url` / `exchange_code` 标记 `#[deprecated]`
- `BulwarkEvent` 派生 `PartialEq`
- `ApiKeyInfo` 新增 `namespace: String` 字段（`#[serde(default)]` 向后兼容）

### 修复

- **SSO validate_ticket spec 冲突解决**：原实现"client_id 不匹配也消费 ticket"（防爆破）
  与测试期望"client_id 不匹配不删除 ticket"（允许重试）冲突。改为两步法：先 `get` 校验
  client_id，匹配后 `get_and_delete` 原子消费。同时满足"用户友好"（错误 client_id 不消费）
  和"TOCTOU 修复"（并发仅一个成功）
- **examples apikey_management MockDao keys() 缺失**：Phase 8 namespace isolation 引入
  `BulwarkDao::keys` 后，`examples/src/apikey_management.rs` 的 MockDao 未实现 `keys()`，
  导致 `ApiKeyHandler::verify` 扫描新格式 key 失败。添加 `keys()` 实现 + `glob_match` 函数
  （与 `tests/protocol_apikey_edge_cases.rs` 保持一致）
- **RFC 7636 测试向量修正**：spec 中 code_verifier `dBjftJeZ4CVP-mB92K29uhjUjUy5YGA`
  （31 字符）不满足 43-128 长度要求，改为 RFC 7636 Appendix B 正确值
  `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`（43 字符）

### 已知限制

- `BulwarkDao::keys` 默认实现返回 `NotImplemented`，`BulwarkDaoOxcache` 当前也返回
  `NotImplemented`（oxcache 0.3 不支持 key scan，待 v0.5.0+ 升级）
- `BulwarkDao::rename` 默认实现为 get→set_permanent→delete 三步，非原子；
  `BulwarkDaoOxcache` 重写为 get→ttl_sync→set_with_ttl_sync→delete 四步保留 TTL，
  但仍非原子（oxcache 0.3 无原子 rename API，待 v0.5.0+）
- `BulwarkEvent::TokenRevoke` 已在 `revoke_token` 调用时集成 broadcast；
  `ConfigReload` 变体未添加（`ConfigLoader` 无 reload 方法，待 v0.5.0+ 实现后添加变体 + 集成 broadcast）
- `LoginId::String` 形式在内部层（i64）尚未完成迁移，公开 API 接受 `impl Into<LoginId>`
  但 `login_id_to_i64` 对 `String` 形式返回 `BulwarkError::Config`（待 v0.5.0+ 完成内部层迁移）
- Strategy Registry 的 `DefaultFirewallStrategy` 为 no-op（`BulwarkLogic` 无
  `check_login_hooks` 方法），`DefaultTokenGenerator::generate_token` 委托 `logic.login`
  （最接近的方法）
- Token Introspection 不缓存结果（每次调用请求授权服务器，待 v0.5.0+ 加缓存）
- PKCE 仅实现 S256 方法（plain 方法已弃用，不实现）

### 文档与示例

- `bulwark-macros/Cargo.toml` + `bulwark-macros/src/lib.rs` 新建（proc-macro crate
  manifest + 3 个 `#[proc_macro_attribute]` 实现）
- `tests/annotation_macros_integration.rs` 新建（13 个集成测试）
- `examples/src/oauth2_flow.rs` 添加 `#[allow(deprecated)]` 兼容旧 PKCE 方法
- 测试统计：lib 1101 个 + 集成测试 80+ 个，全部通过；clippy 零警告；fmt 通过

## [0.4.0] - 2026-07-02

### 概述

Bulwark 0.4.0 聚焦于 0.2.0 协议层遗留 gap 的补齐。通过 openspec change
`v0-2-0-protocol-layer-gap-closure` 实施 8 项 gap 中的 7 项（gap #4 注解系统因 spec
错误 `OAuth2Client::validate_client_token` 不存在而延后至 0.5.0+）。

### 新增

- **OAuth2 RefreshToken GrantType（gap #1）**：`OAuth2Client::refresh_access_token` 方法
  支持 grant_type=refresh_token 流程，可选 scope 参数（用于缩小/扩大授权范围）
- **OAuth2 OIDC 支持（gap #2）**：新增 `protocol-oidc` feature + `OidcHandler` struct
  （sign_id_token / verify_id_token / discovery_metadata），id_token 含标准 OIDC claims
  （iss/sub/aud/exp/iat/nonce/login_id），三重校验（iss/aud/nonce）防重放
- **OAuth2 Scope Handler 注册表（gap #3）**：新增 `oauth2-scope-handler` feature +
  `ScopeHandler` trait + `ScopeRegistry` struct（parking_lot::RwLock + HashMap），
  `OAuth2Client::with_scope_registry` 注入后 3 个 token 方法在 HTTP 请求前委托校验
- **SSO Server 独立抽象（gap #5）**：新增 `protocol-sso-server` feature + `SsoServer`
  trait + `CenterIdConverter` trait + `SsoChannel` trait + `DefaultSsoServer` +
  `IdentityCenterIdConverter` + `NoopSsoChannel`，支持通过共享 BulwarkDao 与 SsoClient
  间接通信
- **AloneCache 多 Redis 实例隔离（gap #6）**：新增 `alone-cache` feature + `AloneCache`
  装饰器（实现 BulwarkDao，入口拼接 key_prefix 后委托 inner dao）+ `AloneCacheManager`
  （RwLock + HashMap 多实例管理）
- **ParameterQuery 参数化查询（gap #7）**：新增 `parameter-query` feature +
  `ParameterQuery` trait + `ParameterQueryBuilder`（链式 with_login_id/with_device/with_token
  - async check_permission/check_role），token 上下文优先于 login_id

### 变更

- `Cargo.toml` 新增 5 个 feature flag：`protocol-oidc` / `oauth2-scope-handler` /
  `protocol-sso-server` / `alone-cache` / `parameter-query`，均加入 `full` 聚合
- `Cargo.toml` 新增 `base64` dev-dependency（OIDC 测试解析 JWT header 段）
- `OAuth2Client` 新增 `scope_registry: Option<Arc<ScopeRegistry>>` 字段（feature-gated）
- `OAuth2Client` 3 个 token 方法新增 `validate_scope` 调用（feature-gated，未注入跳过）
- `src/protocol/oauth2/mod.rs` 模块文档注释更新（"三种"→"四种"，新增 RefreshToken）
- `specmark/specs/dao-oxcache-basic/spec.md` 新增 Known Limitations 章节：oxcache 0.3
  支持 standalone/sentinel/cluster，master-slave 由 sentinel 模式覆盖

### 修复（代码审查后，全维度 review pass）

- **M5（MEDIUM）**：`SsoClient::validate_ticket` 与 `DefaultSsoServer::validate_ticket` 在
  `client_id` 不匹配时错误类型由 `Config` 改为 `InvalidToken`（认证失败语义更准确，
  票据被错误方持有属于认证失败而非配置错误）。同步修复 2 处集成测试断言
  （`tests/protocol_sso_edge_cases.rs` / `tests/protocol_sso_integration.rs`）
- **M6（MEDIUM）**：`SsoTicketData` 跨 `sso::mod.rs` 与 `sso::server.rs` 重复定义，
  改为 `pub(crate)` 导出 + `use super::SsoTicketData` 复用，避免格式漂移
- **M7（MEDIUM）**：`ParameterQueryBuilder::check_permission` / `check_role` ~40 行重复，
  提取 `check_common` helper + `CheckKind` enum，消除重复
- **M4（MEDIUM）**：`OidcHandler::with_algorithm` 接受非对称算法但实现只支持对称密钥，
  新增 `require_hmac_algorithm()` 在 `sign_id_token` / `verify_id_token` 入口校验，
  非对称算法返回 `Config` 错误。新增 2 个回归测试
  （`sign_id_token_rejects_asymmetric_algorithm` /
  `verify_id_token_rejects_asymmetric_algorithm`）
- **L9（LOW）**：`verify_id_token_tampered_fails` 测试断言过弱（仅 `is_err()`），
  强化断言错误类型为 `InvalidToken`
- **M1（MEDIUM，文档警告）**：SSO `validate_ticket` 的 get→delete 非原子存在 TOCTOU 竞态，
  在 `SsoClient` 与 `SsoServer` trait 的 doc 注释中添加显式警告，待 0.5.0+ 设计原子
  get-and-delete 后统一修复

### 文档与示例（代码审查后补全）

- **examples 覆盖 0.4.0 全部新特性**：新增 5 个 example（`oidc_handler` / `scope_handler` /
  `sso_server` / `alone_cache` / `parameter_query`），每个 bin 配套独立 `tests/<name>.rs`
  测试文件；扩展 `oauth2_flow` 增加 `refresh_access_token` 演示段落
- **examples/Cargo.toml**：新增 5 个 feature 转发（`protocol-oidc` / `oauth2-scope-handler` /
  `protocol-sso-server` / `alone-cache` / `parameter-query`）+ 5 个 `[[bin]]` 段，
  `full` 聚合特性同步更新

### 按规则 7 暴露冲突（不修复）

- **M2/M3（MEDIUM）**：`OAuth2Client::exchange_code` 的 `_state` 参数与
  `OAuth2Client::get_password_token` 的 `_scope` 参数未使用。这是有意保留的
  forward-compat API 参数（doc 注释已说明），移除会破坏 0.4.0 公共 API。维持现状

### 已知限制

- **gap #4（OAuth2 @CheckAccessToken/@CheckClientToken 注解）延后至 0.5.0+**：spec 错误
  引用 `OAuth2Client::validate_client_token`（方法不存在于代码库）。需先设计 token
  introspection（RFC 7662）或复用 OidcHandler::verify_id_token 的方案
- **SSO TOCTOU 竞态（M1）**：`validate_ticket` 的 get→delete 非原子，并发调用同一 ticket
  时理论上可重放。60 秒 TTL 窗口内影响有限，安全敏感场景应通过外层加锁或单点校验保证。
  待 0.5.0+ 设计原子 get-and-delete 后统一修复

## [0.2.1] - 2026-07-01

### 概述

Bulwark 0.2.1 是 0.2.0 的 PATCH 版本，聚焦于：auto-wire gap 修复、协议层边界场景测试补全、
examples 工程化重组与文档补充。本版本不引入新协议或新功能特性，仅包含 bug 修复与稳定性优化。

### 修复

- **auto-wire gap（TG4+TG5）**：修复 `BulwarkManager::init` 未注入 PluginManager /
  ListenerManager / AuthLogic / PermissionChecker 的 gap。`BulwarkLogicDefault` 新增 4 个可选字段
  与 builder 方法，`login` / `logout` / `kickout` / `login_by_token` / `refresh_token` 现自动触发
  plugin 钩子与 listener 事件。`BulwarkLogicFactoryFn` 签名扩展为接收 `&BulwarkLogicFactoryContext`
  以支持 factory 注入 manager。

### 新增（测试与工程化）

- **协议层边界场景测试（TG6-TG11）**：新增 6 个测试文件共 20 个边界场景测试
  - OAuth2: refresh_token 失效 / scope 边界 / code 重放 / expires_in=0
  - SSO: ticket 格式非法 / centerId 映射缺失 / 并发校验仅一次成功
  - JWT: none 算法注入拒绝 / iat 未来时间容忍 / refresh 过期 / 空 claims
  - Sign: nonce 重放拒绝 / timestamp 漂移超出窗口 / 缺失必填参数
  - APIKey: namespace 隔离 / 过期校验 / 格式非法
  - Temp: 一次性凭证失效 / 过期校验 / scope 越权
- **auto-wire 集成测试（TG5.8）**：新增 3 个集成测试验证 `BulwarkUtil::login/logout` 自动触发
  plugin/listener
- **examples 工程化重组（TG2-TG3）**：examples 从零散 `.rs` 文件重组为 workspace member
  （`bulwark-examples` crate，`publish = false`），每个 bin 配套独立 `tests/<name>.rs` 测试文件

### 变更

- `BulwarkLogicFactoryFn` 类型签名扩展（新增第 4 个参数 `&BulwarkLogicFactoryContext`）
  — 0.x.x 阶段可接受的不兼容变更，自定义 factory 需适配新签名
- `BulwarkLogicDefault` 新增 4 个字段（`plugin_manager` / `listener_manager` / `auth_logic` /
  `permission_checker`），均通过 builder 方法注入，向后兼容（未注入时行为同 0.2.0）

### 文档

- 修复 `examples/src/context_request.rs` 模块 doc 中未闭合 HTML 标签 `Request<Body>`
- `cargo doc --no-deps --features full --workspace` 零警告

### 测试

- 693 tests passing（+30 vs 0.2.0 的 663）
- clippy 零警告（`-D warnings`）
- 90%+ 覆盖率（保持 0.2.0 水平）

## [0.2.0] - 2026-07-01

### 概述

Bulwark 0.2.0 在 0.1.0 核心基础设施上补全了 13 个占位特性域，覆盖全部能力。
本版本新增 17 个 capability，修改 3 个 capability，新增 200+ 单元测试 + 32 个集成测试，
覆盖率 92.56%。所有协议层与安全模块均通过 spec-driven TDD 工作流实现。

### 新增（17 个 capability）

#### 协议层模块（6 个）

- **protocol-jwt**：JWT 签发与验证（HS256/HS512，自定义 claims，过期校验），
  `JwtHandler` 提供 `sign(login_id, timeout)` / `verify(token)` / `refresh(token)`
- **protocol-oauth2**：OAuth2 授权码模式（Authorization Code）、客户端凭证模式（Client Credentials）、
  密码模式（Password），`OAuth2Client` 提供 `exchange_code` / `get_client_credentials_token` /
  `get_password_token` / `get_auth_url`
- **protocol-sso**：SSO 单点登录 ticket 模型（签发、校验、销毁），64 字符随机 ticket，
  60 秒 TTL，一次性使用，`SsoClient` 跨子系统通过共享 `BulwarkDao` 实现 SSO
- **protocol-sign**：API 签名认证（HMAC-SHA256 + nonce + timestamp 防重放）
- **protocol-apikey**：API Key 认证（生成/校验/吊销/轮换）
- **protocol-temp**：临时凭证（短期 token，自动过期，issue/get/revoke/consume）

#### 安全模块（4 个）

- **secure-totp**：TOTP 动态验证码（RFC 6238，30 秒窗口，6 位数字），
  `TotpHandler` 提供 `generate(secret)` / `validate(secret, code)`
- **secure-sign**：安全签名工具（HMAC-SHA256/SHA512，Base64 编码，MD5 工具）
- **secure-httpbasic**：HTTP Basic 认证（RFC 7617，Base64 编解码）
- **secure-httpdigest**：HTTP Digest 认证（RFC 7616，MD5/SHA256）

#### 核心模块（3 个）

- **core-auth**：`AuthLogic` trait + `DefaultAuthLogic`，整合 login/verify/refresh
- **core-permission**：`PermissionChecker` trait + `DefaultPermissionChecker`，支持 RBAC/ABAC
- **core-token**：`Token` trait + `TokenStyleFactory`，支持 uuid/random_64/simple/jwt 风格

#### 辅助模块（4 个）

- **exception-system**：`BulwarkException` 异常类型体系（含 login_type、token_value 等上下文）
- **json-template**：`BulwarkJsonTemplate` / `BulwarkSerializer` trait（JSON 模板与序列化抽象）
- **plugin-system**：`BulwarkPlugin` trait + `BulwarkPluginManager` + inventory 编译期注册，
  生命周期钩子（on_login / on_logout / on_permission_check），插件失败仅 tracing::warn!
- **listener-system**：`BulwarkListener` trait + `BulwarkListenerManager` + 事件广播，
  6 个事件变体（Login / Logout / Kickout / PermissionDenied / RoleDenied / TokenExpired）

### 修改（3 个 capability）

- **core-auth-api**：扩展 `BulwarkLogic` trait，新增 `login_by_token` / `verify_token` / `refresh_token`
  默认方法（向后兼容 0.1.0）；修复 `generate_token` 对 "jwt" style 的支持（委托 `JwtHandler::sign`）
- **session-management**：扩展 `BulwarkSession`，支持 SSO ticket 关联与临时凭证关联
- **permission-role-check**：扩展 `BulwarkFirewallStrategyDefault`，集成 `PermissionChecker`，
  支持角色层级（hierarchy）、插件钩子、权限缓存短路

### 文档与示例

- **crate-level 文档**：新增 0.2.0 模块概览，修正 default feature 描述
- **协议/安全模块文档**：移除占位描述，添加实现引用
- **示例代码**：
  - `examples/jwt_login.rs`：JwtHandler sign/verify/refresh 完整流程
  - `examples/oauth2_flow.rs`：OAuth2Client 构造 + get_auth_url
  - `examples/sso_flow.rs`：SsoClient ticket 签发/校验/销毁（含 InMemoryDao）
  - `examples/totp_login.rs`：TotpHandler generate/validate + Base32 解码

### 集成测试

- **tests/protocol_jwt_integration.rs**（4 tests）：JWT 完整 login/verify/refresh/logout 流程
- **tests/protocol_oauth2_integration.rs**（7 tests）：wiremock mock 授权服务器，
  覆盖 Authorization Code / Client Credentials / Password 三种流程
- **tests/protocol_sso_integration.rs**（9 tests）：跨子系统 ticket 签发 → 校验 → 销毁，
  验证一次性使用、client_id 隔离、destroy 跨子系统生效
- **tests/plugin_listener_integration.rs**（12 tests）：inventory 编译期注册 +
  钩子调用 + 事件广播 + 端到端生命周期协同

### 测试覆盖率

- **lib tests**：565 个
- **集成测试**：43 个（annotation 9 + axum 11 + dbnexus 10 + jwt 4 + oauth2 7 + sso 9 + plugin_listener 12）
  - 注：部分测试在多 feature 组合下重复编译，全量运行时为 633 tests passed
- **doc-tests**：6 passed, 9 ignored
- **覆盖率**：92.56%（1430/1545 行），超过 90% 目标

### 特性域

| 特性域 | 状态 | 说明 |
|--------|------|------|
| 登录认证 | ✅ 完成 | 基于 Token 的会话管理 |
| 权限认证 | ✅ 完成 | RBAC 权限模型 + PermissionChecker |
| Session 会话 | ✅ 完成 | 双模会话 + SSO/temp 关联 |
| 路由拦截鉴权 | ✅ 完成 | axum Web 框架适配 |
| 插件化扩展 | ✅ 完成 | BulwarkPlugin + inventory 注册 |
| OAuth2 | ✅ 完成 | 三种授权模式 |
| 单点登录 (SSO) | ✅ 完成 | ticket 模型 + 跨子系统 |
| JWT | ✅ 完成 | HS256/HS512 + refresh |
| 微服务网关鉴权 | ✅ 完成 | API 签名认证 |
| API 接口鉴权 | ✅ 完成 | API Key 认证 |
| TOTP 动态验证码 | ✅ 完成 | RFC 6238 |
| Basic 认证 | ✅ 完成 | RFC 7617 |
| Digest 认证 | ✅ 完成 | RFC 7616 |

### 已知限制

- **auto-wire gap**：`BulwarkLogicDefault` 当前不持有 `BulwarkPluginManager` / `BulwarkListenerManager`，
  `BulwarkUtil::login` 不会自动触发 `on_login` / `Login` 事件。需用户在业务层手动调用
  plugin/listener manager。此 auto-wire 在延后任务 13.4/13.5 中实现
- **login_by_token 默认实现**：`BulwarkLogicDefault` 未 override `login_by_token`（返回 `NotImplemented`），
  OAuth2/SSO 场景需直接使用协议层 client
- **oxcache 0.3 `Cache<K,V>::update`**：无法保留 per-entry TTL（同 0.1.0）
- **dbnexus 0.2**：仅支持 SQLite（同 0.1.0）

### 最低支持 Rust 版本

- Rust 1.85+（同 0.1.0）

## [0.1.0] - 2026-06-30

### 概述

Bulwark 0.1.0 是首个里程碑版本，实现了身份认证鉴权框架的核心基础设施。
提供基于 Token 的会话管理、RBAC 权限模型、
axum Web 框架集成等核心能力。

### 新增

#### 核心基础设施

- **错误类型体系**：`BulwarkError` 枚举，涵盖 12 个变体
  （NotLogin / NotPermission / NotRole / InvalidToken / ExpiredToken / Dao / Config / Internal / Session / Annotation / Context）
- **配置系统**：`BulwarkConfig` 全局配置，支持代码默认值 / toml 文件 / 环境变量三级配置源，
  通过 `tokio::sync::watch` 实现热更新
- **上下文抽象**：`BulwarkContext` / `BulwarkRequest` / `BulwarkResponse` / `BulwarkStorage` trait，
  解耦 Web 框架依赖；提供 axum 适配器 `AxumRequest` / `AxumResponse` / `AxumStorage` / `AxumContext`

#### 数据访问层

- **DAO 抽象**：`BulwarkDao` trait，提供 get / set / update / delete / expire 五元操作
- **oxcache 0.3 集成**：`BulwarkDaoOxcache` 实现，支持 per-entry TTL，
  通过 `Cache<K,V>::ttl()` 保留原有 TTL（依赖本地 oxcache 仓库）
- **dbnexus 0.2 集成**：`init_dbnexus` 初始化 + `BulwarkMigration` 8 张核心表迁移
  （users / oauth2_accounts / roles / permissions / user_roles / user_permissions / sessions / user_ext）

#### 会话与认证

- **双模会话管理**：`BulwarkSession` 支持 Account-Session（按 login_id 索引）+ Token-Session（按 token 索引）
- **核心认证 API**：`BulwarkLogic` trait 定义 login / logout / check_login / kickout 完整契约，
  `BulwarkLogicDefault` 默认实现
- **task_local 上下文**：`with_current_token` / `current_token` 提供 async 请求级 token 存取
- **权限校验策略**：`BulwarkFirewallStrategy` trait + `BulwarkFirewallStrategyDefault` 默认实现

#### 全局管理器

- **BulwarkManager 单例**：持有 `Arc<dyn BulwarkLogic>` 全局引用，支持显式 `init()` 初始化
  - 覆盖式更新 + `reset_for_test()`（cfg(test)）
- **inventory 编译期注册**：`BulwarkLogicFactoryEntry` 通过 `inventory::submit!` 注册工厂函数，
  支持编译期扩展
- **BulwarkUtil 静态委托**：8 个静态方法（login / logout / kickout / check_login / get_login_id /
  check_permission / check_role）委托到 `BulwarkManager::logic()?`

#### axum Web 框架集成

- **注解系统**：5 个 axum extractor（`CheckLogin` / `CheckRole<R>` / `CheckPermission<P>` /
  `Ignore` / `Mode<M>`），基于 Marker struct + 关联常量模式
- **`IntoResponse` 实现**：`BulwarkError` 自动映射 HTTP 状态码
  （401 Unauthorized / 403 Forbidden / 500 Internal Server Error）
- **BulwarkRouter**：包装 `axum::Router`，提供 `route_protected(path, handler, annotation)` 语法糖
- **BulwarkInterceptor**：`pre_handle` trait + `DefaultBulwarkInterceptor` 默认实现
- **axum middleware**：自动从 header（Authorization: Bearer 或自定义 token_name）/ cookie 提取 token，
  通过 `with_current_token` 设置 task_local

#### 文档与示例

- **crate-level 文档**：包含快速开始 / 特性 / 架构 3 个章节
- **public API 文档**：所有 pub 项均有 `///` 文档注释
- **示例代码**：
  - `examples/basic_login.rs`：完整业务场景（init + login + check + logout，144 行）
  - `examples/axum_integration.rs`：完整 Web 应用（BulwarkRouter + 4 路由 + 服务器启动，244 行）

### 特性域

| 特性域 | 状态 | 说明 |
|--------|------|------|
| 登录认证 | ✅ 完成 | 基于 Token 的会话管理 |
| 权限认证 | ✅ 完成 | RBAC 权限模型 |
| Session 会话 | ✅ 完成 | 双模会话生命周期管理 |
| 路由拦截鉴权 | ✅ 完成 | axum Web 框架适配 |
| 插件化扩展 | 🚧 占位 | 0.2.0+ 实现 |
| OAuth2 | 🚧 占位 | 0.2.0+ 实现 |
| 单点登录 (SSO) | 🚧 占位 | 0.2.0+ 实现 |
| JWT | 🚧 占位 | 0.2.0+ 实现 |
| 微服务网关鉴权 | 🚧 占位 | 0.2.0+ 实现 |
| API 接口鉴权 | 🚧 占位 | 0.2.0+ 实现 |
| TOTP 动态验证码 | 🚧 占位 | 0.2.0+ 实现 |
| Basic 认证 | 🚧 占位 | 0.2.0+ 实现 |
| Digest 认证 | 🚧 占位 | 0.2.0+ 实现 |

### 技术栈

- **缓存抽象层**：oxcache 0.3（L1 内存 + L2 redis，支持 per-entry TTL）
- **数据库抽象层**：dbnexus 0.2（SQLite + 自动迁移）
- **Web 框架**：axum 0.7
- **异步运行时**：tokio 1.x
- **序列化**：serde + serde_json + toml

### 特性门控

| 特性 | 默认 | 说明 |
|------|------|------|
| `cache-memory` | ✅ | 内存缓存后端（oxcache） |
| `cache-redis` | ✅ | Redis 缓存后端（oxcache） |
| `db-sqlite` | ✅ | SQLite 数据库后端（dbnexus） |
| `web-axum` | ✅ | axum Web 框架适配 |
| `protocol-jwt` | ❌ | JWT 支持 |
| `protocol-oauth2` | ❌ | OAuth2 支持 |
| `protocol-sso` | ❌ | SSO 支持 |
| `protocol-sign` | ❌ | 签名认证 |
| `protocol-apikey` | ❌ | API Key 认证 |
| `secure-totp` | ❌ | TOTP 动态验证码 |
| `secure-sign` | ❌ | 安全签名 |
| `secure-httpbasic` | ❌ | HTTP Basic 认证 |
| `secure-httpdigest` | ❌ | HTTP Digest 认证 |
| `listener` | ❌ | 事件监听器 |
| `metrics-prometheus` | ❌ | Prometheus 指标 |
| `full` | ❌ | 聚合所有特性 |
| `production` | ❌ | 生产环境推荐特性组合 |
| `development` | ❌ | 开发环境特性组合 |

### 测试覆盖率

- **单元测试**：292 个
- **集成测试**：30 个（annotation_integration 9 + axum_integration 11 + dbnexus 10）
- **doc-tests**：1 passed, 9 ignored
- **覆盖率**：97.81%（669/684 行），未覆盖代码为少量错误分支

### 已知限制

- **oxcache 0.3 `Cache<K,V>::update`**：无法保留 per-entry TTL（`Cache<K,V>` 未暴露 `ttl()`），
  当前使用 `set()` 覆盖（清除 per-entry TTL），待 oxcache 暴露 `ttl()` 后修复
- **dbnexus 0.2**：仅支持 SQLite，PostgreSQL/MySQL 待 0.2.0+ dbnexus 添加
- **BulwarkRouter::route_protected**：仅支持 GET 方法，其他方法待后续版本支持

### 最低支持 Rust 版本

- Rust 1.85+（部分 deps 如 inventory 0.3 要求 edition2024）

## [0.7.0] - 2026-07-17 (mod-crate-hardening 加固)

### 概述

v0.7.0 mod/crate 接口隔离加固 + 发布前强制安全审查。通过 specmark `mod-crate-hardening` change 管理，Rule 19 审查通过后发布。

### 修复（Rule 19 发布前强制审查）

#### CRITICAL: C1 本地路径依赖移除

- 删除 `[patch.crates-io]` 段：oxcache / dbnexus / inklog / limiteron / sdforge / trait-kit 全部切换到 crates.io 远程版本（oxcache 0.3.9 / dbnexus 0.4.1 / inklog 0.1.10 / limiteron 0.2.7 / sdforge 0.4.2 / trait-kit 0.3.0）

#### HIGH: H1 Rule 25 mod.rs 接口隔离

- 15 个 mod.rs 拆分测试代码到独立 `tests.rs` 文件：exception / state / listener / json / annotation / context / router / strategy::alert / plugin / account::authflow / account::credential / dao / config / session / abac
- 实现函数迁移到 `helpers.rs` / `init.rs` / `oxcache_impl.rs`：context (effective_is_read_header/cookie) / config (default_jwt_secret/collect_env_vars) / session (account_key/token_key) / abac (init_abac_engine/get_abac_engine/reset_abac_for_test/check_abac_with_policy) / dao (BulwarkDaoOxcache impl)
- mod.rs 现仅保留：trait 定义、pub struct/enum 字段声明、pub type 别名、pub use re-export、mod 声明

#### HIGH: H2 Rule 12 错误显性化

- `src/dao/mod.rs` BulwarkDao::incr 默认实现 + BulwarkDaoOxcache::incr：`v.parse::<u64>().unwrap_or(0)` 改为 `v.parse().map_err(...)` 显式报错
- `src/account/metrics.rs` AccountMetrics::gather + `src/observability/metrics_impl.rs` BulwarkMetrics::gather：`encoder.encode(...).ok()` 改为 `if let Err(e) = ... { tracing::warn!(...) }`

#### HIGH: H3 Rule 25 接口 re-export 补全

- `src/protocol/sso/mod.rs`：添加 `pub use oidc::{DefaultOidcProvider, OidcDiscoveryConfig, OidcProvider, OidcUserInfo}`
- `src/session/mod.rs`：添加 `pub use security_listener::SessionSecurityListener`

#### MEDIUM: 版本格式合规

- `serde` 1.0 → 1，`serde_json` 1.0 → 1（Rule 29 x.x 格式）
- `redis` ~1.2 → 1.2（移除 tilde requirement）
- `sea-orm` 2.0.0-rc.42 → 2.0.0-rc.43（升级到最新 RC，注释标注上游无稳定版）

### 验证

- 全量测试：3785 passed, 0 failed（full feature）
- clippy（主项目）：0 warnings（`-D warnings`）
- cargo doc：0 warnings（`RUSTDOCFLAGS="-D warnings"`）
- tiangang SAST：0 CRITICAL（唯一 MEDIUM 为 rsa 0.9.10 Marvin Attack 上游无补丁）
- diting 代码审查：1 CRITICAL + 3 HIGH 全部修复
