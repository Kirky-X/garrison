# OWASP ASVS 4.0 自评 — Garrison

> **定位声明**：本文是 Garrison 对 OWASP Application Security Verification Standard 4.0 **V2（认证）与 V3（会话管理）** 章节的**自评留档**——自评不是认证，不构成任何第三方保证。作为**框架**（非最终应用），标注口径为「框架提供的能力/默认行为」；标注「不适用」表示该控制点属于最终应用或部署方的职责而非框架 SDK 能覆盖的范围。
>
> 评级图例：✅ 满足（框架提供且经测试）｜🔶 部分满足（框架提供基座，需业务方配置/组合）｜⚪ 不适用（应用/部署方职责）
>
> 关联：[SECURITY.md](../SECURITY.md)｜[THREAT.md](./THREAT.md)｜ADR-0001/0002/0003（密码哈希 / CSPRNG / 常量时间比较）

## V2 认证

### V2.1 密码安全

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 2.1.1 | 用户可设置密码须满足强度要求 | 🔶 | `account-policy` 密码策略引擎（`src/account/policy/`，长度/复杂度规则可配置）；阈值由业务方设定 |
| 2.1.2 | 密码长度 ≥64 字节需支持（防截断） | 🔶 | 密码以 `&str` 传入 `PasswordHasher`，无框架级长度截断；上限策略属业务方 |
| 2.1.3 | 密码不含控制字符/规范化处理 | ✅ | `unicode-normalization` NFC 规范化参与凭据处理；`secure-confusable` 提供同形异义字检测 |
| 2.1.6 | 密码更换须验证旧密码 | 🔶 | 凭据验证原语由 `account-credential` 提供；更换流程编排属业务方（`account-authflow` 提供基座） |
| 2.1.7 | 弱密码字典/泄露库校验 | ✅ | `policy-hibp`（HIBP k-anonymity 范围查询，不泄露原密码）+ 可插拔策略规则 |
| 2.1.9 | 密码哈希：盐化 + 慢哈希（Argon2id 等） | ✅ | `Argon2Hasher`（Argon2id m=19456/t=2/p=1，PHC 自描述盐）；锁定测试 + ADR-0001 |
| 2.1.11 | 密码哈希算法与参数可升级 | ✅ | PHC 字符串自描述参数，verify 按串解析（ADR-0001 Decision 4）；`password_hasher` 配置节可控参数（下限校验） |

### V2.2 一般用户安全

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 2.2.1 | 反自动化：登录/重置/注册暴露的控制面须有反自动化措施 | ✅ | `firewall-bruteforce`（IP 级失败计数封禁，CWE-307）+ `firewall-ratelimit`；API Key 校验失败按 IP 计入（`protocol-apikey` + `with_current_ip`） |
| 2.2.2 | 登录失败提示不区分「用户不存在/密码错误」 | 🔶 | 错误消息 i18n 体系（`GarrisonError` 结构化）支持统一话术；具体文案由业务方配置 |
| 2.2.4 | 注册凭据须与已知泄露库比对 | 🔶 | `policy-hibp` 可在注册编排中启用；是否强制由业务方决定 |

### V2.3 认证器生命周期

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 2.3.1 | 新建认证器须验证用户身份（含重置流程） | 🔶 | `account-authflow` 条件引擎（IP 白名单等）+ `protocol-invitation` 邀请码定向注册（一次性/TTL/防爆破）；完整身份核验链路由业务方编排 |
| 2.3.3 | 凭据更新后使旧会话失效 | ✅ | `listener/audit` Replaced 事件 + 登录顶替/替换语义（`stp/session`，ReplacedLoginExitMode 可配置踢出策略） |

### V2.5 通用认证器

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 2.5.1 | 系统须抵抗暴力破解攻击 | ✅ | `firewall-bruteforce` + `account-lockout` + `firewall-ratelimit`（GCRA/滑动窗口，分布式后端 `rate-limit-redis`） |
| 2.5.2 | 安全验证码（OTP）须经系统安全生成 | ✅ | 备份码/验证码走 `getrandom::fill`（OS CSPRNG，ADR-0002）；邮箱验证码 `email-verification` 同源 |

### V2.7 单点登录 / MFA

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 2.7.1 | 合并 SSO 的认证策略（CSRF 防护、防重定向利用） | 🔶 | `protocol-sso-server`（SsoServer/channel 订阅模型）、OIDC `state` 一次性 + TTL；SP 端策略由业务方 |
| 2.7.3 | MFA 绑定须验证持有 | 🔶 | `secure-totp`（TOTP 绑定校验原语）；MFA 流程编排属业务方 |

### V2.8 TOTP / 时间型 OTP

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 2.8.1 | TOTP 密钥 ≥20 字节、每账户唯一 | ✅ | `TotpHandler::new` 密钥 <10 字节报错（totp-rs 约束 + 框架校验）；密钥由调用方生成（推荐 CSPRNG） |
| 2.8.2 | TOTP 算法一致性（RFC 6238） | ✅ | RFC 6238 Appendix B 官方向量测试锁定（SHA1/SHA256/SHA512，`src/secure/totp/tests.rs`） |

## V3 会话管理

### V3.1 基础

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 3.1.1 | 会话 token 应与用户权限随动、可吊销 | ✅ | 会话集中存储于 DAO（`backend-embedded`/`backend-remote`）；`enable_jwt_revocation` + JWT Mixin 模式防无状态失联；Stateless+无吊销需 `allow_stateless_jwt_no_revocation` 显式风险接受 |
| 3.1.2 | token 生成须防预测（CSPRNG） | ✅ | token/授权码/refresh 生成统一 `getrandom::fill`（ADR-0002）；`secure-simple-token` 未启用签名时 generate 返回 Err（fail-closed） |

### V3.2 会话创建

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 3.2.1 | 登录须生成新会话 token（防会话固定） | ✅ | 登录/替换语义生成新 token（`stp/session`，旧会话按 Replaced 策略处理） |
| 3.2.2 | 凭据验证前不得创建会话 | ✅ | verify_token 在 session 创建前置路径（`stp/session/helpers.rs` 流程） |

### V3.3 会话终止

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 3.3.2 | 任何会话可被用户/管理员终止（logout） | ✅ | logout/踢出 API（`stp/session` + Manager API）；`session-hijack-detection` Kickout 模式 |
| 3.3.3 | 会话超时后服务端失效 | ✅ | `timeout`/`active_timeout`（config）驱动 DAO 过期；`session-extra` 动态活跃超时 |

### V3.4 Cookie 配置（Web 适配层）

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 3.4.1 | cookie `SameSite` 配置 | 🔶 | `cookie_same_site` config 项（web-axum 适配层）；HttpOnly/Secure 由适配层与代理设置 |
| 3.4.2 | Cookie 域与路径最小化 | ⚪ | 部署方按应用域配置 |

### V3.5 基于 Token 的会话

| # | 控制点 | 评级 | 证据 |
|---|--------|------|------|
| 3.5.1 | Bearer token 经 Authorization 头传递且不落 URL | 🔶 | 框架支持 header 携带与解析；客户端行为属业务方 |
| 3.5.3 | JWT 须校验签名与算法一致性 | ✅ | `JwtHandler` 密钥类型感知白名单（KeyMaterial，`validate_algorithm_match`）+ alg confusion 对抗测试锁定；config 层算法白名单 `JWT_ALGORITHMS` |
| 3.5.4 | 重放/过期 token 拒绝 | ✅ | `leeway=0`、`exp`/`nbf` 强制校验；refresh token 重放由 `RefreshTokenRotation` reuse detection（未注入时启动 warn 显性告警） |
| 3.5.5 | token 有效期最小化 | 🔶 | timeout/active_timeout/remember_me_timeout 可配置（默认 30d/90d，SECURITY.md 建议收紧）；默认值选择属业务权衡 |

## 自评结论与差距

**覆盖强项**：密码哈希（V2.1）、暴破防护（V2.2/2.5）、token 生成与校验（V3.1/3.5）、会话终止（V3.3）——均具备代码级证据与回归测试。

**框架边界内待增强（记入 ROADMAP 候选）**：

1. V3.4 Cookie 安全属性默认值可在 web 适配层提供更完整的 safe-by-default（当前依赖配置）。

2. V2.7 MFA 编排基座可进一步抽象（TOTP 原语已备）。

**明示不属于框架**：最终应用的用户 UI 交互、部署层 TLS、业务授权规则本身。
