# 🛡️ Garrison 威胁模型（THREAT.md）

本文档描述 Garrison 的威胁模型：以 **STRIDE** 六维分类，逐维说明**哪些攻击由框架防御**、**哪些责任留给业务方/部署方**。这是项目专业度与免责边界的正式声明——框架不会替代部署方的安全责任，双方边界必须清晰。

> 适用版本：0.9.0-rc.2。威胁模型随版本演进更新；攻击面变化的变更（新协议、新解析入口）应在同一变更中更新本文档。
>
> 相关文档：[SECURITY.md](https://github.com/Kirky-X/garrison/blob/main/SECURITY.md)（漏洞披露与 SLA）｜[OWASP_TOP10.md](https://github.com/Kirky-X/garrison/blob/main/docs/OWASP_TOP10.md)（Top 10 逐类映射）｜[ARCHITECTURE.md](https://github.com/Kirky-X/garrison/blob/main/docs/ARCHITECTURE.md)（分层架构）｜[DEPLOYMENT.md](https://github.com/Kirky-X/garrison/blob/main/docs/DEPLOYMENT.md)（部署加固）

## 📋 目录

- [系统边界与信任假设](#-系统边界与信任假设)
- [STRIDE 矩阵](#-stride-矩阵)
- [对抗面与既有防御索引](#-对抗面与既有防御索引)
- [明确不防御的攻击](#-明确不防御的攻击)

---

## 🌐 系统边界与信任假设

| 边界 | 信任假设 |
|------|---------|
| 应用进程内存 | 信任宿主机（不防御 root/内核级攻击、内存 dump 分析者可读未 zeroize 的密钥残留——建议启用 `credential-zeroize`/`protocol-zeroize`） |
| 网络传输 | **不信任**——TLS 终止由反向代理负责（框架不处理 TLS），代理与框架间须为可信网络 |
| 配置来源 | 信任启动配置的正确性（`config-security-rules` 提供加载期 fail-fast 校验：JWT 密钥强度/CORS/SSRF/TLS） |
| 依赖图 | 部分信任——`cargo deny`（RustSec/许可证/禁用源）、gitleaks、cargo vet 审核记录与 SBOM 构成供应链门禁（见根目录 [SECURITY.md](https://github.com/Kirky-X/garrison/blob/main/SECURITY.md) 供应链章节） |
| 密码学原语 | 信任 RustCrypto 栈（argon2/bcrypt/sha2/hmac/subtle/jsonwebtoken rust_crypto），不手写密码学原语 |
| 客户端输入 | **完全不信任**——所有外部输入（HTTP 头/XML/JSON/JWT/SAML）按恶意输入处理 |

## 🔴 STRIDE 矩阵

### S — Spoofing（仿冒）

| 框架防御 | 业务方责任 |
|---------|-----------|
| JWT 签名验证：密钥类型感知算法白名单（Secret→HS 系 / RSA PEM→RS 系 / EC PEM→ES 系 / Ed PEM→EdDSA，`validate_algorithm_match` 双重校验 + alg confusion 对抗测试）、HS 系密钥最小长度 ≥32 字节 fail-fast、`leeway=0` 严格过期、`nbf` 强制校验（`src/protocol/jwt/handler.rs`） | **JWT 密钥托管**：`GARRISON_JWT_SECRET` 环境变量注入、90 天轮换（[SECURITY.md](https://github.com/Kirky-X/garrison/blob/main/SECURITY.md) 安全配置建议） |
| HTTP Basic/Digest：RFC 7617/7616 解析与验证，Digest 默认 SHA-256（MD5 仅显式回退，见[已知安全考量](#-明确不防御的攻击)） | 下游身份源（LDAP/用户数据库）的账号安全由业务方保障 |
| TOTP（RFC 6238 官方向量测试锁定，`src/secure/totp/`） | Authenticator App 分发与账号恢复流程 |
| API Key：`sha256` 哈希存储（CWE-916）+ 常量时间比较（CWE-208）+ secret 一次性返回 | API Key 的分发渠道安全与 180 天轮换纪律 |
| OAuth2/OIDC/SAML：`state` 一次性使用与绑定校验、`nonce` 校验、id_token 强制验签（fail-closed）、SAML XML 签名验证（`protocol-saml`，ECDSA-SHA256 fail-closed 设计） | OAuth client_secret / SAML IdP 公钥的保管与来源校验 |
| 登录暴破防护：`firewall-bruteforce`（IP 级失败计数与封禁，`with_current_ip` 注入 + `extract_client_ip` 防 X-Forwarded-For 伪造） | 反向代理正确传递真实客户端 IP（trusted_proxies 配置） |

### T — Tampering（篡改）

| 框架防御 | 业务方责任 |
|---------|-----------|
| 请求防伪造：CSRF token（`web-cors`/`web-csrf`，CSPRNG 32B）、API 签名 HMAC（`protocol-sign`，nonce+时间窗防重放） | 前端与反向代理层的 HTTPS 强制（HSTS、禁用旧版 TLS） |
| 审计日志防篡改：`AuditEventChain` 链式哈希（`audit-log`/`audit-inklog`），链首盐取 OS CSPRNG（`getrandom::fill`） | 审计日志的**外部归档**（WORM 存储/SIEM——本机文件可被 root 修改） |
| 响应安全头：`web-security-headers`（X-Content-Type-Options/X-Frame-Options/HSTS/Cache-Control） | 数据库与 Redis 的访问控制、传输加密（`rediss://` + AOF） |
| 配置防漂移：`config-validation`/`config-security-rules` 加载期校验 | 配置文件与密钥文件的文件系统权限（600/700） |

### R — Repudiation（抵赖）

| 框架防御 | 业务方责任 |
|---------|-----------|
| 全事件审计：`listener/audit` 覆盖全部非门控事件（登录/登出/替换/邀请/积分等 20+ 事件类型），token 统一掩码 | 审计日志保留周期与外部不可变存储（合规要求的留存期限由业务方定） |
| API Key `last_used_at` 追踪 + `owner_id` 归属记录 | 关键业务操作的**应用层**业务审计（框架审计认证事件，业务动作需业务方记录） |
| 登录/登出/封禁事件的 SIEM 外送（`audit-inklog-siem`，TCP/UDP 断线缓冲重连） | SIEM 侧的完整性与告警规则配置 |

### I — Information Disclosure（信息泄露）

| 框架防御 | 业务方责任 |
|---------|-----------|
| Token 掩码：审计事件中 token 统一掩码（`secure-masking`，CWE-532） | **日志聚合系统的访问控制**（框架脱敏后，聚合平台仍需鉴权） |
| 密钥零化：`credential-zeroize`/`protocol-zeroize`（Drop 时覆写内存）；`jwt_secret` Debug 手动脱敏 | 生产部署**显式启用** zeroize feature（默认关闭以保持零开销）；swap 加密/core dump 禁用策略 |
| API Key secret 仅生成时返回一次，落库仅哈希 | 错误响应不透传内部细节（框架错误码已结构化，业务层不得将 `GarrisonError` 原文直接回显给终端用户） |
| CORS：`web-cors` 显式 allowlist | CORS allowlist 的正确配置（宽松 `*` 是业务方决策） |
| 密码强度：`account-policy` 密码策略 + HIBP 泄露库检查（`policy-hibp`，k-anonymity 不泄露原密码） | 密码策略阈值按业务风险设定 |

### D — Denial of Service（拒绝服务）

| 框架防御 | 业务方责任 |
|---------|-----------|
| 限流：`firewall-ratelimit`（滑动窗口/GCRA）、`rate-limit-redis` 分布式后端、`firewall-ddos`、`firewall-admission`（AIMD 自适应并发） | **上游基础设施**：CDN/云 WAF/ SYN 防护（框架在应用层，无法防御传输层洪水） |
| 暴破与封禁：`firewall-bruteforce`（IP 级计数封禁）+ `ban-sync`（跨实例同步） | Redis/数据库的容量规划与高可用（缓存穿透时 DAO 回源压力） |
| 慢哈希稳定耗时：Argon2id/bcrypt 经 `spawn_blocking` 下沉，不阻塞 reactor | 登录端点的并发上限（框架限流参数）按机器规格调优 |
| 解析器健壮性：`fuzz/` 四入口模糊测试（SAML XML/OIDC discovery/JWT/HTTP 认证头）回归 | 新增解析入口时同步扩展 fuzz target（见 fuzz/Cargo.toml） |

### E — Elevation of Privilege（权限提升）

| 框架防御 | 业务方责任 |
|---------|-----------|
| 授权引擎：RBAC（`permission-rbac`）+ ABAC（cedar-policy，`abac` feature）+ `forbid` 优先语义（`core-advanced`） | **权限模型配置正确性**（框架执行规则，规则本身由业务方定义——最小权限原则） |
| 多租户隔离：`tenant-isolation`（DAO 层按租户加前缀 + namespace 强制校验，防 IDOR） | 租户边界的业务定义（哪些资源属于哪个租户） |
| 会话劫持检测：`session-hijack-detection`（IP 变更告警/踢出）+ `device-binding` | 管理员账号的额外保护（MFA 强制、独立网络策略） |
| 账号锁定：`account-lockout` + `account-authflow`（IP 白名单等条件求值） | 锁定策略的解锁流程（防锁定滥用） |

## 🎯 对抗面与既有防御索引

| 对抗场景 | 防御位置 | 对抗测试 |
|---------|---------|---------|
| JWT alg confusion / none 算法 | `protocol::jwt` verify 固定单算法 + 库层拒绝 none | `src/protocol/jwt/tests.rs` |
| JWT 弱密钥 | `MIN_SECRET_BYTES=32` fail-fast + config 白名单按算法校验长度 | `src/config/tests.rs` |
| PKCE 降级（plain） | `oauth2_server/authorize.rs` 强制 S256（43 字符长度校验防 DoS） | `tests/acceptance/protocol_oauth2.rs` |
| redirect_uri 前缀/通配绕过 | client 白名单精确匹配 | `tests/acceptance/protocol_oauth2.rs` |
| refresh token 重放 | `RefreshTokenRotation` reuse detection + 链式撤销（未注入时 warn 显性告警） | `src/oauth2_server/token.rs` |
| 状态参数伪造/重放 | OIDC `state` 一次性 + TTL（`protocol/sso/oidc.rs`） | oidc.rs 内嵌测试 |
| API Key 泄露后的横向使用 | sha256 哈希存储 + IP 级失败限速 + namespace 隔离 | 根目录 SECURITY.md（GitHub 仓库主路径）API Key 安全节 |
| 定时侧信道（token 比较） | `secure-ct-eq` 常量时间公共原语（subtle） | `tests/constant_time_eq.rs` |
| XML 注入/畸形 SAML | 长度限制 + 特殊字符拒绝 + 签名 fail-closed + fuzz 回归 | `fuzz/fuzz_targets/fuzz_saml_xml.rs` |

## ⛔ 明确不防御的攻击

以下攻击面**超出框架边界**，须由部署方/业务方自行防御：

1. **传输层网络攻击**（SYN 洪水、DNS 劫持、BGP 劫持）——CDN/云网络层防护。
2. **TLS 终止前的流量窃听**——Garrison 不处理 TLS；反向代理必须正确配置。
3. **宿主机/内核级攻击**（root 提权后读内存、container escape）——进程隔离、加密 swap、最小权限容器运行时。
4. **物理访问**（disk 拔取、RAM 冷启动）——磁盘加密、密钥不落盘（KMS/Vault 注入）。
5. **业务逻辑授权缺陷**（业务规则本身的越权，如"只能删除自己的订单"未实现）——框架执行业务方定义的规则，规则缺失不归框架。
6. **已弃用算法的显式启用**（如显式指定 HTTP Digest MD5）——框架提供 safe-by-default 并在 [SECURITY.md 已知安全考量](https://github.com/Kirky-X/garrison/blob/main/SECURITY.md#️-已知安全考量)中警示，显式绕过属业务方决策。
7. **社会工程与凭证钓鱼**——用户教育、MFA 强制（`secure-totp` 需业务方启用）。
8. **供应链上游投毒**（crates.io 账号被盗后发布恶意版本）——`cargo vet` 审核记录 + SBOM + lockfile 提供检测与追溯，不提供事前绝对防御。

---

发现威胁模型未覆盖的攻击面？请按 [SECURITY.md](https://github.com/Kirky-X/garrison/blob/main/SECURITY.md) 流程私密报告（含"威胁模型缺口"标注）。
