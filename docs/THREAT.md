# 🛡️ Garrison 威胁模型（THREAT.md）

本文档描述 Garrison 的威胁模型：以 **STRIDE** 六维分类，逐维说明**哪些攻击由框架防御**、**哪些责任留给业务方/部署方**。这是项目专业度与免责边界的正式声明——框架不会替代部署方的安全责任，双方边界必须清晰。

> 适用版本：0.9.0-rc.2。威胁模型随版本演进更新；攻击面变化的变更（新协议、新解析入口）应在同一变更中更新本文档。
>
> 相关文档：[SECURITY.md](../SECURITY.md)（漏洞披露与 SLA）｜[OWASP_TOP10.md](./OWASP_TOP10.md)（Top 10 逐类映射）｜[ARCHITECTURE.md](./ARCHITECTURE.md)（分层架构）｜[DEPLOYMENT.md](./DEPLOYMENT.md)（部署加固）

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
| 依赖图 | 部分信任——`cargo deny`（RustSec/许可证/禁用源）、gitleaks、cargo vet 审核记录与 SBOM 构成供应链门禁（见根目录 [SECURITY.md](../SECURITY.md) 供应链章节） |
| 密码学原语 | 信任 RustCrypto 栈（argon2/bcrypt/sha2/hmac/subtle/jsonwebtoken rust_crypto），不手写密码学原语 |
| 客户端输入 | **完全不信任**——所有外部输入（HTTP 头/XML/JSON/JWT/SAML）按恶意输入处理 |

## 🔴 STRIDE 矩阵

### S — Spoofing（仿冒）

| 框架防御 | 业务方责任 |
|---------|-----------|
| JWT 签名验证：密钥类型感知算法白名单（Secret→HS 系 / RSA PEM→RS 系 / EC PEM→ES 系 / Ed PEM→EdDSA，`validate_algorithm_match` 双重校验 + alg confusion 对抗测试）、HS 系密钥最小长度 ≥32 字节 fail-fast、`leeway=0` 严格过期、`nbf` 强制校验（`src/protocol/jwt/handler.rs`） | **JWT 密钥托管**：`GARRISON_JWT_SECRET` 环境变量注入、90 天轮换（[SECURITY.md](../SECURITY.md) 安全配置建议） |
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
| 慢哈希稳定耗时：Argon2id/bcrypt 经 `spawn_blocking` 下沉，不阻塞 reactor；Argon2 并发令牌池（`password_hasher.argon2_pool_size`，默认 1）限制同时执行中的 Argon2 数量——**QPS 限流 × 内存驻留双层防护**：限流约束到达率，permit 池约束内存上界 ≈ `pool_size × m_cost`（verify 路径每 permit 驻留按存量哈希内嵌 `m_cost` 计，混合存量部署按 `max(配置 m, 存量 m)` 评估；permit 存活期 == 哈希执行期，任何取消时序下不超卖） | `argon2_pool_size` 按内存预算调优（[CONFIGURATION.md](CONFIGURATION.md)）；`PasswordVerifier::verify` 同步便捷路径不经池（默认参数直连校验，适合低频管理场景），高频校验应走 `PasswordCredential::verify` / `login_with_password` 池化路径 |
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
| refresh token 重放 | `RefreshTokenRotation` 三级重用分类（RecentPrev / OrphanedBranch / StaleLineage）+ 链式撤销（未注入时 warn 显性告警），处置见下表 | `src/protocol/jwt/refresh.rs` 内嵌测试 |
| 状态参数伪造/重放 | OIDC `state` 一次性 + TTL（`protocol/sso/oidc.rs`） | oidc.rs 内嵌测试 |
| API Key 泄露后的横向使用 | sha256 哈希存储 + IP 级失败限速 + namespace 隔离 | 根目录 [SECURITY.md](../SECURITY.md) API Key 安全节 |
| 定时侧信道（token 比较） | `secure-ct-eq` 常量时间公共原语（subtle） | `tests/constant_time_eq.rs` |
| XML 注入/畸形 SAML | 长度限制 + 特殊字符拒绝 + 签名 fail-closed + fuzz 回归 | `fuzz/fuzz_targets/fuzz_saml_xml.rs` |
| Set-Cookie 属性注入（name/value 含 `;`、控制字符注入 `Domain=`/移除 HttpOnly） | `context::validate_cookie_name_value` 注入校验 + 单一构建点 `context::cookie::build_set_cookie_value`（三框架适配器 / 续签 / CSRF 写点统一经构建点产出，拒绝后不产出 Set-Cookie） | `src/context/cookie.rs`、`src/context/axum_adapter.rs` 内嵌测试 |
| Cookie 子域篡改（恶意子域写同Domain cookie 覆盖会话 token） | 默认不设 `Domain`（host-only）；`production` + Secure 上下文强制 `__Host-`（Path=/ 且无 Domain）/ `__Secure-` 前缀，浏览器层拒绝带 Domain 的 `__Host-` cookie | `src/context/cookie.rs`、`src/web/csrf.rs` 内嵌测试 |
| 非 Secure 上下文 SameSite=None（跨站携带凭证被浏览器拒收 / 属性不一致） | 构建点 None→Lax 降级不变式（`cookie_secure=false` 时降级 `Lax` 并 warn 一次），续签 / CSRF 写点无法直发 `SameSite=None` | `src/context/cookie.rs`、`src/router/tests.rs` 内嵌测试 |
| 登录风暴内存 DoS（并发慢哈希内存驻留叠加：N 并发 × 19 MiB 无上界） | Argon2 并发令牌池：`argon2_pool_size` permit 约束同时执行数（默认 1），permit 移入 `spawn_blocking` 闭包——取消/panic 任何时序下内存上界恒等于 `pool_size × m_cost`，排队不拒绝、池关闭 fail-closed；bcrypt 不入池（决策测试固化） | `src/account/credential/password.rs` 内嵌并发测试、`src/config/tests.rs` 区间校验 |
| 导入弱参数哈希（攻击者注入 m=1GiB 哈希 → 单次登录 CPU/内存 DoS） | 导入校验门 `validate_imported_hash`：格式白名单（argon2id/bcrypt 变体）+ 参数上限（m ≤ 1 GiB、t ≤ 10、p ≤ 4、bcrypt ≤ 15），越界整体拒绝；存量低档位哈希登录期惰性升级到当前档位（走并发令牌池） | `src/dao/repository/mod.rs` 上限常量、`src/account/credential/password.rs` 内嵌测试 |
| 数据库/备份泄露直接读取敏感凭据（OAuth2 token、授权码、TOTP seed） | `field-encryption` 静态加密：AES-256-GCM + AAD 绑定 `garrison:{tenant}:{table}:{key}`（密文挪行解密失败，防挪用重放）；写路径全加密、读路径双读兼容明文遗留行；密钥经 config-encryption 注入、未配密钥启动 fail-closed | `src/secure/encryption/`（crypto_value/dao/rekey 内嵌测试） |
| WebAuthn assertion 重放（截获的认证响应再次提交） | challenge 经 DAO `set_if_absent` + TTL 暂存，消费原子读删（RowsAffected==0 判重放）——同一 assertion 二次提交显性拒绝 | `src/protocol/webauthn/challenge.rs`、`tests.rs` 重放用例 |
| Authenticator 克隆（克隆设备持相同凭据密钥） | sign_count 单调性检测：count ≤ 上次记录值判克隆嫌疑拒绝；backup flags 跟随最新断言落库 | `src/protocol/webauthn/service.rs`、`tests.rs` 克隆用例 |
| 同 authenticator 绑定到多个账户（凭据挪用） | 注册仪式携 `ExcludeCredentials`（协议级防线）+ 数据库唯一约束兜底并发；冲突回查仅披露原占用者 user_id，不泄露其他行内容 | `src/protocol/webauthn/service.rs`、`src/dao/repository/sqlite/webauthn_credential_repo.rs` 契约测试 |
| 找回密码存在性枚举（探测哪些邮箱/手机号已注册） | 未知标识走同路径 dummy token + 相同限流计数与响应外形（对齐 authgear 防枚举）；超限锁定（1 小时窗口） | `src/account/password_reset/service.rs`、`tests.rs` 不可区分用例 |
| 重置 token 重放/并发消费（双花） | jti 经 DAO `set_if_absent` 一次性消费登记 + 原子消费（并发恰一成功）；两段式防竞态：消费失败凭据操作回滚 | `src/account/password_reset/`（jti 并发/两段式回滚用例） |
| 跨用户改密（窃取他人重置 token） | code-subject 绑定存 authflow 会话；`password_owner` claim 与 `sub` 一致性校验；restricted 会话仅可达改密端点 | `tests.rs` 跨用户 token 用例 |
| 新密码重用历史密码 | `app_password_history` 追加 + HistoryRule 复用检测（拒绝最近 N 条）；追加失败回滚凭据写入 | `tests.rs` 历史复用/回滚用例 |

### Refresh token 重用三级处置表

已轮换 refresh token 再次呈现（重放/被盗）时，`detect_reuse` 按提交 token 与存活链的血缘距离三级分类后分派处置：

| 子类型 | 判定（沿 chain 回溯） | 典型形态 | 处置 |
|-------|---------------------|---------|------|
| `RecentPrev` | 命中存活链头记录的 `parent_token_hash`（1 跳） | 并发双发 / 网络重试 | 按 `recent_reuse_behaviour`：`TheftDetected`（默认）吊销整条 chain；`Unauthorised` 仅拒绝本次 |
| `OrphanedBranch` | 命中更早祖先（>1 跳） | 攻击者持更早泄露副本 | 同 `RecentPrev`（按 `recent_reuse_behaviour` 分派） |
| `StaleLineage` | 无存活血缘（无子代或后代全部已吊销） | 陈旧副本重放 | **恒按盗用吊销整条 chain**（配置不可改变） |

宽限窗口（`refresh_grace_period_secs`，默认 0=关闭）：窗口内同一旧 token 命中返回既有新 token（不重旋转，容忍 in-flight 并发双刷；兑现预算 `refresh_grace_max_uses` 默认 1，**耗尽后的窗口内重放按上表处置**——默认吊销整条 chain）；并发落败方（CAS 未抢到消费权且宽限等待未命中）返回 `InvalidToken` 不吊销；窗口外按上表处置。旋转中途写失败补偿删除半成品行，原 chain 仍可用（绝不出现新旧 token 同时有效）。

## ⛔ 明确不防御的攻击

以下攻击面**超出框架边界**，须由部署方/业务方自行防御：

1. **传输层网络攻击**（SYN 洪水、DNS 劫持、BGP 劫持）——CDN/云网络层防护。
2. **TLS 终止前的流量窃听**——Garrison 不处理 TLS；反向代理必须正确配置。
3. **宿主机/内核级攻击**（root 提权后读内存、container escape）——进程隔离、加密 swap、最小权限容器运行时。
4. **物理访问**（disk 拔取、RAM 冷启动）——磁盘加密、密钥不落盘（KMS/Vault 注入）。
5. **业务逻辑授权缺陷**（业务规则本身的越权，如"只能删除自己的订单"未实现）——框架执行业务方定义的规则，规则缺失不归框架。
6. **已弃用算法的显式启用**（如显式指定 HTTP Digest MD5）——框架提供 safe-by-default 并在 [SECURITY.md 已知安全考量](../SECURITY.md#️-已知安全考量)中警示，显式绕过属业务方决策。
7. **社会工程与凭证钓鱼**——用户教育、MFA 强制（`secure-totp` 需业务方启用）。
8. **供应链上游投毒**（crates.io 账号被盗后发布恶意版本）——`cargo vet` 审核记录 + SBOM + lockfile 提供检测与追溯，不提供事前绝对防御。

---

发现威胁模型未覆盖的攻击面？请按 [SECURITY.md](../SECURITY.md) 流程私密报告（含"威胁模型缺口"标注）。
