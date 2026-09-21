# 🗺️ OWASP Top 10（2021）映射

本文档将 **OWASP Top 10 – 2021** 十类风险逐条映射到 Garrison 的防御机制与剩余责任边界，与 [THREAT.md](./THREAT.md)（STRIDE 视角）、[SECURITY_ASVS.md](./SECURITY_ASVS.md)（ASVS 4.0 逐条自评）互为补充——三份文档分别回答「攻击者视角 / 标准对照 / 风险榜单」。

---

> **定位声明**：映射是能力对照而非认证；标注「框架」表示框架内建机制（附证据链接），标注「业务方/部署方」表示该风险的完整处置需应用或部署层配合。
>
> 适用版本：0.9.0-rc.2。

---

## A01 – Broken Access Control（失效的访问控制）

| 维度 | 内容 |
|------|------|
| 框架机制 | RBAC 权限模型（`permission` 策略引擎，角色/权限/通配匹配）；ABAC/ Cedar 属性决策（`abac` feature，策略溯源）；多租户隔离（`tenant-isolation`，DAO 层按租户自动加 key 前缀的物理隔离）；API Key namespace 强制校验（`verify_with_namespace`，跨 namespace key 不可通过，防 IDOR）；firewall 白名单/黑名单路径与 Host 校验（`firewall-waf`，`waf_allowed_hosts` 防 Host 头投毒） |
| 业务方责任 | 权限模型的数据建模（角色/策略定义）与最小权限授予；租户解析器的正确接线（`tenant_resolution_middleware`）；业务对象级授权（如资源属主校验）在应用层执行 |

## A02 – Cryptographic Failures（加密机制失效）

| 维度 | 内容 |
|------|------|
| 框架机制 | 密码哈希 Argon2id 默认（m=19456/t=2/p=1，OWASP 建议档，锁定测试 + [ADR-0001](./adr/0001-argon2id-password-hashing.md)）；安全随机统一 `getrandom::fill` 直读 OS CSPRNG（[ADR-0002](./adr/0002-csprng-policy.md)）；常量时间比较统一原语（`secure-ct-eq`，subtle，[ADR-0003](./adr/0003-constant-time-comparison.md)）；API Key secret sha256 哈希存储（CWE-916，明文不落库）；JWT 算法白名单（HS 最小密钥长度 fail-fast + 非对称 `KeyMaterial` 类型绑定，RSA ≥2048 位 config 校验）；事件/日志 token 统一掩码（CWE-532，`secure-masking`） |
| 业务方责任 | TLS 终止与证书管理（反代层，[SECURITY.md](../SECURITY.md) 安全配置建议）；JWT 密钥的生成强度与 90 天轮换；敏感字段落库加密（下游存储加密不在框架管辖） |

## A03 – Injection（注入）

| 维度 | 内容 |
|------|------|
| 框架机制 | 数据访问统一经 dbnexus 参数化查询（DAO trait 抽象，无字符串拼接 SQL 的公共出口）；XSS 防护（`secure-xss`，输出转义策略）；输入净化（`secure-sanitize`，白名单清洗）；请求过滤（`firewall-waf`，banned headers/params 黑名单 + 方法白名单）；登录标识与 key 拼接经转义工具（如命名空间校验拒绝含 `:` 的 prefix，`protocol-temp` issue 参数校验） |
| 业务方责任 | 业务自有 SQL/ORM 的参数化纪律；模板渲染侧的上下文感知转义；第三方下游（搜索/缓存语法）注入的参数审查 |

## A04 – Insecure Design（不安全的设计）

| 维度 | 内容 |
|------|------|
| 框架机制 | 安全设计文档化：STRIDE 威胁模型（[THREAT.md](./THREAT.md)，六维 × 框架防御/业务方责任矩阵）；密码学选型论证（[ADR 三篇](./adr/0001-argon2id-password-hashing.md)）；ASVS 4.0 V2/V3 逐条自评留档（[SECURITY_ASVS.md](./SECURITY_ASVS.md)）；safe-by-default 设计原则（外网登录端点默认关闭、Digest 默认 SHA-256、限流 fail-closed、SimpleToken 无签名 generate 返回 Err） |
| 业务方责任 | 业务流程级威胁建模（ forgot-password / 邀请注册等编排的滥用分析）；将框架机制组合成完整认证流程时的设计评审 |

## A05 – Security Misconfiguration（安全配置错误）

| 维度 | 内容 |
|------|------|
| 框架机制 | 启动期配置校验 fail-fast（`validate_core`：token_style 白名单、JWT 算法-密钥类型匹配、Argon2 参数下限 + 显式风险接受位、bcrypt cost 区间、remember-me 时间一致性等，非法配置拒绝启动）；配置安全规则集（`config-security-rules`）；危险默认值消除（`cookie_secure` 默认 true、`throw_on_not_login` 默认 true）；退化路径显性告警（refresh 轮换未注入结构性 warn） |
| 业务方责任 | 生产部署加固核对（[DEPLOYMENT.md](./DEPLOYMENT.md)）；环境变量密钥管理（禁入版本库）；框架版本升级时对新增校验项的配置适配 |

## A06 – Vulnerable and Outdated Components（自带缺陷和过时的组件）

| 维度 | 内容 |
|------|------|
| 框架机制 | 分层依赖门禁：`cargo deny`（RustSec 公告/许可证/禁用源/来源校验，PR 阻断）+ `cargo audit`（发布门禁 0 CRITICAL）+ `cargo vet`（供应商审核记录，`supply-chain/` 公开可复核）+ Semgrep/gitleaks CI 扫描 + SBOM（CycloneDX，Release 资产）+ Artifact Attestations（SLSA 溯源）——详见 [SECURITY.md 供应链与门禁](../SECURITY.md)；已知通告处置论证公开（RUSTSEC-2023-0071 忽略理由随路径变化复核） |
| 业务方责任 | 下游自身的传递依赖门禁（SBOM 比对）；框架版本跟进（[SECURITY.md](../SECURITY.md) 支持版本表） |

## A07 – Identification and Authentication Failures（身份识别和认证失效）

| 维度 | 内容 |
|------|------|
| 框架机制 | 暴力破解防护（`firewall-bruteforce` IP 级失败计数封禁 + `account-lockout` 账户锁定 + `firewall-ratelimit` GCRA/滑动窗口，分布式后端 `rate-limit-redis`）；弱密码防护（`account-policy` 复杂度规则 + `policy-hibp` 泄露库 k-anonymity 校验）；慢哈希经 `spawn_blocking` 下沉（防登录风暴打挂 worker）+ 用户名枚举时序对齐（dummy verify）；TOTP RFC 6238 三组官方向量锁定（`secure-totp`）；JWT alg confusion 全链路对抗锁定（`alg=none`/跨密钥类型/篡改全拒）；认证器生命周期（`protocol-invitation` 一次性邀请码、`account-authflow` 条件引擎） |
| 业务方责任 | 认证失败提示话术统一（防枚举的最后一段）；MFA 编排组合（TOTP 原语已备）；会话凭证的前端保管（XSS 面收口） |

## A08 – Software and Data Integrity Failures（软件和数据完整性失效）

| 维度 | 内容 |
|------|------|
| 框架机制 | 审计链完整性（`audit-inklog`/`audit-log`，链式哈希 + 链首盐取 OS CSPRNG，防篡改可校验）；关键路径原子性（DAO `get_and_delete` 一次性消费语义 + loom 交错穷举验证防 double-spend；限流 Lua 脚本原子执行）；构建产物完整性（Artifact Attestations，`gh attestation verify` 可验证产物来自本仓库 CI）；发布门禁分层（lint→test→deny→doc→version→publish→release→verify） |
| 业务方责任 | 更新源可信（从 crates.io / GitHub Release 经 attestation 验证获取）；业务数据完整性约束（DB 外键/唯一性）在应用 schema 层定义 |

## A09 – Security Logging and Monitoring Failures（安全日志和监控失效）

| 维度 | 内容 |
|------|------|
| 框架机制 | 全量认证事件（`listener`：Login/Logout/Kickout/Replaced/TokenExpired/TempCredentialConsumed 等，token 字段统一掩码）；结构化日志（`audit-inklog` JSON + SIEM 输出 `audit-inklog-siem`，inklog 降级路径）；指标采集（`metrics-prometheus`，登录/校验/权限指标）；分布式追踪（`otlp`）；异常行为分析（`anomalous-detector-dual`，周期 + 突发检测） |
| 业务方责任 | 日志的集中采集/告警阈值/留存策略（SIEM 接入）；审计日志外归档（WORM 存储——本机文件可被 root 修改，见 [THREAT.md](./THREAT.md) 抵赖维度）；监控面板搭建 |

## A10 – Server-Side Request Forgery（服务器端请求伪造，SSRF）

| 维度 | 内容 |
|------|------|
| 框架机制 | 出站请求点收敛：OIDC discovery / token 端点 / SAML 元数据拉取均由**配置显式指定**可信 IdP URL（`KeycloakConfig.base_url` 等），不存在从用户输入派生出站目标的路径；`firewall-waf` 提供 Host/方法/参数层入口过滤 |
| 业务方责任 | 应用内自建的出站抓取能力（webhook、URL 预览等）的 SSRF 防护（目标白名单、内网段封禁、重定向审查）属应用层；框架托管 IdP URL 的网络可达性由部署方网络策略保障 |

---

## 覆盖度小结

十类风险中，A01/A02/A05/A06/A07/A08/A09 具备框架级机制与回归测试锚点；A03/A04 框架提供基座、完备性依赖业务组合；A10 框架内出表面收敛、通用 SSRF 属应用层。逐条细粒度对照（含「满足/部分/不适用」三态评级）见 [SECURITY_ASVS.md](./SECURITY_ASVS.md)，攻击路径视角见 [THREAT.md](./THREAT.md)。
