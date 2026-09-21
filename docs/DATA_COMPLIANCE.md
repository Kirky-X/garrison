# 数据合规指南（GDPR / 个保法）

本文档说明 Garrison 作为身份认证框架处理的**数据清单、保存期限、删除权（erasure）行使方式与数据本地化部署指引**，供业务方履行 GDPR / 《个人信息保护法》义务时使用。

> 关联：[SECURITY.md](../SECURITY.md)（漏洞披露与安全配置）｜[THREAT.md](./THREAT.md)（威胁模型）｜[OWASP_TOP10.md](./OWASP_TOP10.md)
>
> **定位声明**：Garrison 是框架（SDK），不是数据处理者——最终应用才是与数据主体的关系方。本文描述框架管辖内数据的处置能力与业务方的剩余责任。

## 1. 数据清单（框架管辖内存储）

| 数据类 | 存储位置（键空间） | 含个人信息 | 保存期限 | 擦除方式 |
|--------|-------------------|-----------|---------|---------|
| 会话（Account-Session 索引） | `account:session:{login_id}` | login_id、设备绑定信息 | `timeout` 配置（默认 30 天） | `logout_by_login_id` / 擦除服务 |
| 会话（Token 明细） | `token:session:{token}` | login_id（记录内）、设备 | 同上，随索引级联 | `logout_by_login_id` 级联删除 |
| OAuth2 access/refresh token | `oauth2:atoken:` / `oauth2:rtoken:`（DAO 路径）或 `refresh_tokens` 表（db-sqlite，仅 SHA-256 哈希） | client_id / user_id | `ACCESS/REFRESH_TOKEN_TTL` | revoke 端点（RFC 7009）/ TTL |
| API Key | DAO `cred:` 命名空间（secret 仅 SHA-256 哈希） | key_id、owner_id、IP 限速计数 | 至吊销 | `ApiKeyRepository` 吊销 API |
| 账户锁定状态 | `lockout:{login_id}` | login_id、失败模式画像 | TTL（锁定窗口） | 擦除服务 / TTL |
| 暴力破解失败计数 | `bf:{ip}:count` | **客户端 IP**（GDPR Recital 30 属个人数据） | TTL（计数窗口） | 擦除服务 `erase_ip_artifacts` |
| 验证码 / 邮箱验证 | `captcha:` 等前缀（手机号/邮箱为键） | 手机号 / 邮箱 | ≤ 1 小时 | TTL 自然过期 |
| 审计日志 | 应用日志 / SIEM（业务方存储） | 事件内 login_id、IP、掩码 token（CWE-532 统一掩码） | **业务方保留策略** | 业务方处置（见 §3 保留期例外） |
| 备份码 / TOTP 密钥 | 业务方凭据存储（框架提供哈希原语） | 主体关联凭据 | 至解除绑定 | 业务方凭据管理 |

## 2. 删除权（erasure）行使方式

### 2.1 框架侧编排（`data-erasure` feature）

启用 feature 后，`compliance::DataErasureService` 按主体擦除框架管辖内可定位数据并产出留档报告：

```rust,ignore
use garrison::compliance::DataErasureService;

let eraser = DataErasureService::new(dao.clone());
// 会话擦除委托 logout_by_login_id（含 per-login 锁与 token 级联删除语义）
let report = eraser
    .erase_subject("1001", |id| async { stp.logout_by_login_id(id).await })
    .await?;
// report.erased_keys：已删除键清单；report.session_erasure_delegated：委托结果；
// report.residual_guidance：业务方残留处置提示——三者可直接作为删除请求响应留档。
// IP 维度（GDPR Recital 30）：
let ip_report = eraser.erase_ip_artifacts("203.0.113.7").await?;
```

设计约束：会话删除的并发正确性由 `StpLogic` 承载（委托而非复制）；委托失败不中断擦除、在报告中显性暴露——删除权路径宁可报告残留也不静默宣称完成。

### 2.2 业务方残留责任（报告 `residual_guidance` 同步提示）

| 残留数据 | 处置方式 |
|---------|---------|
| API Key | 经 `ApiKeyRepository` 按 owner 查询后吊销（含业务授权语义，框架不代删） |
| 业务用户资料 / 业务副本 | 业务方自有存储，框架不可达 |
| 审计日志 | 见 §3 保留期例外 |
| 已签发的无状态 JWT | 到期前技术不可撤回；需即时撤回能力请启用 `enable_jwt_revocation` |
| 验证码记录 | TTL ≤ 1 小时自然过期 |

### 2.3 审计日志的保留期例外

删除权不适用于**为履行法律义务所必需**的处理（GDPR Art. 17(3)(b)、个保法第 47 条例外情形）。安全审计日志通常落入该例外——建议保留策略：安全事件日志 ≥ 法定/合同要求期限，到期自动化销毁；日志中主体字段已按 CWE-532 掩码（token 类）最小化。

## 3. 数据本地化部署

- **存储后端全可指定**：会话/令牌/限速/审计的存储经 `GarrisonDao` 抽象与 `GARRISON_DB_URL` / `GARRISON_REDIS_URL` 指定，可将全部框架数据限定在特定司法辖区的基础设施内（自建 / 区域云 region）。
- **无跨境外呼**：框架运行时不存在向第三方服务发送主体数据的行为（`policy-hibp` 的 HIBP k-anonymity 查询是唯一可选出站，仅发送 5 字符哈希前缀、不含明文密码；不启用 `policy-hibp` 则零出站）。
- **依赖供应链可审计**：SBOM + 依赖清单公开（见 [SECURITY.md 供应链与门禁](../SECURITY.md)），可核验无隐蔽数据通道。

## 4. 数据保护默认值

- 密码：Argon2id（OWASP 建议档）哈希存储，明文不落库；`credential-zeroize` feature 下哈希输入副本用后即清零。
- API Key secret：仅存 SHA-256 哈希（生成期 244-bit 高熵锁定），校验常量时间比较。
- 日志/事件：token 类字段统一掩码（前 8 字符 + `***`）。
- 审计链：链式哈希防篡改，链首盐取 OS CSPRNG。
