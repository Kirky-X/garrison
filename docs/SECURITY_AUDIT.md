# 🛡️ Garrison 安全审计就绪包（v1.0 门禁启动）

> **定位声明**：本文是 v1.0「安全审计」门禁的**启动材料与证据索引**，不是第三方审计报告，也不构成任何认证或合规结论。内部审查持续滚动；第三方审计尚未启动（见文末状态表）。所有结论以可复现命令与仓库内工件为准。

## 📋 目录

- [审计范围与资产](#-审计范围与资产)
- [方法论](#-方法论)
- [证据矩阵](#-证据矩阵)
- [发现与整改](#-发现与整改)
- [ASVS / OWASP 映射](#-asvs--owasp-映射)
- [第三方审计准备（RFP 清单）](#-第三方审计准备rfp-清单)
- [状态表](#-状态表)
- [相关文档](#-相关文档)

---

## 🎯 审计范围与资产

| 资产     | 说明                                                                             |
| -------- | -------------------------------------------------------------------------------- |
| 认证核心 | 登录 / 会话 / Token / 权限 / MFA 编排（`src/stp`、`src/session`、`src/manager`） |
| 协议面   | OAuth2 / OIDC / SSO / SAML / JWT / API Key / 扫码登录 / WebAuthn                 |
| 安全原语 | Argon2id、CSPRNG、常量时间比较、字段静态加密、审计链                             |
| 数据面   | `GarrisonDao` + oxcache / dbnexus 后端；会话 key 摘要化；限流 Redis 运行时       |
| 部署面   | `auth_server` 参考部署（TLS、绑定、API Key、严格档）、Docker 镜像                |
| 供应链   | 依赖版本、RustSec 通告、`cargo vet` 审计、发布流水线                             |

**威胁模型**：见 [THREAT.md](./THREAT.md)；安全策略与漏洞报告渠道见 [SECURITY.md](../SECURITY.md)。

---

## 🧪 方法论

| 层次     | 方法                                                                               | 频率                |
| -------- | ---------------------------------------------------------------------------------- | ------------------- |
| SAST     | Semgrep（`p/rust` + `p/secrets`，`.semgrepignore` 降噪）；CodeQL（GitHub Actions） | 每次 PR / 每周      |
| 依赖     | `cargo audit` + `cargo deny check` + `cargo vet`（`supply-chain/`）                | 每次依赖变更 / 每周 |
| 模糊测试 | 4 个 target：SAML XML / OIDC discovery / JWT verify / HTTP auth headers            | 每周 + 手动深扫     |
| 动态     | 端到端验收（认证 / 协议 / 多租户 / 并发 / 安全攻击面）                             | 每次发布候选        |
| 人工     | 安全审查批次（R01–R18 整改）、ADR 评审、ASVS 自评                                  | 滚动                |
| 外部     | 第三方渗透测试 / 代码审计                                                          | 📋 待启动           |

---

## 📊 证据矩阵

| 证据            | 命令 / 位置                                                | 产物                                               | 当前状态                         |
| --------------- | ---------------------------------------------------------- | -------------------------------------------------- | -------------------------------- |
| SAST（Semgrep） | `semgrep scan --config p/rust --config p/secrets`          | CI 日志 / SARIF                                    | 随 CI 执行（本地需安装 semgrep） |
| SAST（CodeQL）  | `.github/workflows/codeql.yml`                             | GitHub Security 告警                               | 已接线                           |
| 依赖漏洞        | `cargo audit`                                              | 终端输出 / CI                                      | 已接线                           |
| 依赖策略        | `cargo deny check`（license / advisory / ban / source）    | 终端输出                                           | 已接线                           |
| 供应链审计      | `cargo vet check --locked`（`supply-chain/audits.toml`）   | 终端输出                                           | 已接线（工具需本地安装）         |
| 模糊测试        | `cargo +nightly fuzz run <target>`（`fuzz/fuzz_targets/`） | `fuzz/artifacts/` / CI                             | 已接线（每周 + 60s smoke）       |
| 端到端安全面    | `bash scripts/e2e_run.sh`（含 `security::` 域）            | `logs/e2e_final_report.md` / `pentest_report.json` | 可复现                           |
| 双实例限流      | `cargo test --features full --test redis_limiter_backend`  | 测试输出                                           | rc.4 新增                        |
| ASVS 自评       | [SECURITY_ASVS.md](./SECURITY_ASVS.md)                     | 控制点映射                                         | 已建立（持续滚动）               |
| ADR             | `docs/adr/0001-0004`                                       | 决策记录                                           | 已建立                           |
| 发现账本        | `.mimosa/finding-ledger/v1`                                | JSON 账本                                          | 本地工具状态（不入库）           |
| 审计证据摘要    | `bash scripts/security_evidence.sh`                        | `logs/security-evidence.md`                        | 本轮新增                         |

---

## 🔎 发现与整改

- **输入来源**：内部审查（diting / tiangang）、外部安全审计结论、CodeQL/Semgrep 告警、依赖通告、模糊测试崩溃、社区报告。
- **分级**：CRITICAL / HIGH / MEDIUM / LOW；CRITICAL/HIGH 阻断发布，必须有修复 + 回归测试 + CHANGELOG 记录。
- **闭环要求**：每条发现需有「现象 → 根因 → 修复 → 回归证据 → 影响面」；已整改批次见 [CHANGELOG](./CHANGELOG.md)（rc.2 / rc.3 / rc.4 Unreleased）。
- **例外管理**：确需豁免的依赖通告走 `deny.toml` / `supply-chain/config.toml`，附理由与复核日期；禁止无记录豁免。

---

## 🔐 ASVS / OWASP 映射

| 框架                 | 映射文档                               | 说明                                  |
| -------------------- | -------------------------------------- | ------------------------------------- |
| OWASP ASVS 4.0 V2/V3 | [SECURITY_ASVS.md](./SECURITY_ASVS.md) | 认证与会话管理自评；标注 ✅ / 🔶 / ⚪ |
| OWASP Top 10         | [OWASP_TOP10.md](./OWASP_TOP10.md)     | 风险面与框架侧控制                    |
| 威胁模型             | [THREAT.md](./THREAT.md)               | STRIDE 矩阵与信任边界                 |

---

## 📝 第三方审计准备（RFP 清单）

启动外部审计前需准备：

1. **范围**：认证核心 + 协议面 + 加密原语 + 多租户隔离 + 参考部署；明确排除项（业务方自定义插件、下游应用逻辑）。
2. **交付物**：审计报告（发现分级 + 复现步骤 + 修复建议）、复测结论、管理层摘要。
3. **访问**：源码仓库只读权限、构建/测试命令、`docker-compose.e2e.yml` 环境、模糊测试语料、ASVS 自评与 ADR。
4. **时间**：建议在 1.0 API 冻结后、发布前完成；预留整改与复测窗口。
5. **资质**：具备 Rust 生态与认证协议审计经验；接受保密协议与漏洞披露策略。
6. **预算与排期**：📋 待产品决策（不在本仓库单方面承诺）。

---

## 📌 状态表

| 项                         | 状态            | 说明                                                 |
| -------------------------- | --------------- | ---------------------------------------------------- |
| 内部安全审查               | ✅ 已建立，滚动 | R01–R18 整改已随 rc.3 落地；rc.4 继续修复 DAO/会话面 |
| SAST / 依赖 / 模糊测试接线 | ✅ 已接线       | CodeQL / cargo audit / deny / vet / fuzz 4 targets   |
| ASVS 自评                  | 🔶 持续滚动     | 见 [SECURITY_ASVS.md](./SECURITY_ASVS.md)            |
| 第三方审计                 | 📋 未启动       | 需产品决策预算与排期；本文提供 RFP 清单              |
| 认证 / 合规声明            | ⚪ 不适用       | 本仓库不做认证结论；由部署方按其合规体系评估         |

---

## 📚 相关文档

| 文档                               | 说明                                            |
| ---------------------------------- | ----------------------------------------------- |
| [🔒 安全策略](../SECURITY.md)      | 漏洞报告渠道与支持版本                          |
| [🛡️ ASVS 自评](./SECURITY_ASVS.md) | V2/V3 控制点映射                                |
| [🎯 威胁模型](./THREAT.md)         | STRIDE 与信任边界                               |
| [🧭 ADR](./adr/)                   | 密码哈希 / CSPRNG / 常量时间比较 / 统一错误模型 |
| [🗺️ 路线图](./ROADMAP.md)          | v1.0 安全审计门禁状态                           |
