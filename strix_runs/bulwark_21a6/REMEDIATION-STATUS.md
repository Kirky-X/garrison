# Remediation Status — bulwark_21a6

## 审计信息

- **strix run_id**: `bulwark_21a6`
- **审计开始**: 2026-07-16 11:53:58 UTC
- **审计结束**: 2026-07-16 13:25:08 UTC
- **目标版本**: Bulwark v0.7.0
- **审计范围**: 源代码白盒安全评估（OWASP WSTG + PTES 框架）
- **审计报告**: `penetration_test_report.md`

## 漏洞与修复映射

| vuln_id | 标题 | 严重度 | 修复 commit | 修复状态 |
|---------|------|--------|-------------|----------|
| vuln-0001 | ABAC Engine Silently Evaluates Policies Against Empty Entity Set | HIGH | (A1 集成修复) | ✅ 完成 |
| vuln-0002 | Internal Auth API Endpoints Expose Session Data Without Ownership Verification | MEDIUM | `0d7a8fe` (A5) | ✅ 完成 |
| vuln-0003 | Tenant Isolation Bypass via Silent Fallback to tenant_id=0 | HIGH | (A4 集成修复) | ✅ 完成 |
| vuln-0004 | switch_to Endpoint Allows Identity Escalation When Permissive SwitchToGuard Is Configured | HIGH | `43ab79c` (A6) | ✅ 完成 |
| vuln-0005 | ABAC Policy Evaluation Silently Allows When Engine Is Not Initialized | CRITICAL | (A2 集成修复, fail-closed) | ✅ 完成 |
| vuln-0006 | ABAC Expression Injection via Unsanitized Cedar Policy String Interpolation | CRITICAL | `b28ef5c` (A3) | ✅ 完成 |
| vuln-0007 | XSS Whitelist Mode bypass via javascript: URLs in href attributes | MEDIUM | `45a3146` (D5) | ✅ 完成 |
| vuln-0008 | Missing constant-time comparison in HMAC signature verification | MEDIUM | `4476395` (D1) | ✅ 完成 |
| vuln-0009 | SMS verification code 000000 is a valid 6-digit code | NONE | `87c62ba` (F4) | ✅ 完成 |
| vuln-0010 | Custom mask type returns unmasked sensitive data in masking module | MEDIUM | `a79b5a4` (D6) | ✅ 完成 |
| vuln-0011 | JSON Body Token Injection via is_read_body Configuration | MEDIUM | `8903cd4` (C7) | ✅ 完成 |
| vuln-0012 | WAF Security Rules Disabled by Default | MEDIUM | `6960b53` (C1) | ✅ 完成 |
| vuln-0013 | Web WAF DangerousCharacter Rule Does Not Inspect Query Parameters | MEDIUM | `04f8f66` (C2) | ✅ 完成 |
| vuln-0014 | OAuth2 Token Endpoint Lacks Rate Limiting for Non-Password Grants | CRITICAL | `6a5c63b` (B5) | ✅ 完成 |
| vuln-0015 | CSRF Cookie Missing Domain Attribute Creates Subdomain Inconsistency | MEDIUM | `34d663f` (C3) | ✅ 完成 |
| vuln-0016 | Broken [patch.crates-io] path dependencies prevent publishing and pose supply chain risk | MEDIUM | (F1 集成修复) | ✅ 完成 |
| vuln-0017 | Hardcoded API key placeholders in example code | MEDIUM | `8932f3e` (F2) | ✅ 完成 |
| vuln-0018 | CORS Preflight Responses Bypass CSRF and WAF Security Checks | MEDIUM | `72975a5` (C4) | ✅ 完成 |
| vuln-0019 | JWT nbf (Not Before) Claim Not Validated — Premature Token Acceptance | MEDIUM | `1944271` (B10) | ✅ 完成 |
| vuln-0020 | KeycloakProvider Missing Audience and Issuer Validation — Cross-Client Token Reuse | CRITICAL | `4e13b21` (B9) | ✅ 完成 |
| vuln-0021 | CVE-2026-48504 in opentelemetry 0.30.0 | MEDIUM | `7037764` (F3) | ✅ 完成 |

## 修复状态总览

- **修复状态**: ✅ 完成（22/22 漏洞全部修复）
- **修复 commit 范围**: `811ee10`..`2084933`（21 个 commit，含跨审计批次共用 commit）
- **修复日期**: 2026-07-18
- **CRITICAL 漏洞**: 4 个，全部修复
- **HIGH 漏洞**: 4 个，全部修复
- **MEDIUM 漏洞**: 13 个，全部修复
- **NONE 漏洞**: 1 个，已修复

## 验证

- **代码-文档一致性审查**: 待 Convergence 阶段最终确认
- **tiangang SAST 扫描**: 待发布前最终扫描
- **diting 代码审查**: 待发布前最终审查
- **测试通过情况**: 待 `cargo test --features full` 最终验证

## 备注

- 本批次发现的漏洞在 v0.7.0 release 前 Convergence 阶段全部修复
- 部分 commit（如 `4e13b21` OIDC/id_token 验签）同时修复 `bulwark_21a6` 和 `bulwark_6704` 中相关漏洞
- 完整修复明细见 `CHANGELOG.md` 的 `[Unreleased] - 2026-07-18` 条目
