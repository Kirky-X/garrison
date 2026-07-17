# Remediation Status — bulwark_371b

## 审计信息

- **strix run_id**: `bulwark_371b`
- **审计日期**: 2026-07-17
- **目标版本**: Bulwark v0.7.0
- **审计范围**: 认证授权深度评估（switch_to / login_with_token / renew / 设备指纹 / 客户端 DoS 防护）
- **审计报告**: `findings.sarif` + `vulnerabilities.csv`

## 漏洞与修复映射

| vuln_id | 标题 | 严重度 | 修复 commit | 修复状态 |
|---------|------|--------|-------------|----------|
| vuln-0001 | Privilege Escalation via switch_to Identity Switching | CRITICAL | `43ab79c` (A6) | ✅ 完成 |
| vuln-0002 | Cross-User Session Management via Unauthenticated login_id Parameter | CRITICAL | `a1d6e8b` (A7) | ✅ 完成 |
| vuln-0003 | Token Renewal Gap Window During renew_to_equivalent | HIGH | `954ad49` (A9) | ✅ 完成 |
| vuln-0004 | Session Fixation via login_with_token Dual-Mapping Bypass | CRITICAL | `5648f2a` (A8) | ✅ 完成 |
| vuln-0005 | Device Binding Bypass via Spoofable Fingerprint | MEDIUM | `81feb09` (A10) | ✅ 完成 |
| vuln-0006 | reqwest HTTP Client Missing Timeout Configuration Enables DoS via Hanging Connections | HIGH | `65cc6b6` (E1) | ✅ 完成 |
| vuln-0007 | reqwest HTTP Client Missing Response Body Size Limit Enables Memory Exhaustion | HIGH | `65cc6b6` (E2) | ✅ 完成 |
| vuln-0008 | TOTP Per-Login_ID Lock Map Grows Without Bound Causing Memory Exhaustion | HIGH | `accf1e1` (E3) | ✅ 完成 |
| vuln-0009 | API Key Verification Performs Full DAO Pattern Scan on Every Call | HIGH | `811ee10` (E4) | ✅ 完成 |

## 修复状态总览

- **修复状态**: ✅ 完成（9/9 漏洞全部修复）
- **修复 commit 范围**: `811ee10`..`954ad49`（含跨审计批次共用 commit）
- **修复日期**: 2026-07-18
- **CRITICAL 漏洞**: 3 个，全部修复
- **HIGH 漏洞**: 5 个，全部修复
- **MEDIUM 漏洞**: 1 个，全部修复

## 验证

- **代码-文档一致性审查**: 待 Convergence 阶段最终确认
- **tiangang SAST 扫描**: 待发布前最终扫描
- **diting 代码审查**: 待发布前最终审查
- **测试通过情况**: 待 `cargo test --features full` 最终验证

## 备注

- 本批次聚焦认证授权与会话管理深度漏洞
- `954ad49` (A9) 通过 swap 顺序调整消除 DoS gap window，无需新增代码即可修复
- `accf1e1` (E3) 将 TOTP 锁从 DashMap 改为 oxcache 原子 incr，同时解决内存泄漏与并发竞态
- 完整修复明细见 `CHANGELOG.md` 的 `[Unreleased] - 2026-07-18` 条目
