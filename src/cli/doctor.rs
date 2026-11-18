// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `doctor --security` 静态安全姿态审计（`cli-ops` feature 门控）。
//!
//! 聚合既有校验器的拒绝面为 ✓/✗/! 三态报告；不新增安全规则，判定语义与
//! `GarrisonConfig` / `AuthServerConfig` 的 validate 系列逐条对齐。

use crate::config::GarrisonConfig;

#[cfg(feature = "auth-server")]
use crate::server::AuthServerConfig;

/// 单条检查项状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    /// 检查通过。
    Pass,
    /// 检查失败（违反安全基线）。
    Fail,
    /// 警告（建议收紧，非拒绝面；Strict 档计入失败退出码）。
    Warn,
}

/// 稳定 ID 的发现项：id 供监控/告警规则引用，message 为英文静态文案。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCheckFinding {
    /// 稳定检查项 ID（如 `jwt-secret-strength`）。
    pub id: &'static str,
    /// 检查状态。
    pub status: FindingStatus,
    /// 英文静态说明文案。
    pub message: String,
}

impl SecurityCheckFinding {
    fn new(id: &'static str, status: FindingStatus, message: impl Into<String>) -> Self {
        Self {
            id,
            status,
            message: message.into(),
        }
    }
}

/// 编译期 feature 快照：生产经 `cfg!` 装配，测试可注入合成矩阵。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureMatrix {
    /// `web-security`（CORS/CSRF/安全响应头）是否编译启用。
    pub web_security: bool,
    /// `audit-log` 是否编译启用。
    pub audit_log: bool,
    /// `session-hijack-detection` 是否编译启用。
    pub session_hijack: bool,
    /// `device-binding` 是否编译启用。
    pub device_binding: bool,
    /// `config-security-rules` 是否编译启用。
    pub config_security_rules: bool,
    /// `auth-server` 是否编译启用。
    pub auth_server: bool,
}

impl FeatureMatrix {
    /// 由编译期 `cfg!` 装配（每个字段恒为编译期常量，无运行时开销）。
    pub fn from_compilation() -> Self {
        Self {
            web_security: cfg!(feature = "web-security"),
            audit_log: cfg!(feature = "audit-log"),
            session_hijack: cfg!(feature = "session-hijack-detection"),
            device_binding: cfg!(feature = "device-binding"),
            config_security_rules: cfg!(feature = "config-security-rules"),
            auth_server: cfg!(feature = "auth-server"),
        }
    }
}

/// 报告的档位：只影响退出码阈值，不改变报告内容。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorProfile {
    /// 标准档：仅 Fail 计入失败退出码。
    Standard,
    /// 严格档：Fail 与 Warn 均计入失败退出码（CI 门禁）。
    Strict,
}

/// 检查上下文：配置 + 可选服务配置 + feature 矩阵 + 档位。
pub struct DoctorContext {
    /// 已装配的 `GarrisonConfig`（库层加载器的唯一事实来源）。
    pub config: GarrisonConfig,
    #[cfg(feature = "auth-server")]
    /// 库层 `AuthServerConfig`；`auth-server` 未编译时该字段不存在。
    pub server: Option<AuthServerConfig>,
    /// 注入的 feature 快照（生产来自 cfg!，测试可合成）。
    pub features: FeatureMatrix,
    /// 报告档位（只影响退出码）。
    pub profile: DoctorProfile,
}

/// 同步检查项签名（既有校验函数均为同步签名，不引入异步运行时依赖）。
pub type SecurityCheck = fn(&DoctorContext) -> Vec<SecurityCheckFinding>;

/// 将发现项渲染为逐行报告 + 汇总行。
///
/// 逐行格式 `✓|✗|! <id>: <message>`，末行 `<p> passed, <w> warnings, <f> failures`。
fn render_report(findings: &[SecurityCheckFinding]) -> String {
    let mut lines = Vec::with_capacity(findings.len() + 1);
    let mut passed = 0usize;
    let mut warned = 0usize;
    let mut failed = 0usize;
    for finding in findings {
        let mark = match finding.status {
            FindingStatus::Pass => {
                passed += 1;
                "✓"
            },
            FindingStatus::Warn => {
                warned += 1;
                "!"
            },
            FindingStatus::Fail => {
                failed += 1;
                "✗"
            },
        };
        lines.push(format!("{} {}: {}", mark, finding.id, finding.message));
    }
    lines.push(format!(
        "{} passed, {} warnings, {} failures",
        passed, warned, failed
    ));
    lines.join("\n")
}

/// 执行全部检查项并渲染报告（CHECKS 在 T006 接入，当前为空集合）。
pub fn run_security_doctor(ctx: &DoctorContext) -> String {
    let _ = ctx; // CHECKS 接入前显式消费，避免未使用参数告警
    let findings: Vec<SecurityCheckFinding> = Vec::new();
    render_report(&findings)
}

/// 退出码：Standard 仅 Fail 计失败；Strict 下 Fail 或 Warn 均计失败。
pub fn doctor_exit_code(findings: &[SecurityCheckFinding], profile: DoctorProfile) -> i32 {
    let has_fail = findings.iter().any(|f| f.status == FindingStatus::Fail);
    let has_warn = findings.iter().any(|f| f.status == FindingStatus::Warn);
    match profile {
        DoctorProfile::Standard => i32::from(has_fail),
        DoctorProfile::Strict => i32::from(has_fail || has_warn),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &'static str, status: FindingStatus) -> SecurityCheckFinding {
        SecurityCheckFinding::new(id, status, format!("{id} detail"))
    }

    #[test]
    fn exit_code_zero_for_clean_report_in_both_profiles() {
        let findings = [finding("clean-check", FindingStatus::Pass)];
        assert_eq!(doctor_exit_code(&findings, DoctorProfile::Standard), 0);
        assert_eq!(doctor_exit_code(&findings, DoctorProfile::Strict), 0);
        assert_eq!(doctor_exit_code(&[], DoctorProfile::Strict), 0);
    }

    #[test]
    fn exit_code_warn_only_is_zero_standard_and_one_strict() {
        let findings = [finding("warn-check", FindingStatus::Warn)];
        assert_eq!(doctor_exit_code(&findings, DoctorProfile::Standard), 0);
        assert_eq!(doctor_exit_code(&findings, DoctorProfile::Strict), 1);
    }

    #[test]
    fn exit_code_fail_is_one_in_both_profiles() {
        let findings = [
            finding("warn-check", FindingStatus::Warn),
            finding("fail-check", FindingStatus::Fail),
        ];
        assert_eq!(doctor_exit_code(&findings, DoctorProfile::Standard), 1);
        assert_eq!(doctor_exit_code(&findings, DoctorProfile::Strict), 1);
    }

    #[test]
    fn report_renders_marks_and_summary() {
        let findings = [
            finding("ok", FindingStatus::Pass),
            finding("warn", FindingStatus::Warn),
            finding("bad", FindingStatus::Fail),
        ];
        let report = render_report(&findings);
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "✓ ok: ok detail");
        assert_eq!(lines[1], "! warn: warn detail");
        assert_eq!(lines[2], "✗ bad: bad detail");
        assert_eq!(lines[3], "1 passed, 1 warnings, 1 failures");
    }

    #[test]
    fn profile_does_not_change_report_content() {
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };
        let standard = run_security_doctor(&ctx);
        let strict_ctx = DoctorContext {
            profile: DoctorProfile::Strict,
            config: ctx.config.clone(),
            #[cfg(feature = "auth-server")]
            server: ctx.server.clone(),
            features: ctx.features,
        };
        assert_eq!(standard, run_security_doctor(&strict_ctx));
    }

    #[test]
    fn synthetic_feature_matrix_is_injected_into_context() {
        let matrix = FeatureMatrix {
            web_security: true,
            audit_log: false,
            session_hijack: true,
            device_binding: false,
            config_security_rules: true,
            auth_server: false,
        };
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: matrix,
            profile: DoctorProfile::Strict,
        };
        assert_eq!(ctx.features, matrix);
        assert!(ctx.features.web_security);
        assert!(!ctx.features.audit_log);
        assert!(ctx.features.session_hijack);
        assert!(!ctx.features.device_binding);
        assert!(ctx.features.config_security_rules);
        assert!(!ctx.features.auth_server);
        assert_eq!(ctx.profile, DoctorProfile::Strict);
    }

    #[test]
    fn compilation_matrix_matches_enabled_features() {
        let matrix = FeatureMatrix::from_compilation();
        assert_eq!(matrix.web_security, cfg!(feature = "web-security"));
        assert_eq!(matrix.audit_log, cfg!(feature = "audit-log"));
        assert_eq!(
            matrix.session_hijack,
            cfg!(feature = "session-hijack-detection")
        );
        assert_eq!(matrix.device_binding, cfg!(feature = "device-binding"));
        assert_eq!(
            matrix.config_security_rules,
            cfg!(feature = "config-security-rules")
        );
        assert_eq!(matrix.auth_server, cfg!(feature = "auth-server"));
    }
}
