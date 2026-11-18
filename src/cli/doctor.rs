// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `doctor --security` 静态安全姿态审计（`cli-ops` feature 门控）。
//!
//! 聚合既有校验器的拒绝面为 ✓/✗/! 三态报告；不新增安全规则，判定语义与
//! `GarrisonConfig` / `AuthServerConfig` 的 validate 系列逐条对齐。

use crate::config::GarrisonConfig;

use sdforge::cli::{CliArgInfo, CliArgType, CliCommandRegistration, CliHandlerRegistration};
use sdforge::core::{ApiError, HandlerArgs, HandlerFuture, HandlerState};
use sdforge::inventory;

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

/// 编译期封闭的 9 项检查表（顺序与 design D2 / delta spec 清单一致）。
const CHECKS: &[SecurityCheck] = &[
    check_jwt_secret_strength,
    check_config_security_rules,
    check_internal_api_key,
    check_server_bind_address,
    check_external_login_ack,
    check_trusted_proxies,
    check_web_security_stack,
    check_audit_chain,
    check_session_signal_sources,
];

/// 执行全部检查项并渲染报告。
pub fn run_security_doctor(ctx: &DoctorContext) -> String {
    let findings: Vec<SecurityCheckFinding> = CHECKS.iter().flat_map(|check| check(ctx)).collect();
    render_report(&findings)
}

/// `server-bind-address`：通配绑定 → Warn（容器合法，公网须收口）。
fn check_server_bind_address(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    #[cfg(feature = "auth-server")]
    {
        let Some(server) = ctx.server.as_ref() else {
            return vec![SecurityCheckFinding::new(
                "server-bind-address",
                FindingStatus::Pass,
                "Skipped: auth-server not available in this context",
            )];
        };
        if server.external_bind.is_unspecified() || server.internal_bind.is_unspecified() {
            return vec![SecurityCheckFinding::new(
                "server-bind-address",
                FindingStatus::Warn,
                "Wildcard bind is set; legal in containers, but restrict exposure on public hosts",
            )];
        }
        vec![SecurityCheckFinding::new(
            "server-bind-address",
            FindingStatus::Pass,
            "Bind addresses are specific (loopback/private), not wildcard",
        )]
    }
    #[cfg(not(feature = "auth-server"))]
    {
        let _ = ctx;
        vec![SecurityCheckFinding::new(
            "server-bind-address",
            FindingStatus::Pass,
            "Skipped: auth-server not compiled in this build",
        )]
    }
}

/// `external-login-ack`：外网登录开启且非回环绑定未 ACK → 严格档 Fail / 非严格档 Warn。
fn check_external_login_ack(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    #[cfg(feature = "auth-server")]
    {
        let Some(server) = ctx.server.as_ref() else {
            return vec![SecurityCheckFinding::new(
                "external-login-ack",
                FindingStatus::Pass,
                "Skipped: auth-server not available in this context",
            )];
        };
        let unacked = server.external_login_enabled
            && !server.external_bind.is_loopback()
            && server.external_login_ack.as_deref() != Some(crate::server::EXTERNAL_LOGIN_ACK);
        if !unacked {
            return vec![SecurityCheckFinding::new(
                "external-login-ack",
                FindingStatus::Pass,
                "External login is off, loopback-only, or explicitly acknowledged",
            )];
        }
        let status = if server.strict_security {
            FindingStatus::Fail
        } else {
            FindingStatus::Warn
        };
        vec![SecurityCheckFinding::new(
            "external-login-ack",
            status,
            "External login is exposed on a non-loopback bind without the risk acknowledgement",
        )]
    }
    #[cfg(not(feature = "auth-server"))]
    {
        let _ = ctx;
        vec![SecurityCheckFinding::new(
            "external-login-ack",
            FindingStatus::Pass,
            "Skipped: auth-server not compiled in this build",
        )]
    }
}

/// `trusted-proxies`：含公网地址 → Fail（与 validate() 无条件拒绝一致）。
fn check_trusted_proxies(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    #[cfg(feature = "auth-server")]
    {
        let Some(server) = ctx.server.as_ref() else {
            return vec![SecurityCheckFinding::new(
                "trusted-proxies",
                FindingStatus::Pass,
                "Skipped: auth-server not available in this context",
            )];
        };
        let public = server
            .rate_limit_trusted_proxies
            .iter()
            .find(|ip| !crate::server::config::is_private_proxy_addr(ip));
        match public {
            Some(ip) => vec![SecurityCheckFinding::new(
                "trusted-proxies",
                FindingStatus::Fail,
                format!("Trusted proxy {ip} is not a private/loopback address"),
            )],
            None => vec![SecurityCheckFinding::new(
                "trusted-proxies",
                FindingStatus::Pass,
                "All trusted proxies are loopback/private addresses",
            )],
        }
    }
    #[cfg(not(feature = "auth-server"))]
    {
        let _ = ctx;
        vec![SecurityCheckFinding::new(
            "trusted-proxies",
            FindingStatus::Pass,
            "Skipped: auth-server not compiled in this build",
        )]
    }
}

/// `web-security-stack`：`web_security=false` → Warn；`auth_server=true` 隐含 headers → Pass 并注明。
fn check_web_security_stack(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    if ctx.features.web_security {
        return vec![SecurityCheckFinding::new(
            "web-security-stack",
            FindingStatus::Pass,
            "Web security stack (CORS/CSRF/security headers) is enabled",
        )];
    }
    if ctx.features.auth_server {
        return vec![SecurityCheckFinding::new(
            "web-security-stack",
            FindingStatus::Pass,
            "web-security-headers is implied by auth-server (CORS/CSRF still need web-security)",
        )];
    }
    vec![SecurityCheckFinding::new(
        "web-security-stack",
        FindingStatus::Warn,
        "CORS/CSRF/security headers are missing (enable web-security)",
    )]
}

/// `audit-chain`：`audit_log=false` → Warn。
fn check_audit_chain(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    let finding = if ctx.features.audit_log {
        SecurityCheckFinding::new(
            "audit-chain",
            FindingStatus::Pass,
            "Audit event chain is enabled",
        )
    } else {
        SecurityCheckFinding::new(
            "audit-chain",
            FindingStatus::Warn,
            "Audit event chain is missing; events cannot be traced (enable audit-log)",
        )
    };
    vec![finding]
}

/// `session-signal-sources`：两个信号源均关 → Warn，任一启用 → Pass。
fn check_session_signal_sources(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    let finding = if ctx.features.session_hijack || ctx.features.device_binding {
        SecurityCheckFinding::new(
            "session-signal-sources",
            FindingStatus::Pass,
            "At least one risk signal source (session-hijack/device-binding) is enabled",
        )
    } else {
        SecurityCheckFinding::new(
            "session-signal-sources",
            FindingStatus::Warn,
            "Risk signal sources are missing (enable session-hijack-detection or device-binding)",
        )
    };
    vec![finding]
}

/// `jwt-secret-strength`：复用 `validate_jwt_secret`，Err → Fail。
fn check_jwt_secret_strength(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    let finding = match ctx.config.validate_jwt_secret() {
        Ok(()) => SecurityCheckFinding::new(
            "jwt-secret-strength",
            FindingStatus::Pass,
            "JWT secret strength meets the configured token style floor",
        ),
        Err(e) => SecurityCheckFinding::new(
            "jwt-secret-strength",
            FindingStatus::Fail,
            format!("JWT secret is too weak: {e}"),
        ),
    };
    vec![finding]
}

/// `config-security-rules`：feature 关闭记 Warn；启用时复用 `validate_security_rules`。
fn check_config_security_rules(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    // 编译期未启用时，无论注入矩阵如何都记 Warn（校验方法不存在）。
    #[cfg(not(feature = "config-security-rules"))]
    {
        let _ = ctx;
        vec![SecurityCheckFinding::new(
            "config-security-rules",
            FindingStatus::Warn,
            "Config security rule set is not compiled in (enable config-security-rules)",
        )]
    }
    #[cfg(feature = "config-security-rules")]
    {
        let finding = if !ctx.features.config_security_rules {
            SecurityCheckFinding::new(
                "config-security-rules",
                FindingStatus::Warn,
                "Config security rule set is not compiled in (enable config-security-rules)",
            )
        } else {
            match ctx.config.validate_security_rules() {
                Ok(()) => SecurityCheckFinding::new(
                    "config-security-rules",
                    FindingStatus::Pass,
                    "Config security rule set is enabled and passes",
                ),
                Err(e) => SecurityCheckFinding::new(
                    "config-security-rules",
                    FindingStatus::Fail,
                    format!("Config security rule set rejects current config: {e}"),
                ),
            }
        };
        vec![finding]
    }
}

/// `internal-api-key`：空/短 → Fail（严格档语义），非严格档短 Key → Warn。
fn check_internal_api_key(ctx: &DoctorContext) -> Vec<SecurityCheckFinding> {
    #[cfg(feature = "auth-server")]
    {
        let Some(server) = ctx.server.as_ref() else {
            return vec![SecurityCheckFinding::new(
                "internal-api-key",
                FindingStatus::Pass,
                "Skipped: auth-server not compiled in this build",
            )];
        };
        let len = server.internal_api_key.len();
        if len == 0 {
            return vec![SecurityCheckFinding::new(
                "internal-api-key",
                FindingStatus::Fail,
                "Internal API key is missing (empty keys are rejected at startup)",
            )];
        }
        if len < crate::server::MIN_INTERNAL_API_KEY_LEN {
            let status = if server.strict_security {
                FindingStatus::Fail
            } else {
                FindingStatus::Warn
            };
            return vec![SecurityCheckFinding::new(
                "internal-api-key",
                status,
                format!(
                    "Internal API key is {len} bytes; rotate to >= {} bytes",
                    crate::server::MIN_INTERNAL_API_KEY_LEN
                ),
            )];
        }
        vec![SecurityCheckFinding::new(
            "internal-api-key",
            FindingStatus::Pass,
            format!("Internal API key length is {len} bytes (>= required floor)"),
        )]
    }
    #[cfg(not(feature = "auth-server"))]
    {
        let _ = ctx;
        vec![SecurityCheckFinding::new(
            "internal-api-key",
            FindingStatus::Pass,
            "Skipped: auth-server not compiled in this build",
        )]
    }
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

// ---- CLI 注册与 handler（机制同 cli/ops.rs 的 key-rotate） ----

inventory::submit! {
    CliCommandRegistration::new(
        "doctor",
        env!("CARGO_PKG_VERSION"),
        "Run static security posture audit and print findings",
        "handle_doctor_cmd",
    )
    .with_args(&[CliArgInfo::new(
        "profile",
        "Exit nonzero on warnings when set to strict (standard|strict)",
        CliArgType::Body,
        false,
        Some("standard"),
    )])
}
inventory::submit! { CliHandlerRegistration { name: "doctor", handler: handle_doctor_cmd } }

/// 解析 `profile` 参数：缺省 `standard`；仅 `standard|strict` 合法。
fn parse_profile_arg(args: &HandlerArgs) -> Result<DoctorProfile, String> {
    let raw = args
        .get("profile")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "standard".to_string());
    match raw.as_str() {
        "standard" => Ok(DoctorProfile::Standard),
        "strict" => Ok(DoctorProfile::Strict),
        other => Err(format!("cli-arg-invalid::profile::{other}")),
    }
}

/// 从环境装配 doctor 上下文：库层 `GarrisonConfig::load` 是环境覆盖的唯一来源。
fn build_doctor_context(profile: DoctorProfile) -> DoctorContext {
    let config = GarrisonConfig::load(None).unwrap_or_else(|_| GarrisonConfig::default_config());
    DoctorContext {
        config,
        #[cfg(feature = "auth-server")]
        server: Some(AuthServerConfig::default()),
        features: FeatureMatrix::from_compilation(),
        profile,
    }
}

fn handle_doctor_cmd(args: HandlerArgs, _state: HandlerState) -> HandlerFuture {
    Box::pin(async move {
        let profile = parse_profile_arg(&args)
            .map_err(|reason| ApiError::internal_error(reason, "garrison.cli"))?;
        let ctx = build_doctor_context(profile);
        let findings: Vec<SecurityCheckFinding> =
            CHECKS.iter().flat_map(|check| check(&ctx)).collect();
        let report = render_report(&findings);
        let exit_code = doctor_exit_code(&findings, profile);
        let payload = serde_json::json!({"report": report, "exit_code": exit_code});
        if exit_code == 0 {
            Ok(payload)
        } else {
            // 与 healthcheck 同路：非零语义经 ApiError → main 退出码 1；报告已随错误 reason 输出。
            Err(ApiError::internal_error(
                report,
                "garrison.doctor.posture".to_string(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// panic 安全的 env 守卫：Drop（含 unwind）时 remove_var，防断言失败污染共享进程环境。
    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    #[serial_test::serial]
    fn doctor_context_config_reflects_env_override() {
        let _guard = EnvGuard("GARRISON_TIMEOUT");
        std::env::set_var("GARRISON_TIMEOUT", "4321");
        let ctx = build_doctor_context(DoctorProfile::Standard);
        assert_eq!(ctx.config.timeout, 4321);
    }

    #[test]
    fn profile_arg_defaults_to_standard() {
        let args = HandlerArgs::new();
        assert_eq!(parse_profile_arg(&args).unwrap(), DoctorProfile::Standard);
    }

    #[test]
    fn profile_arg_accepts_standard_and_strict_case_insensitive() {
        let mut args = HandlerArgs::new();
        args.insert("profile".to_string(), "STRICT".to_string());
        assert_eq!(parse_profile_arg(&args).unwrap(), DoctorProfile::Strict);
        args.insert("profile".to_string(), " standard ".to_string());
        assert_eq!(parse_profile_arg(&args).unwrap(), DoctorProfile::Standard);
    }

    #[test]
    fn profile_arg_rejects_unknown_value() {
        let mut args = HandlerArgs::new();
        args.insert("profile".to_string(), "loose".to_string());
        let err = parse_profile_arg(&args).unwrap_err();
        assert_eq!(err, "cli-arg-invalid::profile::loose");
    }

    #[test]
    fn checks_table_has_nine_unique_stable_ids() {
        assert_eq!(CHECKS.len(), 9);
        let expected = [
            "jwt-secret-strength",
            "config-security-rules",
            "internal-api-key",
            "server-bind-address",
            "external-login-ack",
            "trusted-proxies",
            "web-security-stack",
            "audit-chain",
            "session-signal-sources",
        ];
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };
        let findings: Vec<SecurityCheckFinding> = CHECKS.iter().flat_map(|c| c(&ctx)).collect();
        let ids: Vec<&str> = findings.iter().map(|f| f.id).collect();
        assert_eq!(ids, expected);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 9, "检查项 ID 不得重复");
    }

    #[test]
    fn doctor_report_contains_nine_lines_and_summary() {
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };
        let report = run_security_doctor(&ctx);
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines.len(), 10, "9 检查行 + 1 汇总行");
        assert!(lines[9].contains("failures"));
    }

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
    fn feature_face_checks_warn_when_absent_and_pass_when_present() {
        let all_off = FeatureMatrix {
            web_security: false,
            audit_log: false,
            session_hijack: false,
            device_binding: false,
            config_security_rules: false,
            auth_server: false,
        };
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: all_off,
            profile: DoctorProfile::Standard,
        };
        assert_eq!(
            check_web_security_stack(&ctx)[0].status,
            FindingStatus::Warn
        );
        assert_eq!(check_audit_chain(&ctx)[0].status, FindingStatus::Warn);
        assert_eq!(
            check_session_signal_sources(&ctx)[0].status,
            FindingStatus::Warn
        );

        let all_on = FeatureMatrix {
            web_security: true,
            audit_log: true,
            session_hijack: true,
            device_binding: true,
            config_security_rules: true,
            auth_server: false,
        };
        let ctx_on = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: all_on,
            profile: DoctorProfile::Standard,
        };
        assert_eq!(
            check_web_security_stack(&ctx_on)[0].status,
            FindingStatus::Pass
        );
        assert_eq!(check_audit_chain(&ctx_on)[0].status, FindingStatus::Pass);
        assert_eq!(
            check_session_signal_sources(&ctx_on)[0].status,
            FindingStatus::Pass
        );
    }

    #[test]
    fn auth_server_implies_web_security_headers_with_note() {
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features: FeatureMatrix {
                web_security: false,
                audit_log: false,
                session_hijack: false,
                device_binding: false,
                config_security_rules: false,
                auth_server: true,
            },
            profile: DoctorProfile::Standard,
        };
        let findings = check_web_security_stack(&ctx);
        assert_eq!(findings[0].status, FindingStatus::Pass);
        assert!(
            findings[0].message.contains("implied by auth-server"),
            "应注明隐含来源，实际: {}",
            findings[0].message
        );
    }

    #[test]
    fn jwt_secret_strength_check_rejects_weak_simple_secret_and_accepts_strong() {
        let mut weak = GarrisonConfig::default_config();
        weak.token_style = "simple".to_string();
        weak.jwt_secret = "short".into();
        let ctx = DoctorContext {
            config: weak,
            #[cfg(feature = "auth-server")]
            server: None,
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };
        let findings = check_jwt_secret_strength(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "jwt-secret-strength");
        assert_eq!(findings[0].status, FindingStatus::Fail);

        let mut strong = GarrisonConfig::default_config();
        strong.token_style = "simple".to_string();
        strong.jwt_secret = "a-32-byte-or-longer-jwt-secret-value".into();
        let ctx_strong = DoctorContext {
            config: strong,
            #[cfg(feature = "auth-server")]
            server: None,
            features: ctx.features,
            profile: DoctorProfile::Standard,
        };
        let findings_strong = check_jwt_secret_strength(&ctx_strong);
        assert_eq!(findings_strong[0].status, FindingStatus::Pass);
    }

    #[test]
    fn config_security_rules_check_warns_when_feature_absent() {
        let mut features = FeatureMatrix::from_compilation();
        features.config_security_rules = false;
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            #[cfg(feature = "auth-server")]
            server: None,
            features,
            profile: DoctorProfile::Standard,
        };
        let findings = check_config_security_rules(&ctx);
        assert_eq!(findings[0].status, FindingStatus::Warn);
        assert_eq!(findings[0].id, "config-security-rules");
    }

    #[cfg(feature = "auth-server")]
    #[test]
    fn server_face_checks_align_with_validate_semantics() {
        let mut server = AuthServerConfig::default();
        server.external_bind = std::net::IpAddr::from([0, 0, 0, 0]);
        server.internal_api_key = "short".to_string();
        server.external_login_enabled = true;
        server.rate_limit_trusted_proxies = vec![std::net::IpAddr::from([8, 8, 8, 8])];
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            server: Some(server.clone()),
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };

        let bind = check_server_bind_address(&ctx);
        assert_eq!(bind[0].id, "server-bind-address");
        assert_eq!(bind[0].status, FindingStatus::Warn);

        let ack = check_external_login_ack(&ctx);
        assert_eq!(ack[0].id, "external-login-ack");
        assert_eq!(ack[0].status, FindingStatus::Fail);

        let proxies = check_trusted_proxies(&ctx);
        assert_eq!(proxies[0].id, "trusted-proxies");
        assert_eq!(proxies[0].status, FindingStatus::Fail);

        let relaxed = DoctorContext {
            config: GarrisonConfig::default_config(),
            server: Some(AuthServerConfig {
                strict_security: false,
                ..server
            }),
            features: ctx.features,
            profile: DoctorProfile::Standard,
        };
        assert_eq!(
            check_external_login_ack(&relaxed)[0].status,
            FindingStatus::Warn
        );
    }

    #[cfg(feature = "auth-server")]
    #[test]
    fn server_face_checks_skip_when_server_absent() {
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            server: None,
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };
        for findings in [
            check_server_bind_address(&ctx),
            check_external_login_ack(&ctx),
            check_trusted_proxies(&ctx),
            check_internal_api_key(&ctx),
        ] {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].status, FindingStatus::Pass);
        }
    }

    #[test]
    fn internal_api_key_check_distinguishes_short_and_strong() {
        let mut server = AuthServerConfig::default();
        server.internal_api_key = "short".to_string();
        let ctx = DoctorContext {
            config: GarrisonConfig::default_config(),
            server: Some(server.clone()),
            features: FeatureMatrix::from_compilation(),
            profile: DoctorProfile::Standard,
        };
        let findings = check_internal_api_key(&ctx);
        assert_eq!(findings[0].status, FindingStatus::Fail);
        assert_eq!(findings[0].id, "internal-api-key");

        server.strict_security = false;
        let ctx_relaxed = DoctorContext {
            config: GarrisonConfig::default_config(),
            server: Some(server.clone()),
            features: ctx.features,
            profile: DoctorProfile::Standard,
        };
        assert_eq!(
            check_internal_api_key(&ctx_relaxed)[0].status,
            FindingStatus::Warn
        );

        server.internal_api_key = "a-32-byte-or-longer-internal-key".to_string();
        let ctx_ok = DoctorContext {
            config: GarrisonConfig::default_config(),
            server: Some(server),
            features: ctx.features,
            profile: DoctorProfile::Standard,
        };
        assert_eq!(
            check_internal_api_key(&ctx_ok)[0].status,
            FindingStatus::Pass
        );
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
