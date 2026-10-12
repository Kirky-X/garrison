// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

use super::{AuthServerConfig, EXTERNAL_LOGIN_ACK, MIN_INTERNAL_API_KEY_LEN};

/// 判断 IP 是否为内网/环回候选（回环 / RFC1918 / link-local / IPv6 ULA）。
///
/// `AuthServerConfig::validate` 与参考部署 bin 的可信代理校验共用本函数（单一实现）。
pub fn is_private_proxy_addr(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
        },
    }
}

/// 读取布尔环境变量开关（"1"/"true"/"yes"/"on"，大小写不敏感）。
///
/// 取值无法识别时告警并返回 `None`（调用方回退默认值），不静默吞掉配置错误。
fn env_flag(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|raw| match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => {
                tracing::warn!(
                    env = key,
                    value = %raw,
                    "unrecognized boolean, falling back to default"
                );
                None
            },
        })
}

/// 读取整数环境变量（非法取值告警并回退默认值，不静默）。
fn env_num<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|raw| match raw.trim().parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(env = key, value = %raw, "unrecognized number, falling back to default");
            None
        },
    })
}

impl AuthServerConfig {
    /// 校验配置合法性（server 启动时调用）。
    ///
    /// 错误：`internal_api_key` 为空（防 fail-open）；`rate_limit_trusted_proxies` 含非内网/环回
    /// 地址——公网 IP 会被互联网路径上的中间设备伪造，扩大 X-Forwarded-For 信任边界。
    ///
    /// 仅 `strict_security = true` 时另拒 `server-internal-api-key-too-short`（密钥短于
    /// [`MIN_INTERNAL_API_KEY_LEN`]）与 `server-external-login-unacknowledged`（外网登录开启、
    /// 绑定非回环且确认串不匹配 [`EXTERNAL_LOGIN_ACK`]）；非严格档同条件只输出含迁移动作的
    /// `tracing::warn!`。通配绑定两档均不拒绝——容器部署必须绑定 `0.0.0.0`，收口须由调用方经
    /// `with_external_bind` / `with_internal_bind` 显式决定。
    pub fn validate(&self) -> Result<(), String> {
        if self.internal_api_key.is_empty() {
            return Err("server-internal-api-key-missing::".to_string());
        }
        // 严格档两条拒绝；非严格档同样条件只告警（棘轮非破坏语义）。
        let key_too_short = self.internal_api_key.len() < MIN_INTERNAL_API_KEY_LEN;
        let login_unacked = self.external_login_enabled
            && !self.external_bind.is_loopback()
            && self.external_login_ack.as_deref() != Some(EXTERNAL_LOGIN_ACK);
        if self.strict_security {
            if key_too_short {
                return Err(format!(
                    "server-internal-api-key-too-short::{}",
                    self.internal_api_key.len()
                ));
            }
            if login_unacked {
                return Err(format!(
                    "server-external-login-unacknowledged::{}",
                    self.external_bind
                ));
            }
        } else {
            if key_too_short {
                tracing::warn!(
                    len = self.internal_api_key.len(),
                    min = MIN_INTERNAL_API_KEY_LEN,
                    "{}",
                    crate::i18n::translate_detail("logs-server-internal-api-key-too-short", &[])
                );
            }
            if login_unacked {
                tracing::warn!(
                    bind = %self.external_bind,
                    "{}",
                    crate::i18n::translate_detail(
                        "logs-server-external-login-unacknowledged",
                        &[]
                    )
                );
            }
            if self.external_bind.is_unspecified() || self.internal_bind.is_unspecified() {
                tracing::warn!(
                    external_bind = %self.external_bind,
                    internal_bind = %self.internal_bind,
                    "{}",
                    crate::i18n::translate_detail("logs-server-wildcard-bind-default", &[])
                );
            }
        }
        for ip in &self.rate_limit_trusted_proxies {
            if !is_private_proxy_addr(ip) {
                return Err(format!("server-trusted-proxy-not-private::{}", ip));
            }
        }
        Ok(())
    }
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            external_port: 8080,
            // 绑定地址默认 0.0.0.0（框架层向后兼容）；安全收口由调用方
            // 经 with_external_bind/with_internal_bind 显式注入。
            external_bind: std::net::IpAddr::from([0, 0, 0, 0]),
            internal_port: 8081,
            internal_bind: std::net::IpAddr::from([0, 0, 0, 0]),
            external_rate_limit_per_ip: 100,
            rate_limit_max_entries: 100_000,
            rate_limit_trusted_proxies: Vec::new(),
            internal_api_key: String::new(),
            external_body_limit: 256 * 1024,  // 256 KB
            internal_body_limit: 1024 * 1024, // 1 MB
            // 外网登录端点默认关闭（框架不校验凭证，secure-by-default）
            external_login_enabled: false,
            // API Key 失败锁定默认开启（阈值 10 / 窗口 300s；0 = 禁用）；
            // 环境变量在 Default 读取，bin 零改动即可经 GARRISON_* 覆盖默认装配。
            api_key_lockout_threshold: env_num("GARRISON_API_KEY_LOCKOUT_THRESHOLD").unwrap_or(10),
            api_key_lockout_window_secs: env_num("GARRISON_API_KEY_LOCKOUT_WINDOW_SECS")
                .unwrap_or(300),
            // readyz details 默认剥离（可能含内部依赖拓扑），显式 opt-in
            health_details_enabled: env_flag("GARRISON_HEALTH_DETAILS").unwrap_or(false),
            // 棘轮语义：缺省 false，只告警不拒绝。
            strict_security: env_flag("GARRISON_STRICT_SECURITY").unwrap_or(false),
            external_login_ack: std::env::var("GARRISON_EXTERNAL_LOGIN_ACK")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}
