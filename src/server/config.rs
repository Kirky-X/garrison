// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

use super::AuthServerConfig;

/// 读取布尔环境变量开关（接受 "1"/"true"/"yes"/"on"，大小写不敏感）。
///
/// 变量存在但无法识别取值时告警并按 `None` 处理（调用方回退默认值）——
/// 不静默吞掉：配置错误必须显性化。
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
    /// 校验配置合法性。
    ///
    /// 在 server 启动时调用，确保关键配置项已正确设置。
    ///
    /// # 错误
    /// - `internal_api_key` 为空时返回错误，防止 fail-open 风险。
    /// - `rate_limit_trusted_proxies` 含非内网/环回地址时返回错误：
    ///   可信代理仅应部署在内网（loopback / RFC 1918 / link-local / IPv6 ULA），
    ///   公网 IP 会被互联网路径上的中间设备伪造，扩大 X-Forwarded-For 信任边界。
    pub fn validate(&self) -> Result<(), String> {
        if self.internal_api_key.is_empty() {
            return Err("server-internal-api-key-missing::".to_string());
        }
        for ip in &self.rate_limit_trusted_proxies {
            let is_private = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_loopback() || v4.is_private() || v4.is_link_local()
                },
                std::net::IpAddr::V6(v6) => {
                    v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
                },
            };
            if !is_private {
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
            internal_port: 8081,
            external_rate_limit_per_ip: 100,
            rate_limit_max_entries: 100_000,
            rate_limit_trusted_proxies: Vec::new(),
            internal_api_key: String::new(),
            external_body_limit: 256 * 1024,  // 256 KB
            internal_body_limit: 1024 * 1024, // 1 MB
            // C-1: 外网登录端点默认关闭（框架不校验凭证，secure-by-default）
            external_login_enabled: false,
            // GAR-25: API Key 失败锁定默认开启（阈值 10 / 窗口 300s；0 = 禁用）。
            // 环境变量在 Default 读取（而非 bin 接线）：保证 bin 零改动即可
            // 经 GARRISON_* 覆盖默认装配。
            api_key_lockout_threshold: env_num("GARRISON_API_KEY_LOCKOUT_THRESHOLD").unwrap_or(10),
            api_key_lockout_window_secs: env_num("GARRISON_API_KEY_LOCKOUT_WINDOW_SECS")
                .unwrap_or(300),
            // GAR-14: readyz details 默认剥离（可能含内部依赖拓扑），显式 opt-in
            health_details_enabled: env_flag("GARRISON_HEALTH_DETAILS").unwrap_or(false),
        }
    }
}
