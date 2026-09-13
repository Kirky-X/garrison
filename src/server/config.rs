//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::AuthServerConfig;

impl AuthServerConfig {
    /// 校验配置合法性。
    ///
    /// 在 server 启动时调用，确保关键配置项已正确设置。
    ///
    /// # 错误
    /// - `internal_api_key` 为空时返回错误，防止 fail-open 风险。
    /// - `rate_limit_trusted_proxies` 含非内网/环回地址时返回错误：
    ///   可信代理仅应部署在内网（loopback / RFC 1918 / link-local / IPv6 ULA），
    ///   公网 IP 会被互联网路径上的中间设备伪造，扩大 X-Forwarded-For 信任边界（ocr #2882）。
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
        }
    }
}
